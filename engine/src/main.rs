//! `vless-engine` child-process IPC & standalone CLI binary (`PLAN.md` §4, §5.2–5.6, §6, §8).
//!
//! Supports two execution modes:
//! 1. **IPC mode** (`vless-engine` or `vless-engine ipc`, spawned by `vless-tray`): speaks
//!    newline-delimited JSON (`vless_ipc::AppToEngine` on `stdin`, `vless_ipc::EngineToApp` on
//!    `stdout`) and communicates with `vless-tray-helper` over `/var/run/vless-tray.sock`
//!    (`SCM_RIGHTS` for `utun` fd passing).
//! 2. **Standalone CLI mode** (`vless-engine run --link 'vless://...' ...`): runs a standalone
//!    MixedProxy (`127.0.0.1:2080` default) or raw-TUN-fd session logging to `stderr` until
//!    `SIGINT` or `SIGTERM`.

use std::io::{self, Write};
use std::net::IpAddr;
use std::os::fd::IntoRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use tokio::net::UnixStream;
use tokio::sync::{RwLock as AsyncRwLock, mpsc};
use vless_engine::cli::{CliAction, RunArgs, RunInboundMode, parse_cli_args};
use vless_engine::{
    EngineConfig, EngineHandle, EngineState, EngineStatus, Profile, resolve_host_via_udp_dns,
    resolve_server_host_ips, set_outbound_interface_index,
};
use vless_ipc::{
    AppToEngine, EngineLaunchMode, EngineToApp, HelperCommand, HelperMessage, HelperResponse,
    LogLevel, async_recv_helper_message, async_send_helper_command,
    builtin_system_proxy_exceptions, builtin_tun_bypass_cidrs, read_json_line_async,
    write_json_line_async, write_json_line_sync,
};

struct JsonStdoutLogger {
    tx: mpsc::UnboundedSender<EngineToApp>,
}

impl log::Log for JsonStdoutLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Trace => LogLevel::Trace,
        };
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let _ = self.tx.send(EngineToApp::Log {
            timestamp_ms,
            level,
            target: record.target().to_owned(),
            message: format!("{}", record.args()),
        });
    }

    fn flush(&self) {}
}

struct StderrLogger {
    max_level: log::Level,
}

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "[{}] {}: {}",
            record.level(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {
        let _ = io::stderr().flush();
    }
}

struct ActiveSession {
    handle: Arc<AsyncRwLock<Option<EngineHandle>>>,
    is_tun: bool,
    utun_name: Option<String>,
    server_host: String,
    server_port: u16,
    outbound_if_index: Arc<AtomicU32>,
    original_dns_servers: Arc<RwLock<Vec<IpAddr>>>,
    helper_cmd_tx: Option<mpsc::Sender<(HelperCommand, Option<tokio::sync::oneshot::Sender<()>>)>>,
    state_forward_task: tokio::task::JoinHandle<()>,
    helper_watch_task: Option<tokio::task::JoinHandle<()>>,
}

impl ActiveSession {
    async fn shutdown(mut self) {
        self.state_forward_task.abort();

        // Send `HelperCommand::Stop` BEFORE awaiting/aborting `helper_watch_task` so `cmd_rx`
        // remains alive to forward `Stop` and receive `HelperResponse::Stopped` cleanly.
        if let Some(tx) = self.helper_cmd_tx.take() {
            let _ = tx.send((HelperCommand::Stop, None)).await;
            drop(tx);
        }
        if let Some(mut task) = self.helper_watch_task.take()
            && tokio::time::timeout(Duration::from_secs(4), &mut task)
                .await
                .is_err()
        {
            task.abort();
        }

        if let Some(handle) = self.handle.write().await.take() {
            let _ = handle.stop().await;
        }
    }
}

fn build_proxy_exceptions(cidrs: &[IpNetwork], domains: &[String]) -> Vec<String> {
    let mut out = builtin_system_proxy_exceptions();
    for cidr in cidrs {
        let s = match cidr {
            IpNetwork::V4(v4) if v4.prefix() == 32 => v4.ip().to_string(),
            IpNetwork::V6(v6) if v6.prefix() == 128 => v6.ip().to_string(),
            other => other.to_string(),
        };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    for dom in domains {
        if !out.contains(dom) {
            out.push(dom.clone());
        }
    }
    out
}

fn merged_tun_bypass_cidrs(user_cidrs: &[IpNetwork]) -> Vec<IpNetwork> {
    let mut out = builtin_tun_bypass_cidrs();
    for c in user_cidrs {
        if !out.contains(c) {
            out.push(*c);
        }
    }
    out
}

/// Re-resolves the VLESS server's own hostname in TUN mode without recursing through tunnel DNS
/// (`PLAN.md` §5.4): sends direct RFC 1035 `A`/`AAAA` UDP queries bound to the physical interface
/// to `original_dns_servers`, falling back to `resolve_server_host_ips` only if
/// `original_dns_servers` is empty.
async fn resolve_tun_server_ips(
    server_host: &str,
    server_port: u16,
    original_dns_servers: &[IpAddr],
    outbound_if_index: Option<u32>,
) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = server_host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if !original_dns_servers.is_empty() {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let bind_if = {
            let _ = outbound_if_index;
            None
        };
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let bind_if = outbound_if_index.and_then(vless_engine::if_index_to_name);

        return resolve_host_via_udp_dns(server_host, original_dns_servers, bind_if).await;
    }
    resolve_server_host_ips(server_host, server_port).await
}

/// Reads messages from the helper Unix socket until a synchronous `HelperMessage::Response`
/// arrives, handling or queuing any interleaved `HelperMessage::NetworkChanged` push notifications.
async fn recv_next_helper_response(
    sock: &UnixStream,
    deferred_net_change: &mut Option<(u32, String, Vec<IpAddr>)>,
) -> io::Result<HelperResponse> {
    loop {
        match async_recv_helper_message(sock)
            .await
            .map_err(|e| io::Error::other(format!("helper recv failed: {e}")))?
        {
            (HelperMessage::Response(resp), _) => return Ok(resp),
            (
                HelperMessage::NetworkChanged {
                    outbound_if_index,
                    outbound_if_name,
                    original_dns_servers,
                },
                _,
            ) => {
                *deferred_net_change =
                    Some((outbound_if_index, outbound_if_name, original_dns_servers));
            }
        }
    }
}

struct TunWatchContext {
    handle_slot: Arc<AsyncRwLock<Option<EngineHandle>>>,
    active_if_idx: Arc<AtomicU32>,
    shared_dns: Arc<RwLock<Vec<IpAddr>>>,
    pinned_resolver: Arc<vless_engine::resolver::ServerEndpointResolver>,
    server_host: String,
    server_port: u16,
    sock: UnixStream,
    utun_name: String,
    out_tx: mpsc::UnboundedSender<EngineToApp>,
}

impl TunWatchContext {
    async fn apply_network_change(
        &self,
        outbound_if_index: u32,
        outbound_if_name: String,
        new_original_dns: Vec<IpAddr>,
        deferred_net_change: &mut Option<(u32, String, Vec<IpAddr>)>,
    ) {
        log::info!(
            "Network interface changed to {outbound_if_name} (index {outbound_if_index}); refreshing server routes"
        );
        self.active_if_idx
            .store(outbound_if_index, Ordering::Release);
        if !new_original_dns.is_empty() {
            *self.shared_dns.write() = new_original_dns;
        }
        if let Some(ref handle) = *self.handle_slot.read().await {
            handle.set_outbound_interface_index(Some(outbound_if_index));
        }

        let _ = self.out_tx.send(EngineToApp::State {
            status: EngineStatus::Reconnecting,
            detail: Some(format!(
                "Switching physical interface to {outbound_if_name}"
            )),
            listen_addr: None,
            utun_name: Some(self.utun_name.clone()),
        });

        let dns_snapshot = self.shared_dns.read().clone();
        if let Ok(ips) = resolve_tun_server_ips(
            &self.server_host,
            self.server_port,
            &dns_snapshot,
            Some(outbound_if_index),
        )
        .await
        {
            self.pinned_resolver.update_server_ips(ips.clone());
            if async_send_helper_command(
                &self.sock,
                &HelperCommand::UpdateServerRoute { server_ips: ips },
            )
            .await
            .is_ok()
                && let Ok(HelperResponse::ServerRouteUpdated {
                    outbound_if_index: updated_idx,
                    original_dns_servers: updated_dns,
                    ..
                }) = recv_next_helper_response(&self.sock, deferred_net_change).await
            {
                self.active_if_idx.store(updated_idx, Ordering::Release);
                if !updated_dns.is_empty() {
                    *self.shared_dns.write() = updated_dns;
                }
                if let Some(ref handle) = *self.handle_slot.read().await {
                    handle.set_outbound_interface_index(Some(updated_idx));
                }
            }
        }

        let _ = self.out_tx.send(EngineToApp::State {
            status: EngineStatus::Connected,
            detail: None,
            listen_addr: None,
            utun_name: Some(self.utun_name.clone()),
        });
    }
}

async fn start_session(
    profile: Profile,
    mode: EngineLaunchMode,
    dns_resolver: IpAddr,
    bypass_cidrs: Vec<IpNetwork>,
    bypass_domains: Vec<String>,
    out_tx: mpsc::UnboundedSender<EngineToApp>,
) -> io::Result<ActiveSession> {
    let _ = out_tx.send(EngineToApp::State {
        status: EngineStatus::Starting,
        detail: None,
        listen_addr: None,
        utun_name: None,
    });

    let server_host = profile.server_host.clone();
    let server_port = profile.server_port;

    match mode {
        EngineLaunchMode::StandaloneProxy { listen_addr } => {
            let mut cfg = EngineConfig::new_mixed_proxy(profile, listen_addr);
            cfg.dns_resolver = dns_resolver;
            cfg.bypass_cidrs = bypass_cidrs;
            cfg.bypass_domains = bypass_domains;

            let (handle, state_rx) = EngineHandle::start(cfg).await?;
            let state_forward_task = spawn_state_forwarder(state_rx, None, out_tx);
            Ok(ActiveSession {
                handle: Arc::new(AsyncRwLock::new(Some(handle))),
                is_tun: false,
                utun_name: None,
                server_host,
                server_port,
                outbound_if_index: Arc::new(AtomicU32::new(0)),
                original_dns_servers: Arc::new(RwLock::new(Vec::new())),
                helper_cmd_tx: None,
                state_forward_task,
                helper_watch_task: None,
            })
        }
        EngineLaunchMode::SystemProxy {
            listen_addr,
            helper_socket,
        } => {
            let exceptions = build_proxy_exceptions(&bypass_cidrs, &bypass_domains);
            let mut cfg = EngineConfig::new_mixed_proxy(profile, listen_addr);
            cfg.dns_resolver = dns_resolver;
            cfg.bypass_cidrs = bypass_cidrs;
            cfg.bypass_domains = bypass_domains;

            let (handle, state_rx) = EngineHandle::start(cfg).await?;
            let bound_port = handle
                .bound_proxy_addr()
                .map(|a| a.port())
                .unwrap_or_else(|| listen_addr.port());

            let stream = match UnixStream::connect(&helper_socket).await {
                Ok(s) => Arc::new(s),
                Err(err) => {
                    let _ = handle.stop().await;
                    return Err(io::Error::new(
                        err.kind(),
                        format!(
                            "failed to connect to helper socket {}: {err}",
                            helper_socket.display()
                        ),
                    ));
                }
            };

            if let Err(err) = async_send_helper_command(
                &stream,
                &HelperCommand::StartSystemProxy {
                    listen_port: bound_port,
                    exceptions,
                },
            )
            .await
            {
                let _ = handle.stop().await;
                return Err(io::Error::other(format!(
                    "helper StartSystemProxy send failed: {err}"
                )));
            }
            match async_recv_helper_message(&stream).await {
                Ok((HelperMessage::Response(HelperResponse::SystemProxyReady { .. }), _)) => {}
                Ok((HelperMessage::Response(HelperResponse::Error { message }), _)) => {
                    let _ = handle.stop().await;
                    return Err(io::Error::other(message));
                }
                Ok((other, _)) => {
                    let _ = handle.stop().await;
                    return Err(io::Error::other(format!(
                        "unexpected helper reply to StartSystemProxy: {other:?}"
                    )));
                }
                Err(err) => {
                    let _ = handle.stop().await;
                    return Err(io::Error::other(format!(
                        "helper StartSystemProxy recv failed: {err}"
                    )));
                }
            }

            let (cmd_tx, mut cmd_rx) =
                mpsc::channel::<(HelperCommand, Option<tokio::sync::oneshot::Sender<()>>)>(8);
            let helper_watch_task = tokio::spawn(async move {
                let mut ignored_net_change = None;
                while let Some((cmd, ack)) = cmd_rx.recv().await {
                    let is_stop = matches!(cmd, HelperCommand::Stop);
                    if async_send_helper_command(&stream, &cmd).await.is_err() {
                        break;
                    }
                    let _ = recv_next_helper_response(&stream, &mut ignored_net_change).await;
                    if let Some(done) = ack {
                        let _ = done.send(());
                    }
                    if is_stop {
                        break;
                    }
                }
            });

            let state_forward_task = spawn_state_forwarder(state_rx, None, out_tx);
            Ok(ActiveSession {
                handle: Arc::new(AsyncRwLock::new(Some(handle))),
                is_tun: false,
                utun_name: None,
                server_host,
                server_port,
                outbound_if_index: Arc::new(AtomicU32::new(0)),
                original_dns_servers: Arc::new(RwLock::new(Vec::new())),
                helper_cmd_tx: Some(cmd_tx),
                state_forward_task,
                helper_watch_task: Some(helper_watch_task),
            })
        }
        EngineLaunchMode::DirectTunFd {
            tun_fd,
            outbound_if_index,
        } => {
            let server_ips = resolve_server_host_ips(&server_host, server_port).await?;
            let mut cfg = EngineConfig::new_tun(
                profile,
                tun_fd,
                true,
                cfg!(target_os = "macos"),
                outbound_if_index,
            );
            cfg.dns_resolver = dns_resolver;
            cfg.bypass_cidrs = bypass_cidrs;
            cfg.bypass_domains = bypass_domains;

            let (handle, state_rx) =
                EngineHandle::start_with_pinned_server_ips(cfg, server_ips).await?;
            let state_forward_task = spawn_state_forwarder(state_rx, None, out_tx);
            Ok(ActiveSession {
                handle: Arc::new(AsyncRwLock::new(Some(handle))),
                is_tun: true,
                utun_name: None,
                server_host,
                server_port,
                outbound_if_index: Arc::new(AtomicU32::new(outbound_if_index.unwrap_or(0))),
                original_dns_servers: Arc::new(RwLock::new(Vec::new())),
                helper_cmd_tx: None,
                state_forward_task,
                helper_watch_task: None,
            })
        }
        EngineLaunchMode::Tun { helper_socket } => {
            // Resolve VLESS server host BEFORE installing TUN routes (`PLAN.md` §5.2).
            let server_ips = resolve_server_host_ips(&server_host, server_port).await?;
            let effective_cidrs = merged_tun_bypass_cidrs(&bypass_cidrs);

            let sock = UnixStream::connect(&helper_socket).await.map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "failed to connect to helper socket {}: {err}",
                        helper_socket.display()
                    ),
                )
            })?;

            async_send_helper_command(
                &sock,
                &HelperCommand::StartTun {
                    server_ips: server_ips.clone(),
                    bypass_cidrs: effective_cidrs.clone(),
                    dns_resolver,
                },
            )
            .await
            .map_err(|e| io::Error::other(format!("helper StartTun send failed: {e}")))?;

            let (utun_name, initial_if_index, initial_dns_servers, utun_fd) =
                match async_recv_helper_message(&sock)
                    .await
                    .map_err(|e| io::Error::other(format!("helper StartTun recv failed: {e}")))?
                {
                    (
                        HelperMessage::Response(HelperResponse::TunReady {
                            utun_name,
                            outbound_if_index,
                            original_dns_servers,
                            ..
                        }),
                        Some(fd),
                    ) => (utun_name, outbound_if_index, original_dns_servers, fd),
                    (HelperMessage::Response(HelperResponse::Error { message }), _) => {
                        return Err(io::Error::other(message));
                    }
                    (other, _) => {
                        return Err(io::Error::other(format!(
                            "unexpected helper reply to StartTun (or missing utun fd): {other:?}"
                        )));
                    }
                };

            let raw_utun_fd = utun_fd.into_raw_fd();

            let mut cfg = EngineConfig::new_tun(
                profile,
                raw_utun_fd,
                true,
                cfg!(target_os = "macos"),
                Some(initial_if_index),
            );
            cfg.dns_resolver = dns_resolver;
            cfg.bypass_cidrs = effective_cidrs;
            cfg.bypass_domains = bypass_domains;

            let (handle, state_rx) =
                match EngineHandle::start_with_pinned_server_ips(cfg, server_ips).await {
                    Ok(pair) => pair,
                    Err(err) => {
                        let _ = async_send_helper_command(&sock, &HelperCommand::Stop).await;
                        let _ = async_recv_helper_message(&sock).await;
                        return Err(err);
                    }
                };

            let pinned_resolver = handle.server_endpoint_resolver();
            let handle_slot = Arc::new(AsyncRwLock::new(Some(handle)));
            let active_if_idx = Arc::new(AtomicU32::new(initial_if_index));
            let shared_dns = Arc::new(RwLock::new(initial_dns_servers));

            let (cmd_tx, mut cmd_rx) =
                mpsc::channel::<(HelperCommand, Option<tokio::sync::oneshot::Sender<()>>)>(8);
            let watch_ctx = TunWatchContext {
                handle_slot: handle_slot.clone(),
                active_if_idx: active_if_idx.clone(),
                shared_dns: shared_dns.clone(),
                pinned_resolver,
                server_host: server_host.clone(),
                server_port,
                sock,
                utun_name: utun_name.clone(),
                out_tx: out_tx.clone(),
            };

            let helper_watch_task = tokio::spawn(async move {
                let mut deferred_net_change: Option<(u32, String, Vec<IpAddr>)> = None;
                loop {
                    if let Some((if_idx, if_name, orig_dns)) = deferred_net_change.take() {
                        watch_ctx
                            .apply_network_change(
                                if_idx,
                                if_name,
                                orig_dns,
                                &mut deferred_net_change,
                            )
                            .await;
                        continue;
                    }

                    tokio::select! {
                        Some((cmd, ack)) = cmd_rx.recv() => {
                            let is_stop = matches!(cmd, HelperCommand::Stop);
                            if async_send_helper_command(&watch_ctx.sock, &cmd).await.is_err() {
                                break;
                            }
                            if let Ok(HelperResponse::ServerRouteUpdated {
                                outbound_if_index: updated_idx,
                                original_dns_servers: updated_dns,
                                ..
                            }) = recv_next_helper_response(&watch_ctx.sock, &mut deferred_net_change).await
                            {
                                watch_ctx.active_if_idx.store(updated_idx, Ordering::Release);
                                if !updated_dns.is_empty() {
                                    *watch_ctx.shared_dns.write() = updated_dns;
                                }
                                if let Some(ref h) = *watch_ctx.handle_slot.read().await {
                                    h.set_outbound_interface_index(Some(updated_idx));
                                }
                            }
                            if let Some(done) = ack {
                                let _ = done.send(());
                            }
                            if is_stop {
                                break;
                            }
                        }
                        msg = async_recv_helper_message(&watch_ctx.sock) => {
                            match msg {
                                Ok((
                                    HelperMessage::NetworkChanged {
                                        outbound_if_index,
                                        outbound_if_name,
                                        original_dns_servers,
                                    },
                                    _,
                                )) => {
                                    watch_ctx
                                        .apply_network_change(
                                            outbound_if_index,
                                            outbound_if_name,
                                            original_dns_servers,
                                            &mut deferred_net_change,
                                        )
                                        .await;
                                }
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            let state_forward_task =
                spawn_state_forwarder(state_rx, Some(utun_name.clone()), out_tx);
            Ok(ActiveSession {
                handle: handle_slot,
                is_tun: true,
                utun_name: Some(utun_name),
                server_host,
                server_port,
                outbound_if_index: active_if_idx,
                original_dns_servers: shared_dns,
                helper_cmd_tx: Some(cmd_tx),
                state_forward_task,
                helper_watch_task: Some(helper_watch_task),
            })
        }
    }
}

fn spawn_state_forwarder(
    mut rx: tokio::sync::watch::Receiver<EngineState>,
    utun_name: Option<String>,
    out_tx: mpsc::UnboundedSender<EngineToApp>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let st = rx.borrow_and_update().clone();
            let _ = out_tx.send(EngineToApp::State {
                status: st.status,
                detail: st.detail,
                listen_addr: st.listen_addr,
                utun_name: utun_name.clone(),
            });
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
}

async fn wait_for_shutdown_signal(#[cfg(unix)] mut sigterm: Option<tokio::signal::unix::Signal>) {
    #[cfg(unix)]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                match sigterm.as_mut() {
                    Some(s) => {
                        let _ = s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn run_standalone_cli(args: RunArgs) -> io::Result<()> {
    // Register SIGTERM handler BEFORE starting listeners or emitting the ready banner on stderr so
    // an immediate SIGTERM from a supervisor or CLI harness is caught cleanly rather than hitting
    // the kernel default disposition (`SIG_DFL` -> exit status 15).
    #[cfg(unix)]
    let sigterm = {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::terminate()).ok()
    };

    let max_level = match std::env::var("RUST_LOG")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "trace" => log::Level::Trace,
        "debug" => log::Level::Debug,
        "warn" => log::Level::Warn,
        "error" => log::Level::Error,
        _ => log::Level::Info,
    };
    let logger = Box::new(StderrLogger { max_level });
    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(max_level.to_level_filter());
    }

    for warning in &args.warnings {
        eprintln!("warning: {warning}");
    }

    let handle = match args.mode {
        RunInboundMode::MixedProxy { listen_addr } => {
            if args.outbound_if_index.is_some() {
                set_outbound_interface_index(args.outbound_if_index);
            }
            let mut cfg = EngineConfig::new_mixed_proxy(args.profile, listen_addr);
            cfg.dns_resolver = args.dns_resolver;
            cfg.bypass_cidrs = args.bypass_cidrs;
            cfg.bypass_domains = args.bypass_domains;

            let (handle, mut state_rx) = EngineHandle::start(cfg).await?;
            let bound = handle.bound_proxy_addr().unwrap_or(listen_addr);
            log::info!("vless-engine listening on {bound} (HTTP/1.1 + SOCKS5)");

            tokio::spawn(async move {
                while state_rx.changed().await.is_ok() {
                    let st = state_rx.borrow_and_update().clone();
                    if st.status == EngineStatus::Error
                        && let Some(detail) = st.detail
                    {
                        log::error!("{detail}");
                    }
                }
            });
            handle
        }
        RunInboundMode::TunFd { raw_fd, af_header } => {
            let server_ips =
                resolve_server_host_ips(&args.profile.server_host, args.profile.server_port)
                    .await?;
            let mut cfg = EngineConfig::new_tun(
                args.profile,
                raw_fd,
                true,
                af_header,
                args.outbound_if_index,
            );
            cfg.dns_resolver = args.dns_resolver;
            cfg.bypass_cidrs = merged_tun_bypass_cidrs(&args.bypass_cidrs);
            cfg.bypass_domains = args.bypass_domains;

            let (handle, mut state_rx) =
                EngineHandle::start_with_pinned_server_ips(cfg, server_ips).await?;
            log::info!("vless-engine TUN stack started on fd {raw_fd}");

            tokio::spawn(async move {
                while state_rx.changed().await.is_ok() {
                    let st = state_rx.borrow_and_update().clone();
                    if st.status == EngineStatus::Error
                        && let Some(detail) = st.detail
                    {
                        log::error!("{detail}");
                    }
                }
            });
            handle
        }
    };

    #[cfg(unix)]
    wait_for_shutdown_signal(sigterm).await;
    #[cfg(not(unix))]
    wait_for_shutdown_signal().await;
    log::info!("Shutting down vless-engine...");
    let res = handle.stop().await;
    if args.outbound_if_index.is_some() {
        set_outbound_interface_index(None);
    }
    res
}

async fn run_ipc_loop() {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<EngineToApp>();

    let logger = Box::new(JsonStdoutLogger { tx: out_tx.clone() });
    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let writer_task = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(msg) = out_rx.recv().await {
            if write_json_line_async(&mut stdout, &msg).await.is_err() {
                break;
            }
        }
    });

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut session: Option<ActiveSession> = None;
    #[cfg(unix)]
    let shutdown_sig = {
        use tokio::signal::unix::{SignalKind, signal};
        wait_for_shutdown_signal(signal(SignalKind::terminate()).ok())
    };
    #[cfg(not(unix))]
    let shutdown_sig = wait_for_shutdown_signal();
    tokio::pin!(shutdown_sig);

    loop {
        tokio::select! {
            () = &mut shutdown_sig => {
                break;
            }
            line_res = read_json_line_async::<_, AppToEngine>(&mut stdin) => {
                match line_res {
                    Ok(Some(AppToEngine::Start {
                        profile,
                        mode,
                        dns_resolver,
                        bypass_cidrs,
                        bypass_domains,
                    })) => {
                        if let Some(prev) = session.take() {
                            prev.shutdown().await;
                        }
                        match start_session(
                            profile,
                            mode,
                            dns_resolver,
                            bypass_cidrs,
                            bypass_domains,
                            out_tx.clone(),
                        )
                        .await
                        {
                            Ok(s) => {
                                session = Some(s);
                            }
                            Err(err) => {
                                let _ = out_tx.send(EngineToApp::State {
                                    status: EngineStatus::Error,
                                    detail: Some(err.to_string()),
                                    listen_addr: None,
                                    utun_name: None,
                                });
                            }
                        }
                    }
                    Ok(Some(AppToEngine::RecheckServer)) => {
                        if let Some(ref active) = session {
                            if active.is_tun {
                                let dns_snapshot = active.original_dns_servers.read().clone();
                                let if_idx = match active.outbound_if_index.load(Ordering::Acquire) {
                                    0 => None,
                                    nz => Some(nz),
                                };
                                if let Ok(ips) = resolve_tun_server_ips(
                                    &active.server_host,
                                    active.server_port,
                                    &dns_snapshot,
                                    if_idx,
                                )
                                .await
                                {
                                    if let Some(ref h) = *active.handle.read().await {
                                        h.server_endpoint_resolver().update_server_ips(ips.clone());
                                    }
                                    if let Some(ref cmd_tx) = active.helper_cmd_tx {
                                        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                                        if cmd_tx
                                            .send((
                                                HelperCommand::UpdateServerRoute {
                                                    server_ips: ips,
                                                },
                                                Some(ack_tx),
                                            ))
                                            .await
                                            .is_ok()
                                        {
                                            let _ = tokio::time::timeout(
                                                Duration::from_secs(3),
                                                ack_rx,
                                            )
                                            .await;
                                        }
                                    }
                                }
                            } else if let Some(ref h) = *active.handle.read().await {
                                let _ = h.resolve_server_ips().await;
                            }

                            let check = match *active.handle.read().await {
                                Some(ref h) => h.recheck_server().await,
                                None => (false, None, Some("engine is not started".into())),
                            };
                            let _ = out_tx.send(EngineToApp::ServerCheck {
                                reachable: check.0,
                                rtt_ms: check.1,
                                error: check.2,
                            });
                        } else {
                            let _ = out_tx.send(EngineToApp::ServerCheck {
                                reachable: false,
                                rtt_ms: None,
                                error: Some("engine is not started".into()),
                            });
                        }
                    }
                    Ok(Some(AppToEngine::Stop)) | Ok(None) => {
                        break;
                    }
                    Err(err) => {
                        let _ = out_tx.send(EngineToApp::State {
                            status: EngineStatus::Error,
                            detail: Some(format!("invalid AppToEngine IPC message: {err}")),
                            listen_addr: None,
                            utun_name: session.as_ref().and_then(|s| s.utun_name.clone()),
                        });
                    }
                }
            }
        }
    }

    if let Some(active) = session.take() {
        active.shutdown().await;
    }

    let _ = out_tx.send(EngineToApp::State {
        status: EngineStatus::Stopped,
        detail: None,
        listen_addr: None,
        utun_name: None,
    });
    drop(out_tx);
    if tokio::time::timeout(Duration::from_secs(1), writer_task)
        .await
        .is_err()
    {
        let mut stdout = io::stdout().lock();
        let _ = write_json_line_sync(
            &mut stdout,
            &EngineToApp::State {
                status: EngineStatus::Stopped,
                detail: None,
                listen_addr: None,
                utun_name: None,
            },
        );
    }
}

/// Private pipe protocol used by the Android profile library.
fn import_profiles() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut text = String::new();
    const LIMIT: u64 = 1024 * 1024;
    io::stdin().take(LIMIT + 1).read_to_string(&mut text)?;
    if text.len() as u64 > LIMIT {
        return Err("subscription exceeds 1 MiB".into());
    }
    let profiles = vless_ipc::parse_profile_list(&text)?
        .into_iter()
        .map(|entry| {
            let p = entry.profile;
            serde_json::json!({"name":p.name,"endpoint":p.server_addr_display(),
            "security":if p.security.is_reality() { "REALITY + Vision" } else { "TLS" },
            "link":p.to_vless_link(), "warnings":entry.warnings})
        })
        .collect::<Vec<_>>();
    serde_json::to_writer(io::stdout().lock(), &profiles)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if std::env::args().skip(1).eq(["import-profiles"]) {
        if import_profiles().is_err() {
            eprintln!("Invalid VLESS link or subscription");
            std::process::exit(2);
        }
        return;
    }
    match parse_cli_args(std::env::args().skip(1)) {
        Ok(CliAction::Help(help_text)) => {
            print!("{help_text}");
        }
        Ok(CliAction::Version) => {
            println!("vless-engine {}", env!("CARGO_PKG_VERSION"));
        }
        Ok(CliAction::Ipc) => {
            run_ipc_loop().await;
        }
        Ok(CliAction::Run(run_args)) => {
            if let Err(err) = run_standalone_cli(*run_args).await {
                eprintln!("vless-engine: {err}");
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("vless-engine: {err}");
            std::process::exit(2);
        }
    }
}

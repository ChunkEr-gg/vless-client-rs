//! `vless-engine` — Embedded VLESS + XTLS-Vision + REALITY + XUDP + TUN library (`PLAN.md` §4, §6).
//!
//! Forked and trimmed from [`cfal/shoes`](https://github.com/cfal/shoes) (`7680938b`, MIT):
//! - Outbound: VLESS over REALITY (with X25519 + X25519MLKEM768) or TLS 1.3 (`kTLS`), with or
//!   without `xtls-rprx-vision`, plus XUDP session-multiplexed UDP (`COMMAND_MUX`).
//! - Inbound:
//!   - [`EngineInbound::MixedProxy`]: auto-detected HTTP/1.x CONNECT + SOCKS5 (with UDP ASSOCIATE).
//!   - [`EngineInbound::Tun`]: `smoltcp` userspace TCP/IP stack + session-based UDP NAT + port-53
//!     DNS-over-XUDP interception over a passed `utun` descriptor (`SCM_RIGHTS`).

pub mod address;
pub mod async_stream;
pub(crate) mod atomic;
pub(crate) mod buf_reader;
pub mod cli;
pub mod client_proxy_chain;
pub mod client_proxy_selector;
pub(crate) mod clock;
pub mod config;
pub mod copy_bidirectional;
pub mod copy_bidirectional_message;
pub mod crypto;
pub mod dns_proxy;
pub mod http_handler;
pub(crate) mod ip_stack;
pub(crate) mod listener_tasks;
pub mod mixed_handler;
pub(crate) mod network_tasks;
pub mod option_util;
pub(crate) mod prepend_stream;
pub mod reality;
pub mod resolver;
pub(crate) mod resources;
pub mod routing;
pub mod rules;
pub mod rustls_config_util;
pub(crate) mod sniff;
pub(crate) mod socket_policy;
pub mod socket_util;
pub mod socks5_udp_relay;
pub mod socks_handler;
pub mod stream_reader;
pub(crate) mod sync_adapter;
pub mod tcp;
pub mod tls_client_handler;
pub mod tun;
pub mod util;
pub(crate) mod uuid_util;
pub mod vless;
pub mod xudp;

#[cfg(test)]
mod e2e_tests;

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use config::{
    EngineConfig, EngineInbound, GlobalLimits, if_index_to_name, tun::TunResourceLimits,
};
pub use reality::generate_keypair as generate_reality_keypair;
pub use resolver::{resolve_host_via_udp_dns, resolve_host_via_udp_dns_addrs};
pub use socket_policy::{outbound_interface_index, set_outbound_interface_index};
pub use vless_ipc::{
    EngineStatus, Profile, ProfileError, ProfileSecurity, REALITY_AUTH_OR_CLOCK_ERROR,
    parse_vless_link,
};

use crate::address::NetLocation;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::TcpConfig;
use crate::mixed_handler::MixedTcpServerHandler;
use crate::network_tasks::NetworkLifetime;
use crate::resolver::{CachingNativeResolver, Resolver, ServerEndpointResolver, resolve_addresses};
use crate::socket_util::{new_tcp_listener, new_tcp_socket_for_peer};
use crate::tcp::chain_builder::build_selector_from_engine_config;
use crate::tcp::socket_connector_impl::connect_tcp_candidates;
use crate::tcp::tcp_server::{StreamErrorCallback, run_tcp_listener};
use crate::tun::{TunServerConfig, run_tun_with_owned_fd};

/// Snapshot of the running engine's lifecycle state and optional diagnostic detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineState {
    pub status: EngineStatus,
    pub detail: Option<String>,
    pub listen_addr: Option<SocketAddr>,
}

/// Handle to a running VLESS engine instance (`MixedProxy` or `Tun` mode).
pub struct EngineHandle {
    config: EngineConfig,
    selector: Arc<ClientProxySelector>,
    caching_resolver: Arc<CachingNativeResolver>,
    server_resolver: Arc<ServerEndpointResolver>,
    cancel: CancellationToken,
    tun_shutdown_tx: Option<oneshot::Sender<()>>,
    network_lifetime: NetworkLifetime,
    state_rx: watch::Receiver<EngineState>,
    state_tx: Arc<watch::Sender<EngineState>>,
    bound_proxy_addr: Option<SocketAddr>,
    owns_outbound_if_policy: AtomicBool,
    worker: Option<JoinHandle<std::io::Result<()>>>,
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("state", &*self.state_rx.borrow())
            .field("bound_proxy_addr", &self.bound_proxy_addr)
            .finish()
    }
}

impl EngineHandle {
    /// Validates `config` and starts the local `MixedProxy` listener or `smoltcp` `Tun` stack.
    pub async fn start(
        config: EngineConfig,
    ) -> std::io::Result<(Self, watch::Receiver<EngineState>)> {
        Self::start_with_pinned_server_ips(config, Vec::new()).await
    }

    /// Starts the engine with pre-resolved `server_ips` pinned in [`ServerEndpointResolver`] so
    /// outbound VLESS connections in TUN mode never trigger recursive system DNS queries.
    pub async fn start_with_pinned_server_ips(
        config: EngineConfig,
        pinned_server_ips: Vec<IpAddr>,
    ) -> std::io::Result<(Self, watch::Receiver<EngineState>)> {
        config.validate()?;
        crate::resources::configure(config.limits)?;

        let caching_resolver = Arc::new(CachingNativeResolver::new());
        let server_resolver = Arc::new(ServerEndpointResolver::new(
            &config.profile.server_host,
            pinned_server_ips,
            caching_resolver.clone(),
        ));
        let resolver_dyn: Arc<dyn Resolver> = server_resolver.clone();
        let selector = build_selector_from_engine_config(&config, resolver_dyn.clone())?;

        let initial_state = EngineState {
            status: EngineStatus::Starting,
            detail: None,
            listen_addr: None,
        };
        let (state_tx, state_rx) = watch::channel(initial_state);
        let state_tx = Arc::new(state_tx);

        let state_tx_for_err = state_tx.clone();
        let on_error: StreamErrorCallback = Arc::new(move |err: &std::io::Error| {
            let msg = err.to_string();
            if msg.contains(REALITY_AUTH_OR_CLOCK_ERROR) {
                state_tx_for_err.send_modify(|st| {
                    st.status = EngineStatus::Error;
                    st.detail = Some(REALITY_AUTH_OR_CLOCK_ERROR.to_string());
                });
            }
        });
        selector.set_dns_error_callback(Some(on_error.clone()));

        let cancel = CancellationToken::new();
        let network_lifetime = NetworkLifetime::default();

        match config.inbound {
            EngineInbound::MixedProxy { listen_addr } => {
                let tokio_listener = Arc::new(new_tcp_listener(listen_addr, 1024, None)?);
                let bound_addr = tokio_listener.local_addr()?;

                let handler = Arc::new(MixedTcpServerHandler::new(
                    None,
                    true,
                    bound_addr.ip(),
                    selector.clone(),
                    resolver_dyn.clone(),
                ));

                let _ = state_tx.send(EngineState {
                    status: EngineStatus::Connected,
                    detail: None,
                    listen_addr: Some(bound_addr),
                });

                let worker_cancel = cancel.clone();
                let worker_state = state_tx.clone();
                let lifetime = network_lifetime.clone();

                let worker = tokio::spawn(async move {
                    let res = lifetime
                        .scope(run_tcp_listener(
                            tokio_listener,
                            TcpConfig::default(),
                            resolver_dyn,
                            handler,
                            worker_cancel,
                            Some(on_error),
                        ))
                        .await;
                    if let Err(ref e) = res {
                        let _ = worker_state.send(EngineState {
                            status: EngineStatus::Error,
                            detail: Some(e.to_string()),
                            listen_addr: Some(bound_addr),
                        });
                    }
                    res
                });

                let rx_clone = state_rx.clone();
                Ok((
                    Self {
                        config,
                        selector,
                        caching_resolver,
                        server_resolver,
                        cancel,
                        tun_shutdown_tx: None,
                        network_lifetime,
                        state_rx,
                        state_tx,
                        bound_proxy_addr: Some(bound_addr),
                        owns_outbound_if_policy: AtomicBool::new(false),
                        worker: Some(worker),
                    },
                    rx_clone,
                ))
            }
            EngineInbound::Tun {
                raw_fd,
                close_fd_on_drop,
                packet_information,
                mtu,
                outbound_if_index,
            } => {
                // SAFETY: `fcntl(raw_fd, F_GETFD)` safely checks that `raw_fd` is an open descriptor
                // before constructing an I/O-safe `OwnedFd` / `BorrowedFd`.
                if unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let owned_fd = if close_fd_on_drop {
                    // SAFETY: Caller transferred ownership (`close_fd_on_drop = true`) of validated `raw_fd`.
                    unsafe { OwnedFd::from_raw_fd(raw_fd) }
                } else {
                    // SAFETY: `raw_fd` was validated open above and remains valid for `try_clone_to_owned`.
                    unsafe { BorrowedFd::borrow_raw(raw_fd) }.try_clone_to_owned()?
                };
                let has_outbound_if = outbound_if_index.is_some_and(|idx| idx != 0);
                if has_outbound_if {
                    crate::socket_policy::set_outbound_interface_index(outbound_if_index);
                }

                let tun_cfg = TunServerConfig::new()
                    .mtu(mtu)
                    .resource_limits(config.tun_limits.clone())
                    .packet_information(packet_information)
                    .close_fd_on_drop(true)
                    .tcp_enabled(true)
                    .udp_enabled(true)
                    .icmp_enabled(true);

                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let (ready_tx, ready_rx) = oneshot::channel();
                let worker_state = state_tx.clone();
                let lifetime = network_lifetime.clone();

                let selector_for_tun = selector.clone();
                let worker = tokio::spawn(async move {
                    let res = lifetime
                        .scope(run_tun_with_owned_fd(
                            owned_fd,
                            tun_cfg,
                            selector_for_tun,
                            resolver_dyn,
                            shutdown_rx,
                            Some(ready_tx),
                            Some(on_error),
                        ))
                        .await;
                    if let Err(ref e) = res {
                        let _ = worker_state.send(EngineState {
                            status: EngineStatus::Error,
                            detail: Some(e.to_string()),
                            listen_addr: None,
                        });
                    }
                    res
                });

                match ready_rx.await {
                    Ok(Ok(())) => {
                        state_tx.send_if_modified(|st| {
                            if st.status == EngineStatus::Starting {
                                st.status = EngineStatus::Connected;
                                true
                            } else {
                                false
                            }
                        });
                    }
                    Ok(Err(err)) => {
                        if has_outbound_if {
                            crate::socket_policy::set_outbound_interface_index(None);
                        }
                        let _ = worker.await;
                        return Err(err);
                    }
                    Err(_) => {
                        if has_outbound_if {
                            crate::socket_policy::set_outbound_interface_index(None);
                        }
                        let _ = worker.await;
                        return Err(std::io::Error::other(
                            "TUN stack exited before completing initialization",
                        ));
                    }
                }

                let rx_clone = state_rx.clone();
                Ok((
                    Self {
                        config,
                        selector,
                        caching_resolver,
                        server_resolver,
                        cancel,
                        tun_shutdown_tx: Some(shutdown_tx),
                        network_lifetime,
                        state_rx,
                        state_tx,
                        bound_proxy_addr: None,
                        owns_outbound_if_policy: AtomicBool::new(has_outbound_if),
                        worker: Some(worker),
                    },
                    rx_clone,
                ))
            }
        }
    }

    /// Returns a cloned [`watch::Receiver`] tracking [`EngineState`] updates.
    pub fn state_subscribe(&self) -> watch::Receiver<EngineState> {
        self.state_rx.clone()
    }

    /// Returns the latest [`EngineState`].
    pub fn current_state(&self) -> EngineState {
        self.state_rx.borrow().clone()
    }

    /// Returns the bound `127.0.0.1:<port>` address when running in `MixedProxy` mode.
    pub fn bound_proxy_addr(&self) -> Option<SocketAddr> {
        self.bound_proxy_addr
    }

    /// Returns the shared [`ServerEndpointResolver`] so callers can atomically refresh pinned IPs.
    pub fn server_endpoint_resolver(&self) -> Arc<ServerEndpointResolver> {
        self.server_resolver.clone()
    }

    /// Updates the live outbound physical interface index (`IP_BOUND_IF` / `IPV6_BOUND_IF` on
    /// macOS) applied to all new outbound TCP and UDP sockets (`PLAN.md` §5.2, §5.5).
    pub fn set_outbound_interface_index(&self, index: Option<u32>) {
        let prev = crate::socket_policy::outbound_interface_index().map_or(0, |nz| nz.get());
        let next = index.unwrap_or(0);
        let active = next != 0;
        self.owns_outbound_if_policy
            .store(active, Ordering::Release);
        crate::socket_policy::set_outbound_interface_index(index);
        if prev != next {
            self.caching_resolver.clear_cache();
            self.selector.notify_network_changed();
        }
    }

    /// Re-resolves the VLESS server address (bypassing cached DNS entries), updates pinned IPs,
    /// and returns the resolved IP list.
    pub async fn resolve_server_ips(&self) -> std::io::Result<Vec<IpAddr>> {
        self.caching_resolver.clear_cache();
        let loc: NetLocation = self.config.server_location()?;
        let resolver_dyn: Arc<dyn Resolver> = self.caching_resolver.clone();
        let addrs = resolve_addresses(&resolver_dyn, &loc).await?;
        let mut ips = Vec::with_capacity(addrs.len());
        for sa in addrs {
            if !ips.contains(&sa.ip()) {
                ips.push(sa.ip());
            }
        }
        self.server_resolver.update_server_ips(ips.clone());
        Ok(ips)
    }

    /// Probes VLESS server TCP reachability (used on wake / `RecheckServer`, `PLAN.md` §5.5).
    ///
    /// Uses [`ServerEndpointResolver`] so TUN sessions probe pinned server IPs directly (never
    /// recursing through tunnel DNS), while MixedProxy sessions resolve fresh via OS DNS.
    pub async fn recheck_server(&self) -> (bool, Option<u64>, Option<String>) {
        self.caching_resolver.clear_cache();
        self.selector.notify_network_changed();
        let loc = match self.config.server_location() {
            Ok(l) => l,
            Err(e) => return (false, None, Some(e.to_string())),
        };
        let resolver_dyn: Arc<dyn Resolver> = self.server_resolver.clone();
        let addrs = match resolve_addresses(&resolver_dyn, &loc).await {
            Ok(a) => a,
            Err(e) => return (false, None, Some(format!("DNS resolution failed: {e}"))),
        };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let bind_if: Option<String> = None;
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let bind_if = self.config.outbound_interface_name();
        let start = Instant::now();
        let probe = tokio::time::timeout(
            Duration::from_secs(5),
            connect_tcp_candidates(addrs, |addr| {
                let sock = match new_tcp_socket_for_peer(bind_if.clone(), addr) {
                    Ok(s) => s,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::PermissionDenied
                            && bind_if.is_some() =>
                    {
                        new_tcp_socket_for_peer(None, addr)?
                    }
                    Err(e) => return Err(e),
                };
                Ok(sock.connect(addr))
            }),
        )
        .await;
        match probe {
            Ok(Ok(stream)) => {
                let rtt = start.elapsed().as_millis() as u64;
                drop(stream);
                let cur = self.state_tx.borrow().clone();
                if cur.status == EngineStatus::Reconnecting {
                    self.state_tx.send_modify(|st| {
                        st.status = EngineStatus::Connected;
                        st.detail = None;
                    });
                }
                (true, Some(rtt), None)
            }
            Ok(Err(e)) => (false, None, Some(e.to_string())),
            Err(_) => (
                false,
                None,
                Some("server TCP reachability probe timed out".into()),
            ),
        }
    }

    /// Gracefully stops the listener or TUN stack, drains spawned tasks, and awaits completion.
    pub async fn stop(mut self) -> std::io::Result<()> {
        let listen_addr = self.bound_proxy_addr;
        let _ = self.state_tx.send(EngineState {
            status: EngineStatus::Disconnecting,
            detail: None,
            listen_addr,
        });
        self.cancel.cancel();
        if let Some(tx) = self.tun_shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.network_lifetime.cancel();

        let mut join_res = Ok(());
        if let Some(mut worker) = self.worker.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut worker).await {
                Ok(Ok(res)) => join_res = res,
                Ok(Err(join_err)) if !join_err.is_cancelled() => {
                    join_res = Err(std::io::Error::other(format!(
                        "engine worker panicked: {join_err}"
                    )));
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    worker.abort();
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), self.network_lifetime.wait()).await;
        if self.owns_outbound_if_policy.swap(false, Ordering::AcqRel) {
            crate::socket_policy::set_outbound_interface_index(None);
        }
        let _ = self.state_tx.send(EngineState {
            status: EngineStatus::Stopped,
            detail: None,
            listen_addr: None,
        });
        join_res
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(tx) = self.tun_shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.network_lifetime.cancel();
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
        if self.owns_outbound_if_policy.swap(false, Ordering::AcqRel) {
            crate::socket_policy::set_outbound_interface_index(None);
        }
    }
}

/// Resolves a VLESS server `host:port` to unique IP addresses using the OS resolver before any
/// TUN routing table changes are applied (`PLAN.md` §5.3).
pub async fn resolve_server_host_ips(host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
    let addr = crate::address::Address::from(host)?;
    let loc = NetLocation::new(addr, port);
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let sock_addrs = resolve_addresses(&resolver, &loc).await?;
    let mut ips = Vec::with_capacity(sock_addrs.len());
    for sa in sock_addrs {
        if !ips.contains(&sa.ip()) {
            ips.push(sa.ip());
        }
    }
    Ok(ips)
}

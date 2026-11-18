//! Asynchronous Unix domain socket daemon loop, `launchd` idle/teardown lifecycle, caller UID
//! gatekeeping, and `SCM_RIGHTS` `utun` descriptor delivery (`PLAN.md` §4, §5.1–§5.5).

use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use vless_ipc::{
    DEFAULT_HELPER_OWNER_UID_PATH, DEFAULT_HELPER_STATE_PATH, HelperCommand, HelperMessage,
    HelperMode, HelperResponse, HelperStatus, async_send_helper_message,
    async_try_recv_frame_with_fd,
};

use crate::auth::OwnerUidPolicy;
use crate::backend::SystemBackend;
use crate::error::HelperError;
use crate::journal::recover_if_present;
use crate::launchd::{LaunchdActivation, claim_launchd_sockets, tokio_listener_from_owned_fd};
use crate::state_machine::HelperStateMachine;

/// Default grace window when launched by `launchd` (`RunAtLoad = true`) with no active session.
pub const DEFAULT_LAUNCHD_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Non-blocking reactor poll window used after session teardown to check whether another client
/// connection is already queued in the kernel listen backlog before exiting `0`.
const PENDING_ACCEPT_POLL_WINDOW: Duration = Duration::from_millis(10);

/// Timeout applied to secondary connections arriving while an engine session already owns the
/// helper (used to answer read-only `Status` queries or return a busy error).
const SECONDARY_CONN_TIMEOUT: Duration = Duration::from_secs(1);

/// Controls when the daemon process exits after startup recovery or session teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonLifecycle {
    /// `launchd` socket-activated mode (`PLAN.md` §4):
    /// - Waits up to `idle_grace_timeout` for an authorized client at startup; exits `0` if idle.
    /// - After an active session tears down, checks for an immediately pending connection and exits
    ///   `0` if none is queued (`KeepAlive = { SuccessfulExit = false }`).
    LaunchdSocketActivated { idle_grace_timeout: Duration },
    /// Standalone `--socket <path>` mode: serves sequential sessions until shutdown is signalled.
    StandaloneSocket,
}

/// Runtime configuration for `vless-tray-helper`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperConfig {
    pub state_path: PathBuf,
    pub owner_uid_policy: OwnerUidPolicy,
    pub lifecycle: DaemonLifecycle,
}

impl Default for HelperConfig {
    fn default() -> Self {
        Self {
            state_path: PathBuf::from(DEFAULT_HELPER_STATE_PATH),
            owner_uid_policy: OwnerUidPolicy::OwnerFile {
                path: PathBuf::from(DEFAULT_HELPER_OWNER_UID_PATH),
                enforce_root_owner_file: cfg!(target_os = "macos"),
            },
            lifecycle: DaemonLifecycle::LaunchdSocketActivated {
                idle_grace_timeout: DEFAULT_LAUNCHD_IDLE_TIMEOUT,
            },
        }
    }
}

/// Performs `--recover-only`: restores any leftover `helper-state.json` via `backend`, deletes it,
/// and returns whether recovery ran.
pub fn run_recover_only<B: SystemBackend>(
    backend: &B,
    state_path: &Path,
) -> Result<bool, HelperError> {
    recover_if_present(backend, state_path)
}

/// Entrypoint for production / CLI execution:
/// 1. Attempts `launch_activate_socket("Listeners", ...)` on macOS.
/// 2. If not launched with an activated socket:
///    - Binds `explicit_socket` (`--socket <path>`) if supplied.
///    - Otherwise performs leftover `helper-state.json` recovery and returns `Ok(())` (exit `0`).
pub async fn run_daemon_entrypoint<B: SystemBackend>(
    backend: Arc<B>,
    mut config: HelperConfig,
    explicit_socket: Option<&Path>,
) -> Result<(), HelperError> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_os_signal_watcher(shutdown_tx);

    match claim_launchd_sockets()? {
        LaunchdActivation::Activated(mut fds) => {
            // `io.vless-tray.helper.plist` declares a single Unix stream socket under `Listeners`.
            let primary_fd = fds.remove(0);
            drop(fds);
            serve_activated_listener_fd(primary_fd, backend, config, shutdown_rx).await
        }
        LaunchdActivation::NotManagedByLaunchd => {
            if let Some(sock_path) = explicit_socket {
                config.lifecycle = DaemonLifecycle::StandaloneSocket;
                serve_bound_socket_path(sock_path, backend, config, shutdown_rx).await
            } else {
                // Direct invocation or RunAtLoad check without socket: recover journal and exit 0.
                let _ = recover_if_present(&*backend, &config.state_path)?;
                Ok(())
            }
        }
    }
}

/// Serves `vless-tray-helper` on a pre-bound Unix stream listener `OwnedFd` (from `launchd` on
/// macOS or a socket-activation integration test harness on Linux).
pub async fn serve_activated_listener_fd<B: SystemBackend>(
    listener_fd: OwnedFd,
    backend: Arc<B>,
    config: HelperConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), HelperError> {
    let listener = tokio_listener_from_owned_fd(listener_fd)?;
    serve_tokio_listener(listener, backend, config, shutdown_rx).await
}

/// Binds a Unix domain stream socket at `socket_path` and serves `vless-tray-helper` until
/// `shutdown_rx` signals `true`.
pub async fn serve_bound_socket_path<B: SystemBackend>(
    socket_path: &Path,
    backend: Arc<B>,
    config: HelperConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), HelperError> {
    prepare_socket_path(socket_path)?;
    let listener = TokioUnixListener::bind(socket_path)?;
    let result = serve_tokio_listener(listener, backend, config, shutdown_rx).await;
    cleanup_socket_path(socket_path);
    result
}

/// Core async event loop serving `listener` against `HelperStateMachine<B>`.
pub async fn serve_tokio_listener<B: SystemBackend>(
    listener: TokioUnixListener,
    backend: Arc<B>,
    config: HelperConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), HelperError> {
    let mut state_machine = HelperStateMachine::new(backend, config.state_path.clone());

    // Always recover any leftover journal from an earlier crash/power-loss BEFORE accepting new
    // client commands (`PLAN.md` §5.1).
    let _ = state_machine.recover_leftover_journal()?;

    let mut route_rx = state_machine.backend().subscribe_route_changes()?;
    let mut pending_authorized_stream: Option<TokioUnixStream> = None;

    loop {
        let session_stream = if let Some(stream) = pending_authorized_stream.take() {
            stream
        } else {
            match accept_next_authorized_client(&listener, &config, &mut shutdown_rx).await? {
                Some(stream) => stream,
                None => {
                    // Clean idle grace timeout (`RunAtLoad`) or shutdown signal while Idle.
                    state_machine.stop()?;
                    return Ok(());
                }
            }
        };

        let shutdown_triggered = run_active_session(
            session_stream,
            &listener,
            &config,
            &mut state_machine,
            &mut route_rx,
            &mut shutdown_rx,
        )
        .await?;

        // Guarantee 100% state restoration and journal removal whenever the session ends (`Stop`,
        // client EOF, `kill -9`, protocol error, or `SIGTERM`).
        state_machine.stop()?;

        if shutdown_triggered || *shutdown_rx.borrow() {
            return Ok(());
        }

        match config.lifecycle {
            DaemonLifecycle::StandaloneSocket => continue,
            DaemonLifecycle::LaunchdSocketActivated { .. } => {
                // Check if another authorized client connection is already queued in the kernel
                // backlog; if none is immediately pending, exit 0 so nothing runs as root while
                // idle (`PLAN.md` §4).
                match poll_immediately_pending_authorized(&listener, &config.owner_uid_policy).await
                {
                    Some(next_stream) => {
                        pending_authorized_stream = Some(next_stream);
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn accept_next_authorized_client(
    listener: &TokioUnixListener,
    config: &HelperConfig,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<Option<TokioUnixStream>, HelperError> {
    if *shutdown_rx.borrow() {
        return Ok(None);
    }

    // Use a fixed deadline so rejected unauthorized connections cannot extend the root daemon's
    // idle lifetime under `launchd`.
    let maybe_deadline = match config.lifecycle {
        DaemonLifecycle::LaunchdSocketActivated { idle_grace_timeout } => {
            Some(Instant::now() + idle_grace_timeout)
        }
        DaemonLifecycle::StandaloneSocket => None,
    };

    loop {
        tokio::select! {
            biased;

            changed = shutdown_rx.changed() => {
                let _ = changed;
                if *shutdown_rx.borrow() {
                    return Ok(None);
                }
            }

            accept_res = listener.accept() => {
                let (stream, _addr) = accept_res?;
                match config.owner_uid_policy.authenticate_stream(&stream) {
                    Ok(_uid) => return Ok(Some(stream)),
                    Err(err) => {
                        log::warn!("rejecting unauthorized peer on helper socket: {err}");
                        drop(stream);
                    }
                }
            }

            () = async {
                if let Some(deadline) = maybe_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                log::debug!("no authorized client connected within launchd idle grace window; exiting 0");
                return Ok(None);
            }
        }
    }
}

/// Runs a single authorized client session until EOF, protocol error, post-`Stop` idle timeout, or
/// daemon shutdown. Returns `Ok(true)` if daemon shutdown was requested.
async fn run_active_session<B: SystemBackend>(
    session_stream: TokioUnixStream,
    listener: &TokioUnixListener,
    config: &HelperConfig,
    state_machine: &mut HelperStateMachine<B>,
    route_rx: &mut mpsc::Receiver<()>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool, HelperError> {
    let mut idle_session_deadline = idle_deadline_for_mode(config.lifecycle, state_machine.mode());

    loop {
        if *shutdown_rx.borrow() {
            return Ok(true);
        }

        tokio::select! {
            biased;

            changed = shutdown_rx.changed() => {
                let _ = changed;
                if *shutdown_rx.borrow() {
                    return Ok(true);
                }
            }

            frame_res = async_try_recv_frame_with_fd::<serde_json::Value>(&session_stream) => {
                match frame_res {
                    Ok(None) => {
                        // Peer closed session socket (clean disconnect or engine crash / kill -9).
                        return Ok(false);
                    }
                    Ok(Some((_val, Some(unexpected_fd)))) => {
                        drop(unexpected_fd);
                        let err_msg = HelperMessage::Response(HelperResponse::Error {
                            message: "unexpected SCM_RIGHTS file descriptor attached to HelperCommand".into(),
                        });
                        let _ = async_send_helper_message(&session_stream, &err_msg, None).await;
                        return Ok(false);
                    }
                    Ok(Some((raw_json, None))) => {
                        match serde_json::from_value::<HelperCommand>(raw_json) {
                            Err(parse_err) => {
                                let err_msg = HelperMessage::Response(HelperResponse::Error {
                                    message: format!("invalid helper command: {parse_err}"),
                                });
                                if async_send_helper_message(&session_stream, &err_msg, None).await.is_err() {
                                    return Ok(false);
                                }
                            }
                            Ok(cmd) => {
                                let outcome = state_machine.handle_command(cmd);
                                let reply = HelperMessage::Response(outcome.response);
                                let utun_fd = outcome.utun_fd;

                                let send_res = async_send_helper_message(
                                    &session_stream,
                                    &reply,
                                    utun_fd.as_ref().map(|fd| fd.as_fd()),
                                )
                                .await;

                                // CRITICAL (`PLAN.md` §4): Drop the helper's copy of `utun_fd`
                                // immediately after `SCM_RIGHTS` transmission so only `vless-engine`
                                // holds the descriptor!
                                drop(utun_fd);

                                if send_res.is_err() {
                                    return Ok(false);
                                }

                                idle_session_deadline =
                                    idle_deadline_for_mode(config.lifecycle, state_machine.mode());
                            }
                        }
                    }
                    Err(err) => {
                        log::debug!("helper session socket read terminated: {err}");
                        return Ok(false);
                    }
                }
            }

            maybe_route_evt = route_rx.recv() => {
                if maybe_route_evt.is_some() {
                    // Coalesce any queued bursts of PF_ROUTE messages before snapshotting.
                    while route_rx.try_recv().is_ok() {}
                    match state_machine.handle_route_change() {
                        Ok(Some(net_changed_msg)) => {
                            if async_send_helper_message(&session_stream, &net_changed_msg, None)
                                .await
                                .is_err()
                            {
                                return Ok(false);
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            log::warn!("failed to reconcile routes after PF_ROUTE event: {err}");
                        }
                    }
                }
            }

            extra_accept = listener.accept(), if state_machine.mode() != HelperMode::Idle => {
                if let Ok((extra_stream, _)) = extra_accept {
                    match config.owner_uid_policy.authenticate_stream(&extra_stream) {
                        Ok(_) => {
                            let status_snapshot = state_machine.status();
                            tokio::spawn(async move {
                                handle_secondary_authorized_connection(extra_stream, status_snapshot).await;
                            });
                        }
                        Err(err) => {
                            log::warn!("rejecting unauthorized secondary peer: {err}");
                            drop(extra_stream);
                        }
                    }
                }
            }

            () = async {
                if let Some(deadline) = idle_session_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                log::debug!("idle client session timed out under launchd mode; closing session");
                return Ok(false);
            }
        }
    }
}

fn idle_deadline_for_mode(lifecycle: DaemonLifecycle, mode: HelperMode) -> Option<Instant> {
    match (lifecycle, mode) {
        (DaemonLifecycle::LaunchdSocketActivated { idle_grace_timeout }, HelperMode::Idle) => {
            Some(Instant::now() + idle_grace_timeout)
        }
        _ => None,
    }
}

async fn handle_secondary_authorized_connection(
    stream: TokioUnixStream,
    current_status: HelperStatus,
) {
    let read_res = tokio::time::timeout(
        SECONDARY_CONN_TIMEOUT,
        async_try_recv_frame_with_fd::<serde_json::Value>(&stream),
    )
    .await;

    let Ok(Ok(Some((raw_json, maybe_fd)))) = read_res else {
        return;
    };
    if maybe_fd.is_some() {
        return;
    }

    let reply = match serde_json::from_value::<HelperCommand>(raw_json) {
        Ok(HelperCommand::Status) => {
            HelperMessage::Response(HelperResponse::Status(current_status))
        }
        Ok(_) => HelperMessage::Response(HelperResponse::Error {
            message: "another helper session is already active".into(),
        }),
        Err(err) => HelperMessage::Response(HelperResponse::Error {
            message: format!("invalid helper command: {err}"),
        }),
    };

    let _ = tokio::time::timeout(
        SECONDARY_CONN_TIMEOUT,
        async_send_helper_message(&stream, &reply, None),
    )
    .await;
}

async fn poll_immediately_pending_authorized(
    listener: &TokioUnixListener,
    policy: &OwnerUidPolicy,
) -> Option<TokioUnixStream> {
    let deadline = Instant::now() + PENDING_ACCEPT_POLL_WINDOW;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        match tokio::time::timeout_at(deadline, listener.accept()).await {
            Ok(Ok((stream, _addr))) => match policy.authenticate_stream(&stream) {
                Ok(_) => return Some(stream),
                Err(err) => {
                    log::warn!("rejecting unauthorized queued peer during teardown check: {err}");
                    drop(stream);
                }
            },
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}

fn prepare_socket_path(socket_path: &Path) -> Result<(), HelperError> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if meta.file_type().is_socket() {
                fs::remove_file(socket_path)?;
            } else {
                return Err(HelperError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing to unlink non-socket path {}",
                        socket_path.display()
                    ),
                )));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(HelperError::Io(err)),
    }
    Ok(())
}

fn cleanup_socket_path(socket_path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(socket_path)
        && meta.file_type().is_socket()
    {
        let _ = fs::remove_file(socket_path);
    }
}

fn spawn_os_signal_watcher(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };

        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("received SIGTERM; tearing down helper session cleanly");
            }
            _ = sigint.recv() => {
                log::info!("received SIGINT; tearing down helper session cleanly");
            }
        }
        let _ = shutdown_tx.send(true);
    });
}

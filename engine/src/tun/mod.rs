//! Userspace `smoltcp` TUN stack over `utun` (`OwnedFd`) (`PLAN.md` §5.3, §5.4, §6).

mod offload;
mod retained;
#[cfg(test)]
use crate::ip_stack::test_gate;
use crate::ip_stack::{packet, tcp_conn, wake};
#[allow(unused_imports)]
pub(crate) use retained::RetainedDevice;
mod tcp_stack_direct;
mod tun_server;
pub(crate) mod udp_handler;
pub(crate) mod udp_manager;

pub use tun_server::TunServerConfig;

use std::net::SocketAddr;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use log::{debug, info, warn};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use crate::address::{Address, NetLocation};
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::tcp::tcp_server::StreamErrorCallback;

use packet::PacketBuffer;
use tcp_stack_direct::{PACKET_QUEUE_CAPACITY, TcpStackDirect};
use udp_manager::TunUdpManager;

/// Runs the TUN packet engine over an already-validated [`OwnedFd`] (received from `vless-helper`
/// via `SCM_RIGHTS` on macOS, or a `UnixDatagram` socketpair in unit/integration tests).
pub async fn run_tun_with_owned_fd(
    fd: OwnedFd,
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut shutdown_rx: oneshot::Receiver<()>,
    mut ready: Option<oneshot::Sender<std::io::Result<()>>>,
    on_error: Option<StreamErrorCallback>,
) -> std::io::Result<()> {
    config.resource_limits.validate()?;
    info!(
        "Starting TUN server: mtu={}, pi={}, tcp={}, udp={}, icmp={}",
        config.mtu,
        config.packet_information,
        config.tcp_enabled,
        config.udp_enabled,
        config.icmp_enabled
    );

    let mut tcp_stack = TcpStackDirect::with_offload(fd, config.clone(), false, None)?;

    let udp_from_stack_rx = tcp_stack.take_udp_rx().expect("udp_rx already taken");
    let (udp_to_stack_tx, udp_to_stack_rx) = mpsc::channel::<PacketBuffer>(PACKET_QUEUE_CAPACITY);
    tcp_stack.set_udp_response_tx(udp_to_stack_rx);

    let mut tcp_conn_rx = tcp_stack.take_tcp_rx().expect("tcp_rx already taken");
    if let Err(err) = tcp_stack.ready().await {
        if let Some(tx) = ready.take() {
            let _ = tx.send(Err(std::io::Error::new(err.kind(), err.to_string())));
        }
        return Err(err);
    }

    let mut tasks = JoinSet::new();
    if config.tcp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let error_cb = on_error.clone();

        crate::network_tasks::spawn_in(&mut tasks, async move {
            info!("Starting TUN TCP connection handler");
            let mut connections = JoinSet::new();
            loop {
                let new_conn = tokio::select! {
                    conn = tcp_conn_rx.recv() => match conn {
                        Some(conn) => conn,
                        None => break,
                    },
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                let proxy_selector = proxy_selector.clone();
                let resolver = resolver.clone();
                let error_cb = error_cb.clone();

                crate::network_tasks::spawn_in(&mut connections, async move {
                    let remote_addr = new_conn.remote_addr;
                    let target = socket_addr_to_net_location(remote_addr);
                    debug!("Handling TUN TCP connection to {target:?}");

                    if let Err(e) = handle_tcp_connection(
                        new_conn.connection,
                        target,
                        proxy_selector,
                        resolver,
                        Some(new_conn.source_addr),
                    )
                    .await
                    {
                        if let Some(cb) = error_cb {
                            cb(&e);
                        }
                        debug!("TUN TCP connection to {remote_addr} failed: {e}");
                    }
                });
            }
            debug!("TUN TCP connection handler ended");
        });
    }

    if config.udp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let limits = config.resource_limits.clone();
        let wake = tcp_stack.wake_handle();
        let error_cb = on_error;

        crate::network_tasks::spawn_in(&mut tasks, async move {
            handle_udp_packets(
                udp_from_stack_rx,
                udp_to_stack_tx,
                proxy_selector,
                resolver,
                limits,
                wake,
                error_cb,
            )
            .await;
        });
    }

    info!("TUN server started successfully");
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
    }

    let result = tokio::select! {
        _ = &mut shutdown_rx => {
            info!("TUN server shutdown requested");
            Ok(())
        }
        result = tcp_stack.finished() => result.and_then(|()| {
            Err(std::io::Error::other("TUN stack stopped unexpectedly"))
        }),
    };

    tasks.shutdown().await;
    info!("TUN server stopped");
    result
}

/// Runs the TUN server from a [`TunServerConfig`] wrapping `raw_fd`.
pub async fn run_tun_server(
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let Some(fd) = config.raw_fd else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TunServerConfig::raw_fd is required (privileges are isolated in vless-tray-helper)",
        ));
    };
    // SAFETY: `fcntl(fd, F_GETFD)` is safe on any integer descriptor and validates that `fd` is open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned_fd = if config.close_fd_on_drop {
        // SAFETY: Caller transferred ownership (`close_fd_on_drop = true`) of a validated open fd.
        unsafe { OwnedFd::from_raw_fd(fd) }
    } else {
        // SAFETY: `fd` was validated open above and remains valid for the duration of `try_clone_to_owned`.
        unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?
    };

    run_tun_with_owned_fd(
        owned_fd,
        config,
        proxy_selector,
        resolver,
        shutdown_rx,
        None,
        None,
    )
    .await
}

fn socket_addr_to_net_location(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

pub(crate) async fn handle_tcp_connection<T: crate::async_stream::AsyncStream>(
    mut connection: T,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    source: Option<std::net::SocketAddr>,
) -> std::io::Result<()> {
    let _permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
    let prepared =
        crate::tcp::ingress::PreparedTcp::new(&proxy_selector, target.clone(), Vec::new())?
            .with_source(source);
    let route = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        prepared.route(&mut connection, &proxy_selector, &resolver),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TUN routing timed out"))??;

    let connected = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        use tokio::io::AsyncWriteExt;
        let routed = route.connect(&resolver).await?;
        let Some(mut setup) = routed.setup else {
            return Ok(None);
        };
        if let Some(data) = setup.early_data.take() {
            connection.write_all(&data).await?;
            connection.flush().await?;
        }
        if !routed.is_local_dns && !routed.prefix.is_empty() {
            setup.client_stream.write_all(&routed.prefix).await?;
            setup.client_stream.flush().await?;
        }
        Ok::<_, std::io::Error>(Some((
            setup.client_stream,
            routed.wire_destination,
            routed.is_local_dns,
            routed.prefix,
        )))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TUN TCP setup timed out"))
    .and_then(|result| result)
    .inspect_err(|error| warn!("Failed to connect to {target}: {error}"))?;
    drop(proxy_selector);
    drop(resolver);

    let Some((mut remote, wire_destination, is_local_dns, prefix)) = connected else {
        debug!("TUN TCP connection blocked by rules");
        return Ok(());
    };

    let result = if is_local_dns && !prefix.is_empty() {
        let mut prepended =
            crate::prepend_stream::PrependStream::new(connection, Some(prefix.into_boxed_slice()));
        tokio::io::copy_bidirectional(&mut prepended, &mut remote).await
    } else {
        tokio::io::copy_bidirectional(&mut connection, &mut remote).await
    };
    match result {
        Ok((sent, received)) => debug!(
            "TUN TCP connection to {wire_destination} completed: {sent} bytes sent, {received} bytes received"
        ),
        Err(error) => debug!("TUN TCP connection to {wire_destination} error: {error}"),
    }
    Ok(())
}

async fn handle_udp_packets(
    from_stack_rx: mpsc::Receiver<PacketBuffer>,
    to_stack_tx: mpsc::Sender<PacketBuffer>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::tun::TunResourceLimits,
    wake: wake::Wake,
    on_error: Option<crate::tcp::tcp_server::StreamErrorCallback>,
) {
    info!("Starting TUN UDP handler (session-based)");
    let udp_handler = udp_handler::UdpHandler::new(from_stack_rx, to_stack_tx, wake);
    let (reader, writer) = udp_handler.split();
    let manager = TunUdpManager::new(reader, writer, proxy_selector, resolver, limits)
        .with_error_callback(on_error);
    if let Err(e) = manager.run().await {
        warn!("TUN UDP handler error: {e}");
    }
    info!("TUN UDP handler stopped");
}

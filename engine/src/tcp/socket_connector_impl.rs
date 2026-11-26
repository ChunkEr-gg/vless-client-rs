//! TCP + UDP outbound socket connector with Happy Eyeballs and `bind_interface` (`IP_BOUND_IF`).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncStream;
use crate::config::ResolvedClientConfig;
use crate::resolver::{Resolver, resolve_addresses, resolve_location};
use crate::socket_util::{new_tcp_socket_for_peer, new_udp_socket_for_peer, set_tcp_keepalive};

use super::socket_connector::SocketConnector;

const TCP_FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
const TCP_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_TCP_ATTEMPTS: usize = 2;

fn interleave_tcp_addresses(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let prefer_ipv6 = first.is_ipv6();
    let (preferred, alternate): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == prefer_ipv6);
    let mut alternate = alternate.into_iter();
    let mut ordered = Vec::with_capacity(preferred.len() + alternate.len());
    for address in preferred {
        ordered.push(address);
        if let Some(address) = alternate.next() {
            ordered.push(address);
        }
    }
    ordered.extend(alternate);
    ordered
}

pub(crate) async fn connect_tcp_candidates<T, F>(
    addresses: Vec<SocketAddr>,
    mut connect: impl FnMut(SocketAddr) -> std::io::Result<F>,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    if addresses.len() == 1 {
        return connect(addresses[0])?.await;
    }

    let mut candidates = interleave_tcp_addresses(addresses).into_iter().enumerate();
    let mut attempts = FuturesUnordered::new();
    let mut next_launch = tokio::time::Instant::now();
    let mut last_error: Option<(usize, std::io::Error)> = None;

    while candidates.len() != 0 || !attempts.is_empty() {
        let has_active = !attempts.is_empty();
        tokio::select! {
            biased;
            Some((index, address, result)) = attempts.next(), if has_active => {
                match result {
                    Ok(stream) => {
                        drop(attempts);
                        return Ok(stream);
                    }
                    Err(error) => {
                        debug!("TCP connect to {address} failed: {error}");
                        if last_error.as_ref().is_none_or(|(previous, _)| index > *previous) {
                            last_error = Some((index, error));
                        }
                        next_launch = tokio::time::Instant::now();
                    }
                }
            }
            () = tokio::time::sleep_until(next_launch),
                if candidates.len() != 0 && attempts.len() < MAX_TCP_ATTEMPTS =>
            {
                let (index, address) = candidates.next().unwrap();
                let attempt = connect(address)?;
                attempts.push(async move {
                    let result = tokio::time::timeout(TCP_ATTEMPT_TIMEOUT, attempt)
                        .await
                        .unwrap_or_else(|_| Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("TCP connect to {address} timed out"),
                        )));
                    (index, address, result)
                });
                next_launch = tokio::time::Instant::now() + TCP_FALLBACK_DELAY;
            }
        }
    }
    Err(last_error
        .map(|(_, error)| error)
        .unwrap_or_else(|| std::io::Error::other("no resolved addresses succeeded")))
}

#[derive(Debug)]
pub struct SocketConnectorImpl {
    bind_interface: Option<String>,
    no_delay: bool,
}

impl SocketConnectorImpl {
    pub fn new_tcp(bind_interface: Option<String>, no_delay: bool) -> Self {
        Self {
            bind_interface,
            no_delay,
        }
    }

    pub fn from_config(config: &ResolvedClientConfig) -> Self {
        Self::new_tcp(
            config.bind_interface.clone().into_option(),
            config.tcp_settings.unwrap_or_default().no_delay,
        )
    }
}

#[async_trait]
impl SocketConnector for SocketConnectorImpl {
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let target_addrs = match address.resolved_addr() {
            Some(r) => vec![r],
            None => resolve_addresses(resolver, address.location()).await?,
        };

        let stream = connect_tcp_candidates(target_addrs, |address| {
            let socket = new_tcp_socket_for_peer(self.bind_interface.clone(), address)?;
            Ok(socket.connect(address))
        })
        .await?;
        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(120),
            std::time::Duration::from_secs(30),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }
        if self.no_delay
            && let Err(e) = stream.set_nodelay(true)
        {
            error!("Failed to set TCP no-delay: {e}");
        }
        Ok(Box::new(stream))
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        mut target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        debug!(
            "[SocketConnector] connect_udp_bidirectional called, target: {}",
            target.location()
        );
        let remote_addr = resolve_location(&mut target, resolver).await?;
        let client_socket = new_udp_socket_for_peer(remote_addr, self.bind_interface.clone())?;
        Ok(Box::new(UnconnectedUdpSocket::new(
            client_socket,
            remote_addr,
        )))
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }
}

struct UnconnectedUdpSocket {
    socket: UdpSocket,
    destination: SocketAddr,
}

impl UnconnectedUdpSocket {
    fn new(socket: UdpSocket, destination: SocketAddr) -> Self {
        Self {
            socket,
            destination,
        }
    }
}

impl crate::async_stream::AsyncReadMessage for UnconnectedUdpSocket {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }

    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.socket.poll_recv_from(cx, buf) {
            Poll::Ready(Ok(addr)) => {
                log::debug!(
                    "[UnconnectedUdp] Received {} bytes from {} (target: {})",
                    buf.filled().len(),
                    addr,
                    this.destination
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncWriteMessage for UnconnectedUdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.socket
            .poll_send_to(cx, buf, this.destination)
            .map(|r| r.map(|_| ()))
    }
}

impl crate::async_stream::AsyncFlushMessage for UnconnectedUdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for UnconnectedUdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncPing for UnconnectedUdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncMessageStream for UnconnectedUdpSocket {}

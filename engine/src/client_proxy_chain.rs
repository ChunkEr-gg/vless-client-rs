//! Client proxy chain & group dialers (`PLAN.md` §6).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::debug;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

/// Entry in the initial hop (hop 0).
pub enum InitialHopEntry {
    /// Direct socket connection (used for private/bypass CIDRs & domains).
    Direct(Arc<dyn SocketConnector>),
    /// Outbound VLESS proxy connection (socket + VLESS/TLS/REALITY handler).
    Proxy {
        socket: Arc<dyn SocketConnector>,
        proxy: Box<dyn ProxyConnector>,
    },
}

impl std::fmt::Debug for InitialHopEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialHopEntry::Direct(socket) => f.debug_tuple("Direct").field(socket).finish(),
            InitialHopEntry::Proxy { socket, proxy } => f
                .debug_struct("Proxy")
                .field("socket", socket)
                .field("proxy_location", &proxy.proxy_location())
                .finish(),
        }
    }
}

impl InitialHopEntry {
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) => true,
            InitialHopEntry::Proxy { proxy, .. } => proxy.supports_udp(),
        }
    }
}

/// Single-path outbound client chain (either Direct or 1-hop VLESS proxy).
pub struct ClientProxyChain {
    initial: Arc<InitialHopEntry>,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProxyChain")
            .field("initial", &self.initial)
            .field("supports_udp", &self.supports_udp())
            .finish()
    }
}

impl ClientProxyChain {
    pub fn new_single(initial: InitialHopEntry) -> Self {
        Self {
            initial: Arc::new(initial),
        }
    }

    pub fn supports_udp(&self) -> bool {
        self.initial.supports_udp()
    }

    pub fn is_direct_only(&self) -> bool {
        matches!(self.initial.as_ref(), InitialHopEntry::Direct(_))
    }

    pub async fn connect_tcp(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        match self.initial.as_ref() {
            InitialHopEntry::Direct(socket) => {
                debug!("Direct TCP connect -> {}", target.location());
                Ok(TcpClientSetupResult {
                    client_stream: socket.connect(resolver, &target).await?,
                    early_data: None,
                })
            }
            InitialHopEntry::Proxy { socket, proxy } => {
                let target = proxy.prepare_target(target, resolver).await?;
                if let Some(reused) = proxy.try_reuse_tcp_stream(&target).await? {
                    return Ok(reused);
                }
                debug!(
                    "Proxy TCP connect via {} -> {}",
                    proxy.proxy_location(),
                    target.location()
                );
                let stream = socket
                    .connect(resolver, &proxy.proxy_location().into())
                    .await?;
                proxy.setup_tcp_stream(stream, &target).await
            }
        }
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.supports_udp() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Outbound chain does not support UDP",
            ));
        }
        match self.initial.as_ref() {
            InitialHopEntry::Direct(socket) => {
                debug!("Direct UDP connect -> {}", target.location());
                socket.connect_udp_bidirectional(resolver, target).await
            }
            InitialHopEntry::Proxy { socket, proxy } => {
                debug!(
                    "Proxy UDP connect via {} -> {}",
                    proxy.proxy_location(),
                    target.location()
                );
                let stream = socket
                    .connect(resolver, &proxy.proxy_location().into())
                    .await?;
                proxy.setup_udp_bidirectional(stream, target).await
            }
        }
    }
}

/// Group of [`ClientProxyChain`]s with lock-free round-robin selection.
#[derive(Debug)]
pub struct ClientChainGroup {
    chains: Vec<ClientProxyChain>,
    next_index: AtomicUsize,
}

impl ClientChainGroup {
    pub fn new(chains: Vec<ClientProxyChain>) -> Self {
        assert!(
            !chains.is_empty(),
            "ClientChainGroup requires at least one chain"
        );
        Self {
            chains,
            next_index: AtomicUsize::new(0),
        }
    }

    pub fn single(chain: ClientProxyChain) -> Self {
        Self::new(vec![chain])
    }

    fn select_chain(&self) -> &ClientProxyChain {
        if self.chains.len() == 1 {
            &self.chains[0]
        } else {
            let idx = self.next_index.fetch_add(1, Ordering::Relaxed) % self.chains.len();
            &self.chains[idx]
        }
    }

    pub fn supports_udp(&self) -> bool {
        self.chains.iter().any(ClientProxyChain::supports_udp)
    }

    pub fn is_direct_only(&self) -> bool {
        self.chains.iter().all(ClientProxyChain::is_direct_only)
    }

    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.select_chain()
            .connect_tcp(remote_location, resolver)
            .await
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.select_chain()
            .connect_udp_bidirectional(resolver, target)
            .await
    }
}

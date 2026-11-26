use std::sync::Arc;

use async_trait::async_trait;
use log::debug;

use super::carrier_dialer::CarrierDialer;
use super::proxy_connector::ProxyConnector;
use super::tcp_client_handler_factory::create_tcp_client_handler;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ResolvedClientConfig;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};

pub(crate) fn create_proxy_connector(
    config: ResolvedClientConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Option<Box<dyn ProxyConnector>>> {
    Ok(ProxyConnectorImpl::from_config(config, resolver)?
        .map(|connector| Box::new(connector) as Box<dyn ProxyConnector>))
}

#[derive(Debug)]
pub struct ProxyConnectorImpl {
    location: NetLocation,
    client_handler: Box<dyn TcpClientHandler>,
}

impl ProxyConnectorImpl {
    fn client_transport(&self, dialer: Arc<dyn CarrierDialer>) -> ClientTransport<'_> {
        ClientTransport {
            route: dialer.clone(),
            open: Box::pin(async move { dialer.open_stream().await }),
        }
    }

    pub fn from_config(
        config: ResolvedClientConfig,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<Option<Self>> {
        if config.protocol.is_direct() {
            return Ok(None);
        }
        let client_handler = create_tcp_client_handler(config.protocol, &config.address, resolver)?;
        Ok(Some(Self {
            location: config.address,
            client_handler,
        }))
    }
}

#[async_trait]
impl ProxyConnector for ProxyConnectorImpl {
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        self.client_handler.prepare_target(target, resolver).await
    }

    fn needs_carrier_dialer(&self) -> bool {
        self.client_handler.has_session_pool()
    }

    async fn connect_tcp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.client_handler
            .connect_client_tcp(self.client_transport(dialer), target.clone())
            .await
    }

    async fn connect_udp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.client_handler
            .connect_client_udp(self.client_transport(dialer), target)
            .await
    }

    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp(&self) -> bool {
        self.client_handler.supports_udp_over_tcp()
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        self.client_handler.try_reuse_tcp_stream(target).await
    }

    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        debug!(
            "[ProxyConnector] setup_tcp_stream: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_tcp_stream(stream, target.clone())
            .await
    }

    async fn setup_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.supports_udp() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("Proxy {} does not support UDP", self.location),
            ));
        }
        self.client_handler
            .setup_client_udp_bidirectional(stream, target)
            .await
    }
}

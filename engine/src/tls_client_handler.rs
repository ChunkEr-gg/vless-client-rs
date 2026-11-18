use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};

#[derive(Debug)]
pub struct TlsClientHandler {
    pub client_config: Arc<rustls::ClientConfig>,
    pub tls_buffer_size: Option<usize>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub handler: TlsInnerClientHandler,
}

#[derive(Debug)]
pub enum TlsInnerClientHandler {
    Default(Box<dyn TcpClientHandler>),
    VisionVless { uuid: Box<[u8]>, udp_enabled: bool },
}

impl TlsClientHandler {
    fn create_connection(&self) -> Result<rustls::ClientConnection, rustls::Error> {
        let mut connection =
            rustls::ClientConnection::new(self.client_config.clone(), self.server_name.clone())?;
        if let Some(size) = self.tls_buffer_size {
            let size = match self.handler {
                TlsInnerClientHandler::VisionVless { .. } => size.max(21),
                TlsInnerClientHandler::Default(_) => size,
            };
            connection.set_buffer_limit(Some(size));
        }
        Ok(connection)
    }

    async fn wrap_pooled_transport(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        let connection = self.create_connection().map_err(std::io::Error::other)?;
        CryptoTlsStream::handshake(
            stream,
            TlsConnection::new(connection),
            TlsReadMode::Stream,
            &[],
        )
        .await
    }

    pub fn new(
        client_config: Arc<rustls::ClientConfig>,
        tls_buffer_size: Option<usize>,
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::Default(handler),
        }
    }

    pub fn new_vision_vless(
        client_config: Arc<rustls::ClientConfig>,
        tls_buffer_size: Option<usize>,
        server_name: rustls::pki_types::ServerName<'static>,
        uuid: Box<[u8]>,
        udp_enabled: bool,
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::VisionVless { uuid, udp_enabled },
        }
    }

    async fn setup_client_stream_common(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        let client_conn = self.create_connection().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Failed to create client connection: {e}"),
            )
        })?;

        let connection = TlsConnection::new(client_conn);
        let mode = match self.handler {
            TlsInnerClientHandler::VisionVless { .. } => TlsReadMode::PreserveRecords,
            TlsInnerClientHandler::Default(_) => TlsReadMode::Stream,
        };
        CryptoTlsStream::handshake(client_stream, connection, mode, &[]).await
    }
}

#[async_trait]
impl TcpClientHandler for TlsClientHandler {
    fn has_session_pool(&self) -> bool {
        matches!(&self.handler, TlsInnerClientHandler::Default(handler) if handler.has_session_pool())
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let TlsInnerClientHandler::Default(handler) = &self.handler {
            let transport = transport.wrap(|stream| async move {
                let stream = self.wrap_pooled_transport(stream).await?;
                handler.validate_alpn(stream.alpn_protocol())?;
                Ok(stream)
            });
            handler.connect_client_tcp(transport, target).await
        } else {
            self.setup_client_tcp_stream(transport.open.await?, target)
                .await
        }
    }

    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if let TlsInnerClientHandler::Default(handler) = &self.handler {
            let transport = transport.wrap(|stream| self.wrap_pooled_transport(stream));
            handler.connect_client_udp(transport, target).await
        } else {
            self.setup_client_udp_bidirectional(transport.open.await?, target)
                .await
        }
    }

    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &std::sync::Arc<dyn crate::resolver::Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler.prepare_target(target, resolver).await
            }
            TlsInnerClientHandler::VisionVless { .. } => Ok(target),
        }
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => handler.try_reuse_tcp_stream(target).await,
            TlsInnerClientHandler::VisionVless { .. } => Ok(None),
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let tls_stream = self.setup_client_stream_common(client_stream).await?;

        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler.validate_alpn(tls_stream.alpn_protocol())?;
                handler
                    .setup_client_tcp_stream(Box::new(tls_stream), remote_location)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_custom_tls_vision_vless_client_stream(
                    tls_stream,
                    uuid,
                    remote_location.location(),
                )
                .await
            }
        }
    }

    fn supports_udp_over_tcp(&self) -> bool {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => handler.supports_udp_over_tcp(),
            TlsInnerClientHandler::VisionVless { udp_enabled, .. } => *udp_enabled,
        }
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let tls_stream = self.setup_client_stream_common(client_stream).await?;

        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_udp_bidirectional(Box::new(tls_stream), target)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_vision_vless_udp_bidirectional(
                    tls_stream,
                    uuid,
                    target.into_location(),
                    crate::vless::VisionWriteErrorPolicy::Legacy,
                )
                .await
            }
        }
    }
}

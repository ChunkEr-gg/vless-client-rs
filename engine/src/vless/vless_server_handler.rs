//! Test-only VLESS server counterparty (used by Vision & XUDP unit/integration tests).

use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;
use crate::uuid_util::parse_uuid;
use crate::xudp::XudpMessageStream;

use super::vision_stream::{VisionStream, VisionWriteErrorPolicy};
use super::vision_transport::VisionTransport;
use super::vless_message_stream::VlessMessageStream;
use super::vless_util::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, XTLS_VISION_FLOW, parse_addons_from_reader,
    parse_remote_location_from_reader,
};

pub struct VlessTcpServerHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
}

impl std::fmt::Debug for VlessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpServerHandler")
            .field("user_id", &self.user_id)
            .field("udp_enabled", &self.udp_enabled)
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl VlessTcpServerHandler {
    pub(crate) fn new(
        user_id: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<NetLocation>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            user_id: parse_uuid(user_id)?.into_boxed_slice(),
            udp_enabled,
            proxy_selector,
            resolver,
            fallback,
        })
    }
}

const SERVER_RESPONSE_HEADER: &[u8] = &[0u8, 0u8];

async fn vless_fallback_to_dest<S: AsyncStream + 'static>(
    client_stream: S,
    reader: StreamReader,
    fallback: &NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    let unconsumed_data = reader.unparsed_data();
    let dest_addr = crate::resolver::resolve_single_address(resolver, fallback).await?;
    let socket = crate::socket_util::new_tcp_socket(None, dest_addr.is_ipv6())?;
    let mut dest_stream: Box<dyn AsyncStream> = Box::new(socket.connect(dest_addr).await?);

    if !unconsumed_data.is_empty() {
        write_all(&mut dest_stream, unconsumed_data).await?;
        dest_stream.flush().await?;
    }

    Ok(TcpServerSetupResult::Session(Box::pin(async move {
        let mut client_stream = client_stream;
        let _ = crate::copy_bidirectional::copy_bidirectional(
            &mut client_stream,
            &mut *dest_stream,
            false,
            false,
        )
        .await;
        futures::join!(
            crate::util::shutdown_stream(&mut client_stream),
            crate::util::shutdown_stream(&mut dest_stream),
        );
    })))
}

#[async_trait]
impl TcpServerHandler for VlessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut stream_reader = StreamReader::new_with_buffer_size(800);

        let client_version = stream_reader.peek_u8(&mut server_stream).await?;
        if client_version != 0 {
            if let Some(ref fallback) = self.fallback {
                return vless_fallback_to_dest(
                    server_stream,
                    stream_reader,
                    fallback,
                    &self.resolver,
                )
                .await;
            }
            return Err(std::io::Error::other(format!(
                "invalid client protocol version, expected 0, got {client_version}"
            )));
        }

        let header = stream_reader.peek_slice(&mut server_stream, 17).await?;
        let target_id = &header[1..17];

        if self.user_id.ct_eq(target_id).unwrap_u8() == 0 {
            if let Some(ref fallback) = self.fallback {
                return vless_fallback_to_dest(
                    server_stream,
                    stream_reader,
                    fallback,
                    &self.resolver,
                )
                .await;
            }
            return Err(std::io::Error::other("Unknown user id"));
        }

        stream_reader.consume(17);

        let addon_length = stream_reader.read_u8(&mut server_stream).await?;
        if addon_length > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS addons not supported without Vision",
            ));
        }

        let instruction = stream_reader.read_u8(&mut server_stream).await?;
        match instruction {
            COMMAND_TCP => {
                let remote_location =
                    parse_remote_location_from_reader(&mut stream_reader, &mut server_stream)
                        .await?;
                let unparsed_data = stream_reader.unparsed_data();

                Ok(TcpServerSetupResult::TcpForward {
                    connection_failure_response: None,
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: true,
                    connection_success_response: Some(
                        SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                    ),
                    initial_remote_data: if unparsed_data.is_empty() {
                        None
                    } else {
                        Some(unparsed_data.to_vec().into_boxed_slice())
                    },
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            COMMAND_MUX => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MUX/XUDP requires UDP to be enabled",
                    ));
                }

                let unparsed_data = stream_reader.unparsed_data();
                write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;
                let mut xudp_stream =
                    XudpMessageStream::new(server_stream).with_legacy_resolution(true);
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: true,
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            unknown_protocol_type => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown requested protocol: {unknown_protocol_type}"),
            )),
        }
    }
}

pub(crate) async fn setup_custom_tls_vision_vless_server_stream<S>(
    mut tls_stream: S,
    user_id: &[u8],
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
) -> std::io::Result<TcpServerSetupResult>
where
    S: VisionTransport + 'static,
{
    tls_stream.require_record_framing()?;
    let mut stream_reader = StreamReader::new_with_buffer_size(800);

    let client_version = stream_reader.peek_u8(&mut tls_stream).await?;
    if client_version != 0 {
        if let Some(ref fb) = fallback {
            tls_stream.allow_streaming_reads();
            return vless_fallback_to_dest(tls_stream, stream_reader, fb, resolver).await;
        }
        return Err(std::io::Error::other(format!(
            "invalid client protocol version, expected 0, got {client_version}"
        )));
    }

    let header = stream_reader.peek_slice(&mut tls_stream, 17).await?;
    let target_id = &header[1..17];
    if user_id.ct_eq(target_id).unwrap_u8() == 0 {
        if let Some(ref fb) = fallback {
            tls_stream.allow_streaming_reads();
            return vless_fallback_to_dest(tls_stream, stream_reader, fb, resolver).await;
        }
        return Err(std::io::Error::other("Unknown user id"));
    }

    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(target_id);
    stream_reader.consume(17);

    let addon_length = stream_reader.read_u8(&mut tls_stream).await?;
    let flow = if addon_length > 0 {
        parse_addons_from_reader(&mut stream_reader, &mut tls_stream, addon_length).await?
    } else {
        String::new()
    };

    let instruction = stream_reader.read_u8(&mut tls_stream).await?;
    match instruction {
        COMMAND_TCP => {
            if flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::other("expected vision flow for TCP"));
            }
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            let unparsed_data = stream_reader.unparsed_data();
            debug!("Creating VISION stream (Custom TLS) for flow: {flow}");
            let vision_stream = VisionStream::new_server(tls_stream, user_uuid, unparsed_data)?
                .with_write_error_policy(VisionWriteErrorPolicy::Legacy);

            Ok(TcpServerSetupResult::TcpForward {
                connection_failure_response: None,
                remote_location,
                stream: Box::new(vision_stream),
                need_initial_flush: false,
                connection_success_response: None,
                initial_remote_data: None,
                proxy_selector: proxy_selector.clone(),
            })
        }
        COMMAND_UDP => {
            if !udp_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP not enabled",
                ));
            }
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            tls_stream.allow_streaming_reads();
            let unparsed_data = stream_reader.unparsed_data();
            let mut vless_stream = VlessMessageStream::new(Box::new(tls_stream));
            if !unparsed_data.is_empty() {
                vless_stream.feed_initial_read_data(unparsed_data)?;
            }
            Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(vless_stream),
                need_initial_flush: false,
                proxy_selector,
            })
        }
        COMMAND_MUX => {
            if !udp_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "MUX/XUDP requires UDP to be enabled",
                ));
            }
            let unparsed_data = stream_reader.unparsed_data();
            if flow == XTLS_VISION_FLOW {
                let vision_stream =
                    VisionStream::new_xudp_server(tls_stream, user_uuid, unparsed_data)?
                        .with_write_error_policy(VisionWriteErrorPolicy::Legacy);
                let xudp_stream =
                    XudpMessageStream::new(Box::new(vision_stream)).with_legacy_resolution(true);
                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false,
                    proxy_selector,
                })
            } else {
                tls_stream.allow_streaming_reads();
                write_all(&mut tls_stream, SERVER_RESPONSE_HEADER).await?;
                let mut xudp_stream =
                    XudpMessageStream::new(Box::new(tls_stream)).with_legacy_resolution(true);
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }
                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: true,
                    proxy_selector,
                })
            }
        }
        unknown => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unknown requested protocol: {unknown}"),
        )),
    }
}

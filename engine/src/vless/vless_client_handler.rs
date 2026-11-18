//! VLESS client protocol setup (`PLAN.md` §2, §6).
//!
//! Supports:
//! - VLESS + Vision + XUDP (`setup_custom_tls_vision_vless_client_stream` / `setup_vision_vless_udp_bidirectional`)
//! - VLESS + plain TLS + XUDP without Vision (`VlessTcpClientHandler`: TCP via `COMMAND_TCP` (0x01),
//!   UDP via `COMMAND_MUX` (0x03) + `VlessResponseStream` + `XudpClientStream` for Xray kTLS servers).

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::util::{allocate_vec, write_all};
use crate::uuid_util::parse_uuid;
use crate::xudp::client_stream::XudpClientStream;

use super::vision_stream::{VisionStream, VisionWriteErrorPolicy};
use super::vision_transport::VisionTransport;
use super::vless_response_stream::VlessResponseStream;
use super::vless_util::{COMMAND_MUX, COMMAND_TCP, vision_flow_addon_data};

pub struct VlessTcpClientHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
}

impl std::fmt::Debug for VlessTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpClientHandler")
            .field("user_id", &self.user_id)
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl VlessTcpClientHandler {
    pub(crate) fn new(user_id: &str, udp_enabled: bool) -> std::io::Result<Self> {
        Ok(Self {
            user_id: parse_uuid(user_id)?.into_boxed_slice(),
            udp_enabled,
        })
    }
}

#[async_trait]
impl TcpClientHandler for VlessTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        write_vless_header(
            &mut client_stream,
            &self.user_id,
            &[],
            remote_location.location(),
        )
        .await?;
        client_stream.flush().await?;
        let client_stream = Box::new(VlessResponseStream::new(client_stream));

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP is disabled on this VLESS client handler",
            ));
        }

        // XUDP without Vision (for VLESS+TLS / kTLS Xray servers, `PLAN.md` §2 & §6):
        // 19-byte VLESS MUX header: version (0x00) + UUID (16B) + addon_len (0x00) + COMMAND_MUX (0x03).
        // Destination is carried per-session inside XUDP New/Keep frames (`v1.mux.cool:666` is implicit
        // and omitted from the VLESS wire header for COMMAND_MUX).
        let mut header = [0u8; 19];
        header[0] = 0;
        header[1..17].copy_from_slice(&self.user_id);
        header[17] = 0;
        header[18] = COMMAND_MUX;

        write_all(&mut client_stream, &header).await?;
        client_stream.flush().await?;

        let response_stream = Box::new(VlessResponseStream::new(client_stream));
        Ok(Box::new(XudpClientStream::new(
            response_stream,
            target.into_location(),
        )))
    }
}

pub(crate) async fn setup_vision_vless_udp_bidirectional<S>(
    mut stream: S,
    user_id: &[u8],
    target: NetLocation,
    policy: VisionWriteErrorPolicy,
) -> std::io::Result<Box<dyn AsyncMessageStream>>
where
    S: VisionTransport + 'static,
{
    stream.require_record_framing()?;
    let addon = vision_flow_addon_data();
    let mut header = vec![0];
    header.extend_from_slice(user_id);
    header.push(addon.len() as u8);
    header.extend_from_slice(addon);
    // MUX uses the implicit v1.mux.cool:666 destination, omitted from the wire header.
    header.push(COMMAND_MUX);
    stream.write_all(&header).await?;
    stream.flush().await?;
    let uuid = user_id.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS UUID must be 16 bytes",
        )
    })?;
    let vision = VisionStream::new_client(stream, uuid)?
        .with_write_error_policy(policy)
        .with_xudp();
    Ok(Box::new(XudpClientStream::new(Box::new(vision), target)))
}

pub(crate) async fn setup_custom_tls_vision_vless_client_stream<S>(
    tls_stream: S,
    user_id: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<TcpClientSetupResult>
where
    S: VisionTransport + 'static,
{
    setup_vision_vless_client_stream(
        tls_stream,
        user_id,
        remote_location,
        VisionWriteErrorPolicy::Legacy,
    )
    .await
}

async fn setup_vision_vless_client_stream<S: VisionTransport + 'static>(
    mut tls_stream: S,
    user_id: &[u8],
    remote_location: &NetLocation,
    policy: VisionWriteErrorPolicy,
) -> std::io::Result<TcpClientSetupResult> {
    tls_stream.require_record_framing()?;
    write_vless_header(
        &mut tls_stream,
        user_id,
        vision_flow_addon_data(),
        remote_location,
    )
    .await?;
    tls_stream.flush().await?;

    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(user_id);
    let vision_stream =
        VisionStream::new_client(tls_stream, user_uuid)?.with_write_error_policy(policy);

    Ok(TcpClientSetupResult {
        client_stream: Box::new(vision_stream),
        early_data: None,
    })
}

async fn write_vless_header<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    user_id: &[u8],
    addon_data: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<()> {
    let base_header_size = 1 + 16 + 1 + addon_data.len() + 1 + 2 + 1;
    let mut header_bytes = allocate_vec(base_header_size);

    header_bytes[0] = 0;
    header_bytes[1..17].copy_from_slice(user_id);
    header_bytes[17] = addon_data.len() as u8;
    if !addon_data.is_empty() {
        header_bytes[18..18 + addon_data.len()].copy_from_slice(addon_data);
    }

    let addon_end = 18 + addon_data.len();
    header_bytes[addon_end] = COMMAND_TCP;

    let remote_port = remote_location.port();
    header_bytes[addon_end + 1] = (remote_port >> 8) as u8;
    header_bytes[addon_end + 2] = (remote_port & 0xff) as u8;

    let address_type_offset = addon_end + 3;
    match remote_location.address() {
        Address::Ipv4(v4addr) => {
            header_bytes[address_type_offset] = 1;
            header_bytes.extend_from_slice(&v4addr.octets());
        }
        Address::Ipv6(v6addr) => {
            header_bytes[address_type_offset] = 3;
            header_bytes.extend_from_slice(&v6addr.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Hostname is too long: {hostname}"),
                ));
            }
            header_bytes[address_type_offset] = 2;
            header_bytes.push(hostname.len() as u8);
            header_bytes.extend_from_slice(hostname.as_bytes());
        }
    }

    write_all(stream, &header_bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use futures::future::poll_fn;
    use tokio::io::ReadBuf;

    use super::*;
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::resolver::NativeResolver;
    use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
    use crate::vless::vless_server_handler::VlessTcpServerHandler;

    #[tokio::test]
    async fn xudp_without_vision_speaks_command_mux_and_roundtrips_datagrams() {
        const USER_ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let client_handler = VlessTcpClientHandler::new(USER_ID, true).unwrap();
        let selector = Arc::new(ClientProxySelector::new(vec![]));
        let resolver: Arc<dyn crate::resolver::Resolver> = Arc::new(NativeResolver::new());
        let server_handler =
            VlessTcpServerHandler::new(USER_ID, true, selector, resolver, None).unwrap();

        let (client_io, server_io) = tokio::io::duplex(65536);
        let target = NetLocation::from_str("1.1.1.1:53", None).unwrap();

        let (client_res, server_res) = tokio::join!(
            client_handler
                .setup_client_udp_bidirectional(Box::new(client_io), target.clone().into()),
            server_handler.setup_server_stream(Box::new(server_io)),
        );

        let mut client_udp = client_res.unwrap();
        let TcpServerSetupResult::SessionBasedUdp {
            mut stream,
            need_initial_flush,
            ..
        } = server_res.unwrap()
        else {
            panic!("expected SessionBasedUdp from COMMAND_MUX");
        };
        if need_initial_flush {
            poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
                .await
                .unwrap();
        }

        // Send a UDP datagram from client -> server over XUDP (without Vision)
        let query = b"\x12\x34\x01\x00\x00\x01dns-query-over-xudp";
        poll_fn(|cx| Pin::new(&mut *client_udp).poll_write_message(cx, query))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut *client_udp).poll_flush_message(cx))
            .await
            .unwrap();

        let mut recv_buf = [0u8; 1024];
        let (session_id, dest) = poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut recv_buf);
            Pin::new(&mut *stream)
                .poll_read_session_message(cx, &mut rb)
                .map(|res| res.map(|(sid, loc)| (sid, (loc, rb.filled().to_vec()))))
        })
        .await
        .unwrap();
        assert_eq!(dest.0, target);
        assert_eq!(dest.1, query);

        // Send response back server -> client (this also delivers the 2-byte VLESS response header
        // stripped transparently by VlessResponseStream!)
        let reply = b"\x12\x34\x81\x80\x00\x01dns-reply-over-xudp";
        poll_fn(|cx| {
            Pin::new(&mut *stream).poll_write_session_message(cx, session_id, reply, &target)
        })
        .await
        .unwrap();
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
            .await
            .unwrap();

        let mut client_recv = [0u8; 1024];
        let got = poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut client_recv);
            Pin::new(&mut *client_udp)
                .poll_read_message(cx, &mut rb)
                .map(|res| res.map(|()| rb.filled().to_vec()))
        })
        .await
        .unwrap();
        assert_eq!(got, reply);
    }
}

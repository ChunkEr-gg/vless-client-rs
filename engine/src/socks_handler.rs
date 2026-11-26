//! Inbound SOCKS5 (CONNECT + UDP ASSOCIATE) server handler (`PLAN.md` §6).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks5_udp_relay::Socks5UdpRelayStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;

pub const VER_SOCKS5: u8 = 0x05;
pub const VER_AUTH: u8 = 0x01;

pub const METHOD_NONE: u8 = 0x00;
pub const METHOD_USERNAME: u8 = 0x02;
pub const METHOD_INVALID: u8 = 0xff;

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

pub const RESULT_SUCCESS: u8 = 0x0;
const RESULT_FAILURE: u8 = 0x01;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    auth_info: Option<(String, String)>,
    udp_enabled: bool,
    bind_ip: IpAddr,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl SocksTcpServerHandler {
    pub fn new(
        auth_info: Option<(String, String)>,
        udp_enabled: bool,
        bind_ip: IpAddr,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            auth_info,
            udp_enabled,
            bind_ip,
            proxy_selector,
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for SocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_reader = StreamReader::new_with_buffer_size(400);
        let udp_bind_ip = if self.udp_enabled {
            Some(self.bind_ip)
        } else {
            None
        };
        setup_socks_server_stream_inner(
            self.auth_info.as_ref(),
            udp_bind_ip,
            &self.proxy_selector,
            &self.resolver,
            server_stream,
            stream_reader,
        )
        .await
    }
}

async fn send_rejection(stream: &mut Box<dyn AsyncStream>, response: &[u8]) -> std::io::Result<()> {
    stream.write_all(response).await?;
    stream.flush().await
}

pub async fn setup_socks_server_stream_inner(
    auth_info: Option<&(String, String)>,
    udp_bind_ip: Option<IpAddr>,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    mut server_stream: Box<dyn AsyncStream>,
    mut stream_reader: StreamReader,
) -> std::io::Result<TcpServerSetupResult> {
    let socks_version = stream_reader.read_u8(&mut server_stream).await?;
    if socks_version != VER_SOCKS5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unsupported SOCKS version: {socks_version}"),
        ));
    }

    let method_len = stream_reader.read_u8(&mut server_stream).await? as usize;
    if method_len < 1 {
        send_rejection(&mut server_stream, &[VER_SOCKS5, METHOD_INVALID]).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid method length: {method_len}"),
        ));
    }

    let methods = stream_reader
        .read_slice(&mut server_stream, method_len)
        .await?;

    let supported_method = if auth_info.is_some() {
        METHOD_USERNAME
    } else {
        METHOD_NONE
    };

    if !methods.contains(&supported_method) {
        send_rejection(&mut server_stream, &[VER_SOCKS5, METHOD_INVALID]).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Supported SOCKS method not found",
        ));
    }

    write_all(&mut server_stream, &[VER_SOCKS5, supported_method]).await?;
    server_stream.flush().await?;

    if let Some((target_username, target_password)) = auth_info {
        let auth_version = stream_reader.read_u8(&mut server_stream).await?;
        if auth_version != VER_AUTH {
            send_rejection(&mut server_stream, &[VER_AUTH, RESULT_FAILURE]).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported SOCKS auth version",
            ));
        }

        let username_len = stream_reader.read_u8(&mut server_stream).await? as usize;
        if username_len == 0 {
            send_rejection(&mut server_stream, &[VER_AUTH, RESULT_FAILURE]).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported SOCKS username length",
            ));
        }

        let username_bytes = stream_reader
            .read_slice(&mut server_stream, username_len)
            .await?
            .to_vec();

        let password_len = stream_reader.read_u8(&mut server_stream).await? as usize;
        if password_len == 0 {
            send_rejection(&mut server_stream, &[VER_AUTH, RESULT_FAILURE]).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported SOCKS password length",
            ));
        }

        let password = stream_reader
            .read_slice(&mut server_stream, password_len)
            .await?;

        let username_match = target_username.as_bytes().ct_eq(&username_bytes);
        let password_match = target_password.as_bytes().ct_eq(password);

        if username_match.unwrap_u8() == 0 || password_match.unwrap_u8() == 0 {
            send_rejection(&mut server_stream, &[VER_AUTH, RESULT_FAILURE]).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS authentication failed",
            ));
        }

        write_all(&mut server_stream, &[VER_AUTH, RESULT_SUCCESS]).await?;
        server_stream.flush().await?;
    }

    let connection_request = stream_reader.read_slice(&mut server_stream, 3).await?;
    if connection_request[0] != VER_SOCKS5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid SOCKS version: {}", connection_request[0]),
        ));
    }

    if connection_request[1] == CMD_UDP_ASSOCIATE {
        let bind_ip = match udp_bind_ip {
            Some(ip) => ip,
            None => {
                let response = build_error_response(REPLY_COMMAND_NOT_SUPPORTED);
                write_all(&mut server_stream, &response).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "UDP ASSOCIATE not enabled",
                ));
            }
        };
        return handle_udp_associate(
            bind_ip,
            proxy_selector,
            resolver,
            server_stream,
            &mut stream_reader,
        )
        .await;
    }

    if connection_request[1] != CMD_CONNECT {
        let command = connection_request[1];
        send_rejection(
            &mut server_stream,
            &build_error_response(REPLY_COMMAND_NOT_SUPPORTED),
        )
        .await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid command code: {command}"),
        ));
    }

    if connection_request[2] != 0x0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid reserved bit",
        ));
    }

    static SUCCESS_RESPONSE: OnceLock<Box<[u8]>> = OnceLock::new();
    let connection_success_response = SUCCESS_RESPONSE.get_or_init(|| {
        let mut response_bytes = vec![VER_SOCKS5, RESULT_SUCCESS, 0];
        let mut location_vec = write_location_to_vec(&NetLocation::new(
            Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            65535,
        ))
        .expect("fixed IP address");
        response_bytes.append(&mut location_vec);
        response_bytes.into_boxed_slice()
    });

    let location = read_location(&mut server_stream, &mut stream_reader).await?;

    Ok(TcpServerSetupResult::TcpForward {
        remote_location: location,
        stream: server_stream,
        need_initial_flush: true,
        connection_success_response: Some(connection_success_response.to_vec().into_boxed_slice()),
        connection_failure_response: Some(connect_failure_response),
        initial_remote_data: stream_reader.unparsed_data_owned(),
        proxy_selector: proxy_selector.clone(),
    })
}

async fn handle_udp_associate(
    bind_ip: IpAddr,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    mut server_stream: Box<dyn AsyncStream>,
    stream_reader: &mut StreamReader,
) -> std::io::Result<TcpServerSetupResult> {
    let _client_hint = read_location(&mut server_stream, stream_reader).await?;

    const UDP_BUFFER_SIZE: usize = 2 * 1024 * 1024;
    let udp_bind_addr = if bind_ip.is_unspecified() {
        server_stream
            .local_addr()
            .filter(|address| address.is_ipv6() == bind_ip.is_ipv6())
            .map(|mut address| {
                address.set_port(0);
                address
            })
            .unwrap_or_else(|| SocketAddr::new(bind_ip, 0))
    } else {
        SocketAddr::new(bind_ip, 0)
    };
    let udp_socket: std::net::UdpSocket =
        match crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_ip.is_ipv6(),
            None,
            Some(udp_bind_addr),
            false,
            Some(UDP_BUFFER_SIZE),
        ) {
            Ok(s) => s.into(),
            Err(e) => {
                log::error!("Failed to bind UDP socket: {e}");
                let response = build_error_response(REPLY_GENERAL_FAILURE);
                write_all(&mut server_stream, &response).await?;
                server_stream.flush().await?;
                return Err(e);
            }
        };
    let udp_socket = tokio::net::UdpSocket::from_std(udp_socket)?;
    let bound_addr = udp_socket.local_addr()?;
    log::info!("SOCKS5 UDP ASSOCIATE: bound UDP relay at {bound_addr}");

    let response = build_udp_associate_response(bound_addr);
    write_all(&mut server_stream, &response).await?;
    server_stream.flush().await?;

    let relay_stream = Socks5UdpRelayStream::new(udp_socket);
    let proxy_selector = proxy_selector.clone();
    let resolver = resolver.clone();

    Ok(TcpServerSetupResult::Session(Box::pin(async move {
        if let Err(e) =
            run_udp_associate(server_stream, relay_stream, proxy_selector, resolver).await
        {
            log::debug!("SOCKS5 UDP ASSOCIATE ended: {e}");
        }
    })))
}

fn build_error_response(reply_code: u8) -> Vec<u8> {
    vec![
        VER_SOCKS5,
        reply_code,
        0x00,
        ADDR_TYPE_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

fn connect_failure_response(kind: std::io::ErrorKind) -> Vec<u8> {
    use std::io::ErrorKind;
    build_error_response(match kind {
        ErrorKind::PermissionDenied => 2,
        ErrorKind::NetworkUnreachable => 3,
        ErrorKind::HostUnreachable | ErrorKind::NotFound | ErrorKind::AddrNotAvailable => 4,
        ErrorKind::ConnectionRefused => 5,
        _ => REPLY_GENERAL_FAILURE,
    })
}

fn build_udp_associate_response(bound_addr: SocketAddr) -> Vec<u8> {
    let mut response = vec![VER_SOCKS5, REPLY_SUCCESS, 0x00];
    match SocketAddr::new(bound_addr.ip().to_canonical(), bound_addr.port()) {
        SocketAddr::V4(v4) => {
            response.push(ADDR_TYPE_IPV4);
            response.extend_from_slice(&v4.ip().octets());
            response.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            response.push(ADDR_TYPE_IPV6);
            response.extend_from_slice(&v6.ip().octets());
            response.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    response
}

async fn run_udp_associate(
    mut tcp_stream: Box<dyn AsyncStream>,
    relay_stream: Socks5UdpRelayStream,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let server_stream: Box<dyn crate::async_stream::AsyncTargetedMessageStream> =
        Box::new(relay_stream);

    tokio::select! {
        result = run_udp_routing(ServerStream::Targeted(server_stream), proxy_selector, resolver, false) => result,
        _ = monitor_tcp_close(&mut tcp_stream) => {
            log::debug!("SOCKS5 UDP ASSOCIATE: TCP connection closed, terminating relay");
            Ok(())
        }
    }
}

async fn monitor_tcp_close(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(_) => continue,
        }
    }
}

pub async fn read_location<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    stream_reader: &mut StreamReader,
) -> std::io::Result<NetLocation> {
    let address_type = stream_reader.read_u8(stream).await?;
    match address_type {
        ADDR_TYPE_IPV4 => {
            let address_bytes = stream_reader.read_slice(stream, 6).await?;
            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );
            let port = u16::from_be_bytes(address_bytes[4..6].try_into().unwrap());
            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let address_bytes = stream_reader.read_slice(stream, 18).await?;
            let v6addr = std::net::Ipv6Addr::new(
                u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[4..6].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[6..8].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[8..10].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[10..12].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[12..14].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[14..16].try_into().unwrap()),
            );
            let port = u16::from_be_bytes(address_bytes[16..18].try_into().unwrap());
            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let address_len = stream_reader.read_u8(stream).await? as usize;
            let address_bytes = stream_reader.read_slice(stream, address_len + 2).await?;
            let address_str = std::str::from_utf8(&address_bytes[0..address_len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to decode address: {e}"),
                )
            })?;
            let port = u16::from_be_bytes(
                address_bytes[address_len..address_len + 2]
                    .try_into()
                    .unwrap(),
            );
            Ok(NetLocation::new(Address::from(address_str)?, port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {address_type}"),
        )),
    }
}

pub fn write_location_to_vec(location: &NetLocation) -> std::io::Result<Vec<u8>> {
    let (address, port) = location.components();
    let mut vec = match address {
        Address::Ipv4(v4addr) => {
            let mut vec = Vec::with_capacity(7);
            vec.push(ADDR_TYPE_IPV4);
            vec.extend_from_slice(&v4addr.octets());
            vec
        }
        Address::Ipv6(v6addr) => {
            let mut vec = Vec::with_capacity(19);
            vec.push(ADDR_TYPE_IPV6);
            vec.extend_from_slice(&v6addr.octets());
            vec
        }
        Address::Hostname(domain_name) => {
            let domain_name_bytes = domain_name.as_bytes();
            let length = u8::try_from(domain_name_bytes.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS hostname exceeds 255 bytes",
                )
            })?;
            let mut vec = Vec::with_capacity(4 + domain_name_bytes.len());
            vec.push(ADDR_TYPE_DOMAIN_NAME);
            vec.push(length);
            vec.extend_from_slice(domain_name_bytes);
            vec
        }
    };

    vec.push((port >> 8) as u8);
    vec.push((port & 0xff) as u8);
    Ok(vec)
}

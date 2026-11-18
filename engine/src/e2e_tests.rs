//! End-to-end integration tests for `vless-engine` (`PLAN.md` §5, §6, §7, §8).
//!
//! Exercises real cryptography, wire protocols, XUDP muxing, `pcs` SHA-256 certificate pinning,
//! REALITY cover-site fallback diagnostics, and userspace `smoltcp` TUN + port-53 DNS-over-VLESS-TCP
//! completely in-process without requiring root privileges.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use etherparse::PacketBuilder;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixDatagram as AsyncUnixDatagram};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use vless_ipc::{REALITY_AUTH_OR_CLOCK_ERROR, parse_vless_link};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use crate::prepend_stream::PrependStream;
use crate::reality::{
    CipherSuite, RealityServerConfig, decode_private_key, default_target_records, generate_keypair,
};
use crate::resolver::{NativeResolver, Resolver};
use crate::rules::Predicate;
use crate::socks_handler::{
    ADDR_TYPE_IPV4, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_NONE, VER_SOCKS5,
};
use crate::tcp::chain_builder::build_direct_chain_group;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::process_stream;
use crate::vless::vless_server_handler::{
    VlessTcpServerHandler, setup_custom_tls_vision_vless_server_stream,
};
use crate::{EngineConfig, EngineHandle, EngineStatus};

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn direct_selector(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
    Arc::new(ClientProxySelector::new(vec![ConnectRule::compiled(
        Predicate::match_all(),
        false,
        ConnectAction::new_allow(None, Arc::new(build_direct_chain_group(resolver))),
    )]))
}

fn generate_self_signed_tls(hostname: &str) -> (Arc<rustls::ServerConfig>, String) {
    let certified = rcgen::generate_simple_self_signed(vec![hostname.to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let sha256_hex: String = digest(&SHA256, cert_der.as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    (Arc::new(server_cfg), sha256_hex)
}

/// Reads a single complete TLS record (`5 + payload_len` bytes) from `stream`.
async fn read_tls_record<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// Spawns an in-process REALITY + VLESS + Vision + XUDP server that falls back to a genuine cover
/// TLS 1.3 server when REALITY authentication fails (`wrong pbk`, `wrong sid`, or clock skew).
async fn spawn_inprocess_reality_vless_server(
    sni: &str,
    short_id: [u8; 8],
    tasks: &mut JoinSet<()>,
) -> (SocketAddr, String) {
    let (priv_b64, pub_b64) = generate_keypair().unwrap();
    let private_key = decode_private_key(&priv_b64).unwrap();
    let (cover_tls_cfg, _) = generate_self_signed_tls(sni);
    let cover_acceptor = TlsAcceptor::from(cover_tls_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_reality = RealityServerConfig {
        private_key,
        short_ids: vec![short_id],
        dest: NetLocation::from_str(&format!("{sni}:443"), None).unwrap(),
        max_time_diff: Some(120_000),
        min_client_version: None,
        max_client_version: None,
        cipher_suites: vec![
            CipherSuite::AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384,
            CipherSuite::CHACHA20_POLY1305_SHA256,
        ],
    };

    let user_uuid_bytes = crate::uuid_util::parse_uuid(TEST_UUID)
        .unwrap()
        .into_boxed_slice();

    tasks.spawn(async move {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(resolver.clone());
        while let Ok((mut tcp, _)) = listener.accept().await {
            let cfg = server_reality.clone();
            let acceptor = cover_acceptor.clone();
            let user_id = user_uuid_bytes.clone();
            let sel = selector.clone();
            let res = resolver.clone();
            tokio::spawn(async move {
                let Ok(hello) = read_tls_record(&mut tcp).await else {
                    return;
                };
                match cfg.authenticate_client_hello(&hello) {
                    Ok(authenticated) => {
                        let target_flight = default_target_records(&hello[44..76]);
                        let Ok(conn): Result<TlsConnection, _> =
                            authenticated.into_connection(&target_flight)
                        else {
                            return;
                        };
                        let Ok(tls_stream) = CryptoTlsStream::handshake(
                            tcp,
                            conn,
                            TlsReadMode::PreserveRecords,
                            &[],
                        )
                        .await
                        else {
                            return;
                        };
                        let Ok(setup) = setup_custom_tls_vision_vless_server_stream(
                            tls_stream, &user_id, true, sel, &res, None,
                        )
                        .await
                        else {
                            return;
                        };
                        run_test_server_setup(setup, res).await;
                    }
                    Err(_) => {
                        // Transparent cover-site fallback: complete a normal TLS 1.3 handshake with
                        // the cover site's certificate so the client observes an untrusted cover cert.
                        let prepended = PrependStream::new(tcp, Some(hello.into_boxed_slice()));
                        if let Ok(mut cover_stream) = acceptor.accept(prepended).await {
                            let _ = cover_stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                                .await;
                            let _ = cover_stream.flush().await;
                        }
                    }
                }
            });
        }
    });

    (addr, pub_b64)
}

async fn run_test_server_setup(setup: TcpServerSetupResult, resolver: Arc<dyn Resolver>) {
    let handler = Arc::new(OneShotSetupHandler(parking_lot::Mutex::new(Some(setup))));
    let (dummy_a, _dummy_b) = tokio::io::duplex(64);
    let _ = process_stream(
        crate::async_stream::test_streams::FlushGatedStream::new(dummy_a),
        handler,
        resolver,
    )
    .await;
}

struct OneShotSetupHandler(parking_lot::Mutex<Option<TcpServerSetupResult>>);

impl std::fmt::Debug for OneShotSetupHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OneShotSetupHandler")
    }
}

#[async_trait::async_trait]
impl TcpServerHandler for OneShotSetupHandler {
    async fn setup_server_stream(
        &self,
        _server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.0
            .lock()
            .take()
            .ok_or_else(|| std::io::Error::other("setup consumed"))
    }
}

/// Spawns an in-process plain TLS 1.3 (`kTLS`, `vision = false`) VLESS server (`TCP` + `XUDP`).
async fn spawn_inprocess_ktls_vless_server(
    sni: &str,
    tasks: &mut JoinSet<()>,
) -> (SocketAddr, String) {
    let (tls_cfg, sha256_pin) = generate_self_signed_tls(sni);
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tasks.spawn(async move {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(resolver.clone());
        let vless_handler = Arc::new(
            VlessTcpServerHandler::new(TEST_UUID, true, selector, resolver.clone(), None).unwrap(),
        );

        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let handler = vless_handler.clone();
            let res = resolver.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(tcp).await else {
                    return;
                };
                // Wrap tokio_rustls::server::TlsStream in DuplexAsyncStream bridge
                let (a, b) = tokio::io::duplex(65536);
                tokio::spawn(async move {
                    let mut tls_stream = tls_stream;
                    let mut b = b;
                    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut b).await;
                });
                let _ = process_stream(
                    crate::async_stream::test_streams::FlushGatedStream::new(a),
                    handler,
                    res,
                )
                .await;
            });
        }
    });

    (addr, sha256_pin)
}

async fn spawn_tcp_echo(tasks: &mut JoinSet<()>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tasks.spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_udp_echo(prefix: &'static [u8], tasks: &mut JoinSet<()>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tasks.spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let mut reply = Vec::with_capacity(prefix.len() + n);
            reply.extend_from_slice(prefix);
            reply.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&reply, peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn reality_vision_mixed_proxy_http_socks5_and_xudp_e2e() {
    let mut tasks = JoinSet::new();
    let short_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let (vless_addr, pbk) =
        spawn_inprocess_reality_vless_server("cover.example.com", short_id, &mut tasks).await;
    let tcp_echo = spawn_tcp_echo(&mut tasks).await;
    let udp_echo_a = spawn_udp_echo(b"A:", &mut tasks).await;
    let udp_echo_b = spawn_udp_echo(b"B:", &mut tasks).await;

    let profile = parse_vless_link(&format!(
        "vless://{TEST_UUID}@127.0.0.1:{}?security=reality&flow=xtls-rprx-vision&sni=cover.example.com&pbk={pbk}&sid=0123456789abcdef#RealityE2E",
        vless_addr.port()
    ))
    .unwrap()
    .profile;

    let mut cfg = EngineConfig::new_mixed_proxy(profile, "127.0.0.1:0".parse().unwrap());
    // Clear built-in loopback/private bypasses? Note: 127.0.0.0/8 is NOT in BUILTIN_TUN_BYPASS_CIDR_STRS,
    // so 127.0.0.1 targets go straight through VLESS!
    cfg.bypass_cidrs.clear();

    let (handle, state_rx) = EngineHandle::start(cfg).await.unwrap();
    assert_eq!(state_rx.borrow().status, EngineStatus::Connected);
    let proxy_addr = handle.bound_proxy_addr().unwrap();

    // 1. HTTP CONNECT through MixedProxy -> VLESS + REALITY + XTLS-Vision -> TCP echo
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            tcp_echo.port(),
            tcp_echo.port()
        );
        client.write_all(connect_req.as_bytes()).await.unwrap();
        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 Connection established\r\n\r\n"));

        let payload = b"hello over HTTP CONNECT + VLESS + REALITY + Vision!";
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, payload);
    }

    // 2. SOCKS5 CONNECT through MixedProxy -> VLESS + REALITY + XTLS-Vision -> TCP echo
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [VER_SOCKS5, METHOD_NONE]);

        let mut req = vec![VER_SOCKS5, CMD_CONNECT, 0x00, ADDR_TYPE_IPV4, 127, 0, 0, 1];
        req.extend_from_slice(&tcp_echo.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut conn_reply = [0u8; 10];
        client.read_exact(&mut conn_reply).await.unwrap();
        assert_eq!(conn_reply[0..2], [VER_SOCKS5, 0x00]);

        let payload = vec![0x5a; 16384];
        client.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    }

    // 3. SOCKS5 UDP ASSOCIATE -> VLESS + REALITY + Vision + XUDP (`COMMAND_MUX`) to TWO destinations
    {
        let mut ctrl = TcpStream::connect(proxy_addr).await.unwrap();
        ctrl.write_all(&[VER_SOCKS5, 1, METHOD_NONE]).await.unwrap();
        let mut method_reply = [0u8; 2];
        ctrl.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [VER_SOCKS5, METHOD_NONE]);

        ctrl.write_all(&[
            VER_SOCKS5,
            CMD_UDP_ASSOCIATE,
            0x00,
            ADDR_TYPE_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await
        .unwrap();
        let mut assoc_reply = [0u8; 10];
        ctrl.read_exact(&mut assoc_reply).await.unwrap();
        assert_eq!(assoc_reply[0..4], [VER_SOCKS5, 0x00, 0x00, ADDR_TYPE_IPV4]);
        let relay_ip = Ipv4Addr::new(
            assoc_reply[4],
            assoc_reply[5],
            assoc_reply[6],
            assoc_reply[7],
        );
        let relay_port = u16::from_be_bytes([assoc_reply[8], assoc_reply[9]]);
        let relay_addr = SocketAddr::new(IpAddr::V4(relay_ip), relay_port);

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for (target, msg, expected) in [
            (udp_echo_a, b"ping-one".as_slice(), b"A:ping-one".as_slice()),
            (udp_echo_b, b"ping-two".as_slice(), b"B:ping-two".as_slice()),
        ] {
            let mut dgram = vec![0x00, 0x00, 0x00, ADDR_TYPE_IPV4, 127, 0, 0, 1];
            dgram.extend_from_slice(&target.port().to_be_bytes());
            dgram.extend_from_slice(msg);
            udp_client.send_to(&dgram, relay_addr).await.unwrap();

            let mut buf = [0u8; 256];
            let (n, _) =
                tokio::time::timeout(Duration::from_secs(3), udp_client.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(buf[3], ADDR_TYPE_IPV4);
            let src_port = u16::from_be_bytes([buf[8], buf[9]]);
            assert_eq!(src_port, target.port());
            assert_eq!(&buf[10..n], expected);
        }
        drop(ctrl);
    }

    // 4. RecheckServer reachability probe & clean shutdown
    let (reachable, rtt, err) = handle.recheck_server().await;
    assert!(reachable, "expected reachable server, got err={err:?}");
    assert!(rtt.is_some());

    handle.stop().await.unwrap();
    tasks.abort_all();
}

#[tokio::test]
async fn reality_wrong_credentials_surface_cover_fallback_diagnostic() {
    let mut tasks = JoinSet::new();
    let server_sid = [0xaa; 8];
    let (vless_addr, pbk) =
        spawn_inprocess_reality_vless_server("cover.example.com", server_sid, &mut tasks).await;
    let tcp_echo = spawn_tcp_echo(&mut tasks).await;

    // Configure WRONG short_id (`0000000000000000` != `aaaaaaaaaaaaaaaa`)
    let bad_profile = parse_vless_link(&format!(
        "vless://{TEST_UUID}@127.0.0.1:{}?security=reality&flow=xtls-rprx-vision&sni=cover.example.com&pbk={pbk}&sid=0000000000000000#WrongSid",
        vless_addr.port()
    ))
    .unwrap()
    .profile;

    let cfg = EngineConfig::new_mixed_proxy(bad_profile, "127.0.0.1:0".parse().unwrap());
    let (handle, mut state_rx) = EngineHandle::start(cfg).await.unwrap();
    let proxy_addr = handle.bound_proxy_addr().unwrap();

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        tcp_echo.port(),
        tcp_echo.port()
    );
    client.write_all(req.as_bytes()).await.unwrap();

    // Wait for EngineState to transition to Error(REALITY_AUTH_OR_CLOCK_ERROR)
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let st = state_rx.borrow_and_update().clone();
            if st.status == EngineStatus::Error {
                assert_eq!(st.detail.as_deref(), Some(REALITY_AUTH_OR_CLOCK_ERROR));
                break;
            }
            state_rx.changed().await.unwrap();
        }
    })
    .await
    .expect("expected REALITY cover-site fallback diagnostic");

    handle.stop().await.unwrap();
    tasks.abort_all();
}

#[tokio::test]
async fn ktls_plain_tls13_enforces_pcs_sha256_pin_and_supports_tcp_and_xudp_without_vision() {
    let mut tasks = JoinSet::new();
    let (ktls_addr, valid_pin) = spawn_inprocess_ktls_vless_server("localhost", &mut tasks).await;
    let tcp_echo = spawn_tcp_echo(&mut tasks).await;
    let udp_echo = spawn_udp_echo(b"KTLS:", &mut tasks).await;

    // 1. Self-signed kTLS server MUST fail when `pcs` pin is omitted (`PLAN.md` §7)
    {
        let unpinned = parse_vless_link(&format!(
            "vless://{TEST_UUID}@127.0.0.1:{}?security=tls&sni=localhost#Unpinned",
            ktls_addr.port()
        ))
        .unwrap()
        .profile;
        let (handle, _) = EngineHandle::start(EngineConfig::new_mixed_proxy(
            unpinned,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
        let mut client = TcpStream::connect(handle.bound_proxy_addr().unwrap())
            .await
            .unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", tcp_echo.port());
        client.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "self-signed kTLS without pcs must be rejected");
        handle.stop().await.unwrap();
    }

    // 2. Self-signed kTLS server MUST fail when `pcs` pin does NOT match
    {
        let wrong_pin = "ff".repeat(32);
        let bad_pinned = parse_vless_link(&format!(
            "vless://{TEST_UUID}@127.0.0.1:{}?security=tls&sni=localhost&pcs={wrong_pin}#BadPin",
            ktls_addr.port()
        ))
        .unwrap()
        .profile;
        let (handle, _) = EngineHandle::start(EngineConfig::new_mixed_proxy(
            bad_pinned,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
        let mut client = TcpStream::connect(handle.bound_proxy_addr().unwrap())
            .await
            .unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", tcp_echo.port());
        client.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "mismatched pcs SHA-256 pin must be rejected");
        handle.stop().await.unwrap();
    }

    // 3. Matching `pcs` pin succeeds for BOTH plain-TLS VLESS TCP AND XUDP without Vision!
    {
        let pinned = parse_vless_link(&format!(
            "vless://{TEST_UUID}@127.0.0.1:{}?security=tls&sni=localhost&pcs={valid_pin}#GoodPin",
            ktls_addr.port()
        ))
        .unwrap()
        .profile;
        let (handle, _) = EngineHandle::start(EngineConfig::new_mixed_proxy(
            pinned,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
        let proxy_addr = handle.bound_proxy_addr().unwrap();

        // TCP over kTLS
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", tcp_echo.port());
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = [0u8; 39];
        client.read_exact(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200"));
        client.write_all(b"ktls-tcp-ok").await.unwrap();
        let mut echoed = [0u8; 11];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ktls-tcp-ok");

        // UDP over kTLS (`COMMAND_MUX` XUDP without Vision!)
        let mut ctrl = TcpStream::connect(proxy_addr).await.unwrap();
        ctrl.write_all(&[VER_SOCKS5, 1, METHOD_NONE]).await.unwrap();
        let mut m = [0u8; 2];
        ctrl.read_exact(&mut m).await.unwrap();
        ctrl.write_all(&[
            VER_SOCKS5,
            CMD_UDP_ASSOCIATE,
            0x00,
            ADDR_TYPE_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await
        .unwrap();
        let mut assoc = [0u8; 10];
        ctrl.read_exact(&mut assoc).await.unwrap();
        let relay_port = u16::from_be_bytes([assoc[8], assoc[9]]);
        let relay_addr = SocketAddr::from(([127, 0, 0, 1], relay_port));

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut dgram = vec![0, 0, 0, ADDR_TYPE_IPV4, 127, 0, 0, 1];
        dgram.extend_from_slice(&udp_echo.port().to_be_bytes());
        dgram.extend_from_slice(b"udp-no-vision");
        udp.send_to(&dgram, relay_addr).await.unwrap();

        let mut buf = [0u8; 128];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), udp.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[10..n], b"KTLS:udp-no-vision");

        handle.stop().await.unwrap();
    }

    tasks.abort_all();
}

fn utun_pi_header() -> [u8; 4] {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let proto = libc::AF_INET as u32;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let proto: u32 = 0x0800;
    proto.to_be_bytes()
}

fn build_ipv4_udp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    framed: bool,
) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("expected IPv4");
    };
    let builder = PacketBuilder::ipv4(s.octets(), d.octets(), 64).udp(src.port(), dst.port());
    let mut pkt = Vec::new();
    if framed {
        pkt.extend_from_slice(&utun_pi_header());
    }
    builder.write(&mut pkt, payload).unwrap();
    pkt
}

fn parse_ipv4_udp_packet(raw: &[u8], framed: bool) -> (SocketAddr, SocketAddr, Vec<u8>) {
    let raw = if framed {
        assert_eq!(&raw[..4], &utun_pi_header());
        &raw[4..]
    } else {
        raw
    };
    let ip = Ipv4Packet::new_checked(raw).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Udp);
    let src_ip = IpAddr::V4(ip.src_addr());
    let dst_ip = IpAddr::V4(ip.dst_addr());
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert!(udp.verify_checksum(
        &IpAddress::from(ip.src_addr()),
        &IpAddress::from(ip.dst_addr())
    ));
    (
        SocketAddr::new(src_ip, udp.src_port()),
        SocketAddr::new(dst_ip, udp.dst_port()),
        udp.payload().to_vec(),
    )
}

fn build_ipv4_tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    payload: &[u8],
    framed: bool,
) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("expected IPv4");
    };
    let mut tcp =
        PacketBuilder::ipv4(s.octets(), d.octets(), 64).tcp(src.port(), dst.port(), seq, 65535);
    if syn {
        tcp = tcp.syn();
    }
    if let Some(ack_num) = ack {
        tcp = tcp.ack(ack_num);
    }
    if !payload.is_empty() {
        tcp = tcp.psh();
    }
    let mut pkt = Vec::new();
    if framed {
        pkt.extend_from_slice(&utun_pi_header());
    }
    tcp.write(&mut pkt, payload).unwrap();
    pkt
}

#[tokio::test]
async fn tun_mode_port53_dns_over_vless_tcp_and_xudp_e2e() {
    // Upstream UDP DNS responder (`DnsForwarder` forwards both TUN UDP:53 and TUN TCP:53 over a
    // single shared XUDP association to `<dns_resolver>:53`, redirected on the server to `dns_local_addr`).
    let mut tasks = JoinSet::new();
    let dns_udp_hits = Arc::new(AtomicUsize::new(0));
    let seen_wire_ids = Arc::new(parking_lot::Mutex::new(Vec::<u16>::new()));
    let dns_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let dns_local_addr = dns_sock.local_addr().unwrap();
    let hits_clone = dns_udp_hits.clone();
    let wire_ids_clone = seen_wire_ids.clone();
    let dns_sock_task = dns_sock.clone();

    tasks.spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = dns_sock_task.recv_from(&mut buf).await {
            if n < 12 {
                continue;
            }
            let query = buf[..n].to_vec();
            let wire_id = u16::from_be_bytes([query[0], query[1]]);
            wire_ids_clone.lock().push(wire_id);
            hits_clone.fetch_add(1, Ordering::SeqCst);

            let sock_reply = dns_sock_task.clone();
            tokio::spawn(async move {
                let marker = query.get(12).copied().unwrap_or(34);
                // Reply out-of-order when marker 1 and marker 2 are concurrently in flight!
                if marker == 1 {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                } else if marker == 2 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let mut answer = query;
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer.extend_from_slice(&[93, 184, 216, marker]);
                let _ = sock_reply.send_to(&answer, peer).await;
            });
        }
    });

    // Spawn REALITY+VLESS server whose outbound selector redirects `198.51.100.53/32` to `dns_local_addr`
    let (priv_b64, pub_b64) = generate_keypair().unwrap();
    let private_key = decode_private_key(&priv_b64).unwrap();
    let short_id = [0x55; 8];
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vless_addr = vless_listener.local_addr().unwrap();
    let udp_echo = spawn_udp_echo(b"TUN-UDP:", &mut tasks).await;
    let vless_conn_count = Arc::new(AtomicUsize::new(0));
    let conn_count_accept = vless_conn_count.clone();

    let server_reality = RealityServerConfig {
        private_key,
        short_ids: vec![short_id],
        dest: NetLocation::from_str("dns.example.com:443", None).unwrap(),
        max_time_diff: Some(120_000),
        min_client_version: None,
        max_client_version: None,
        cipher_suites: vec![CipherSuite::AES_128_GCM_SHA256],
    };
    let user_uuid_bytes = crate::uuid_util::parse_uuid(TEST_UUID)
        .unwrap()
        .into_boxed_slice();

    tasks.spawn(async move {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let direct = Arc::new(build_direct_chain_group(resolver.clone()));
        let dns_cidr: Vec<ipnetwork::IpNetwork> = vec!["198.51.100.53/32".parse().unwrap()];
        let selector = Arc::new(ClientProxySelector::new(vec![
            ConnectRule::compiled(
                Predicate::from_cidrs(&dns_cidr, true).unwrap(),
                true,
                ConnectAction::new_allow(
                    Some(NetLocation::from_ip_addr(
                        dns_local_addr.ip(),
                        dns_local_addr.port(),
                    )),
                    direct.clone(),
                ),
            ),
            ConnectRule::compiled(
                Predicate::match_all(),
                false,
                ConnectAction::new_allow(None, direct),
            ),
        ]));

        while let Ok((mut tcp, _)) = vless_listener.accept().await {
            conn_count_accept.fetch_add(1, Ordering::SeqCst);
            let cfg = server_reality.clone();
            let uid = user_uuid_bytes.clone();
            let sel = selector.clone();
            let res = resolver.clone();
            tokio::spawn(async move {
                let Ok(hello) = read_tls_record(&mut tcp).await else {
                    return;
                };
                let Ok(auth) = cfg.authenticate_client_hello(&hello) else {
                    return;
                };
                let target_flight = default_target_records(&hello[44..76]);
                let Ok(conn) = auth.into_connection(&target_flight) else {
                    return;
                };
                let Ok(tls_stream) =
                    CryptoTlsStream::handshake(tcp, conn, TlsReadMode::PreserveRecords, &[]).await
                else {
                    return;
                };
                if let Ok(setup) = setup_custom_tls_vision_vless_server_stream(
                    tls_stream, &uid, true, sel, &res, None,
                )
                .await
                {
                    run_test_server_setup(setup, res).await;
                }
            });
        }
    });

    // Test BOTH raw IP framing (`framed = false`) AND 4-byte PI framing (`framed = true`)!
    for framed in [false, true] {
        vless_conn_count.store(0, Ordering::SeqCst);
        seen_wire_ids.lock().clear();

        let (wire_std, tun_std) = UnixDatagram::pair().unwrap();
        wire_std.set_nonblocking(true).unwrap();
        let wire = AsyncUnixDatagram::from_std(wire_std).unwrap();

        let profile = parse_vless_link(&format!(
            "vless://{TEST_UUID}@vless.internal.invalid:{}?security=reality&flow=xtls-rprx-vision&sni=dns.example.com&pbk={pub_b64}&sid=5555555555555555#TunTest",
            vless_addr.port()
        ))
        .unwrap()
        .profile;

        let mut cfg = EngineConfig::new_tun(profile, tun_std.as_raw_fd(), false, framed, None);
        cfg.dns_resolver = "198.51.100.53".parse().unwrap();

        // Pin `vless.internal.invalid` -> `127.0.0.1` via ServerEndpointResolver!
        let (handle, state_rx) =
            EngineHandle::start_with_pinned_server_ips(cfg, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
                .await
                .unwrap();
        assert_eq!(state_rx.borrow().status, EngineStatus::Connected);

        // 1. Fire TWO concurrent TUN UDP DNS queries from DIFFERENT source ports (`53001` ->
        //    `198.18.0.2:53` and `53002` -> `198.51.100.53:53`) with the EXACT SAME client DNS ID
        //    `0xabcd` to verify concurrent wire ID rewriting over a single XUDP session!
        let app_src_1: SocketAddr = "198.18.0.1:53001".parse().unwrap();
        let app_src_2: SocketAddr = "198.18.0.1:53002".parse().unwrap();
        let stub_dns: SocketAddr = "198.18.0.2:53".parse().unwrap();
        let configured_dns: SocketAddr = "198.51.100.53:53".parse().unwrap();

        let dns_query_1 = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 1,
        ];
        let dns_query_2 = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 2,
        ];
        wire.send(&build_ipv4_udp_packet(
            app_src_1,
            stub_dns,
            &dns_query_1,
            framed,
        ))
        .await
        .unwrap();
        wire.send(&build_ipv4_udp_packet(
            app_src_2,
            configured_dns,
            &dns_query_2,
            framed,
        ))
        .await
        .unwrap();

        let mut recv_buf = [0u8; 2048];
        let mut got_1 = false;
        let mut got_2 = false;
        for _ in 0..2 {
            let n = tokio::time::timeout(Duration::from_secs(3), wire.recv(&mut recv_buf))
                .await
                .unwrap()
                .unwrap();
            let (reply_src, reply_dst, reply_payload) =
                parse_ipv4_udp_packet(&recv_buf[..n], framed);
            assert_eq!(&reply_payload[0..2], &[0xab, 0xcd]);
            if reply_dst == app_src_1 {
                assert_eq!(reply_src, stub_dns);
                assert_eq!(
                    &reply_payload[reply_payload.len() - 4..],
                    &[93, 184, 216, 1]
                );
                got_1 = true;
            } else if reply_dst == app_src_2 {
                assert_eq!(reply_src, configured_dns);
                assert_eq!(
                    &reply_payload[reply_payload.len() - 4..],
                    &[93, 184, 216, 2]
                );
                got_2 = true;
            } else {
                panic!("unexpected UDP DNS reply destination {reply_dst}");
            }
        }
        assert!(got_1 && got_2);
        {
            let ids = seen_wire_ids.lock().clone();
            assert_eq!(ids.len(), 2);
            assert_ne!(
                ids[0], ids[1],
                "concurrent colliding client DNS IDs must be rewritten to distinct wire IDs"
            );
        }

        // 2. Drive a TUN TCP port-53 DNS query (`smoltcp` 3-way handshake + RFC 1035 2-byte length
        //    frame) to `198.51.100.53:53` and verify it ALSO shares the exact same XUDP connection!
        let tcp_src: SocketAddr = "198.18.0.1:53100".parse().unwrap();
        let mut client_seq: u32 = 10_000;
        wire.send(&build_ipv4_tcp_packet(
            tcp_src,
            configured_dns,
            client_seq,
            None,
            true,
            &[],
            framed,
        ))
        .await
        .unwrap();
        client_seq = client_seq.wrapping_add(1);

        let server_ack = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let n = wire.recv(&mut recv_buf).await.unwrap();
                let raw = if framed {
                    &recv_buf[4..n]
                } else {
                    &recv_buf[..n]
                };
                let ip = Ipv4Packet::new_checked(raw).unwrap();
                if ip.next_header() != IpProtocol::Tcp {
                    continue;
                }
                let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                if tcp.dst_port() == tcp_src.port() && tcp.syn() && tcp.ack() {
                    return (tcp.seq_number().0 as u32).wrapping_add(1);
                }
            }
        })
        .await
        .unwrap();

        // Complete 3-way handshake (`ACK`) and push RFC 1035 TCP DNS query frame
        wire.send(&build_ipv4_tcp_packet(
            tcp_src,
            configured_dns,
            client_seq,
            Some(server_ack),
            false,
            &[],
            framed,
        ))
        .await
        .unwrap();

        let tcp_dns_query = vec![
            0x77, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3,
        ];
        let mut tcp_dns_frame = Vec::with_capacity(2 + tcp_dns_query.len());
        tcp_dns_frame.extend_from_slice(&(tcp_dns_query.len() as u16).to_be_bytes());
        tcp_dns_frame.extend_from_slice(&tcp_dns_query);

        wire.send(&build_ipv4_tcp_packet(
            tcp_src,
            configured_dns,
            client_seq,
            Some(server_ack),
            false,
            &tcp_dns_frame,
            framed,
        ))
        .await
        .unwrap();
        client_seq = client_seq.wrapping_add(tcp_dns_frame.len() as u32);

        let tcp_dns_resp = tokio::time::timeout(Duration::from_secs(3), async {
            let mut acc = Vec::new();
            let mut next_ack = server_ack;
            loop {
                let n = wire.recv(&mut recv_buf).await.unwrap();
                let raw = if framed {
                    &recv_buf[4..n]
                } else {
                    &recv_buf[..n]
                };
                let ip = Ipv4Packet::new_checked(raw).unwrap();
                if ip.next_header() != IpProtocol::Tcp {
                    continue;
                }
                let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                if tcp.dst_port() != tcp_src.port() || tcp.payload().is_empty() {
                    continue;
                }
                acc.extend_from_slice(tcp.payload());
                next_ack = next_ack.wrapping_add(tcp.payload().len() as u32);
                let _ = wire
                    .send(&build_ipv4_tcp_packet(
                        tcp_src,
                        configured_dns,
                        client_seq,
                        Some(next_ack),
                        false,
                        &[],
                        framed,
                    ))
                    .await;
                if acc.len() >= 2 {
                    let expected_len = usize::from(u16::from_be_bytes([acc[0], acc[1]]));
                    if acc.len() >= 2 + expected_len {
                        return acc[2..2 + expected_len].to_vec();
                    }
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(&tcp_dns_resp[0..2], &[0x77, 0x88]);
        assert_eq!(&tcp_dns_resp[tcp_dns_resp.len() - 4..], &[93, 184, 216, 3]);

        // ALL THREE DNS queries (2 UDP source ports + 1 TCP port-53 connection) MUST have shared
        // a SINGLE VLESS+REALITY+XUDP connection!
        assert_eq!(
            vless_conn_count.load(Ordering::SeqCst),
            1,
            "multiple TUN UDP DNS source ports + TUN TCP port-53 must share ONE XUDP session"
        );

        // 3. Send non-53 UDP packet through TUN -> XUDP -> udp_echo
        let app_udp_src: SocketAddr = "198.18.0.1:54000".parse().unwrap();
        let udp_pkt = build_ipv4_udp_packet(app_udp_src, udp_echo, b"hello-tun", framed);
        wire.send(&udp_pkt).await.unwrap();

        let n2 = tokio::time::timeout(Duration::from_secs(3), wire.recv(&mut recv_buf))
            .await
            .unwrap()
            .unwrap();
        let (u_src, u_dst, u_payload) = parse_ipv4_udp_packet(&recv_buf[..n2], framed);
        assert_eq!(u_src, udp_echo);
        assert_eq!(u_dst, app_udp_src);
        assert_eq!(u_payload, b"TUN-UDP:hello-tun");
        assert_eq!(vless_conn_count.load(Ordering::SeqCst), 2);

        handle.stop().await.unwrap();
        drop(tun_std);
    }

    assert_eq!(
        dns_udp_hits.load(Ordering::SeqCst),
        6,
        "all 6 TUN DNS queries (4 UDP + 2 TCP) must be tunnelled over shared XUDP"
    );
    tasks.abort_all();
}

#[tokio::test]
async fn tun_dns_query_against_wrong_reality_credentials_surfaces_auth_clock_error() {
    let mut tasks = JoinSet::new();
    let server_sid = [0xaa; 8];
    let (vless_addr, pbk) =
        spawn_inprocess_reality_vless_server("cover.example.com", server_sid, &mut tasks).await;

    let bad_profile = parse_vless_link(&format!(
        "vless://{TEST_UUID}@127.0.0.1:{}?security=reality&flow=xtls-rprx-vision&sni=cover.example.com&pbk={pbk}&sid=0000000000000000#TunWrongSid",
        vless_addr.port()
    ))
    .unwrap()
    .profile;

    let (wire_std, tun_std) = std::os::unix::net::UnixDatagram::pair().unwrap();
    wire_std.set_nonblocking(true).unwrap();
    let wire = tokio::net::UnixDatagram::from_std(wire_std).unwrap();

    let cfg = EngineConfig::new_tun(bad_profile, tun_std.as_raw_fd(), false, true, None);
    let (handle, mut state_rx) =
        EngineHandle::start_with_pinned_server_ips(cfg, vec![vless_addr.ip()])
            .await
            .unwrap();

    // Send ONLY a UDP port-53 DNS query (no TCP SYN!) — matching macOS where mDNSResponder queries
    // DNS before any TCP connection starts.
    let dns_query = crate::resolver::build_rfc1035_query("example.com", 1, 0x3344).unwrap();
    let pkt = build_ipv4_udp_packet(
        "198.18.0.1:53001".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
        &dns_query,
        true,
    );
    wire.send(&pkt).await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let st = state_rx.borrow_and_update().clone();
            if st.status == EngineStatus::Error {
                assert_eq!(st.detail.as_deref(), Some(REALITY_AUTH_OR_CLOCK_ERROR));
                break;
            }
            state_rx.changed().await.unwrap();
        }
    })
    .await
    .expect(
        "TUN DNS query with wrong REALITY credentials must surface REALITY_AUTH_OR_CLOCK_ERROR",
    );

    handle.stop().await.unwrap();
    drop(tun_std);
    tasks.abort_all();
}

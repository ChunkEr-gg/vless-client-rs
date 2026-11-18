//! Live protocol interoperability E2E suite against stock `Xray-core` (`26.11.9`)
//! per `docs/PLAN.md` (§1, §2, §5.4, §5.6, §8 Phase 2).
//!
//! Exercises:
//! 1. VLESS + REALITY + `xtls-rprx-vision` (`0x01` TCP via HTTP proxy GET, HTTP CONNECT, and
//!    SOCKS5 CONNECT including a 2 MiB binary stream SHA-256 check; right-zero-padded short `sid`;
//!    SOCKS5 `UDP ASSOCIATE` over Vision + Mux `0x03` XUDP; plus side-by-side stock `Xray-core`
//!    client verification against the exact same server).
//! 2. REALITY unauthenticated fallback diagnostics (`wrong sid` and `wrong pbk` transparently
//!    forwarded by live `Xray-core` to a local TLS 1.3 cover server, surfacing
//!    [`vless_ipc::REALITY_AUTH_OR_CLOCK_ERROR`] on [`EngineState`]).
//! 3. Plain TLS 1.3 (`kTLS` profile, `flow = ""`, `alpn = ["http/1.1"]`, `pcs` SHA-256 leaf pin)
//!    TCP (`0x01`) AND non-Vision Mux `0x03` XUDP (`UDP ASSOCIATE`), plus rejection when `pcs` is
//!    omitted against a self-signed server certificate.
//! 4. Userspace `smoltcp` `Tun` mode over a raw socketpair fd with 4-byte PI/AF framing, routing
//!    concurrent port-53 DNS queries (`1.1.1.1:53`) through [`DnsForwarder`]'s single shared XUDP
//!    session -> live `Xray-core` REALITY+Vision server -> local RFC 1035 UDP DNS responder.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use etherparse::PacketBuilder;
use parking_lot::Mutex;
use serde_json::{Value, json};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixDatagram as AsyncUnixDatagram};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use vless_engine::socks_handler::{
    ADDR_TYPE_IPV4, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_NONE, VER_SOCKS5,
};
use vless_engine::{EngineConfig, EngineHandle, EngineState, EngineStatus};
use vless_ipc::{REALITY_AUTH_OR_CLOCK_ERROR, parse_vless_link};

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const COVER_SNI: &str = "cover.example.test";
const KTLS_SNI: &str = "ktls.example.test";
const BINARY_PAYLOAD_LEN: usize = 2 * 1024 * 1024; // 2 MiB
const SMALL_HTTP_BODY: &[u8] = b"xray-interop-small-http-ok\n";

struct StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        eprintln!(
            "[ENGINE {} {}] {}",
            record.level(),
            record.target(),
            record.args()
        );
    }
    fn flush(&self) {}
}
static LOGGER: StderrLogger = StderrLogger;

/// Locates the `xray` binary via `XRAY_BINARY` or the default `/tmp/xray-bin/xray`.
fn find_xray_binary() -> Option<PathBuf> {
    if std::env::var_os("INTEROP_DEBUG_LOG").is_some() {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Debug);
    }
    let candidate = std::env::var_os("XRAY_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/xray-bin/xray"));
    if candidate.is_file() {
        Some(candidate)
    } else {
        eprintln!(
            "Skipping live Xray interop test: xray binary not found at {} (set XRAY_BINARY to override)",
            candidate.display()
        );
        None
    }
}

/// Parses `xray x25519` output across Xray versions (`PrivateKey:` and `Password (PublicKey):`).
fn parse_xray_x25519_output(stdout: &str) -> Option<(String, String)> {
    let mut private_key = None;
    let mut public_key = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("PrivateKey:")
            .or_else(|| line.strip_prefix("Private key:"))
        {
            private_key = Some(rest.trim().to_owned());
        } else if let Some(rest) = line
            .strip_prefix("Password (PublicKey):")
            .or_else(|| line.strip_prefix("Password:"))
            .or_else(|| line.strip_prefix("Public key:"))
        {
            public_key = Some(rest.trim().to_owned());
        }
    }
    Some((private_key?, public_key?))
}

/// Generates an X25519 keypair `(private_key_b64, public_key_b64)` by invoking `xray x25519`.
fn generate_xray_x25519_keypair(xray_bin: &Path) -> (String, String) {
    let out = Command::new(xray_bin)
        .arg("x25519")
        .output()
        .expect("failed to execute `xray x25519`");
    assert!(
        out.status.success(),
        "`xray x25519` failed with {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("invalid UTF-8 from `xray x25519`");
    parse_xray_x25519_output(&stdout)
        .unwrap_or_else(|| panic!("failed to parse `xray x25519` output:\n{stdout}"))
}

/// RAII process guard ensuring spawned `xray` child processes are always killed and reaped,
/// even if an assertion panics mid-test.
struct XrayProcess {
    child: Option<Child>,
    kill_on_drop: bool,
    port: u16,
    logs: Arc<Mutex<String>>,
    err_log_path: PathBuf,
    stdout_reader: Option<ThreadJoinHandle<()>>,
    stderr_reader: Option<ThreadJoinHandle<()>>,
    _temp_dir: TempDir,
}

impl XrayProcess {
    fn kill_on_drop(&mut self, enabled: bool) {
        self.kill_on_drop = enabled;
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    fn logs_snapshot(&self) -> String {
        let mut out = self.logs.lock().clone();
        if let Ok(file_logs) = std::fs::read_to_string(&self.err_log_path)
            && !file_logs.is_empty()
        {
            out.push_str(&file_logs);
        }
        out
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(handle) = self.stdout_reader.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_reader.take() {
            let _ = handle.join();
        }
    }

    /// Allocates an ephemeral loopback port, writes Xray's JSON config inside an isolated
    /// `TempDir`, spawns `xray run -c`, and awaits the `core: Xray ... started` banner
    /// (retrying automatically if another process raced for the ephemeral port).
    async fn spawn_with_port<F>(xray_bin: &Path, mut make_config: F) -> Self
    where
        F: FnMut(u16, &Path) -> Value,
    {
        let mut last_err = String::new();
        for _attempt in 0..5 {
            let temp_dir = tempfile::tempdir().expect("create tempdir for xray");
            let err_log_path = temp_dir.path().join("xray-error.log");
            let port = {
                let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
                listener.local_addr().expect("ephemeral local_addr").port()
            };

            let mut cfg_value = make_config(port, temp_dir.path());
            if let Some(log_obj) = cfg_value.get_mut("log").and_then(Value::as_object_mut) {
                log_obj.insert(
                    "error".to_owned(),
                    Value::String(err_log_path.to_str().unwrap().to_owned()),
                );
            }
            let cfg_path = temp_dir.path().join("config.json");
            std::fs::write(
                &cfg_path,
                serde_json::to_vec_pretty(&cfg_value).expect("serialize xray config"),
            )
            .expect("write xray config.json");

            let mut cmd = Command::new(xray_bin);
            cmd.args(["run", "-c"])
                .arg(&cfg_path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(asset_dir) = xray_bin.parent() {
                cmd.env("XRAY_LOCATION_ASSET", asset_dir);
            }

            let mut child = cmd.spawn().expect("failed to spawn xray binary");
            let stdout = child.stdout.take().expect("xray piped stdout");
            let stderr = child.stderr.take().expect("xray piped stderr");

            let logs = Arc::new(Mutex::new(String::new()));
            let (ready_tx, ready_rx) = oneshot::channel::<()>();
            let ready_tx = Arc::new(Mutex::new(Option::Some(ready_tx)));

            let stdout_reader = spawn_log_drainer(stdout, logs.clone(), ready_tx.clone());
            let stderr_reader = spawn_log_drainer(stderr, logs.clone(), ready_tx.clone());
            let err_log_for_wait = err_log_path.clone();
            let ready_for_poll = ready_tx;
            tokio::spawn(async move {
                for _ in 0..250 {
                    if ready_for_poll.lock().is_none() {
                        break;
                    }
                    if let Ok(txt) = std::fs::read_to_string(&err_log_for_wait)
                        && txt.contains("Xray ")
                        && txt.contains(" started")
                    {
                        if let Some(tx) = ready_for_poll.lock().take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });

            let mut guard = Self {
                child: Some(child),
                kill_on_drop: true,
                port,
                logs,
                err_log_path,
                stdout_reader: Some(stdout_reader),
                stderr_reader: Some(stderr_reader),
                _temp_dir: temp_dir,
            };
            guard.kill_on_drop(true);

            match tokio::time::timeout(Duration::from_secs(5), ready_rx).await {
                Ok(Ok(())) => return guard,
                Ok(Err(_)) => {
                    let output = guard.logs_snapshot();
                    guard.terminate();
                    if output.contains("address already in use") {
                        last_err = output;
                        continue;
                    }
                    panic!("xray exited before starting:\n{output}");
                }
                Err(_) => {
                    let output = guard.logs_snapshot();
                    guard.terminate();
                    panic!("timed out waiting for xray startup banner:\n{output}");
                }
            }
        }
        panic!("failed to bind xray ephemeral port after 5 attempts:\n{last_err}");
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        if self.kill_on_drop {
            self.terminate();
        }
    }
}

fn spawn_log_drainer<R: io::Read + Send + 'static>(
    reader: R,
    logs: Arc<Mutex<String>>,
    ready_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) -> ThreadJoinHandle<()> {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines().map_while(Result::ok) {
            let is_started = line.contains("Xray ") && line.contains(" started");
            {
                let mut guard = logs.lock();
                guard.push_str(&line);
                guard.push('\n');
            }
            if is_started && let Some(tx) = ready_tx.lock().take() {
                let _ = tx.send(());
            }
        }
    })
}

struct GeneratedCertMaterial {
    server_config: Arc<rustls::ServerConfig>,
    cert_pem: String,
    key_pem: String,
    sha256_hex: String,
}

fn generate_tls13_cert_material(hostname: &str, alpns: &[&[u8]]) -> GeneratedCertMaterial {
    let certified = rcgen::generate_simple_self_signed(vec![hostname.to_owned()])
        .expect("rcgen self-signed certificate");
    let cert_der_bytes = certified.cert.der().to_vec();
    let sha256_hex: String = digest(&SHA256, &cert_der_bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();

    let cert_der = rustls::pki_types::CertificateDer::from(cert_der_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
    );
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 protocol config")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("single cert server config");
    server_cfg.alpn_protocols = alpns.iter().map(|p| p.to_vec()).collect();
    server_cfg.ticketer =
        rustls::crypto::aws_lc_rs::Ticketer::new().expect("aws-lc-rs TLS 1.3 ticketer");

    GeneratedCertMaterial {
        server_config: Arc::new(server_cfg),
        cert_pem,
        key_pem,
        sha256_hex,
    }
}

struct CoverServerStats {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
}

impl CoverServerStats {
    /// Deterministically awaits completion of Xray REALITY's asynchronous startup target probe
    /// (`DetectPostHandshakeRecordsLens`, which opens 6 probe connections to `dest` and closes
    /// them once post-handshake `NewSessionTicket` record lengths are recorded).
    async fn wait_for_xray_startup_probes(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.accepted.load(Ordering::SeqCst) < 6 || self.active.load(Ordering::SeqCst) > 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed out waiting for Xray DetectPostHandshakeRecordsLens startup probes");
    }
}

struct ActiveConnGuard(Arc<AtomicUsize>);
impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Spawns a local TLS 1.3 cover server (`"cover.example.test"`, ALPN `h2` + `http/1.1`) used as
/// Xray REALITY's `dest` target.
async fn spawn_cover_tls_server(tasks: &mut JoinSet<()>) -> CoverServerStats {
    let cert = generate_tls13_cert_material(COVER_SNI, &[b"h2", b"http/1.1"]);
    let acceptor = TlsAcceptor::from(cert.server_config);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cover server");
    let addr = listener.local_addr().expect("cover local_addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    let active_task = active.clone();

    tasks.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            accepted_task.fetch_add(1, Ordering::SeqCst);
            active_task.fetch_add(1, Ordering::SeqCst);
            let active_guard = ActiveConnGuard(active_task.clone());
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _guard = active_guard;
                let Ok(Ok(mut tls)) =
                    tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await
                else {
                    return;
                };
                // Flush post-handshake TLS 1.3 `NewSessionTicket` records immediately so Xray
                // REALITY's parallel target handshake completes without waiting for HTTP data.
                let _ = tls.flush().await;

                let mut buf = [0u8; 4096];
                loop {
                    match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(_)) => {
                            let resp = concat!(
                                "HTTP/1.1 200 OK\r\n",
                                "Server: cover-example-test\r\n",
                                "Content-Type: text/plain\r\n",
                                "Content-Length: 16\r\n",
                                "Connection: keep-alive\r\n\r\n",
                                "cover-site-alive"
                            );
                            if tls.write_all(resp.as_bytes()).await.is_err()
                                || tls.flush().await.is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                let _ = tls.shutdown().await;
            });
        }
    });

    CoverServerStats {
        addr,
        accepted,
        active,
    }
}

/// Generates a deterministic 2 MiB binary stream (containing pseudo-random high-entropy bytes and
/// embedded TLS record header lookalikes `0x16 0x03 0x03` to exercise Vision's TLS filter/padding)
/// together with its expected SHA-256 digest.
fn deterministic_2mib_payload() -> (Arc<Vec<u8>>, [u8; 32]) {
    let mut data = vec![0u8; BINARY_PAYLOAD_LEN];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (idx, byte) in data.iter_mut().enumerate() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state as u8).wrapping_add((idx & 0xff) as u8);
    }
    // Inject synthetic TLS 1.3 handshake/application header sequences at deterministic offsets so
    // Vision's inner-TLS scanner and deframer are exercised across record boundaries.
    for offset in [0usize, 1024, 16_384, 65_537, 524_288, 1_500_000] {
        data[offset..offset + 5].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x40]);
    }
    let mut sha = [0u8; 32];
    sha.copy_from_slice(digest(&SHA256, &data).as_ref());
    (Arc::new(data), sha)
}

/// Spawns a local HTTP/1.1 target server on `127.0.0.1:0` serving:
/// - `GET /small` -> 27-byte plain-text body (`SMALL_HTTP_BODY`)
/// - `GET /binary-2mib` -> 2 MiB deterministic binary stream (`BINARY_PAYLOAD_LEN`)
async fn spawn_target_http_and_binary_server(
    payload_2mib: Arc<Vec<u8>>,
    tasks: &mut JoinSet<()>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target HTTP server");
    let addr = listener.local_addr().expect("target local_addr");

    tasks.spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let payload = payload_2mib.clone();
            tokio::spawn(async move {
                let mut req = Vec::with_capacity(512);
                let mut tmp = [0u8; 512];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp)).await
                    {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                        Ok(Ok(n)) => {
                            req.extend_from_slice(&tmp[..n]);
                            if req.len() > 16_384 {
                                return;
                            }
                        }
                    }
                }
                let req_str = String::from_utf8_lossy(&req);
                let first_line = req_str.lines().next().unwrap_or("");
                if first_line.starts_with("GET /binary-2mib ") {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    if stream.write_all(header.as_bytes()).await.is_err() {
                        return;
                    }
                    // Write in varied chunk sizes to exercise multi-record TLS + Vision framing.
                    let mut pos = 0;
                    let chunk_sizes = [4096usize, 16_384, 32_768, 65_536];
                    let mut step = 0;
                    while pos < payload.len() {
                        let end = (pos + chunk_sizes[step % chunk_sizes.len()]).min(payload.len());
                        if stream.write_all(&payload[pos..end]).await.is_err() {
                            return;
                        }
                        pos = end;
                        step += 1;
                    }
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                } else {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        SMALL_HTTP_BODY.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(SMALL_HTTP_BODY).await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });

    addr
}

struct DnsResponderStats {
    addr: SocketAddr,
    query_count: Arc<AtomicUsize>,
    seen_wire_ids: Arc<Mutex<Vec<u16>>>,
    seen_peers: Arc<Mutex<HashSet<SocketAddr>>>,
}

/// Encodes a standard RFC 1035 DNS `A` (`IN`) query with recursion desired (`0x0100`).
fn build_rfc1035_a_query(tx_id: u16, qname: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // QR=0, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    for label in qname.trim_end_matches('.').split('.') {
        assert!(!label.is_empty() && label.len() <= 63);
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // root label
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A (1)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN (1)
    pkt
}

/// Parses the QNAME and end-of-question offset from an RFC 1035 DNS packet.
fn parse_rfc1035_question(pkt: &[u8]) -> Option<(String, usize)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *pkt.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || pos + len > pkt.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&pkt[pos..pos + len])
                .ok()?
                .to_ascii_lowercase(),
        );
        pos += len;
    }
    if pos + 4 > pkt.len() {
        return None;
    }
    let _qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let _qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    pos += 4;
    Some((labels.join("."), pos))
}

/// Parses the transaction ID and first `A` record from an RFC 1035 DNS response packet.
fn parse_rfc1035_a_response(pkt: &[u8]) -> (u16, Ipv4Addr) {
    assert!(
        pkt.len() >= 12,
        "DNS response too short: {} bytes",
        pkt.len()
    );
    let tx_id = u16::from_be_bytes([pkt[0], pkt[1]]);
    assert_eq!(pkt[2] & 0x80, 0x80, "expected QR=1 DNS response");
    assert_eq!(pkt[3] & 0x0f, 0, "expected RCODE=0 NOERROR");
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    assert!(ancount >= 1, "expected at least 1 DNS answer record");

    let (_, mut pos) = parse_rfc1035_question(pkt).expect("valid echoed DNS question");
    // Answer NAME: either 2-byte compression pointer (`0xc0xx`) or uncompressed label sequence.
    if pkt[pos] & 0xc0 == 0xc0 {
        pos += 2;
    } else {
        while pkt[pos] != 0 {
            pos += 1 + usize::from(pkt[pos]);
        }
        pos += 1;
    }
    assert!(pos + 10 <= pkt.len(), "truncated DNS answer RR header");
    let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let rclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
    pos += 10;
    assert_eq!(rtype, 1, "expected A record (TYPE=1)");
    assert_eq!(rclass, 1, "expected IN class (CLASS=1)");
    assert_eq!(rdlen, 4, "expected 4-byte IPv4 RDATA");
    assert!(pos + 4 <= pkt.len(), "truncated DNS A record RDATA");
    (
        tx_id,
        Ipv4Addr::new(pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]),
    )
}

fn expected_dns_answer_for(qname: &str) -> Ipv4Addr {
    match qname {
        "alpha.interop.test" => Ipv4Addr::new(203, 0, 113, 11),
        "bravo.interop.test" => Ipv4Addr::new(203, 0, 113, 22),
        "charlie.interop.test" => Ipv4Addr::new(203, 0, 113, 33),
        "tcp.interop.test" => Ipv4Addr::new(203, 0, 113, 44),
        _ => Ipv4Addr::new(203, 0, 113, 99),
    }
}

/// Spawns a local RFC 1035 UDP DNS responder on `127.0.0.1:0` that answers `A` queries with
/// deterministic `203.0.113.0/24` addresses (intentionally delaying `"alpha.interop.test"` slightly
/// so concurrent queries return out-of-order and exercise wire-ID demultiplexing).
async fn spawn_rfc1035_udp_dns_responder(tasks: &mut JoinSet<()>) -> DnsResponderStats {
    let sock = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind RFC 1035 UDP DNS responder"),
    );
    let addr = sock.local_addr().expect("dns local_addr");
    let query_count = Arc::new(AtomicUsize::new(0));
    let seen_wire_ids = Arc::new(Mutex::new(Vec::new()));
    let seen_peers = Arc::new(Mutex::new(HashSet::new()));

    let sock_task = sock.clone();
    let count_task = query_count.clone();
    let ids_task = seen_wire_ids.clone();
    let peers_task = seen_peers.clone();

    tasks.spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock_task.recv_from(&mut buf).await {
            let pkt = buf[..n].to_vec();
            let Some((qname, question_end)) = parse_rfc1035_question(&pkt) else {
                continue;
            };
            let wire_id = u16::from_be_bytes([pkt[0], pkt[1]]);
            ids_task.lock().push(wire_id);
            peers_task.lock().insert(peer);
            count_task.fetch_add(1, Ordering::SeqCst);

            let sock_reply = sock_task.clone();
            tokio::spawn(async move {
                if qname == "alpha.interop.test" {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let answer_ip = expected_dns_answer_for(&qname);
                let mut resp = Vec::with_capacity(question_end + 16);
                resp.extend_from_slice(&pkt[0..2]); // transaction ID
                resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, NOERROR
                resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
                resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
                resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
                resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
                resp.extend_from_slice(&pkt[12..question_end]); // echoed question
                resp.extend_from_slice(&[0xc0, 0x0c]); // NAME pointer to offset 12
                resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
                resp.extend_from_slice(&answer_ip.octets());
                let _ = sock_reply.send_to(&resp, peer).await;
            });
        }
    });

    DnsResponderStats {
        addr,
        query_count,
        seen_wire_ids,
        seen_peers,
    }
}

/// Splits an HTTP/1.1 response byte vector into `(header_str, body_slice)` and asserts `200 OK`.
fn split_http_200_response(raw: &[u8]) -> (&str, &[u8]) {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "missing HTTP header terminator in {} bytes: {:?}",
                raw.len(),
                String::from_utf8_lossy(&raw[..raw.len().min(200)])
            )
        });
    let headers = std::str::from_utf8(&raw[..sep]).expect("UTF-8 HTTP response headers");
    assert!(
        headers.starts_with("HTTP/1.1 200 OK") || headers.starts_with("HTTP/1.0 200 OK"),
        "expected HTTP 200 OK, got:\n{headers}"
    );
    (headers, &raw[sep + 4..])
}

/// Issues an absolute-form HTTP/1.1 proxy `GET http://target/...` request through `proxy_addr`.
async fn http_proxy_get(proxy_addr: SocketAddr, target_addr: SocketAddr, path: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("connect to HTTP proxy");
    let req = format!(
        "GET http://{target_addr}{path} HTTP/1.1\r\nHost: {target_addr}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write HTTP proxy GET");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("read HTTP proxy GET response");
    let (_, body) = split_http_200_response(&raw);
    body.to_vec()
}

/// Issues an HTTP `CONNECT` tunnel request through `proxy_addr` and fetches `path` from `target_addr`.
async fn http_connect_get(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    path: &str,
) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let connect_req = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await?;

    let mut tunnel_hdr = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !tunnel_hdr.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed connection before CONNECT 200 response",
            ));
        }
        tunnel_hdr.push(byte[0]);
        if tunnel_hdr.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized CONNECT response header",
            ));
        }
    }
    let hdr_str = String::from_utf8_lossy(&tunnel_hdr);
    if !hdr_str.starts_with("HTTP/1.1 200") && !hdr_str.starts_with("HTTP/1.0 200") {
        return Err(io::Error::other(format!(
            "CONNECT failed with status: {hdr_str}"
        )));
    }

    let get_req =
        format!("GET {path} HTTP/1.1\r\nHost: {target_addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(get_req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    if raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty response body over HTTP CONNECT tunnel",
        ));
    }
    let (_, body) = split_http_200_response(&raw);
    Ok(body.to_vec())
}

/// Connects via SOCKS5 `CONNECT` (`127.0.0.1:<port>`) and fetches `path` over HTTP/1.1.
async fn socks5_connect_get(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    path: &str,
) -> io::Result<Vec<u8>> {
    let IpAddr::V4(target_v4) = target_addr.ip() else {
        panic!("expected IPv4 target_addr");
    };
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.write_all(&[VER_SOCKS5, 1, METHOD_NONE]).await?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if method_reply != [VER_SOCKS5, METHOD_NONE] {
        return Err(io::Error::other(format!(
            "unexpected SOCKS5 auth reply: {method_reply:?}"
        )));
    }

    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[VER_SOCKS5, CMD_CONNECT, 0x00, ADDR_TYPE_IPV4]);
    req.extend_from_slice(&target_v4.octets());
    req.extend_from_slice(&target_addr.port().to_be_bytes());
    stream.write_all(&req).await?;

    let mut reply_head = [0u8; 4];
    stream.read_exact(&mut reply_head).await?;
    if reply_head[0] != VER_SOCKS5 || reply_head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT rejected with reply={reply_head:?}"
        )));
    }
    let skip_len = match reply_head[3] {
        ADDR_TYPE_IPV4 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut dlen = [0u8; 1];
            stream.read_exact(&mut dlen).await?;
            usize::from(dlen[0]) + 2
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown SOCKS5 ATYP {other}"),
            ));
        }
    };
    let mut bound_tail = vec![0u8; skip_len];
    stream.read_exact(&mut bound_tail).await?;

    let get_req =
        format!("GET {path} HTTP/1.1\r\nHost: {target_addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(get_req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    if raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty response over SOCKS5 tunnel",
        ));
    }
    let (_, body) = split_http_200_response(&raw);
    Ok(body.to_vec())
}

/// Opens a SOCKS5 `UDP ASSOCIATE` session against `socks_addr` and sends multiple RFC 1035 DNS
/// queries over the same UDP association, asserting source addresses, transaction IDs, and `A`
/// records.
async fn verify_socks5_udp_associate_dns_queries(
    socks_addr: SocketAddr,
    dns_addr: SocketAddr,
    queries: &[(u16, &str)],
) {
    let IpAddr::V4(dns_v4) = dns_addr.ip() else {
        panic!("expected IPv4 dns_addr");
    };
    let mut ctrl = TcpStream::connect(socks_addr)
        .await
        .expect("connect SOCKS5 control stream");
    ctrl.write_all(&[VER_SOCKS5, 1, METHOD_NONE])
        .await
        .expect("write SOCKS5 greeting");
    let mut method_reply = [0u8; 2];
    ctrl.read_exact(&mut method_reply)
        .await
        .expect("read SOCKS5 greeting");
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
    .expect("write UDP ASSOCIATE");

    let mut assoc = [0u8; 10];
    ctrl.read_exact(&mut assoc)
        .await
        .expect("read UDP ASSOCIATE reply");
    assert_eq!(assoc[0..4], [VER_SOCKS5, 0x00, 0x00, ADDR_TYPE_IPV4]);
    let relay_ip = Ipv4Addr::new(assoc[4], assoc[5], assoc[6], assoc[7]);
    let relay_ip = if relay_ip.is_unspecified() {
        Ipv4Addr::LOCALHOST
    } else {
        relay_ip
    };
    let relay_port = u16::from_be_bytes([assoc[8], assoc[9]]);
    let relay_addr = SocketAddr::new(IpAddr::V4(relay_ip), relay_port);

    let udp_client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind local UDP client");
    for &(tx_id, qname) in queries {
        let dns_wire = build_rfc1035_a_query(tx_id, qname);
        let mut dgram = Vec::with_capacity(10 + dns_wire.len());
        dgram.extend_from_slice(&[0x00, 0x00, 0x00, ADDR_TYPE_IPV4]);
        dgram.extend_from_slice(&dns_v4.octets());
        dgram.extend_from_slice(&dns_addr.port().to_be_bytes());
        dgram.extend_from_slice(&dns_wire);

        udp_client
            .send_to(&dgram, relay_addr)
            .await
            .expect("send SOCKS5 UDP datagram");

        let mut recv_buf = [0u8; 1024];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(5), udp_client.recv_from(&mut recv_buf))
                .await
                .expect("timed out waiting for SOCKS5 UDP DNS reply")
                .expect("recv_from SOCKS5 UDP relay");
        assert!(n > 10, "SOCKS5 UDP reply too short ({n} bytes)");
        assert_eq!(&recv_buf[0..4], &[0x00, 0x00, 0x00, ADDR_TYPE_IPV4]);
        let src_ip = Ipv4Addr::new(recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7]);
        let src_port = u16::from_be_bytes([recv_buf[8], recv_buf[9]]);
        assert_eq!(SocketAddr::new(IpAddr::V4(src_ip), src_port), dns_addr);

        let (got_id, got_ip) = parse_rfc1035_a_response(&recv_buf[10..n]);
        assert_eq!(got_id, tx_id);
        assert_eq!(got_ip, expected_dns_answer_for(qname));
    }

    drop(ctrl);
}

fn utun_pi_ipv4_header() -> [u8; 4] {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let proto = libc::AF_INET as u32;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let proto: u32 = 0x0800;
    proto.to_be_bytes()
}

fn build_framed_ipv4_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("expected IPv4 endpoints");
    };
    let builder = PacketBuilder::ipv4(s.octets(), d.octets(), 64).udp(src.port(), dst.port());
    let mut pkt = Vec::with_capacity(4 + 28 + payload.len());
    pkt.extend_from_slice(&utun_pi_ipv4_header());
    builder.write(&mut pkt, payload).expect("encode IPv4+UDP");
    pkt
}

fn parse_framed_ipv4_udp_packet(raw: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    assert!(raw.len() > 4 + 28, "framed TUN packet too short");
    assert_eq!(
        &raw[..4],
        &utun_pi_ipv4_header(),
        "unexpected 4-byte TUN PI/AF header"
    );
    let ip = Ipv4Packet::new_checked(&raw[4..]).expect("valid IPv4 packet");
    assert_eq!(ip.next_header(), IpProtocol::Udp);
    let udp = UdpPacket::new_checked(ip.payload()).expect("valid UDP packet");
    assert!(
        udp.verify_checksum(
            &IpAddress::from(ip.src_addr()),
            &IpAddress::from(ip.dst_addr())
        ),
        "UDP checksum verification failed"
    );
    (
        SocketAddr::new(IpAddr::V4(ip.src_addr()), udp.src_port()),
        SocketAddr::new(IpAddr::V4(ip.dst_addr()), udp.dst_port()),
        udp.payload().to_vec(),
    )
}

fn build_framed_ipv4_tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    payload: &[u8],
) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("expected IPv4 endpoints");
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
    let mut pkt = Vec::with_capacity(4 + 40 + payload.len());
    pkt.extend_from_slice(&utun_pi_ipv4_header());
    tcp.write(&mut pkt, payload).expect("encode IPv4+TCP");
    pkt
}

/// 1. Live `Xray-core` REALITY + `xtls-rprx-vision` server interoperability:
///    - Right-zero-padded short `sid=beef` (`"beef000000000000"` on Xray server)
///    - HTTP proxy `GET`, HTTP `CONNECT`, SOCKS5 `CONNECT`
///    - Deterministic 2 MiB binary stream verified by SHA-256
///    - SOCKS5 `UDP ASSOCIATE` over Vision + Mux `0x03` XUDP to local RFC 1035 DNS responder
///    - Side-by-side stock `Xray-core` client process (`socks` inbound -> `vless` + `reality` +
///      `xtls-rprx-vision` outbound) against the exact same live Xray server (`PLAN.md` §8 Phase 2)
#[tokio::test]
async fn xray_reality_vision_tcp_http_socks5_large_sha256_and_xudp_e2e() {
    let Some(xray_bin) = find_xray_binary() else {
        return;
    };

    tokio::time::timeout(Duration::from_secs(30), async move {
        let mut tasks = JoinSet::new();
        let cover_stats = spawn_cover_tls_server(&mut tasks).await;
        let cover_addr = cover_stats.addr;
        let (payload_2mib, expected_sha256) = deterministic_2mib_payload();
        let target_addr = spawn_target_http_and_binary_server(payload_2mib, &mut tasks).await;
        let dns_stats = spawn_rfc1035_udp_dns_responder(&mut tasks).await;

        let (priv_key, pub_key) = generate_xray_x25519_keypair(&xray_bin);
        let priv_for_cfg = priv_key.clone();
        let mut xray_server = XrayProcess::spawn_with_port(&xray_bin, move |port, _dir| {
            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "flow": "xtls-rprx-vision"
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": false,
                            "dest": cover_addr.to_string(),
                            "xver": 0,
                            "serverNames": [COVER_SNI],
                            "privateKey": priv_for_cfg,
                            "shortIds": ["0123456789abcdef", "beef000000000000"],
                            "maxTimeDiff": 120000
                        }
                    }
                }],
                "outbounds": [{
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": { "finalRules": [{ "action": "allow" }] }
                }]
            })
        })
        .await;
        cover_stats.wait_for_xray_startup_probes().await;

        // Pass 4-hex-digit `sid=beef` in `vless://` link to verify right-zero-padding against Xray's
        // `"beef000000000000"` shortId entry (`PLAN.md` §2).
        let vless_link = format!(
            "vless://{TEST_UUID}@127.0.0.1:{}?security=reality&flow=xtls-rprx-vision&sni={COVER_SNI}&pbk={pub_key}&sid=beef#XrayRealityVision",
            xray_server.port()
        );
        let profile = parse_vless_link(&vless_link)
            .expect("parse REALITY vless:// link")
            .profile;

        let cfg = EngineConfig::new_mixed_proxy(profile, "127.0.0.1:0".parse().unwrap());
        let (engine, state_rx) = EngineHandle::start(cfg).await.expect("start vless-engine");
        assert_eq!(state_rx.borrow().status, EngineStatus::Connected);
        let engine_proxy = engine.bound_proxy_addr().expect("bound mixed proxy addr");

        // (a) HTTP proxy GET
        let body_proxy_get = http_proxy_get(engine_proxy, target_addr, "/small").await;
        assert_eq!(body_proxy_get, SMALL_HTTP_BODY);

        // (b) HTTP CONNECT
        let body_connect = http_connect_get(engine_proxy, target_addr, "/small")
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "HTTP CONNECT via vless-engine failed: {e}\nXray logs:\n{}",
                    xray_server.logs_snapshot()
                )
            });
        assert_eq!(body_connect, SMALL_HTTP_BODY);

        // (c) SOCKS5 TCP CONNECT + 2 MiB binary transfer SHA-256 verification
        let body_socks_small = socks5_connect_get(engine_proxy, target_addr, "/small")
            .await
            .expect("SOCKS5 small GET via vless-engine");
        assert_eq!(body_socks_small, SMALL_HTTP_BODY);

        let body_2mib = socks5_connect_get(engine_proxy, target_addr, "/binary-2mib")
            .await
            .expect("SOCKS5 2 MiB download via vless-engine");
        assert_eq!(body_2mib.len(), BINARY_PAYLOAD_LEN);
        assert_eq!(digest(&SHA256, &body_2mib).as_ref(), &expected_sha256);

        // Also verify 2 MiB over HTTP CONNECT to exercise both mixed-inbound tunnel paths.
        let connect_2mib = http_connect_get(engine_proxy, target_addr, "/binary-2mib")
            .await
            .expect("HTTP CONNECT 2 MiB download via vless-engine");
        assert_eq!(connect_2mib.len(), BINARY_PAYLOAD_LEN);
        assert_eq!(digest(&SHA256, &connect_2mib).as_ref(), &expected_sha256);

        // (d) SOCKS5 UDP ASSOCIATE -> Vision + Mux `0x03` XUDP (`New` + `Keep` frames) -> Xray `freedom`
        verify_socks5_udp_associate_dns_queries(
            engine_proxy,
            dns_stats.addr,
            &[(0x1001, "alpha.interop.test"), (0x1002, "bravo.interop.test")],
        )
        .await;

        // (e) Side-by-side stock `Xray-core` client process against the exact same Xray server (`PLAN.md` §8 Phase 2)
        let server_port = xray_server.port();
        let pub_for_client = pub_key.clone();
        let mut xray_client = XrayProcess::spawn_with_port(&xray_bin, move |socks_port, _dir| {
            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": true,
                        "ip": "127.0.0.1"
                    }
                }],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": server_port,
                            "users": [{
                                "id": TEST_UUID,
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": COVER_SNI,
                            "fingerprint": "chrome",
                            "publicKey": pub_for_client,
                            "shortId": "beef"
                        }
                    }
                }]
            })
        })
        .await;

        let xray_client_body =
            socks5_connect_get(xray_client.addr(), target_addr, "/binary-2mib")
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "side-by-side Xray client TCP failed: {e}\nclient logs:\n{}\nserver logs:\n{}",
                        xray_client.logs_snapshot(),
                        xray_server.logs_snapshot()
                    )
                });
        assert_eq!(xray_client_body.len(), BINARY_PAYLOAD_LEN);
        assert_eq!(
            digest(&SHA256, &xray_client_body).as_ref(),
            &expected_sha256
        );

        verify_socks5_udp_associate_dns_queries(
            xray_client.addr(),
            dns_stats.addr,
            &[(0x2001, "alpha.interop.test"), (0x2002, "charlie.interop.test")],
        )
        .await;

        engine.stop().await.expect("stop vless-engine");
        xray_client.terminate();
        xray_server.terminate();
        tasks.abort_all();
    })
    .await
    .expect("xray_reality_vision_tcp_http_socks5_large_sha256_and_xudp_e2e timed out");
}

async fn assert_reality_auth_or_clock_error_surfaced(vless_link: &str, target_addr: SocketAddr) {
    let profile = parse_vless_link(vless_link)
        .expect("parse REALITY vless:// link")
        .profile;
    let cfg = EngineConfig::new_mixed_proxy(profile, "127.0.0.1:0".parse().unwrap());
    let (engine, mut state_rx) = EngineHandle::start(cfg).await.expect("start vless-engine");
    let proxy_addr = engine.bound_proxy_addr().expect("bound mixed proxy addr");

    let connect_res = http_connect_get(proxy_addr, target_addr, "/small").await;
    assert!(
        connect_res.is_err(),
        "unauthenticated REALITY client must reject cover server certificate"
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let st: EngineState = state_rx.borrow_and_update().clone();
            if st.status == EngineStatus::Error {
                let detail = st.detail.unwrap_or_default();
                assert!(
                    detail.contains(REALITY_AUTH_OR_CLOCK_ERROR),
                    "expected REALITY_AUTH_OR_CLOCK_ERROR in EngineState::detail, got: {detail:?}"
                );
                break;
            }
            state_rx
                .changed()
                .await
                .expect("state_rx closed before EngineStatus::Error");
        }
    })
    .await
    .expect("timed out waiting for EngineStatus::Error(REALITY_AUTH_OR_CLOCK_ERROR)");

    engine.stop().await.expect("stop vless-engine");
}

/// 2. Live `Xray-core` REALITY transparent cover-server fallback on (a) wrong `sid` and
///    (b) wrong `pbk` (`PLAN.md` §5.6, §8 Phase 2):
///    Verifies Xray hands unauthenticated handshakes to the cover TLS 1.3 server and `vless-engine`
///    rejects the untrusted cover certificate with [`vless_ipc::REALITY_AUTH_OR_CLOCK_ERROR`].
#[tokio::test]
async fn xray_reality_wrong_pbk_and_wrong_sid_report_clear_auth_clock_error() {
    let Some(xray_bin) = find_xray_binary() else {
        return;
    };

    tokio::time::timeout(Duration::from_secs(30), async move {
        let mut tasks = JoinSet::new();
        let cover_stats = spawn_cover_tls_server(&mut tasks).await;
        let cover_addr = cover_stats.addr;
        let (payload_2mib, _) = deterministic_2mib_payload();
        let target_addr = spawn_target_http_and_binary_server(payload_2mib, &mut tasks).await;

        let (server_priv, server_pub) = generate_xray_x25519_keypair(&xray_bin);
        let (_, mut wrong_pub) = generate_xray_x25519_keypair(&xray_bin);
        while wrong_pub == server_pub {
            (_, wrong_pub) = generate_xray_x25519_keypair(&xray_bin);
        }

        let mut xray_server = XrayProcess::spawn_with_port(&xray_bin, move |port, _dir| {
            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "flow": "xtls-rprx-vision"
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": false,
                            "dest": cover_addr.to_string(),
                            "xver": 0,
                            "serverNames": [COVER_SNI],
                            "privateKey": server_priv,
                            "shortIds": ["0123456789abcdef"],
                            "maxTimeDiff": 120000
                        }
                    }
                }],
                "outbounds": [{
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": { "finalRules": [{ "action": "allow" }] }
                }]
            })
        })
        .await;
        cover_stats.wait_for_xray_startup_probes().await;

        let baseline_cover = cover_stats.accepted.load(Ordering::SeqCst);

        // (a) Wrong `sid` (`deadbeefcafebabe` != `0123456789abcdef`)
        let wrong_sid_link = format!(
            "vless://{TEST_UUID}@127.0.0.1:{}?security=reality&flow=xtls-rprx-vision&sni={COVER_SNI}&pbk={server_pub}&sid=deadbeefcafebabe#WrongSid",
            xray_server.port()
        );
        assert_reality_auth_or_clock_error_surfaced(&wrong_sid_link, target_addr).await;
        let after_wrong_sid = cover_stats.accepted.load(Ordering::SeqCst);
        assert!(
            after_wrong_sid > baseline_cover,
            "expected Xray REALITY server to forward wrong-sid handshake to cover TLS server"
        );

        // (b) Wrong `pbk` (`wrong_pub` != `server_pub`)
        let wrong_pbk_link = format!(
            "vless://{TEST_UUID}@127.0.0.1:{}?security=reality&flow=xtls-rprx-vision&sni={COVER_SNI}&pbk={wrong_pub}&sid=0123456789abcdef#WrongPbk",
            xray_server.port()
        );
        assert_reality_auth_or_clock_error_surfaced(&wrong_pbk_link, target_addr).await;
        let after_wrong_pbk = cover_stats.accepted.load(Ordering::SeqCst);
        assert!(
            after_wrong_pbk > after_wrong_sid,
            "expected Xray REALITY server to forward wrong-pbk handshake to cover TLS server"
        );

        xray_server.terminate();
        tasks.abort_all();
    })
    .await
    .expect("xray_reality_wrong_pbk_and_wrong_sid_report_clear_auth_clock_error timed out");
}

/// 3. Live `Xray-core` plain TLS 1.3 (`kTLS` profile, `flow = ""`, `alpn = ["http/1.1"]`, `pcs`
///    SHA-256 leaf pin) interoperability (`PLAN.md` §1, §2, §7):
///    - Proves TCP (`0x01`) + 2 MiB SHA-256 AND non-Vision Mux `0x03` XUDP (`UDP ASSOCIATE`) are
///      100% wire-compatible with stock `Xray-core` `26.11.9`.
///    - Proves omitting `pcs` against the self-signed TLS server fails certificate verification.
#[tokio::test]
async fn xray_tls13_ktls_profile_tcp_and_non_vision_xudp_e2e() {
    let Some(xray_bin) = find_xray_binary() else {
        return;
    };

    tokio::time::timeout(Duration::from_secs(30), async move {
        let mut tasks = JoinSet::new();
        let (payload_2mib, expected_sha256) = deterministic_2mib_payload();
        let target_addr = spawn_target_http_and_binary_server(payload_2mib, &mut tasks).await;
        let dns_stats = spawn_rfc1035_udp_dns_responder(&mut tasks).await;

        let cert = generate_tls13_cert_material(KTLS_SNI, &[b"http/1.1"]);
        let cert_pem = cert.cert_pem.clone();
        let key_pem = cert.key_pem.clone();
        let pcs_sha256 = cert.sha256_hex.clone();

        let mut xray_server = XrayProcess::spawn_with_port(&xray_bin, move |port, dir| {
            let cert_file = dir.join("cert.pem");
            let key_file = dir.join("key.pem");
            std::fs::write(&cert_file, &cert_pem).expect("write cert.pem");
            std::fs::write(&key_file, &key_pem).expect("write key.pem");

            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "flow": ""
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "alpn": ["http/1.1"],
                            "minVersion": "1.3",
                            "certificates": [{
                                "certificateFile": cert_file.to_str().unwrap(),
                                "keyFile": key_file.to_str().unwrap()
                            }]
                        }
                    }
                }],
                "outbounds": [{
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": { "finalRules": [{ "action": "allow" }] }
                }]
            })
        })
        .await;

        // (a) Without `pcs`: connecting to self-signed TLS 1.3 server MUST fail cert verification!
        {
            let unpinned_link = format!(
                "vless://{TEST_UUID}@127.0.0.1:{}?security=tls&sni={KTLS_SNI}#UnpinnedKtls",
                xray_server.port()
            );
            let unpinned_profile = parse_vless_link(&unpinned_link)
                .expect("parse unpinned kTLS vless:// link")
                .profile;
            let (engine, _) = EngineHandle::start(EngineConfig::new_mixed_proxy(
                unpinned_profile,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .await
            .expect("start unpinned engine");
            let proxy_addr = engine.bound_proxy_addr().unwrap();

            assert!(
                http_connect_get(proxy_addr, target_addr, "/small")
                    .await
                    .is_err(),
                "self-signed TLS server without pcs pin must fail HTTP CONNECT"
            );
            assert!(
                socks5_connect_get(proxy_addr, target_addr, "/small")
                    .await
                    .is_err(),
                "self-signed TLS server without pcs pin must fail SOCKS5 CONNECT"
            );

            engine.stop().await.expect("stop unpinned engine");
        }

        // (b) With `pcs=<sha256_hex>`: BOTH TCP (`0x01`) AND non-Vision Mux `0x03` XUDP succeed!
        {
            let pinned_link = format!(
                "vless://{TEST_UUID}@127.0.0.1:{}?security=tls&sni={KTLS_SNI}&pcs={pcs_sha256}#PinnedKtls",
                xray_server.port()
            );
            let pinned_profile = parse_vless_link(&pinned_link)
                .expect("parse pinned kTLS vless:// link")
                .profile;
            let (engine, state_rx) = EngineHandle::start(EngineConfig::new_mixed_proxy(
                pinned_profile,
                "127.0.0.1:0".parse().unwrap(),
            ))
            .await
            .expect("start pinned kTLS engine");
            assert_eq!(state_rx.borrow().status, EngineStatus::Connected);
            let proxy_addr = engine.bound_proxy_addr().unwrap();

            let small = http_connect_get(proxy_addr, target_addr, "/small")
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "kTLS HTTP CONNECT failed: {e}\nXray logs:\n{}",
                        xray_server.logs_snapshot()
                    )
                });
            assert_eq!(small, SMALL_HTTP_BODY);

            let body_2mib = socks5_connect_get(proxy_addr, target_addr, "/binary-2mib")
                .await
                .expect("kTLS SOCKS5 2 MiB download");
            assert_eq!(body_2mib.len(), BINARY_PAYLOAD_LEN);
            assert_eq!(digest(&SHA256, &body_2mib).as_ref(), &expected_sha256);

            // Non-Vision Mux `0x03` XUDP over plain TLS 1.3 (`New` + `Keep` frames) against live Xray!
            verify_socks5_udp_associate_dns_queries(
                proxy_addr,
                dns_stats.addr,
                &[
                    (0x3001, "alpha.interop.test"),
                    (0x3002, "bravo.interop.test"),
                    (0x3003, "charlie.interop.test"),
                ],
            )
            .await;

            engine.stop().await.expect("stop pinned kTLS engine");
        }

        xray_server.terminate();
        tasks.abort_all();
    })
    .await
    .expect("xray_tls13_ktls_profile_tcp_and_non_vision_xudp_e2e timed out");
}

/// 4. Live `Xray-core` REALITY + Vision + userspace `smoltcp` `Tun` mode (`PLAN.md` §5.2, §5.4):
///    - Feeds `EngineHandle` in `Tun` mode over a `UnixDatagram::pair()` socketpair with 4-byte
///      PI/AF packet headers (`packet_information = true`).
///    - Configures live `Xray-core` to route `1.1.1.1:53` via `freedom` `redirect` to our local
///      RFC 1035 UDP DNS responder (`127.0.0.1:<dns_port>`).
///    - Fires concurrent TUN UDP DNS queries (from distinct source ports with colliding client ID
///      `0x4242`) plus a TUN TCP port-53 DNS query to `1.1.1.1:53`, proving `DnsForwarder`
///      rewrites wire transaction IDs and multiplexes every query over ONE shared XUDP session!
#[tokio::test]
async fn xray_tun_raw_fd_af_header_and_single_xudp_dns_mux_e2e() {
    let Some(xray_bin) = find_xray_binary() else {
        return;
    };

    tokio::time::timeout(Duration::from_secs(30), async move {
        let mut tasks = JoinSet::new();
        let cover_stats = spawn_cover_tls_server(&mut tasks).await;
        let cover_addr = cover_stats.addr;
        let dns_stats = spawn_rfc1035_udp_dns_responder(&mut tasks).await;
        let dns_local_addr = dns_stats.addr;

        let (priv_key, pub_key) = generate_xray_x25519_keypair(&xray_bin);
        let mut xray_server = XrayProcess::spawn_with_port(&xray_bin, move |port, _dir| {
            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "flow": "xtls-rprx-vision"
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": false,
                            "dest": cover_addr.to_string(),
                            "xver": 0,
                            "serverNames": [COVER_SNI],
                            "privateKey": priv_key,
                            "shortIds": ["0123456789abcdef"],
                            "maxTimeDiff": 120000
                        }
                    }
                }],
                "outbounds": [
                    {
                        "protocol": "freedom",
                        "tag": "direct",
                        "settings": { "finalRules": [{ "action": "allow" }] }
                    },
                    {
                        "protocol": "freedom",
                        "tag": "dns-redirect",
                        "settings": {
                            "redirect": dns_local_addr.to_string(),
                            "finalRules": [{ "action": "allow" }]
                        }
                    }
                ],
                "routing": {
                    "rules": [{
                        "type": "field",
                        "ip": ["1.1.1.1"],
                        "port": 53,
                        "outboundTag": "dns-redirect"
                    }]
                }
            })
        })
        .await;
        cover_stats.wait_for_xray_startup_probes().await;

        let (wire_std, tun_std) = UnixDatagram::pair().expect("UnixDatagram::pair");
        wire_std
            .set_nonblocking(true)
            .expect("wire_std set_nonblocking");
        let wire = AsyncUnixDatagram::from_std(wire_std).expect("AsyncUnixDatagram");

        let vless_link = format!(
            "vless://{TEST_UUID}@vless.xray-tun.test:{}?security=reality&flow=xtls-rprx-vision&sni={COVER_SNI}&pbk={pub_key}&sid=0123456789abcdef#XrayTunDns",
            xray_server.port()
        );
        let profile = parse_vless_link(&vless_link)
            .expect("parse TUN vless:// link")
            .profile;

        // Enable `packet_information = true` (4-byte PI/AF header) and default `1.1.1.1` resolver.
        let mut cfg = EngineConfig::new_tun(profile, tun_std.as_raw_fd(), false, true, None);
        cfg.dns_resolver = "1.1.1.1".parse().unwrap();

        let (engine, state_rx) = EngineHandle::start_with_pinned_server_ips(
            cfg,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .await
        .expect("start vless-engine in Tun mode");
        assert_eq!(state_rx.borrow().status, EngineStatus::Connected);

        let resolver_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let client_1: SocketAddr = "198.18.0.1:53011".parse().unwrap();
        let client_2: SocketAddr = "198.18.0.1:53012".parse().unwrap();
        let client_3: SocketAddr = "198.18.0.1:53013".parse().unwrap();

        // Send THREE concurrent TUN UDP DNS queries from different source ports with the EXACT
        // SAME client DNS transaction ID `0x4242` (`alpha` is delayed 20ms so replies return
        // out-of-order over XUDP!).
        let colliding_tx_id: u16 = 0x4242;
        for (src, qname) in [
            (client_1, "alpha.interop.test"),
            (client_2, "bravo.interop.test"),
            (client_3, "charlie.interop.test"),
        ] {
            let query = build_rfc1035_a_query(colliding_tx_id, qname);
            let framed_pkt = build_framed_ipv4_udp_packet(src, resolver_dst, &query);
            wire.send(&framed_pkt)
                .await
                .expect("inject framed TUN UDP DNS packet");
        }

        let mut recv_buf = [0u8; 2048];
        let mut resolved = [false; 3];
        for _ in 0..3 {
            let n = tokio::time::timeout(Duration::from_secs(5), wire.recv(&mut recv_buf))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "timed out waiting for TUN UDP DNS response\nXray logs:\n{}",
                        xray_server.logs_snapshot()
                    )
                })
                .expect("recv from TUN socketpair");
            let (reply_src, reply_dst, dns_payload) = parse_framed_ipv4_udp_packet(&recv_buf[..n]);
            assert_eq!(reply_src, resolver_dst);

            let (got_id, got_ip) = parse_rfc1035_a_response(&dns_payload);
            assert_eq!(
                got_id, colliding_tx_id,
                "original client DNS transaction ID must be restored"
            );

            if reply_dst == client_1 {
                assert_eq!(got_ip, expected_dns_answer_for("alpha.interop.test"));
                resolved[0] = true;
            } else if reply_dst == client_2 {
                assert_eq!(got_ip, expected_dns_answer_for("bravo.interop.test"));
                resolved[1] = true;
            } else if reply_dst == client_3 {
                assert_eq!(got_ip, expected_dns_answer_for("charlie.interop.test"));
                resolved[2] = true;
            } else {
                panic!("unexpected TUN UDP DNS reply destination {reply_dst}");
            }
        }
        assert_eq!(resolved, [true, true, true]);

        // Verify all 3 colliding client DNS IDs were rewritten to distinct wire IDs on the wire!
        {
            let wire_ids = dns_stats.seen_wire_ids.lock().clone();
            assert_eq!(wire_ids.len(), 3);
            let unique_ids: HashSet<u16> = wire_ids.into_iter().collect();
            assert_eq!(
                unique_ids.len(),
                3,
                "concurrent colliding client DNS IDs must be rewritten to distinct wire IDs"
            );
        }

        // Also drive a TUN TCP port-53 RFC 1035 length-prefixed DNS query to `1.1.1.1:53` and
        // verify it shares the exact same XUDP association!
        let tcp_client: SocketAddr = "198.18.0.1:53150".parse().unwrap();
        let mut seq: u32 = 50_000;
        wire.send(&build_framed_ipv4_tcp_packet(
            tcp_client,
            resolver_dst,
            seq,
            None,
            true,
            &[],
        ))
        .await
        .expect("send TUN TCP SYN");
        seq = seq.wrapping_add(1);

        let server_ack = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let n = wire.recv(&mut recv_buf).await.expect("recv TUN TCP SYN-ACK");
                assert_eq!(&recv_buf[..4], &utun_pi_ipv4_header());
                let ip = Ipv4Packet::new_checked(&recv_buf[4..n]).expect("valid IPv4");
                if ip.next_header() != IpProtocol::Tcp {
                    continue;
                }
                let tcp = TcpPacket::new_checked(ip.payload()).expect("valid TCP");
                if tcp.dst_port() == tcp_client.port() && tcp.syn() && tcp.ack() {
                    return (tcp.seq_number().0 as u32).wrapping_add(1);
                }
            }
        })
        .await
        .expect("timed out waiting for smoltcp TCP SYN-ACK");

        wire.send(&build_framed_ipv4_tcp_packet(
            tcp_client,
            resolver_dst,
            seq,
            Some(server_ack),
            false,
            &[],
        ))
        .await
        .expect("send TUN TCP ACK");

        let tcp_dns_q = build_rfc1035_a_query(0x7788, "tcp.interop.test");
        let mut tcp_dns_frame = Vec::with_capacity(2 + tcp_dns_q.len());
        tcp_dns_frame.extend_from_slice(&(tcp_dns_q.len() as u16).to_be_bytes());
        tcp_dns_frame.extend_from_slice(&tcp_dns_q);

        wire.send(&build_framed_ipv4_tcp_packet(
            tcp_client,
            resolver_dst,
            seq,
            Some(server_ack),
            false,
            &tcp_dns_frame,
        ))
        .await
        .expect("send TUN TCP DNS payload");
        seq = seq.wrapping_add(tcp_dns_frame.len() as u32);

        let tcp_dns_resp = tokio::time::timeout(Duration::from_secs(5), async {
            let mut acc = Vec::new();
            let mut next_ack = server_ack;
            loop {
                let n = wire.recv(&mut recv_buf).await.expect("recv TUN TCP DNS reply");
                assert_eq!(&recv_buf[..4], &utun_pi_ipv4_header());
                let ip = Ipv4Packet::new_checked(&recv_buf[4..n]).expect("valid IPv4");
                if ip.next_header() != IpProtocol::Tcp {
                    continue;
                }
                let tcp = TcpPacket::new_checked(ip.payload()).expect("valid TCP");
                if tcp.dst_port() != tcp_client.port() || tcp.payload().is_empty() {
                    continue;
                }
                acc.extend_from_slice(tcp.payload());
                next_ack = next_ack.wrapping_add(tcp.payload().len() as u32);
                let _ = wire
                    .send(&build_framed_ipv4_tcp_packet(
                        tcp_client,
                        resolver_dst,
                        seq,
                        Some(next_ack),
                        false,
                        &[],
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
        .expect("timed out waiting for TUN TCP DNS response");

        let (tcp_id, tcp_ip) = parse_rfc1035_a_response(&tcp_dns_resp);
        assert_eq!(tcp_id, 0x7788);
        assert_eq!(tcp_ip, expected_dns_answer_for("tcp.interop.test"));

        assert_eq!(dns_stats.query_count.load(Ordering::SeqCst), 4);
        assert_eq!(
            dns_stats.seen_peers.lock().len(),
            1,
            "all 4 TUN DNS queries (3 UDP source ports + 1 TCP port-53) must traverse a SINGLE XUDP session on Xray"
        );

        engine.stop().await.expect("stop TUN engine");
        drop(tun_std);
        xray_server.terminate();
        tasks.abort_all();
    })
    .await
    .expect("xray_tun_raw_fd_af_header_and_single_xudp_dns_mux_e2e timed out");
}

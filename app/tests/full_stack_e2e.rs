//! Full-stack 3-crate (`vless-tray` supervisor <-> real `vless-engine` binary <-> real
//! `vless-tray-helper` daemon) end-to-end integration tests (`PLAN.md` §4, §5.1–§5.5, §7, §8).
//!
//! Exercises:
//! 1. System Proxy full lifecycle: `EngineSupervisor` -> `vless-engine ipc` child process (zero
//!    UUID in `/proc/<pid>/cmdline` & `environ`) -> `vless-tray-helper` Unix-socket daemon ->
//!    `0600` `helper-state.json` + multi-service proxy configuration -> real HTTP CONNECT and
//!    SOCKS5 traffic over SHA-256 leaf-pinned TLS 1.3 (`pcs`) VLESS -> clean `disconnect()`
//!    restoring original proxy state and deleting `helper-state.json`.
//! 2. TUN mode full lifecycle: `localhost` server pre-TUN DNS resolution, `SCM_RIGHTS` `utun` fd
//!    passing (zero retained `utun` fd copies in helper), `/1` capture routes + server host route +
//!    RFC1918 bypass routes + `1.1.1.1` `SCDynamicStore` DNS override, live Wi-Fi (`en0`) ->
//!    Hotspot (`en1`) `PF_ROUTE` network migration (`HelperMessage::NetworkChanged`), wake
//!    `RecheckServer` probe, and catastrophic `kill -9` (`SIGKILL`) crash recovery across all 3
//!    components without manual cleanup.

use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aws_lc_rs::digest::{SHA256, digest};
use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use vless_ipc::{
    AppConfig, BUILTIN_SYSTEM_PROXY_EXCEPTIONS, ConnectionMode, EngineStatus, parse_vless_link,
};
use vless_tray::supervisor::{
    EngineSupervisor, SupervisorConfig, SupervisorState, resolve_engine_binary_from,
};
use vless_tray_helper::{
    DaemonLifecycle, DefaultGatewayV4, DefaultGatewayV6, HelperConfig, MockNetworkService,
    MockServiceDnsState, MockSystemBackend, OwnerUidPolicy, ProxyEndpointConfig, RouteDestination,
    RouteSpec, RouteTarget, TUN_CAPTURE_CIDR_STRS, encode_mock_dns_xml, serve_tokio_listener,
};

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const WIFI_SERVICE_ID: &str = "E621E1F8-C36C-495A-93FC-0C247A3E6E5F";
const HOTSPOT_SERVICE_ID: &str = "A1B2C3D4-E5F6-4789-ABCD-0123456789AB";

/// Serializes full-stack tests so child `vless-engine` PID discovery under our test-runner `PPid`
/// is 100% deterministic and contention-free.
static FULL_STACK_SERIAL: AsyncMutex<()> = AsyncMutex::const_new(());

/// Ensures the real `vless-engine` binary exists next to `vless-tray` in the active Cargo profile
/// output directory and verifies `resolve_engine_binary(None)` discovers it automatically.
fn ensure_real_vless_engine_binary() -> PathBuf {
    static ENGINE_BIN: OnceLock<PathBuf> = OnceLock::new();
    ENGINE_BIN
        .get_or_init(|| {
            let tray_bin = PathBuf::from(env!("CARGO_BIN_EXE_vless-tray"));
            let profile_dir = tray_bin
                .parent()
                .expect("CARGO_BIN_EXE_vless-tray must reside in target/<profile>/");
            let engine_bin = profile_dir.join("vless-engine");

            if !engine_bin.is_file() {
                let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
                let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("workspace root");
                let mut cmd = StdCommand::new(cargo);
                cmd.current_dir(workspace_root).args([
                    "build",
                    "-p",
                    "vless-engine",
                    "--bin",
                    "vless-engine",
                ]);
                if let Some(target_root) = profile_dir.parent() {
                    cmd.env("CARGO_TARGET_DIR", target_root);
                }
                let status = cmd
                    .status()
                    .expect("failed to invoke cargo build --bin vless-engine");
                assert!(status.success(), "building vless-engine binary failed");
            }

            assert!(
                engine_bin.is_file(),
                "expected real vless-engine binary at {}",
                engine_bin.display()
            );
            assert_eq!(
                resolve_engine_binary_from(Some(&tray_bin), None),
                engine_bin,
                "resolve_engine_binary_from(vless-tray) must locate sibling vless-engine"
            );
            engine_bin
        })
        .clone()
}

fn current_euid() -> u32 {
    // SAFETY: `libc::geteuid()` is a pure, thread-safe POSIX query with no pointer arguments or
    // preconditions.
    unsafe { libc::geteuid() }
}

/// Picks a positive interface index not assigned to any host network interface so unprivileged
/// Linux tests never hit `EPERM` on `SO_BINDTODEVICE`, while still exercising non-zero interface
/// index plumbing (`outbound_if_index`) end-to-end.
fn find_unused_if_index(start: u32) -> u32 {
    let mut idx = start.max(1);
    loop {
        let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE + 1];
        // SAFETY: `buf` provides `IF_NAMESIZE + 1` writable bytes on the stack; `if_indextoname`
        // writes at most `IF_NAMESIZE` bytes on hit or returns NULL when `idx` is unassigned.
        let ptr = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr()) };
        if ptr.is_null() {
            return idx;
        }
        idx += 1;
    }
}

fn pick_unused_localhost_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// Generates a self-signed TLS 1.3 server config for `hostname` and returns `(ServerConfig, pcs_sha256_hex)`.
fn generate_self_signed_ktls_config(hostname: &str) -> (Arc<rustls::ServerConfig>, String) {
    let certified =
        rcgen::generate_simple_self_signed(vec![hostname.to_string()]).expect("rcgen self-signed");
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
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("single cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    (Arc::new(server_cfg), sha256_hex)
}

/// Spawns a self-contained TLS 1.3 (`kTLS`, flow empty) VLESS v0 server validating `expected_uuid`
/// and forwarding `COMMAND_TCP` (`0x01`) streams to their requested destinations.
async fn spawn_inprocess_ktls_vless_server(
    sni: &str,
    expected_uuid: Uuid,
    tasks: &mut JoinSet<()>,
) -> (SocketAddr, String, Arc<AtomicUsize>) {
    let (tls_cfg, sha256_pin) = generate_self_signed_ktls_config(sni);
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind kTLS listener");
    let addr = listener.local_addr().expect("kTLS local_addr");
    let tunneled_connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&tunneled_connections);
    let expected_uuid_bytes = *expected_uuid.as_bytes();

    tasks.spawn(async move {
        while let Ok((tcp, _peer)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                // Note: `RecheckServer` performs a bare TCP connect+close reachability probe, so a
                // clean EOF during TLS handshake is normal and ignored.
                let Ok(mut tls_stream) = acceptor.accept(tcp).await else {
                    return;
                };
                if handle_vless_tcp_stream(&mut tls_stream, &expected_uuid_bytes, &counter)
                    .await
                    .is_err()
                {
                    let _ = tls_stream.shutdown().await;
                }
            });
        }
    });

    (addr, sha256_pin, tunneled_connections)
}

async fn handle_vless_tcp_stream<S>(
    stream: &mut S,
    expected_uuid: &[u8; 16],
    counter: &AtomicUsize,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // VLESS v0 request header:
    // [version: 1B = 0x00][uuid: 16B][addon_len: 1B][addons: addon_len B][cmd: 1B][port: 2B BE][addr_type: 1B][addr...]
    let mut prefix = [0u8; 18];
    stream.read_exact(&mut prefix).await?;
    if prefix[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected VLESS version {}", prefix[0]),
        ));
    }
    if &prefix[1..17] != expected_uuid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VLESS UUID mismatch",
        ));
    }

    let addon_len = usize::from(prefix[17]);
    if addon_len > 0 {
        let mut addon_buf = vec![0u8; addon_len];
        stream.read_exact(&mut addon_buf).await?;
    }

    let mut cmd_port_atype = [0u8; 4];
    stream.read_exact(&mut cmd_port_atype).await?;
    let cmd = cmd_port_atype[0];
    if cmd != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported VLESS command {cmd:#x} in TCP test server"),
        ));
    }
    let dst_port = u16::from_be_bytes([cmd_port_atype[1], cmd_port_atype[2]]);
    let addr_type = cmd_port_atype[3];

    let target_addr = match addr_type {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), dst_port)
        }
        2 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host_bytes = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut host_bytes).await?;
            let host = std::str::from_utf8(&host_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            tokio::net::lookup_host((host, dst_port))
                .await?
                .next()
                .ok_or_else(|| io::Error::other("empty DNS resolution for VLESS domain target"))?
        }
        3 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), dst_port)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown VLESS address type {other}"),
            ));
        }
    };

    let mut upstream = TcpStream::connect(target_addr).await?;
    counter.fetch_add(1, Ordering::SeqCst);

    // VLESS v0 server response header: [version = 0x00, addon_len = 0x00]
    stream.write_all(&[0x00, 0x00]).await?;
    stream.flush().await?;

    let _ = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    Ok(())
}

/// Spawns a local HTTP/1.1 echo server that echoes back the request line and `x-probe` header.
async fn spawn_local_http_echo_server(tasks: &mut JoinSet<()>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP echo server");
    let addr = listener.local_addr().expect("HTTP echo local_addr");

    tasks.spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut req_buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 512];
                while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") && req_buf.len() < 16 * 1024 {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req_buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let req_text = String::from_utf8_lossy(&req_buf);
                let request_line = req_text.lines().next().unwrap_or("").trim_end_matches('\r');
                let probe_hdr = req_text
                    .lines()
                    .find_map(|line| {
                        let (name, val) = line.split_once(':')?;
                        if name.trim().eq_ignore_ascii_case("x-probe") {
                            Some(val.trim().to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();

                let body = format!("ECHO:{request_line}|{probe_hdr}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

/// Starts `vless_tray_helper` on a bound Unix socket path with `MockSystemBackend`.
fn start_helper_daemon(
    socket_path: &Path,
    state_path: &Path,
    backend: Arc<MockSystemBackend>,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent).expect("create helper socket parent dir");
    }
    let listener = UnixListener::bind(socket_path).expect("bind helper Unix socket");
    let config = HelperConfig {
        state_path: state_path.to_path_buf(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        serve_tokio_listener(listener, backend, config, shutdown_rx)
            .await
            .expect("vless-tray-helper daemon exited with error");
    });
    (shutdown_tx, handle)
}

#[cfg(target_os = "linux")]
fn find_child_engine_pids(expected_engine_bin: &Path) -> Vec<libc::pid_t> {
    let our_ppid = std::process::id().to_string();
    let mut pids = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<libc::pid_t>() else {
            continue;
        };
        let status_path = entry.path().join("status");
        let Ok(status_text) = fs::read_to_string(&status_path) else {
            continue;
        };

        let mut ppid_matches = false;
        let mut is_zombie = false;
        for line in status_text.lines() {
            if let Some(ppid) = line.strip_prefix("PPid:") {
                ppid_matches = ppid.trim() == our_ppid;
            } else if let Some(state) = line.strip_prefix("State:") {
                is_zombie = state.trim_start().starts_with('Z');
            }
        }
        if !ppid_matches || is_zombie {
            continue;
        }

        let Ok(cmdline_bytes) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = cmdline_bytes
            .split(|&b| b == 0)
            .filter(|seg| !seg.is_empty())
            .collect();
        if args.is_empty() {
            continue;
        }
        let arg0 = String::from_utf8_lossy(args[0]);
        if Path::new(arg0.as_ref()) == expected_engine_bin
            || arg0.ends_with("/vless-engine")
            || arg0 == "vless-engine"
        {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(not(target_os = "linux"))]
fn find_child_engine_pids(_expected_engine_bin: &Path) -> Vec<libc::pid_t> {
    let out = StdCommand::new("/usr/bin/pgrep")
        .args(["-P", &std::process::id().to_string(), "vless-engine"])
        .output()
        .expect("invoke pgrep");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<libc::pid_t>().ok())
        .collect()
}

#[cfg(target_os = "linux")]
fn assert_zero_secrets_in_child_process(pid: libc::pid_t, forbidden_secrets: &[&str]) {
    let cmdline_raw =
        fs::read(format!("/proc/{pid}/cmdline")).expect("read /proc/<pid>/cmdline on Linux");
    let args: Vec<String> = cmdline_raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    assert_eq!(
        args.len(),
        2,
        "expected exact 2-arg [`vless-engine`, `ipc`] cmdline, got {args:?}"
    );
    assert_eq!(args[1], "ipc");

    let cmdline_lower = String::from_utf8_lossy(&cmdline_raw).to_ascii_lowercase();
    let environ_raw = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
    let environ_lower = String::from_utf8_lossy(&environ_raw).to_ascii_lowercase();

    for secret in forbidden_secrets {
        let needle = secret.to_ascii_lowercase();
        assert!(
            !cmdline_lower.contains(&needle),
            "SECURITY VIOLATION: child /proc/{pid}/cmdline leaked secret {secret:?}"
        );
        assert!(
            !environ_lower.contains(&needle),
            "SECURITY VIOLATION: child /proc/{pid}/environ leaked secret {secret:?}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn assert_zero_secrets_in_child_process(pid: libc::pid_t, forbidden_secrets: &[&str]) {
    let out = StdCommand::new("/bin/ps")
        .args(["-ww", "-o", "command=", "-p", &pid.to_string()])
        .output()
        .expect("invoke ps");
    let cmdline_lower = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    for secret in forbidden_secrets {
        let needle = secret.to_ascii_lowercase();
        assert!(
            !cmdline_lower.contains(&needle),
            "SECURITY VIOLATION: ps command output for pid {pid} leaked secret {secret:?}"
        );
    }
}

async fn wait_for_condition<F>(timeout: Duration, description: &str, mut predicate: F)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {timeout:?} waiting for: {description}"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

#[tokio::test]
async fn full_stack_system_proxy_connect_traffic_and_clean_disconnect() {
    let _serial = FULL_STACK_SERIAL.lock().await;
    let engine_bin = ensure_real_vless_engine_binary();

    let temp = tempfile::tempdir().expect("tempdir");
    let helper_sock = temp.path().join("helper.sock");
    let state_path = temp.path().join("helper-state.json");
    let config_dir = temp.path().join("user-cfg");

    // 1. Configure MockSystemBackend with 2 enabled services ("Wi-Fi" and "Ethernet") + 1 disabled
    //    service ("Thunderbolt Bridge").
    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    backend.remove_network_service("USB 10/100/1000 LAN");

    let original_wifi = MockNetworkService {
        enabled: true,
        web: ProxyEndpointConfig {
            enabled: false,
            server: String::new(),
            port: 0,
        },
        secure_web: ProxyEndpointConfig {
            enabled: false,
            server: String::new(),
            port: 0,
        },
        socks: ProxyEndpointConfig {
            enabled: false,
            server: String::new(),
            port: 0,
        },
        bypass_domains: vec!["*.local".to_string(), "169.254/16".to_string()],
    };
    let original_ethernet = MockNetworkService {
        enabled: true,
        web: ProxyEndpointConfig {
            enabled: true,
            server: "corp-gw.internal".to_string(),
            port: 8080,
        },
        secure_web: ProxyEndpointConfig {
            enabled: false,
            server: "corp-gw.internal".to_string(),
            port: 8443,
        },
        socks: ProxyEndpointConfig::default(),
        bypass_domains: vec!["*.corp.local".to_string()],
    };
    let original_disabled = backend
        .service_state("Thunderbolt Bridge")
        .expect("Thunderbolt Bridge present");
    assert!(!original_disabled.enabled);

    backend.set_network_service("Wi-Fi", original_wifi.clone());
    backend.set_network_service("Ethernet", original_ethernet.clone());

    let (helper_shutdown_tx, helper_task) =
        start_helper_daemon(&helper_sock, &state_path, Arc::clone(&backend));

    // 2. Start in-process SHA-256 leaf-pinned (`pcs`) TLS 1.3 VLESS server + local HTTP echo server.
    let mut server_tasks = JoinSet::new();
    let parsed_uuid = Uuid::parse_str(TEST_UUID).expect("valid UUID");
    let (vless_addr, pcs_pin, tunneled_count) =
        spawn_inprocess_ktls_vless_server("localhost", parsed_uuid, &mut server_tasks).await;
    let echo_addr = spawn_local_http_echo_server(&mut server_tasks).await;

    // 3. Configure EngineSupervisor + AppConfig (SystemProxy on ephemeral localhost port, custom
    //    bypass domain `internal.corp`).
    let proxy_port = pick_unused_localhost_port();
    let vless_link = format!(
        "vless://{TEST_UUID}@127.0.0.1:{}?security=tls&sni=localhost&pcs={pcs_pin}#SystemProxyFullStack",
        vless_addr.port()
    );
    let profile = parse_vless_link(&vless_link)
        .expect("parse kTLS link")
        .profile;
    let profile_id = profile.id;
    let uuid_simple_hex = parsed_uuid.simple().to_string();

    let app_cfg = AppConfig {
        profiles: vec![profile],
        selected_profile_id: Some(profile_id),
        mode: ConnectionMode::SystemProxy,
        system_proxy_port: proxy_port,
        dns_resolver: "1.1.1.1".parse().unwrap(),
        bypass_list: vec!["internal.corp".to_string()],
    };

    let mut sup_cfg = SupervisorConfig::new(config_dir);
    sup_cfg.helper_socket = helper_sock.clone();
    sup_cfg.engine_bin_override = Some(engine_bin.clone());
    let supervisor = EngineSupervisor::new(sup_cfg);
    let mut state_rx = supervisor.subscribe();

    supervisor
        .connect(&app_cfg)
        .await
        .expect("supervisor.connect(SystemProxy)");

    tokio::time::timeout(
        Duration::from_secs(5),
        state_rx.wait_for(|s| s.status == EngineStatus::Connected),
    )
    .await
    .expect("timed out waiting for EngineStatus::Connected")
    .expect("state watch open");

    let connected = supervisor.state();
    assert_eq!(connected.status, EngineStatus::Connected);
    assert_eq!(connected.active_mode, ConnectionMode::SystemProxy);
    assert_eq!(
        connected.listen_addr,
        Some(SocketAddr::from(([127, 0, 0, 1], proxy_port)))
    );

    // 4. Verify child `vless-engine` `/proc/<pid>/cmdline` (and environ) has ZERO occurrences of
    //    the profile UUID (`PLAN.md` §4) or `pcs` certificate pin!
    let child_pids = find_child_engine_pids(&engine_bin);
    assert_eq!(
        child_pids.len(),
        1,
        "expected exactly 1 live vless-engine child process, found {child_pids:?}"
    );
    assert_zero_secrets_in_child_process(
        child_pids[0],
        &[
            TEST_UUID,
            &uuid_simple_hex,
            &pcs_pin,
            &profile_id.to_string(),
        ],
    );

    // 5. Verify MockSystemBackend proxy configuration on "Wi-Fi" & "Ethernet", untouched disabled
    //    service, and `helper-state.json` mode `0600`.
    let state_meta = fs::symlink_metadata(&state_path).expect("helper-state.json must exist");
    assert_eq!(
        state_meta.mode() & 0o777,
        0o600,
        "helper-state.json must have strict 0600 permissions"
    );

    let expected_endpoint = ProxyEndpointConfig {
        enabled: true,
        server: "127.0.0.1".to_string(),
        port: proxy_port,
    };
    for svc_name in ["Wi-Fi", "Ethernet"] {
        let svc = backend
            .service_state(svc_name)
            .unwrap_or_else(|| panic!("missing service {svc_name}"));
        assert_eq!(svc.web, expected_endpoint, "{svc_name} HTTP proxy mismatch");
        assert_eq!(
            svc.secure_web, expected_endpoint,
            "{svc_name} HTTPS proxy mismatch"
        );
        assert_eq!(
            svc.socks, expected_endpoint,
            "{svc_name} SOCKS proxy mismatch"
        );
        assert!(
            svc.bypass_domains.iter().any(|d| d == "internal.corp"),
            "{svc_name} missing custom bypass domain internal.corp: {:?}",
            svc.bypass_domains
        );
        for &builtin in BUILTIN_SYSTEM_PROXY_EXCEPTIONS {
            assert!(
                svc.bypass_domains.iter().any(|d| d == builtin),
                "{svc_name} missing built-in proxy exception {builtin}: {:?}",
                svc.bypass_domains
            );
        }
    }
    assert_eq!(
        backend.service_state("Thunderbolt Bridge").unwrap(),
        original_disabled,
        "disabled network service must never be modified"
    );

    // 6. Send real HTTP CONNECT and SOCKS5 requests through `127.0.0.1:<proxy_port>` ->
    //    `vless-engine` -> kTLS VLESS server -> local HTTP echo server!
    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));

    // 6a. HTTP CONNECT request
    {
        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("connect to vless-engine mixed proxy (HTTP CONNECT)");
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            echo_addr.port(),
            echo_addr.port()
        );
        client.write_all(connect_req.as_bytes()).await.unwrap();

        let mut tunnel_hdr = Vec::new();
        let mut byte = [0u8; 1];
        while !tunnel_hdr.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.unwrap();
            tunnel_hdr.push(byte[0]);
            assert!(tunnel_hdr.len() < 1024, "oversized CONNECT response header");
        }
        let tunnel_status = String::from_utf8_lossy(&tunnel_hdr);
        assert!(
            tunnel_status.starts_with("HTTP/1.1 200"),
            "unexpected HTTP CONNECT status: {tunnel_status:?}"
        );

        let http_req = "GET /http-connect-e2e HTTP/1.1\r\nHost: echo.local\r\nX-Probe: http-tunnel-ok\r\nConnection: close\r\n\r\n";
        client.write_all(http_req.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        let reply_str = String::from_utf8(reply).unwrap();
        assert!(
            reply_str.contains("ECHO:GET /http-connect-e2e HTTP/1.1|http-tunnel-ok"),
            "unexpected HTTP CONNECT echoed payload: {reply_str:?}"
        );
    }

    // 6b. SOCKS5 CONNECT request
    {
        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("connect to vless-engine mixed proxy (SOCKS5)");
        // Greeting: VER=5, NMETHODS=1, METHOD_NONE=0
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [0x05, 0x00]);

        // CONNECT 127.0.0.1:<echo_port>
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut socks_reply = [0u8; 10];
        client.read_exact(&mut socks_reply).await.unwrap();
        assert_eq!(&socks_reply[..4], &[0x05, 0x00, 0x00, 0x01]);

        let http_req = "GET /socks5-e2e HTTP/1.1\r\nHost: echo.local\r\nX-Probe: socks5-tunnel-ok\r\nConnection: close\r\n\r\n";
        client.write_all(http_req.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        let reply_str = String::from_utf8(reply).unwrap();
        assert!(
            reply_str.contains("ECHO:GET /socks5-e2e HTTP/1.1|socks5-tunnel-ok"),
            "unexpected SOCKS5 echoed payload: {reply_str:?}"
        );
    }

    assert_eq!(
        tunneled_count.load(Ordering::SeqCst),
        2,
        "both HTTP CONNECT and SOCKS5 streams must traverse the kTLS VLESS server"
    );

    // 7. Disconnect cleanly and verify AppToEngine::Stop -> HelperCommand::Stop restores original
    //    proxy state, deletes `helper-state.json`, and reaches `EngineStatus::Stopped`.
    supervisor
        .disconnect()
        .await
        .expect("supervisor.disconnect()");

    assert_eq!(supervisor.state().status, EngineStatus::Stopped);
    assert_eq!(supervisor.state().active_mode, ConnectionMode::Off);
    assert!(
        !state_path.exists(),
        "helper-state.json must be deleted on clean disconnect"
    );
    assert_eq!(
        backend.service_state("Wi-Fi").unwrap(),
        original_wifi,
        "Wi-Fi proxy settings must be restored bit-for-bit"
    );
    assert_eq!(
        backend.service_state("Ethernet").unwrap(),
        original_ethernet,
        "Ethernet proxy settings must be restored bit-for-bit"
    );
    assert_eq!(
        backend.service_state("Thunderbolt Bridge").unwrap(),
        original_disabled
    );
    assert!(
        find_child_engine_pids(&engine_bin).is_empty(),
        "vless-engine child process must have exited cleanly"
    );

    let _ = helper_shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), helper_task).await;
    server_tasks.abort_all();
}

#[tokio::test]
async fn full_stack_tun_mode_network_switch_recheck_and_sigkill_crash_recovery() {
    let _serial = FULL_STACK_SERIAL.lock().await;
    let engine_bin = ensure_real_vless_engine_binary();

    let temp = tempfile::tempdir().expect("tempdir");
    let helper_sock = temp.path().join("helper.sock");
    let state_path = temp.path().join("helper-state.json");
    let config_dir = temp.path().join("tun-user-cfg");

    // 1. Configure MockSystemBackend (`en0`, gateway `192.168.1.1`, DNS `["192.168.1.1"]`).
    let if_idx_en0 = find_unused_if_index(50);
    let if_idx_en1 = find_unused_if_index(if_idx_en0 + 1);
    let wifi_gw: Ipv4Addr = "192.168.1.1".parse().unwrap();
    let hotspot_gw: Ipv4Addr = "172.20.10.1".parse().unwrap();
    let wifi_dns_ip = IpAddr::V4(wifi_gw);
    let hotspot_dns_ip = IpAddr::V4(hotspot_gw);
    let tunnel_dns_ip: IpAddr = "1.1.1.1".parse().unwrap();

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    backend.set_ipv4_gateway(Some(DefaultGatewayV4 {
        gateway: wifi_gw,
        interface: "en0".to_string(),
        if_index: if_idx_en0,
    }));
    backend.set_ipv6_gateway(Some(DefaultGatewayV6 {
        gateway: "fe80::1%en0".to_string(),
        interface: "en0".to_string(),
        if_index: if_idx_en0,
    }));
    backend.set_service_dns_state(
        WIFI_SERVICE_ID,
        MockServiceDnsState {
            state_dns_servers: Some(vec![wifi_dns_ip]),
            state_supplemental_match_domains: None,
            state_raw_xml: Some(encode_mock_dns_xml(&[wifi_dns_ip], None)),
            setup_dns_servers: Vec::new(),
        },
    );

    let (helper_shutdown_tx, helper_task) =
        start_helper_daemon(&helper_sock, &state_path, Arc::clone(&backend));

    // 2. Start in-process kTLS VLESS server so `localhost:<port>` resolves via DNS and responds to
    //    `RecheckServer` reachability probes.
    let mut server_tasks = JoinSet::new();
    let parsed_uuid = Uuid::parse_str(TEST_UUID).expect("valid UUID");
    let (vless_addr, pcs_pin, _tunneled_count) =
        spawn_inprocess_ktls_vless_server("localhost", parsed_uuid, &mut server_tasks).await;

    let vless_link = format!(
        "vless://{TEST_UUID}@localhost:{}?security=tls&sni=localhost&pcs={pcs_pin}#TunFullStack",
        vless_addr.port()
    );
    let profile = parse_vless_link(&vless_link)
        .expect("parse localhost TUN link")
        .profile;
    let profile_id = profile.id;

    let app_cfg = AppConfig {
        profiles: vec![profile],
        selected_profile_id: Some(profile_id),
        mode: ConnectionMode::Tun,
        system_proxy_port: 2080,
        dns_resolver: tunnel_dns_ip,
        bypass_list: Vec::new(),
    };

    // Record every SupervisorState transition synchronously so rapid `Reconnecting -> Connected`
    // transitions during `NetworkChanged` are captured without watch-channel coalescing.
    let recorded_states: Arc<Mutex<Vec<SupervisorState>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded_clone = Arc::clone(&recorded_states);

    let mut sup_cfg = SupervisorConfig::new(config_dir);
    sup_cfg.helper_socket = helper_sock.clone();
    sup_cfg.engine_bin_override = Some(engine_bin.clone());
    sup_cfg.on_state_change = Some(Arc::new(move |st| {
        recorded_clone.lock().unwrap().push(st.clone());
    }));

    let supervisor = EngineSupervisor::new(sup_cfg);
    let mut state_rx = supervisor.subscribe();

    // 3. Connect in `ConnectionMode::Tun` using `localhost` as `server_host`.
    supervisor
        .connect(&app_cfg)
        .await
        .expect("supervisor.connect(Tun)");

    tokio::time::timeout(
        Duration::from_secs(5),
        state_rx.wait_for(|s| s.status == EngineStatus::Connected),
    )
    .await
    .expect("timed out waiting for initial TUN Connected")
    .expect("state watch open");

    let initial_state = supervisor.state();
    let utun_name = initial_state
        .utun_name
        .clone()
        .expect("TUN Connected state must populate utun_name");
    assert!(
        utun_name.starts_with("utun"),
        "expected utun interface name, got {utun_name:?}"
    );
    assert!(
        state_path.exists(),
        "helper-state.json must exist while TUN is active"
    );
    assert_eq!(
        fs::symlink_metadata(&state_path).unwrap().mode() & 0o777,
        0o600
    );

    // Extract the simulated kernel peer half of the utun socketpair (retaining it alive during the
    // session) so we can also prove `vless-tray-helper` kept ZERO duplicate copies of `utun_fd`
    // once `vless-engine` receives `SIGKILL` (`PLAN.md` §4).
    let mut utun_kernel_peer = backend
        .take_utun_peer(&utun_name)
        .expect("extract mock utun kernel peer");
    utun_kernel_peer
        .set_nonblocking(true)
        .expect("set nonblocking on utun_kernel_peer");

    // 4. Verify initial TUN routes (`/1` capture routes on `utun`, `localhost` -> `127.0.0.1` host
    //    route + RFC1918 bypass routes via `192.168.1.1`) and `SCDynamicStore` DNS == `1.1.1.1`!
    let routes_initial = backend.routes();
    for &capture_str in TUN_CAPTURE_CIDR_STRS {
        let cidr: IpNetwork = capture_str.parse().unwrap();
        assert!(
            routes_initial.contains(&RouteSpec {
                destination: RouteDestination::Cidr(cidr),
                target: RouteTarget::Interface(utun_name.clone()),
            }),
            "missing half-default capture route {capture_str} on {utun_name}: {routes_initial:?}"
        );
    }
    assert!(
        routes_initial.contains(&RouteSpec {
            destination: RouteDestination::Host(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target: RouteTarget::GatewayV4(wifi_gw),
        }),
        "missing resolved server host route 127.0.0.1 -> {wifi_gw}: {routes_initial:?}"
    );
    for rfc1918 in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
        let cidr: IpNetwork = rfc1918.parse().unwrap();
        assert!(
            routes_initial.contains(&RouteSpec {
                destination: RouteDestination::Cidr(cidr),
                target: RouteTarget::GatewayV4(wifi_gw),
            }),
            "missing RFC1918 bypass route {rfc1918} -> {wifi_gw}: {routes_initial:?}"
        );
    }
    assert_eq!(
        backend
            .dns_state(WIFI_SERVICE_ID)
            .expect("Wi-Fi DNS entry")
            .state_dns_servers,
        Some(vec![tunnel_dns_ip]),
        "SCDynamicStore DNS must be overridden to 1.1.1.1"
    );

    // 5. Simulate Wi-Fi (`en0`, `192.168.1.1`) -> Personal Hotspot (`en1`, `172.20.10.1`) network
    //    transition (`PF_ROUTE` -> `HelperMessage::NetworkChanged`).
    recorded_states.lock().unwrap().clear();

    backend.simulate_network_transition(
        Some(DefaultGatewayV4 {
            gateway: hotspot_gw,
            interface: "en1".to_string(),
            if_index: if_idx_en1,
        }),
        None,
        Some(HOTSPOT_SERVICE_ID.to_string()),
        Some((
            HOTSPOT_SERVICE_ID.to_string(),
            MockServiceDnsState {
                state_dns_servers: Some(vec![hotspot_dns_ip]),
                state_supplemental_match_domains: None,
                state_raw_xml: Some(encode_mock_dns_xml(&[hotspot_dns_ip], None)),
                setup_dns_servers: Vec::new(),
            },
        )),
    );

    // Wait until:
    // - `vless-tray-helper` migrates routes to `172.20.10.1` and updates `SCDynamicStore` DNS, AND
    // - `vless-engine` processes `HelperMessage::NetworkChanged` (`Reconnecting` on `en1`) and
    //   returns `EngineSupervisor` to `EngineStatus::Connected`!
    wait_for_condition(
        Duration::from_secs(10),
        "Hotspot route migration + NetworkChanged Reconnecting -> Connected",
        || {
            let states = recorded_states.lock().unwrap();
            let reconnect_pos = states.iter().position(|s| {
                s.status == EngineStatus::Reconnecting
                    && s.detail.as_deref().is_some_and(|d| d.contains("en1"))
            });
            let returned_connected = reconnect_pos.is_some_and(|idx| {
                states[idx + 1..]
                    .iter()
                    .any(|s| s.status == EngineStatus::Connected)
            });
            returned_connected && supervisor.state().status == EngineStatus::Connected
        },
    )
    .await;

    let routes_hotspot = backend.routes();
    assert!(
        routes_hotspot.contains(&RouteSpec {
            destination: RouteDestination::Host(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target: RouteTarget::GatewayV4(hotspot_gw),
        }),
        "server host route must migrate to Hotspot gateway {hotspot_gw}: {routes_hotspot:?}"
    );
    for rfc1918 in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
        let cidr: IpNetwork = rfc1918.parse().unwrap();
        assert!(
            routes_hotspot.contains(&RouteSpec {
                destination: RouteDestination::Cidr(cidr),
                target: RouteTarget::GatewayV4(hotspot_gw),
            }),
            "RFC1918 bypass route {rfc1918} must migrate to {hotspot_gw}: {routes_hotspot:?}"
        );
    }
    assert!(
        !routes_hotspot
            .iter()
            .any(|r| r.target == RouteTarget::GatewayV4(wifi_gw)),
        "stale Wi-Fi gateway routes via {wifi_gw} must be removed: {routes_hotspot:?}"
    );
    assert_eq!(
        backend
            .dns_state(WIFI_SERVICE_ID)
            .unwrap()
            .state_dns_servers,
        Some(vec![wifi_dns_ip]),
        "previous Wi-Fi service DNS must be restored on service switch"
    );
    assert_eq!(
        backend
            .dns_state(HOTSPOT_SERVICE_ID)
            .unwrap()
            .state_dns_servers,
        Some(vec![tunnel_dns_ip]),
        "new Hotspot service DNS must be overridden to 1.1.1.1"
    );

    // 6. Trigger `supervisor.recheck_server()` (simulating macOS `NSWorkspaceDidWakeNotification`)!
    let recheck_sent = supervisor
        .recheck_server()
        .await
        .expect("supervisor.recheck_server()");
    assert!(
        recheck_sent,
        "recheck_server must dispatch to active TUN engine"
    );

    tokio::time::timeout(
        Duration::from_secs(10),
        state_rx.wait_for(|s| s.last_server_check.is_some()),
    )
    .await
    .expect("timed out waiting for ServerCheck response")
    .expect("state watch open");

    let check = supervisor
        .state()
        .last_server_check
        .expect("last_server_check populated");
    assert!(
        check.reachable,
        "expected reachable ServerCheck, got {check:?}"
    );
    assert!(check.rtt_ms.is_some());
    assert!(check.error.is_none());

    // 7. Simulate catastrophic `kill -9` (`SIGKILL`) directly on the `vless-engine` child PID
    //    WITHOUT calling `supervisor.disconnect()`!
    let child_pids = find_child_engine_pids(&engine_bin);
    assert_eq!(
        child_pids.len(),
        1,
        "expected exactly 1 live vless-engine child PID before SIGKILL, got {child_pids:?}"
    );
    let victim_pid = child_pids[0];

    // Confirm `utun` socketpair is still open (`WouldBlock`) immediately before `SIGKILL`.
    let mut probe_byte = [0u8; 1];
    assert_eq!(
        utun_kernel_peer
            .read(&mut probe_byte)
            .expect_err("expected WouldBlock while engine holds utun_fd")
            .kind(),
        io::ErrorKind::WouldBlock
    );

    // SAFETY: `victim_pid` was verified immediately above to be our direct `vless-engine` child
    // process (`PPid == getpid()`); sending `SIGKILL` terminates only that child process.
    let kill_rc = unsafe { libc::kill(victim_pid, libc::SIGKILL) };
    assert_eq!(
        kill_rc,
        0,
        "kill(SIGKILL) failed: {}",
        io::Error::last_os_error()
    );

    // Invariant (2): `EngineSupervisor` survives the child crash and transitions `SupervisorState`
    // to `EngineStatus::Error`!
    tokio::time::timeout(
        Duration::from_secs(5),
        state_rx.wait_for(|s| s.status == EngineStatus::Error),
    )
    .await
    .expect("EngineSupervisor must transition to EngineStatus::Error on child SIGKILL")
    .expect("state watch open");

    let crash_state = supervisor.state();
    assert_eq!(crash_state.status, EngineStatus::Error);
    assert!(crash_state.utun_name.is_none());
    let crash_detail = crash_state
        .detail
        .expect("crash diagnostic detail must be populated");
    assert!(
        crash_detail.contains("signal 9") || crash_detail.contains("exited"),
        "expected crash diagnostic mentioning signal 9, got {crash_detail:?}"
    );

    // Invariant (1): `vless-tray-helper` detects Unix socket EOF from the killed engine, restores
    // ALL routes and `SCDynamicStore` DNS in `MockSystemBackend`, and deletes `helper-state.json`
    // automatically!
    wait_for_condition(
        Duration::from_secs(5),
        "automatic helper EOF teardown (routes cleared, DNS restored, helper-state.json deleted)",
        || !state_path.exists() && backend.routes().is_empty(),
    )
    .await;

    assert!(
        backend.routes().is_empty(),
        "all managed routes must be removed after SIGKILL: {:?}",
        backend.routes()
    );
    assert!(
        !state_path.exists(),
        "helper-state.json must be deleted automatically after SIGKILL"
    );
    assert_eq!(
        backend
            .dns_state(WIFI_SERVICE_ID)
            .unwrap()
            .state_dns_servers,
        Some(vec![wifi_dns_ip]),
        "Wi-Fi SCDynamicStore DNS must remain restored to 192.168.1.1"
    );
    assert_eq!(
        backend
            .dns_state(HOTSPOT_SERVICE_ID)
            .unwrap()
            .state_dns_servers,
        Some(vec![hotspot_dns_ip]),
        "Hotspot SCDynamicStore DNS must be restored from 1.1.1.1 back to 172.20.10.1"
    );

    // Bonus invariant (`PLAN.md` §4): `utun` kernel peer immediately sees `Ok(0)` EOF because
    // `vless-tray-helper` retained zero copies of `utun_fd` after `SCM_RIGHTS` delivery!
    assert_eq!(
        utun_kernel_peer
            .read(&mut probe_byte)
            .expect("read utun_kernel_peer after engine SIGKILL"),
        0,
        "utun fd must reach EOF immediately when vless-engine dies (zero fd copies retained in helper)"
    );

    let _ = helper_shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), helper_task).await;
    server_tasks.abort_all();
}

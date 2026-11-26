//! Integration tests for the `vless-engine` binary (`ipc` JSON-lines mode, helper `Stop` /
//! `NetworkChanged` lifecycle, `--version` / `--help`, and standalone `run` CLI mode).

use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, UnixListener};
use vless_engine::generate_reality_keypair;
use vless_ipc::{
    AppToEngine, EngineLaunchMode, EngineStatus, EngineToApp, HelperCommand, HelperMessage,
    HelperResponse, async_send_helper_message, async_try_recv_helper_command, parse_vless_link,
    read_json_line_sync, write_json_line_sync,
};

#[tokio::test]
async fn vless_engine_child_binary_json_lines_lifecycle() {
    let fake_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = fake_server.local_addr().unwrap().port();
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fake_server.accept().await {
            drop(stream);
        }
    });

    let (_, pbk) = generate_reality_keypair().unwrap();
    let profile = parse_vless_link(&format!(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:{server_port}?security=reality&flow=xtls-rprx-vision&sni=example.com&pbk={pbk}&sid=0123456789abcdef#BinaryIPC"
    ))
    .unwrap()
    .profile;

    // Exercise `vless-engine ipc` (exact subcommand spawned by `app/src/supervisor.rs`)
    let work = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vless-engine"))
            .arg("ipc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vless-engine ipc");

        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());

        write_json_line_sync(
            &mut stdin,
            &AppToEngine::Start {
                profile,
                mode: EngineLaunchMode::StandaloneProxy {
                    listen_addr: "127.0.0.1:0".parse().unwrap(),
                },
                dns_resolver: "1.1.1.1".parse().unwrap(),
                bypass_cidrs: vec![],
                bypass_domains: vec!["*.local".into()],
            },
        )
        .unwrap();

        let bound_addr = loop {
            let msg: EngineToApp = read_json_line_sync(&mut stdout)
                .unwrap()
                .expect("unexpected EOF before Connected");
            if let EngineToApp::State {
                status: EngineStatus::Connected,
                listen_addr: Some(addr),
                ..
            } = msg
            {
                break addr;
            }
        };
        assert_ne!(bound_addr.port(), 0);

        write_json_line_sync(&mut stdin, &AppToEngine::RecheckServer).unwrap();
        loop {
            let msg: EngineToApp = read_json_line_sync(&mut stdout)
                .unwrap()
                .expect("unexpected EOF before ServerCheck");
            if let EngineToApp::ServerCheck {
                reachable,
                rtt_ms,
                error,
            } = msg
            {
                assert!(reachable, "expected reachable server, error={error:?}");
                assert!(rtt_ms.is_some());
                break;
            }
        }

        write_json_line_sync(&mut stdin, &AppToEngine::Stop).unwrap();
        while let Some(msg) = read_json_line_sync::<_, EngineToApp>(&mut stdout).unwrap() {
            if matches!(
                msg,
                EngineToApp::State {
                    status: EngineStatus::Stopped,
                    ..
                }
            ) {
                break;
            }
        }

        let status = child.wait().unwrap();
        assert!(status.success());
    });

    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .expect("vless-engine child binary IPC test timed out")
        .unwrap();
    accept_task.abort();
}

#[tokio::test]
async fn vless_engine_tun_helper_network_changed_and_clean_stop_handshake() {
    let fake_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = fake_server.local_addr().unwrap().port();
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fake_server.accept().await {
            drop(stream);
        }
    });

    let tmp_dir = tempfile::tempdir().unwrap();
    let helper_sock_path = tmp_dir.path().join("helper.sock");
    let helper_listener = UnixListener::bind(&helper_sock_path).unwrap();

    let saw_update_route = Arc::new(AtomicBool::new(false));
    let saw_helper_stop = Arc::new(AtomicBool::new(false));
    let saw_update_clone = saw_update_route.clone();
    let saw_stop_clone = saw_helper_stop.clone();

    let helper_task = tokio::spawn(async move {
        let (sock, _) = helper_listener.accept().await.unwrap();
        let cmd = async_try_recv_helper_command(&sock)
            .await
            .unwrap()
            .expect("expected StartTun");
        assert!(matches!(cmd, HelperCommand::StartTun { .. }));

        let (_wire_peer, tun_end) = UnixDatagram::pair().unwrap();
        async_send_helper_message(
            &sock,
            &HelperMessage::Response(HelperResponse::TunReady {
                utun_name: "utun77".into(),
                outbound_if_index: 1,
                outbound_if_name: "en0".into(),
                original_dns_servers: vec!["192.0.2.53".parse().unwrap()],
            }),
            Some(tun_end.as_fd()),
        )
        .await
        .unwrap();

        // Push a `NetworkChanged` notification and verify `vless-engine` sends `UpdateServerRoute`
        async_send_helper_message(
            &sock,
            &HelperMessage::NetworkChanged {
                outbound_if_index: 2,
                outbound_if_name: "en1".into(),
                original_dns_servers: vec!["198.51.100.53".parse().unwrap()],
            },
            None,
        )
        .await
        .unwrap();

        loop {
            match async_try_recv_helper_command(&sock).await {
                Ok(Some(HelperCommand::UpdateServerRoute { .. })) => {
                    saw_update_clone.store(true, Ordering::SeqCst);
                    async_send_helper_message(
                        &sock,
                        &HelperMessage::Response(HelperResponse::ServerRouteUpdated {
                            outbound_if_index: 2,
                            outbound_if_name: "en1".into(),
                            original_dns_servers: vec!["198.51.100.53".parse().unwrap()],
                        }),
                        None,
                    )
                    .await
                    .unwrap();
                }
                Ok(Some(HelperCommand::Stop)) => {
                    saw_stop_clone.store(true, Ordering::SeqCst);
                    async_send_helper_message(
                        &sock,
                        &HelperMessage::Response(HelperResponse::Stopped),
                        None,
                    )
                    .await
                    .unwrap();
                    break;
                }
                other => panic!("unexpected helper command: {other:?}"),
            }
        }
    });

    let (_, pbk) = generate_reality_keypair().unwrap();
    let profile = parse_vless_link(&format!(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:{server_port}?security=reality&flow=xtls-rprx-vision&sni=example.com&pbk={pbk}&sid=0123456789abcdef#TunIPC"
    ))
    .unwrap()
    .profile;

    let sock_for_engine = helper_sock_path.clone();
    let work = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vless-engine"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vless-engine");

        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());

        write_json_line_sync(
            &mut stdin,
            &AppToEngine::Start {
                profile,
                mode: EngineLaunchMode::Tun {
                    helper_socket: sock_for_engine,
                },
                dns_resolver: "1.1.1.1".parse().unwrap(),
                bypass_cidrs: vec![],
                bypass_domains: vec![],
            },
        )
        .unwrap();

        // Wait for initial `Connected`, then `Reconnecting` -> `Connected` from `NetworkChanged`
        let mut saw_reconnecting = false;
        loop {
            let msg: EngineToApp = read_json_line_sync(&mut stdout).unwrap().unwrap();
            match msg {
                EngineToApp::State {
                    status: EngineStatus::Reconnecting,
                    utun_name: Some(ref name),
                    ..
                } if name == "utun77" => {
                    saw_reconnecting = true;
                }
                EngineToApp::State {
                    status: EngineStatus::Connected,
                    utun_name: Some(ref name),
                    ..
                } if saw_reconnecting && name == "utun77" => {
                    break;
                }
                _ => {}
            }
        }

        write_json_line_sync(&mut stdin, &AppToEngine::Stop).unwrap();
        while let Some(msg) = read_json_line_sync::<_, EngineToApp>(&mut stdout).unwrap() {
            if matches!(
                msg,
                EngineToApp::State {
                    status: EngineStatus::Stopped,
                    ..
                }
            ) {
                break;
            }
        }
        assert!(child.wait().unwrap().success());
    });

    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), helper_task)
        .await
        .unwrap()
        .unwrap();

    assert!(
        saw_update_route.load(Ordering::SeqCst),
        "expected UpdateServerRoute after NetworkChanged"
    );
    assert!(
        saw_helper_stop.load(Ordering::SeqCst),
        "expected HelperCommand::Stop to reach helper before exit"
    );
    accept_task.abort();
}

#[tokio::test]
async fn vless_engine_cli_version_help_and_standalone_run() {
    let bin = env!("CARGO_BIN_EXE_vless-engine");

    let ver = Command::new(bin).arg("--version").output().unwrap();
    assert!(ver.status.success());
    let ver_stdout = String::from_utf8(ver.stdout).unwrap();
    assert!(
        ver_stdout.starts_with("vless-engine "),
        "unexpected --version output: {ver_stdout:?}"
    );

    let run_help = Command::new(bin).args(["run", "--help"]).output().unwrap();
    assert!(run_help.status.success());
    let help_stdout = String::from_utf8(run_help.stdout).unwrap();
    for flag in [
        "--link",
        "--listen",
        "--tun-fd",
        "--outbound-if-index",
        "--dns-resolver",
        "--bypass",
    ] {
        assert!(help_stdout.contains(flag), "missing {flag} in run --help");
    }

    // Exercise standalone `vless-engine run --link ... --listen 127.0.0.1:0` + clean SIGTERM exit
    let (_, pbk) = generate_reality_keypair().unwrap();
    let link = format!(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443?security=reality&flow=xtls-rprx-vision&sni=example.com&pbk={pbk}&sid=0123456789abcdef#StandaloneRun"
    );

    let work = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(bin)
            .args([
                "run",
                "--link",
                &link,
                "--listen",
                "127.0.0.1:0",
                "--bypass",
                "10.0.0.0/8,*.local",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vless-engine run");

        let stderr = BufReader::new(child.stderr.take().unwrap());
        for line in stderr.lines() {
            let line = line.unwrap();
            if line.contains("vless-engine listening on 127.0.0.1:") {
                break;
            }
        }

        // Send SIGTERM and verify graceful exit with status 0
        // SAFETY: `child.id()` is the live PID of our spawned child process before `wait()`.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "expected exit 0 on SIGTERM, got {status:?}"
        );
    });

    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .expect("standalone CLI run test timed out")
        .unwrap();
}

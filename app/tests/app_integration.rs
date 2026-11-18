use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use vless_ipc::{AppToEngine, ConfigStore, ConnectionMode, EngineLaunchMode, EngineStatus};
use vless_tray::settings_ui::{ProfileKindDraft, SettingsState};
use vless_tray::supervisor::{RuntimeSupervisor, SupervisorConfig};

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const TEST_PBK: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

#[test]
fn vless_tray_cli_help_version_and_install_helper_dry_run_work() {
    let bin = env!("CARGO_BIN_EXE_vless-tray");

    let help_out = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(help_out.status.success());
    let help_str = String::from_utf8(help_out.stdout).unwrap();
    assert!(help_str.contains("--settings"));
    assert!(help_str.contains("install-helper"));

    let ver_out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(ver_out.status.success());
    assert!(
        String::from_utf8(ver_out.stdout)
            .unwrap()
            .starts_with("vless-tray ")
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let app_dir = temp.path().join("VLESS Tray.app").join("Contents");
    let res_dir = app_dir.join("Resources");
    let daemon_dir = app_dir.join("Library").join("LaunchDaemons");
    fs::create_dir_all(&res_dir).unwrap();
    fs::create_dir_all(&daemon_dir).unwrap();

    let script = res_dir.join("install-helper.sh");
    let helper = daemon_dir.join("vless-tray-helper");
    let plist = res_dir.join("io.vless-tray.helper.dev.plist");
    fs::write(&script, b"#!/bin/bash\n").unwrap();
    fs::write(&helper, b"helper").unwrap();
    fs::write(&plist, b"<plist/>").unwrap();

    let dry_out = Command::new(bin)
        .args(["install-helper", "--dry-run", "--uid", "501"])
        .arg("--script")
        .arg(&script)
        .arg("--helper")
        .arg(&helper)
        .arg("--plist")
        .arg(&plist)
        .output()
        .expect("run install-helper --dry-run");
    assert!(
        dry_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let stdout = String::from_utf8(dry_out.stdout).unwrap();
    assert!(stdout.contains("/usr/bin/osascript -e "));
    assert!(stdout.contains("with administrator privileges"));
    assert!(stdout.contains("--uid 501"));
    assert!(stdout.contains("VLESS Tray.app"));
}

#[test]
fn end_to_end_settings_store_runtime_supervisor_mode_switch_and_live_log_tail() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = temp.path().join("user-config");
    let store = ConfigStore::new(cfg_dir.clone());

    // 1. Configure profile, custom bypass list, DNS resolver, and proxy port via SettingsState
    let mut settings = SettingsState::load(store.clone());
    let link = format!(
        "vless://{TEST_UUID}@edge.example.com:443?security=reality&flow=xtls-rprx-vision&sni=www.apple.com&pbk={TEST_PBK}&sid=01ab#Primary"
    );
    let reality_id = settings.import_vless_link(&link).expect("import REALITY");

    // Also add a manual kTLS profile via editor with SHA-256 pin
    settings.start_new_profile();
    {
        let draft = settings.editor.as_mut().unwrap();
        draft.kind = ProfileKindDraft::Ktls;
        draft.name = "Secondary kTLS".to_string();
        draft.server_host = "ktls.example.net".to_string();
        draft.server_port = "8443".to_string();
        draft.uuid = TEST_UUID.to_string();
        draft.sni = "ktls.example.net".to_string();
        draft.alpn = "h2, http/1.1".to_string();
        draft.cert_sha256_pin = "aa".repeat(32);
    }
    let _ktls_id = settings.save_profile_draft().expect("save manual kTLS");

    settings.select_profile(reality_id).unwrap();
    settings.bypass_input = "*.internal.example".to_string();
    settings.add_bypass_from_input().unwrap();
    settings.dns_resolver_input = "1.0.0.1".to_string();
    settings.proxy_port_input = "2085".to_string();
    settings.save_dns_and_proxy().unwrap();

    assert_eq!(
        fs::metadata(store.config_path()).unwrap().mode() & 0o777,
        0o600
    );

    // 2. Prepare a mock `vless-engine` recording every `start` payload received over stdin
    let recorded_starts = temp.path().join("starts.jsonl");
    let mock_engine = temp.path().join("mock-engine.sh");
    let script = format!(
        r#"#!/bin/sh
set -eu
while IFS= read -r line; do
    case "$line" in
        *'"type":"start"'*)
            printf '%s\n' "$line" >> "{starts}"
            printf '%s\n' '{{"type":"log","timestamp_ms":1700000001000,"level":"info","target":"vless_engine","message":"session started"}}'
            case "$line" in
                *'"kind":"system_proxy"'*)
                    printf '%s\n' '{{"type":"state","status":"connected","detail":null,"listen_addr":"127.0.0.1:2085","utun_name":null}}'
                    ;;
                *'"kind":"tun"'*)
                    printf '%s\n' '{{"type":"state","status":"connected","detail":null,"listen_addr":null,"utun_name":"utun9"}}'
                    ;;
            esac
            ;;
        *'"type":"stop"'*)
            exit 0
            ;;
    esac
done
"#,
        starts = recorded_starts.display()
    );
    fs::write(&mock_engine, script).unwrap();
    fs::set_permissions(&mock_engine, Permissions::from_mode(0o755)).unwrap();

    let mut sup_cfg = SupervisorConfig::new(cfg_dir);
    sup_cfg.engine_bin_override = Some(mock_engine);
    sup_cfg.helper_socket = PathBuf::from("/tmp/helper-e2e.sock");

    let runtime_sup = RuntimeSupervisor::new(sup_cfg).expect("create RuntimeSupervisor");

    // Connect in SystemProxy mode first
    let mut cfg = store.load().unwrap();
    cfg.mode = ConnectionMode::SystemProxy;
    store.save(&cfg).unwrap();
    runtime_sup.spawn_connect(cfg.clone());

    wait_until(Duration::from_secs(3), || {
        let st = runtime_sup.state();
        st.status == EngineStatus::Connected
            && st.listen_addr == Some("127.0.0.1:2085".parse().unwrap())
    });

    // Live switch to TUN mode -> tears down SystemProxy session and launches TUN session
    cfg.mode = ConnectionMode::Tun;
    store.save(&cfg).unwrap();
    runtime_sup.spawn_connect(cfg);

    wait_until(Duration::from_secs(3), || {
        let st = runtime_sup.state();
        st.status == EngineStatus::Connected && st.utun_name.as_deref() == Some("utun9")
    });

    // Settings UI incrementally tails the live engine.log written by RuntimeSupervisor
    settings.refresh_logs_incremental();
    assert!(
        settings
            .log_tailer
            .lines()
            .iter()
            .any(|l| l.raw_line.contains("session started"))
    );

    // Graceful Quit shutdown
    runtime_sup.shutdown();
    assert_eq!(runtime_sup.state().status, EngineStatus::Stopped);

    // Verify both Start payloads written to child stdin
    let starts_raw = fs::read_to_string(&recorded_starts).expect("read starts.jsonl");
    let parsed_starts: Vec<AppToEngine> = starts_raw
        .lines()
        .map(|l| vless_ipc::decode_json_line(l).expect("decode AppToEngine"))
        .collect();
    assert_eq!(parsed_starts.len(), 2);

    match &parsed_starts[0] {
        AppToEngine::Start { mode, .. } => assert_eq!(
            mode,
            &EngineLaunchMode::SystemProxy {
                listen_addr: "127.0.0.1:2085".parse().unwrap(),
                helper_socket: PathBuf::from("/tmp/helper-e2e.sock"),
            }
        ),
        other => panic!("unexpected msg 0: {other:?}"),
    }
    match &parsed_starts[1] {
        AppToEngine::Start { mode, .. } => assert_eq!(
            mode,
            &EngineLaunchMode::Tun {
                helper_socket: PathBuf::from("/tmp/helper-e2e.sock"),
            }
        ),
        other => panic!("unexpected msg 1: {other:?}"),
    }
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("condition was not met within {timeout:?}");
}

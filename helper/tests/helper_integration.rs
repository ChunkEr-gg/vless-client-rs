//! Comprehensive Unix-socket, `SCM_RIGHTS`, `PF_ROUTE`, crash-recovery, rollback, and `launchd`
//! lifecycle integration tests for `vless-tray-helper`.

use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixStream as TokioUnixStream;
use tokio::sync::watch;
use vless_ipc::{
    HelperCommand, HelperMessage, HelperMode, HelperResponse, async_recv_helper_message,
    async_send_frame_with_fd, async_send_helper_command, async_try_recv_frame_with_fd,
};
use vless_tray_helper::{
    DaemonLifecycle, DefaultGatewayV4, DefaultGatewayV6, DnsSnapshot, HelperConfig, HelperJournal,
    JOURNAL_SCHEMA_VERSION, MockFailPoint, MockOperation, MockServiceDnsState, MockSystemBackend,
    OwnerUidPolicy, ProxyEndpointConfig, RouteDestination, RouteSpec, RouteTarget,
    ServiceProxySnapshot, TUN_CAPTURE_CIDR_STRS, UTUN_IPV4_ADDR, UTUN_IPV4_PEER,
    UTUN_IPV4_SUBNET_STR, UTUN_IPV6_ADDR, UTUN_IPV6_PREFIXLEN, UTUN_MTU, encode_mock_dns_xml,
    load_journal, run_recover_only, save_journal, serve_activated_listener_fd,
    serve_bound_socket_path,
};

fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and is always thread-safe.
    unsafe { libc::geteuid() }
}

#[test]
fn boot_and_recover_only_restore_leftover_tun_and_system_proxy_journals() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("helper-state.json");
    let backend = MockSystemBackend::new_dual_stack_default();

    let svc_id = "E621E1F8-C36C-495A-93FC-0C247A3E6E5F".to_string();
    let orig_dns: IpAddr = "192.168.1.1".parse().unwrap();

    // Simulate system left dirty after a hard crash in TUN mode:
    let dirty_routes = vec![
        RouteSpec {
            destination: RouteDestination::Cidr(UTUN_IPV4_SUBNET_STR.parse().unwrap()),
            target: RouteTarget::Interface("utun7".to_string()),
        },
        RouteSpec {
            destination: RouteDestination::Host("203.0.113.10".parse().unwrap()),
            target: RouteTarget::GatewayV4("192.168.1.1".parse().unwrap()),
        },
        RouteSpec {
            destination: RouteDestination::Cidr("0.0.0.0/1".parse().unwrap()),
            target: RouteTarget::Interface("utun7".to_string()),
        },
        RouteSpec {
            destination: RouteDestination::Cidr("128.0.0.0/1".parse().unwrap()),
            target: RouteTarget::Interface("utun7".to_string()),
        },
    ];
    backend.seed_routes(dirty_routes.clone());
    backend.set_service_dns_state(
        &svc_id,
        MockServiceDnsState {
            state_dns_servers: Some(vec!["1.1.1.1".parse().unwrap()]),
            state_supplemental_match_domains: Some(vec![String::new()]),
            state_raw_xml: Some(encode_mock_dns_xml(
                &["1.1.1.1".parse().unwrap()],
                Some(&[String::new()]),
            )),
            setup_dns_servers: Vec::new(),
        },
    );

    let tun_journal = HelperJournal::Tun {
        version: JOURNAL_SCHEMA_VERSION,
        utun_name: "utun7".to_string(),
        v4_gateway: Some(DefaultGatewayV4 {
            gateway: "192.168.1.1".parse().unwrap(),
            interface: "en0".to_string(),
            if_index: 6,
        }),
        v6_gateway: None,
        dns_snapshots: vec![DnsSnapshot {
            service_id: svc_id.clone(),
            had_state_dns: true,
            state_dns_plist_xml: Some(encode_mock_dns_xml(&[orig_dns], None)),
            had_setup_dns: false,
            setup_dns_plist_xml: None,
            original_dns_servers: vec![orig_dns],
        }],
        dns_resolver: "1.1.1.1".parse().unwrap(),
        server_ips: vec!["203.0.113.10".parse().unwrap()],
        bypass_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        routes: dirty_routes,
    };
    save_journal(&state_path, &tun_journal).expect("save tun journal");
    assert_eq!(fs::metadata(&state_path).unwrap().mode() & 0o777, 0o600);

    // Run --recover-only logic
    assert!(run_recover_only(&backend, &state_path).expect("recover tun journal"));
    assert!(!state_path.exists(), "journal file must be deleted");
    assert!(backend.routes().is_empty(), "all routes must be removed");
    assert_eq!(
        backend.dns_state(&svc_id).unwrap().state_dns_servers,
        Some(vec![orig_dns])
    );

    // Second call when no journal exists is a clean no-op returning false
    assert!(!run_recover_only(&backend, &state_path).expect("idempotent recover"));

    // Also test recovery when `had_state_dns == false` and `had_setup_dns == true`
    // (removes ephemeral State:/.../DNS key while restoring manual Setup:/.../DNS)
    let static_svc = "STATIC-SERVICE-01";
    let manual_dns: IpAddr = "9.9.9.9".parse().unwrap();
    backend.set_service_dns_state(
        static_svc,
        MockServiceDnsState {
            state_dns_servers: Some(vec!["1.1.1.1".parse().unwrap()]),
            state_supplemental_match_domains: None,
            state_raw_xml: None,
            setup_dns_servers: vec!["1.1.1.1".parse().unwrap()],
        },
    );
    let no_prior_state_dns_journal = HelperJournal::Tun {
        version: JOURNAL_SCHEMA_VERSION,
        utun_name: "utun8".to_string(),
        v4_gateway: None,
        v6_gateway: None,
        dns_snapshots: vec![DnsSnapshot {
            service_id: static_svc.to_string(),
            had_state_dns: false,
            state_dns_plist_xml: None,
            had_setup_dns: true,
            setup_dns_plist_xml: Some(encode_mock_dns_xml(&[manual_dns], None)),
            original_dns_servers: vec![manual_dns],
        }],
        dns_resolver: "1.1.1.1".parse().unwrap(),
        server_ips: vec!["203.0.113.10".parse().unwrap()],
        bypass_cidrs: vec![],
        routes: vec![],
    };
    save_journal(&state_path, &no_prior_state_dns_journal).unwrap();
    assert!(run_recover_only(&backend, &state_path).unwrap());
    let restored_static = backend.dns_state(static_svc).unwrap();
    assert!(restored_static.state_dns_servers.is_none());
    assert_eq!(restored_static.setup_dns_servers, vec![manual_dns]);
}

#[tokio::test]
async fn daemon_startup_recovers_leftover_system_proxy_journal_before_serving() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());

    // Mutate Wi-Fi proxy as if previous helper crashed mid-session
    let dirty_ep = ProxyEndpointConfig {
        enabled: true,
        server: "127.0.0.1".to_string(),
        port: 2080,
    };
    backend.set_network_service(
        "Wi-Fi",
        vless_tray_helper::MockNetworkService {
            enabled: true,
            web: dirty_ep.clone(),
            secure_web: dirty_ep.clone(),
            socks: dirty_ep,
            bypass_domains: vec!["*.local".to_string()],
        },
    );

    let proxy_journal = HelperJournal::SystemProxy {
        version: JOURNAL_SCHEMA_VERSION,
        listen_port: 2080,
        exceptions: vec!["*.local".to_string()],
        services: vec![ServiceProxySnapshot {
            service: "Wi-Fi".to_string(),
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
            bypass_domains: Vec::new(),
        }],
    };
    save_journal(&state_path, &proxy_journal).unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let backend_clone = Arc::clone(&backend);
    let sock_clone = sock_path.clone();
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    // Wait for socket bind
    let client = connect_with_retry(&sock_path).await;
    async_send_helper_command(&client, &HelperCommand::Status)
        .await
        .unwrap();
    let (msg, fd) = async_recv_helper_message(&client).await.unwrap();
    assert!(fd.is_none());
    match msg {
        HelperMessage::Response(HelperResponse::Status(st)) => {
            assert_eq!(st.mode, HelperMode::Idle);
        }
        other => panic!("unexpected reply: {other:?}"),
    }

    // Leftover journal must already have been recovered and deleted
    assert!(!state_path.exists());
    let wifi = backend.service_state("Wi-Fi").unwrap();
    assert!(!wifi.web.enabled);
    assert!(wifi.web.server.is_empty());
    assert!(wifi.bypass_domains.is_empty());

    drop(client);
    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn unauthorized_peer_uid_is_rejected_before_reading_commands() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");
    let owner_uid_file = tmp.path().join("owner-uid");

    // Write an owner-uid that does NOT match our current effective UID
    let wrong_uid = current_euid().saturating_add(1).max(1);
    vless_ipc::write_atomic_0600(&owner_uid_file, format!("{wrong_uid}\n").as_bytes()).unwrap();

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path,
        owner_uid_policy: OwnerUidPolicy::OwnerFile {
            path: owner_uid_file.clone(),
            enforce_root_owner_file: false,
        },
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let rogue_client = connect_with_retry(&sock_path).await;
    // Even if we write a Status command, the daemon closes our socket immediately without replying.
    let _ = async_send_helper_command(&rogue_client, &HelperCommand::Status).await;
    let recv_res = async_try_recv_frame_with_fd::<HelperMessage>(&rogue_client).await;
    match recv_res {
        Ok(None) | Err(_) => {}
        Ok(Some(unexpected)) => panic!("unauthorized peer received reply: {unexpected:?}"),
    }
    drop(rogue_client);

    // Updating owner-uid to the current non-zero UID allows authorized connections immediately
    if current_euid() > 0 {
        vless_ipc::write_atomic_0600(&owner_uid_file, format!("{}\n", current_euid()).as_bytes())
            .unwrap();
        let valid_client = TokioUnixStream::connect(&sock_path).await.unwrap();
        async_send_helper_command(&valid_client, &HelperCommand::Status)
            .await
            .unwrap();
        let (msg, _) = async_recv_helper_message(&valid_client).await.unwrap();
        assert!(matches!(
            msg,
            HelperMessage::Response(HelperResponse::Status(_))
        ));
    }

    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn full_tun_lifecycle_scm_rights_fd_drop_route_update_pf_route_and_kill9_cleanup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let client = connect_with_retry(&sock_path).await;

    // 1. StartTun
    let start_cmd = HelperCommand::StartTun {
        server_ips: vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ],
        bypass_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
        dns_resolver: "1.1.1.1".parse().unwrap(),
    };
    async_send_helper_command(&client, &start_cmd)
        .await
        .unwrap();

    let (msg, maybe_utun_fd) = async_recv_helper_message(&client).await.unwrap();
    let utun_fd: OwnedFd =
        maybe_utun_fd.expect("TunReady must deliver utun OwnedFd via SCM_RIGHTS");
    assert_eq!(
        msg,
        HelperMessage::Response(HelperResponse::TunReady {
            utun_name: "utun7".to_string(),
            outbound_if_index: 6,
            outbound_if_name: "en0".to_string(),
            original_dns_servers: vec!["192.168.1.1".parse().unwrap()],
        })
    );

    // Verify 0600 journal on disk
    assert!(state_path.exists());
    assert_eq!(fs::metadata(&state_path).unwrap().mode() & 0o777, 0o600);

    // Verify utun7 configuration (198.18.0.1 -> 198.18.0.2 /30, fd00:198:18::1/128, MTU 1400)
    let utun_cfg = backend.utun_device("utun7").unwrap().config.unwrap();
    assert_eq!(utun_cfg.ipv4_addr, UTUN_IPV4_ADDR);
    assert_eq!(utun_cfg.ipv4_peer, UTUN_IPV4_PEER);
    assert_eq!(utun_cfg.ipv6_addr, UTUN_IPV6_ADDR);
    assert_eq!(utun_cfg.ipv6_prefixlen, UTUN_IPV6_PREFIXLEN);
    assert_eq!(utun_cfg.ipv6_prefixlen, 128);
    assert_eq!(utun_cfg.mtu, UTUN_MTU);
    assert_eq!(utun_cfg.mtu, 1400);

    // Verify DNS override in dynamic store (both State: and Setup:, without SupplementalMatchDomains)
    let wifi_svc = "E621E1F8-C36C-495A-93FC-0C247A3E6E5F";
    let dns_now = backend.dns_state(wifi_svc).unwrap();
    assert_eq!(
        dns_now.state_dns_servers,
        Some(vec!["1.1.1.1".parse().unwrap()])
    );
    assert!(dns_now.state_supplemental_match_domains.is_none());
    assert_eq!(
        dns_now.setup_dns_servers,
        vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
    );

    // Verify routes include server host routes, custom bypass CIDR, on-link link-local/multicast,
    // no unscoped fe80::/10 route, and all 4 half-default TUN routes
    let initial_routes = backend.routes();
    assert!(initial_routes.contains(&RouteSpec {
        destination: RouteDestination::Host("203.0.113.10".parse().unwrap()),
        target: RouteTarget::GatewayV4("192.168.1.1".parse().unwrap()),
    }));
    assert!(initial_routes.contains(&RouteSpec {
        destination: RouteDestination::Host("2001:db8::10".parse().unwrap()),
        target: RouteTarget::GatewayV6("fe80::1%en0".to_string()),
    }));
    assert!(initial_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("100.64.0.0/10".parse().unwrap()),
        target: RouteTarget::GatewayV4("192.168.1.1".parse().unwrap()),
    }));
    assert!(initial_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("169.254.0.0/16".parse().unwrap()),
        target: RouteTarget::Interface("en0".to_string()),
    }));
    assert!(initial_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("224.0.0.0/4".parse().unwrap()),
        target: RouteTarget::Interface("en0".to_string()),
    }));
    assert!(
        !initial_routes
            .iter()
            .any(|r| { r.destination == RouteDestination::Cidr("fe80::/10".parse().unwrap()) }),
        "fe80::/10 must be skipped on XNU"
    );
    for cap in TUN_CAPTURE_CIDR_STRS {
        assert!(initial_routes.contains(&RouteSpec {
            destination: RouteDestination::Cidr(cap.parse().unwrap()),
            target: RouteTarget::Interface("utun7".to_string()),
        }));
    }

    // 2. CRITICAL PROOF (`PLAN.md` §4): Verify helper dropped its copy of `utun_fd` immediately!
    let mut kernel_utun_peer = backend
        .take_utun_peer("utun7")
        .expect("simulated utun socketpair peer");
    kernel_utun_peer
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut client_utun_stream = StdUnixStream::from(utun_fd);
    client_utun_stream
        .write_all(b"\x00\x00\x00\x02pkt-over-utun")
        .unwrap();
    let mut pkt_buf = [0u8; 17];
    kernel_utun_peer.read_exact(&mut pkt_buf).unwrap();
    assert_eq!(&pkt_buf, b"\x00\x00\x00\x02pkt-over-utun");

    // Closing ONLY the client's utun stream while keeping `client` IPC socket open MUST immediately
    // produce EOF (`Ok(0)`) on `kernel_utun_peer` because the helper holds ZERO copies of `utun_fd`!
    drop(client_utun_stream);
    let mut eof_check = [0u8; 1];
    assert_eq!(
        kernel_utun_peer.read(&mut eof_check).expect("EOF read"),
        0,
        "helper leaked a copy of utun_fd!"
    );

    // 3. Spurious PF_ROUTE wakeup (no gateway change) must NOT emit NetworkChanged
    backend.emit_spurious_route_event();
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Also verify secondary connection can query `Status` while primary session is active,
    // while mutating commands on the secondary connection are rejected!
    let secondary = TokioUnixStream::connect(&sock_path).await.unwrap();
    async_send_helper_command(&secondary, &HelperCommand::Status)
        .await
        .unwrap();
    let (sec_status, _) = async_recv_helper_message(&secondary).await.unwrap();
    match sec_status {
        HelperMessage::Response(HelperResponse::Status(st)) => {
            assert_eq!(st.mode, HelperMode::Tun);
            assert_eq!(st.utun_name.as_deref(), Some("utun7"));
        }
        other => panic!("unexpected secondary status: {other:?}"),
    }
    drop(secondary);

    let secondary_stop = TokioUnixStream::connect(&sock_path).await.unwrap();
    async_send_helper_command(&secondary_stop, &HelperCommand::Stop)
        .await
        .unwrap();
    let (sec_err, _) = async_recv_helper_message(&secondary_stop).await.unwrap();
    assert!(matches!(
        sec_err,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));
    drop(secondary_stop);

    // 4. UpdateServerRoute
    let new_server_ip: IpAddr = "198.51.100.77".parse().unwrap();
    async_send_helper_command(
        &client,
        &HelperCommand::UpdateServerRoute {
            server_ips: vec![new_server_ip],
        },
    )
    .await
    .unwrap();
    let (upd_msg, _) = async_recv_helper_message(&client).await.unwrap();
    assert_eq!(
        upd_msg,
        HelperMessage::Response(HelperResponse::ServerRouteUpdated {
            outbound_if_index: 6,
            outbound_if_name: "en0".to_string(),
            original_dns_servers: vec!["192.168.1.1".parse().unwrap()],
        })
    );
    let routes_after_upd = backend.routes();
    assert!(
        !routes_after_upd
            .iter()
            .any(|r| { r.destination == RouteDestination::Host("203.0.113.10".parse().unwrap()) })
    );
    assert!(routes_after_upd.contains(&RouteSpec {
        destination: RouteDestination::Host(new_server_ip),
        target: RouteTarget::GatewayV4("192.168.1.1".parse().unwrap()),
    }));

    // 5. PF_ROUTE simulated physical network switch (Wi-Fi en0 -> Ethernet en5 + new PrimaryService)
    let eth_svc = "A1112222-3333-4444-5555-666677778888".to_string();
    let eth_dns: IpAddr = "10.20.0.53".parse().unwrap();
    backend.simulate_network_transition(
        Some(DefaultGatewayV4 {
            gateway: "10.20.0.1".parse().unwrap(),
            interface: "en5".to_string(),
            if_index: 14,
        }),
        Some(DefaultGatewayV6 {
            gateway: "fe80::99%en5".to_string(),
            interface: "en5".to_string(),
            if_index: 14,
        }),
        Some(eth_svc.clone()),
        Some((
            eth_svc.clone(),
            MockServiceDnsState {
                state_dns_servers: Some(vec![eth_dns]),
                state_supplemental_match_domains: None,
                state_raw_xml: Some(encode_mock_dns_xml(&[eth_dns], None)),
                setup_dns_servers: Vec::new(),
            },
        )),
    );

    let (push_msg, push_fd) =
        tokio::time::timeout(Duration::from_secs(2), async_recv_helper_message(&client))
            .await
            .expect("receive NetworkChanged push")
            .unwrap();
    assert!(push_fd.is_none());
    assert_eq!(
        push_msg,
        HelperMessage::NetworkChanged {
            outbound_if_index: 14,
            outbound_if_name: "en5".to_string(),
            original_dns_servers: vec![eth_dns],
        }
    );

    // Verify routes migrated to 10.20.0.1 / fe80::99%en5 and Wi-Fi DNS restored while Eth DNS overridden
    let migrated_routes = backend.routes();
    assert!(migrated_routes.contains(&RouteSpec {
        destination: RouteDestination::Host(new_server_ip),
        target: RouteTarget::GatewayV4("10.20.0.1".parse().unwrap()),
    }));
    assert!(migrated_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("100.64.0.0/10".parse().unwrap()),
        target: RouteTarget::GatewayV4("10.20.0.1".parse().unwrap()),
    }));
    assert!(migrated_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("fc00::/7".parse().unwrap()),
        target: RouteTarget::GatewayV6("fe80::99%en5".to_string()),
    }));
    // Physical-interface bypass routes (169.254.0.0/16 & 224.0.0.0/4) must also migrate en0 -> en5!
    assert!(migrated_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("169.254.0.0/16".parse().unwrap()),
        target: RouteTarget::Interface("en5".to_string()),
    }));
    assert!(migrated_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("224.0.0.0/4".parse().unwrap()),
        target: RouteTarget::Interface("en5".to_string()),
    }));
    assert!(
        !migrated_routes
            .iter()
            .any(|r| r.target == RouteTarget::Interface("en0".to_string())),
        "stale -interface en0 bypass routes must be removed after migrating to en5: {migrated_routes:?}"
    );
    assert_eq!(
        backend.dns_state(wifi_svc).unwrap().state_dns_servers,
        Some(vec!["192.168.1.1".parse().unwrap()])
    );
    assert!(
        backend
            .dns_state(wifi_svc)
            .unwrap()
            .setup_dns_servers
            .is_empty()
    );
    assert_eq!(
        backend.dns_state(&eth_svc).unwrap().state_dns_servers,
        Some(vec!["1.1.1.1".parse().unwrap()])
    );
    assert_eq!(
        backend.dns_state(&eth_svc).unwrap().setup_dns_servers,
        vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
    );

    // 6. Abrupt client socket drop (simulating `kill -9 vless-engine` without `Stop`)!
    drop(client);

    // Wait briefly for daemon to process EOF teardown
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while state_path.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        !state_path.exists(),
        "helper-state.json must be deleted on session EOF"
    );
    assert!(
        backend.routes().is_empty(),
        "all managed routes must be removed on session EOF"
    );
    assert_eq!(
        backend.dns_state(&eth_svc).unwrap().state_dns_servers,
        Some(vec![eth_dns]),
        "Ethernet service DNS must be restored to original 10.20.0.53 on session EOF"
    );

    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn ipv4_only_network_skips_ipv6_gateway_routes_but_captures_ipv6_in_utun() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    backend.set_ipv6_gateway(None);

    // Also pre-populate `224.0.0.0/4` as an OS-owned route (`EEXIST`) to verify preexisting routes
    // are neither fatal on add nor erroneously deleted on Stop!
    let os_multicast_route = RouteSpec {
        destination: RouteDestination::Cidr("224.0.0.0/4".parse().unwrap()),
        target: RouteTarget::Interface("en0".to_string()),
    };
    backend.insert_preexisting_route(os_multicast_route.clone());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let client = connect_with_retry(&sock_path).await;
    async_send_helper_command(
        &client,
        &HelperCommand::StartTun {
            server_ips: vec![
                "203.0.113.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
            bypass_cidrs: vec![],
            dns_resolver: "1.1.1.1".parse().unwrap(),
        },
    )
    .await
    .unwrap();

    let (msg, fd) = async_recv_helper_message(&client).await.unwrap();
    assert!(fd.is_some());
    assert!(matches!(
        msg,
        HelperMessage::Response(HelperResponse::TunReady { .. })
    ));

    let routes = backend.routes();
    // IPv6 gateway routes skipped cleanly
    assert!(
        !routes
            .iter()
            .any(|r| matches!(r.target, RouteTarget::GatewayV6(_)))
    );
    // `::/1` and `8000::/1` MUST still point to utun7 so IPv6 cannot leak (`PLAN.md` §5.2 item 6)
    assert!(routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("::/1".parse().unwrap()),
        target: RouteTarget::Interface("utun7".to_string()),
    }));
    assert!(routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("8000::/1".parse().unwrap()),
        target: RouteTarget::Interface("utun7".to_string()),
    }));

    // Clean Stop preserves preexisting OS multicast route while removing all helper-owned routes
    async_send_helper_command(&client, &HelperCommand::Stop)
        .await
        .unwrap();
    let (stop_msg, _) = async_recv_helper_message(&client).await.unwrap();
    assert_eq!(stop_msg, HelperMessage::Response(HelperResponse::Stopped));
    assert_eq!(backend.routes(), vec![os_multicast_route]);
    assert!(!state_path.exists());

    drop(client);
    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn partial_failure_rollback_cleans_up_tun_and_system_proxy_mutations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let client = connect_with_retry(&sock_path).await;

    // 1. Fail partway through route installation (`AddRouteNth(4)`)
    backend.set_fail_point(Some(MockFailPoint::AddRouteNth(4)));
    async_send_helper_command(
        &client,
        &HelperCommand::StartTun {
            server_ips: vec!["203.0.113.10".parse().unwrap()],
            bypass_cidrs: vec![],
            dns_resolver: "1.1.1.1".parse().unwrap(),
        },
    )
    .await
    .unwrap();
    let (err_msg, err_fd) = async_recv_helper_message(&client).await.unwrap();
    assert!(err_fd.is_none());
    assert!(matches!(
        err_msg,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));
    assert!(
        backend.routes().is_empty(),
        "partial routes must be rolled back"
    );
    assert!(
        !state_path.exists(),
        "journal must be deleted after rollback"
    );

    // 2. Fail on `SetDnsOverride` after ALL routes were installed
    backend.set_fail_point(Some(MockFailPoint::SetDnsOverride));
    async_send_helper_command(
        &client,
        &HelperCommand::StartTun {
            server_ips: vec!["203.0.113.10".parse().unwrap()],
            bypass_cidrs: vec![],
            dns_resolver: "1.1.1.1".parse().unwrap(),
        },
    )
    .await
    .unwrap();
    let (err_msg2, err_fd2) = async_recv_helper_message(&client).await.unwrap();
    assert!(err_fd2.is_none());
    assert!(matches!(
        err_msg2,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));
    assert!(
        backend.routes().is_empty(),
        "all routes must be rolled back on DNS failure"
    );
    assert!(!state_path.exists());

    // 3. Fail on the second enabled network service (`USB 10/100/1000 LAN`) during `StartSystemProxy`
    let orig_wifi = backend.service_state("Wi-Fi").unwrap();
    let orig_usb = backend.service_state("USB 10/100/1000 LAN").unwrap();
    backend.set_fail_point(Some(MockFailPoint::SetServiceProxies(
        "USB 10/100/1000 LAN".to_string(),
    )));

    async_send_helper_command(
        &client,
        &HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: vec!["*.corp.example".to_string()],
        },
    )
    .await
    .unwrap();
    let (err_msg3, _) = async_recv_helper_message(&client).await.unwrap();
    assert!(matches!(
        err_msg3,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));
    assert_eq!(backend.service_state("Wi-Fi").unwrap(), orig_wifi);
    assert_eq!(
        backend.service_state("USB 10/100/1000 LAN").unwrap(),
        orig_usb
    );
    assert!(!state_path.exists());

    // 4. Also verify invalid raw command JSON / invalid parameters return structured Error
    backend.set_fail_point(None);
    let bad_cmd = serde_json::json!({
        "command": "start_system_proxy",
        "listen_port": 0,
        "exceptions": []
    });
    async_send_frame_with_fd(&client, &bad_cmd, None)
        .await
        .unwrap();
    let (val_err, _) = async_recv_helper_message(&client).await.unwrap();
    assert!(matches!(
        val_err,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));

    drop(client);
    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn full_system_proxy_lifecycle_restores_multiple_services_and_empty_exceptions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    let orig_wifi = backend.service_state("Wi-Fi").unwrap();
    let orig_thunderbolt = backend.service_state("Thunderbolt Bridge").unwrap();
    let orig_usb = backend.service_state("USB 10/100/1000 LAN").unwrap();
    assert!(orig_usb.bypass_domains.is_empty());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let client = connect_with_retry(&sock_path).await;
    async_send_helper_command(
        &client,
        &HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: vec!["*.internal.example".to_string(), "*.local".to_string()],
        },
    )
    .await
    .unwrap();

    let (ready_msg, fd) = async_recv_helper_message(&client).await.unwrap();
    assert!(fd.is_none());
    assert_eq!(
        ready_msg,
        HelperMessage::Response(HelperResponse::SystemProxyReady {
            services: vec!["Wi-Fi".to_string(), "USB 10/100/1000 LAN".to_string()],
        })
    );
    assert!(state_path.exists());

    // Disabled Thunderbolt Bridge must be completely untouched
    assert_eq!(
        backend.service_state("Thunderbolt Bridge").unwrap(),
        orig_thunderbolt
    );

    // Enabled Wi-Fi and USB LAN must both have HTTP, HTTPS, and SOCKS set to 127.0.0.1:2080
    for svc_name in ["Wi-Fi", "USB 10/100/1000 LAN"] {
        let svc = backend.service_state(svc_name).unwrap();
        for ep in [&svc.web, &svc.secure_web, &svc.socks] {
            assert!(ep.enabled);
            assert_eq!(ep.server, "127.0.0.1");
            assert_eq!(ep.port, 2080);
        }
        assert!(svc.bypass_domains.contains(&"*.local".to_string()));
        assert!(svc.bypass_domains.contains(&"169.254.0.0/16".to_string()));
        assert!(svc.bypass_domains.contains(&"10.0.0.0/8".to_string()));
        assert!(svc.bypass_domains.contains(&"127.0.0.1".to_string()));
        assert!(svc.bypass_domains.contains(&"::1".to_string()));
        assert!(
            svc.bypass_domains
                .contains(&"*.internal.example".to_string())
        );
    }

    // Stop restores original proxy host/port/enabled and empty bypass list
    async_send_helper_command(&client, &HelperCommand::Stop)
        .await
        .unwrap();
    let (stopped_msg, _) = async_recv_helper_message(&client).await.unwrap();
    assert_eq!(
        stopped_msg,
        HelperMessage::Response(HelperResponse::Stopped)
    );
    assert!(!state_path.exists());

    assert_eq!(backend.service_state("Wi-Fi").unwrap(), orig_wifi);
    assert_eq!(
        backend.service_state("USB 10/100/1000 LAN").unwrap(),
        orig_usb
    );

    drop(client);
    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn launchd_socket_activation_lifecycle_exits_zero_when_idle_and_after_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("launchd-vless.sock");
    let state_path = tmp.path().join("helper-state.json");

    // Simulate `launchd` PID 1 holding the listening Unix socket open across helper exits.
    let launchd_master_listener = StdUnixListener::bind(&sock_path).unwrap();
    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());

    // 1. RunAtLoad boot invocation with leftover journal and NO client queued -> recovers & exits 0!
    let leftover = HelperJournal::SystemProxy {
        version: JOURNAL_SCHEMA_VERSION,
        listen_port: 2080,
        exceptions: vec!["*.local".to_string()],
        services: vec![],
    };
    save_journal(&state_path, &leftover).unwrap();

    let activated_fd_1: OwnedFd = launchd_master_listener.try_clone().unwrap().into();
    let (_tx1, rx1) = watch::channel(false);
    let cfg_1 = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::LaunchdSocketActivated {
            idle_grace_timeout: Duration::from_millis(60),
        },
    };
    tokio::time::timeout(
        Duration::from_secs(2),
        serve_activated_listener_fd(activated_fd_1, Arc::clone(&backend), cfg_1, rx1),
    )
    .await
    .expect("RunAtLoad idle exit within grace timeout")
    .expect("clean exit 0");
    assert!(!state_path.exists());

    // 2. Client connects to `launchd`'s socket BEFORE helper spawns (on-demand socket activation!),
    //    runs a session, disconnects, and helper exits immediately once session finishes!
    let client = TokioUnixStream::connect(&sock_path).await.unwrap();
    let activated_fd_2: OwnedFd = launchd_master_listener.try_clone().unwrap().into();
    let (_tx2, rx2) = watch::channel(false);
    let cfg_2 = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::LaunchdSocketActivated {
            idle_grace_timeout: Duration::from_secs(5),
        },
    };

    let helper_task = tokio::spawn(serve_activated_listener_fd(
        activated_fd_2,
        Arc::clone(&backend),
        cfg_2,
        rx2,
    ));

    async_send_helper_command(
        &client,
        &HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: vec![],
        },
    )
    .await
    .unwrap();
    let (msg, _) = async_recv_helper_message(&client).await.unwrap();
    assert!(matches!(
        msg,
        HelperMessage::Response(HelperResponse::SystemProxyReady { .. })
    ));

    // Client disconnects -> helper restores proxies, deletes journal, checks pending accept, exits!
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), helper_task)
        .await
        .expect("helper must exit promptly after session EOF without waiting 5s idle timeout")
        .unwrap()
        .unwrap();

    assert!(!state_path.exists());
    assert!(!backend.service_state("Wi-Fi").unwrap().web.enabled);
}

#[test]
fn cli_binary_recover_only_and_help_execute_cleanly() {
    let bin = env!("CARGO_BIN_EXE_vless-tray-helper");

    let help_out = Command::new(bin).arg("--help").output().unwrap();
    assert!(help_out.status.success());
    assert!(String::from_utf8_lossy(&help_out.stdout).contains("--recover-only"));

    let tmp = tempfile::tempdir().unwrap();
    let state_path = tmp.path().join("helper-state.json");
    let journal = HelperJournal::SystemProxy {
        version: JOURNAL_SCHEMA_VERSION,
        listen_port: 2080,
        exceptions: vec!["*.local".to_string()],
        services: vec![],
    };
    save_journal(&state_path, &journal).unwrap();
    assert!(state_path.exists());

    let recover_out = Command::new(bin)
        .arg("--recover-only")
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .unwrap();
    assert!(recover_out.status.success());
    assert!(!state_path.exists());
}

async fn connect_with_retry(sock_path: &std::path::Path) -> TokioUnixStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match TokioUnixStream::connect(sock_path).await {
            Ok(stream) => return stream,
            Err(err) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("timed out connecting to {}: {err}", sock_path.display());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

#[tokio::test]
async fn wave5_manual_setup_dns_cellular_pdp_ip_and_en0_to_en1_interface_migration() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());
    let wifi_svc = "E621E1F8-C36C-495A-93FC-0C247A3E6E5F";
    let dhcp_dns: IpAddr = "192.168.1.1".parse().unwrap();
    let manual_dns: IpAddr = "9.9.9.9".parse().unwrap();

    // User configured manual DNS (`Setup:`) on top of DHCP DNS (`State:`).
    backend.set_service_dns_state(
        wifi_svc,
        MockServiceDnsState {
            state_dns_servers: Some(vec![dhcp_dns]),
            state_supplemental_match_domains: None,
            state_raw_xml: Some(encode_mock_dns_xml(&[dhcp_dns], None)),
            setup_dns_servers: vec![manual_dns],
        },
    );

    // Validate DnsSnapshot invariant when had_setup_dns=true without XML
    let bad_snap = DnsSnapshot {
        service_id: wifi_svc.to_string(),
        had_state_dns: false,
        state_dns_plist_xml: None,
        had_setup_dns: true,
        setup_dns_plist_xml: None,
        original_dns_servers: vec![manual_dns],
    };
    assert!(bad_snap.validate().is_err());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let client = connect_with_retry(&sock_path).await;
    async_send_helper_command(
        &client,
        &HelperCommand::StartTun {
            server_ips: vec!["203.0.113.55".parse().unwrap()],
            bypass_cidrs: vec!["fe80::/10".parse().unwrap()],
            dns_resolver: "1.1.1.1".parse().unwrap(),
        },
    )
    .await
    .unwrap();

    let (msg, maybe_fd) = async_recv_helper_message(&client).await.unwrap();
    let _utun_fd = maybe_fd.expect("utun fd");
    // `original_dns_servers` MUST prioritize manual `Setup:` DNS (9.9.9.9) over DHCP `State:`!
    assert_eq!(
        msg,
        HelperMessage::Response(HelperResponse::TunReady {
            utun_name: "utun7".to_string(),
            outbound_if_index: 6,
            outbound_if_name: "en0".to_string(),
            original_dns_servers: vec![manual_dns],
        })
    );

    // Persisted journal must record had_setup_dns=true and load cleanly via load_journal
    let saved = load_journal(&state_path).unwrap().expect("active journal");
    match &saved {
        HelperJournal::Tun { dns_snapshots, .. } => {
            assert_eq!(dns_snapshots.len(), 1);
            assert!(dns_snapshots[0].had_setup_dns);
            assert!(dns_snapshots[0].setup_dns_plist_xml.is_some());
            assert!(dns_snapshots[0].had_state_dns);
        }
        other => panic!("unexpected journal variant: {other:?}"),
    }

    // Migrate en0 -> en1, then en1 -> cellular pdp_ip0 (F-02 + F-12)
    let en1_svc = "EN1-SERVICE-ID";
    let en1_dns: IpAddr = "10.0.1.1".parse().unwrap();
    backend.simulate_network_transition(
        Some(DefaultGatewayV4 {
            gateway: "10.0.1.1".parse().unwrap(),
            interface: "en1".to_string(),
            if_index: 9,
        }),
        None,
        Some(en1_svc.to_string()),
        Some((
            en1_svc.to_string(),
            MockServiceDnsState {
                state_dns_servers: Some(vec![en1_dns]),
                state_supplemental_match_domains: None,
                state_raw_xml: Some(encode_mock_dns_xml(&[en1_dns], None)),
                setup_dns_servers: Vec::new(),
            },
        )),
    );

    let (chg1, _) =
        tokio::time::timeout(Duration::from_secs(2), async_recv_helper_message(&client))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        chg1,
        HelperMessage::NetworkChanged {
            outbound_if_index: 9,
            outbound_if_name: "en1".to_string(),
            original_dns_servers: vec![en1_dns],
        }
    );

    // Previous Wi-Fi service must have BOTH State: (192.168.1.1) and Setup: (9.9.9.9) restored!
    let restored_wifi_dns = backend.dns_state(wifi_svc).unwrap();
    assert_eq!(restored_wifi_dns.state_dns_servers, Some(vec![dhcp_dns]));
    assert_eq!(restored_wifi_dns.setup_dns_servers, vec![manual_dns]);

    // Link-local and multicast routes must have migrated from en0 -> en1
    let en1_routes = backend.routes();
    assert!(en1_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("169.254.0.0/16".parse().unwrap()),
        target: RouteTarget::Interface("en1".to_string()),
    }));
    assert!(en1_routes.contains(&RouteSpec {
        destination: RouteDestination::Cidr("224.0.0.0/4".parse().unwrap()),
        target: RouteTarget::Interface("en1".to_string()),
    }));
    assert!(
        !en1_routes
            .iter()
            .any(|r| r.target == RouteTarget::Interface("en0".to_string()))
    );

    // Transition en1 -> cellular pdp_ip0
    let cell_svc = "CELLULAR-PDP-0";
    let cell_dns: IpAddr = "172.20.10.1".parse().unwrap();
    backend.simulate_network_transition(
        Some(DefaultGatewayV4 {
            gateway: "172.20.10.1".parse().unwrap(),
            interface: "pdp_ip0".to_string(),
            if_index: 21,
        }),
        None,
        Some(cell_svc.to_string()),
        Some((
            cell_svc.to_string(),
            MockServiceDnsState {
                state_dns_servers: Some(vec![cell_dns]),
                state_supplemental_match_domains: None,
                state_raw_xml: Some(encode_mock_dns_xml(&[cell_dns], None)),
                setup_dns_servers: Vec::new(),
            },
        )),
    );

    let (chg2, _) =
        tokio::time::timeout(Duration::from_secs(2), async_recv_helper_message(&client))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        chg2,
        HelperMessage::NetworkChanged {
            outbound_if_index: 21,
            outbound_if_name: "pdp_ip0".to_string(),
            original_dns_servers: vec![cell_dns],
        }
    );
    assert!(backend.routes().contains(&RouteSpec {
        destination: RouteDestination::Cidr("169.254.0.0/16".parse().unwrap()),
        target: RouteTarget::Interface("pdp_ip0".to_string()),
    }));

    async_send_helper_command(&client, &HelperCommand::Stop)
        .await
        .unwrap();
    let (stopped, _) = async_recv_helper_message(&client).await.unwrap();
    assert_eq!(stopped, HelperMessage::Response(HelperResponse::Stopped));
    assert!(backend.routes().is_empty());

    drop(client);
    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn wave5_surgical_rollback_preserves_preexisting_routes_and_untouched_services() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("helper.sock");
    let state_path = tmp.path().join("helper-state.json");

    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());

    // Pre-populate an OS-owned route (`10.0.0.0/8`) that returns `AlreadyExisted` on `add_route`,
    // and a third enabled service (`iPhone USB`) with a space-containing bypass token (`F-09`).
    let preexisting_rfc1918 = RouteSpec {
        destination: RouteDestination::Cidr("10.0.0.0/8".parse().unwrap()),
        target: RouteTarget::GatewayV4("192.168.1.1".parse().unwrap()),
    };
    backend.insert_preexisting_route(preexisting_rfc1918.clone());

    backend.set_network_service(
        "iPhone USB",
        vless_tray_helper::MockNetworkService {
            enabled: true,
            web: ProxyEndpointConfig::default(),
            secure_web: ProxyEndpointConfig::default(),
            socks: ProxyEndpointConfig::default(),
            bypass_domains: vec!["*.local, 169.254/16".to_string()],
        },
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::StandaloneSocket,
    };

    let sock_clone = sock_path.clone();
    let backend_clone = Arc::clone(&backend);
    let server_task = tokio::spawn(async move {
        serve_bound_socket_path(&sock_clone, backend_clone, cfg, shutdown_rx).await
    });

    let client = connect_with_retry(&sock_path).await;

    // 1. Fail StartTun on the 5th `add_route` call AFTER `10.0.0.0/8` returned `AlreadyExisted`
    //    and BEFORE `set_dns_override` ran (`F-05`).
    //    Planned routes order:
    //      1: 198.18.0.0/30 -> Added
    //      2: 203.0.113.10 -> Added
    //      3: 10.0.0.0/8 -> AlreadyExisted (MUST NOT be deleted!)
    //      4: 172.16.0.0/12 -> Added
    //      5: 192.168.0.0/16 -> Fails!
    backend.set_fail_point(Some(MockFailPoint::AddRouteNth(5)));
    async_send_helper_command(
        &client,
        &HelperCommand::StartTun {
            server_ips: vec!["203.0.113.10".parse().unwrap()],
            bypass_cidrs: vec![],
            dns_resolver: "1.1.1.1".parse().unwrap(),
        },
    )
    .await
    .unwrap();
    let (err_reply, _) = async_recv_helper_message(&client).await.unwrap();
    assert!(matches!(
        err_reply,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));

    // Pre-existing OS route `10.0.0.0/8` MUST still be intact, and DNS was never touched/restored!
    assert_eq!(backend.routes(), vec![preexisting_rfc1918.clone()]);
    let ops = backend.operations();
    assert!(
        !ops.iter()
            .any(|op| matches!(op, MockOperation::DeleteRoute(r) if r == &preexisting_rfc1918)),
        "rollback must never delete AlreadyExisted OS routes"
    );
    assert!(
        !ops.iter()
            .any(|op| matches!(op, MockOperation::RestoreDnsOverride { .. })),
        "rollback must not call RestoreDnsOverride when set_dns_override was never reached"
    );

    // 2. Fail StartSystemProxy on the 2nd enabled service (`USB 10/100/1000 LAN`):
    //    Enabled order: `Wi-Fi` (0), `USB 10/100/1000 LAN` (1), `iPhone USB` (2).
    //    Rollback must restore ONLY `Wi-Fi` (`&snapshots[..1]`), never `USB 10/100/1000 LAN` or `iPhone USB`!
    backend.set_fail_point(Some(MockFailPoint::SetServiceProxies(
        "USB 10/100/1000 LAN".to_string(),
    )));
    async_send_helper_command(
        &client,
        &HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: vec![],
        },
    )
    .await
    .unwrap();
    let (proxy_err, _) = async_recv_helper_message(&client).await.unwrap();
    assert!(matches!(
        proxy_err,
        HelperMessage::Response(HelperResponse::Error { .. })
    ));

    let restored_services: Vec<String> = backend
        .operations()
        .into_iter()
        .filter_map(|op| match op {
            MockOperation::RestoreServiceProxies { service } => Some(service),
            _ => None,
        })
        .collect();
    assert_eq!(restored_services, vec!["Wi-Fi".to_string()]);

    // 3. Clear fail point and verify `iPhone USB` with space-containing `"*.local, 169.254/16"`
    //    starts and stops cleanly (`F-09`).
    backend.set_fail_point(None);
    async_send_helper_command(
        &client,
        &HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: vec![],
        },
    )
    .await
    .unwrap();
    let (proxy_ok, _) = async_recv_helper_message(&client).await.unwrap();
    assert!(matches!(
        proxy_ok,
        HelperMessage::Response(HelperResponse::SystemProxyReady { .. })
    ));
    async_send_helper_command(&client, &HelperCommand::Stop)
        .await
        .unwrap();
    let (proxy_stop, _) = async_recv_helper_message(&client).await.unwrap();
    assert_eq!(proxy_stop, HelperMessage::Response(HelperResponse::Stopped));
    assert_eq!(
        backend.service_state("iPhone USB").unwrap().bypass_domains,
        vec!["*.local, 169.254/16".to_string()]
    );

    drop(client);
    let _ = shutdown_tx.send(true);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn wave5_idle_session_does_not_intercept_reconnect_as_secondary_connection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("launchd-reconnect.sock");
    let state_path = tmp.path().join("helper-state.json");

    let launchd_master_listener = StdUnixListener::bind(&sock_path).unwrap();
    let backend = Arc::new(MockSystemBackend::new_dual_stack_default());

    let client1 = TokioUnixStream::connect(&sock_path).await.unwrap();
    let activated_fd: OwnedFd = launchd_master_listener.try_clone().unwrap().into();
    let (_tx, rx) = watch::channel(false);
    let cfg = HelperConfig {
        state_path: state_path.clone(),
        owner_uid_policy: OwnerUidPolicy::FixedUid(current_euid()),
        lifecycle: DaemonLifecycle::LaunchdSocketActivated {
            idle_grace_timeout: Duration::from_secs(2),
        },
    };

    let helper_task = tokio::spawn(serve_activated_listener_fd(
        activated_fd,
        Arc::clone(&backend),
        cfg,
        rx,
    ));

    // Client 1 starts SystemProxy and sends Stop (transitioning state_machine back to Idle).
    async_send_helper_command(
        &client1,
        &HelperCommand::StartSystemProxy {
            listen_port: 2080,
            exceptions: vec![],
        },
    )
    .await
    .unwrap();
    let _ = async_recv_helper_message(&client1).await.unwrap();

    async_send_helper_command(&client1, &HelperCommand::Stop)
        .await
        .unwrap();
    let (stopped, _) = async_recv_helper_message(&client1).await.unwrap();
    assert_eq!(stopped, HelperMessage::Response(HelperResponse::Stopped));

    // Client 2 immediately connects BEFORE client1's socket EOF is processed (`F-08`):
    // `extra_accept` MUST NOT hijack client2 while mode == Idle!
    let client2 = TokioUnixStream::connect(&sock_path).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(client1);

    // Client 2 must be promoted to primary session and succeed on `StartSystemProxy`!
    async_send_helper_command(
        &client2,
        &HelperCommand::StartSystemProxy {
            listen_port: 2081,
            exceptions: vec![],
        },
    )
    .await
    .unwrap();
    let (ready2, _) = async_recv_helper_message(&client2).await.unwrap();
    assert!(
        matches!(
            ready2,
            HelperMessage::Response(HelperResponse::SystemProxyReady { .. })
        ),
        "expected primary SystemProxyReady on immediate reconnect, got {ready2:?}"
    );

    drop(client2);
    tokio::time::timeout(Duration::from_secs(2), helper_task)
        .await
        .expect("helper exits cleanly after client2 disconnects")
        .unwrap()
        .unwrap();
}

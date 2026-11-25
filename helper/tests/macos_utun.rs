#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::time::{Duration, Instant};
use vless_tray_helper::{MacosSystemBackend, SystemBackend};

#[test]
#[ignore = "requires permission to open the macOS utun kernel control"]
fn kernel_releases_utun_after_last_descriptor_closes() {
    let (fd, name) = MacosSystemBackend::new().create_utun().unwrap();
    assert!(name.strip_prefix("utun").unwrap().parse::<u32>().is_ok());
    let name = CString::new(name).unwrap();
    // SAFETY: name is a live NUL-terminated interface name.
    let index = || unsafe { libc::if_nametoindex(name.as_ptr()) };
    let original = index();
    assert_ne!(original, 0);

    let retained = fd.try_clone().unwrap();
    drop(fd);
    assert_eq!(index(), original);
    drop(retained);

    let deadline = Instant::now() + Duration::from_secs(5);
    while index() == original {
        assert!(
            Instant::now() < deadline,
            "kernel retained the utun interface"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "requires permission to configure the macOS utun interface"]
fn configured_utun_delivers_ipv4_udp_packet() {
    use std::net::UdpSocket;
    use std::os::unix::net::UnixDatagram;
    use vless_tray_helper::UtunConfig;

    let backend = MacosSystemBackend::new();
    let (fd, name) = backend.create_utun().unwrap();
    let config = UtunConfig::default();
    backend.configure_utun(&name, &config).unwrap();
    let tunnel = UnixDatagram::from(fd);
    let sender = UdpSocket::bind((config.ipv4_addr, 0)).unwrap();
    let payload = b"macOS helper packet check";
    let port = 19444_u16;
    sender.send_to(payload, (config.ipv4_peer, port)).unwrap();

    // The kernel can also emit IPv6 control traffic as the interface comes up.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0; 2048];
    loop {
        tunnel
            .set_read_timeout(Some(deadline - Instant::now()))
            .unwrap();
        let len = tunnel.recv(&mut buf).unwrap();
        let frame = &buf[..len];
        if frame.len() < 24 || frame[..4] != (libc::AF_INET as u32).to_be_bytes() {
            continue;
        }
        let ip = &frame[4..];
        if ip[9] != 17 || ip[16..20] != config.ipv4_peer.octets() {
            continue;
        }
        assert_eq!(ip[0] >> 4, 4);
        let udp = &ip[usize::from(ip[0] & 0x0f) * 4..];
        if udp[2..4] == port.to_be_bytes() {
            assert_eq!(ip[12..16], config.ipv4_addr.octets());
            assert_eq!(&udp[8..], payload);
            break;
        }
    }
}

#[test]
#[ignore = "requires permission to configure macOS routes and DNS"]
fn helper_binary_recovers_native_route_and_dns() {
    use std::process::Command;
    use system_configuration::core_foundation::propertylist::{
        create_data, kCFPropertyListXMLFormat_v1_0,
    };
    use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
    use vless_tray_helper::{
        DnsSnapshot, HelperJournal, JOURNAL_SCHEMA_VERSION, RouteAddResult, RouteDestination,
        RouteSpec, RouteTarget, UtunConfig, save_journal,
    };

    struct DnsCleanup<'a> {
        store: &'a SCDynamicStore,
        keys: [&'a str; 2],
    }

    impl Drop for DnsCleanup<'_> {
        fn drop(&mut self) {
            for key in self.keys {
                self.store.remove(key);
            }
        }
    }

    let backend = MacosSystemBackend::new();
    let (_fd, name) = backend.create_utun().unwrap();
    backend
        .configure_utun(&name, &UtunConfig::default())
        .unwrap();

    let destination = "192.0.2.211";
    let route_interface = || {
        let output = Command::new("/sbin/route")
            .args(["-n", "get", destination])
            .output()
            .unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
            .map(str::to_owned)
    };
    let original_interface = route_interface();
    let route = RouteSpec {
        destination: RouteDestination::Host(destination.parse().unwrap()),
        target: RouteTarget::Interface(name.clone()),
    };
    // Use a service ID dedicated to this fixture so recovery leaves live DNS alone.
    let service_id = "757E8D55-7E69-4391-A470-3806000953C2";
    let store = SCDynamicStoreBuilder::new("io.vless-tray.recovery-test")
        .build()
        .unwrap();
    let state_key = format!("State:/Network/Service/{service_id}/DNS");
    let setup_key = format!("Setup:/Network/Service/{service_id}/DNS");
    assert!(store.get(state_key.as_str()).is_none());
    assert!(store.get(setup_key.as_str()).is_none());
    let _cleanup = DnsCleanup {
        store: &store,
        keys: [&state_key, &setup_key],
    };
    let original_resolver = "192.0.2.54".parse().unwrap();
    let replacement_resolver = "192.0.2.53".parse().unwrap();
    backend
        .set_dns_override(service_id, original_resolver)
        .unwrap();
    let original_dns = store.get(state_key.as_str()).unwrap();
    assert!(store.remove(setup_key.as_str()));
    let xml = create_data(original_dns.as_CFTypeRef(), kCFPropertyListXMLFormat_v1_0).unwrap();

    let state = tempfile::tempdir().unwrap();
    let journal_path = state.path().join("helper-state.json");
    save_journal(
        &journal_path,
        &HelperJournal::Tun {
            version: JOURNAL_SCHEMA_VERSION,
            utun_name: name.clone(),
            v4_gateway: None,
            v6_gateway: None,
            dns_snapshots: vec![DnsSnapshot {
                service_id: service_id.into(),
                had_state_dns: true,
                state_dns_plist_xml: Some(String::from_utf8(xml.bytes().to_vec()).unwrap()),
                had_setup_dns: false,
                setup_dns_plist_xml: None,
                original_dns_servers: vec![original_resolver],
            }],
            dns_resolver: replacement_resolver,
            server_ips: vec!["192.0.2.1".parse().unwrap()],
            bypass_cidrs: vec![],
            routes: vec![route.clone()],
        },
    )
    .unwrap();
    assert_eq!(backend.add_route(&route).unwrap(), RouteAddResult::Added);
    assert_eq!(route_interface().as_deref(), Some(name.as_str()));

    backend
        .set_dns_override(service_id, replacement_resolver)
        .unwrap();
    let overridden_dns = store.get(state_key.as_str()).unwrap();
    assert_ne!(overridden_dns, original_dns);
    assert_eq!(store.get(setup_key.as_str()), Some(overridden_dns));

    let recover = || {
        let result = Command::new(env!("CARGO_BIN_EXE_vless-tray-helper"))
            .arg("--recover-only")
            .arg("--state-path")
            .arg(&journal_path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    recover();
    assert_eq!(route_interface(), original_interface);
    assert_eq!(store.get(state_key.as_str()), Some(original_dns));
    assert!(store.get(setup_key.as_str()).is_none());
    assert!(!journal_path.exists());
    recover();
}

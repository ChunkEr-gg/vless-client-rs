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
#[ignore = "requires permission to install a macOS host route"]
fn journal_recovery_removes_native_host_route() {
    use std::process::Command;
    use vless_tray_helper::{
        HelperJournal, JOURNAL_SCHEMA_VERSION, RouteAddResult, RouteDestination, RouteSpec,
        RouteTarget, UtunConfig, recover_if_present, save_journal,
    };

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
    let state = tempfile::tempdir().unwrap();
    let journal_path = state.path().join("helper-state.json");
    save_journal(
        &journal_path,
        &HelperJournal::Tun {
            version: JOURNAL_SCHEMA_VERSION,
            utun_name: name.clone(),
            v4_gateway: None,
            v6_gateway: None,
            dns_snapshots: vec![],
            dns_resolver: "192.0.2.53".parse().unwrap(),
            server_ips: vec!["192.0.2.1".parse().unwrap()],
            bypass_cidrs: vec![],
            routes: vec![route.clone()],
        },
    )
    .unwrap();
    assert_eq!(backend.add_route(&route).unwrap(), RouteAddResult::Added);
    assert_eq!(route_interface().as_deref(), Some(name.as_str()));

    assert!(recover_if_present(&backend, &journal_path).unwrap());
    assert_eq!(route_interface(), original_interface);
    assert!(!journal_path.exists());
    assert!(!recover_if_present(&backend, &journal_path).unwrap());
}

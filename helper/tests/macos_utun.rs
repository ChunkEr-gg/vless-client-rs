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

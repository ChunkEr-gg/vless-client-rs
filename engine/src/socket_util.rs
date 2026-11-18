use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
use std::mem::ManuallyDrop;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_family = "unix")]
use std::path::Path;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub fn new_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = new_outbound_socket2_udp_socket(
        is_ipv6,
        bind_interface,
        Some(get_unspecified_socket_addr(is_ipv6)),
    )?;

    into_tokio_udp_socket(socket)
}

pub fn new_udp_socket_for_peer(
    peer: SocketAddr,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let is_ipv6 = peer.is_ipv6();
    if peer.ip().is_loopback() {
        let socket = new_socket2_udp_socket_inner(
            is_ipv6,
            None,
            Some(get_unspecified_socket_addr(is_ipv6)),
            false,
            None,
            false,
        )?;
        return into_tokio_udp_socket(socket);
    }
    new_udp_socket(is_ipv6, bind_interface)
}

pub fn new_hostname_udp_socket(
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let (socket, is_ipv6) = prefer_ipv6_socket(|ipv6| {
        new_socket2_udp_socket_inner(
            ipv6,
            None,
            Some(get_unspecified_socket_addr(ipv6)),
            false,
            None,
            false,
        )
        .map(|sock| (sock, ipv6))
    })?;
    crate::socket_policy::apply(
        socket2::SockRef::from(&socket),
        is_ipv6,
        bind_interface.as_deref(),
    )?;
    bind_socket_interface(
        socket2::SockRef::from(&socket),
        is_ipv6,
        bind_interface.as_deref(),
    )?;
    into_tokio_udp_socket(socket)
}

fn prefer_ipv6_socket<T>(mut create: impl FnMut(bool) -> std::io::Result<T>) -> std::io::Result<T> {
    match create(true) {
        Err(error) if ipv6_unavailable(&error) => create(false),
        result => result,
    }
}

pub(crate) fn ipv6_unavailable(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    let codes = [
        libc::EAFNOSUPPORT,
        libc::EPROTONOSUPPORT,
        libc::ENOPROTOOPT,
        libc::EADDRNOTAVAIL,
    ];
    #[cfg(windows)]
    let codes = [10042, 10043, 10047, 10049];
    error
        .raw_os_error()
        .is_some_and(|code| codes.contains(&code))
}

fn bind_socket_interface(
    socket: socket2::SockRef<'_>,
    is_ipv6: bool,
    interface: Option<&str>,
) -> std::io::Result<()> {
    let Some(interface) = interface else {
        return Ok(());
    };

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        let _ = is_ipv6;
        socket.bind_device(Some(interface.as_bytes()))
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let idx = crate::socket_policy::interface_name_to_index(interface)?;
        crate::socket_policy::bind_socket_to_index(socket, is_ipv6, idx)
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let _ = (socket, is_ipv6, interface);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "binding sockets to an interface is unsupported on this platform",
        ))
    }
}

pub fn new_outbound_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
) -> std::io::Result<Socket> {
    let apply_outbound_policy = bind_address.is_none_or(|addr| !addr.ip().is_loopback());
    new_socket2_udp_socket_inner(
        is_ipv6,
        bind_interface,
        bind_address,
        false,
        None,
        apply_outbound_policy,
    )
}

fn get_unspecified_socket_addr(is_ipv6: bool) -> SocketAddr {
    if !is_ipv6 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    } else {
        "[::]:0".parse().unwrap()
    }
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    new_socket2_udp_socket_with_buffer_size(is_ipv6, bind_interface, bind_address, reuse_port, None)
}

pub fn new_socket2_udp_socket_with_buffer_size(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
) -> std::io::Result<socket2::Socket> {
    // Local listener UDP sockets (e.g. SOCKS5 UDP ASSOCIATE on 127.0.0.1) pass `bind_address: Some`
    // with a non-unspecified local IP; only apply outbound physical interface policy when the
    // socket is not bound to a loopback address.
    let apply_outbound_policy = bind_address.is_none_or(|addr| !addr.ip().is_loopback());
    new_socket2_udp_socket_inner(
        is_ipv6,
        bind_interface,
        bind_address,
        reuse_port,
        buffer_size,
        apply_outbound_policy,
    )
}

fn new_socket2_udp_socket_inner(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
    apply_outbound_policy: bool,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let is_loopback_bind = bind_address.is_some_and(|addr| addr.ip().is_loopback());
    if apply_outbound_policy && !is_loopback_bind {
        crate::socket_policy::apply(
            socket2::SockRef::from(&socket),
            is_ipv6,
            bind_interface.as_deref(),
        )?;
    }

    if is_ipv6 {
        socket.set_only_v6(false)?;
    }

    socket.set_nonblocking(true)?;

    if let Some(size) = buffer_size {
        set_udp_socket_buffers(socket2::SockRef::from(&socket), size);
    }

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP port reuse is unsupported on this platform",
        ));
    }

    bind_socket_interface(
        socket2::SockRef::from(&socket),
        is_ipv6,
        bind_interface.as_deref(),
    )?;

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

pub(crate) fn set_udp_socket_buffers(socket: socket2::SockRef<'_>, size: usize) {
    static RECEIVE_WARNING: AtomicBool = AtomicBool::new(false);
    static SEND_WARNING: AtomicBool = AtomicBool::new(false);

    let receive_result = socket.set_recv_buffer_size(size);
    let receive_actual = socket.recv_buffer_size();
    let send_result = socket.set_send_buffer_size(size);
    let send_actual = socket.send_buffer_size();

    for (direction, result, actual, warned) in [
        ("receive", receive_result, receive_actual, &RECEIVE_WARNING),
        ("send", send_result, send_actual, &SEND_WARNING),
    ] {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let actual = actual.map(|bytes| bytes / 2);
        if result.is_ok() && actual.as_ref().is_ok_and(|bytes| *bytes >= size) {
            continue;
        }
        if !warned.swap(true, Ordering::Relaxed) {
            log::warn!(
                "UDP {direction} buffer request of {size} bytes was not satisfied \
                 (set: {result:?}, effective bytes: {actual:?}); \
                 continuing with OS buffers"
            );
        }
    }
}

pub(crate) fn into_tokio_udp_socket(
    socket: socket2::Socket,
) -> std::io::Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    {
        let raw_fd = socket.into_raw_fd();
        // SAFETY: `into_raw_fd()` transfers ownership of a valid open UDP socket descriptor.
        let std_udp_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
    #[cfg(windows)]
    {
        let std_udp_socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
}

pub fn new_tcp_socket(
    bind_interface: Option<String>,
    is_ipv6: bool,
) -> std::io::Result<tokio::net::TcpSocket> {
    let tcp_socket = if is_ipv6 {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    crate::socket_policy::apply(
        socket2::SockRef::from(&tcp_socket),
        is_ipv6,
        bind_interface.as_deref(),
    )?;
    bind_socket_interface(
        socket2::SockRef::from(&tcp_socket),
        is_ipv6,
        bind_interface.as_deref(),
    )?;

    Ok(tcp_socket)
}

pub fn new_tcp_socket_for_peer(
    bind_interface: Option<String>,
    peer: SocketAddr,
) -> std::io::Result<tokio::net::TcpSocket> {
    let is_ipv6 = peer.is_ipv6();
    if peer.ip().is_loopback() {
        return if is_ipv6 {
            tokio::net::TcpSocket::new_v6()
        } else {
            tokio::net::TcpSocket::new_v4()
        };
    }
    new_tcp_socket(bind_interface, is_ipv6)
}

pub fn set_tcp_keepalive(
    tcp_stream: &tokio::net::TcpStream,
    idle_time: std::time::Duration,
    send_interval: std::time::Duration,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let raw_fd = tcp_stream.as_raw_fd();
        // SAFETY: `raw_fd` is borrowed from `tcp_stream` for the duration of this block and wrapped
        // in `ManuallyDrop` so `Socket`'s destructor never closes `tcp_stream`'s descriptor.
        let socket2_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(raw_fd) });
        if idle_time.is_zero() && send_interval.is_zero() {
            socket2_socket.set_keepalive(false)?;
        } else {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(idle_time)
                .with_interval(send_interval);
            socket2_socket.set_keepalive(true)?;
            socket2_socket.set_tcp_keepalive(&keepalive)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (tcp_stream, idle_time, send_interval);
        Ok(())
    }
}

pub fn new_tcp_listener(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::TcpListener> {
    let is_ipv6 = bind_address.is_ipv6();
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nonblocking(true)?;
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;

    bind_socket_interface(
        socket2::SockRef::from(&socket),
        is_ipv6,
        bind_interface.as_deref(),
    )?;

    socket.bind(&SockAddr::from(bind_address))?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

#[cfg(target_family = "unix")]
pub fn new_unix_listener<P: AsRef<Path>>(
    path: P,
    backlog: u32,
) -> std::io::Result<tokio::net::UnixListener> {
    let path = path.as_ref();

    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;

    let addr = SockAddr::unix(path)?;
    socket.bind(&addr)?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::os::unix::net::UnixListener = socket.into();
    tokio::net::UnixListener::from_std(std_listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_buffer_requests_match_os_supported_sizes() {
        for size in [65536, 8 << 20] {
            let reference = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            let _ = reference.set_recv_buffer_size(size);
            let _ = reference.set_send_buffer_size(size);
            let socket = new_socket2_udp_socket_with_buffer_size(
                false,
                None,
                Some("0.0.0.0:0".parse().unwrap()),
                false,
                Some(size),
            )
            .unwrap();
            assert_eq!(
                socket.recv_buffer_size().unwrap(),
                reference.recv_buffer_size().unwrap()
            );
            assert_eq!(
                socket.send_buffer_size().unwrap(),
                reference.send_buffer_size().unwrap()
            );
        }
    }

    #[test]
    fn hostname_socket_fallback_is_limited_to_family_errors() {
        #[cfg(unix)]
        let unavailable = libc::EAFNOSUPPORT;
        #[cfg(windows)]
        let unavailable = 10047;
        let mut attempts = Vec::new();
        let socket = prefer_ipv6_socket(|ipv6| {
            attempts.push(ipv6);
            if ipv6 {
                Err(std::io::Error::from_raw_os_error(unavailable))
            } else {
                new_socket2_udp_socket(false, None, Some("0.0.0.0:0".parse().unwrap()), false)
            }
        })
        .unwrap();
        assert_eq!(attempts, [true, false]);
        assert!(socket.local_addr().unwrap().as_socket().unwrap().is_ipv4());

        attempts.clear();
        let error = prefer_ipv6_socket::<Socket>(|ipv6| {
            attempts.push(ipv6);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied",
            ))
        })
        .unwrap_err();
        assert_eq!(attempts, [true]);
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn hostname_socket_prefers_dual_stack_and_enforces_interface_binding() {
        let ipv6_available =
            match new_socket2_udp_socket(true, None, Some("[::]:0".parse().unwrap()), false) {
                Ok(_) => true,
                Err(error) if ipv6_unavailable(&error) => false,
                Err(error) => panic!("IPv6 socket probe failed: {error}"),
            };
        let socket = new_hostname_udp_socket(None).unwrap();
        assert_eq!(socket.local_addr().unwrap().is_ipv6(), ipv6_available);
        assert!(new_hostname_udp_socket(Some("vless-missing-if0".into())).is_err());
    }
}

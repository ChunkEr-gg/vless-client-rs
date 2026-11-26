//! Platform socket policy & macOS `IP_BOUND_IF` / `IPV6_BOUND_IF` interface binding (`PLAN.md` §5.2, §5.5).

#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::ffi::CString;
use std::io;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::resolver::Resolver;

/// Live outbound physical interface index (`0` = unbound, `> 0` = `NonZeroU32` interface index).
///
/// Updated when TUN mode starts, when `PF_ROUTE` reports a physical interface transition
/// (`HelperMessage::NetworkChanged`), and cleared (`0`) when `EngineHandle` stops.
static OUTBOUND_IF_INDEX: AtomicU32 = AtomicU32::new(0);

/// Sets or clears the live outbound physical interface index (`0` or `None` clears the policy).
pub fn set_outbound_interface_index(index: Option<u32>) {
    OUTBOUND_IF_INDEX.store(index.unwrap_or(0), Ordering::Release);
}

/// Returns the currently configured non-zero outbound physical interface index, if any.
pub fn outbound_interface_index() -> Option<NonZeroU32> {
    NonZeroU32::new(OUTBOUND_IF_INDEX.load(Ordering::Acquire))
}

#[allow(dead_code)]
pub(crate) fn bootstrap() -> Option<Arc<dyn Resolver>> {
    None
}

#[allow(dead_code)]
pub(crate) fn bootstrap_endpoints() -> Option<Vec<std::net::SocketAddr>> {
    None
}

pub(crate) fn apply(
    socket: socket2::SockRef<'_>,
    is_ipv6: bool,
    interface: Option<&str>,
) -> io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if interface.is_none()
            && let Some(nz) = outbound_interface_index()
        {
            bind_socket_to_index(socket, is_ipv6, nz)?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = (socket, is_ipv6, interface);
        Ok(())
    }
}

pub(crate) fn check_native_hostname() -> io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn interface_name_to_index(interface: &str) -> io::Result<NonZeroU32> {
    let c_name = CString::new(interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {interface:?} contains interior NUL byte"),
        )
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated C string; `if_nametoindex` only reads it.
    let raw_idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    NonZeroU32::new(raw_idx).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("network interface {interface:?} not found"),
        )
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn bind_socket_to_index(
    socket: socket2::SockRef<'_>,
    is_ipv6: bool,
    index: NonZeroU32,
) -> io::Result<()> {
    if is_ipv6 {
        socket.bind_device_by_index_v6(Some(index))
    } else {
        socket.bind_device_by_index_v4(Some(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_interface_index_atomic_lifecycle() {
        set_outbound_interface_index(None);
        assert_eq!(outbound_interface_index(), None);

        set_outbound_interface_index(Some(0));
        assert_eq!(outbound_interface_index(), None);

        set_outbound_interface_index(Some(1));
        assert_eq!(outbound_interface_index(), NonZeroU32::new(1));

        set_outbound_interface_index(None);
        assert_eq!(outbound_interface_index(), None);
    }
}

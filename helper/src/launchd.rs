//! `launchd` socket activation (`launch_activate_socket`) and Unix listener descriptor helpers
//! (`PLAN.md` §4 & `dist/io.vless-tray.helper.plist`).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener as StdUnixListener;

use tokio::net::UnixListener as TokioUnixListener;

/// Name of the socket dictionary key in `dist/io.vless-tray.helper.plist`.
pub const LAUNCHD_SOCKET_NAME: &str = "Listeners";

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        cnt: *mut libc::size_t,
    ) -> libc::c_int;
}

/// Result of querying `launchd` for pre-bound socket-activation file descriptors.
#[derive(Debug)]
pub enum LaunchdActivation {
    /// Process was launched by `launchd` with one or more activated listening socket descriptors.
    Activated(Vec<OwnedFd>),
    /// Process was not launched by `launchd` with the `"Listeners"` socket (`ESRCH` or `ENOENT`,
    /// or non-macOS host).
    NotManagedByLaunchd,
}

/// Claims the `"Listeners"` Unix domain socket descriptor(s) from `launchd` on macOS.
///
/// Frees the `fds` buffer allocated by `libSystem` immediately after wrapping all descriptors in
/// [`OwnedFd`], and configures both `FD_CLOEXEC` and `O_NONBLOCK` on every returned descriptor.
pub fn claim_launchd_sockets() -> io::Result<LaunchdActivation> {
    #[cfg(target_os = "macos")]
    {
        let mut fds_ptr: *mut libc::c_int = std::ptr::null_mut();
        let mut cnt: libc::size_t = 0;

        // SAFETY: `c"Listeners"` is a static NUL-terminated C string matching `<key>Listeners</key>`
        // in `io.vless-tray.helper.plist`, and `fds_ptr` / `cnt` are valid stack out-pointers.
        // `launch_activate_socket` returns 0 on success or a positive errno value on failure.
        let rc = unsafe {
            launch_activate_socket(c"Listeners".as_ptr(), &raw mut fds_ptr, &raw mut cnt)
        };

        if rc == libc::ESRCH || rc == libc::ENOENT {
            return Ok(LaunchdActivation::NotManagedByLaunchd);
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }

        let mut owned_fds: Vec<OwnedFd> = Vec::with_capacity(cnt);
        if !fds_ptr.is_null() {
            // Wrap every returned descriptor in `OwnedFd` BEFORE freeing `fds_ptr` or running
            // fallible `fcntl` calls so neither heap memory nor file descriptors can ever leak.
            // SAFETY: On `rc == 0` with non-null `fds_ptr`, `libSystem` allocated an array of
            // `cnt` open `c_int` descriptors via `malloc`, transferring ownership of both the fds
            // and the `fds_ptr` buffer to the caller.
            unsafe {
                let raw_slice = std::slice::from_raw_parts(fds_ptr, cnt);
                for &raw_fd in raw_slice {
                    if raw_fd >= 0 {
                        owned_fds.push(std::os::fd::FromRawFd::from_raw_fd(raw_fd));
                    }
                }
                libc::free(fds_ptr.cast::<libc::c_void>());
            }
        }

        if owned_fds.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "launch_activate_socket(Listeners) succeeded with 0 descriptors",
            ));
        }

        for fd in &owned_fds {
            set_cloexec(fd.as_raw_fd())?;
            set_nonblocking(fd.as_raw_fd())?;
        }

        Ok(LaunchdActivation::Activated(owned_fds))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = LAUNCHD_SOCKET_NAME;
        Ok(LaunchdActivation::NotManagedByLaunchd)
    }
}

/// Converts a pre-bound Unix stream listener [`OwnedFd`] (from `launchd` or a test harness) into a
/// non-blocking Tokio [`TokioUnixListener`] with `FD_CLOEXEC` and `O_NONBLOCK` set.
pub fn tokio_listener_from_owned_fd(fd: OwnedFd) -> io::Result<TokioUnixListener> {
    set_cloexec(fd.as_raw_fd())?;
    set_nonblocking(fd.as_raw_fd())?;
    let std_listener = StdUnixListener::from(fd);
    TokioUnixListener::from_std(std_listener)
}

/// Sets `FD_CLOEXEC` on an open file descriptor.
pub fn set_cloexec(raw_fd: RawFd) -> io::Result<()> {
    // SAFETY: `raw_fd` is a valid open file descriptor owned or borrowed by the caller.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Preserving existing descriptor flags while setting `FD_CLOEXEC`.
    let rc = unsafe { libc::fcntl(raw_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets `O_NONBLOCK` on an open file descriptor.
pub fn set_nonblocking(raw_fd: RawFd) -> io::Result<()> {
    // SAFETY: `raw_fd` is a valid open file descriptor owned or borrowed by the caller.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Preserving existing status flags while setting `O_NONBLOCK`.
    let rc = unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

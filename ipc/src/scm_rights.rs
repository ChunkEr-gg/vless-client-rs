//! Length-prefixed JSON framing, `SCM_RIGHTS` file-descriptor passing, and peer UID verification
//! over Unix domain stream sockets (`std::os::unix::net::UnixStream` and `tokio::net::UnixStream`).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::Interest;
use tokio::net::UnixStream as TokioUnixStream;

use crate::helper_ipc::{HelperCommand, HelperMessage, MAX_HELPER_FRAME_BYTES};

/// Maximum number of file descriptors budgeted in the receive `cmsghdr` buffer so we can detect
/// and close any unexpected extra descriptors without kernel truncation.
const MAX_CMSG_FDS: usize = 4;

/// 64-byte control buffer aligned to `libc::cmsghdr` requirements on both 64-bit Linux and macOS.
#[repr(C, align(8))]
struct AlignedControlBuf([u8; 64]);

const _: () = {
    assert!(std::mem::align_of::<AlignedControlBuf>() >= std::mem::align_of::<libc::cmsghdr>());
};

/// Returns the effective user ID (`uid_t` as `u32`) of the peer process connected to `stream`.
///
/// Uses `libc::getpeereid` on macOS/BSD and `SO_PEERCRED` on Linux (`PLAN.md` §4).
pub fn peer_uid(stream: &StdUnixStream) -> io::Result<u32> {
    peer_uid_from_fd(stream.as_fd())
}

/// Returns the effective user ID (`uid_t` as `u32`) of the peer process connected to a Tokio
/// [`TokioUnixStream`].
pub fn tokio_peer_uid(stream: &TokioUnixStream) -> io::Result<u32> {
    peer_uid_from_fd(stream.as_fd())
}

/// Returns the effective user ID (`uid_t` as `u32`) of the peer on a borrowed Unix stream socket.
pub fn peer_uid_from_fd(fd: BorrowedFd<'_>) -> io::Result<u32> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `fd.as_raw_fd()` is a live borrowed socket descriptor for the duration of this
        // call, and `uid` / `gid` are valid aligned stack variables passed as out-pointers.
        let rc = unsafe { libc::getpeereid(fd.as_raw_fd(), &raw mut uid, &raw mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }

    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `fd.as_raw_fd()` is a live borrowed socket descriptor, `cred` is properly
        // initialized and aligned for `libc::ucred`, and `len` holds its exact byte size.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if (len as usize) != std::mem::size_of::<libc::ucred>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected SO_PEERCRED structure size",
            ));
        }
        Ok(cred.uid)
    }
}

/// Encodes `msg` as a `u32` big-endian length-prefixed JSON frame (`<= 64 KiB`) and sends it over
/// blocking `stream`, optionally attaching `fd` via `SCM_RIGHTS`.
pub fn send_frame_with_fd<T: Serialize>(
    stream: &StdUnixStream,
    msg: &T,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let frame = encode_frame(msg)?;
    let raw_sock = stream.as_raw_fd();
    configure_nosigpipe(raw_sock);

    let first_written = sendmsg_retry_eintr(raw_sock, &frame, fd)?;
    if first_written == 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "sendmsg wrote 0 bytes on unix socket",
        ));
    }

    let mut offset = first_written;
    while offset < frame.len() {
        let n = send_retry_eintr(raw_sock, &frame[offset..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "send wrote 0 bytes on unix socket",
            ));
        }
        offset += n;
    }

    Ok(())
}

/// Receives a length-prefixed JSON frame and optional `SCM_RIGHTS` file descriptor from blocking
/// `stream`. Returns `Ok(None)` on clean EOF at a frame boundary.
pub fn try_recv_frame_with_fd<T: DeserializeOwned>(
    stream: &StdUnixStream,
) -> io::Result<Option<(T, Option<OwnedFd>)>> {
    let raw_sock = stream.as_raw_fd();
    let mut hdr = [0u8; 4];

    let (first_read, maybe_fd) = recvmsg_retry_eintr(raw_sock, &mut hdr)?;
    if first_read == 0 {
        return Ok(None);
    }

    let mut hdr_offset = first_read;
    while hdr_offset < 4 {
        let n = recv_retry_eintr(raw_sock, &mut hdr[hdr_offset..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated 4-byte frame header on unix socket",
            ));
        }
        hdr_offset += n;
    }

    let payload_len = parse_and_validate_frame_len(hdr)?;
    let mut payload = vec![0u8; payload_len];
    let mut offset = 0;
    while offset < payload_len {
        let n = recv_retry_eintr(raw_sock, &mut payload[offset..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame payload on unix socket",
            ));
        }
        offset += n;
    }

    let decoded = decode_frame_payload(&payload)?;
    Ok(Some((decoded, maybe_fd)))
}

/// Receives a length-prefixed JSON frame and optional `SCM_RIGHTS` file descriptor from blocking
/// `stream`, returning `ErrorKind::UnexpectedEof` if the peer closed the connection.
pub fn recv_frame_with_fd<T: DeserializeOwned>(
    stream: &StdUnixStream,
) -> io::Result<(T, Option<OwnedFd>)> {
    try_recv_frame_with_fd(stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed unix socket before sending frame",
        )
    })
}

/// Sends a validated [`HelperCommand`] over blocking `stream`.
pub fn send_helper_command(stream: &StdUnixStream, cmd: &HelperCommand) -> io::Result<()> {
    cmd.validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    send_frame_with_fd(stream, cmd, None)
}

/// Receives and validates a [`HelperCommand`] over blocking `stream`, returning `Ok(None)` on
/// clean session EOF. Rejects any unexpected `SCM_RIGHTS` descriptor.
pub fn try_recv_helper_command(stream: &StdUnixStream) -> io::Result<Option<HelperCommand>> {
    let Some((cmd, maybe_fd)) = try_recv_frame_with_fd::<HelperCommand>(stream)? else {
        return Ok(None);
    };
    if maybe_fd.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SCM_RIGHTS file descriptor attached to HelperCommand",
        ));
    }
    cmd.validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(Some(cmd))
}

/// Receives and validates a [`HelperCommand`] over blocking `stream`.
pub fn recv_helper_command(stream: &StdUnixStream) -> io::Result<HelperCommand> {
    try_recv_helper_command(stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed unix socket before sending HelperCommand",
        )
    })
}

/// Sends a [`HelperMessage`] and optional `SCM_RIGHTS` descriptor over blocking `stream`.
pub fn send_helper_message(
    stream: &StdUnixStream,
    msg: &HelperMessage,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    send_frame_with_fd(stream, msg, fd)
}

/// Receives a [`HelperMessage`] and optional `SCM_RIGHTS` descriptor over blocking `stream`.
pub fn recv_helper_message(stream: &StdUnixStream) -> io::Result<(HelperMessage, Option<OwnedFd>)> {
    recv_frame_with_fd(stream)
}

/// Asynchronously sends a length-prefixed JSON frame and optional `SCM_RIGHTS` file descriptor
/// over a Tokio [`TokioUnixStream`].
pub async fn async_send_frame_with_fd<T: Serialize>(
    stream: &TokioUnixStream,
    msg: &T,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let frame = encode_frame(msg)?;
    let raw_sock = stream.as_raw_fd();
    configure_nosigpipe(raw_sock);

    let first_written = loop {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || {
            sendmsg_retry_eintr(raw_sock, &frame, fd)
        }) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "async sendmsg wrote 0 bytes on unix socket",
                ));
            }
            Ok(n) => break n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    };

    let mut offset = first_written;
    while offset < frame.len() {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || {
            send_retry_eintr(raw_sock, &frame[offset..])
        }) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "async send wrote 0 bytes on unix socket",
                ));
            }
            Ok(n) => offset += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

/// Asynchronously receives a length-prefixed JSON frame and optional `SCM_RIGHTS` file descriptor
/// from a Tokio [`TokioUnixStream`]. Returns `Ok(None)` on clean EOF at a frame boundary.
pub async fn async_try_recv_frame_with_fd<T: DeserializeOwned>(
    stream: &TokioUnixStream,
) -> io::Result<Option<(T, Option<OwnedFd>)>> {
    let raw_sock = stream.as_raw_fd();
    let mut hdr = [0u8; 4];

    let (first_read, maybe_fd) = loop {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || {
            recvmsg_retry_eintr(raw_sock, &mut hdr)
        }) {
            Ok(res) => break res,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    };

    if first_read == 0 {
        return Ok(None);
    }

    let mut hdr_offset = first_read;
    while hdr_offset < 4 {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || {
            recv_retry_eintr(raw_sock, &mut hdr[hdr_offset..])
        }) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated 4-byte frame header on unix socket",
                ));
            }
            Ok(n) => hdr_offset += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }

    let payload_len = parse_and_validate_frame_len(hdr)?;
    let mut payload = vec![0u8; payload_len];
    let mut offset = 0;
    while offset < payload_len {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || {
            recv_retry_eintr(raw_sock, &mut payload[offset..])
        }) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame payload on unix socket",
                ));
            }
            Ok(n) => offset += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }

    let decoded = decode_frame_payload(&payload)?;
    Ok(Some((decoded, maybe_fd)))
}

/// Asynchronously receives a length-prefixed JSON frame and optional `SCM_RIGHTS` file descriptor
/// from a Tokio [`TokioUnixStream`].
pub async fn async_recv_frame_with_fd<T: DeserializeOwned>(
    stream: &TokioUnixStream,
) -> io::Result<(T, Option<OwnedFd>)> {
    async_try_recv_frame_with_fd(stream).await?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed unix socket before sending frame",
        )
    })
}

/// Asynchronously sends a validated [`HelperCommand`] over a Tokio [`TokioUnixStream`].
pub async fn async_send_helper_command(
    stream: &TokioUnixStream,
    cmd: &HelperCommand,
) -> io::Result<()> {
    cmd.validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    async_send_frame_with_fd(stream, cmd, None).await
}

/// Asynchronously receives and validates a [`HelperCommand`], returning `Ok(None)` on clean EOF.
pub async fn async_try_recv_helper_command(
    stream: &TokioUnixStream,
) -> io::Result<Option<HelperCommand>> {
    let Some((cmd, maybe_fd)) = async_try_recv_frame_with_fd::<HelperCommand>(stream).await? else {
        return Ok(None);
    };
    if maybe_fd.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SCM_RIGHTS file descriptor attached to HelperCommand",
        ));
    }
    cmd.validate()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(Some(cmd))
}

/// Asynchronously sends a [`HelperMessage`] and optional `SCM_RIGHTS` descriptor.
pub async fn async_send_helper_message(
    stream: &TokioUnixStream,
    msg: &HelperMessage,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    async_send_frame_with_fd(stream, msg, fd).await
}

/// Asynchronously receives a [`HelperMessage`] and optional `SCM_RIGHTS` descriptor.
pub async fn async_recv_helper_message(
    stream: &TokioUnixStream,
) -> io::Result<(HelperMessage, Option<OwnedFd>)> {
    async_recv_frame_with_fd(stream).await
}

fn encode_frame<T: Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let json =
        serde_json::to_vec(msg).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    if json.is_empty() || json.len() > MAX_HELPER_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "helper IPC JSON payload size {} is outside 1..={MAX_HELPER_FRAME_BYTES}",
                json.len()
            ),
        ));
    }
    let len_u32 = u32::try_from(json.len()).expect("MAX_HELPER_FRAME_BYTES fits in u32");
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len_u32.to_be_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

fn parse_and_validate_frame_len(hdr: [u8; 4]) -> io::Result<usize> {
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > MAX_HELPER_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("helper IPC frame length {len} is outside 1..={MAX_HELPER_FRAME_BYTES}"),
        ));
    }
    Ok(len)
}

fn decode_frame_payload<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    serde_json::from_slice(payload).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn configure_nosigpipe(raw_sock: RawFd) {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let enable: libc::c_int = 1;
        // SAFETY: `raw_sock` is a borrowed open socket descriptor and `enable` is a valid `c_int`.
        let _ = unsafe {
            libc::setsockopt(
                raw_sock,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&raw const enable).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    {
        let _ = raw_sock;
    }
}

fn send_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::MSG_NOSIGNAL
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

fn recvmsg_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::MSG_CMSG_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn set_msg_controllen(msg: &mut libc::msghdr, bytes: libc::c_uint) {
    msg.msg_controllen = bytes as usize;
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn set_msg_controllen(msg: &mut libc::msghdr, bytes: libc::c_uint) {
    msg.msg_controllen = bytes;
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn set_cmsg_len(cmsg: &mut libc::cmsghdr, bytes: libc::c_uint) {
    cmsg.cmsg_len = bytes as usize;
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn set_cmsg_len(cmsg: &mut libc::cmsghdr, bytes: libc::c_uint) {
    cmsg.cmsg_len = bytes;
}

fn sendmsg_retry_eintr(
    raw_sock: RawFd,
    data: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<usize> {
    loop {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: data.len(),
        };

        let mut cmsg_buf = AlignedControlBuf([0u8; 64]);
        // SAFETY: `msghdr` is a plain C struct safe to zero-initialize before populating pointers.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;

        if let Some(borrowed_fd) = fd {
            let fd_size = std::mem::size_of::<RawFd>() as libc::c_uint;
            // SAFETY: `CMSG_SPACE` and `CMSG_LEN` are pure arithmetic macros over `c_uint`.
            let cmsg_space = unsafe { libc::CMSG_SPACE(fd_size) };
            let cmsg_len = unsafe { libc::CMSG_LEN(fd_size) };
            assert!((cmsg_space as usize) <= cmsg_buf.0.len());

            msg.msg_control = cmsg_buf.0.as_mut_ptr().cast::<libc::c_void>();
            set_msg_controllen(&mut msg, cmsg_space);

            // SAFETY: `msg.msg_control` points to `cmsg_buf`, which is aligned to `cmsghdr` and
            // has at least `cmsg_space` bytes available.
            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
            if cmsg.is_null() {
                return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
            }
            // SAFETY: `cmsg` points into `cmsg_buf` with room for one `RawFd` payload.
            unsafe {
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                set_cmsg_len(&mut *cmsg, cmsg_len);
                let data_ptr = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                data_ptr.write_unaligned(borrowed_fd.as_raw_fd());
            }
        }

        // SAFETY: `msg` references live stack `iov` and `cmsg_buf` buffers for the duration of the
        // `sendmsg` syscall, and `data` is only read by the kernel.
        let sent = unsafe { libc::sendmsg(raw_sock, &raw const msg, send_flags()) };
        if sent >= 0 {
            return Ok(sent as usize);
        }

        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

fn recvmsg_retry_eintr(raw_sock: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    loop {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };

        let mut cmsg_buf = AlignedControlBuf([0u8; 64]);
        let fd_array_bytes = (std::mem::size_of::<RawFd>() * MAX_CMSG_FDS) as libc::c_uint;
        // SAFETY: `CMSG_SPACE` is a pure size calculation.
        let cmsg_space = unsafe { libc::CMSG_SPACE(fd_array_bytes) };
        assert!((cmsg_space as usize) <= cmsg_buf.0.len());

        // SAFETY: `msghdr` is a plain C struct safe to zero-initialize before populating pointers.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.0.as_mut_ptr().cast::<libc::c_void>();
        set_msg_controllen(&mut msg, cmsg_space);

        // SAFETY: `msg` points to live stack `iov` (`buf`) and `cmsg_buf` buffers valid for the
        // duration of `recvmsg`.
        let recvd = unsafe { libc::recvmsg(raw_sock, &raw mut msg, recvmsg_flags()) };
        if recvd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // Collect all SCM_RIGHTS file descriptors immediately into OwnedFd so no error path below
        // can leak descriptors into this process.
        let mut received_fds: Vec<OwnedFd> = Vec::new();
        let mut cloexec_err: Option<io::Error> = None;

        // SAFETY: Iterating kernel-populated control messages within `cmsg_buf` via standard
        // `CMSG_FIRSTHDR` / `CMSG_NXTHDR` macros after a successful `recvmsg` call.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    let header_offset = (data_ptr as usize).saturating_sub(cmsg as usize);
                    let total_len = (*cmsg).cmsg_len as usize;
                    let payload_bytes = total_len.saturating_sub(header_offset);
                    let count = payload_bytes / std::mem::size_of::<RawFd>();
                    let raw_fds_ptr = data_ptr.cast::<RawFd>();

                    for idx in 0..count {
                        let raw_fd = raw_fds_ptr.add(idx).read_unaligned();
                        if raw_fd >= 0 {
                            if let Err(err) = ensure_cloexec(raw_fd)
                                && cloexec_err.is_none()
                            {
                                cloexec_err = Some(err);
                            }
                            received_fds.push(OwnedFd::from_raw_fd(raw_fd));
                        }
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }

        if let Some(err) = cloexec_err {
            return Err(err);
        }

        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ancillary control message truncated (MSG_CTRUNC)",
            ));
        }

        if received_fds.len() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected at most 1 descriptor in SCM_RIGHTS, received {}",
                    received_fds.len()
                ),
            ));
        }

        return Ok((recvd as usize, received_fds.pop()));
    }
}

fn ensure_cloexec(raw_fd: RawFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Already set atomically via MSG_CMSG_CLOEXEC, verify/keep no-op.
        let _ = raw_fd;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: `raw_fd` was just delivered by `recvmsg` via `SCM_RIGHTS` and is open.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Setting `FD_CLOEXEC` on a valid open file descriptor.
        let rc = unsafe { libc::fcntl(raw_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn send_retry_eintr(raw_sock: RawFd, buf: &[u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `raw_sock` is a valid socket descriptor and `buf` is a live read slice.
        let n = unsafe {
            libc::send(
                raw_sock,
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
                send_flags(),
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

fn recv_retry_eintr(raw_sock: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `raw_sock` is a valid socket descriptor and `buf` is a live mutable slice.
        let n = unsafe {
            libc::recv(
                raw_sock,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::helper_ipc::{HelperCommand, HelperMessage, HelperResponse};

    #[test]
    fn sync_scm_rights_tun_ready_fd_passing_and_peer_uid() {
        let (engine_sock, helper_sock) = StdUnixStream::pair().expect("UnixStream::pair");

        // Verify peer_uid matches current process effective UID
        // SAFETY: `geteuid` has no preconditions and is always safe to call.
        let expected_uid = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&helper_sock).expect("peer_uid"), expected_uid);
        assert_eq!(peer_uid(&engine_sock).expect("peer_uid"), expected_uid);

        // Simulate Engine -> Helper command
        let start_cmd = HelperCommand::StartTun {
            server_ips: vec!["198.51.100.42".parse().unwrap()],
            bypass_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            dns_resolver: "1.1.1.1".parse().unwrap(),
        };
        send_helper_command(&engine_sock, &start_cmd).expect("send StartTun");
        let received_cmd = recv_helper_command(&helper_sock).expect("recv StartTun");
        assert_eq!(received_cmd, start_cmd);

        // Create a real socketpair representing the kernel utun packet channel
        let (utun_kernel_side, utun_client_side) =
            StdUnixStream::pair().expect("simulated utun socketpair");

        let tun_ready = HelperMessage::Response(HelperResponse::TunReady {
            utun_name: "utun9".to_string(),
            outbound_if_index: 5,
            outbound_if_name: "en0".to_string(),
            original_dns_servers: vec!["192.168.1.1".parse().unwrap()],
        });

        send_helper_message(&helper_sock, &tun_ready, Some(utun_client_side.as_fd()))
            .expect("send TunReady with utun fd");

        // Helper immediately drops its copy of the utun fd per PLAN.md §4!
        drop(utun_client_side);

        let (received_msg, received_fd) =
            recv_helper_message(&engine_sock).expect("recv TunReady + fd");
        assert_eq!(received_msg, tun_ready);
        let owned_utun_fd = received_fd.expect("SCM_RIGHTS must deliver OwnedFd");

        // Verify FD_CLOEXEC is set on the received descriptor
        // SAFETY: `owned_utun_fd` is a valid open OwnedFd.
        let fd_flags = unsafe { libc::fcntl(owned_utun_fd.as_raw_fd(), libc::F_GETFD) };
        assert!(fd_flags >= 0);
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);

        // Verify bidirectional I/O works across the transferred OwnedFd even after sender closed its copy
        let mut engine_utun = StdUnixStream::from(owned_utun_fd);
        let mut kernel_utun = utun_kernel_side;

        engine_utun
            .write_all(b"\x00\x00\x00\x02hello-utun")
            .expect("write to transferred fd");
        let mut buf = [0u8; 14];
        kernel_utun
            .read_exact(&mut buf)
            .expect("read from peer after sender closed copy");
        assert_eq!(&buf, b"\x00\x00\x00\x02hello-utun");

        kernel_utun
            .write_all(b"\x00\x00\x00\x02reply-pkt!")
            .expect("write back");
        engine_utun.read_exact(&mut buf).expect("read reply");
        assert_eq!(&buf, b"\x00\x00\x00\x02reply-pkt!");
    }

    #[tokio::test]
    async fn async_scm_rights_and_network_changed_push_work() {
        let (engine_sock, helper_sock) = TokioUnixStream::pair().expect("TokioUnixStream::pair");

        // SAFETY: `geteuid` has no preconditions.
        let expected_uid = unsafe { libc::geteuid() };
        assert_eq!(tokio_peer_uid(&helper_sock).unwrap(), expected_uid);

        let helper_task = tokio::spawn(async move {
            let cmd = async_try_recv_helper_command(&helper_sock)
                .await
                .unwrap()
                .expect("StartTun command");
            assert!(matches!(cmd, HelperCommand::StartTun { .. }));

            let (mut kernel_end, client_end) = StdUnixStream::pair().unwrap();
            let ready = HelperMessage::Response(HelperResponse::TunReady {
                utun_name: "utun3".to_string(),
                outbound_if_index: 4,
                outbound_if_name: "en0".to_string(),
                original_dns_servers: vec!["9.9.9.9".parse().unwrap()],
            });
            async_send_helper_message(&helper_sock, &ready, Some(client_end.as_fd()))
                .await
                .unwrap();
            drop(client_end);

            // Also push an asynchronous NetworkChanged frame without an fd
            let net_changed = HelperMessage::NetworkChanged {
                outbound_if_index: 7,
                outbound_if_name: "en1".to_string(),
                original_dns_servers: vec!["1.0.0.1".parse().unwrap()],
            };
            async_send_helper_message(&helper_sock, &net_changed, None)
                .await
                .unwrap();

            kernel_end.write_all(b"async-fd-ok").unwrap();

            // Wait for engine disconnect -> should yield Ok(None) on clean EOF
            let eof = async_try_recv_helper_command(&helper_sock).await.unwrap();
            assert_eq!(eof, None);
        });

        async_send_helper_command(
            &engine_sock,
            &HelperCommand::StartTun {
                server_ips: vec!["203.0.113.1".parse().unwrap()],
                bypass_cidrs: vec![],
                dns_resolver: "1.1.1.1".parse().unwrap(),
            },
        )
        .await
        .unwrap();

        let (msg1, fd1) = async_recv_helper_message(&engine_sock).await.unwrap();
        assert!(matches!(
            msg1,
            HelperMessage::Response(HelperResponse::TunReady { .. })
        ));
        let mut transferred = StdUnixStream::from(fd1.expect("utun fd"));

        let (msg2, fd2) = async_recv_helper_message(&engine_sock).await.unwrap();
        assert!(matches!(msg2, HelperMessage::NetworkChanged { .. }));
        assert!(fd2.is_none());

        let mut check = [0u8; 11];
        transferred.read_exact(&mut check).unwrap();
        assert_eq!(&check, b"async-fd-ok");

        drop(engine_sock);
        helper_task.await.unwrap();
    }
}

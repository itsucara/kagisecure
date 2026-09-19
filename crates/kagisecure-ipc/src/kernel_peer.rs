//! The peer's pid, straight from the kernel — not from what the caller says it is.
//!
//! `kagisecure-ipc` denies unsafe code everywhere except here (see the crate attribute in
//! [`crate`], and the note on why it is `deny` rather than `forbid`). `getsockopt` with
//! `LOCAL_PEERPID` (macOS, `<sys/un.h>`, `SOL_LOCAL`/`LOCAL_PEERPID = 0x002`) and `SO_PEERCRED`
//! (Linux, `unix(7)`) have no safe wrapper in `interprocess` or the standard library — `libc`
//! exposes the constants and the raw calls, and this module is the one place that FFI happens,
//! kept small and reviewed on its own.
//!
//! ADR-0007 §3 explains why this exists: `interprocess` 2.4.4's `peer_creds()` already gets the
//! pid on Linux (and the BSDs) from the kernel, but not on macOS — `xucred` carries no pid at
//! all there. `LOCAL_PEERPID` is the macOS-specific answer, so macOS is the platform this module
//! exists for; the Linux implementation is included for the same reason the ADR gives for not
//! wanting two different trust mechanisms on the two platforms the project ships to first.

#![allow(unsafe_code)]

use interprocess::local_socket::Stream;

/// Ask the kernel which process is on the other end of `stream`.
///
/// `None` means either this module has no implementation for the current platform, or the
/// syscall itself failed. Callers must treat both the same way — as "unverified" — never as
/// "pid 0" or as license to fall back to a value the peer supplied itself.
#[must_use]
pub fn peer_pid(stream: &Stream) -> Option<u32> {
    imp::peer_pid(stream)
}

/// Resolve `pid` to the path of its executable without shelling out or reading `/proc`.
///
/// Only implemented on macOS: Linux already has `/proc/<pid>/exe`, which needs no FFI and lives
/// in `server.rs` next to the code that calls it.
#[cfg(target_os = "macos")]
#[must_use]
pub fn executable_path(pid: u32) -> Option<String> {
    imp::executable_path(pid)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::os::unix::io::AsRawFd;

    use interprocess::local_socket::Stream;

    pub(super) fn peer_pid(stream: &Stream) -> Option<u32> {
        // `Stream` is a single-variant enum on a Unix build (the `NamedPipe` arm only exists
        // under `#[cfg(windows)]`), so this destructure is irrefutable here.
        let Stream::UdSocket(inner) = stream;
        let fd = inner.inner().as_raw_fd();

        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `fd` names an open local-domain socket for the duration of this call, borrowed
        // from `stream`, which outlives it. `pid` and `len` are stack storage sized exactly to
        // what `LOCAL_PEERPID` writes back per `<sys/un.h>`: one `pid_t`, with `len` telling the
        // kernel the buffer's size up front the way `getsockopt(2)` requires.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                std::ptr::addr_of_mut!(pid).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if ret == 0 && pid > 0 {
            u32::try_from(pid).ok()
        } else {
            None
        }
    }

    pub(super) fn executable_path(pid: u32) -> Option<String> {
        let pid = libc::pid_t::try_from(pid).ok()?;
        let mut buf = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `buf` is a live allocation of exactly `buf.len()` bytes, which is exactly the
        // `buffersize` passed alongside it; `proc_pidpath` writes at most that many bytes and
        // returns the count written (or a negative/zero value on failure, handled below without
        // reading `buf`).
        let n = unsafe {
            libc::proc_pidpath(
                pid,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len() as u32,
            )
        };
        let len = usize::try_from(n).ok()?;
        if len == 0 {
            return None;
        }
        buf.truncate(len);
        String::from_utf8(buf).ok()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::os::unix::io::AsRawFd;

    use interprocess::local_socket::Stream;

    pub(super) fn peer_pid(stream: &Stream) -> Option<u32> {
        // See the macOS `imp::peer_pid` for why this destructure is irrefutable.
        let Stream::UdSocket(inner) = stream;
        let fd = inner.inner().as_raw_fd();

        // SAFETY: `libc::ucred` is a plain-old-data struct of three integers; the all-zero bit
        // pattern is a valid, if meaningless, value for it — which is all that is required before
        // `getsockopt` overwrites the fields it actually returns.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `fd` names an open `AF_UNIX` socket for the duration of this call, borrowed
        // from `stream`, which outlives it. `cred` and `len` are stack storage sized exactly to
        // what `SO_PEERCRED` writes back per `unix(7)`: one `struct ucred`.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if ret == 0 && cred.pid > 0 {
            u32::try_from(cred.pid).ok()
        } else {
            None
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use interprocess::local_socket::Stream;

    /// Windows has no pid on a named pipe worth trusting more than `interprocess` already
    /// reports (none, today). The BSDs already get their pid from `interprocess`'s own
    /// `LOCAL_PEERCRED`/`SO_PEERCRED` support that backs `Stream::peer_creds` (ADR-0007 §3), so
    /// this module has nothing to add there either — `server.rs` falls back to that.
    pub(super) fn peer_pid(_stream: &Stream) -> Option<u32> {
        None
    }
}

#[cfg(test)]
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod tests {
    use super::*;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_socket_connected_to_itself_reports_this_processs_pid() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        // `Stream::UdSocket`'s field is public (enum variant fields are), so a std `UnixStream`
        // can be wrapped directly without going through a listener/connect round trip.
        let stream = Stream::UdSocket(a.into());
        assert_eq!(peer_pid(&stream), Some(std::process::id()));
    }
}

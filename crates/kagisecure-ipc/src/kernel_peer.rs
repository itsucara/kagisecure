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

/// This process's own effective uid, straight from the kernel.
///
/// `geteuid(2)` reads a field of this process's credentials. It takes no arguments, touches no
/// filesystem and cannot fail, which is the whole reason it lives here: the same-user gate
/// (threat-model M-13/M-15) is a hard gate, and a hard gate cannot be built on an answer that is
/// sometimes unavailable. It replaces a probe that created `$TMPDIR/kagisecure-uid-<pid>` and
/// read the owner back — a probe that returned nothing when `$TMPDIR` (inherited, and so
/// attacker-choosable) was unwritable, and that followed a symlink planted at its predictable
/// path and truncated whatever it pointed at.
#[cfg(unix)]
#[must_use]
pub fn own_euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, reads only this process's own credential fields,
    // returns a plain integer and is documented as always succeeding. There is nothing to
    // validate before the call and nothing to free after it.
    unsafe { libc::geteuid() }
}

/// Resolve `pid` to the path of its executable without shelling out or reading `/proc`.
///
/// Implemented on macOS (`proc_pidpath`) and Windows (`QueryFullProcessImageNameW`). Linux
/// already has `/proc/<pid>/exe`, which needs no FFI and lives in `server.rs` next to the code
/// that calls it.
#[cfg(any(target_os = "macos", windows))]
#[must_use]
pub fn executable_path(pid: u32) -> Option<String> {
    imp::executable_path(pid)
}

/// When `pid` started, in microseconds since the Unix epoch, straight from the kernel.
///
/// macOS only: `proc_pidinfo(PROC_PIDTBSDINFO)`'s `pbi_start_tvsec`/`pbi_start_tvusec`. Linux
/// reads the same fact from `/proc/<pid>/stat`, which needs no FFI and lives in `server.rs`
/// beside `/proc/<pid>/exe` (see `server::process_start_time`, the function callers use).
///
/// A pid names whichever process holds it now; a pid together with its start time names one
/// process for as long as the machine runs, because the kernel does not hand a pid to a new
/// process while the old one still holds it. `None` means the process is gone or the call failed.
#[cfg(target_os = "macos")]
#[must_use]
pub fn process_start_time(pid: u32) -> Option<u64> {
    imp::process_start_time(pid)
}

/// The parent process id of `pid`, straight from the kernel.
///
/// Windows only, and deliberately so: every Unix that matters here answers this question through
/// `ps(1)` without any FFI at all, and `kagisecure-extension-ipc` already does exactly that.
/// Windows has no `ps`, and the alternative — parsing `wmic`/PowerShell output — would put a
/// shell on the process-ancestry path that gates browser-extension trust. This is the same
/// reasoning that put `peer_pid` in this module rather than in a helper that shells out.
///
/// `None` means the snapshot failed, `pid` is gone, or the parent is the idle process.
///
/// # Pid reuse
///
/// The value is the parent recorded at *this* moment; Windows reuses pids aggressively and does
/// not keep a zombie entry the way Unix does, so a parent that has already exited may be
/// reported as a pid that now belongs to something else. The caller resolves that pid to an
/// executable separately, which means the window is "the real parent exited **and** its pid was
/// handed to a process whose image path matches a browser". The macOS `ps` path carries the
/// identical weakness; see the `TODO(windows)` in `kagisecure_extension_ipc::peer` for the
/// `GetProcessTimes` hardening that would close it on this platform.
#[cfg(windows)]
#[must_use]
pub fn parent_pid(pid: u32) -> Option<u32> {
    imp::parent_pid(pid)
}

/// The account `pid` runs as: the user SID in its primary token.
///
/// Windows only — it is the input `server::peer_is_same_user` compares there, where a named
/// pipe carries no uid. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` here, then
/// `kagisecure_core::windows_acl::process_user_sid` (`OpenProcessToken` + `TokenUser`) on the
/// handle, which this module keeps open for the duration so the process object cannot go away
/// underneath the token query.
///
/// `None` means the process could not be opened or its token could not be read. For a process
/// belonging to another account that is the *normal* answer — its DACL does not grant this one
/// `PROCESS_QUERY_LIMITED_INFORMATION` — so a caller deciding "same user?" must read `None` as
/// "no", never as "unknown, let it through".
///
/// # Pid reuse
///
/// A pid names whichever process holds it *now*. `GetNamedPipeClientProcessId` records the pid
/// that opened the pipe; if that process has exited and its pid been handed to another process
/// before this runs, the answer describes the newcomer. For that to admit a stranger, the
/// stranger's connection must outlive the process that made it (a duplicated or inherited pipe
/// handle) **and** the pid must land on a process of *this* user in the gap — and the stranger
/// must have got past the pipe's DACL to connect at all, which is the boundary this check backs
/// up rather than replaces.
#[cfg(windows)]
#[must_use]
pub fn process_user_sid(pid: u32) -> Option<kagisecure_core::windows_acl::Sid> {
    imp::process_user_sid(pid)
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

    pub(super) fn process_start_time(pid: u32) -> Option<u64> {
        let pid = libc::c_int::try_from(pid).ok()?;
        // Pid 0 is the kernel; `proc_pidinfo` would describe it, and it is nobody's sidecar.
        if pid <= 0 {
            return None;
        }
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: `libc::proc_bsdinfo` is a plain-old-data struct of integers and integer arrays;
        // the all-zero bit pattern is a valid value for it, which is all that is required before
        // `proc_pidinfo` overwrites it.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is live stack storage of exactly `size` bytes, and `size` is the
        // `buffersize` passed alongside it; with `PROC_PIDTBSDINFO` the kernel writes one
        // `struct proc_bsdinfo` (`<sys/proc_info.h>`) and returns the byte count written, or zero
        // or less on failure, in which case `info` is not read below.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                std::ptr::addr_of_mut!(info).cast::<libc::c_void>(),
                size,
            )
        };
        // Anything short of the whole struct is a failure, not a start time.
        if written != size {
            return None;
        }
        info.pbi_start_tvsec
            .checked_mul(1_000_000)?
            .checked_add(info.pbi_start_tvusec)
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

#[cfg(windows)]
mod imp {
    use interprocess::local_socket::Stream;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    /// `interprocess` (pinned at 2.4.4) already reports a trustworthy pid here through
    /// `Stream::peer_creds` — `GetNamedPipeClientProcessId` (ADR-0007 §3) — so this module has
    /// nothing to add; `server.rs` falls back to that.
    pub(super) fn peer_pid(_stream: &Stream) -> Option<u32> {
        None
    }

    /// A `HANDLE` that is closed when it goes out of scope.
    ///
    /// Both functions below have early returns between opening a handle and being done with it,
    /// and a leaked process handle in the daemon is a leak that grows once per approval prompt.
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from `OpenProcess`/`CreateToolhelp32Snapshot` and was
            // checked to be neither null nor `INVALID_HANDLE_VALUE` before this type was
            // constructed. `Drop` runs exactly once, so the handle is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    impl OwnedHandle {
        /// Wrap a handle, rejecting both of the two values the Win32 API uses for failure.
        ///
        /// `OpenProcess` returns null on failure while `CreateToolhelp32Snapshot` returns
        /// `INVALID_HANDLE_VALUE` (`-1`), and closing either would be a bug, so both are refused
        /// here rather than at each call site.
        fn new(raw: HANDLE) -> Option<Self> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(Self(raw))
            }
        }
    }

    pub(super) fn executable_path(pid: u32) -> Option<String> {
        // `PROCESS_QUERY_LIMITED_INFORMATION` rather than `PROCESS_QUERY_INFORMATION`: it is the
        // least this needs, and it is the right that is still granted for a process running at a
        // higher integrity level as the same user, which `PROCESS_QUERY_INFORMATION` is not.
        // SAFETY: a plain call with three by-value arguments; the returned handle is immediately
        // given to `OwnedHandle`, which rejects the failure values and closes it on drop.
        let handle =
            OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;

        // `MAX_PATH` (260) is the wrong size for this. A system with long paths enabled can hand
        // back up to 32767 UTF-16 code units, and the failure mode of a short buffer is
        // `ERROR_INSUFFICIENT_BUFFER` — i.e. this function would return `None` and the peer
        // would be reported as unverified purely for living under a deep path. One 64 KiB
        // allocation for the length of the call is cheaper than a grow-and-retry loop and
        // cheaper still than that bug.
        let mut buf = vec![0_u16; 32768];
        let mut len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `handle` is a live process handle opened with
        // `PROCESS_QUERY_LIMITED_INFORMATION`, which is the right this call requires. `buf` is a
        // live allocation of `buf.len()` `u16`s and `len` tells the call that size in code units
        // up front, as the API requires; on success it is overwritten with the number of code
        // units written, which is what is read back below. Nothing is read from `buf` when the
        // call reports failure.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                std::ptr::addr_of_mut!(len),
            )
        };
        if ok == 0 {
            return None;
        }
        let len = usize::try_from(len).ok()?;
        // A zero-length path is not a path; treating it as one would put an empty string in the
        // approval prompt where an executable belongs.
        if len == 0 || len > buf.len() {
            return None;
        }
        String::from_utf16(&buf[..len]).ok()
    }

    pub(super) fn process_user_sid(pid: u32) -> Option<kagisecure_core::windows_acl::Sid> {
        // The least right `OpenProcessToken(TOKEN_QUERY)` needs of the process handle, and — as
        // in `executable_path` — one still granted on the user's own elevated processes.
        // SAFETY: a plain call with three by-value arguments; the returned handle is immediately
        // given to `OwnedHandle`, which rejects the failure values and closes it on drop.
        let handle =
            OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
        // SAFETY: `handle.0` is a live process handle owned by `handle`, which is not dropped
        // until after the borrow below has ended — the borrow does not escape this function.
        let borrowed = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(handle.0) };
        kagisecure_core::windows_acl::process_user_sid(borrowed).ok()
    }

    pub(super) fn parent_pid(pid: u32) -> Option<u32> {
        // There is no `GetParentProcessId`. The documented way is a process snapshot; the
        // undocumented one is `NtQueryInformationProcess`, which is explicitly "may be altered or
        // unavailable in future versions" and is not worth it on a path that runs once per
        // approval prompt.
        // SAFETY: a plain call with two by-value arguments; the returned handle is immediately
        // given to `OwnedHandle`, which rejects the failure values and closes it on drop.
        let snapshot =
            OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;

        let mut entry = PROCESSENTRY32W {
            // Required by the API, and the one field the caller must fill in: the call fails if
            // `dwSize` does not match the struct it was compiled against.
            dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).ok()?,
            ..Default::default()
        };

        // SAFETY: `snapshot` is a live `TH32CS_SNAPPROCESS` snapshot and `entry` is a live,
        // zeroed `PROCESSENTRY32W` whose `dwSize` was set to its own size, which is what
        // `Process32FirstW` requires before it writes to it.
        let mut ok = unsafe { Process32FirstW(snapshot.0, std::ptr::addr_of_mut!(entry)) };
        while ok != 0 {
            if entry.th32ProcessID == pid {
                let parent = entry.th32ParentProcessID;
                // Pid 0 is the idle process, which is nobody's meaningful parent; report it the
                // same way a missing answer is reported rather than handing a caller a pid it
                // would then try to resolve.
                return (parent != 0).then_some(parent);
            }
            // SAFETY: as for `Process32FirstW` — the snapshot is still live and `entry` still
            // carries the `dwSize` this call checks.
            ok = unsafe { Process32NextW(snapshot.0, std::ptr::addr_of_mut!(entry)) };
        }
        None
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    use interprocess::local_socket::Stream;

    /// The BSDs need no kernel-FFI shim here: `interprocess` (pinned at 2.4.4) already reports a
    /// trustworthy pid through `Stream::peer_creds` — `LOCAL_PEERCRED`/`SO_PEERCRED` (ADR-0007
    /// §3) — so this module has nothing to add there; `server.rs` falls back to that.
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

    #[cfg(target_os = "macos")]
    #[test]
    fn this_process_has_a_start_time_in_the_past_and_it_does_not_change() {
        let first = process_start_time(std::process::id()).expect("a start time");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros();
        assert!(u128::from(first) <= now, "started {first}, now {now}");
        assert_eq!(process_start_time(std::process::id()), Some(first));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_pid_that_names_no_process_has_no_start_time() {
        assert_eq!(process_start_time(0), None);
        assert_eq!(process_start_time(u32::MAX), None);
    }
}

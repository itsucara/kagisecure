//! Opening the client end of a connection: every client-side connect in the workspace goes here.
//!
//! Both clients — [`crate::client::Client`] for the MCP sidecar and the CLI, and
//! `kagisecure_extension_ipc::Client` for the native host — and the bind-error probe in
//! [`crate::endpoint::Endpoint::classify_bind_error`] open their end through [`open`] rather than
//! through `interprocess`'s `Stream::connect`. On Unix that is the same `connect(2)`; the function
//! exists for what `Stream::connect` does on Windows, which is wrong for this project in two ways.
//!
//! # 1. It waits without bound
//!
//! `interprocess` 2.4.4's local-socket connect ignores the connect options' wait mode on named
//! pipes and meets `ERROR_PIPE_BUSY` — "the name exists, but no instance of it is free" — with
//! `WaitNamedPipe(NMPWAIT_WAIT_FOREVER)`. A name held only by instances that will never become
//! free — a stopped listener's leftover connections, or a squatter's — parks the caller there
//! for good. That is how the extension channel's stop/restart test hung for 39 minutes: the
//! restart's bind was refused, and the bind-error probe then waited forever to connect to a name
//! whose only instance was the connection the stop had left open. The named-pipe API underneath
//! honours a timeout, so [`open`] calls it directly, with a bound.
//!
//! # 2. It lets the server impersonate the client
//!
//! `interprocess` opens the pipe with `CreateFileW` and no `SECURITY_SQOS_PRESENT` flags
//! (`src/os/windows/named_pipe/c_wrappers.rs`, `connect_without_waiting`), and the documented
//! default for a pipe opened that way is `SecurityImpersonation`: whoever holds the server end
//! may call `ImpersonateNamedPipeClient` and then act **as the client**, on this machine, with
//! the client's whole token. The client's owner check
//! (`crate::client::server_is_same_user`) refuses a pipe another account created before a
//! single byte is sent — but impersonation needs only the connection, not the bytes. An ordinary
//! account cannot use it (impersonating at that level takes `SeImpersonatePrivilege`); a service
//! account squatting `kagisecure-<user>.sock` could, in the window between the connect and the
//! owner check.
//!
//! [`open`] passes `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the most any server end
//! can get from our clients is an identification token: it can read who the client is (user SID,
//! groups, privileges) but cannot act as the client, open objects as it, or pass it on.
//!
//! **Why identification and not anonymous**, which would withhold even the reading: nothing in
//! this project impersonates today — the agent resolves a client through the pipe's client pid —
//! but identification is exactly what a server needs to read the client's token straight off the
//! connection instead of through a pid, which is the one way to close the pid-reuse window
//! `kernel_peer::process_user_sid` documents (threat-model W-10). Anonymous would rule that fix
//! out, and gain little against a squatter: what an identification token tells it — the
//! connecting account's SID, groups and privileges — is information about the account, not a
//! capability, and the default pipe name `kagisecure-<user>.sock` already says whose it is.
//!
//! Static tracking (no `SECURITY_CONTEXT_TRACKING`), the default: the context is captured once, at
//! open, which is all a client that never changes identity needs.
//!
//! # Why the client end is a [`ClientStream`], not an `interprocess` stream
//!
//! The obvious way to hand a handle opened here to `interprocess` is its
//! `DuplexPipeStream: TryFrom<OwnedHandle>`, and that is what this module first did. It is
//! wrong, in a way that only shows up under a race. The conversion calls `ReOpenFile` on the
//! handle, to make sure it is overlapped — and on a named-pipe **client**, `ReOpenFile` does not
//! reopen the same connection. It opens a *new* one, to whatever instance of the pipe is free
//! at that moment, with default flags (so `SecurityImpersonation` again), and the conversion
//! then closes the original. Whether that happened depended on timing: if the server's accept had
//! already returned and created its next instance, the reopen connected to that one and the
//! connection the server had accepted saw end-of-stream before its first frame; if not, the
//! reopen failed with `ERROR_PIPE_BUSY` and `interprocess` quietly kept the original. Measured on
//! Windows 11: a server that accepted before the conversion read end-of-stream on the accepted
//! connection, and the level on the new one read back as `SecurityImpersonation`.
//! (`tests::the_connection_open_returns_is_the_one_the_server_accepted` is the regression test;
//! against the conversion it failed within 50 rounds.)
//!
//! `interprocess` 2.4.4 has no other public way to build a pipe stream from a handle. So on
//! Windows the client end is opened **synchronous** (no `FILE_FLAG_OVERLAPPED`) and read and
//! written through `std::fs::File` — plain `ReadFile`/`WriteFile` on the handle `CreateFileW`
//! returned, which nothing ever reopens. On Unix it is `interprocess`'s stream, as before. The
//! server side is untouched: it is `interprocess` all the way down, and a synchronous client
//! talks to an overlapped server like any other.
//!
//! A synchronous handle serializes I/O on its file object, and a duplicate from
//! [`ClientStream::try_clone`] shares that file object — so a read blocked on one clone blocks a
//! write on the other. Every client here is lock-step (write a request, then read its reply, on
//! one thread), which never waits on both at once.
//!
//! # Why this module allows `unsafe`
//!
//! `CreateFileW` and `WaitNamedPipeW` with these flags have no safe wrapper in `interprocess` or
//! the standard library. The calls are here, isolated as [`crate::kernel_peer`] isolates that
//! module's FFI, each with its own `SAFETY:` comment; the handle is owned by an `OwnedHandle`,
//! and then a `std::fs::File`, the moment it exists.

#![allow(unsafe_code)]

use std::time::Duration;

use crate::endpoint::Endpoint;

/// The client end of a connection, as [`open`] returns it.
///
/// On Windows a synchronous named-pipe handle read and written through `std::fs::File`; on Unix
/// `interprocess`'s local-socket stream. See the [module documentation](self) for why Windows is
/// not an `interprocess` stream. Dropping it closes the handle there and then.
pub struct ClientStream {
    #[cfg(windows)]
    pipe: std::fs::File,
    #[cfg(not(windows))]
    stream: interprocess::local_socket::Stream,
}

impl ClientStream {
    /// A second handle to the same connection, for a reader and a writer held apart.
    ///
    /// On Windows the two share one synchronous file object, so a read in progress on one blocks
    /// a write on the other: use them in lock step, as every client here does.
    ///
    /// # Errors
    ///
    /// Any failure duplicating the handle.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                pipe: self.pipe.try_clone()?,
            })
        }
        #[cfg(not(windows))]
        {
            use interprocess::TryClone as _;
            Ok(Self {
                stream: self.stream.try_clone()?,
            })
        }
    }
}

impl std::io::Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        {
            // The server hanging up is end-of-stream, however Windows words it: `std` already
            // reads `ERROR_BROKEN_PIPE` as `Ok(0)`, and a server that disconnected the instance
            // (`DisconnectNamedPipe`, which is how our listeners sever a connection on stop)
            // surfaces as `ERROR_PIPE_NOT_CONNECTED` instead. `interprocess` maps both the same
            // way, so this keeps the client's view of a closed connection what it was.
            match self.pipe.read(buf) {
                Err(e)
                    if e.kind() == std::io::ErrorKind::BrokenPipe
                        || e.raw_os_error()
                            == i32::try_from(
                                windows_sys::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED,
                            )
                            .ok() =>
                {
                    Ok(0)
                }
                other => other,
            }
        }
        #[cfg(not(windows))]
        {
            self.stream.read(buf)
        }
    }
}

impl std::io::Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        {
            self.pipe.write(buf)
        }
        #[cfg(not(windows))]
        {
            self.stream.write(buf)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            self.pipe.flush()
        }
        #[cfg(not(windows))]
        {
            self.stream.flush()
        }
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsHandle for ClientStream {
    fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.pipe.as_handle()
    }
}

impl std::fmt::Debug for ClientStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientStream { .. }")
    }
}

/// How long [`open`] waits for a busy pipe instance before giving up.
///
/// Windows only in effect: a Unix `connect(2)` never waits for a free instance. A live listener
/// here is busy for at most one accept poll (25 ms in both hosts) after another client connects,
/// which this covers with a wide margin; a name that stays busy for this long is held by
/// instances nobody is going to free, and waiting longer would only hang the caller.
pub const PIPE_BUSY_WAIT: Duration = Duration::from_secs(2);

/// Open a client connection to `endpoint`, waiting at most [`PIPE_BUSY_WAIT`] for a busy pipe.
///
/// # Errors
///
/// Whatever the platform reports. On Windows a name whose every instance stayed busy for the
/// whole wait comes back as the OS error `ERROR_PIPE_BUSY` — [`is_busy`] recognizes it — so a
/// caller can tell "the name exists and is held" from "nothing is there" (`ERROR_FILE_NOT_FOUND`).
pub fn open(endpoint: &Endpoint) -> std::io::Result<ClientStream> {
    open_waiting(endpoint, PIPE_BUSY_WAIT)
}

/// [`open`], waiting at most `busy_wait` for a free pipe instance.
///
/// `Duration::ZERO` makes one attempt and reports a busy name at once. (It is **not** passed to
/// `WaitNamedPipe` as `0`: there `0` means `NMPWAIT_USE_DEFAULT_WAIT`, the server's own default.)
/// On Unix `busy_wait` is unused.
///
/// # Errors
///
/// As [`open`].
pub fn open_waiting(endpoint: &Endpoint, busy_wait: Duration) -> std::io::Result<ClientStream> {
    // `name()` validates the endpoint on every platform — on Windows it refuses a filesystem path
    // with a sentence saying what to use instead — so the error for a bad endpoint is the same
    // one whichever way it is opened.
    let name = endpoint.name()?;
    #[cfg(windows)]
    {
        drop(name);
        Ok(ClientStream {
            pipe: imp::open(&pipe_path(endpoint), busy_wait)?,
        })
    }
    #[cfg(not(windows))]
    {
        use interprocess::local_socket::traits::Stream as _;
        let _ = busy_wait;
        Ok(ClientStream {
            stream: interprocess::local_socket::Stream::connect(name)?,
        })
    }
}

/// Whether `error` from [`open`] means "the name exists, but no instance of it came free".
///
/// Always `false` off Windows, where there is no such state.
#[must_use]
pub fn is_busy(error: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        error.raw_os_error() == i32::try_from(windows_sys::Win32::Foundation::ERROR_PIPE_BUSY).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        false
    }
}

/// The `\\.\pipe\…` path `endpoint` names, already validated by [`Endpoint::name`].
///
/// Rebuilt here because `interprocess`'s `Name` does not give its path back.
/// `GenericNamespaced` maps a namespaced name to `\\.\pipe\<name>` on Windows, and a `Path`
/// endpoint that got past [`Endpoint::name`] is already a pipe path.
#[cfg(windows)]
fn pipe_path(endpoint: &Endpoint) -> std::ffi::OsString {
    match endpoint {
        Endpoint::Path(p) => p.as_os_str().to_owned(),
        Endpoint::Namespaced(s) => format!(r"\\.\pipe\{s}").into(),
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
    use std::time::{Duration, Instant};

    #[cfg(test)]
    use interprocess::local_socket::Stream;
    use windows_sys::Win32::Foundation::{
        ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    /// `WaitNamedPipe`'s "forever". Never passed: every wait here is bounded below it.
    const NMPWAIT_WAIT_FOREVER: u32 = u32::MAX;

    pub(super) fn open(path: &OsStr, busy_wait: Duration) -> std::io::Result<std::fs::File> {
        let wide: Vec<u16> = path.encode_wide().chain(std::iter::once(0)).collect();
        let deadline = Instant::now() + busy_wait;
        let handle = loop {
            match create_client(&wide) {
                Ok(handle) => break handle,
                Err(e) if super::is_busy(&e) => {}
                Err(e) => return Err(e),
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(busy());
            }
            // At least 1 ms, because 0 is `NMPWAIT_USE_DEFAULT_WAIT`; and below "forever".
            let ms = u32::try_from(left.as_millis())
                .unwrap_or(u32::MAX)
                .clamp(1, NMPWAIT_WAIT_FOREVER - 1);
            match wait_for_instance(&wide, ms) {
                // An instance was free a moment ago. Another client may take it first, which is
                // why this goes round the loop rather than assuming the next open succeeds.
                Ok(()) => {}
                Err(e) if e.raw_os_error() == os_error(ERROR_SEM_TIMEOUT) => return Err(busy()),
                // Most often `ERROR_FILE_NOT_FOUND`: the listener went away while we waited.
                Err(e) => return Err(e),
            }
        };
        // Straight into a `File`, which only ever reads, writes and closes this handle. Not
        // `interprocess`'s `TryFrom<OwnedHandle>`: that reopens the handle, and reopening a pipe
        // client makes a second connection (see the module documentation).
        Ok(std::fs::File::from(handle))
    }

    /// One attempt at opening the client end, with identification-only impersonation.
    fn create_client(wide_path: &[u16]) -> std::io::Result<OwnedHandle> {
        debug_assert_eq!(
            wide_path.last(),
            Some(&0),
            "the path must be NUL-terminated"
        );
        // SAFETY: `wide_path` is a NUL-terminated UTF-16 string that outlives the call (asserted
        // above; built that way by `open`). The security-attributes and template-file arguments
        // are null, which `CreateFileW` documents as "default" and "none". It writes nothing
        // through any argument, and the handle it returns is checked against
        // `INVALID_HANDLE_VALUE` before anything takes ownership of it.
        let raw = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                // Synchronous — no `FILE_FLAG_OVERLAPPED` — because it is read and written
                // through `std::fs::File` (see the module documentation). The two `SECURITY_*`
                // flags are the point of this module.
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `raw` is a valid handle `CreateFileW` just returned to this process, owned by
        // nothing else, so `OwnedHandle` may take it and will close it exactly once.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    /// Wait up to `ms` for an instance of the pipe to come free.
    fn wait_for_instance(wide_path: &[u16], ms: u32) -> std::io::Result<()> {
        debug_assert_eq!(
            wide_path.last(),
            Some(&0),
            "the path must be NUL-terminated"
        );
        // SAFETY: `wide_path` is NUL-terminated and outlives the call; `WaitNamedPipeW` only reads
        // it. `ms` is never `NMPWAIT_WAIT_FOREVER` (the caller clamps below it), so the call
        // returns within the bound.
        if unsafe { WaitNamedPipeW(wide_path.as_ptr(), ms) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn os_error(code: u32) -> Option<i32> {
        i32::try_from(code).ok()
    }

    /// The error [`super::open`] reports for a name that stayed busy for the whole wait:
    /// `ERROR_PIPE_BUSY`, whichever of "busy" or "the wait timed out" the OS said last, so
    /// [`super::is_busy`] has one thing to recognize.
    fn busy() -> std::io::Error {
        std::io::Error::from_raw_os_error(os_error(ERROR_PIPE_BUSY).unwrap_or(231))
    }

    /// The impersonation level the server end of `server` would be granted, read the only way
    /// it can be: by impersonating and looking at the thread's token.
    ///
    /// Test-only. Runs on a thread of its own, so the impersonation this performs can never leak
    /// into the caller's thread even if reverting failed.
    #[cfg(test)]
    pub(super) fn impersonation_level_granted_to(
        server: &Stream,
    ) -> std::io::Result<windows_sys::Win32::Security::SECURITY_IMPERSONATION_LEVEL> {
        use std::os::windows::io::{AsHandle as _, AsRawHandle as _};

        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, RevertToSelf, SECURITY_IMPERSONATION_LEVEL, TOKEN_QUERY,
            TokenImpersonationLevel,
        };
        use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
        use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

        let Stream::NamedPipe(pipe) = server;
        // A `BorrowedHandle` is `Send`, and the scope keeps `server` borrowed until the thread
        // has been joined.
        let borrowed = pipe.as_handle();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let pipe_handle = borrowed.as_raw_handle();
                    // SAFETY: `pipe_handle` is the server end of a connected pipe, borrowed from
                    // `server` for the whole scope, so it stays open. The call takes no pointers.
                    if unsafe { ImpersonateNamedPipeClient(pipe_handle) } == 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut token: HANDLE = std::ptr::null_mut();
                    // SAFETY: `GetCurrentThread` returns a pseudo-handle that needs no closing;
                    // `token` is a valid out-pointer for one `HANDLE`. `OpenAsSelf = TRUE` so the
                    // access check uses the process's own context, which is what lets an
                    // identification-level token be opened at all.
                    let opened =
                        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
                    let result = if opened == 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        let mut level: SECURITY_IMPERSONATION_LEVEL = -1;
                        let mut written = 0u32;
                        // SAFETY: `token` was just opened with `TOKEN_QUERY`; `level` is a valid,
                        // correctly sized buffer for `TokenImpersonationLevel`'s single `i32`, and
                        // `written` a valid out-pointer.
                        let ok = unsafe {
                            GetTokenInformation(
                                token,
                                TokenImpersonationLevel,
                                std::ptr::from_mut(&mut level).cast(),
                                u32::try_from(std::mem::size_of_val(&level)).unwrap_or(4),
                                &mut written,
                            )
                        };
                        // SAFETY: `token` is a handle this closure opened and owns.
                        unsafe { CloseHandle(token) };
                        if ok == 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(level)
                        }
                    };
                    // SAFETY: ends this thread's impersonation; takes no arguments.
                    if unsafe { RevertToSelf() } == 0 {
                        // A thread that cannot revert must not run anything else: the scope is
                        // about to end it, and the panic says why.
                        panic!("RevertToSelf failed: {}", std::io::Error::last_os_error());
                    }
                    result
                })
                .join()
                .expect("the impersonation thread")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_nothing_fails_at_once_and_is_not_busy() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(dir.path(), "nothing-here.sock");
        let started = std::time::Instant::now();
        let err = open(&endpoint).expect_err("nothing is listening");
        assert!(!is_busy(&err), "{err:?}");
        assert!(
            started.elapsed() < PIPE_BUSY_WAIT,
            "an absent name is not waited on: {:?}",
            started.elapsed()
        );
    }

    /// The connection [`open`] returns is the one the server accepted, and it is still the
    /// identification-level one when the first byte goes over it.
    ///
    /// The regression this guards: `open` used to hand its handle to `interprocess`'s
    /// `DuplexPipeStream: TryFrom<OwnedHandle>`, which calls `ReOpenFile` on it. On a named-pipe
    /// client, `ReOpenFile` does not reopen the same connection — it opens a *new* one, to the
    /// next free instance, with the default `SecurityImpersonation` — and the original handle is
    /// then closed. Whether that happened depended on a race: if the server's accept had already
    /// returned and created its next instance, the reopen connected to it; if not, the reopen
    /// failed with `ERROR_PIPE_BUSY` and `interprocess` quietly kept the original. The losing
    /// side of the race showed up as an accepted connection that hit end-of-stream before its
    /// first frame (`the_native_host_exits_when_the_port_closes_even_while_the_app_is_silent`,
    /// about one run in five), and — silently — as a client talking at impersonation level.
    ///
    /// Many rounds, each with the server blocked in `accept` while the client opens, because
    /// that is the ordering that lost the race.
    #[cfg(windows)]
    #[test]
    fn the_connection_open_returns_is_the_one_the_server_accepted() {
        use std::io::{Read as _, Write as _};

        use interprocess::local_socket::traits::Listener as _;
        use windows_sys::Win32::Security::SecurityIdentification;

        for round in 0..50 {
            let (listener, endpoint) = bind_bare("same-connection.sock");
            std::thread::scope(|scope| {
                let accepting = scope.spawn(|| listener.accept().expect("accept"));
                // Let the server park in `accept` first.
                std::thread::sleep(Duration::from_millis(5));
                let mut client = open(&endpoint).expect("open");
                let mut server = accepting.join().expect("the accept thread");
                // `accept` has returned, so the listener's next free instance exists now: the
                // state a reopen needed to go astray.
                client.write_all(b"x").expect("write");
                client.flush().expect("flush");
                let mut byte = [0u8; 1];
                let read = server.read(&mut byte).expect("read");
                assert_eq!(
                    read, 1,
                    "round {round}: the accepted connection hit end-of-stream — the client is \
                     talking on another connection"
                );
                assert_eq!(
                    imp::impersonation_level_granted_to(&server).expect("impersonate"),
                    SecurityIdentification,
                    "round {round}"
                );
            });
        }
    }

    /// Bind a bare `interprocess` listener on a fresh endpoint, returning both.
    #[cfg(windows)]
    fn bind_bare(label: &str) -> (interprocess::local_socket::Listener, Endpoint) {
        use interprocess::local_socket::ListenerOptions;
        let dir = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(dir.path(), label);
        let listener = ListenerOptions::new()
            .name(endpoint.name().unwrap())
            .create_sync()
            .unwrap();
        (listener, endpoint)
    }

    /// A name whose every instance is taken is waited on for the bound, then reported busy.
    ///
    /// Windows only: a Unix listener's backlog accepts a second `connect` whether or not anyone
    /// calls `accept`. Here the listener's one free instance is taken by `first` and never
    /// accepted, so no instance comes free again.
    #[cfg(windows)]
    #[test]
    fn a_pipe_with_no_free_instance_is_given_up_on_and_reported_busy() {
        let (_listener, endpoint) = bind_bare("busy.sock");
        let first = open(&endpoint).expect("the one free instance");

        let wait = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let err = open_waiting(&endpoint, wait).expect_err("no instance is free");
        let waited = started.elapsed();
        assert!(is_busy(&err), "{err:?}");
        assert!(
            waited >= wait / 2 && waited < wait * 10,
            "waited {waited:?} against a {wait:?} bound"
        );

        let started = std::time::Instant::now();
        let err = open_waiting(&endpoint, Duration::ZERO).expect_err("still none");
        assert!(is_busy(&err), "{err:?}");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "a zero wait is one attempt, not the server's default wait: {:?}",
            started.elapsed()
        );
        drop(first);
    }

    /// What a server end gets from our client: an identification token, not an impersonation one.
    ///
    /// Observed from the server side, the only side it can be observed from: the server reads a
    /// byte (a pipe client cannot be impersonated before it has written), calls
    /// `ImpersonateNamedPipeClient`, and reads the impersonation level off the thread token.
    /// The same is done for a stream `interprocess` opened itself, as the control: it must come
    /// back `SecurityImpersonation`, or this test would pass without testing anything.
    #[cfg(windows)]
    #[test]
    fn a_server_can_identify_our_client_but_not_impersonate_it() {
        use std::io::Read as _;

        use interprocess::local_socket::Stream;
        use interprocess::local_socket::traits::{Listener as _, Stream as _};
        use windows_sys::Win32::Security::{SecurityIdentification, SecurityImpersonation};

        fn level_for(
            mut client: impl std::io::Write,
            listener: &interprocess::local_socket::Listener,
        ) -> windows_sys::Win32::Security::SECURITY_IMPERSONATION_LEVEL {
            client.write_all(b"x").unwrap();
            client.flush().unwrap();
            let mut server = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            server.read_exact(&mut byte).unwrap();
            let level = imp::impersonation_level_granted_to(&server).expect("impersonate");
            drop(client);
            level
        }

        let (listener, endpoint) = bind_bare("sqos.sock");
        let ours = open(&endpoint).expect("open");
        assert_eq!(
            level_for(ours, &listener),
            SecurityIdentification,
            "our client must grant identification only"
        );

        let (listener, endpoint) = bind_bare("control.sock");
        let theirs = Stream::connect(endpoint.name().unwrap()).expect("interprocess connect");
        assert_eq!(
            level_for(theirs, &listener),
            SecurityImpersonation,
            "the control: `interprocess`'s own connect grants full impersonation"
        );
    }

    /// The owner check still reads the pipe's owner through a handle opened this way. Against
    /// [`crate::server::Server`], whose pipe names its owner explicitly: a bare listener's pipe
    /// takes the token's default owner, which for an elevated administrator is the
    /// Administrators group rather than the user.
    #[cfg(windows)]
    #[test]
    fn the_owner_check_works_on_a_stream_opened_here() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(dir.path(), "owner.sock");
        let _server = crate::server::Server::bind(&endpoint).expect("bind");
        let client = open(&endpoint).expect("open");
        assert!(crate::client::server_is_same_user(&client));
    }
}

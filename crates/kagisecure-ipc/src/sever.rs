//! Ending an accepted connection from a thread that is not serving it.
//!
//! Used by both listeners the app runs — the MCP agent's ([`crate::server`]) and the browser
//! extension's (`kagisecure_extension_ipc::listener`) — because both have the same problem, and
//! it was found on the second one first. This module started life in `kagisecure-extension-ipc`
//! and moved here, below both, when the MCP channel turned out to need it too.
//!
//! # Why this exists
//!
//! A host serves each accepted connection on its own thread, and that thread spends nearly all of
//! its life parked in a blocking read, waiting for the peer's next request. When the app stops a
//! listener — which it does for both channels on every vault lock, and which the next unlock
//! undoes by binding the same endpoint again — the accept loop can be told to stop, but the
//! serving threads cannot: nothing wakes a blocking read except the peer or the transport.
//!
//! On Unix that was merely untidy. The listener's socket file is unlinked and a fresh one is bound
//! at the same path; the stale connection lingers, unreachable, until the peer next speaks on it.
//!
//! On Windows it is a hard failure. A named pipe's name belongs to its **instances**, not to a
//! listener: it exists for as long as any server-side handle to any instance is open, and a
//! connected instance is exactly such a handle. So after a stop, the parked thread's connection
//! keeps the name alive, the next bind's `FILE_FLAG_FIRST_PIPE_INSTANCE` is refused with
//! `ERROR_ACCESS_DENIED`, and — worse — the only instance left is a busy one, so anything that
//! then tries to *connect* to the name without a bound waits in `WaitNamedPipe` for an instance
//! that will never become free. That is how the extension channel's
//! `the_native_host_survives_the_app_going_away_and_coming_back` hung for 39 minutes: the
//! restart's bind was refused, the bind-error classifier probed the name with an unbounded
//! connect, and the connection it was waiting behind was the one the test would only have used
//! after the restart returned. (The probe is bounded now — see
//! [`crate::endpoint::Endpoint::classify_bind_error`] — but a bounded probe only turns the hang
//! into a refused restart; this module is what makes the restart succeed.)
//!
//! A [`Severer`] is the missing wake-up. It is taken from an accepted connection when the
//! connection is accepted, kept by whoever may need to stop the listener — [`LiveConnections`]
//! is that registry — and, when [`Severer::sever`] is called, ends the session at the transport,
//! so the serving thread's read returns end-of-stream, the thread drops its handles, and the
//! instance (and with it, on Windows, the name) is released.
//!
//! "Drops its handles" has to mean "closes them before the drop returns", or a stop that waited
//! for the thread would still return before the name was free. `interprocess` does not promise
//! that on Windows, so every handle an accepted connection holds is kept in a [`Closing`], which
//! does; `close_now` says why.
//!
//! # What severing does to each end
//!
//! * **Unix:** `shutdown(SHUT_RD)` on a duplicate of the connection's socket. `shutdown` acts
//!   on the socket, not the descriptor, so the serving thread's blocked `recv` returns 0; the
//!   thread then drops the connection and the registry drops the duplicate, and the peer sees
//!   end-of-stream. Only the read side: a stop denies every queued approval *before* it severs,
//!   and the serving thread may be writing that denial at the moment of the sever. Shutting the
//!   write side too would turn a request that was answered into one that was dropped — and, in
//!   a host that has not ignored `SIGPIPE` (the macOS app, which links this library), into a
//!   process-killing signal on that write. For the same reason every accepted socket is set
//!   `SO_NOSIGPIPE` on Apple platforms, so a write to a peer that has gone away is an `EPIPE`
//!   error on that connection, never a signal to the whole app.
//! * **Windows:** `DisconnectNamedPipe` on a duplicate of the connection's server-side handle.
//!   Named-pipe handles duplicated with `DuplicateHandle` share one pipe instance, so this
//!   disconnects the instance the serving thread is reading: its pending read completes with
//!   `ERROR_PIPE_NOT_CONNECTED` — which `interprocess` reports as end-of-stream — and the peer's
//!   next read or write on its end fails the same way.
//!
//! Either way the peer sees an ordinary dead connection. The native host's one-retry reconnect,
//! and the MCP sidecar's connection-per-tool-call, take it to whatever is listening now.
//!
//! # Why this module allows `unsafe`
//!
//! `DisconnectNamedPipe` has no safe wrapper in `interprocess` or the standard library. The one
//! call is here, isolated the same way [`crate::kernel_peer`] isolates that module's FFI.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use interprocess::TryClone as _;
use interprocess::local_socket::Stream;

/// The means to end one accepted connection from another thread. See the [module documentation].
///
/// Holds its own duplicate of the connection's handle, so it keeps the connection's transport
/// object open for as long as it lives: drop it once the connection it severs has been closed,
/// or the endpoint is not free. Dropping it closes that duplicate there and then, as the rest of
/// this module's handles are.
///
/// [module documentation]: self
pub struct Severer {
    stream: Closing,
}

impl Severer {
    /// Take a severer for `stream`, an accepted (server-side) connection: a duplicate handle to
    /// the same connection.
    ///
    /// # Errors
    ///
    /// Any failure duplicating the handle — in practice only a process out of handles.
    pub fn for_stream(stream: &Stream) -> std::io::Result<Self> {
        imp::no_sigpipe(stream);
        Ok(Self {
            stream: Closing::new(stream.try_clone()?),
        })
    }

    /// End the session at the transport. Idempotent; failure is ignored, because the only way it
    /// can fail is the connection already being over, which is the state this asks for.
    pub fn sever(&self) {
        imp::sever(self.stream.get());
    }
}

impl std::fmt::Debug for Severer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Severer { .. }")
    }
}

/// A stream whose handle is closed where it is dropped, not later. See `close_now`.
///
/// What an accepted connection's reader and writer are held in, on both channels, so that no
/// path that drops a connection — a normal hang-up, a refused peer, a failed thread spawn — can
/// leave a pipe instance open behind it.
pub struct Closing(Option<Stream>);

impl Closing {
    /// Take ownership of `stream`, to be closed on drop.
    #[must_use]
    pub fn new(stream: Stream) -> Self {
        Self(Some(stream))
    }

    /// The stream, for what `Read` and `Write` do not cover (credentials, cloning, severing).
    #[must_use]
    pub fn get(&self) -> &Stream {
        self.0.as_ref().expect("only `Drop` takes the stream")
    }

    fn get_mut(&mut self) -> &mut Stream {
        self.0.as_mut().expect("only `Drop` takes the stream")
    }
}

impl std::io::Read for Closing {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.get_mut().read(buf)
    }
}

impl std::io::Write for Closing {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.get_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.get_mut().flush()
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            close_now(stream);
        }
    }
}

impl std::fmt::Debug for Closing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Closing { .. }")
    }
}

/// Close `stream`'s handle before returning.
///
/// Dropping an `interprocess` stream does not promise that on Windows. A named-pipe stream that
/// may hold unflushed writes is not closed where it is dropped but handed to `interprocess`'s
/// "linger pool", a background thread that flushes it and closes it later — and any stream that
/// has ever been cloned is permanently marked as possibly unflushed, both the clone and the
/// original. Every accepted connection is cloned (its reader and writer are two handles), and so
/// is every [`Severer`]; left to their own `Drop`, all of those handles would be closed at some
/// moment after the connection's thread had finished, and a restart binding the same pipe name in
/// between would be refused because an instance was, briefly, still open. (Measured on the
/// extension channel: about one restart in five on Windows 11, before [`Closing`] existed.)
///
/// Taking the handle out of the stream and dropping it directly is a plain `CloseHandle`. What
/// the linger pool is for — not closing on a peer that has yet to read the last reply — does not
/// arise on either channel: both frame writers ([`crate::frame::write`] and
/// `kagisecure_extension_ipc::frame::write`) flush every frame before they return, so there is
/// never a reply left in the pipe for the pool to wait on.
///
/// On Unix, dropping a stream closes its descriptor, so this is `drop`.
fn close_now(stream: Stream) {
    #[cfg(windows)]
    {
        let Stream::NamedPipe(inner) = stream;
        drop(std::os::windows::io::OwnedHandle::from(inner));
    }
    #[cfg(not(windows))]
    drop(stream);
}

/// The accepted connections a stop has to end, each with the means to end it from another thread.
///
/// The use is fixed, and both listeners follow it: a connection is entered with
/// [`LiveConnections::arrived`] **before** its serving thread is spawned, and removed with
/// [`LiveConnections::gone`] only **after** that thread has dropped every handle to it. So
/// "empty" means what a stop needs it to mean: no handle to any connection the listener accepted
/// is still open. That is a correctness condition on Windows, not tidiness — see the
/// [module documentation](self) for how one stale connection keeps a pipe name alive and turns
/// the next bind into a refusal.
#[derive(Default)]
pub struct LiveConnections {
    registry: Mutex<Registry>,
    /// Signalled whenever a connection leaves the registry, for [`Self::sever_all`] to wait on.
    changed: Condvar,
}

#[derive(Default)]
struct Registry {
    next: u64,
    severers: HashMap<u64, Severer>,
}

/// What [`LiveConnections::arrived`] hands back, and [`LiveConnections::gone`] takes: one
/// connection's place in the registry.
///
/// `Copy`, because a host needs it in two places: inside the serving thread's closure, and at
/// the spawn site in case the spawn fails and the closure — ticket and all — is dropped unrun.
/// Marking a connection gone twice is harmless; the second call finds nothing to remove.
#[derive(Clone, Copy, Debug)]
#[must_use = "a connection that is never marked gone keeps its endpoint taken after a stop"]
pub struct Ticket(u64);

impl LiveConnections {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Enter an accepted connection, by its severer.
    pub fn arrived(&self, severer: Severer) -> Ticket {
        let mut registry = self.lock();
        let id = registry.next;
        registry.next = registry.next.wrapping_add(1);
        registry.severers.insert(id, severer);
        Ticket(id)
    }

    /// Remove a connection whose handles have all been closed. Dropping its [`Severer`] closes the
    /// last duplicate of its handle.
    pub fn gone(&self, ticket: Ticket) {
        let severer = self.lock().severers.remove(&ticket.0);
        drop(severer);
        self.changed.notify_all();
    }

    /// How many connections are entered right now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().severers.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sever every entered connection, then wait up to `drain` for all of them to be let go of.
    ///
    /// Call it only once nothing can be entered any more — after the accept threads have been
    /// joined — or a connection accepted meanwhile escapes it. Returns whether every connection
    /// was released in time; `false` means one was busy outside a read (a request still being
    /// served) and will release its handles when that finishes.
    pub fn sever_all(&self, drain: Duration) -> bool {
        let deadline = Instant::now() + drain;
        let mut registry = self.lock();
        for severer in registry.severers.values() {
            severer.sever();
        }
        while !registry.severers.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            registry = self
                .changed
                .wait_timeout(registry, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

impl std::fmt::Debug for LiveConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveConnections")
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(unix)]
mod imp {
    use interprocess::local_socket::Stream;

    pub(super) fn sever(stream: &Stream) {
        // `Stream` is a single-variant enum on a Unix build, as in `crate::kernel_peer`.
        let Stream::UdSocket(inner) = stream;
        // The read side only: see "What severing does to each end" in the module documentation.
        let _ = inner.inner().shutdown(std::net::Shutdown::Read);
    }

    /// Make a write to a peer that has gone away an `EPIPE` on this socket rather than a
    /// `SIGPIPE` to the process. Apple platforms only: they have `SO_NOSIGPIPE`, and they are
    /// where this library runs inside a host (the macOS app) that has not ignored the signal the
    /// way every Rust binary's runtime does. Best effort — a failure leaves the socket as it was.
    #[cfg(target_vendor = "apple")]
    pub(super) fn no_sigpipe(stream: &Stream) {
        use std::os::fd::AsRawFd as _;

        let Stream::UdSocket(inner) = stream;
        let fd = inner.inner().as_raw_fd();
        let on: libc::c_int = 1;
        let len = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4);
        // SAFETY: `fd` is the open socket `stream` owns, borrowed for this call; `on` is a local
        // `c_int` that outlives it and `len` is its size. `setsockopt` reads the value and keeps
        // no pointer.
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&raw const on).cast(),
                len,
            )
        };
    }

    #[cfg(not(target_vendor = "apple"))]
    pub(super) fn no_sigpipe(_stream: &Stream) {}
}

#[cfg(windows)]
mod imp {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};

    use interprocess::local_socket::Stream;
    use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;

    /// Nothing to do: a Windows pipe raises no signal.
    pub(super) fn no_sigpipe(_stream: &Stream) {}

    pub(super) fn sever(stream: &Stream) {
        // Single-variant on a Windows build, the mirror of the Unix arm above.
        let Stream::NamedPipe(inner) = stream;
        let handle = inner.as_handle().as_raw_handle();
        // SAFETY: `handle` is a server-side named-pipe handle owned by `stream`, which the caller
        // borrows for the duration of this call, so it is open and cannot be closed under us.
        // `DisconnectNamedPipe` takes no pointers besides the handle and writes nothing back; a
        // failure (already disconnected, or never connected) is reported through the return
        // value, which is ignored for the reason given on `Severer::sever`.
        let _ = unsafe { DisconnectNamedPipe(handle) };
    }
}

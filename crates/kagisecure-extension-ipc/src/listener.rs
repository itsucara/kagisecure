//! The app's half: bind the extension socket, accept, and identify what connected.
//!
//! Mirrors `kagisecure_ipc::server` in shape — a `0700` directory, a `0600` socket, a non-blocking
//! accept so a host that has to quit can — and differs in exactly two places: the frame format
//! ([`crate::frame`], big-endian) and the identity ([`HostIdentity`], which resolves one hop up
//! the process tree).
//!
//! A connection is served by one thread, but it can be written from two: its replies, and the
//! [`crate::protocol::Push`]es another thread sends through a [`PushSender`]. Both go through one
//! writer behind a mutex, a whole frame at a time.

use std::io::BufWriter;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use interprocess::local_socket::traits::{Listener as _, Stream as _, StreamCommon as _};
use interprocess::local_socket::{Listener as IpcListener, ListenerOptions};
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};

use crate::frame::{self, FrameError};
use crate::peer::{HostIdentity, HostKind};
use crate::protocol::{Envelope, Push, PushEnvelope, Request, Response};
use crate::sever::{Closing, Severer};

/// A bound extension socket.
pub struct Listener {
    listener: IpcListener,
    endpoint: Endpoint,
    kind: HostKind,
}

impl Listener {
    /// Bind the Chromium native-messaging front end to `endpoint`.
    ///
    /// # Errors
    ///
    /// See [`Listener::bind_kind`].
    pub fn bind(endpoint: &Endpoint) -> Result<Self, EndpointError> {
        Self::bind_kind(endpoint, HostKind::NativeMessaging)
    }

    /// Bind to `endpoint`, replacing a corpse socket but never a live one.
    ///
    /// `kind` decides only what an accepted connection's identity is resolved *as* — the wire
    /// format, the permissions and the accept loop are the same on both front ends, which is the
    /// point: Safari changes the transport and nothing above it (ADR-0024).
    ///
    /// # Errors
    ///
    /// [`EndpointError`] if the directory cannot be prepared or the socket cannot be created. An
    /// [`std::io::ErrorKind::AddrInUse`] inside it means another kagisecure is already serving.
    pub fn bind_kind(endpoint: &Endpoint, kind: HostKind) -> Result<Self, EndpointError> {
        endpoint.prepare_dir()?;
        // Probed through `kagisecure_ipc::connect`, as in `kagisecure_ipc::server::Server::bind`.
        if let Some(path) = endpoint.path()
            && path.exists()
        {
            endpoint.name().map_err(|source| EndpointError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            if kagisecure_ipc::connect::open(endpoint).is_err() {
                let _ = std::fs::remove_file(path);
            }
        }

        // The pipe name when there is no path, rather than the empty string: see the same line
        // in `kagisecure_ipc::server::Server::bind`. Identical for a `Path` endpoint.
        let socket_path = endpoint.path().map_or_else(
            || std::path::PathBuf::from(endpoint.to_string()),
            std::path::Path::to_path_buf,
        );
        let io_err = |source: std::io::Error| EndpointError::Io {
            path: socket_path.clone(),
            source,
        };

        let listener = bind_listener(endpoint).map_err(io_err)?;

        #[cfg(unix)]
        if let Some(path) = endpoint.path() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(Self {
            listener,
            endpoint: endpoint.clone(),
            kind,
        })
    }

    /// Where this listener is bound.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Which front end this listener serves.
    #[must_use]
    pub fn kind(&self) -> HostKind {
        self.kind
    }

    /// Make `accept` return [`std::io::ErrorKind::WouldBlock`] instead of parking.
    ///
    /// # Errors
    ///
    /// Any I/O failure from the underlying `fcntl`.
    pub fn set_accept_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        use interprocess::local_socket::ListenerNonblockingMode;
        self.listener.set_nonblocking(if nonblocking {
            ListenerNonblockingMode::Accept
        } else {
            ListenerNonblockingMode::Neither
        })
    }

    /// Accept the next native host.
    ///
    /// # Errors
    ///
    /// Any I/O failure from `accept`, including `WouldBlock`.
    pub fn accept(&self) -> std::io::Result<HostConnection> {
        // Held in `Closing` from the start, so every way out of this function — and every way a
        // `HostConnection` is dropped later — closes the handle there and then. See
        // `crate::sever::close_now` for why `interprocess` would not.
        let accepted = Closing::new(self.listener.accept()?);
        let stream = accepted.get();
        // BSD `accept()` hands the new socket the listener's `O_NONBLOCK`; a connection handler
        // wants to block on its next request.
        stream.set_nonblocking(false)?;
        let creds = stream.peer_creds().ok();
        // Windows named pipes have no effective uid to report.
        #[cfg(unix)]
        let euid = creds
            .as_ref()
            .and_then(interprocess::local_socket::PeerCreds::euid);
        #[cfg(not(unix))]
        let euid = None;
        // `interprocess`'s `Pid` is `i32` on Unix and `u32` on Windows, so this conversion is a
        // real narrowing on one platform and a no-op on the other. Writing it once and allowing
        // the lint beats two `cfg` arms of the same expression.
        #[allow(
            clippy::useless_conversion,
            reason = "`Pid` is already `u32` on Windows; it is `i32` everywhere else"
        )]
        let pid = kagisecure_ipc::kernel_peer::peer_pid(stream).or_else(|| {
            creds
                .as_ref()
                .and_then(interprocess::local_socket::PeerCreds::pid)
                .and_then(|p| u32::try_from(p).ok())
        });
        let mut identity = HostIdentity::resolve_kind(self.kind, pid, euid);
        identity.audit_token = kagisecure_ipc::kernel_peer::peer_audit_token(stream);
        let reader = {
            use interprocess::TryClone;
            Closing::new(TryClone::try_clone(stream)?)
        };
        Ok(HostConnection {
            reader,
            writer: Arc::new(Mutex::new(BufWriter::new(accepted))),
            identity,
            kind: self.kind,
        })
    }
}

/// One connected native host.
///
/// Dropping it closes both of its handles before the drop returns, on every platform — including
/// while a [`PushSender`] taken from it is still alive, since the sender does not own the writer.
///
/// The writer sits behind a mutex it shares with every [`PushSender`], and each frame is written
/// and flushed whole under that lock, so a push and a reply can be sent from different threads
/// without their bytes interleaving.
pub struct HostConnection {
    reader: Closing,
    writer: Arc<Mutex<BufWriter<Closing>>>,
    identity: HostIdentity,
    kind: HostKind,
}

impl HostConnection {
    /// What the kernel and the process tree say about the caller.
    #[must_use]
    pub fn identity(&self) -> &HostIdentity {
        &self.identity
    }

    /// Which front end this connection arrived on.
    #[must_use]
    pub fn kind(&self) -> HostKind {
        self.kind
    }

    /// A [`Severer`] for this connection: the means for another thread to end it.
    ///
    /// Take it at accept time and keep it where a stop can reach it. A listener that stops
    /// without severing the connections it accepted has not let go of its endpoint — on Windows
    /// the pipe name outlives the listener for as long as any accepted instance is open, and the
    /// next bind on it is refused. See [`crate::sever`].
    ///
    /// # Errors
    ///
    /// Any failure duplicating the connection's handle.
    pub fn severer(&self) -> std::io::Result<Severer> {
        Severer::for_stream(self.reader.get())
    }

    /// Read the next request and its correlation id.
    ///
    /// # Errors
    ///
    /// [`FrameError::Closed`] when the host goes away, [`FrameError::InvalidBody`] when a frame
    /// was read in full but its body did not deserialize as a [`Request`] — the caller can answer
    /// that one against the recovered id rather than closing the connection — or any other wire
    /// failure.
    pub fn read_request(&mut self) -> Result<Envelope<Request>, FrameError> {
        frame::read(&mut self.reader)
    }

    /// Write a reply against `id`.
    ///
    /// # Errors
    ///
    /// Any wire failure.
    pub fn write_response(&mut self, id: &str, response: &Response) -> Result<(), FrameError> {
        frame::write(&mut *lock(&self.writer)?, &Envelope::new(id, response))
    }

    /// A handle another thread can send [`Push`]es to this host through.
    ///
    /// Cheap to clone, and safe to keep: it holds the writer weakly, so it never keeps the
    /// connection open after the connection is dropped — a send after that is
    /// [`FrameError::Closed`], not a write to a handle nobody is serving.
    ///
    /// Whether this session may be sent a push at all — it declared
    /// [`crate::protocol::Capability::AgentFill`] — is the caller's to check; this is only the
    /// means.
    ///
    /// On Windows the accepted pipe instance is read and written through one file object, so a
    /// push sent while the serving thread is parked in [`Self::read_request`] may wait for that
    /// read. Windows never offers agent fills (ADR-0036 §12), so nothing sends one there today.
    #[must_use]
    pub fn push_sender(&self) -> PushSender {
        PushSender {
            writer: Arc::downgrade(&self.writer),
        }
    }
}

/// Sends [`Push`]es to one connected native host. From [`HostConnection::push_sender`].
#[derive(Clone)]
pub struct PushSender {
    writer: Weak<Mutex<BufWriter<Closing>>>,
}

impl PushSender {
    /// Write `push` as one frame.
    ///
    /// # Errors
    ///
    /// [`FrameError::Closed`] once the connection has been dropped, or any wire failure.
    pub fn send(&self, push: &Push) -> Result<(), FrameError> {
        let writer = self.writer.upgrade().ok_or(FrameError::Closed)?;
        frame::write(&mut *lock(&writer)?, &PushEnvelope::new(push.clone()))
    }

    /// Whether the connection this sender belongs to is still held by its server.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.writer.strong_count() > 0
    }
}

impl std::fmt::Debug for PushSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushSender")
            .field("open", &self.is_open())
            .finish()
    }
}

/// Take the writer's lock.
///
/// A poisoned lock means a thread panicked part-way through a frame, and the stream may now hold
/// half of one. Nothing written after that could be read in sync, so it is refused rather than
/// sent.
fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, FrameError> {
    mutex.lock().map_err(|_| {
        FrameError::Io(std::io::Error::other(
            "a writer panicked mid-frame; the connection is no longer in sync",
        ))
    })
}

#[cfg(test)]
impl HostConnection {
    /// Write `body` as one frame, whatever it is: for tests of what a reader does with a frame
    /// this crate would never send.
    fn write_raw(&mut self, body: &[u8]) {
        use std::io::Write as _;
        let mut writer = lock(&self.writer).expect("writer");
        let len = u32::try_from(body.len()).expect("small");
        writer.write_all(&len.to_be_bytes()).expect("prefix");
        writer.write_all(body).expect("body");
        writer.flush().expect("flush");
    }
}

impl std::fmt::Debug for HostConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostConnection")
            .field("kind", &self.kind)
            .field("identity", &self.identity)
            .finish()
    }
}

/// Create the listener, asking for a `0600` socket where the platform can do it before `bind`.
///
/// The same fallback `kagisecure_ipc::server` needs: `ListenerOptionsExt::mode` is unsupported on
/// macOS, so we bind and chmod afterwards. The `0700` directory is the boundary either way.
///
/// On Windows the pipe is created with the same owner-only descriptor as the agent's —
/// `kagisecure_ipc::server::owner_only_pipe_descriptor`, shared rather than written twice,
/// since the two sockets sit side by side and a boundary that holds on one of them and not the
/// other is no boundary at all. That function documents the descriptor; `interprocess`'s
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance means a name someone else already holds
/// fails this bind rather than being joined.
///
/// The error goes through [`Endpoint::classify_bind_error`] for the same reason the agent's does:
/// "already being served" is `AddrInUse` on Unix and `PermissionDenied` on Windows, and
/// `kagisecure_agent`'s `ExtensionError::AlreadyBound` is keyed off the former.
fn bind_listener(endpoint: &Endpoint) -> std::io::Result<IpcListener> {
    #[cfg(unix)]
    {
        use interprocess::os::unix::local_socket::ListenerOptionsExt;
        match ListenerOptions::new()
            .name(endpoint.name()?)
            .mode(0o600)
            .create_sync()
        {
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
            other => return other.map_err(|e| endpoint.classify_bind_error(e)),
        }
    }
    #[cfg(windows)]
    {
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        ListenerOptions::new()
            .name(endpoint.name()?)
            .security_descriptor(kagisecure_ipc::server::owner_only_pipe_descriptor()?)
            .create_sync()
            .map_err(|e| endpoint.classify_bind_error(e))
    }
    #[cfg(not(windows))]
    ListenerOptions::new()
        .name(endpoint.name()?)
        .create_sync()
        .map_err(|e| endpoint.classify_bind_error(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::protocol::PROTOCOL_VERSION;

    #[cfg(unix)]
    #[test]
    fn the_socket_is_owner_only_inside_an_owner_only_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::Path(dir.path().join("run").join("extension.sock"));
        let listener = Listener::bind(&endpoint).expect("bind");
        let path = endpoint.path().unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        drop(listener);
    }

    /// The Windows counterpart of the test above: the extension pipe carries the same
    /// owner-only descriptor as the agent's, read back through a connected client handle.
    #[cfg(windows)]
    #[test]
    fn the_pipe_is_created_owner_only() {
        use kagisecure_core::windows_acl::{self, ObjectKind};
        use std::os::windows::io::AsHandle;

        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "extension-dacl");
        let listener = Listener::bind(&endpoint).expect("bind");
        let client = kagisecure_ipc::connect::open(&endpoint).expect("connect");
        let security = windows_acl::object_security(client.as_handle()).expect("read descriptor");
        let me = windows_acl::current_user_sid().unwrap();
        assert!(
            windows_acl::is_owner_only(&security, &me, ObjectKind::Pipe, true),
            "{security:?}"
        );
        assert!(kagisecure_ipc::client::server_is_same_user(&client));

        let connection = listener.accept().expect("accept");
        assert!(kagisecure_ipc::server::peer_is_same_user(
            connection.identity().euid,
            connection.identity().pid
        ));
    }

    #[test]
    fn a_second_bind_on_a_live_socket_fails_rather_than_stealing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "live.sock");
        let first = Listener::bind(&endpoint).expect("first");
        let second = Listener::bind(&endpoint);
        assert!(second.is_err(), "a live socket must not be replaced");
        drop(first);
    }

    #[test]
    fn a_round_trip_carries_the_correlation_id_and_the_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "rt.sock");
        let listener = Listener::bind(&endpoint).expect("bind");

        let server = std::thread::spawn(move || {
            let mut connection = listener.accept().expect("accept");
            // The kernel gave us a pid, and it is this test process — which is not a browser.
            assert_eq!(connection.identity().pid, Some(std::process::id()));
            assert!(!connection.identity().launched_by_browser());
            let request = connection.read_request().expect("request");
            assert_eq!(request.id, "call-1");
            assert_eq!(request.body, Request::Status);
            connection
                .write_response("call-1", &Response::Status { unlocked: true })
                .expect("respond");
        });

        let mut client = Client::connect(&endpoint).expect("connect");
        let response = client.call("call-1", &Request::Status).expect("call");
        assert_eq!(response, Response::Status { unlocked: true });
        server.join().expect("server thread");
    }

    #[test]
    fn a_reply_with_the_wrong_id_is_a_correlation_error_not_a_silent_accept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "mis.sock");
        let listener = Listener::bind(&endpoint).expect("bind");

        let server = std::thread::spawn(move || {
            let mut connection = listener.accept().expect("accept");
            let _ = connection.read_request().expect("request");
            connection
                .write_response("somebody-elses-call", &Response::Status { unlocked: true })
                .expect("respond");
        });

        let mut client = Client::connect(&endpoint).expect("connect");
        let err = client.call("mine", &Request::Status).unwrap_err();
        match err {
            ClientErrorAlias::Correlation { got, want } => {
                assert_eq!(got, "somebody-elses-call");
                assert_eq!(want, "mine");
            }
            other => panic!("expected a correlation error, got {other:?}"),
        }
        server.join().expect("server thread");
    }

    use crate::client::ClientError as ClientErrorAlias;

    #[test]
    fn a_hello_naming_a_future_protocol_version_is_still_readable_on_the_wire() {
        // Version negotiation is the service's job, not the transport's: the frame must decode so
        // the app can answer with a legible refusal instead of dropping the connection.
        let hello = Request::Hello {
            extension_id: "x".to_owned(),
            browser: "chrome".to_owned(),
            extension_version: "9.9.9".to_owned(),
            protocol_version: PROTOCOL_VERSION + 41,
            capabilities: vec![],
        };
        let mut buf = Vec::new();
        frame::write(&mut buf, &Envelope::new("h", &hello)).expect("write");
        let back: Envelope<Request> = frame::read(&mut buf.as_slice()).expect("read");
        assert_eq!(back.body, hello);
    }

    // ---------------------------------------------------------------------------------------
    // Pushes, and the duplex client that receives them.
    // ---------------------------------------------------------------------------------------

    use crate::client::ReadMode;
    use crate::protocol::Push;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    /// Long enough for anything on a local socket; short enough that a lost frame fails the test.
    const PATIENCE: Duration = Duration::from_secs(10);

    fn locate(probe_id: &str) -> Push {
        Push::Locate {
            probe_id: probe_id.to_owned(),
            origin: None,
        }
    }

    /// Bind a fresh endpoint and hand the accepted connection to `serve` on a thread.
    fn serve(
        name: &str,
        serve: impl FnOnce(HostConnection) + Send + 'static,
    ) -> (Endpoint, std::thread::JoinHandle<()>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), name);
        let listener = Listener::bind(&endpoint).expect("bind");
        let server = std::thread::spawn(move || serve(listener.accept().expect("accept")));
        (endpoint, server, dir)
    }

    fn duplex(
        endpoint: &Endpoint,
        mode: ReadMode,
    ) -> (crate::client::DuplexClient, Receiver<Push>) {
        Client::connect(endpoint)
            .expect("connect")
            .into_duplex_mode(mode)
            .expect("duplex")
    }

    #[test]
    fn a_push_that_lands_mid_call_is_delivered_and_not_taken_for_the_reply() {
        for mode in [ReadMode::Background, ReadMode::LockStep] {
            let (endpoint, server, _dir) = serve("mid.sock", |mut connection| {
                let pushes = connection.push_sender();
                let request = connection.read_request().expect("request");
                pushes.send(&locate("before-the-reply")).expect("push");
                connection
                    .write_response(&request.id, &Response::Status { unlocked: true })
                    .expect("respond");
                let request = connection.read_request().expect("second request");
                connection
                    .write_response(&request.id, &Response::Noted)
                    .expect("respond");
            });
            let (client, pushes) = duplex(&endpoint, mode);
            assert_eq!(
                client.call("c1", &Request::Status).expect("call"),
                Response::Status { unlocked: true },
                "{mode:?}"
            );
            assert_eq!(
                pushes.recv_timeout(PATIENCE).expect("the push"),
                locate("before-the-reply")
            );
            assert_eq!(
                client.call("c2", &Request::Status).expect("call"),
                Response::Noted
            );
            server.join().expect("server thread");
        }
    }

    #[test]
    fn a_push_reaches_an_idle_duplex_client() {
        // The case the reader thread exists for: nothing is in flight when the app rings.
        let (endpoint, server, _dir) = serve("idle.sock", |connection| {
            let pushes = connection.push_sender();
            pushes.send(&locate("p1")).expect("push");
            pushes
                .send(&Push::Deliver {
                    probe_id: "p1".to_owned(),
                    grant_id: "g1".to_owned(),
                })
                .expect("push");
            // Hold the connection until the client has both.
            std::thread::sleep(Duration::from_millis(200));
            drop(connection);
        });
        let (_client, pushes) = duplex(&endpoint, ReadMode::Background);
        assert_eq!(pushes.recv_timeout(PATIENCE).expect("first"), locate("p1"));
        assert_eq!(
            pushes.recv_timeout(PATIENCE).expect("second"),
            Push::Deliver {
                probe_id: "p1".to_owned(),
                grant_id: "g1".to_owned(),
            },
            "in the order they were sent"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn pushes_and_replies_from_different_threads_never_interleave() {
        const ROUNDS: usize = 200;
        let (endpoint, server, _dir) = serve("mix.sock", |mut connection| {
            let pushes = connection.push_sender();
            let pusher = std::thread::spawn(move || {
                for n in 0..ROUNDS {
                    pushes.send(&locate(&format!("p{n}"))).expect("push");
                }
            });
            for _ in 0..ROUNDS {
                let request = connection.read_request().expect("request");
                connection
                    .write_response(&request.id, &Response::Status { unlocked: true })
                    .expect("respond");
            }
            pusher.join().expect("pusher");
        });
        let (client, pushes) = duplex(&endpoint, ReadMode::Background);
        for n in 0..ROUNDS {
            assert_eq!(
                client
                    .call(&format!("c{n}"), &Request::Status)
                    .expect("call"),
                Response::Status { unlocked: true }
            );
        }
        for n in 0..ROUNDS {
            assert_eq!(
                pushes.recv_timeout(PATIENCE).expect("push"),
                locate(&format!("p{n}"))
            );
        }
        server.join().expect("server thread");
    }

    #[test]
    fn concurrent_calls_are_answered_by_id_not_by_arrival_order() {
        let (endpoint, server, _dir) = serve("order.sock", |mut connection| {
            let first = connection.read_request().expect("first");
            let second = connection.read_request().expect("second");
            // Answer them backwards, each with its own id echoed in the body.
            for request in [second, first] {
                connection
                    .write_response(
                        &request.id,
                        &Response::Matches {
                            origin: request.id.clone(),
                            items: vec![],
                        },
                    )
                    .expect("respond");
            }
        });
        let (client, _pushes) = duplex(&endpoint, ReadMode::Background);
        let client = std::sync::Arc::new(client);
        let callers: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|id| {
                let client = std::sync::Arc::clone(&client);
                std::thread::spawn(move || (id, client.call(id, &Request::Status).expect("call")))
            })
            .collect();
        for caller in callers {
            let (id, response) = caller.join().expect("caller");
            assert_eq!(
                response,
                Response::Matches {
                    origin: id.to_owned(),
                    items: vec![],
                }
            );
        }
        server.join().expect("server thread");
    }

    #[test]
    fn a_second_call_on_an_id_still_waiting_is_refused_before_it_is_sent() {
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (endpoint, server, _dir) = serve("dup.sock", move |mut connection| {
            let request = connection.read_request().expect("request");
            seen_tx.send(()).expect("signal");
            // Give the duplicate call time to be refused, then answer the first.
            std::thread::sleep(Duration::from_millis(100));
            connection
                .write_response(&request.id, &Response::Noted)
                .expect("respond");
        });
        let (client, _pushes) = duplex(&endpoint, ReadMode::Background);
        let client = std::sync::Arc::new(client);
        let first = {
            let client = std::sync::Arc::clone(&client);
            std::thread::spawn(move || client.call("x", &Request::Status))
        };
        seen_rx
            .recv_timeout(PATIENCE)
            .expect("the first call arrived");
        assert!(matches!(
            client.call("x", &Request::Status),
            Err(ClientErrorAlias::IdInUse(id)) if id == "x"
        ));
        assert_eq!(first.join().expect("first").expect("call"), Response::Noted);
        server.join().expect("server thread");
    }

    #[test]
    fn a_duplex_reply_nobody_asked_for_is_a_correlation_error() {
        for mode in [ReadMode::Background, ReadMode::LockStep] {
            let (endpoint, server, _dir) = serve("stray.sock", |mut connection| {
                let _ = connection.read_request().expect("request");
                connection
                    .write_response("somebody-elses-call", &Response::Status { unlocked: true })
                    .expect("respond");
                // Hanging up here is fine: the reply is already on the wire ahead of the close.
                // (Waiting for the client to hang up instead would wait forever in the background
                // mode, whose reader keeps the connection open until the app closes it.)
            });
            let (client, _pushes) = duplex(&endpoint, mode);
            match client.call("mine", &Request::Status) {
                Err(ClientErrorAlias::Correlation { got, want }) => {
                    assert_eq!(got, "somebody-elses-call", "{mode:?}");
                    assert_eq!(want, "mine");
                }
                other => panic!("{mode:?}: expected a correlation error, got {other:?}"),
            }
            drop(client);
            server.join().expect("server thread");
        }
    }

    #[test]
    fn a_malformed_app_frame_is_dropped_unless_a_call_is_waiting_on_its_id() {
        for mode in [ReadMode::Background, ReadMode::LockStep] {
            let (endpoint, server, _dir) = serve("junk.sock", |mut connection| {
                let first = connection.read_request().expect("request");
                // A frame with no id at all, then the real reply: the junk is skipped.
                connection.write_raw(br#"{"ksx":1,"push":{"push":"teleport"}}"#);
                connection
                    .write_response(&first.id, &Response::Noted)
                    .expect("respond");
                // A reply whose body does not parse, against the waiting call's id.
                let second = connection.read_request().expect("request");
                connection.write_raw(
                    format!(
                        r#"{{"ksx":1,"id":"{}","body":{{"reply":"nonsense"}}}}"#,
                        second.id
                    )
                    .as_bytes(),
                );
            });
            let (client, pushes) = duplex(&endpoint, mode);
            assert_eq!(
                client.call("c1", &Request::Status).expect("call"),
                Response::Noted,
                "{mode:?}"
            );
            assert!(matches!(
                client.call("c2", &Request::Status),
                Err(ClientErrorAlias::Frame(FrameError::InvalidBody { id: Some(id), .. })) if id == "c2"
            ));
            assert!(
                pushes.try_recv().is_err(),
                "the junk push was not delivered"
            );
            drop(client);
            server.join().expect("server thread");
        }
    }

    #[test]
    fn a_duplex_call_after_the_app_hangs_up_says_closed() {
        let (endpoint, server, _dir) = serve("gone.sock", drop);
        let (client, _pushes) = duplex(&endpoint, ReadMode::Background);
        server.join().expect("server thread");
        assert!(matches!(
            client.call("late", &Request::Status),
            Err(ClientErrorAlias::Frame(_))
        ));
    }

    #[test]
    fn a_push_sender_does_not_keep_its_connection_open() {
        let (endpoint, server, _dir) = serve("weak.sock", |connection| {
            let pushes = connection.push_sender();
            assert!(pushes.is_open());
            drop(connection);
            assert!(!pushes.is_open());
            assert!(matches!(pushes.send(&locate("p")), Err(FrameError::Closed)));
        });
        let (client, pushes) = duplex(&endpoint, ReadMode::Background);
        server.join().expect("server thread");
        // The connection is really gone from the client's side too: the reader saw it close.
        assert!(matches!(
            client.call("after", &Request::Status),
            Err(ClientErrorAlias::Frame(_))
        ));
        assert!(pushes.try_recv().is_err());
    }
}

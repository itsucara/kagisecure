//! The app's half: bind the extension socket, accept, and identify what connected.
//!
//! Mirrors `kagisecure_ipc::server` in shape — a `0700` directory, a `0600` socket, a non-blocking
//! accept so a host that has to quit can — and differs in exactly two places: the frame format
//! ([`crate::frame`], big-endian) and the identity ([`HostIdentity`], which resolves one hop up
//! the process tree).

use std::io::BufWriter;

use interprocess::local_socket::traits::{Listener as _, Stream as _, StreamCommon as _};
use interprocess::local_socket::{Listener as IpcListener, ListenerOptions, Stream};
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};

use crate::frame::{self, FrameError};
use crate::peer::{HostIdentity, HostKind};
use crate::protocol::{Envelope, Request, Response};

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
        if let Some(path) = endpoint.path()
            && path.exists()
            && Stream::connect(endpoint.name().map_err(|source| EndpointError::Io {
                path: path.to_path_buf(),
                source,
            })?)
            .is_err()
        {
            let _ = std::fs::remove_file(path);
        }

        let socket_path = endpoint
            .path()
            .unwrap_or(std::path::Path::new(""))
            .to_path_buf();
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
        let stream = self.listener.accept()?;
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
        let pid = kagisecure_ipc::kernel_peer::peer_pid(&stream).or_else(|| {
            creds
                .as_ref()
                .and_then(interprocess::local_socket::PeerCreds::pid)
                .and_then(|p| u32::try_from(p).ok())
        });
        let identity = HostIdentity::resolve_kind(self.kind, pid, euid);
        let reader = {
            use interprocess::TryClone;
            TryClone::try_clone(&stream)?
        };
        Ok(HostConnection {
            reader,
            writer: BufWriter::new(stream),
            identity,
            kind: self.kind,
        })
    }
}

/// One connected native host.
pub struct HostConnection {
    reader: Stream,
    writer: BufWriter<Stream>,
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

    /// Read the next request and its correlation id.
    ///
    /// # Errors
    ///
    /// [`FrameError::Closed`] when the host goes away, or any wire failure.
    pub fn read_request(&mut self) -> Result<Envelope<Request>, FrameError> {
        frame::read(&mut self.reader)
    }

    /// Write a reply against `id`.
    ///
    /// # Errors
    ///
    /// Any wire failure.
    pub fn write_response(&mut self, id: &str, response: &Response) -> Result<(), FrameError> {
        frame::write(&mut self.writer, &Envelope::new(id, response))
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
            other => return other,
        }
    }
    ListenerOptions::new().name(endpoint.name()?).create_sync()
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

    #[test]
    fn a_second_bind_on_a_live_socket_fails_rather_than_stealing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::Path(dir.path().join("live.sock"));
        let first = Listener::bind(&endpoint).expect("first");
        let second = Listener::bind(&endpoint);
        assert!(second.is_err(), "a live socket must not be replaced");
        drop(first);
    }

    #[test]
    fn a_round_trip_carries_the_correlation_id_and_the_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::Path(dir.path().join("rt.sock"));
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
        let endpoint = Endpoint::Path(dir.path().join("mis.sock"));
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
        };
        let mut buf = Vec::new();
        frame::write(&mut buf, &Envelope::new("h", &hello)).expect("write");
        let back: Envelope<Request> = frame::read(&mut buf.as_slice()).expect("read");
        assert_eq!(back.body, hello);
    }
}

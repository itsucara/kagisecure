//! The listening half of the protocol, plus caller verification.
//!
//! # What "verified" means in M2
//!
//! threat-model M-19 wants the peer's pid from the socket and then that process's **code
//! signature**. Signature checking is M3+ (it needs the app bundle and `SecCode*`), so what this
//! module does is the part that is available without it:
//!
//! * the peer's **effective uid** comes from the kernel via `SO_PEERCRED`/`LOCAL_PEERCRED` and is
//!   a hard requirement — a connection from another local user is refused, not warned about;
//! * the peer's **pid** comes from the kernel: `interprocess`'s own `peer_creds()` on Linux and
//!   the BSDs, and [`crate::kernel_peer`]'s `LOCAL_PEERPID` on macOS, whose `xucred` carries no
//!   pid for `interprocess` to read. Only when both of those come back empty — a syscall failure,
//!   or a platform neither covers — does the identity fall back to the sidecar's **self-reported**
//!   pid, and the identity is marked *unverified*;
//! * the pid is resolved to an executable path for display and for the audit log: `/proc/<pid>/exe`
//!   on Linux, `proc_pidpath` (also [`crate::kernel_peer`]) on macOS, `ps -o comm=` elsewhere.
//!
//! The approval prompt says which of those it is, in those words. See ADR-0007.

use std::io::BufWriter;

use interprocess::local_socket::traits::{Listener as _, Stream as _, StreamCommon as _};
use interprocess::local_socket::{Listener, ListenerOptions, Stream};

use crate::endpoint::{Endpoint, EndpointError};
use crate::frame::{self, FrameError};
use crate::protocol::{ClientInfo, Request, Response};

/// What the daemon knows about a connected caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer's process id, from the kernel when the platform provides it.
    pub pid: Option<u32>,
    /// The peer's effective uid, from the kernel.
    pub euid: Option<u32>,
    /// Whether [`PeerIdentity::pid`] came from the kernel rather than from the peer itself.
    pub pid_from_kernel: bool,
    /// The executable behind that pid, resolved for display.
    pub executable: Option<String>,
    /// The peer's self-reported description, display-only.
    pub reported: Option<ClientInfo>,
}

impl PeerIdentity {
    /// Whether this identity was established by the kernel rather than taken on trust.
    ///
    /// In M2 this is `false` on macOS by construction. It becomes meaningful in M3+, when the
    /// app checks a code signature.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.pid_from_kernel && self.executable.is_some()
    }

    /// A one-line rendering for the approval prompt and the audit log.
    ///
    /// Deliberately shows the self-reported name in quotes and the verified facts bare, so a
    /// caller that calls itself `"Claude Code (verified)"` cannot borrow the word.
    #[must_use]
    pub fn describe(&self) -> String {
        let reported = self
            .reported
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |c| format!("{:?}", c.name));
        let exe = self.executable.as_deref().unwrap_or("unknown executable");
        let pid = self.pid.map_or_else(|| "?".to_owned(), |p| p.to_string());
        let trust = if self.verified() {
            "verified"
        } else {
            "UNVERIFIED"
        };
        format!("{reported} [{trust}] pid {pid} {exe}")
    }
}

/// A bound listener.
pub struct Server {
    listener: Listener,
    endpoint: Endpoint,
}

impl Server {
    /// Bind to `endpoint`, creating a `0700` directory and a `0600` socket.
    ///
    /// A stale socket file from a daemon that died without cleaning up is replaced; a socket that
    /// a *live* daemon is listening on is not, so the second daemon fails loudly instead of
    /// silently stealing the first one's callers.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] if the directory cannot be prepared or the socket cannot be created.
    pub fn bind(endpoint: &Endpoint) -> Result<Self, EndpointError> {
        endpoint.prepare_dir()?;
        if let Some(path) = endpoint.path()
            && path.exists()
            && Stream::connect(endpoint.name().map_err(|source| EndpointError::Io {
                path: path.to_path_buf(),
                source,
            })?)
            .is_err()
        {
            // Nothing answered: this is a corpse socket, not a running daemon.
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
            // Belt to the directory's braces. The `0700` directory is what actually keeps other
            // local users out (threat-model M-13); this narrows the socket itself as well, on
            // the platforms where it was not already set before `bind`.
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(Self {
            listener,
            endpoint: endpoint.clone(),
        })
    }

    /// Where this server is listening.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Make `accept` return [`ErrorKind::WouldBlock`](std::io::ErrorKind::WouldBlock) instead of
    /// parking, leaving accepted streams blocking.
    ///
    /// A host that has to be able to *stop* — the macOS app quitting, or a test dropping its
    /// agent — cannot be left with a thread parked in `accept()` forever, and there is no
    /// portable way to interrupt one. Polling with a short sleep is the cost of being able to
    /// shut down deterministically; the accepted connections stay blocking, because a connection
    /// handler wants to wait for its next request.
    ///
    /// # Errors
    ///
    /// Any I/O failure from the underlying `fcntl`/`ioctl`.
    pub fn set_accept_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        use interprocess::local_socket::ListenerNonblockingMode;
        self.listener.set_nonblocking(if nonblocking {
            ListenerNonblockingMode::Accept
        } else {
            ListenerNonblockingMode::Neither
        })
    }

    /// Accept the next connection.
    ///
    /// # Errors
    ///
    /// Any I/O failure from `accept`, including
    /// [`WouldBlock`](std::io::ErrorKind::WouldBlock) after
    /// [`set_accept_nonblocking`](Self::set_accept_nonblocking).
    pub fn accept(&self) -> std::io::Result<Connection> {
        let stream = self.listener.accept()?;
        // BSD `accept()` — macOS included — hands the new socket the listener's `O_NONBLOCK`,
        // where Linux does not. A connection handler wants to block on its next request, so the
        // flag is cleared here rather than left to differ by platform.
        stream.set_nonblocking(false)?;
        let identity = peer_identity(&stream);
        let reader = {
            use interprocess::TryClone;
            TryClone::try_clone(&stream)?
        };
        Ok(Connection {
            reader,
            writer: BufWriter::new(stream),
            identity,
        })
    }
}

/// One accepted connection.
pub struct Connection {
    reader: Stream,
    writer: BufWriter<Stream>,
    identity: PeerIdentity,
}

impl Connection {
    /// What the kernel says about the caller.
    #[must_use]
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Fold the caller's self-reported description into the identity, for display only.
    ///
    /// When the kernel did not give us a pid (macOS), the self-reported one is adopted so the
    /// executable can be resolved for the prompt — and [`PeerIdentity::verified`] stays `false`,
    /// which is exactly the honest answer.
    pub fn adopt_reported(&mut self, reported: ClientInfo) {
        if self.identity.pid.is_none() {
            self.identity.pid = Some(reported.pid);
            self.identity.executable = executable_for_pid(reported.pid);
        }
        self.identity.reported = Some(reported);
    }

    /// Read the next request.
    ///
    /// # Errors
    ///
    /// [`FrameError::Closed`] when the peer goes away, or any wire failure.
    pub fn read_request(&mut self) -> Result<Request, FrameError> {
        frame::read(&mut self.reader)
    }

    /// Write a reply.
    ///
    /// # Errors
    ///
    /// Any wire failure.
    pub fn write_response(&mut self, response: &Response) -> Result<(), FrameError> {
        frame::write(&mut self.writer, response)
    }
}

/// Create the listener, asking for a `0600` socket where the platform can do it before `bind`.
///
/// `ListenerOptionsExt::mode` performs an `fchmod` prior to `bind`, which closes a umask race —
/// but only Linux, OpenBSD and recent FreeBSD support it, and macOS returns
/// [`ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported). Rather than refuse to run on the
/// project's primary platform, we fall back to binding without it and chmod-ing afterwards. The
/// containing directory is `0700` either way, which is the boundary that matters.
fn bind_listener(endpoint: &Endpoint) -> std::io::Result<Listener> {
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

fn peer_identity(stream: &Stream) -> PeerIdentity {
    let creds = stream.peer_creds().ok();
    // Windows named pipes have no effective uid to report.
    #[cfg(unix)]
    let euid = creds
        .as_ref()
        .and_then(interprocess::local_socket::PeerCreds::euid);
    #[cfg(not(unix))]
    let euid = None;
    // `kernel_peer::peer_pid` is the kernel-verified source (macOS `LOCAL_PEERPID`, Linux
    // `SO_PEERCRED`). Where it has no implementation — the BSDs, today — fall back to
    // `interprocess`'s own `peer_creds()`, which reaches the same kernel fact on those
    // platforms (ADR-0007 §3). Either way this is a kernel answer, never the peer's own word.
    let pid = crate::kernel_peer::peer_pid(stream).or_else(|| {
        creds
            .as_ref()
            .and_then(interprocess::local_socket::PeerCreds::pid)
            .and_then(|p| u32::try_from(p).ok())
    });
    PeerIdentity {
        executable: pid.and_then(executable_for_pid),
        pid,
        euid,
        pid_from_kernel: pid.is_some(),
        reported: None,
    }
}

/// Resolve a pid to an executable path.
///
/// `/proc/<pid>/exe` on Linux and `proc_pidpath` ([`crate::kernel_peer`]) on macOS are both
/// kernel-backed and preferred; `ps -o comm=` is the fallback for everything else (and for the
/// rare case either of those fails).
#[must_use]
pub fn executable_for_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(path) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            return Some(path.display().to_string());
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(path) = crate::kernel_peer::executable_path(pid) {
            return Some(path);
        }
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("/bin/ps")
            .args(["-o", "comm=", "-p"])
            .arg(pid.to_string())
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(trimmed.to_owned())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// The uid this process runs as, for the same-user check.
///
/// Derived without FFI by looking at a file this process certainly owns.
#[cfg(unix)]
#[must_use]
pub fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let dir = std::env::temp_dir();
    let probe = dir.join(format!("kagisecure-uid-{}", std::process::id()));
    let uid = std::fs::File::create(&probe)
        .ok()
        .and_then(|f| f.metadata().ok())
        .map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    uid
}

/// Windows has no uid; the pipe's DACL is what restricts the caller there.
#[cfg(not(unix))]
#[must_use]
pub fn own_uid() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unverified_identity_says_so_in_its_description() {
        let identity = PeerIdentity {
            pid: Some(4242),
            euid: Some(501),
            pid_from_kernel: false,
            // A plausible absolute path for `describe()` to render — not asserted on verbatim.
            // The bundled location (ADR-0026) rather than a Homebrew-style one, since that is
            // where this executable actually lives today.
            executable: Some(
                "/Applications/Kagisecure.app/Contents/Helpers/kagisecure-mcp".to_owned(),
            ),
            reported: Some(ClientInfo {
                name: "Claude Code (verified)".to_owned(),
                version: "1".to_owned(),
                pid: 4242,
                parent_pid: None,
                argv0: "kagisecure-mcp".to_owned(),
                cwd: None,
            }),
        };
        assert!(!identity.verified());
        let described = identity.describe();
        assert!(described.contains("UNVERIFIED"), "{described}");
        assert!(
            described.contains("\"Claude Code (verified)\""),
            "a self-reported name is quoted so it cannot pass itself off as our own label: {described}"
        );
        assert!(described.contains("4242"));
    }

    #[test]
    fn a_kernel_supplied_pid_with_an_executable_is_verified() {
        let identity = PeerIdentity {
            pid: Some(1),
            euid: Some(0),
            pid_from_kernel: true,
            executable: Some("/sbin/launchd".to_owned()),
            reported: None,
        };
        assert!(identity.verified());
        assert!(identity.describe().contains("verified"));
    }

    #[cfg(unix)]
    #[test]
    fn this_process_can_learn_its_own_uid() {
        assert!(own_uid().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_pid_resolves_to_an_executable() {
        assert!(executable_for_pid(std::process::id()).is_some());
    }

    #[test]
    fn an_impossible_pid_resolves_to_nothing() {
        assert_eq!(executable_for_pid(u32::MAX), None);
    }
}

//! The listening half of the protocol, plus caller verification.
//!
//! # What "verified" means in M2
//!
//! threat-model M-19 wants the peer's pid from the socket and then that process's **code
//! signature**. Signature checking is M3+ (it needs the app bundle and `SecCode*`), so what this
//! module does is the part that is available without it:
//!
//! * the peer's **effective uid** comes from the kernel via `SO_PEERCRED`/`LOCAL_PEERCRED` and is
//!   a hard requirement — a connection from another local user is refused, not warned about. A
//!   Windows named pipe carries no uid; there the pipe is created with an owner-only DACL, and
//!   the same gate compares the account in the peer process's token with this one's instead
//!   (see [`peer_is_same_user`]);
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
use std::path::Path;

use interprocess::local_socket::traits::{Listener as _, Stream as _, StreamCommon as _};
use interprocess::local_socket::{Listener, ListenerOptions, Stream};

use crate::endpoint::{Endpoint, EndpointError};
use crate::frame::{self, FrameError};
use crate::protocol::{ClientInfo, Request, Response};
use crate::sever::{Closing, Severer};

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

    /// The pid, only if the kernel supplied it — never one adopted from the peer's own report.
    ///
    /// This is what [`peer_is_same_user`] takes: on Windows the same-user decision is made from
    /// the pid, and a pid the peer merely *claimed* must not be able to name somebody else's
    /// process as its own.
    #[must_use]
    pub fn kernel_pid(&self) -> Option<u32> {
        self.pid.filter(|_| self.pid_from_kernel)
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
        // The probe goes through `crate::connect` like every other client-side open, so that
        // it can neither wait without bound nor be impersonated on the one platform where either
        // is possible. On Unix it is the same `connect(2)` it always was.
        if let Some(path) = endpoint.path()
            && path.exists()
        {
            // An endpoint that cannot even be named is an error, not a file to delete.
            endpoint.name().map_err(|source| EndpointError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            if crate::connect::open(endpoint).is_err() {
                // Nothing answered: this is a corpse socket, not a running daemon.
                let _ = std::fs::remove_file(path);
            }
        }

        // A namespaced endpoint has no path, and reporting the empty string for it produced
        // "i/o error preparing : ..." — the one line that says *where* said nothing. The pipe
        // name is what a Windows user would recognize, so that is what goes in. Identical for a
        // `Path` endpoint, which is every endpoint on Unix.
        let socket_path = endpoint.path().map_or_else(
            || std::path::PathBuf::from(endpoint.to_string()),
            Path::to_path_buf,
        );
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
        // Held in `Closing` from the start, so every way out of this function — and every way a
        // `Connection` is dropped later — closes the handle there and then. See
        // `crate::sever::Closing` for why `interprocess` would not.
        let accepted = Closing::new(self.listener.accept()?);
        let stream = accepted.get();
        // BSD `accept()` — macOS included — hands the new socket the listener's `O_NONBLOCK`,
        // where Linux does not. A connection handler wants to block on its next request, so the
        // flag is cleared here rather than left to differ by platform.
        stream.set_nonblocking(false)?;
        let identity = peer_identity(stream);
        let reader = {
            use interprocess::TryClone;
            Closing::new(TryClone::try_clone(stream)?)
        };
        Ok(Connection {
            reader,
            writer: BufWriter::new(accepted),
            identity,
        })
    }
}

/// One accepted connection.
///
/// Dropping it closes both of its handles before the drop returns, on every platform.
pub struct Connection {
    reader: Closing,
    writer: BufWriter<Closing>,
    identity: PeerIdentity,
}

impl Connection {
    /// A [`Severer`] for this connection: the means for another thread to end it.
    ///
    /// Take it at accept time and keep it where a stop can reach it — a
    /// [`crate::sever::LiveConnections`]. A host that stops without severing the connections it
    /// accepted has not let go of its endpoint: on Windows the pipe name outlives the listener
    /// for as long as any accepted instance is open, and the next bind on it is refused. See
    /// [`crate::sever`].
    ///
    /// # Errors
    ///
    /// Any failure duplicating the connection's handle.
    pub fn severer(&self) -> std::io::Result<Severer> {
        Severer::for_stream(self.reader.get())
    }

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
///
/// # Windows: the pipe's owner-only DACL attaches here
///
/// There is no directory and no mode on Windows; the pipe's own security descriptor is the whole
/// boundary, so it is set at creation through `ListenerOptionsExt::security_descriptor` —
/// `owner_only_pipe_descriptor`, shared with `kagisecure_extension_ipc::listener`, since a
/// boundary on one of the two sockets and not the other is no boundary. `interprocess` creates
/// the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so if *anyone* — another user
/// included — already holds the name, this bind fails rather than joining their pipe as a
/// further instance; and every further instance this listener creates while accepting is
/// governed by the first instance's descriptor, which grants `FILE_CREATE_PIPE_INSTANCE` to
/// this user alone.
///
/// The error is passed through [`Endpoint::classify_bind_error`] so that "someone is already
/// listening there" reaches the host as [`ErrorKind::AddrInUse`](std::io::ErrorKind::AddrInUse)
/// on both platforms; Windows reports that case as `PermissionDenied`.
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
            other => return other.map_err(|e| endpoint.classify_bind_error(e)),
        }
    }
    #[cfg(windows)]
    {
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        ListenerOptions::new()
            .name(endpoint.name()?)
            .security_descriptor(owner_only_pipe_descriptor()?)
            .create_sync()
            .map_err(|e| endpoint.classify_bind_error(e))
    }
    #[cfg(not(windows))]
    ListenerOptions::new()
        .name(endpoint.name()?)
        .create_sync()
        .map_err(|e| endpoint.classify_bind_error(e))
}

/// The security descriptor every named pipe this project listens on is created with.
///
/// `O:<user SID>D:P(A;;FA;;;<user SID>)` — owned by the account this process runs as, a DACL
/// protected from inheritance, and one entry: full access for that account and nobody else. Not
/// SYSTEM and not Administrators: `kagisecure_core::windows_acl` gives the reasoning, which is
/// the same for a pipe as for the vault file. Built there, as SDDL, and parsed here by
/// `interprocess`'s own `SecurityDescriptor::deserialize`, so this crate needs no `unsafe` for
/// it. No `G:` (group) component, deliberately: `interprocess` 2.4.4's descriptor clone copies a
/// group SID into the *owner* slot (`security_descriptor/try_clone.rs`), and it clones this
/// descriptor for every pipe instance it creates.
///
/// Before this existed the pipe was created with no descriptor at all, i.e. the default one
/// `CreateNamedPipeW` documents — full control for SYSTEM, Administrators and the creator,
/// *read* access for Everyone and Anonymous — and nothing narrowed it.
///
/// # Errors
///
/// Any failure reading this process's token, or parsing the descriptor.
#[cfg(windows)]
pub fn owner_only_pipe_descriptor()
-> std::io::Result<interprocess::os::windows::security_descriptor::SecurityDescriptor> {
    use kagisecure_core::windows_acl::{ObjectKind, owner_only_sddl};
    let sddl = widestring::U16CString::from_str(owner_only_sddl(ObjectKind::Pipe)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    interprocess::os::windows::security_descriptor::SecurityDescriptor::deserialize(&sddl)
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
    // `interprocess`'s `Pid` is `i32` on Unix and `u32` on Windows, so this conversion is a
    // real narrowing on one platform and a no-op on the other. Writing it once and allowing
    // the lint beats two `cfg` arms of the same expression.
    #[allow(
        clippy::useless_conversion,
        reason = "`Pid` is already `u32` on Windows; it is `i32` everywhere else"
    )]
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
/// `/proc/<pid>/exe` on Linux, `proc_pidpath` ([`crate::kernel_peer`]) on macOS and
/// `QueryFullProcessImageNameW` (also [`crate::kernel_peer`]) on Windows are all kernel-backed
/// and preferred; `ps -o comm=` is the fallback for everything else (and for the rare case any
/// of those fails).
///
/// Note what the Windows answer buys: [`PeerIdentity::verified`] requires *both* a kernel pid
/// and a resolved executable, so while this returned `None` there, every named-pipe connection
/// was unverified no matter what the kernel said about it.
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
    #[cfg(windows)]
    {
        crate::kernel_peer::executable_path(pid)
    }
    #[cfg(unix)]
    {
        let out = ps_command()?
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
    // Neither Unix nor Windows: nothing to ask. `None` here means "unverified", never "pid 0".
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        None
    }
}

/// When `pid` started, as an opaque value that only means something compared with another answer
/// of this function for the same pid.
///
/// A pid alone names whichever process holds it *now*, and every process that runs the same
/// program has the same executable; the start time is what tells the process a caller saw
/// earlier from a newcomer that was handed its pid after it exited. Asked of the kernel:
///
/// * **macOS** — `proc_pidinfo(PROC_PIDTBSDINFO)`'s start time, in microseconds
///   ([`crate::kernel_peer`]);
/// * **Linux** — field 22 of `/proc/<pid>/stat`, `starttime`, in clock ticks since boot;
/// * **everywhere else, Windows included** — `None`: not implemented. A caller must then fall back
///   to what it checked without it (the pid and its executable), and say so where it documents
///   what it binds to.
///
/// `None` also means the process is gone or could not be asked.
#[must_use]
pub fn process_start_time(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        start_time_from_stat(&stat)
    }
    #[cfg(target_os = "macos")]
    {
        crate::kernel_peer::process_start_time(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// `starttime` out of one `/proc/<pid>/stat` line (`proc(5)`): the 22nd field. The second field
/// is the command name in parentheses, which may itself contain spaces and parentheses, so the
/// count starts after the **last** `)` — where the third field begins.
#[cfg(any(target_os = "linux", test))]
fn start_time_from_stat(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_ascii_whitespace().nth(22 - 3)?.parse().ok()
}

/// Absolute locations `ps` is known to live at, tried in order.
///
/// A fixed list rather than a `PATH` lookup: this runs on the process-ancestry path that
/// underpins peer identity, and an attacker-influenced `PATH` could otherwise redirect it to a
/// binary of their choosing, whereas these absolute paths cannot be. `/bin/ps` — correct on
/// macOS and Linux, where this is only reached as a fallback — stays first so behavior there is
/// unchanged; `/usr/bin/ps` and `/system/bin/ps` cover the BSDs and Android, where it is the
/// only path.
#[cfg(unix)]
fn ps_command() -> Option<std::process::Command> {
    ["/bin/ps", "/usr/bin/ps", "/system/bin/ps"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
        .map(std::process::Command::new)
}

/// The effective uid this process runs as, for the same-user check.
///
/// Asked of the kernel with `geteuid(2)` through [`crate::kernel_peer`], the one module in this
/// crate allowed to use FFI. It never touches the filesystem and is always `Some` on a Unix
/// build, which is what the same-user gate needs: see [`peer_is_same_user`].
#[cfg(unix)]
#[must_use]
pub fn own_uid() -> Option<u32> {
    Some(crate::kernel_peer::own_euid())
}

/// Windows has no uid. The same-user gate there compares SIDs instead — see
/// [`peer_is_same_user`] — so this is `None` by construction and nothing gates on it.
#[cfg(not(unix))]
#[must_use]
pub fn own_uid() -> Option<u32> {
    None
}

/// Whether the peer is the same local user as this process.
///
/// `peer_euid` is the kernel's uid for the peer, and is what Unix compares. `peer_pid` must be
/// the **kernel-supplied** pid ([`PeerIdentity::kernel_pid`], or `HostIdentity::pid` on the
/// extension socket), never a self-reported one, and is what Windows compares. Each platform
/// ignores the argument it has no use for; both are taken so that every caller makes the one
/// call on every platform and cannot forget the half that matters where it runs.
///
/// **This fails closed, on every platform.** On Unix, a peer whose uid could not be established
/// — `SO_PEERCRED`/`LOCAL_PEERCRED` failed, or the connection carries no credentials at all — is
/// *not* the same user as far as this function is concerned. The gate it backs is documented as
/// "a hard gate rather than a warning" (threat-model M-13/M-15), and a gate that evaporates when
/// its input is missing is a warning at best. The previous shape, `if let (Some(peer),
/// Some(mine))`, skipped the comparison whenever either side was unknown.
///
/// On Windows a named pipe has no uid, and this used to answer `true` there outright. It now
/// compares the user SID in the peer process's token
/// (`kernel_peer::process_user_sid`) with the one in this process's own, and answers
/// `false` when there is no kernel pid, when the peer process cannot be opened or its token read
/// — which is what happens for another account's process — or when the SIDs differ. It is the
/// second of two walls: the first is the pipe's owner-only DACL
/// (`owner_only_pipe_descriptor`), which keeps another account from connecting at all. What
/// the second one cannot do is rule out pid reuse between the connection and this check; see
/// `kernel_peer::process_user_sid` for the exact window.
///
/// A platform that is neither answers `false`: there is no identity to compare there.
#[must_use]
pub fn peer_is_same_user(peer_euid: Option<u32>, peer_pid: Option<u32>) -> bool {
    #[cfg(unix)]
    {
        let _ = peer_pid;
        matches!((peer_euid, own_uid()), (Some(peer), Some(mine)) if peer == mine)
    }
    #[cfg(windows)]
    {
        let _ = peer_euid;
        let Some(pid) = peer_pid else {
            return false;
        };
        match (
            crate::kernel_peer::process_user_sid(pid),
            kagisecure_core::windows_acl::current_user_sid(),
        ) {
            (Some(peer), Ok(mine)) => peer == mine,
            _ => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (peer_euid, peer_pid);
        false
    }
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
    fn the_same_user_gate_fails_closed_on_an_unknown_peer() {
        assert!(peer_is_same_user(own_uid(), None));
        assert!(
            !peer_is_same_user(None, Some(std::process::id())),
            "a peer whose uid the kernel would not report must be refused, not waved through"
        );
        let someone_else = own_uid().map(|u| u.wrapping_add(1));
        assert!(!peer_is_same_user(someone_else, None));
    }

    #[cfg(windows)]
    #[test]
    fn the_same_user_gate_compares_token_sids_on_windows() {
        assert!(
            peer_is_same_user(None, Some(std::process::id())),
            "this process is the same user as itself"
        );
        assert!(
            !peer_is_same_user(Some(0), None),
            "no kernel pid means no answer, and no answer means no"
        );
        assert!(
            !peer_is_same_user(None, Some(u32::MAX)),
            "a pid that names no process must be refused"
        );
        // Pid 4 is always the System process: another account (or unreadable, which is the
        // same answer), whatever this test runs as.
        assert!(!peer_is_same_user(None, Some(4)));
    }

    /// The pipe `Server::bind` creates carries exactly the owner-only descriptor, read back the
    /// way a client sees it — through a connected client handle, which is what
    /// `client::server_is_same_user` also looks at.
    #[cfg(windows)]
    #[test]
    fn the_pipe_is_created_owner_only() {
        use kagisecure_core::windows_acl::{self, ObjectKind};

        let dir = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(dir.path(), "dacl-test");
        let server = Server::bind(&endpoint).unwrap();
        let client = crate::connect::open(&endpoint).unwrap();

        let security = {
            use std::os::windows::io::AsHandle;
            windows_acl::object_security(client.as_handle()).unwrap()
        };
        let me = windows_acl::current_user_sid().unwrap();
        assert!(
            windows_acl::is_owner_only(&security, &me, ObjectKind::Pipe, true),
            "{security:?}"
        );
        assert!(crate::client::server_is_same_user(&client));

        // And the server end sees this very process as the same user.
        let connection = server.accept().unwrap();
        assert_eq!(connection.identity().kernel_pid(), Some(std::process::id()));
        assert!(peer_is_same_user(
            connection.identity().euid,
            connection.identity().kernel_pid()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_pid_resolves_to_an_executable() {
        assert!(executable_for_pid(std::process::id()).is_some());
    }

    #[test]
    fn an_impossible_pid_resolves_to_nothing() {
        assert_eq!(executable_for_pid(u32::MAX), None);
        assert_eq!(process_start_time(u32::MAX), None);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn this_process_has_a_start_time_that_does_not_change() {
        let own = process_start_time(std::process::id()).expect("a start time");
        assert_eq!(process_start_time(std::process::id()), Some(own));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_process_started_later_does_not_start_before_this_one() {
        let own = process_start_time(std::process::id()).expect("a start time");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        let started = process_start_time(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let started = started.expect("the child's start time");
        assert!(started >= own, "child {started}, this process {own}");
        assert_ne!(
            process_start_time(child.id()),
            Some(started),
            "a reaped child's pid names nothing now, or a process that started later"
        );
    }

    #[test]
    fn the_start_time_is_the_twenty_second_field_of_a_stat_line() {
        // A command name with spaces and a closing parenthesis of its own.
        let line = "4242 (evil) 1 2 3) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 \
                    987654 1000000 200 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(start_time_from_stat(line), Some(987_654));
        assert_eq!(
            start_time_from_stat("4242 (no closing parenthesis S 1"),
            None
        );
        assert_eq!(start_time_from_stat("4242 (short) S 1 2"), None);
    }
}

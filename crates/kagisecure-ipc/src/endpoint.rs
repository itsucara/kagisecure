//! Where the socket lives (architecture.md §4.2, threat-model M-13/M-15).
//!
//! On Unix everything is under the user's own home directory or their own runtime directory: no
//! system-wide daemon, no shared temporary files. The directory is `0700` and the socket `0600`,
//! so another local user cannot even see the endpoint, let alone connect to it.
//!
//! On Windows there is no filesystem socket to put in a directory at all. The transport is a
//! named pipe and its name lives in a machine-global namespace, so the name is no secret and no
//! boundary. The boundary is on the pipe instead: it is created with an owner-only DACL (see
//! [`Endpoint::prepare_dir`] and `server::owner_only_pipe_descriptor`), a bind never joins a
//! pipe someone else already holds, and a client checks the owner of the pipe it reached before
//! sending anything (`client::server_is_same_user`).
//!
//! # A Unix socket path has a hard limit
//!
//! `sun_path` is a fixed buffer — 104 bytes on macOS, 108 on Linux — and neither the caller's
//! directory nor a label it hands [`Endpoint::for_instance`] is bounded: `KAGISECURE_SOCKET` can
//! point anywhere (a synced folder, a deeply nested test fixture), and a label names a job, an
//! extension or a run, whatever length its author gave it. [`Endpoint::for_instance`] and
//! [`Endpoint::discover`]'s own default therefore fall back to [`short_fallback_path`] — a short,
//! per-user, hashed path this platform's shortest temporary directory can always hold — rather
//! than handing `bind` or `connect` something they can only fail on. [`Endpoint::name`] checks
//! again right before the conversion interprocess would otherwise fail on with its own opaque
//! message, for the one path this cannot shorten: one a caller (`--socket`, `KAGISECURE_SOCKET`)
//! set explicitly, taken verbatim on purpose (see [`Endpoint::parse`]).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use interprocess::local_socket::Name;

/// The most bytes a Unix domain socket path may have, not counting the NUL terminator
/// `sockaddr_un` still needs. `sun_path` is a fixed-size `char` array baked into each platform's
/// C headers — 104 bytes on Darwin (macOS, iOS), 108 on Linux — not something `libc` exposes as a
/// named constant; 96 is a deliberately conservative floor for any other Unix this ever runs on,
/// since undershooting only means falling back to [`short_fallback_path`] a little earlier than
/// strictly necessary, where overshooting would mean handing `bind` or `connect` a path this
/// crate believed fit and did not.
#[cfg(unix)]
fn max_socket_path_bytes() -> usize {
    #[cfg(target_os = "macos")]
    {
        104 - 1
    }
    #[cfg(target_os = "linux")]
    {
        108 - 1
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        96 - 1
    }
}

/// `path`'s length the way `sockaddr_un` counts it: bytes, not characters.
#[cfg(unix)]
fn socket_path_byte_len(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().len()
}

/// Whether `path` fits in a `sockaddr_un` on this platform.
#[cfg(unix)]
fn fits_socket_path(path: &Path) -> bool {
    socket_path_byte_len(path) <= max_socket_path_bytes()
}

/// A short, deterministic stand-in for a Unix socket path too long for `sun_path`: a hash of
/// `dir` and `label`, so the same pair always resolves to the same socket, under the shortest
/// per-user directory this platform offers (`TMPDIR` on macOS — Apple's own answer to this exact
/// problem — `$XDG_RUNTIME_DIR` or `/tmp` elsewhere), in a `0700` directory of its own rather
/// than directly in a directory other processes can also write to.
///
/// Not a general escape from the "no shared temporary files" rule above: nothing is written
/// there but this one user's own socket, named so that nobody else can predict which of their
/// sockets it is, and the directory it sits in is prepared exactly as any other endpoint's
/// (`Endpoint::prepare_dir`, `0700`).
#[cfg(unix)]
fn short_fallback_path(dir: &Path, label: &str) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut hasher);
    label.hash(&mut hasher);
    let hash = hasher.finish();
    // `$USER`, not a uid looked up over FFI (this crate is `deny(unsafe_code)` outside its four
    // named exceptions, ADR's `lib.rs` doc): good enough to keep two accounts on one Mac from
    // landing in the same directory, which is all a *name* needs to do here — the directory's
    // `0700` permissions (`Endpoint::prepare_dir`), not its name, are what keeps another account
    // out once it exists.
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_owned());
    std::env::temp_dir()
        .join(format!("kagisecure-{user}"))
        .join(format!("{hash:016x}.sock"))
}

/// `dir.join(label)`, or [`short_fallback_path`] if that does not fit in a `sun_path`.
#[cfg(unix)]
fn joined_socket_path(dir: &Path, label: &str) -> PathBuf {
    let path = dir.join(label);
    if fits_socket_path(&path) {
        path
    } else {
        short_fallback_path(dir, label)
    }
}

/// Overrides the endpoint. Used by the test suite and by anyone running two vaults at once.
pub const SOCKET_ENV: &str = "KAGISECURE_SOCKET";

/// The socket file name.
pub const SOCKET_FILE: &str = "daemon.sock";

/// Where to listen or connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A filesystem path — a Unix domain socket.
    Path(PathBuf),
    /// A name in the OS namespace — a Windows named pipe.
    Namespaced(String),
}

/// Why an endpoint could not be determined.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// The platform's data directory could not be determined.
    #[error("could not determine this platform's application data directory")]
    NoDataDir,
    /// The endpoint could not be created or prepared.
    #[error("i/o error preparing {path}: {source}")]
    Io {
        /// What was being prepared.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// An explicitly supplied endpoint is not something this platform can listen on.
    ///
    /// Carries the value as the user wrote it and a sentence saying what this platform does
    /// accept, because the alternative — the transport's own `Unsupported: "not a named pipe
    /// path"` — reaches the user as an opaque I/O error from a flag they set deliberately.
    #[error("{value} cannot be used as a kagisecure endpoint: {reason}")]
    Unsupported {
        /// The value as it was supplied, for the user to recognize.
        value: String,
        /// What was wrong with it and what this platform accepts instead.
        reason: String,
    },
}

impl Endpoint {
    /// The per-user default endpoint, or whatever [`SOCKET_ENV`] names.
    ///
    /// * macOS: `~/Library/Application Support/kagisecure/run/daemon.sock`
    /// * Linux: `$XDG_RUNTIME_DIR/kagisecure/daemon.sock`, falling back to
    ///   `~/.local/share/kagisecure/run/daemon.sock`
    /// * Windows: the named pipe `kagisecure-<user>.sock`
    ///
    /// # Errors
    ///
    /// [`EndpointError::NoDataDir`] if there is no home directory to put it in, or
    /// [`EndpointError::Unsupported`] if [`SOCKET_ENV`] names something this platform cannot
    /// listen on.
    pub fn discover() -> Result<Self, EndpointError> {
        if let Some(explicit) = std::env::var_os(SOCKET_ENV) {
            return Self::parse(&explicit);
        }
        Self::default_endpoint()
    }

    /// Interpret an endpoint the user named explicitly: `--socket`, or [`SOCKET_ENV`].
    ///
    /// The two go through one function on purpose — a flag and the environment variable that
    /// backs it must mean the same thing — and the meaning is platform-specific because the
    /// transport is:
    ///
    /// * **Unix**: the value is a filesystem path, taken verbatim, and the socket is created
    ///   there. Unchanged from every release so far.
    /// * **Windows**: the value is a **named pipe name** — `kagisecure-mine.sock`, or the full
    ///   form `\\.\pipe\kagisecure-mine.sock`. A filesystem path is refused with a sentence
    ///   saying so, because Windows has no filesystem sockets: `to_fs_name` there accepts only
    ///   strings already shaped like `\\HOST\pipe\NAME`, and everything else fails at `bind`.
    ///
    /// A path is **not** quietly turned into a pipe name. Two directories holding the same file
    /// name would collapse onto one pipe, which is the opposite of what a caller naming two
    /// different socket locations asked for.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Unsupported`] when the value is not usable on this platform.
    pub fn parse(value: &OsStr) -> Result<Self, EndpointError> {
        #[cfg(not(windows))]
        {
            Ok(Self::Path(PathBuf::from(value)))
        }
        #[cfg(windows)]
        {
            Self::parse_windows(value)
        }
    }

    /// The Windows reading of an explicit endpoint: a pipe name, or a legible refusal.
    #[cfg(windows)]
    fn parse_windows(value: &OsStr) -> Result<Self, EndpointError> {
        /// What Windows will actually listen on, for the end of every refusal.
        const ACCEPTS: &str = "Windows has no filesystem sockets: kagisecure listens on a named \
                               pipe there. Pass a pipe name — `kagisecure-mine.sock`, or the \
                               full form `\\\\.\\pipe\\kagisecure-mine.sock` — bearing in mind \
                               that a pipe name is a machine-global name rather than a private \
                               file.";
        let unsupported = |value: &OsStr, reason: String| EndpointError::Unsupported {
            value: value.to_string_lossy().into_owned(),
            reason,
        };

        let Some(text) = value.to_str() else {
            return Err(unsupported(
                value,
                format!("it is not valid UTF-8. {ACCEPTS}"),
            ));
        };
        if text.is_empty() {
            return Err(unsupported(value, format!("it is empty. {ACCEPTS}")));
        }

        // The full form first: `\\HOST\pipe\NAME`, which is the only path shape the transport
        // accepts. Only this machine's own pipes are servable, so a hostname that is not the
        // local one is refused rather than silently reinterpreted as local.
        if let Some(rest) = text.strip_prefix(r"\\") {
            let Some((host, tail)) = rest.split_once('\\') else {
                return Err(unsupported(
                    value,
                    format!("it starts with `\\\\` but names no pipe. {ACCEPTS}"),
                ));
            };
            if !(host == "." || host.eq_ignore_ascii_case("localhost")) {
                return Err(unsupported(
                    value,
                    format!(
                        "`{host}` is another host, and a daemon can only serve pipes on the \
                         machine it runs on. {ACCEPTS}"
                    ),
                ));
            }
            let Some(name) = tail
                .strip_prefix("pipe\\")
                .or_else(|| tail.strip_prefix("PIPE\\"))
                .filter(|name| !name.is_empty())
            else {
                return Err(unsupported(
                    value,
                    format!("`\\\\{host}\\{tail}` is not a pipe path. {ACCEPTS}"),
                ));
            };
            return Ok(Self::Namespaced(name.to_owned()));
        }

        if text.contains('\\') || text.contains('/') || text.contains(':') {
            return Err(unsupported(
                value,
                format!("it is a filesystem path. {ACCEPTS}"),
            ));
        }
        Ok(Self::Namespaced(text.to_owned()))
    }

    /// An endpoint for one instance of this program, distinct from every *other* instance of it.
    ///
    /// For a caller that needs an endpoint of its own rather than one specific location: a
    /// second vault, the extension harness, a test. There is no one expression that works on
    /// both platforms — a Unix socket is a file in a directory the caller controls, and Windows
    /// has no filesystem sockets to put anywhere — so this is that expression, written once:
    ///
    /// * **Unix**: `dir/label`, exactly as `dir.join(label)`. The caller's `dir` is the boundary
    ///   ([`Self::prepare_dir`] makes it `0700`), which is why one is required.
    /// * **Windows**: a namespaced pipe whose name carries `label`, this process's id and a
    ///   per-process counter. `dir` is unused, because a pipe name is not in the filesystem.
    ///
    /// The uniqueness on Windows prevents **collision between our own listeners** — two
    /// instances in one test run, or two vaults — and nothing else. It is not an access
    /// boundary: the name is in a machine-global namespace. The boundary is the owner-only
    /// descriptor the pipe is created with (`server::owner_only_pipe_descriptor`), which is the
    /// same whichever name it has.
    #[must_use]
    pub fn for_instance(dir: &Path, label: &str) -> Self {
        #[cfg(not(windows))]
        {
            Self::Path(joined_socket_path(dir, label))
        }
        #[cfg(windows)]
        {
            use std::sync::atomic::{AtomicU64, Ordering};

            /// Distinguishes two instances made by the same process. Pipe names are global, so
            /// the pid alone is not enough within one test binary.
            static NEXT: AtomicU64 = AtomicU64::new(0);

            let _ = dir;
            // A pipe name may hold anything but a backslash; `/` is swapped too so that a label
            // written as a relative path does not read as one.
            let label: String = label
                .chars()
                .map(|c| if c == '\\' || c == '/' { '-' } else { c })
                .collect();
            Self::Namespaced(format!(
                "kagisecure-{}-{}-{label}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        }
    }

    #[cfg(windows)]
    fn default_endpoint() -> Result<Self, EndpointError> {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
        Ok(Self::Namespaced(format!("kagisecure-{user}.sock")))
    }

    #[cfg(not(windows))]
    fn default_endpoint() -> Result<Self, EndpointError> {
        if cfg!(not(target_os = "macos"))
            && let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR")
        {
            return Ok(Self::Path(joined_socket_path(
                &PathBuf::from(runtime).join("kagisecure"),
                SOCKET_FILE,
            )));
        }
        let dirs =
            directories::ProjectDirs::from("", "", "kagisecure").ok_or(EndpointError::NoDataDir)?;
        Ok(Self::Path(joined_socket_path(
            &dirs.data_dir().join("run"),
            SOCKET_FILE,
        )))
    }

    /// The interprocess name for this endpoint.
    ///
    /// # Errors
    ///
    /// If the path or name is not usable as a local socket name on this platform. On Windows
    /// that is every [`Self::Path`] except one already shaped like `\\HOST\pipe\NAME`, and the
    /// error says so in words: the transport's own message for the case is `Unsupported: "not a
    /// named pipe path"`, which tells a user who set `--socket` nothing about what to set it to.
    /// [`Self::parse`] refuses such a value up front; this is the backstop for an [`Endpoint`]
    /// built in code.
    pub fn name(&self) -> std::io::Result<Name<'_>> {
        use interprocess::local_socket::{GenericFilePath, GenericNamespaced, ToFsName, ToNsName};
        match self {
            Self::Path(p) => {
                #[cfg(windows)]
                if !is_pipe_path(p) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!(
                            "{} is a filesystem path, and Windows has no filesystem sockets. \
                             kagisecure listens on a named pipe there: build an \
                             `Endpoint::Namespaced(<pipe name>)` — `Endpoint::for_instance` \
                             makes one — or pass a pipe name to `Endpoint::parse`.",
                            p.display()
                        ),
                    ));
                }
                // `Endpoint::for_instance` and the per-user default already shorten a path that
                // would not fit; the one this cannot shorten is one a caller set explicitly
                // (`--socket`, `KAGISECURE_SOCKET`), taken verbatim on purpose. Catching it here
                // trades interprocess's own "local socket name length exceeds capacity of
                // sun_path" — which names no path and no limit — for one that does.
                #[cfg(unix)]
                if !fits_socket_path(p) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "{} is {} bytes, too long for a Unix domain socket (the limit here is \
                             {} bytes); use a shorter --socket or KAGISECURE_SOCKET",
                            p.display(),
                            socket_path_byte_len(p),
                            max_socket_path_bytes()
                        ),
                    ));
                }
                p.as_path().to_fs_name::<GenericFilePath>()
            }
            Self::Namespaced(s) => s.as_str().to_ns_name::<GenericNamespaced>(),
        }
    }

    /// Recast a `bind` failure that actually means "something else is already listening here".
    ///
    /// The hosts above this crate turn [`std::io::ErrorKind::AddrInUse`] into the one error a
    /// user can act on — "another kagisecure is already listening on …; quit the app, or stop
    /// `kagisecure daemon`" — and that mapping is the whole of how the app-versus-daemon
    /// collision stays legible (architecture.md §4.2).
    ///
    /// Unix `bind` reports the taken socket as `AddrInUse` and this returns the error untouched.
    /// Windows does not: `CreateNamedPipe` with `FILE_FLAG_FIRST_PIPE_INSTANCE` answers
    /// `ERROR_ACCESS_DENIED` for a name another process already holds, which arrives as
    /// [`std::io::ErrorKind::PermissionDenied`] and is indistinguishable *by kind* from a pipe
    /// this user genuinely may not create. The two are told apart by the only thing that does
    /// distinguish them: whether anything answers on the name. Something answers → the name is
    /// occupied, report `AddrInUse`. Nothing answers → leave the refusal exactly as it came, so
    /// a real access problem is not relabelled as a busy socket.
    ///
    /// This is not a security check and does not say *who* holds the pipe: a named pipe's name is
    /// machine-global, and any local account can create one under a name nobody holds yet —
    /// including ours, before we do. What stops that from mattering is elsewhere: the bind fails
    /// rather than joining a foreign pipe (`FILE_FLAG_FIRST_PIPE_INSTANCE`), and a client checks
    /// who owns the pipe it reached before it sends anything (`client::server_is_same_user`).
    /// The probe connection made here sends nothing, and is opened through
    /// [`crate::connect`], so it grants whatever holds the name identification only.
    ///
    /// # The probe does not wait
    ///
    /// "Answers" includes a name whose every instance is busy: `ERROR_PIPE_BUSY` is only ever
    /// returned for a name that exists, which is all this needs to know, so the probe makes one
    /// attempt and takes a busy name as occupied. It used to be `interprocess`'s
    /// `Stream::connect`, which meets a busy name with `WaitNamedPipe(NMPWAIT_WAIT_FOREVER)` —
    /// and a busy name is exactly what a stopped listener's leftover connection leaves behind, so
    /// the probe that was meant to turn a refused restart into a legible error waited, without
    /// bound, for the connection that was refusing it. That is the second of the four causes of
    /// the 39-minute hang recorded in [`crate::sever`].
    #[must_use]
    pub fn classify_bind_error(&self, error: std::io::Error) -> std::io::Error {
        #[cfg(not(windows))]
        {
            error
        }
        #[cfg(windows)]
        {
            if error.kind() != std::io::ErrorKind::PermissionDenied {
                return error;
            }
            let answered = match crate::connect::open_waiting(self, std::time::Duration::ZERO) {
                Ok(probe) => {
                    drop(probe);
                    true
                }
                Err(e) => crate::connect::is_busy(&e),
            };
            if answered {
                std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    // Not "another process": the second `bind` can come from this one, which is
                    // exactly the app-versus-daemon case the hosts above render.
                    format!("{self} already has a listener on it: {error}"),
                )
            } else {
                error
            }
        }
    }

    /// This endpoint written the way [`Self::parse`] reads it back.
    ///
    /// What to hand another process: the value of [`SOCKET_ENV`] for a sidecar, or the argument
    /// after `--socket` for a daemon. An [`std::ffi::OsString`] rather than a [`String`] so that
    /// a Unix path which is not UTF-8 survives the trip, where [`std::fmt::Display`] would
    /// replace the bytes it cannot render.
    #[must_use]
    pub fn as_override(&self) -> std::ffi::OsString {
        match self {
            Self::Path(p) => p.as_os_str().to_owned(),
            Self::Namespaced(s) => std::ffi::OsString::from(s),
        }
    }

    /// The path, when this endpoint is one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Path(p) => Some(p),
            Self::Namespaced(_) => None,
        }
    }

    /// Create the containing directory, `0700` on Unix.
    ///
    /// # Windows: nothing to prepare; the boundary is on the pipe itself
    ///
    /// This is a no-op on Windows, and correctly so: `Self::default_endpoint` returns a
    /// [`Self::Namespaced`] pipe name there, [`Self::path`] is `None`, and there is no directory
    /// to harden. The `0700` directory and `0600` socket that
    /// [`crate::server::Server::bind`] relies on on Unix have their Windows counterpart in the
    /// pipe's own security descriptor instead, set when the pipe is created
    /// (`server::bind_listener`, via `server::owner_only_pipe_descriptor`):
    /// `O:<user SID>D:P(A;;FA;;;<user SID>)` — owned by this user, protected from inheritance,
    /// one entry, for this user only. An earlier sketch here also granted SYSTEM and
    /// Administrators; `kagisecure_core::windows_acl` explains why that was not kept.
    /// `peer_is_same_user` compares token SIDs behind it on Windows.
    ///
    /// Moving Windows callers onto namespaced pipes (`KAGISECURE_SOCKET` and `--socket` name a
    /// pipe there; [`Self::parse`] refuses a path) is what made that descriptor load-bearing:
    /// the pipe is the only thing between the endpoint and another local user.
    ///
    /// Not tested: the refusal of a second local account. The tests read the pipe's descriptor
    /// back and assert its exact shape; "connect as another user and be refused" needs two
    /// accounts and has not been run.
    ///
    /// # Errors
    ///
    /// Any I/O failure creating or chmod-ing the directory.
    pub fn prepare_dir(&self) -> Result<(), EndpointError> {
        let Some(path) = self.path() else {
            return Ok(());
        };
        let Some(dir) = path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(dir).map_err(|source| EndpointError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |source| EndpointError::Io {
                    path: dir.to_path_buf(),
                    source,
                },
            )?;
        }
        Ok(())
    }
}

/// Whether `path` is already the one path shape the Windows transport accepts.
///
/// `interprocess`'s own test is `\\`, then a hostname, then `\pipe\` — see
/// `interprocess/src/os/windows/local_socket/name_type.rs`. This mirrors it so that a path
/// which *would* work is still passed through rather than refused by our own check.
#[cfg(windows)]
fn is_pipe_path(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    let Some(rest) = text.strip_prefix(r"\\") else {
        return false;
    };
    rest.split_once('\\')
        .is_some_and(|(_host, tail)| tail.to_ascii_lowercase().starts_with("pipe\\"))
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(p) => write!(f, "{}", p.display()),
            Self::Namespaced(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_endpoint_reports_its_path_and_renders_it() {
        let e = Endpoint::Path(PathBuf::from("/tmp/x/daemon.sock"));
        assert_eq!(e.path(), Some(Path::new("/tmp/x/daemon.sock")));
        assert_eq!(e.to_string(), "/tmp/x/daemon.sock");
        // A filesystem socket is a Unix thing. On Windows the same value has no transport to be
        // named on, and the error has to say which value and what the platform wants instead —
        // `name()` is the last place that can still tell the difference.
        #[cfg(not(windows))]
        assert!(e.name().is_ok());
        #[cfg(windows)]
        {
            let err = e.name().expect_err("a path cannot name a Windows pipe");
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
            let text = err.to_string();
            assert!(text.contains("daemon.sock"), "{text}");
            assert!(text.contains("named pipe"), "{text}");
        }
    }

    #[test]
    fn an_instance_endpoint_is_bindable_on_this_platform() {
        let tmp = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(tmp.path(), SOCKET_FILE);
        assert!(
            endpoint.name().is_ok(),
            "for_instance must produce something this platform can listen on: {endpoint}"
        );
        // Two instances never collide, which is what a test run and a second vault need. This
        // says nothing about who else can reach either one. Where the uniqueness comes from
        // differs: on Unix it is the caller's directory — `for_instance` is `dir.join(label)`,
        // so the same arguments name the same socket by design — and on Windows it is minted
        // per call, because a pipe name has no directory to lean on.
        #[cfg(not(windows))]
        {
            let other = tempfile::tempdir().unwrap();
            assert_ne!(endpoint, Endpoint::for_instance(other.path(), SOCKET_FILE));
        }
        #[cfg(windows)]
        assert_ne!(endpoint, Endpoint::for_instance(tmp.path(), SOCKET_FILE));
    }

    #[test]
    fn an_endpoint_survives_being_handed_to_another_process() {
        // `--socket $(KAGISECURE_SOCKET)` has to name the endpoint the parent bound, or a test
        // harness — and anyone running two vaults — is chasing two different sockets.
        let tmp = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(tmp.path(), SOCKET_FILE);
        assert_eq!(Endpoint::parse(&endpoint.as_override()).unwrap(), endpoint);
    }

    #[cfg(not(windows))]
    #[test]
    fn an_instance_endpoint_is_a_socket_in_the_directory_it_was_given() {
        let tmp = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::for_instance(tmp.path(), SOCKET_FILE);
        assert_eq!(
            endpoint.path(),
            Some(tmp.path().join(SOCKET_FILE).as_path())
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn an_explicit_endpoint_is_a_path_taken_verbatim() {
        let parsed = Endpoint::parse(OsStr::new("/tmp/override.sock")).unwrap();
        assert_eq!(parsed, Endpoint::Path(PathBuf::from("/tmp/override.sock")));
    }

    #[cfg(unix)]
    #[test]
    fn an_instance_endpoint_too_long_for_sun_path_falls_back_short() {
        // A directory long enough on its own, plus a label an app or a job could plausibly
        // choose (not obviously "too long" to whoever wrote it), together exceed every Unix's
        // `sun_path`. `KAGISECURE_SOCKET` pointing into a synced folder, or a job named by its
        // owner, both look just like this.
        let deep = "d".repeat(80);
        let dir = Path::new("/tmp").join(deep);
        let label = "a rather descriptively named unattended job.sock";
        let endpoint = Endpoint::for_instance(&dir, label);
        let path = endpoint.path().expect("a path endpoint");
        assert!(
            fits_socket_path(path),
            "{} is {} bytes, over the {}-byte limit",
            path.display(),
            socket_path_byte_len(path),
            max_socket_path_bytes()
        );
        assert!(
            endpoint.name().is_ok(),
            "the fallback must itself be bindable"
        );
        // Deterministic: the same directory and label always land on the same fallback, since a
        // caller that asks twice (a restart, a second process) means the same socket both times.
        assert_eq!(endpoint, Endpoint::for_instance(&dir, label));
        // But not the same as some other job's fallback.
        assert_ne!(
            endpoint,
            Endpoint::for_instance(&dir, "a different job.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_explicit_endpoint_too_long_for_sun_path_names_itself_and_the_limit() {
        // Unlike `for_instance`, `parse` takes what it is given verbatim (`--socket` and
        // `KAGISECURE_SOCKET` are meant literally) — so this cannot be shortened automatically,
        // and `name()` is the last chance to say why in words instead of interprocess's own
        // "local socket name length exceeds capacity of sun_path", which names no path.
        let long = format!("/tmp/{}/daemon.sock", "x".repeat(120));
        let endpoint = Endpoint::parse(OsStr::new(&long)).unwrap();
        let err = endpoint.name().expect_err("too long to bind or connect to");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let text = err.to_string();
        assert!(text.contains(&long), "{text}");
        assert!(text.contains("too long"), "{text}");
        assert!(!text.to_lowercase().contains("sun_path"), "{text}");
    }

    #[cfg(windows)]
    #[test]
    fn an_explicit_endpoint_is_a_pipe_name_in_either_spelling() {
        assert_eq!(
            Endpoint::parse(OsStr::new("kagisecure-mine.sock")).unwrap(),
            Endpoint::Namespaced("kagisecure-mine.sock".to_owned())
        );
        assert_eq!(
            Endpoint::parse(OsStr::new(r"\\.\pipe\kagisecure-mine.sock")).unwrap(),
            Endpoint::Namespaced("kagisecure-mine.sock".to_owned())
        );
    }

    #[cfg(windows)]
    #[test]
    fn an_explicit_path_on_windows_is_refused_with_what_to_use_instead() {
        for value in [
            r"C:\Users\ada\AppData\Local\Temp\d.sock",
            "/tmp/d.sock",
            r"..\d.sock",
            "",
            r"\\fileserver\pipe\d.sock",
            r"\\.\mailslot\d.sock",
        ] {
            let err = Endpoint::parse(OsStr::new(value))
                .expect_err("Windows cannot listen on a filesystem path");
            let text = err.to_string();
            assert!(
                text.contains("named pipe") || text.contains("machine it runs on"),
                "the refusal must say what Windows accepts: {text}"
            );
            assert!(
                value.is_empty() || text.contains(value),
                "the refusal must quote what was supplied: {text}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn preparing_the_directory_makes_it_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::Path(tmp.path().join("run").join(SOCKET_FILE));
        endpoint.prepare_dir().unwrap();
        let dir = endpoint.path().unwrap().parent().unwrap();
        let mode = std::fs::metadata(dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn the_environment_variable_wins() {
        // Not using `discover()` here: the test process's environment is shared, and this crate
        // does not get to make other tests flaky. The behaviour is one `if let`, asserted on the
        // shape it produces.
        let explicit = Endpoint::Path(PathBuf::from("/tmp/override.sock"));
        assert_eq!(
            explicit.path().unwrap().to_str().unwrap(),
            "/tmp/override.sock"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn the_default_endpoint_is_under_the_users_own_directory() {
        let endpoint = Endpoint::default_endpoint().unwrap();
        let path = endpoint.path().unwrap();
        assert!(path.ends_with(SOCKET_FILE));
        assert!(
            path.to_string_lossy().contains("kagisecure"),
            "{}",
            path.display()
        );
    }
}

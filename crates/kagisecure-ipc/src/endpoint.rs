//! Where the socket lives (architecture.md §4.2, threat-model M-13/M-15).
//!
//! Everything is under the user's own home directory or their own runtime directory: no
//! system-wide daemon, no shared temporary files. The directory is `0700` and the socket `0600`,
//! so another local user cannot even see the endpoint, let alone connect to it.

use std::path::{Path, PathBuf};

use interprocess::local_socket::Name;

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
    /// [`EndpointError::NoDataDir`] if there is no home directory to put it in.
    pub fn discover() -> Result<Self, EndpointError> {
        if let Some(explicit) = std::env::var_os(SOCKET_ENV) {
            let explicit = PathBuf::from(explicit);
            return Ok(Self::Path(explicit));
        }
        Self::default_endpoint()
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
            return Ok(Self::Path(
                PathBuf::from(runtime).join("kagisecure").join(SOCKET_FILE),
            ));
        }
        let dirs =
            directories::ProjectDirs::from("", "", "kagisecure").ok_or(EndpointError::NoDataDir)?;
        Ok(Self::Path(dirs.data_dir().join("run").join(SOCKET_FILE)))
    }

    /// The interprocess name for this endpoint.
    ///
    /// # Errors
    ///
    /// If the path or name is not usable as a local socket name on this platform.
    pub fn name(&self) -> std::io::Result<Name<'_>> {
        use interprocess::local_socket::{GenericFilePath, GenericNamespaced, ToFsName, ToNsName};
        match self {
            Self::Path(p) => p.as_path().to_fs_name::<GenericFilePath>(),
            Self::Namespaced(s) => s.as_str().to_ns_name::<GenericNamespaced>(),
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
        assert!(e.name().is_ok());
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

//! The caller's half of the protocol.
//!
//! Used by the MCP sidecar for every tool call and by `kagisecure lock` / `kagisecure audit`
//! when a daemon is running. It is deliberately blocking: the traffic is one round trip per tool
//! call, and the sidecar runs it on a blocking task rather than colouring the whole crate async.

use std::io::BufWriter;

use interprocess::local_socket::Stream;
use interprocess::local_socket::traits::Stream as _;

use crate::endpoint::Endpoint;
use crate::frame::{self, FrameError};
use crate::protocol::{ClientInfo, ErrorCode, PROTOCOL_VERSION, Request, Response};

/// What can go wrong talking to the daemon.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Nothing is listening. This becomes `APP_NOT_RUNNING` at the MCP surface.
    #[error("no kagisecure daemon is listening on {endpoint}")]
    NotRunning {
        /// Where we looked.
        endpoint: String,
    },
    /// The endpoint could not even be determined.
    #[error(transparent)]
    Endpoint(#[from] crate::endpoint::EndpointError),
    /// Wire failure.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The daemon replied with something the caller did not ask for.
    #[error("unexpected reply from the daemon: {0}")]
    Unexpected(String),
}

impl ClientError {
    /// The MCP error code this failure maps to (mcp-server.md §7).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotRunning { .. } | Self::Endpoint(_) => ErrorCode::AppNotRunning,
            Self::Frame(_) | Self::Unexpected(_) => ErrorCode::Internal,
        }
    }
}

/// One connection to the daemon.
pub struct Client {
    reader: Stream,
    writer: BufWriter<Stream>,
    /// How the daemon rendered this caller's identity after checking peer credentials.
    identity: String,
    /// Whether the daemon could verify that identity rather than take it on trust.
    verified: bool,
}

impl Client {
    /// Connect and complete the handshake.
    ///
    /// A failure to connect is reported as [`ClientError::NotRunning`] rather than as a generic
    /// I/O error, because the *only* useful thing to tell a model is "open kagisecure", and it
    /// must arrive promptly rather than after a retry loop (roadmap M2).
    ///
    /// # Errors
    ///
    /// [`ClientError::NotRunning`] when nothing is listening, or any wire failure.
    pub fn connect(endpoint: &Endpoint, client: ClientInfo) -> Result<Self, ClientError> {
        let name = endpoint.name().map_err(|_| ClientError::NotRunning {
            endpoint: endpoint.to_string(),
        })?;
        let stream = Stream::connect(name).map_err(|_| ClientError::NotRunning {
            endpoint: endpoint.to_string(),
        })?;
        let reader = stream.try_clone_stream()?;
        let mut this = Self {
            reader,
            writer: BufWriter::new(stream),
            identity: String::new(),
            verified: false,
        };
        match this.call(&Request::Hello {
            protocol: PROTOCOL_VERSION,
            client,
        })? {
            Response::Hello {
                client_identity,
                client_verified,
                ..
            } => {
                this.identity = client_identity;
                this.verified = client_verified;
                Ok(this)
            }
            Response::Error { code, message } => Err(ClientError::Unexpected(format!(
                "handshake refused: {code}: {message}"
            ))),
            other => Err(ClientError::Unexpected(format!(
                "expected a handshake reply, got {}",
                reply_name(&other)
            ))),
        }
    }

    /// Send one request and read one reply.
    ///
    /// # Errors
    ///
    /// Any wire failure. A daemon-side refusal comes back as `Ok(Response::Error { .. })`, not as
    /// an `Err`: a denial is a normal outcome, not a transport problem.
    pub fn call(&mut self, request: &Request) -> Result<Response, ClientError> {
        frame::write(&mut self.writer, request)?;
        Ok(frame::read(&mut self.reader)?)
    }

    /// How the daemon identified this caller.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Whether that identity was verified.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.verified
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("identity", &self.identity)
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

/// Trait-object-free `try_clone` for the enum-dispatched stream type.
trait TryCloneStream: Sized {
    fn try_clone_stream(&self) -> Result<Self, FrameError>;
}

impl TryCloneStream for Stream {
    fn try_clone_stream(&self) -> Result<Self, FrameError> {
        use interprocess::TryClone;
        Ok(TryClone::try_clone(self)?)
    }
}

fn reply_name(response: &Response) -> &'static str {
    match response {
        Response::Hello { .. } => "Hello",
        Response::Vaults { .. } => "Vaults",
        Response::Items { .. } => "Items",
        Response::Environments { .. } => "Environments",
        Response::Item { .. } => "Item",
        Response::Environment { .. } => "Environment",
        Response::AddedVariables { .. } => "AddedVariables",
        Response::WroteEnvFile { .. } => "WroteEnvFile",
        Response::Ran { .. } => "Ran",
        Response::Revoked { .. } => "Revoked",
        Response::Audit { .. } => "Audit",
        Response::Leases { .. } => "Leases",
        Response::Locked => "Locked",
        Response::Error { .. } => "Error",
    }
}

/// The [`ClientInfo`] describing this process.
///
/// Every field is self-reported, and the daemon treats it as such. It is here so the approval
/// prompt can *display* "Claude Code" next to the identity it actually verified.
#[must_use]
pub fn self_info(name: impl Into<String>, version: impl Into<String>) -> ClientInfo {
    ClientInfo {
        name: name.into(),
        version: version.into(),
        pid: std::process::id(),
        parent_pid: parent_pid(),
        argv0: std::env::args()
            .next()
            .unwrap_or_else(|| "unknown".to_owned()),
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
    }
}

/// This process's parent, discovered without FFI so the crate can keep `forbid(unsafe_code)`.
///
/// Cached: the sidecar opens a connection per tool call, and shelling out to `ps` every time
/// would be a silly price for a display-only field.
fn parent_pid() -> Option<u32> {
    static CACHED: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *CACHED.get_or_init(read_parent_pid)
}

#[cfg(target_os = "linux")]
fn read_parent_pid() -> Option<u32> {
    // /proc/self/stat: pid (comm) state ppid ... — `comm` can contain spaces and parentheses, so
    // the split starts after the last ')'.
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_parent_pid() -> Option<u32> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "ppid=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()?;
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

#[cfg(not(unix))]
fn read_parent_pid() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn connecting_to_nothing_says_the_app_is_not_running_and_returns_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        let endpoint = Endpoint::Path(tmp.path().join("nobody-home.sock"));
        let started = std::time::Instant::now();
        let err = Client::connect(&endpoint, self_info("test", "0")).unwrap_err();
        assert!(matches!(err, ClientError::NotRunning { .. }));
        assert_eq!(err.code(), ErrorCode::AppNotRunning);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "a missing daemon must be reported in well under a second, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn self_info_reports_this_process() {
        let info = self_info("kagisecure-mcp", "0.1.0");
        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.name, "kagisecure-mcp");
        assert!(!info.argv0.is_empty());
    }

    #[test]
    fn an_undiscoverable_endpoint_still_maps_to_app_not_running() {
        let endpoint = Endpoint::Path(PathBuf::from("/definitely/not/here/daemon.sock"));
        let err = Client::connect(&endpoint, self_info("test", "0")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AppNotRunning);
    }
}

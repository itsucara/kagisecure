//! The native host's half: connect to the app's extension socket and do one round trip at a time.
//!
//! Blocking and synchronous, like `kagisecure_ipc::client`, and for the same reason: a native
//! messaging host is a single-threaded pipe between two blocking endpoints, and an async runtime
//! would be three dependencies and a scheduler in a process whose entire job is `read`, `write`,
//! `read`, `write`.

use std::io::BufWriter;

use interprocess::local_socket::Stream;
use interprocess::local_socket::traits::Stream as _;
use kagisecure_ipc::endpoint::Endpoint;

use crate::frame::{self, FrameError};
use crate::protocol::{Envelope, Request, Response};

/// Why a call to the app did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Nothing is listening: the app is not running.
    #[error(
        "kagisecure is not running. Open the Kagisecure app and unlock your vault, then try again."
    )]
    AppNotRunning,
    /// The socket path could not be worked out.
    #[error("{0}")]
    Endpoint(#[from] kagisecure_ipc::endpoint::EndpointError),
    /// Wire failure.
    #[error("{0}")]
    Frame(#[from] FrameError),
    /// The app answered a different request than the one that was asked.
    #[error("the app replied to {got:?} when {want:?} was asked")]
    Correlation {
        /// The id that came back.
        got: String,
        /// The id that went out.
        want: String,
    },
}

/// A connection to the app's extension socket.
pub struct Client {
    reader: Stream,
    writer: BufWriter<Stream>,
}

impl Client {
    /// Connect to `endpoint`.
    ///
    /// # Errors
    ///
    /// [`ClientError::AppNotRunning`] when nothing is listening — the common case, and the one
    /// the popup turns into "Open Kagisecure" rather than a stack trace.
    pub fn connect(endpoint: &Endpoint) -> Result<Self, ClientError> {
        let name = endpoint.name().map_err(FrameError::Io)?;
        let stream = Stream::connect(name).map_err(|_| ClientError::AppNotRunning)?;
        let reader = {
            use interprocess::TryClone;
            TryClone::try_clone(&stream).map_err(FrameError::Io)?
        };
        Ok(Self {
            reader,
            writer: BufWriter::new(stream),
        })
    }

    /// Connect to the per-user extension endpoint.
    ///
    /// # Errors
    ///
    /// As [`Client::connect`], plus [`ClientError::Endpoint`] if the path cannot be determined.
    pub fn connect_default() -> Result<Self, ClientError> {
        let endpoint = crate::endpoint::extension_endpoint()?;
        Self::connect(&endpoint)
    }

    /// Send one request and read its reply.
    ///
    /// The correlation id is checked rather than assumed. This connection is used by one thread
    /// in lock step, so a mismatch means the app is confused, not that a reply arrived early —
    /// and answering a `Fill` with the reply to somebody else's `Fill` is exactly the bug worth
    /// failing loudly on.
    ///
    /// # Errors
    ///
    /// [`ClientError::Frame`] on a wire failure, [`ClientError::Correlation`] if the reply is for
    /// a different request.
    pub fn call(&mut self, id: &str, request: &Request) -> Result<Response, ClientError> {
        frame::write(&mut self.writer, &Envelope::new(id, request))?;
        let reply: Envelope<Response> = frame::read(&mut self.reader)?;
        if reply.id != id {
            return Err(ClientError::Correlation {
                got: reply.id,
                want: id.to_owned(),
            });
        }
        Ok(reply.body)
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connecting_to_nothing_says_the_app_is_not_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::Path(dir.path().join("nobody-home.sock"));
        let err = Client::connect(&endpoint).unwrap_err();
        assert!(
            matches!(err, ClientError::AppNotRunning),
            "the common failure must be legible, not an errno: {err:?}"
        );
        assert!(err.to_string().contains("Open the Kagisecure app"));
    }
}

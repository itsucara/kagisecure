//! The caller's side of the host socket: `kagisecure-host request <grant> -- <argv...>`.
//!
//! It holds no credential at any point: it sends the command line and prints what comes back.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::protocol::{Request, Response};
use crate::{HostError, Result, io};

/// Send `request` to the socket at `socket` and return the response.
///
/// # Errors
///
/// If the socket cannot be reached, or the answer is not a response.
pub fn request(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket).map_err(io(format!(
        "connecting to {} (is kagisecure-host.service running, and are you in its group?)",
        socket.display()
    )))?;
    let mut json = serde_json::to_string(request)
        .map_err(|e| HostError::Invalid(format!("cannot encode the request: {e}")))?;
    json.push('\n');
    stream
        .write_all(json.as_bytes())
        .map_err(io("sending the request"))?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(io("reading the response"))?;
    serde_json::from_str(&line)
        .map_err(|e| HostError::Invalid(format!("kagisecure-host answered something else: {e}")))
}

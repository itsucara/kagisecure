//! The host socket (ADR-0043, accepted scope §A4).
//!
//! Who may ask is decided by the file system: the socket lives in a directory systemd creates
//! (`RuntimeDirectory=`, mode `0750`, group `kagisecure`) and is itself `0660`, so only the
//! service account and members of that group can connect. What they may ask for is decided by the
//! grants; a caller can do no more than start a command the owner already granted, exactly.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use crate::engine::Engine;
use crate::protocol::{MAX_REQUEST, Request, Response};
use crate::{Result, io};

/// The default socket path.
pub const DEFAULT_SOCKET: &str = "/run/kagisecure-host/host.sock";

/// Bind `path` (replacing a stale socket), make it `0660`, and serve until the process ends.
///
/// # Errors
///
/// If the socket cannot be bound.
pub fn serve(engine: Arc<Engine>, path: &Path) -> Result<()> {
    let listener = bind(path)?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || handle(&engine, stream));
    }
    Ok(())
}

/// Bind `path`, replacing a stale socket, `0660`.
///
/// # Errors
///
/// If it cannot be bound or its mode set.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path).map_err(io(format!("removing {}", path.display())))?;
    }
    let listener = UnixListener::bind(path).map_err(io(format!("binding {}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(io(format!("setting the mode of {}", path.display())))?;
    Ok(listener)
}

/// Answer one connection: one request line, one response line.
pub fn handle(engine: &Engine, stream: UnixStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut line = String::new();
    let limit = u64::try_from(MAX_REQUEST).unwrap_or(u64::MAX);
    let read = BufReader::new(read_half.take(limit)).read_line(&mut line);
    let response = match read {
        Ok(_) if line.ends_with('\n') => match serde_json::from_str::<Request>(&line) {
            Ok(request) => engine.handle(&request),
            Err(e) => Response::Refused {
                reason: "BAD_REQUEST".to_owned(),
                message: format!("not a request: {e}"),
            },
        },
        _ => Response::Refused {
            reason: "BAD_REQUEST".to_owned(),
            message: "a request is one JSON line of at most 64 KiB".to_owned(),
        },
    };
    let mut stream = stream;
    if let Ok(mut json) = serde_json::to_string(&response) {
        json.push('\n');
        let _ = stream.write_all(json.as_bytes());
    }
}

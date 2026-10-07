//! `kagisecure-host`: kagisecure on a headless host (ADR-0043, accepted 2026-10-07 for deploy
//! keys).
//!
//! A host holds no personal vault and has no approval path. Everything it releases comes from a
//! **bundle** made on the owner's Mac: machine-vault environments and the standing grants meant
//! for this host, sealed to the host's key and signed by the owner's device key. A grant names
//! one exact command — executable pinned by SHA-256, argument pattern, working directory — and
//! the host starts that command itself, writing the values to its standard input (ADR-0047's
//! frame), never to its environment or arguments.
//!
//! - [`bundle`]: what a bundle carries, and how the Mac makes one.
//! - [`grant`]: whether a request is exactly what a grant names.
//! - [`identity`]: the host's key pair and the owner it trusts.
//! - [`store`]: the state directory — bundle, uses, suspensions, the audit log.
//! - [`engine`]: the decision and the release.
//! - `server` / `client`: the Unix socket a caller asks through.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bundle;
#[cfg(unix)]
pub mod client;
pub mod engine;
pub mod grant;
pub mod identity;
pub mod passwd;
pub mod protocol;
#[cfg(unix)]
pub mod server;
pub mod spec;
pub mod store;

/// Errors this crate reports. None carries a credential value.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// From the core.
    #[error(transparent)]
    Core(#[from] kagisecure_core::Error),
    /// From the bundle envelope.
    #[error(transparent)]
    Shared(#[from] kagisecure_shared::SharedError),
    /// File or socket I/O.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The error.
        source: std::io::Error,
    },
    /// A bundle, grant or state file that is not acceptable; says why.
    #[error("{0}")]
    Invalid(String),
}

/// This crate's result.
pub type Result<T> = std::result::Result<T, HostError>;

pub(crate) fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> HostError {
    let what = what.into();
    move |source| HostError::Io { what, source }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

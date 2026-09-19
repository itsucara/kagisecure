//! `kagisecure-core` — the vault, its crypto, the item model and the injection paths.
//!
//! This crate is the whole product minus UI and transport. It has no networking, no MCP types
//! and no UI types (see `docs/architecture.md` §2.1).
//!
//! # Feature flags
//!
//! * `secret-material` (default) — compiles the [`Secret`] type, the vault
//!   open/save paths, recovery codes and the injector. Crates that must never be able to hold
//!   plaintext (`kagisecure-mcp`, `kagisecure-ipc`) depend on this crate with
//!   `default-features = false` and see only the metadata-only modules.
//!   The password generator ([`generator`]) and the TOTP engine ([`totp`]) are behind this flag
//!   too: both *produce* secret material — a generated password and a one-time code are values,
//!   not metadata — so a crate that may not hold plaintext must not be able to call them
//!   (mcp-server.md §2.7).
//! * `proto` — a no-op marker enabled by those crates so that their `Cargo.toml` says what they
//!   want rather than only what they refuse (ADR-0002 §3). The metadata modules
//!   ([`proto`], [`audit`], [`lease`]) are compiled unconditionally; none of them can name
//!   `Secret`.
//!
//! # Threat-model notes that constrain this crate
//!
//! * No secret value ever appears in an [`Error`] message, a `Debug` rendering or a log line
//!   (threat-model M-14).
//! * Vault files are written atomically and mode `0600` on Unix (threat-model M-13).
//! * KDF parameters are read from the vault header, never hardcoded in the open path
//!   (vault-format §9).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod error;
pub mod lease;
pub mod proto;

pub use error::{Error, Result};

#[cfg(feature = "secret-material")]
pub mod crypto;
#[cfg(feature = "secret-material")]
pub mod generator;
#[cfg(feature = "secret-material")]
pub mod inject;
#[cfg(feature = "secret-material")]
pub mod model;
#[cfg(feature = "secret-material")]
pub mod recovery;
#[cfg(feature = "secret-material")]
pub mod totp;
#[cfg(feature = "secret-material")]
pub mod vault;

#[cfg(feature = "secret-material")]
pub use model::{Environment, Secret};
#[cfg(feature = "secret-material")]
pub use recovery::RecoveryCode;
#[cfg(feature = "secret-material")]
pub use totp::Totp;
#[cfg(feature = "secret-material")]
pub use vault::Vault;

/// Seconds since the Unix epoch, saturating at 0 for clocks set before 1970.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

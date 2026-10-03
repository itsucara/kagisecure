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
//! * Vault files are written atomically: mode `0600` on Unix, and on Windows an owner-only,
//!   inheritance-protected DACL set when the file is created (`windows_acl`) (threat-model M-13).
//! * KDF parameters are read from the vault header, never hardcoded in the open path
//!   (vault-format §9).
//!
//! # `unsafe`: forbidden everywhere but one Windows-only module
//!
//! The crate is `#![forbid(unsafe_code)]` on every platform except Windows, where it is
//! `#![deny(unsafe_code)]` instead. The one reason is `windows_acl`: `std` has no API for a
//! file's security descriptor, so giving the vault the Windows counterpart of `0600` takes
//! `windows-sys` calls — and `forbid`, by design, cannot be relaxed by a nested `allow` for one
//! module. Every other module is exactly as `unsafe`-free as `forbid` would make it, and
//! `windows_acl` states its own `#![allow(unsafe_code)]`, and why, at the top of the file.
//! `kagisecure-ipc` made the same trade for the same reason (see its crate documentation).

#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]
#![warn(missing_docs)]

pub mod audit;
pub mod error;
pub mod lease;
pub mod proto;
#[cfg(windows)]
pub mod windows_acl;

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

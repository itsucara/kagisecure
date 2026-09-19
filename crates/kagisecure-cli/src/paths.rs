//! Where the vault lives.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Default vault file name.
pub const DEFAULT_FILE: &str = "default.kagivault";

/// The per-user default vault path.
///
/// macOS: `~/Library/Application Support/kagisecure/default.kagivault`.
/// Linux: `~/.local/share/kagisecure/default.kagivault`.
/// Windows: `%APPDATA%\kagisecure\data\default.kagivault`.
///
/// All state lives under the user's own home directory — no system-wide daemon and no shared
/// temporary files (threat-model M-15).
///
/// # Errors
///
/// If the platform's data directory cannot be determined.
pub fn default_vault_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "kagisecure")
        .context("could not determine this platform's application data directory")?;
    Ok(dirs.data_dir().join(DEFAULT_FILE))
}

/// Resolve the vault path from the `--vault` flag, `KAGISECURE_VAULT`, or the default.
///
/// # Errors
///
/// If no path was given and the default cannot be determined.
pub fn resolve(explicit: Option<PathBuf>) -> Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        None => default_vault_path(),
    }
}

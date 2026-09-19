//! Overwriting and removing an export file after it has been imported.
//!
//! # This is best effort, and saying so is part of the feature
//!
//! An export from another password manager is a complete plaintext copy of the user's vault,
//! sitting in `~/Downloads`. Importing it does not make that copy go away, and leaving it there
//! is very often the worst thing about the whole day (threat-model W-9). So kagisecure offers to
//! remove it — and must be honest about what "remove" can mean on a modern machine:
//!
//! * **APFS is copy-on-write.** Overwriting a file's bytes writes *new* blocks; the old ones stay
//!   allocated until they are reused.
//! * **Local snapshots and Time Machine** may already hold the file, and nothing a process can do
//!   reaches into a snapshot.
//! * **SSD wear levelling** means the drive decides which physical cells a logical block lands
//!   on. A single-pass overwrite does not reach the cells that held the old contents.
//! * **Spotlight, Quick Look thumbnails and the browser's own download cache** may hold
//!   derivatives.
//!
//! What this does still helps in the common case — the file is gone from the filesystem, and a
//! casual undelete will not bring it back — and the wording the user sees says exactly that:
//! *best effort — the file may survive in a snapshot, a backup or unallocated SSD blocks*
//! (plan §9 decision 4).
//!
//! It is **never** implicit: a flag on the command line, a button in the app, always after the
//! vault has been saved successfully.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand_core::{RngCore, TryRngCore};
use zeroize::Zeroizing;

use crate::error::{ImportError, Result};

/// How far [`shred_file`] got.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ShredOutcome {
    /// The file's bytes were overwritten and the write was flushed to the device.
    pub overwritten: bool,
    /// The directory entry is gone.
    pub removed: bool,
}

impl ShredOutcome {
    /// The sentence a UI puts under the result. Deliberately does not say "securely erased".
    #[must_use]
    pub fn caveat(self) -> &'static str {
        if self.removed && self.overwritten {
            "Best effort — the file may survive in a snapshot, a backup or unallocated SSD blocks."
        } else if self.removed {
            "The file was removed, but its contents could not be overwritten first."
        } else {
            "The file could not be removed."
        }
    }
}

/// The buffer size used for the overwrite pass. One megabyte: big enough that a large export is
/// not thousands of syscalls, small enough to keep off the stack and out of a big allocation.
const CHUNK: usize = 1 << 20;

/// Overwrite `path` with random bytes, truncate it and remove it.
///
/// The sequence is: open write-only, overwrite the full length with CSPRNG bytes, `sync_data`,
/// `set_len(0)`, `sync_all`, `remove_file`. The syncs are what make the overwrite reach the
/// device rather than sitting in the page cache until the `unlink` makes it moot.
///
/// Random bytes rather than zeroes so that the overwrite is not compressible: a filesystem or an
/// SSD controller that deduplicates or compresses can turn a run of zeroes into "a hole", writing
/// nothing at all and leaving the original blocks exactly where they were.
///
/// On macOS the file's extended attributes are dropped first, because an xattr is stored
/// separately from the data fork and truncating the file does not touch it.
///
/// Errors after a partial overwrite are returned rather than swallowed, with whatever succeeded
/// reported — a caller that is told `overwritten: false, removed: false` still has the file.
///
/// # Errors
///
/// [`ImportError::SourceNotFound`] if there is nothing there, or [`ImportError::Io`] if the file
/// cannot be opened for writing. A failure *after* the file has been opened is reported through
/// the returned [`ShredOutcome`], not as an error: the caller needs to know how far it got.
pub fn shred_file(path: &Path) -> Result<ShredOutcome> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ImportError::SourceNotFound(path.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };
    if !metadata.is_file() {
        return Err(ImportError::SourceNotFound(path.to_path_buf()));
    }

    #[cfg(target_os = "macos")]
    drop_xattrs(path);

    let mut outcome = ShredOutcome::default();
    let mut file = OpenOptions::new().write(true).open(path)?;

    if overwrite(&mut file, metadata.len()).is_ok() {
        outcome.overwritten = true;
    }
    let _ = file.set_len(0);
    let _ = file.sync_all();
    drop(file);

    outcome.removed = std::fs::remove_file(path).is_ok();
    Ok(outcome)
}

/// Write `len` random bytes over the start of `file`.
fn overwrite(file: &mut std::fs::File, len: u64) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    let mut written = 0u64;
    let mut rng = rand_core::OsRng.unwrap_err();
    while written < len {
        let want = usize::try_from((len - written).min(CHUNK as u64)).unwrap_or(CHUNK);
        rng.fill_bytes(&mut buffer[..want]);
        file.write_all(&buffer[..want])?;
        written += want as u64;
    }
    file.flush()?;
    file.sync_data()
}

/// Remove every extended attribute from `path`, best effort.
///
/// Shells out to `xattr -c` rather than calling `removexattr(2)`, because this crate forbids
/// `unsafe` and the whole step is already best effort. A machine without the tool, or a file
/// whose xattrs cannot be cleared, loses nothing that the overwrite below was going to give it.
#[cfg(target_os = "macos")]
fn drop_xattrs(path: &Path) {
    let _ = std::process::Command::new("/usr/bin/xattr")
        .arg("-c")
        .arg("--")
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_overwritten_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, b"title,url,username,password\nAcme,,ada,hunter2\n").unwrap();

        let outcome = shred_file(&path).unwrap();
        assert!(outcome.overwritten);
        assert!(outcome.removed);
        assert!(!path.exists());
        assert!(outcome.caveat().contains("Best effort"));
    }

    #[test]
    fn an_empty_file_is_still_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.1pux");
        std::fs::write(&path, b"").unwrap();

        let outcome = shred_file(&path).unwrap();
        assert!(outcome.overwritten);
        assert!(outcome.removed);
    }

    #[test]
    fn a_file_larger_than_one_chunk_is_fully_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, vec![0xABu8; CHUNK + 4_096]).unwrap();

        assert!(shred_file(&path).unwrap().overwritten);
        assert!(!path.exists());
    }

    #[test]
    fn a_missing_file_is_reported_rather_than_silently_succeeding() {
        let dir = tempfile::tempdir().unwrap();
        let err = shred_file(&dir.path().join("nope")).unwrap_err();
        assert!(matches!(err, ImportError::SourceNotFound(_)));
        // A directory is not a file, and must not be walked into.
        let err = shred_file(dir.path()).unwrap_err();
        assert!(matches!(err, ImportError::SourceNotFound(_)));
    }
}

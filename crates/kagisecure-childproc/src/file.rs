//! Identifying a file by what it *is* rather than by the path that names it right now.
//!
//! `kagisecure-core`'s `.env` shredder must destroy exactly the file kagisecure wrote, never
//! whatever a path has been pointed at since: a revoke needs no approval and a lock shreds every
//! file in the written ledger, so a symlink or a different file planted at the path after the
//! write would otherwise turn cleanup into "zero any file this user can write". The fix is to
//! remember the file's identity at write time and to act only on a handle that
//!
//! 1. was opened **without following** a final symlink (`O_NOFOLLOW`; on Windows
//!    `FILE_FLAG_OPEN_REPARSE_POINT`, which opens a reparse point itself rather than its target),
//!    and
//! 2. names the same file as the one written — compared on the open handle, so there is no gap
//!    between checking and acting in which the path could be swapped again.
//!
//! On Unix both halves have safe spellings in `std` once the flag constants are in hand (which is
//! why this needs `libc` at all); Windows' file index is only reachable through
//! `GetFileInformationByHandle`, which has no safe wrapper — that call is the reason this module
//! lives in the crate whose job is to hold the FFI the other two crates forbid.

use std::fs::File;
use std::io;
use std::path::Path;

/// Open `path` for reading (and, if `write`, for writing) **without following a symlink** in its
/// final component.
///
/// A symlink there is an error rather than its target (`ELOOP` on Unix; on Windows the reparse
/// point itself is opened, and its metadata reports it as not a regular file). On Unix the open is
/// also non-blocking, so a FIFO planted at the path cannot park the caller waiting for a writer;
/// a regular file ignores the flag.
///
/// # Errors
///
/// Whatever the OS reports: not found, permission denied, a symlink, and so on.
pub fn open_no_follow(path: &Path, write: bool) -> io::Result<File> {
    imp::open_no_follow(path, write)
}

/// The identity of an open file: `(device, file number)` — `st_dev`/`st_ino` on Unix, the volume
/// serial number and the 64-bit file index on Windows.
///
/// Two handles with equal identities name the same file for as long as both are open. A number
/// can be reused once the file it named is deleted, which is why a caller compares an identity it
/// recorded against a handle it holds, not against another path lookup.
///
/// # Errors
///
/// Whatever the OS reports when asked about the handle.
pub fn identity(file: &File) -> io::Result<(u64, u128)> {
    imp::identity(file)
}

#[cfg(unix)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    pub(super) fn open_no_follow(path: &Path, write: bool) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    pub(super) fn identity(file: &File) -> io::Result<(u64, u128)> {
        let meta = file.metadata()?;
        Ok((meta.dev(), u128::from(meta.ino())))
    }
}

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
    };

    pub(super) fn open_no_follow(path: &Path, write: bool) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub(super) fn identity(file: &File) -> io::Result<(u64, u128)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is owned by `file`, which outlives this call; `info` is a local,
        // fully initialized value of exactly the type the API writes, borrowed mutably for the
        // duration of the call only.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let index = (u128::from(info.nFileIndexHigh) << 32) | u128::from(info.nFileIndexLow);
        Ok((u64::from(info.dwVolumeSerialNumber), index))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_symlink_in_the_final_component_is_refused_not_followed() {
        let dir = tempfile_dir();
        let target = dir.join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_no_follow(&link, true).is_err());
        assert!(open_no_follow(&target, true).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn identity_tells_two_files_apart_and_one_file_from_itself() {
        let dir = tempfile_dir();
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        let ia = identity(&open_no_follow(&a, false).unwrap()).unwrap();
        let ib = identity(&open_no_follow(&b, false).unwrap()).unwrap();
        assert_ne!(ia, ib);
        assert_eq!(ia, identity(&File::open(&a).unwrap()).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// No `tempfile` dependency for one directory: this crate is kept to the FFI it exists for.
    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kagisecure-childproc-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

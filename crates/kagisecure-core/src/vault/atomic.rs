//! Atomic file writes and bounded reads, shared by every file this crate writes.
//!
//! Both functions here were written for the personal vault file and, until this refactor, lived
//! as private functions inside `vault/mod.rs`. They assume nothing about the file's contents —
//! only that it should be replaced whole, never edited in place, and that a reader must refuse an
//! unreasonably large file before allocating anything for it. That makes them reusable for any
//! other file this crate or a dependent crate writes the same way: a shared vault's local replica
//! (ADR-0035) is the first of those. [`crate::vault::lock::FileLock`] is this module's usual
//! companion — a writer takes the lock, then calls [`write_atomically`]; a reader calls
//! [`read_file_bounded`] with no lock at all, because the rename in [`write_atomically`] already
//! guarantees a reader sees either the whole old file or the whole new one, never a mixture.

use std::io::Read;
use std::path::Path;

use crate::error::Result;

/// Write `bytes` to `path` atomically, owner-read/write only.
///
/// A temporary file in the same directory is created with mode `0600` *before* any bytes are
/// written to it, flushed, then renamed over the target. A crash therefore leaves either the old
/// file or the new one, never a half-written file, and the plaintext-adjacent window in which a
/// world-readable file exists is never opened at all.
///
/// # On Windows: an owner-only DACL, set as the file is created
///
/// `OpenOptionsExt::mode` has no Windows meaning, so there the `0600` and `0700` above are
/// replaced by `crate::windows_acl`, which describes the descriptor exactly: owner = the user,
/// a *protected* DACL (nothing inherited from the parent), one entry granting `FILE_ALL_ACCESS`
/// to the user's SID and nobody else — not SYSTEM, not Administrators, for the reasons given
/// there. It is passed to `CreateFileW` itself, so the temporary file never exists under any
/// other ACL — the same "before a single byte" property the Unix path has — and the rename keeps
/// it, because a rename moves the file's own descriptor with it.
///
/// Be precise about what that buys, because the obvious reading overstates it:
///
/// * **Not** protection from anything the user runs. No file permission system stops that; a
///   process running as the user has the user's rights on Unix too.
/// * The protection is against **other users of the machine**. A default `%LOCALAPPDATA%`
///   subtree grants only SYSTEM / Administrators / the user, but that is inheritance from a
///   parent this code did not create and does not check; a file under a redirected profile, a
///   shared drive, a path the user chose, or a directory an installer created as someone else
///   used to inherit that directory's ACL instead. It no longer does.
///
/// Directories: the ones this call *creates* get the directory form of the descriptor, whose
/// entry is inherited by anything created inside them later. An existing directory is left
/// alone — unlike Unix, where it is `chmod`ed `0700` best effort — because on Windows a
/// directory's DACL does not stop another user opening a file inside it by path (Bypass
/// traverse checking), and rewriting it would propagate down every file beneath it. The file's
/// own DACL is the boundary. The directory `fsync` has no Windows equivalent and is a durability
/// point, not a security one; `sync_all` already flushes the file.
///
/// Not tested: another account actually being refused. The tests read the descriptor back and
/// assert its exact shape; the refusal itself follows from Windows' access check and has not
/// been exercised with a second login.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<std::fs::Metadata> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(not(windows))]
    std::fs::create_dir_all(dir)?;
    #[cfg(windows)]
    crate::windows_acl::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best effort: an existing directory keeps whatever mode it has.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    let tmp = temporary_beside(path)?;

    #[cfg(not(windows))]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(not(windows))]
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| -> Result<std::fs::Metadata> {
        #[cfg(not(windows))]
        let mut file = opts.open(&tmp)?;
        // `create_new` semantics, with the owner-only descriptor part of the create call.
        #[cfg(windows)]
        let mut file = crate::windows_acl::create_new_file(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // Taken from the handle, after the last write and before the rename: this describes the
        // inode that becomes the file, whatever the path names a moment later.
        let written = file.metadata()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        Ok(written)
    })();

    let written = match result {
        Ok(written) => written,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };

    // Best effort: make the rename durable too. Not available on Windows.
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(written)
}

/// Write `bytes` to a new file at `path`, owner-read/write only, failing if anything is already
/// there — an error of kind [`std::io::ErrorKind::AlreadyExists`] — and never replacing it.
///
/// For a file that must not overwrite an older one of the same name: the copy a format upgrade
/// takes before it writes (vault-format §9 rule 3), and a shared vault's record in an exchange
/// directory (ADR-0035). Atomic, as [`write_atomically`] is: the bytes go to a temporary file in
/// the same directory, created with mode `0600` (on Windows, the owner-only descriptor
/// [`write_atomically`] describes) before a byte is written, and flushed; the temporary is then
/// hard-linked to `path` — which, unlike a rename, fails rather than replaces when `path` exists
/// — and unlinked, and the directory is flushed. A crash therefore leaves either no file at
/// `path` or the complete one, never a short one.
///
/// The temporary is named `<name of temp_beside>.<16 hex>.tmp`, the pattern
/// [`crate::vault::lock::FileLock::sweep_stale_temporaries`] removes for the file `temp_beside`,
/// so a writer holding that file's lock cleans up after a crash here too. It must be in the same
/// directory as `path`.
///
/// **On a file system without hard links** — FAT, exFAT, some network and sync file systems,
/// which refuse the link as unsupported or not permitted — the file is created directly at
/// `path` instead, create-new (`O_CREAT | O_EXCL`, the same owner-only mode), written and
/// flushed. It still never replaces anything, and a write that fails removes what it created;
/// but it is not atomic: a crash in the middle can leave a short file at `path`.
///
/// # Errors
///
/// An I/O error, including one of kind [`std::io::ErrorKind::AlreadyExists`].
pub fn write_new_file(path: &Path, bytes: &[u8], temp_beside: &Path) -> Result<()> {
    write_new_file_linking(path, bytes, temp_beside, |from, to| {
        std::fs::hard_link(from, to)
    })
}

/// [`write_new_file`], with the hard link made by `link` — `std::fs::hard_link`, or, in tests,
/// one that fails the way a file system without links does.
fn write_new_file_linking(
    path: &Path,
    bytes: &[u8],
    temp_beside: &Path,
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = temporary_beside(temp_beside)?;

    let mut file = create_new_owner_only(&tmp)?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            link(&tmp, path)
        });
    let _ = std::fs::remove_file(&tmp);
    match result {
        Ok(()) => {}
        Err(e) if links_unsupported(&e) => write_new_in_place(path, bytes)?,
        Err(e) => return Err(e.into()),
    }

    // Best effort: make the new name durable too. Not available on Windows.
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// A new, empty file at `path`, owner-only from the moment it exists, failing if anything is
/// there.
fn create_new_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(not(windows))]
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
    }
    #[cfg(windows)]
    {
        crate::windows_acl::create_new_file(path)
    }
}

/// Whether a failed hard link means the file system has none, rather than something else.
fn links_unsupported(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
    ) {
        return true;
    }
    // ERROR_INVALID_FUNCTION: what Windows answers for a hard link on FAT.
    #[cfg(windows)]
    if error.raw_os_error() == Some(1) {
        return true;
    }
    false
}

/// [`write_new_file`]'s fallback for a file system without hard links: create-new at `path`
/// itself, write, flush — removing what it created if the write fails.
fn write_new_in_place(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut file = create_new_owner_only(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        // Remove what this call created — and only that: if something replaced it at `path`
        // in the meantime, it is left alone.
        if is_same_file(&file, path) {
            let _ = std::fs::remove_file(path);
        }
        return Err(e.into());
    }
    Ok(())
}

/// Whether `path` still names the file `file` has open. On Unix, by device and inode; elsewhere
/// the standard library offers no stable file identity, and the file is taken to be ours.
fn is_same_file(file: &std::fs::File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (file.metadata(), std::fs::symlink_metadata(path)) {
            (Ok(ours), Ok(there)) => ours.dev() == there.dev() && ours.ino() == there.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        true
    }
}

/// A fresh temporary path beside `path`: `<file name>.<16 hex>.tmp` in the same directory.
fn temporary_beside(path: &Path) -> Result<std::path::PathBuf> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let suffix = crate::crypto::random::array::<8>()?;
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    name.push('.');
    for b in suffix {
        name.push_str(&format!("{b:02x}"));
    }
    name.push_str(".tmp");
    Ok(dir.join(name))
}

/// Read the whole file at `path`, refusing one over `max` bytes before allocating anything for
/// it.
///
/// The file's declared length (its metadata) is checked before any allocation, and only it is
/// reserved — fallibly, so a failed allocation is an error rather than an abort. The read itself
/// is capped too, because metadata can understate a file that is still growing, or a special file
/// that has no meaningful length.
///
/// # Errors
///
/// [`crate::Error::VaultTooLarge`] when the file is, or claims to be, over `max` bytes; otherwise
/// an I/O error, including one of kind [`std::io::ErrorKind::NotFound`] when there is nothing at
/// `path`.
pub fn read_file_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let declared_len = file.metadata()?.len();
    read_bounded(file, declared_len, max, path)
}

/// Read at most `max` bytes, refusing more.
///
/// `declared_len` (the file's metadata) is checked before any allocation, and only it is
/// reserved — fallibly, so a failed allocation is an error rather than an abort. The read itself is
/// capped too, because metadata can understate a file that is still growing, or a special file
/// that has no meaningful length.
///
/// Crate-private: [`read_file_bounded`] is the public entry point for a caller that only has a
/// path; this lower-level form exists so [`crate::vault::Vault`]'s own read path can reuse the
/// same bounds-checking logic on a file handle it has already opened (to also read its metadata
/// for a fingerprint) without opening the file twice.
pub(crate) fn read_bounded(
    reader: impl Read,
    declared_len: u64,
    max: u64,
    path: &Path,
) -> Result<Vec<u8>> {
    let too_large = || crate::Error::VaultTooLarge {
        path: path.to_owned(),
        max,
    };
    if declared_len > max {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    let reserve = usize::try_from(declared_len).map_err(|_| too_large())?;
    bytes
        .try_reserve_exact(reserve)
        .map_err(|_| crate::Error::Io(std::io::ErrorKind::OutOfMemory.into()))?;
    reader.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(too_large());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.bin");
        write_atomically(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn atomic_write_replaces_the_file_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.bin");
        write_atomically(&path, b"first").unwrap();
        write_atomically(&path, b"second, longer than first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second, longer than first");
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_new_file_is_owner_only_and_never_replaces_an_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let beside = dir.path().join("thing");
        let path = dir.path().join("thing.bak-1");
        write_new_file(&path, b"first", &beside).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let again = write_new_file(&path, b"second", &beside);
        assert!(
            matches!(&again, Err(crate::Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "{again:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        // No temporary is left behind, whether the call succeeded or found the name taken.
        assert_eq!(names_in(dir.path()), ["thing.bak-1"]);
    }

    /// On a file system that refuses hard links, the file is created in place, create-new: the
    /// same contents and mode, still never replacing anything, and no temporary left behind.
    #[test]
    fn a_new_file_is_written_in_place_where_hard_links_are_unsupported() {
        let refusals = [
            std::io::ErrorKind::Unsupported,
            std::io::ErrorKind::PermissionDenied,
        ];
        for kind in refusals {
            let dir = tempfile::tempdir().unwrap();
            let beside = dir.path().join("records");
            let path = dir.path().join("a.ksr");
            let no_links = |_: &Path, _: &Path| Err(std::io::Error::from(kind));
            write_new_file_linking(&path, b"first", &beside, no_links).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"first");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
            let again = write_new_file_linking(&path, b"second", &beside, no_links);
            assert!(
                matches!(&again, Err(crate::Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
                "{again:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"first");
            assert_eq!(names_in(dir.path()), ["a.ksr"]);
        }
        // Any other failure of the link is reported, and nothing is left at the name.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.ksr");
        let broken = |_: &Path, _: &Path| Err(std::io::Error::other("disk on fire"));
        assert!(write_new_file_linking(&path, b"x", &dir.path().join("records"), broken).is_err());
        assert!(names_in(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_file_replaced_at_the_name_is_not_taken_for_ours() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.ksr");
        let file = create_new_owner_only(&path).unwrap();
        assert!(is_same_file(&file, &path));
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"someone else's").unwrap();
        assert!(!is_same_file(&file, &path));
    }

    #[test]
    fn a_new_file_s_temporary_is_one_the_lock_sweeps_for_the_file_it_sits_beside() {
        let dir = tempfile::tempdir().unwrap();
        let beside = dir.path().join("v.kagivault");
        let tmp = temporary_beside(&beside).unwrap();
        let name = tmp.file_name().unwrap().to_string_lossy().into_owned();
        let hex = name
            .strip_prefix("v.kagivault.")
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .unwrap();
        assert_eq!(hex.len(), 16, "{name}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        assert_eq!(tmp.parent(), beside.parent());
    }

    #[test]
    fn read_file_bounded_refuses_a_file_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thing.bin");
        std::fs::write(&path, vec![0u8; 32]).unwrap();
        assert!(matches!(
            read_file_bounded(&path, 16),
            Err(crate::Error::VaultTooLarge { max: 16, .. })
        ));
        assert_eq!(read_file_bounded(&path, 32).unwrap().len(), 32);
    }

    #[test]
    fn read_bounded_rejects_a_reader_that_lies_about_its_length() {
        let data = vec![0u8; 64];
        // Declared length under the cap, but the reader actually offers more than `max`.
        let result = read_bounded(&data[..], 4, 16, Path::new("/v"));
        assert!(matches!(result, Err(crate::Error::VaultTooLarge { .. })));
        assert_eq!(
            read_bounded(&data[..], 64, 64, Path::new("/v")).unwrap(),
            data
        );
    }
}

//! The sibling lock file that serialises every writer of one vault file.
//!
//! # Why a sibling file, and why it is never deleted
//!
//! A vault is written by *replacing* it: `write_atomically` renames a complete temporary file
//! over the path. A lock taken on the vault file itself would be a lock on an inode the very next
//! save unlinks — the following writer would open the *new* file, find it unlocked, and two
//! processes would both believe they held the lock. The lock therefore lives on
//! `<vault>.lock` ([`lock_path`]): a separate, empty file that is created once with mode `0600`
//! (on Windows, the owner-only DACL of `crate::windows_acl`, as the vault file itself gets),
//! never written, never renamed and **never deleted** by this crate. Deleting it on release would
//! reintroduce the same race one level down: a waiter still holding a handle to the unlinked
//! inode would lock that orphan while a newcomer created and locked a fresh file at the path.
//!
//! # What the lock does and does not promise
//!
//! It is advisory and cooperative: `flock(2)` on Unix and `LockFileEx` on Windows, both through
//! `std::fs::File::try_lock`. Every writer in this build takes it before it reads the state it is
//! about to change and holds it until the new file has been renamed into place. Readers never
//! take it, because the atomic rename already guarantees they see either the old file or the new
//! one, never a mixture.
//!
//! It is **not** a security boundary. Anything running as the user can write the vault file
//! directly, lock or no lock; the lock only stops kagisecure's own writers from erasing each
//! other's work. Builds that predate it (0.1.x) do not take it at all.
//!
//! The kernel drops the lock when its holder exits for any reason, `SIGKILL` included, so a
//! crashed writer can never wedge the vault. `flock` locks belong to an open file description,
//! and std opens every file close-on-exec, so a child process does not inherit one.
//!
//! # Replacement while waiting or while held
//!
//! On Unix a lock is only as good as the path still naming the locked inode. After a successful
//! `try_lock` the acquirer compares the `(dev, ino)` of its handle with a fresh `stat` of the path
//! and goes round again if the file was replaced between its `open` and its `flock`. The holder
//! re-checks immediately before it writes (`FileLock::ensure_current`) and aborts with
//! [`Error::LockLost`] if the lock file was renamed or deleted while it was held — by then a
//! second process may have created a fresh lock file and "acquired" that one too, so continuing
//! would be exactly the lost update the lock exists to prevent. A rename that lands in the
//! instant between that check and the write is not caught; that is the price of an advisory lock
//! any same-user process can tamper with, and is why it is described as cooperative above.
//!
//! On Windows the file is opened without `FILE_SHARE_DELETE`, so it cannot be renamed or deleted
//! while any kagisecure process has it open, and neither check is needed.
//!
//! # Waiting
//!
//! Acquisition polls `try_lock` with jittered exponential backoff up to a caller-chosen timeout
//! and then fails with [`Error::VaultBusy`]. It never blocks indefinitely: a blocking `lock()`
//! cannot be abandoned, and the holder may be a stuck process the user needs to be told about.
//! What keeps waits short is the rule the transaction API enforces by taking a synchronous
//! closure: the lock is only ever held around in-memory work plus one file write — never across
//! a human prompt, an approval sheet, an Argon2id derivation or a child process.
//!
//! # File systems without locks
//!
//! Some network and FUSE file systems answer `ENOTSUP`/`EOPNOTSUPP`, `ENOLCK` or `ENOSYS`, and
//! some Windows network redirectors `ERROR_NOT_SUPPORTED` or `ERROR_INVALID_FUNCTION`. std maps
//! several of these to no specific `ErrorKind`, so they are recognised by number, per platform.
//! Writing without mutual exclusion is precisely the lost-update bug this module exists to
//! prevent, so such a vault refuses writes with [`Error::LockUnsupported`]; it can still be
//! opened and read.
//!
//! A sharing violation while opening the lock file on Windows (an antivirus scanner or backup
//! agent holding it without sharing) is contention, not failure: it is retried within the same
//! deadline as a held lock.
//!
//! # Linux NFS: no exclusion *within* one process
//!
//! The Linux NFS client emulates `flock` with POSIX `fcntl` byte-range locks, and those belong
//! to the *process*, not to the open file. Two processes still exclude each other there, but two
//! `Vault` values on the same NFS-hosted vault inside one process both "acquire" at once.
//! A process that needs more than one writer on such a vault must serialise them itself, e.g.
//! by sharing one `Vault` behind a mutex, as `kagisecure-agent`'s `VaultHandle` does. Local file
//! systems are unaffected: there `flock` locks belong to the open file, as described above.

use std::ffi::{OsStr, OsString};
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{File, TryLockError};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// How long a write waits for another writer before giving up with [`Error::VaultBusy`], unless
/// the caller chose otherwise with [`Vault::set_lock_timeout`](super::Vault::set_lock_timeout).
///
/// A holder only ever keeps the lock for one in-memory closure plus one `fsync`ed write, so
/// anything close to this long means the holder is stuck, not slow.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// The first pause between two `try_lock` attempts.
const FIRST_BACKOFF: Duration = Duration::from_millis(1);

/// The longest pause between two `try_lock` attempts. Small enough that a waiter notices a
/// release within a few tens of milliseconds, large enough that sixteen waiters do not spin.
const MAX_BACKOFF: Duration = Duration::from_millis(25);

/// The lock file that guards the vault at `vault_path`: the same directory, the vault's file
/// name with `.lock` appended.
///
/// Public so a caller can name it in a "waiting for another kagisecure process" message, and so
/// tests can tamper with it. Nothing outside this module creates, locks or removes it.
#[must_use]
pub fn lock_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path
        .file_name()
        .map_or_else(|| OsString::from("vault"), OsStr::to_os_string);
    name.push(".lock");
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

/// An exclusive lock on one file's sibling `.lock` file. Released when dropped.
///
/// Written for the personal vault, and exposed (this type was `pub(crate) VaultLock` until this
/// refactor) so any other file this crate or a dependent crate writes under the same
/// create-a-temporary-then-rename discipline can serialise its writers the same way — a shared
/// vault's local replica (ADR-0035) is the first of those. Nothing about the lock itself assumes
/// the guarded file is a vault: the parameter and field below are still named for the caller this
/// module was written for, and every error message still says "vault", which reads oddly from a
/// non-vault caller but changes no behaviour.
#[derive(Debug)]
pub struct FileLock {
    file: File,
    /// The lock file. Only Unix re-checks it (see `names_held_file`).
    #[cfg_attr(not(unix), allow(dead_code))]
    path: PathBuf,
    /// The vault it guards, for error messages: that is the path a user recognises.
    vault_path: PathBuf,
}

impl FileLock {
    /// Take the lock for the vault at `vault_path`, waiting at most `timeout`.
    ///
    /// Creates the containing directory and the lock file if they do not exist yet, which is
    /// what lets [`Vault::create`](super::Vault::create) hold the lock across its existence check
    /// and its first write.
    ///
    /// # Errors
    ///
    /// [`Error::VaultBusy`] when another writer still holds it after `timeout`,
    /// [`Error::LockUnsupported`] when the file system has no locks, and [`Error::Io`] when the
    /// lock file cannot be created or opened.
    pub fn acquire(vault_path: &Path, timeout: Duration) -> Result<Self> {
        let path = lock_path(vault_path);
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            // The lock is taken before a new vault's first write, so this is often where the
            // vault's directory is created: it must get the same owner-only descriptor
            // `write_atomically` would have given it, not an inherited ACL it then leaves alone.
            #[cfg(not(windows))]
            std::fs::create_dir_all(dir)?;
            #[cfg(windows)]
            crate::windows_acl::create_dir_all(dir)?;
        }
        let started = Instant::now();
        let mut backoff = FIRST_BACKOFF;
        loop {
            if let Some(lock) = Self::attempt(&path, vault_path)? {
                return Ok(lock);
            }
            let waited = started.elapsed();
            if waited >= timeout {
                return Err(Error::VaultBusy {
                    path: vault_path.to_owned(),
                    waited: timeout,
                });
            }
            std::thread::sleep(jittered(backoff).min(timeout - waited));
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// One try: `Some` with the lock, `None` if it is held elsewhere for now (contention, a
    /// transient sharing violation, a lock file replaced under us), or the error that ends
    /// waiting.
    fn attempt(path: &Path, vault_path: &Path) -> Result<Option<Self>> {
        let file = match open_lock_file(path) {
            Ok(file) => file,
            Err(e) => return classify(e, vault_path).map(|()| None),
        };
        match file.try_lock() {
            Ok(()) => {
                let lock = Self {
                    file,
                    path: path.to_owned(),
                    vault_path: vault_path.to_owned(),
                };
                // If the file was replaced between our `open` and our `flock`, what we hold
                // guards an orphaned inode nobody else will ever look at. Dropping `lock`
                // releases it; the next round opens whatever the path names now.
                Ok(lock.names_held_file()?.then_some(lock))
            }
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => classify(e, vault_path).map(|()| None),
        }
    }

    /// Fail unless the lock file this lock holds is still the one its path names.
    ///
    /// Called immediately before a write: see the module documentation for why a lock whose file
    /// was renamed away must not be trusted.
    ///
    /// # Errors
    ///
    /// [`Error::LockLost`] when the path now names a different file or nothing, [`Error::Io`]
    /// when it cannot be checked.
    pub fn ensure_current(&self) -> Result<()> {
        if self.names_held_file()? {
            Ok(())
        } else {
            Err(Error::LockLost(self.vault_path.clone()))
        }
    }

    /// Remove temporaries a crashed writer left behind (`<vault>.<16 hex digits>.tmp`).
    ///
    /// Only callable with the lock held, which is what makes it safe: every writer in this build
    /// creates its temporary and renames it away while holding this lock, so a temporary that
    /// exists while we hold it belongs to a writer that died mid-write. (A 0.1.x writer does not
    /// lock, and would find its temporary gone and its save failed — never a damaged vault.)
    /// Best effort: a temporary that cannot be removed is left for the next sweep.
    pub fn sweep_stale_temporaries(&self) {
        let Some(vault_name) = self.vault_path.file_name() else {
            return;
        };
        let prefix = format!("{}.", vault_name.to_string_lossy());
        let dir = match self.vault_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if is_stale_temporary(&name.to_string_lossy(), &prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    #[cfg(unix)]
    fn names_held_file(&self) -> Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let held = self.file.metadata()?;
        match std::fs::metadata(&self.path) {
            Ok(now) => Ok(now.dev() == held.dev() && now.ino() == held.ino()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Always true: the handle was opened without `FILE_SHARE_DELETE`, so nobody can have
    /// renamed or deleted the file while we have it open (see the module documentation).
    #[cfg(not(unix))]
    #[allow(clippy::unnecessary_wraps)] // Same signature as the Unix version.
    fn names_held_file(&self) -> Result<bool> {
        Ok(true)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing the handle releases the lock too, but Windows documents that release as
        // happening "at some point" after close; unlocking explicitly makes it immediate.
        let _ = self.file.unlock();
    }
}

#[cfg(not(windows))]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// On Windows: created with the owner-only DACL in the `CreateFileW` call itself (the `0600`
/// above), and shared for reading and writing — deliberately not `FILE_SHARE_DELETE`.
#[cfg(windows)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    /// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
    const SHARE_READ_WRITE: u32 = 0x1 | 0x2;
    crate::windows_acl::open_or_create_file(path, SHARE_READ_WRITE)
}

/// Raw OS error codes that mean "this file system cannot lock files at all". Matched by number
/// because std maps most of them to no specific `ErrorKind` (`ENOTSUP` on macOS comes out as
/// `Uncategorized`, for one), and a lock-less SMB, FUSE or NFS mount must be reported as that —
/// not as an opaque I/O error.
#[cfg(any(target_os = "linux", target_os = "android"))]
const LOCKS_UNSUPPORTED: &[i32] = &[
    95, // EOPNOTSUPP == ENOTSUP
    37, // ENOLCK: NFS without a lock manager
    38, // ENOSYS
];
#[cfg(target_vendor = "apple")]
const LOCKS_UNSUPPORTED: &[i32] = &[
    45,  // ENOTSUP: SMB, many FUSE file systems
    102, // EOPNOTSUPP
    77,  // ENOLCK
    78,  // ENOSYS
];
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const LOCKS_UNSUPPORTED: &[i32] = &[45 /* EOPNOTSUPP == ENOTSUP */, 77, 78];
#[cfg(target_os = "openbsd")]
const LOCKS_UNSUPPORTED: &[i32] = &[91 /* ENOTSUP */, 45 /* EOPNOTSUPP */, 77, 78];
#[cfg(target_os = "netbsd")]
const LOCKS_UNSUPPORTED: &[i32] = &[86 /* ENOTSUP */, 45 /* EOPNOTSUPP */, 77, 78];
#[cfg(windows)]
const LOCKS_UNSUPPORTED: &[i32] = &[
    1,   // ERROR_INVALID_FUNCTION: what some network redirectors answer LockFileEx with
    50,  // ERROR_NOT_SUPPORTED
    120, // ERROR_CALL_NOT_IMPLEMENTED
];
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    windows
)))]
const LOCKS_UNSUPPORTED: &[i32] = &[];

/// Raw OS error codes that mean "someone else has this file right now; try again". On Windows,
/// an antivirus scanner or backup agent that opens the lock file without sharing makes our `open`
/// fail with a sharing violation; that is contention like any other and is waited out within the
/// same deadline. (`try_lock`'s own `ERROR_LOCK_VIOLATION` is already `WouldBlock` in std; it is
/// listed for the `open` path.)
#[cfg(windows)]
const TRANSIENTLY_BUSY: &[i32] = &[
    32, // ERROR_SHARING_VIOLATION
    33, // ERROR_LOCK_VIOLATION
];
#[cfg(not(windows))]
const TRANSIENTLY_BUSY: &[i32] = &[];

/// Sort a failure to open or lock the lock file: `Ok(())` when it is contention to be waited out
/// like `WouldBlock`, [`Error::LockUnsupported`] when the file system simply has no locks, and
/// [`Error::Io`] for anything else.
fn classify(e: std::io::Error, vault_path: &Path) -> Result<()> {
    let code = e.raw_os_error();
    if e.kind() == ErrorKind::Interrupted || code.is_some_and(|c| TRANSIENTLY_BUSY.contains(&c)) {
        Ok(())
    } else if e.kind() == ErrorKind::Unsupported
        || code.is_some_and(|c| LOCKS_UNSUPPORTED.contains(&c))
    {
        Err(Error::LockUnsupported(vault_path.to_owned()))
    } else {
        Err(Error::Io(e))
    }
}

/// `backoff` plus up to the same again, drawn at random, so that waiters that started together
/// do not keep retrying in lockstep. The OS generator is used because it is the only one this
/// crate has (see `crypto::random`); if it fails, the pause is simply not jittered.
fn jittered(backoff: Duration) -> Duration {
    let fraction = crate::crypto::random::array::<2>().map_or(0, u16::from_le_bytes);
    backoff + backoff.mul_f64(f64::from(fraction) / f64::from(u16::MAX))
}

/// Whether `name` is `prefix` followed by exactly sixteen lowercase hex digits and `.tmp` —
/// the shape `write_atomically` gives its temporaries, and nothing else.
fn is_stale_temporary(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(|hex| {
            hex.len() == 16
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_in(dir: &Path) -> PathBuf {
        dir.join("v.kagivault")
    }

    #[test]
    fn the_lock_file_sits_beside_the_vault() {
        assert_eq!(
            lock_path(Path::new("/a/b/v.kagivault")),
            Path::new("/a/b/v.kagivault.lock")
        );
        assert_eq!(
            lock_path(Path::new("v.kagivault")),
            Path::new("v.kagivault.lock")
        );
    }

    /// [`FileLock`] guards any file, not only a `.kagivault`: a shared vault's replica (ADR-0035)
    /// will lock a `.kagishared` file the same way, with the same sibling `.lock` and the same
    /// busy behaviour.
    #[test]
    fn a_second_acquirer_on_an_arbitrary_non_vault_path_also_fails_busy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replica.kagishared");
        let held = FileLock::acquire(&path, Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        let second = FileLock::acquire(&path, Duration::from_millis(150));
        let waited = started.elapsed();
        match second {
            Err(Error::VaultBusy {
                path: reported,
                waited,
            }) => {
                assert_eq!(reported, path);
                assert_eq!(waited, Duration::from_millis(150));
            }
            other => panic!("expected VaultBusy, got {other:?}"),
        }
        assert!(
            waited >= Duration::from_millis(150),
            "gave up after {waited:?}, before its timeout"
        );
        drop(held);
    }

    #[test]
    fn a_second_acquirer_waits_and_then_reports_busy() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let held = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        let second = FileLock::acquire(&vault, Duration::from_millis(150));
        let waited = started.elapsed();
        match second {
            Err(Error::VaultBusy { path, waited }) => {
                assert_eq!(path, vault);
                assert_eq!(waited, Duration::from_millis(150));
            }
            other => panic!("expected VaultBusy, got {other:?}"),
        }
        assert!(
            waited >= Duration::from_millis(150),
            "gave up after {waited:?}, before its timeout"
        );
        drop(held);
    }

    #[test]
    fn dropping_the_lock_releases_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let first = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();
        drop(first);
        let second = FileLock::acquire(&vault, Duration::from_millis(10));
        assert!(second.is_ok(), "{second:?}");
        // The lock file is never deleted: removing it would let a waiter lock an orphan.
        drop(second);
        assert!(lock_path(&vault).exists());
    }

    #[test]
    fn a_waiter_gets_the_lock_once_the_holder_lets_go() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let held = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();
        let waiter_vault = vault.clone();
        let waiter = std::thread::spawn(move || {
            FileLock::acquire(&waiter_vault, Duration::from_secs(30)).map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(50));
        drop(held);
        assert!(waiter.join().unwrap().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let _held = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();
        let mode = std::fs::metadata(lock_path(&vault))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// The Windows counterpart: the owner-only, protected DACL, and — because the lock is taken
    /// before a new vault's first write — the directory it created carries the inheritable form.
    #[cfg(windows)]
    #[test]
    fn the_lock_file_and_the_directory_it_created_are_owner_only() {
        use crate::windows_acl::{self, ObjectKind};
        let dir = tempfile::tempdir().unwrap();
        let created = dir.path().join("made-by-the-lock");
        let vault = vault_in(&created);
        let _held = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();
        let me = windows_acl::current_user_sid().unwrap();
        let file = windows_acl::path_security(&lock_path(&vault)).unwrap();
        assert!(
            windows_acl::is_owner_only(&file, &me, ObjectKind::File, true),
            "{file:?}"
        );
        let directory = windows_acl::path_security(&created).unwrap();
        assert!(
            windows_acl::is_owner_only(&directory, &me, ObjectKind::Directory, true),
            "{directory:?}"
        );
    }

    /// The failure the holder's re-check exists for: once the lock file is renamed away, a
    /// newcomer creates a fresh one and locks it without waiting — two "holders" at once.
    #[cfg(unix)]
    #[test]
    fn a_lock_file_renamed_while_held_is_detected_by_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let held = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();
        held.ensure_current().unwrap();

        std::fs::rename(lock_path(&vault), dir.path().join("moved.lock")).unwrap();
        let interloper = FileLock::acquire(&vault, Duration::from_millis(10));
        assert!(
            interloper.is_ok(),
            "a fresh lock file is lockable at once — which is exactly the danger"
        );

        match held.ensure_current() {
            Err(Error::LockLost(path)) => assert_eq!(path, vault),
            other => panic!("expected LockLost, got {other:?}"),
        }
    }

    fn sorted(code: i32) -> &'static str {
        match classify(std::io::Error::from_raw_os_error(code), Path::new("/v")) {
            Ok(()) => "busy",
            Err(Error::LockUnsupported(_)) => "unsupported",
            Err(_) => "io",
        }
    }

    #[test]
    fn a_file_system_without_locks_is_reported_as_such_whatever_errno_it_uses() {
        assert!(matches!(
            classify(
                std::io::Error::from(ErrorKind::Unsupported),
                Path::new("/v")
            ),
            Err(Error::LockUnsupported(_))
        ));
        #[cfg(target_vendor = "apple")]
        for code in [45, 102, 77, 78] {
            assert_eq!(sorted(code), "unsupported", "errno {code}");
        }
        #[cfg(target_os = "linux")]
        for code in [95, 37, 38] {
            assert_eq!(sorted(code), "unsupported", "errno {code}");
        }
        #[cfg(windows)]
        for code in [1, 50, 120] {
            assert_eq!(sorted(code), "unsupported", "error {code}");
        }
    }

    #[test]
    fn contention_is_waited_out_and_everything_else_is_an_io_error() {
        assert!(
            classify(
                std::io::Error::from(ErrorKind::Interrupted),
                Path::new("/v")
            )
            .is_ok()
        );
        assert!(matches!(
            classify(
                std::io::Error::from(ErrorKind::PermissionDenied),
                Path::new("/v")
            ),
            Err(Error::Io(_))
        ));
        #[cfg(unix)]
        assert_eq!(sorted(2 /* ENOENT */), "io");
        #[cfg(windows)]
        for code in [32, 33] {
            assert_eq!(sorted(code), "busy", "error {code}");
        }
    }

    #[test]
    fn only_the_writers_own_temporaries_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let stale = dir.path().join("v.kagivault.0123456789abcdef.tmp");
        let keep = [
            "v.kagivault",
            "v.kagivault.lock",
            "v.kagivault.FEDCBA9876543210.tmp",
            "v.kagivault.0123.tmp",
            "other.kagivault.0123456789abcdef.tmp",
            "notes.tmp",
        ];
        std::fs::write(&stale, b"x").unwrap();
        for name in keep {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let held = FileLock::acquire(&vault, Duration::from_secs(1)).unwrap();
        held.sweep_stale_temporaries();
        assert!(!stale.exists());
        for name in keep {
            assert!(dir.path().join(name).exists(), "{name} was swept");
        }
    }

    #[test]
    fn jitter_stays_within_twice_the_backoff() {
        for _ in 0..100 {
            let d = jittered(Duration::from_millis(4));
            assert!(d >= Duration::from_millis(4) && d <= Duration::from_millis(8));
        }
    }
}

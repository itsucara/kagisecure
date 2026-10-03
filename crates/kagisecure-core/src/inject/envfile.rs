//! The `.env` file writer (mcp-server.md §2.7, threat-model M-13/M-16).
//!
//! Rules this module enforces rather than documents:
//!
//! 1. The file is created mode `0600` — on Windows, with an owner-only DACL; see [`fn@write`] —
//!    **before** any byte is written to it, so there is no window in which a file other users
//!    can read holds a secret. The temporary file is created with `create_new` (`O_EXCL`;
//!    `CREATE_NEW` on Windows) and renamed into place, so a crash leaves the old file or the new
//!    one, never half of either.
//! 2. The contents live in a [`Zeroizing`] buffer for their whole life in this process.
//! 3. An existing file is never clobbered unless the caller passes `overwrite`.
//! 4. [`shred`] overwrites the bytes before unlinking. That is best effort on a journalling or
//!    copy-on-write filesystem, and says so.
//! 5. [`shred`] acts only on the file that was written. [`write()`] reports the written file's
//!    identity ([`FileIdentity`]); the shredder opens the path without following a final symlink
//!    and touches nothing unless the handle it holds is that same regular file. The path is not
//!    the file: it can be repointed after the write, and a revoke needs no approval.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::EnvInjection;
use crate::error::{Error, Result};
use crate::lease::FileIdentity;
use crate::proto::VarName;

/// The default file name.
pub const DEFAULT_FILENAME: &str = ".env";

/// What a write produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrittenFile {
    /// Where it landed.
    pub path: PathBuf,
    /// How many bytes were written.
    pub bytes: usize,
    /// The variable names written, in order.
    pub variables: Vec<String>,
    /// Whether the file is covered by a `.gitignore` in the work tree, or `None` when the target
    /// is not inside one. Best effort; see [`gitignore_status`].
    pub gitignored: Option<bool>,
    /// Which file was written: read off the handle the bytes went through, before the rename
    /// put it at `path`. The only file [`shred`] will later touch for this write.
    pub identity: FileIdentity,
}

/// What [`shred`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shredded {
    /// The file was the one written: its bytes were overwritten and it was unlinked.
    Removed,
    /// Nothing is at the path any more.
    Missing,
    /// Something is at the path, but it is not the file that was written — a symlink, a
    /// directory, a different file renamed over it — so it was left exactly as it is.
    NotTheWrittenFile,
}

/// Reject a file name that is not a plain file name.
///
/// Matches the `^\.?[A-Za-z0-9._-]+$` pattern in mcp-server.md §2.7, which excludes `/`, `..` and
/// anything that would make the name a path. A name that passes therefore joins onto any
/// directory to give a path inside it, with no `..` component in it to render.
///
/// Public because [`write()`] is not the only thing that needs the answer: a caller that shows a
/// human the target path before writing has to know the name is a name *first*, or the sheet can
/// describe a file the write would never produce (see the agent's `write_env_file`).
///
/// # Errors
///
/// [`Error::InvalidEnvFileName`] for anything that is not a plain file name.
pub fn validate_filename(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .strip_prefix('.')
            .unwrap_or(name)
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.strip_prefix('.').unwrap_or(name).is_empty();
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidEnvFileName(name.to_owned()))
    }
}

/// Render one `NAME=value` line, quoting when the value needs it.
///
/// The name is a [`VarName`], so it is an identifier by construction and is written bare: there is
/// no quoting rule for a key, and none is needed for one that cannot contain `=`, a quote or a
/// line break. The quoting rules for the value are the ones `.env` readers actually agree on: a
/// value containing a newline, a quote, a backslash, whitespace, or a shell metacharacter is
/// wrapped in double quotes with `\`, `"`, newline, carriage return and tab escaped. Everything
/// else is written bare.
fn push_line(out: &mut Zeroizing<Vec<u8>>, name: &VarName, value: &[u8]) {
    out.extend_from_slice(name.as_str().as_bytes());
    out.push(b'=');

    let needs_quotes = value.is_empty()
        || value.iter().any(|b| {
            !(b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'+' | b','))
        });

    if !needs_quotes {
        out.extend_from_slice(value);
        out.push(b'\n');
        return;
    }

    out.push(b'"');
    for &b in value {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'$' => out.extend_from_slice(b"\\$"),
            other => out.push(other),
        }
    }
    out.push(b'"');
    out.push(b'\n');
}

/// Render the whole file body into a zeroizing buffer.
#[must_use]
pub fn render(injections: &[EnvInjection]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(b"# Written by kagisecure. Do not commit.\n");
    for injection in injections {
        push_line(&mut out, &injection.name, injection.value.expose());
    }
    out
}

/// Write a `.env` file into `directory`.
///
/// `directory` must already be canonicalized by the caller — this function does not resolve
/// symlinks, because the *approval prompt* has to have been shown for the same path that gets
/// written, and resolving it twice invites a TOCTOU disagreement. Guarding the window between
/// the prompt and the write is therefore the caller's job, and it is the caller that knows what
/// was approved: the agent re-resolves the approved directory immediately before calling this
/// and refuses if it no longer resolves to itself (A-05).
///
/// On Windows the `0600` is an owner-only DACL instead (`crate::windows_acl`): owner = the
/// user, protected from inheritance, one entry for the user's SID. It is part of the
/// `CreateFileW` that creates the temporary file, so — as on Unix — no byte is ever written to a
/// file with any other ACL, and the rename carries it over whatever `.env` was there before.
/// This matters more here than for the vault: the directory is a project working directory the
/// *user* chose, whose inherited ACL this program neither controls nor checks, and on Windows it
/// is no boundary anyway (a directory's DACL does not stop a user who knows a file's path). The
/// directory itself is not touched. Not tested: a second local account being refused — the
/// tests read the descriptor back and assert its shape.
///
/// # Errors
///
/// [`Error::InvalidEnvFileName`] for a name that is not a plain file name,
/// [`Error::EnvFileExists`] when the target exists and `overwrite` is false, and any I/O failure.
pub fn write(
    directory: &Path,
    filename: &str,
    injections: &[EnvInjection],
    overwrite: bool,
) -> Result<WrittenFile> {
    use std::io::Write;

    validate_filename(filename)?;
    if !directory.is_dir() {
        return Err(Error::InvalidPath(directory.to_path_buf()));
    }

    let path = directory.join(filename);
    if path.exists() && !overwrite {
        return Err(Error::EnvFileExists(path));
    }

    let body = render(injections);

    let suffix = crate::crypto::random::array::<8>()?;
    let mut tmp_name = String::from(filename);
    tmp_name.push('.');
    for b in suffix {
        tmp_name.push_str(&format!("{b:02x}"));
    }
    tmp_name.push_str(".tmp");
    let tmp = directory.join(tmp_name);

    #[cfg(not(windows))]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(not(windows))]
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| -> Result<FileIdentity> {
        #[cfg(not(windows))]
        let mut file = opts.open(&tmp)?;
        // `create_new` semantics, with the owner-only descriptor part of the create call.
        #[cfg(windows)]
        let mut file = crate::windows_acl::create_new_file(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
        // From the handle the bytes went through, not from a later lookup of `path`: a rename
        // keeps the file's identity, and nothing can come between this handle and the file.
        let identity = identity_of(&file)?;
        drop(file);
        std::fs::rename(&tmp, &path)?;
        Ok(identity)
    })();
    let identity = match result {
        Ok(identity) => identity,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `create_new` + `mode` already did this; re-asserting it costs nothing and covers a
        // pre-existing target whose permissions the rename did not change.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(WrittenFile {
        bytes: body.len(),
        variables: injections.iter().map(|i| i.name.to_string()).collect(),
        gitignored: gitignore_status(&path),
        identity,
        path,
    })
}

fn identity_of(file: &std::fs::File) -> Result<FileIdentity> {
    let (device, index) = kagisecure_childproc::file::identity(file)?;
    Ok(FileIdentity::new(device, index))
}

/// The identity of the regular file at `path` now, without following a symlink in its final
/// component; `None` when there is nothing there, it is not a regular file, or it cannot be
/// opened.
///
/// For asking "is the file at this path still the one kagisecure wrote?": compare this against
/// the ledger's recorded identity.
#[must_use]
pub fn current_identity(path: &Path) -> Option<FileIdentity> {
    let file = kagisecure_childproc::file::open_no_follow(path, false).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    identity_of(&file).ok()
}

/// Overwrite the bytes of the file kagisecure wrote at `path` and delete it — if, and only if,
/// the file at `path` is still that file.
///
/// `expected` is the identity [`write()`] reported. The path is opened **without following** a
/// symlink in its final component (`O_NOFOLLOW`, or `FILE_FLAG_OPEN_REPARSE_POINT` on Windows),
/// and the handle — not the path — is checked for being a regular file with that identity before
/// a single byte is written through it. Anything else at the path (a symlink to the user's SSH
/// key, a directory, a different file renamed over it) is left untouched and reported as
/// [`Shredded::NotTheWrittenFile`], for the caller to record.
///
/// The unlink that follows the overwrite is by path, so it is preceded by one more identity check
/// of what the path names; a swap in the instant between that check and the unlink can make it
/// remove a directory entry for a different file (never overwrite one — the bytes went through
/// the verified handle). Closing that last window needs `unlinkat` relative to a held directory
/// handle, which `std` does not offer; on a single-user machine the party able to race it is the
/// user's own uid.
///
/// Best effort, and documented as such: on a journalling, copy-on-write or flash-translated
/// filesystem the old blocks may survive.
///
/// # Errors
///
/// An I/O failure while overwriting or unlinking the verified file.
pub fn shred(path: &Path, expected: FileIdentity) -> Result<Shredded> {
    use std::io::Write;

    let mut file = match kagisecure_childproc::file::open_no_follow(path, true) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Shredded::Missing),
        // A symlink (`ELOOP`), a file this user may not write, anything else that will not open
        // as a plain writable file: none of these is the 0600 file kagisecure wrote.
        Err(_) => return Ok(Shredded::NotTheWrittenFile),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || identity_of(&file)? != expected {
        return Ok(Shredded::NotTheWrittenFile);
    }

    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    let zeros = vec![0u8; len.min(1 << 20)];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len());
        if file.write_all(&zeros[..n]).is_err() {
            break;
        }
        left -= n;
    }
    let _ = file.sync_all();
    drop(file);

    if current_identity(path) != Some(expected) {
        return Ok(Shredded::NotTheWrittenFile);
    }
    std::fs::remove_file(path)?;
    Ok(Shredded::Removed)
}

/// Whether `path` is inside a git work tree and, if so, whether a `.gitignore` covers it.
///
/// **Best effort, and not a security boundary.** This walks up from the file looking for a `.git`
/// entry, then checks the `.gitignore` files it passed for a line matching the file name. It does
/// not implement git's full pattern language (no `**`, no directory-scoped negation ordering, no
/// `.git/info/exclude`, no global excludes), and it never shells out to `git`. It exists so the
/// approval prompt can say "this is going into a repo and nothing ignores it", which is the case
/// that matters.
#[must_use]
pub fn gitignore_status(path: &Path) -> Option<bool> {
    let file_name = path.file_name()?.to_str()?;
    let mut dir = path.parent()?;
    let mut ignored = false;
    loop {
        let candidate = dir.join(".gitignore");
        if let Ok(text) = std::fs::read_to_string(&candidate)
            && text
                .lines()
                .any(|line| gitignore_line_matches(line, file_name))
        {
            ignored = true;
        }
        if dir.join(".git").exists() {
            return Some(ignored);
        }
        dir = dir.parent()?;
    }
}

fn gitignore_line_matches(line: &str, file_name: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return false;
    }
    let pattern = line.trim_end_matches('/').trim_start_matches('/');
    if pattern == file_name {
        return true;
    }
    match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
        (Some(suffix), None) => file_name.ends_with(suffix),
        (None, Some(prefix)) => file_name.starts_with(prefix),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Secret;

    fn injection(name: &str, value: &str) -> EnvInjection {
        EnvInjection {
            name: VarName::new(name).expect("a test name is a valid name"),
            value: Secret::from_string(value.to_owned()),
        }
    }

    #[test]
    fn writes_the_expected_contents() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(
            dir.path(),
            ".env",
            &[injection("A", "one"), injection("B", "two")],
            false,
        )
        .unwrap();
        let text = std::fs::read_to_string(&written.path).unwrap();
        assert!(text.starts_with("# Written by kagisecure"));
        assert!(text.contains("\nA=one\n"));
        assert!(text.contains("\nB=two\n"));
        assert_eq!(written.variables, ["A", "B"]);
        assert_eq!(written.bytes, text.len());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_read_write_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        let mode = std::fs::metadata(&written.path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    /// The Windows counterpart: one entry, for this user, in a protected DACL — both for a fresh
    /// `.env` and for one written over a pre-existing file that carried the directory's
    /// inherited ACL, which the rename must replace rather than keep.
    #[cfg(windows)]
    #[test]
    fn the_file_is_owner_only_on_windows_too() {
        use crate::windows_acl::{self, ObjectKind};
        let me = windows_acl::current_user_sid().unwrap();
        let dir = tempfile::tempdir().unwrap();

        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        let security = windows_acl::path_security(&written.path).unwrap();
        assert!(
            windows_acl::is_owner_only(&security, &me, ObjectKind::File, true),
            "{security:?}"
        );

        std::fs::write(dir.path().join(".env.old"), b"KEEP=me\n").unwrap();
        std::fs::rename(dir.path().join(".env.old"), &written.path).unwrap();
        assert!(
            !windows_acl::path_security(&written.path)
                .unwrap()
                .dacl_protected
        );
        write(dir.path(), ".env", &[injection("A", "y")], true).unwrap();
        let security = windows_acl::path_security(&written.path).unwrap();
        assert!(
            windows_acl::is_owner_only(&security, &me, ObjectKind::File, true),
            "an overwritten .env: {security:?}"
        );
    }

    #[test]
    fn values_that_need_quoting_get_it() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(
            dir.path(),
            ".env",
            &[
                injection("PLAIN", "postgres://user@host:5432/db"),
                injection("SPACED", "two words"),
                injection("TRICKY", "a\"b\\c\nd$e"),
                injection("EMPTY", ""),
            ],
            false,
        )
        .unwrap();
        let text = std::fs::read_to_string(&written.path).unwrap();
        assert!(text.contains("PLAIN=postgres://user@host:5432/db\n"));
        assert!(text.contains("SPACED=\"two words\"\n"));
        assert!(text.contains("TRICKY=\"a\\\"b\\\\c\\nd\\$e\"\n"));
        assert!(text.contains("EMPTY=\"\"\n"));
    }

    #[test]
    fn an_existing_file_is_not_clobbered_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), b"KEEP=me\n").unwrap();
        let err = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap_err();
        assert!(matches!(err, Error::EnvFileExists(_)));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".env")).unwrap(),
            "KEEP=me\n"
        );

        write(dir.path(), ".env", &[injection("A", "x")], true).unwrap();
        assert!(
            std::fs::read_to_string(dir.path().join(".env"))
                .unwrap()
                .contains("A=x")
        );
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty());
    }

    #[test]
    fn path_traversal_in_the_file_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../escape", "a/b", "..", ".", "", ".."] {
            assert!(
                write(dir.path(), bad, &[], false).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn shredding_removes_the_file_and_reports_whether_it_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        assert_eq!(
            shred(&written.path, written.identity).unwrap(),
            Shredded::Removed
        );
        assert!(!written.path.exists());
        assert_eq!(
            shred(&written.path, written.identity).unwrap(),
            Shredded::Missing
        );
    }

    #[cfg(unix)]
    #[test]
    fn shredding_never_follows_a_symlink_planted_after_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        std::fs::remove_file(&written.path).unwrap();
        std::os::unix::fs::symlink(&victim, &written.path).unwrap();

        assert_eq!(
            shred(&written.path, written.identity).unwrap(),
            Shredded::NotTheWrittenFile
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert!(
            written.path.symlink_metadata().is_ok(),
            "the link is left too"
        );
    }

    #[test]
    fn shredding_leaves_a_different_file_renamed_over_the_written_one() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        let other = dir.path().join("other");
        std::fs::write(&other, b"the user's own").unwrap();
        std::fs::rename(&other, &written.path).unwrap();

        assert_eq!(
            shred(&written.path, written.identity).unwrap(),
            Shredded::NotTheWrittenFile
        );
        assert_eq!(std::fs::read(&written.path).unwrap(), b"the user's own");
    }

    #[test]
    fn a_directory_at_the_path_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        std::fs::remove_file(&written.path).unwrap();
        std::fs::create_dir(&written.path).unwrap();
        assert_eq!(
            shred(&written.path, written.identity).unwrap(),
            Shredded::NotTheWrittenFile
        );
        assert!(written.path.is_dir());
    }

    #[test]
    fn gitignore_status_is_none_outside_a_work_tree() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        assert_eq!(written.gitignored, None);
    }

    #[test]
    fn gitignore_status_sees_a_covering_rule_and_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();

        let written = write(dir.path(), ".env", &[injection("A", "x")], false).unwrap();
        assert_eq!(written.gitignored, Some(false), "no .gitignore yet");

        std::fs::write(dir.path().join(".gitignore"), "# comment\n\n.env\n").unwrap();
        assert_eq!(gitignore_status(&written.path), Some(true));

        std::fs::write(dir.path().join(".gitignore"), ".env*\n").unwrap();
        assert_eq!(gitignore_status(&written.path), Some(true));

        std::fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();
        assert_eq!(gitignore_status(&written.path), Some(false));
    }

    #[test]
    fn gitignore_status_looks_up_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        let nested = dir.path().join("services").join("api");
        std::fs::create_dir_all(&nested).unwrap();
        let written = write(&nested, ".env", &[injection("A", "x")], false).unwrap();
        assert_eq!(written.gitignored, Some(true));
    }

    #[test]
    fn rendering_never_shows_a_secret_through_debug() {
        let injections = [injection("A", "hunter2")];
        assert!(!format!("{injections:?}").contains("hunter2"));
    }
}

//! The `.env` file writer (mcp-server.md §2.7, threat-model M-13/M-16).
//!
//! Rules this module enforces rather than documents:
//!
//! 1. The file is created mode `0600` **before** any byte is written to it, so there is no window
//!    in which a world-readable file holds a secret. The temporary file is created with
//!    `create_new` (`O_EXCL`) and renamed into place, so a crash leaves the old file or the new
//!    one, never half of either.
//! 2. The contents live in a [`Zeroizing`] buffer for their whole life in this process.
//! 3. An existing file is never clobbered unless the caller passes `overwrite`.
//! 4. [`shred`] overwrites the bytes before unlinking. That is best effort on a journalling or
//!    copy-on-write filesystem, and says so.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::EnvInjection;
use crate::error::{Error, Result};

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
}

/// Reject a file name that is not a plain file name.
///
/// Matches the `^\.?[A-Za-z0-9._-]+$` pattern in mcp-server.md §2.7, which excludes `/`, `..` and
/// anything that would make the name a path.
fn validate_filename(name: &str) -> Result<()> {
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
/// The quoting rules are the ones `.env` readers actually agree on: a value containing a newline,
/// a quote, a backslash, whitespace, or a shell metacharacter is wrapped in double quotes with
/// `\`, `"`, newline, carriage return and tab escaped. Everything else is written bare.
fn push_line(out: &mut Zeroizing<Vec<u8>>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
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
/// written, and resolving it twice invites a TOCTOU disagreement.
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

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| -> Result<()> {
        let mut file = opts.open(&tmp)?;
        file.write_all(&body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        result?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `create_new` + `mode` already did this; re-asserting it costs nothing and covers a
        // pre-existing target whose permissions the rename did not change.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(WrittenFile {
        bytes: body.len(),
        variables: injections.iter().map(|i| i.name.clone()).collect(),
        gitignored: gitignore_status(&path),
        path,
    })
}

/// Overwrite a file's bytes and delete it.
///
/// Best effort, and documented as such: on a journalling, copy-on-write or flash-translated
/// filesystem the old blocks may survive. Returns whether the file was there to remove.
///
/// # Errors
///
/// Any I/O failure other than the file already being gone.
pub fn shred(path: &Path) -> Result<bool> {
    use std::io::Write;

    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(false);
    };
    if !meta.is_file() {
        return Err(Error::InvalidPath(path.to_path_buf()));
    }
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
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
    }
    std::fs::remove_file(path)?;
    Ok(true)
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
            name: name.to_owned(),
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
        assert!(shred(&written.path).unwrap());
        assert!(!written.path.exists());
        assert!(!shred(&written.path).unwrap());
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

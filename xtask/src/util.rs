//! The small shared things: where the repository is, and how to run a command and complain well.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use camino::Utf8PathBuf;

/// The `cargo` to invoke. Honours `CARGO`, so a task that shells out uses the same toolchain
/// that is running it.
pub fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

/// `RUSTFLAGS` for a build whose binaries leave this machine: whatever the caller already set, plus
/// `--remap-path-prefix` so that panic locations and debug info name `~/.cargo/...` and
/// `./crates/...` rather than the absolute paths of whoever happened to build the release.
pub fn release_rustflags(root: &Path) -> String {
    let mut flags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let mut remap = |from: &Path, to: &str| {
        if !flags.is_empty() {
            flags.push(' ');
        }
        flags.push_str(&format!("--remap-path-prefix={}={to}", from.display()));
    };
    // Most specific first: rustc applies the last matching prefix, so the checkout, which may live
    // under the home directory, must come after it.
    if let Some(home) = std::env::var_os("HOME") {
        remap(Path::new(&home), "~");
    }
    remap(root, ".");
    flags
}

/// Convert to a UTF-8 path, or say which path was not one.
pub fn utf8(path: &Path) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path.to_path_buf())
        .map_err(|p| anyhow::anyhow!("{} is not valid UTF-8", p.display()))
}

/// The repository root.
pub fn repo_root() -> Result<PathBuf> {
    // `CARGO_MANIFEST_DIR` is `<root>/xtask`, which beats shelling out to git and works in a
    // checkout that is not a git repository at all (a release tarball, say).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("xtask has no parent directory")
}

/// Run a command, inheriting stdio, and fail with the whole command line if it does not succeed.
pub fn run(command: &mut Command) -> Result<()> {
    let rendered = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("could not start {rendered}"))?;
    if !status.success() {
        bail!("{rendered} exited with {status}");
    }
    Ok(())
}

/// Run a command and return its stdout, trimmed.
///
/// Deliberately *not* a shell pipeline. `codesign -dvv "$APP" | grep -q Authority=…` is the
/// idiom this replaces, and under `set -o pipefail` it is a race: `grep -q` exits at the first
/// match and closes the pipe, `codesign` takes SIGPIPE, and the pipeline reports 141 — so a
/// correctly signed build silently skips notarization about half the time. Capturing first and
/// searching the string afterwards has no such failure mode.
pub fn capture(command: &mut Command) -> Result<String> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("could not start {rendered}"))?;
    if !output.status.success() {
        bail!(
            "{rendered} exited with {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Run a command and return stdout and stderr together, whether or not it succeeded.
///
/// `codesign`, `spctl` and `stapler` all write their verdict to stderr and some of them exit
/// non-zero while still saying something worth reading, so the caller judges the text.
pub fn capture_all(command: &mut Command) -> Result<(bool, String)> {
    let rendered = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("could not start {rendered}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text.trim().to_owned()))
}

/// `true` if `haystack` contains `needle`. A named function so call sites read as assertions.
pub fn says(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

//! Shared support for integration tests that need *another* package's binary.
//!
//! `env!("CARGO_BIN_EXE_<name>")` is the right tool when a test wants a binary its own package
//! produces — `kagisecure-cli/tests/mcp.rs` uses it for `kagisecure`, correctly, because cargo
//! only sets that variable for binaries of the package currently being tested. It is not set for a
//! binary that lives in a different package, which is the situation every caller of this crate is
//! in: an agent test that wants `kagisecure-nmhost`, or an MCP test that wants `kagisecure-mcp`.
//!
//! For that case, [`binary`] resolves the path cargo actually built (or will build) the binary at,
//! honoring however the target directory happens to be configured — the `CARGO_TARGET_DIR`
//! environment variable, the `build.target-dir` key in `.cargo/config.toml`, or neither of those
//! (the default `<workspace>/target`) — without this crate having to know which one is in play or
//! re-implement cargo's precedence between them.
//!
//! # Why derive it from `current_exe()`
//!
//! The one thing guaranteed to already reflect whichever of those cargo used is the path of the
//! test binary that is currently running: cargo places it at
//! `<target-dir>/<profile>/deps/<name>-<hash>` (or, for some layouts, directly under
//! `<profile>/`). Popping the file name, and the trailing `deps` component when it is there, lands
//! on `<target-dir>/<profile>` — the directory every sibling binary cargo built for this same
//! profile and target also lives in. This is the same technique `assert_cmd` uses internally for
//! `cargo_bin`'s legacy (non-`CARGO_BIN_EXE_`) fallback, so it is already proven for exactly this
//! job rather than novel.
//!
//! Reading `CARGO_TARGET_DIR` directly and joining `"debug"` or `"release"` onto it would work for
//! the environment-variable case but silently do the wrong thing for `build.target-dir`, and would
//! need its own logic for a `--target <triple>` build's extra path component. Deriving from
//! `current_exe()` gets all three for free, because cargo already resolved them before this
//! process existed.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

/// The profile directory (e.g. `<target-dir>/debug`, or `<target-dir>/<triple>/release`) that
/// produced the test binary currently running.
pub fn profile_dir() -> PathBuf {
    let mut path = std::env::current_exe().expect("the running test binary has its own path");
    path.pop(); // the test binary's own file name
    if path.ends_with("deps") {
        path.pop();
    }
    path
}

/// Resolve `file_name`'s path in the current profile directory, having run
/// `cargo build -p <package>` for it once in this test process.
///
/// Built whether or not a binary is already there. `cargo test --workspace` has already built
/// every binary any test needs, but `cargo test -p <some-single-crate>` does not rebuild a
/// *different* package's binary, so "use it if it exists" runs the tests against whatever an
/// earlier build left behind — twice during the Windows port that was a stale `kagisecure-nmhost`,
/// and a fixed defect looked unfixed. Cargo makes an up-to-date build a no-op, so this costs
/// little when nothing changed; it runs once per package per process.
///
/// `file_name` is the exact file name cargo gives the binary on this platform, suffix included
/// (`"kagisecure-mcp.exe"` on Windows, `"kagisecure-mcp"` elsewhere) — callers already have a
/// constant for this (e.g. `kagisecure_agent::bundle::SIDECAR`) or define one locally the same way,
/// since this crate must not gain a dependency on the crate that owns that name.
///
/// # Panics
///
/// Panics if `cargo` cannot be run, if it exits unsuccessfully, or if the binary is still missing
/// afterward.
pub fn binary(package: &str, file_name: &str) -> PathBuf {
    static BUILT: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

    let candidate = profile_dir().join(file_name);
    let mut built = BUILT.lock().unwrap_or_else(|e| e.into_inner());
    if built.contains(package) {
        return candidate;
    }

    // This build must land in the exact directory `profile_dir()` reads from. Rather than
    // re-deriving a `--target-dir` flag for it, this passes none at all: the child `cargo`
    // inherits this process's environment, so if `CARGO_TARGET_DIR` is what put the current test
    // binary where it is, the nested build sees the same variable and agrees. If a
    // `.cargo/config.toml` `build.target-dir` key did it instead, running from the workspace root
    // (below) reads the same file. The one case this does not cover — a *relative*
    // `CARGO_TARGET_DIR` combined with running the outer `cargo test` from somewhere other than
    // the workspace root — is already ambiguous in cargo itself (relative target dirs are resolved
    // against the invoking working directory), so it is out of scope here too.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(cargo);
    build
        .current_dir(workspace_root())
        .args(["build", "-p", package]);
    // Into the profile directory this test binary came from, not always `debug`.
    if profile_dir()
        .file_name()
        .is_some_and(|name| name == "release")
    {
        build.arg("--release");
    }
    let status = build
        .status()
        .unwrap_or_else(|e| panic!("could not run cargo to build {package}: {e}"));
    assert!(status.success(), "building {package} failed");
    assert!(
        candidate.is_file(),
        "{file_name} is still missing at {} after building {package}",
        candidate.display()
    );
    built.insert(package.to_owned());
    candidate
}

/// The workspace root, derived from this crate's own fixed location.
///
/// This crate lives at `<workspace>/crates/kagisecure-test-support`, so its own
/// `CARGO_MANIFEST_DIR` (baked in at compile time) is two components under the root regardless of
/// where a caller's own manifest happens to sit.
fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(dir.pop(), "kagisecure-test-support sits inside crates/");
    assert!(dir.pop(), "crates/ sits inside the workspace root");
    dir
}

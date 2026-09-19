//! Where kagisecure's helper binaries are, on a machine that has them.
//!
//! There are three of them — the MCP sidecar, the native messaging host and the CLI — and until
//! M7 each caller answered "where is it?" for itself. Two searches that disagreed would be a
//! support problem nobody could reproduce ("the setup screen shows one path, `kagisecure mcp
//! path` prints another"), so the search lives here once and every caller reads it.
//!
//! [ADR-0026](../../../docs/decisions/0026-helper-binaries-inside-the-app-bundle.md) is the
//! decision this module implements: a released `Kagisecure.app` carries all three helpers in its
//! own `Contents/Helpers`, so the answer for a normal install is "inside the app the user already
//! dragged to /Applications", and nothing has to be on `PATH` at all.
//!
//! **`Contents/Helpers`, not `Contents/MacOS`.** The obvious directory is the wrong one, for a
//! reason that is invisible until it bites: the app's own executable is `Contents/MacOS/
//! Kagisecure` and the CLI is called `kagisecure`, and the default macOS filesystem is
//! case-*insensitive*. Copying the CLI in beside the app silently overwrites the app. ADR-0026
//! has the measurement; `Contents/Helpers` is a directory Apple's bundle layout allows, it is
//! signed and notarized exactly the same way, and it holds all three helpers so there is one
//! rule rather than an exception for one of them.

use std::path::{Path, PathBuf};

/// The MCP sidecar's file name.
#[cfg(windows)]
pub const SIDECAR: &str = "kagisecure-mcp.exe";
/// The MCP sidecar's file name.
#[cfg(not(windows))]
pub const SIDECAR: &str = "kagisecure-mcp";

/// The native messaging host's file name.
#[cfg(windows)]
pub const NMHOST: &str = "kagisecure-nmhost.exe";
/// The native messaging host's file name.
#[cfg(not(windows))]
pub const NMHOST: &str = "kagisecure-nmhost";

/// The command-line tool's file name.
#[cfg(windows)]
pub const CLI: &str = "kagisecure.exe";
/// The command-line tool's file name.
#[cfg(not(windows))]
pub const CLI: &str = "kagisecure";

/// Where a user who followed the DMG's instructions put the app.
///
/// Capitalised, because the app's *display* name is a proper noun and the bundle takes it
/// exactly; the CLI, the crates and the bundle identifier stay lowercase. Documents that spelled
/// this `/Applications/kagisecure.app` were wrong and are fixed.
pub const INSTALLED_APP: &str = "/Applications/Kagisecure.app";

/// The directory inside the bundle that holds the helpers, relative to `Contents`.
pub const HELPERS_DIR: &str = "Helpers";

/// The `Contents/Helpers` of an installed `Kagisecure.app`, whether or not one is there.
#[must_use]
pub fn installed_helper_dir() -> PathBuf {
    PathBuf::from(INSTALLED_APP)
        .join("Contents")
        .join(HELPERS_DIR)
}

/// The path a helper *would* have in a normal install.
///
/// Used for the placeholder the setup screens show when nothing could be found: a screen that
/// names the path an install would have can explain what is missing, where a blank one cannot.
#[must_use]
pub fn installed_helper(name: &str) -> PathBuf {
    installed_helper_dir().join(name)
}

/// Find one helper binary, in the order that makes the answer true for the person asking.
///
/// 1. `hint` — the app passes its own `Contents/Helpers`. A shipped copy beside the running app
///    beats everything: it is the one that is signed with the same identity, notarized in the
///    same submission and guaranteed to be the same version as the app asking.
/// 2. `env` — `KAGISECURE_MCP` or `KAGISECURE_NMHOST`, for a contributor pointing at a `target/`
///    build. Second rather than first because the hint is only ever set by a *bundled* app, and a
///    development build has nothing in its hint directory to shadow.
/// 3. Beside the running executable, which covers `cargo build`, a Homebrew `bin`, and the CLI
///    when it is the copy inside the app bundle.
/// 4. Inside an installed `Kagisecure.app`, which covers a CLI or a shell that is not in the
///    bundle and has nothing on `PATH`.
/// 5. `PATH`, which covers a Homebrew install of the CLI alone.
#[must_use]
pub fn find(name: &str, hint: Option<&Path>, env: &str) -> Option<PathBuf> {
    if let Some(dir) = hint {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Some(explicit) = std::env::var_os(env) {
        let candidate = PathBuf::from(explicit);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if cfg!(target_os = "macos") {
        let candidate = installed_helper(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installed_paths_are_inside_the_capitalised_app_bundle() {
        assert_eq!(
            installed_helper(SIDECAR),
            PathBuf::from("/Applications/Kagisecure.app/Contents/Helpers").join(SIDECAR)
        );
        assert!(
            !installed_helper(NMHOST)
                .to_string_lossy()
                .contains("kagisecure.app"),
            "the bundle's display name is capitalised"
        );
    }

    #[test]
    fn a_hint_directory_wins_over_everything_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join(SIDECAR);
        std::fs::write(&fake, b"#!/bin/sh\n").expect("write");
        assert_eq!(
            find(SIDECAR, Some(dir.path()), "KAGISECURE_NOT_SET_ANYWHERE"),
            Some(fake)
        );
    }

    #[test]
    fn an_empty_hint_falls_through_to_the_rest_of_the_search() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Whatever this machine has installed, the empty hint directory must not be the answer.
        let found = find(SIDECAR, Some(dir.path()), "KAGISECURE_NOT_SET_ANYWHERE");
        assert!(found.is_none_or(|p| p.parent() != Some(dir.path())));
    }

    #[test]
    fn all_three_helper_names_are_distinct() {
        assert_ne!(SIDECAR, NMHOST);
        assert_ne!(SIDECAR, CLI);
        assert_ne!(NMHOST, CLI);
    }

    /// The bug ADR-0026 is about: `Contents/MacOS/Kagisecure` and a CLI called `kagisecure` are
    /// the same path on a case-insensitive filesystem, which is the macOS default. Copying the
    /// CLI in beside the app overwrites the app, with no error anywhere. Nothing may put a helper
    /// in `Contents/MacOS` again.
    #[test]
    fn the_helper_directory_is_not_the_one_holding_the_apps_own_executable() {
        assert_ne!(HELPERS_DIR, "MacOS");
        assert!(
            !installed_helper_dir()
                .to_string_lossy()
                .contains("Contents/MacOS")
        );
        assert!(
            CLI.eq_ignore_ascii_case("Kagisecure"),
            "if this ever stops being true the collision is gone and the note above is stale"
        );
    }
}

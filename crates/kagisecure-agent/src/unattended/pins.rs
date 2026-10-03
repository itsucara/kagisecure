//! Whether a pinned executable is still what the person approved (ADR-0042 §4, §5).
//!
//! A SHA-256 pin is checked by hashing the file. A code-signing pin is checked with the system's
//! own `/usr/bin/codesign`: the signature must verify (`--verify --strict`), and its team and
//! signing identifiers must be the pinned ones. This crate has no Security framework binding, and
//! the tool is what a person would run to check the same thing (implementation decision 12). On
//! any platform without it, a code-signing pin never holds.

use std::path::Path;

use kagisecure_core::vault::machine::{ExecutablePin, PinnedExecutable, file_sha256};

/// Whether `exe` is still the executable its pin names.
#[must_use]
pub fn executable_holds(exe: &PinnedExecutable) -> bool {
    let path = Path::new(&exe.path);
    match &exe.pin {
        ExecutablePin::Sha256(hash) => file_sha256(path).is_ok_and(|h| h.as_slice() == hash),
        ExecutablePin::CodeSigning {
            team_id,
            signing_id,
        } => code_signing_holds(path, team_id, signing_id),
    }
}

/// Pin the executable at `path` as it is now (owner's answer 7): by code-signing identity when it
/// is validly signed with a team identifier, and by the SHA-256 of its bytes otherwise.
///
/// # Errors
///
/// Whatever reading the file returns, when it has to be hashed.
pub fn pin_executable(path: &str) -> std::io::Result<PinnedExecutable> {
    let pin = match signing_identity(Path::new(path)) {
        Some((team_id, signing_id)) => ExecutablePin::CodeSigning {
            team_id,
            signing_id,
        },
        None => ExecutablePin::Sha256(file_sha256(Path::new(path))?.to_vec()),
    };
    Ok(PinnedExecutable {
        path: path.to_owned(),
        pin,
    })
}

/// The team and signing identifiers of a validly signed executable that has a team.
#[cfg(target_os = "macos")]
fn signing_identity(path: &Path) -> Option<(String, String)> {
    use std::process::{Command, Stdio};

    const CODESIGN: &str = "/usr/bin/codesign";
    let verified = Command::new(CODESIGN)
        .args(["--verify", "--strict"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !verified {
        return None;
    }
    let out = Command::new(CODESIGN)
        .args(["-d", "--verbose=2"])
        .arg(path)
        .stdout(Stdio::null())
        .output()
        .ok()?;
    identifiers(&String::from_utf8_lossy(&out.stderr))
}

#[cfg(not(target_os = "macos"))]
fn signing_identity(_path: &Path) -> Option<(String, String)> {
    None
}

/// `(TeamIdentifier, Identifier)` from `codesign -dv` output, when both are present and the team
/// is set.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn identifiers(display: &str) -> Option<(String, String)> {
    let value = |key: &str| {
        display
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(|v| v.trim().to_owned())
    };
    let team = value("TeamIdentifier=").filter(|t| !t.is_empty() && t != "not set")?;
    let signing = value("Identifier=").filter(|s| !s.is_empty())?;
    Some((team, signing))
}

#[cfg(target_os = "macos")]
fn code_signing_holds(path: &Path, team_id: &str, signing_id: &str) -> bool {
    use std::process::{Command, Stdio};

    const CODESIGN: &str = "/usr/bin/codesign";
    let verified = Command::new(CODESIGN)
        .args(["--verify", "--strict"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !verified {
        return false;
    }
    // `-dv` writes what it displays to stderr.
    let Ok(out) = Command::new(CODESIGN)
        .args(["-d", "--verbose=2"])
        .arg(path)
        .stdout(Stdio::null())
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stderr);
    identifiers_match(&text, team_id, signing_id)
}

#[cfg(not(target_os = "macos"))]
fn code_signing_holds(_path: &Path, _team_id: &str, _signing_id: &str) -> bool {
    false
}

/// Whether `codesign -dv` output names exactly this signing identifier and team.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn identifiers_match(display: &str, team_id: &str, signing_id: &str) -> bool {
    let value = |key: &str| {
        display
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    value("Identifier=") == Some(signing_id) && value("TeamIdentifier=") == Some(team_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_matched_exactly() {
        let shown = "Executable=/Applications/Tool.app/Contents/MacOS/Tool\n\
                     Identifier=org.example.tool\n\
                     Format=app bundle with Mach-O universal\n\
                     TeamIdentifier=ABCDE12345\n";
        assert!(identifiers_match(shown, "ABCDE12345", "org.example.tool"));
        assert!(!identifiers_match(shown, "ABCDE12345", "org.example"));
        assert!(!identifiers_match(shown, "ABCDE1234", "org.example.tool"));
        assert!(!identifiers_match(
            "Identifier=org.example.tool\n",
            "",
            "org.example.tool"
        ));
    }

    #[test]
    fn identities_come_from_a_team_signature_only() {
        let signed = "Identifier=org.example.tool\nTeamIdentifier=ABCDE12345\n";
        assert_eq!(
            identifiers(signed),
            Some(("ABCDE12345".to_owned(), "org.example.tool".to_owned()))
        );
        assert_eq!(
            identifiers("Identifier=tool\nTeamIdentifier=not set\n"),
            None
        );
        assert_eq!(identifiers("Identifier=tool\n"), None);
    }

    #[test]
    fn an_unsigned_file_is_pinned_by_its_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        let path = path.to_string_lossy().into_owned();
        let pinned = pin_executable(&path).unwrap();
        assert!(matches!(pinned.pin, ExecutablePin::Sha256(_)));
        assert!(executable_holds(&pinned));
    }

    #[test]
    fn a_sha256_pin_holds_until_the_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"one").unwrap();
        let exe = PinnedExecutable {
            path: path.to_string_lossy().into_owned(),
            pin: ExecutablePin::Sha256(file_sha256(&path).unwrap().to_vec()),
        };
        assert!(executable_holds(&exe));
        std::fs::write(&path, b"two").unwrap();
        assert!(!executable_holds(&exe));
        std::fs::remove_file(&path).unwrap();
        assert!(!executable_holds(&exe));
    }
}

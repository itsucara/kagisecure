//! `kagisecure-import` — reading vaults exported from other password managers.
//!
//! # Why this is a separate crate
//!
//! Everything in here is a parser for a file someone else wrote. A 1PUX archive is a zip full of
//! JSON; a CSV export is a text file with quoting rules. Both are, in the plainest sense,
//! untrusted input from outside the process, and handling them means `zip`, `flate2`, `csv` and
//! `serde_json` — four parsers, none of which `kagisecure-core` needs for anything else.
//!
//! Putting them in core would put them in *every* consumer's dependency graph: the daemon, the
//! browser-extension forwarder, the FFI layer, and the manual review checklist in
//! `docs/threat-model.md` §8 that covers core. A separate crate keeps the blast radius where it
//! belongs, gives `cargo deny` a subtree it can point at, and gives the fuzz targets a home.
//!
//! ```text
//! kagisecure-import → kagisecure-core { features = ["secret-material"] }
//! kagisecure-cli    → kagisecure-import
//! kagisecure-ffi    → kagisecure-import
//! ```
//!
//! # `kagisecure-mcp` and `kagisecure-ipc` must never depend on this crate
//!
//! ADR-0002 does not say "the sidecar promises not to return secrets". It says the sidecar
//! **cannot**: it depends on `kagisecure-core` with `default-features = false`, so the
//! `secret-material` feature is not in its build graph and the [`kagisecure_core::Secret`] type
//! is not a name it can write down. A tool that returned a value would not compile.
//!
//! This crate enables `secret-material` explicitly, because constructing secrets from a foreign
//! export is its entire job. An edge from `kagisecure-mcp` or `kagisecure-ipc` to here — direct
//! or through some future shared helper — would switch that feature on for the sidecar and
//! quietly demolish the argument, without a single line of sidecar code changing. That is why
//! the rule is a dependency-graph rule and not a review note, and why
//! `tests/dependency_guard.rs` asserts it from inside this crate, beside the code that would
//! cause the problem.
//!
//! The privileged consumers — the CLI and the FFI layer — already enable `secret-material` for
//! their own reasons and are the two places this crate is meant to be linked from.
//!
//! # The shape of an import
//!
//! ```text
//! parse  →  ImportPlan  →  report()  →  the user decides  →  commit()  →  Vault::save()
//! ```
//!
//! Parsing finishes before anything is written, so a malformed file fails with the vault
//! untouched. The plan holds values; **the report does not, and structurally cannot** — see
//! [`ir`] and [`report`]. `--dry-run` is a run that stops after `report()`.
//!
//! # Threat-model notes that constrain this crate
//!
//! * No value ever appears in a report, an error, a `Debug` rendering or the audit log
//!   (threat-model M-14, M-21). `tests/report_canary.rs` asserts it byte by byte.
//! * No intermediate plaintext on disk: archive entries are read through [`std::io::Read`] into a
//!   `Zeroizing` buffer, never into a temporary file.
//! * Parser limits are checked before allocation, so a zip bomb is refused rather than survived.
//! * Imported items are never agent-visible, whatever the source said (threat-model M-9).
//! * The export itself is a full plaintext copy of the user's vault sitting on disk. [`shred`]
//!   offers to remove it and is explicit that doing so is best effort (threat-model W-9).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commit;
pub mod dedupe;
pub mod error;
pub mod ir;
pub mod report;
pub mod shred;

// The parsers. Declared here from the start so that WP1 and WP2 can fill them in without
// touching this file (plan §8, collision rules).
pub mod csv;
pub mod onepux;

pub use commit::{ImportOutcome, commit};
pub use dedupe::{DuplicatePolicy, ItemAction};
pub use error::{ImportError, Result};
pub use ir::{
    Decision, DropKind, DropNote, ImportPlan, ImportedField, ImportedItem, ImportedRevision,
    ImportedValue, ItemReport, SourceKind, TargetVault, Tier,
};
pub use report::{ImportReport, ItemRow, Totals};
pub use shred::{ShredOutcome, shred_file};

use std::path::Path;

/// The first four bytes of a zip local file header.
const ZIP_MAGIC: [u8; 4] = *b"PK\x03\x04";

/// Parse `path` into a plan, choosing a parser from `format` or from the file itself.
///
/// `format` is `--format` when the user named one. With `None`, a file that begins with the zip
/// magic or is named `*.1pux` goes to [`onepux`] and everything else goes to [`csv`], which does
/// its own dialect detection from the header row. Sniffing is deliberately shallow — it picks a
/// *parser*, and the parser then validates properly; it is not a content-based guess about what
/// any column means (plan §3).
///
/// # Errors
///
/// [`ImportError::SourceNotFound`] if there is no readable file there, or whatever the chosen
/// parser returns.
pub fn parse(path: &Path, format: Option<SourceKind>) -> Result<ImportPlan> {
    match format {
        Some(SourceKind::OnePux) => onepux::parse(path),
        Some(dialect) => csv::parse(path, Some(dialect)),
        None => {
            if looks_like_an_archive(path)? {
                onepux::parse(path)
            } else {
                csv::parse(path, None)
            }
        }
    }
}

/// Whether `path` is a zip archive, by its first four bytes or failing that its name.
fn looks_like_an_archive(path: &Path) -> Result<bool> {
    use std::io::Read;

    if ir::looks_like_onepux_name(path) {
        return Ok(true);
    }
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ImportError::SourceNotFound(path.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };
    let mut magic = [0u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == ZIP_MAGIC),
        // A file shorter than four bytes is not an archive. Let the CSV parser produce the
        // complaint, which will be a better one than "not a zip".
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_named_rather_than_handed_to_a_parser() {
        let dir = tempfile::tempdir().unwrap();
        let err = parse(&dir.path().join("nope.csv"), None).unwrap_err();
        assert!(matches!(err, ImportError::SourceNotFound(_)));
    }

    #[test]
    fn the_parser_is_chosen_by_magic_bytes_then_by_extension() {
        let dir = tempfile::tempdir().unwrap();

        let zip = dir.path().join("export.bin");
        std::fs::write(&zip, b"PK\x03\x04rest").unwrap();
        assert!(looks_like_an_archive(&zip).unwrap());

        let named = dir.path().join("export.1pux");
        std::fs::write(&named, b"not actually a zip").unwrap();
        assert!(looks_like_an_archive(&named).unwrap());

        let text = dir.path().join("export.csv");
        std::fs::write(&text, b"title,url,username,password\n").unwrap();
        assert!(!looks_like_an_archive(&text).unwrap());

        let tiny = dir.path().join("tiny.csv");
        std::fs::write(&tiny, b"ab").unwrap();
        assert!(!looks_like_an_archive(&tiny).unwrap());
    }

    /// Both parsers are real now (WP1's 1PUX reader, WP2's CSV family): a file that is not what
    /// it claims still fails cleanly, as a real error rather than a panic — the point this test
    /// always existed to make, updated once there was real behaviour to check it against.
    #[test]
    fn a_file_that_is_not_what_it_claims_fails_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, b"title,url,username,password\n").unwrap();

        // Not a full header for any of the four CSV dialects: nothing detects.
        assert!(matches!(
            parse(&path, None).unwrap_err(),
            ImportError::UndetectedFormat { .. }
        ));
        // Named as 1pux, but the bytes are not a zip archive.
        assert!(matches!(
            parse(&path, Some(SourceKind::OnePux)).unwrap_err(),
            ImportError::Malformed {
                source_kind: SourceKind::OnePux,
                ..
            }
        ));
        // Named as each CSV dialect in turn: the header is short of what every one of them
        // requires, so each still fails rather than silently accepting the wrong shape.
        for kind in [
            SourceKind::AppleCsv,
            SourceKind::ChromiumCsv,
            SourceKind::FirefoxCsv,
            SourceKind::OnePasswordCsv,
        ] {
            assert!(
                matches!(
                    parse(&path, Some(kind)).unwrap_err(),
                    ImportError::MissingColumn { .. }
                ),
                "{kind:?} did not report a missing column"
            );
        }
    }
}

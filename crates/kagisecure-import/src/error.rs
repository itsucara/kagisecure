//! Error type for `kagisecure-import`.
//!
//! Same rule as [`kagisecure_core::error`], and here it matters more: this crate is the one place
//! that holds a foreign vault's plaintext in memory, and a parse error is the most tempting place
//! in the world to write `"could not parse {value}"`. **No variant may carry a field value, a
//! password, a note or a row's contents.** Positions, counts, column names, entry names and byte
//! offsets are fine; what was *at* that offset is not.
//!
//! `tests/report_canary.rs` asserts this end to end by seeding a marker and checking every error
//! rendering for it.

use std::path::PathBuf;

use crate::ir::SourceKind;

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, ImportError>;

/// Everything that can go wrong reading, parsing or committing an import.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// This build cannot read this source yet.
    ///
    /// The stub parsers return this until WP1 and WP2 replace them; it stays afterwards for a
    /// format named on the command line that this build does not implement.
    #[error("that import format is not supported by this build")]
    Unsupported,

    /// The file could not be read or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The vault refused the change.
    #[error(transparent)]
    Vault(#[from] kagisecure_core::Error),

    /// The source file does not exist.
    #[error("no file at {0}")]
    SourceNotFound(PathBuf),

    /// The file's shape is wrong — a missing archive entry, JSON that is not an object, a row
    /// with the wrong arity. Says *what* is wrong structurally, never what was in it.
    #[error("{source_kind} import source is malformed: {detail}")]
    Malformed {
        /// The format being read.
        source_kind: SourceKind,
        /// A structural complaint. Metadata only.
        detail: String,
    },

    /// No dialect's header signature matched, or more than one did.
    #[error(
        "could not tell which format this file is{}; pass --format to say",
        crate::error::candidates(.candidates)
    )]
    UndetectedFormat {
        /// The formats that were considered plausible, if any.
        candidates: Vec<SourceKind>,
    },

    /// A required column is absent from a CSV header.
    #[error("this looks like a {source_kind} export but has no {column:?} column")]
    MissingColumn {
        /// The dialect that was selected.
        source_kind: SourceKind,
        /// The column that should have been there.
        column: &'static str,
    },

    /// The bytes are not the text encoding this crate reads.
    ///
    /// Carries an offset and a row number so a user can find the problem, and nothing from the
    /// row itself.
    #[error("{detail}")]
    Encoding {
        /// What is wrong with the encoding, e.g. `"the file is UTF-16; re-export it as UTF-8"`.
        detail: String,
        /// Byte offset into the file, when known.
        offset: Option<u64>,
        /// One-based row number, when known.
        row: Option<u64>,
    },

    /// A parser limit was hit. Refusing is the point: these limits are what stop a zip bomb or a
    /// hostile export from becoming an out-of-memory kill (plan §2, threat-model M-21).
    #[error("this file exceeds the {what} limit of {limit}")]
    LimitExceeded {
        /// Which limit, e.g. `"uncompressed archive size in bytes"`.
        what: &'static str,
        /// The limit that was exceeded.
        limit: u64,
    },

    /// An archive entry's name would have escaped the archive root.
    ///
    /// Nothing is extracted to disk in any case, so this is defence in depth; it is an error
    /// rather than a skip because a `../` in an export is not a mistake.
    #[error("the archive contains an entry whose name escapes the archive root")]
    UnsafeEntryName,

    /// The caller named a logical vault that does not exist and asked not to create one.
    #[error("no logical vault named {0:?}")]
    TargetVaultNotFound(String),
}

/// Renders the candidate list for [`ImportError::UndetectedFormat`].
fn candidates(candidates: &[SourceKind]) -> String {
    if candidates.is_empty() {
        return String::new();
    }
    let names: Vec<&str> = candidates.iter().map(|c| c.as_str()).collect();
    format!(" (it could be {})", names.join(" or "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_undetected_format_error_names_the_candidates_and_the_flag() {
        let e = ImportError::UndetectedFormat {
            candidates: vec![SourceKind::AppleCsv, SourceKind::ChromiumCsv],
        };
        let rendered = e.to_string();
        assert!(rendered.contains("apple-csv"), "{rendered}");
        assert!(rendered.contains("chromium-csv"), "{rendered}");
        assert!(rendered.contains("--format"), "{rendered}");
    }

    #[test]
    fn an_empty_candidate_list_still_reads_as_a_sentence() {
        let rendered = ImportError::UndetectedFormat {
            candidates: Vec::new(),
        }
        .to_string();
        assert_eq!(
            rendered,
            "could not tell which format this file is; pass --format to say"
        );
    }
}

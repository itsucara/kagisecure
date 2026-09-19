//! The CSV family: Apple, Chromium, Firefox and 1Password's own CSV export.
//!
//! One entry point, [`parse`], shared by all four dialects. The steps, in order:
//!
//! 1. Reject a UTF-16 BOM outright, strip a UTF-8 one if present.
//! 2. Read the header through the `csv` crate (which un-quotes it) and normalize each cell —
//!    lowercase, trimmed, with any leading `'\u{feff}'` removed
//!    ([`dialect::normalize_header_cell`]).
//! 3. Choose a dialect: `--format` when the caller named one, or an exact match of the normalized
//!    header against [`dialect::detect`]'s signature table otherwise. Either way, the dialect's
//!    own `Columns::resolve` still validates that every column it needs is present — an explicit
//!    `--format` skips *detection*, never *validation*.
//! 4. Stream the rows one at a time through the dialect's `map_row`, pushing an item per non-empty
//!    row onto the plan. Nothing here reads the file into memory as a whole: [`::csv::Reader`]
//!    wraps a [`std::io::BufReader`] and each `record()` call reads exactly one row.
//!
//! # Naming
//!
//! This module and the `csv` crate share a name, so the crate is always reached as `::csv`
//! (`use ::csv::...`); a bare `csv::` inside this crate would be ambiguous.

mod apple;
mod chromium;
pub mod dialect;
mod firefox;
mod onepassword;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::error::{ImportError, Result};
use crate::ir::{ImportPlan, ImportedItem, SourceKind};

/// Parse a CSV export into a plan.
///
/// `dialect` is `--format` when the user named one, and `None` when the dialect should be
/// detected from the header signature.
///
/// # Errors
///
/// [`ImportError::SourceNotFound`] if `path` does not exist; [`ImportError::Encoding`] for a
/// UTF-16 BOM or invalid UTF-8; [`ImportError::UndetectedFormat`] when detection finds zero or
/// more than one candidate; [`ImportError::MissingColumn`] when a required column is absent,
/// whichever way the dialect was chosen; [`ImportError::Malformed`] for a structurally broken row.
pub fn parse(path: &Path, dialect: Option<SourceKind>) -> Result<ImportPlan> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ImportError::SourceNotFound(path.to_path_buf())
        } else {
            ImportError::Io(e)
        }
    })?;
    let mut reader = BufReader::new(file);
    reject_utf16_or_strip_utf8_bom(&mut reader)?;

    let mut csv_reader = ::csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);

    let probe_source = dialect.unwrap_or(SourceKind::AppleCsv);
    let raw_headers = csv_reader
        .headers()
        .map_err(|e| map_csv_error(probe_source, e))?
        .clone();
    let normalized: Vec<String> = raw_headers
        .iter()
        .map(dialect::normalize_header_cell)
        .collect();

    let source = match dialect {
        Some(named) => named,
        None => dialect::detect(&normalized)?,
    };

    let mut plan = ImportPlan::new(source, path);
    match dialect {
        Some(_) => plan.note(
            "format-given",
            format!(
                "the format was named on the command line: {}",
                source.as_str()
            ),
        ),
        None => plan.note(
            "format-detected",
            format!("the header matched {}", source.as_str()),
        ),
    }

    let empty_rows = match source {
        SourceKind::AppleCsv => {
            let columns = apple::Columns::resolve(&normalized)?;
            plan.note("format-limits", apple::LOSS_NOTE);
            import_rows(&mut plan, &mut csv_reader, source, &columns, apple::map_row)?
        }
        SourceKind::ChromiumCsv => {
            let columns = chromium::Columns::resolve(&normalized)?;
            plan.note("format-limits", chromium::LOSS_NOTE);
            import_rows(
                &mut plan,
                &mut csv_reader,
                source,
                &columns,
                chromium::map_row,
            )?
        }
        SourceKind::FirefoxCsv => {
            let columns = firefox::Columns::resolve(&normalized)?;
            plan.note("format-limits", firefox::LOSS_NOTE);
            import_rows(
                &mut plan,
                &mut csv_reader,
                source,
                &columns,
                firefox::map_row,
            )?
        }
        SourceKind::OnePasswordCsv => {
            let columns = onepassword::Columns::resolve(&normalized)?;
            plan.note("format-limits", onepassword::LOSS_NOTE);
            plan.note(
                "higher-fidelity-path",
                "1PUX is the higher-fidelity path for importing from 1Password.",
            );
            import_rows(
                &mut plan,
                &mut csv_reader,
                source,
                &columns,
                onepassword::map_row,
            )?
        }
        SourceKind::OnePux => unreachable!("kagisecure_import::parse never routes 1pux here"),
    };

    if empty_rows > 0 {
        plan.note(
            "rows-skipped-empty",
            format!(
                "{empty_rows} row{} had neither a username nor a password and {} not imported",
                if empty_rows == 1 { "" } else { "s" },
                if empty_rows == 1 { "was" } else { "were" }
            ),
        );
    }

    Ok(plan)
}

/// Stream every remaining record through `map_row`, pushing the items it produces onto `plan` and
/// counting the rows it skips.
fn import_rows<C>(
    plan: &mut ImportPlan,
    reader: &mut ::csv::Reader<BufReader<File>>,
    source: SourceKind,
    columns: &C,
    map_row: fn(&::csv::StringRecord, &C) -> Option<ImportedItem>,
) -> Result<usize> {
    let mut empty_rows = 0usize;
    for result in reader.records() {
        let record = result.map_err(|e| map_csv_error(source, e))?;
        match map_row(&record, columns) {
            Some(item) => plan.push(item),
            None => empty_rows += 1,
        }
    }
    Ok(empty_rows)
}

/// Reject a UTF-16 BOM outright and strip a UTF-8 one, without consuming anything else — the
/// `csv` reader gets everything after the BOM check untouched (plan §3).
fn reject_utf16_or_strip_utf8_bom(reader: &mut BufReader<File>) -> Result<()> {
    let buf = reader.fill_buf()?;
    if buf.starts_with(&[0xFF, 0xFE]) || buf.starts_with(&[0xFE, 0xFF]) {
        return Err(ImportError::Encoding {
            detail: "this file is UTF-16; re-export or re-save it as UTF-8".to_owned(),
            offset: Some(0),
            row: None,
        });
    }
    if buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
        reader.consume(3);
    }
    Ok(())
}

/// Translate a `csv` crate error into ours: an encoding complaint keeps its byte offset and row
/// number, everything else becomes a structural complaint naming counts only — never a row's
/// contents.
fn map_csv_error(source_kind: SourceKind, err: ::csv::Error) -> ImportError {
    match err.into_kind() {
        ::csv::ErrorKind::Utf8 { pos, .. } => ImportError::Encoding {
            detail: "this row contains bytes that are not valid UTF-8; re-export the file as \
                UTF-8"
                .to_owned(),
            offset: pos.as_ref().map(::csv::Position::byte),
            row: pos.map(|p| p.line()),
        },
        ::csv::ErrorKind::UnequalLengths {
            pos,
            expected_len,
            len,
        } => ImportError::Malformed {
            source_kind,
            detail: format!(
                "a row has {len} field(s) but the header has {expected_len}{}",
                pos.map_or_else(String::new, |p| format!(" (row {})", p.line()))
            ),
        },
        ::csv::ErrorKind::Io(io_err) => ImportError::Io(io_err),
        _ => ImportError::Malformed {
            source_kind,
            detail: "the file could not be parsed as CSV".to_owned(),
        },
    }
}

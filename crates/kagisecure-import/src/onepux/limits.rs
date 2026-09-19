//! What the 1PUX reader refuses to do.
//!
//! A 1PUX archive is a zip someone else wrote, and a zip is the classic shape of a resource
//! attack: a few hundred kilobytes on disk that become half a terabyte in memory, an entry name
//! that walks out of the destination directory, a JSON array with a hundred million elements.
//! None of that is exotic and none of it needs an attacker — a corrupt file does it by accident.
//!
//! So the reader decides what it will accept *before* it decompresses anything. Every number
//! here is checked against the central directory, which states the uncompressed size of each
//! entry without a byte being inflated (plan §2, threat-model M-21).
//!
//! The limits are a [`Limits`] value rather than constants so a test can shrink them: proving
//! that the 100 000-item refusal works should not cost 100 000 items.

use std::io::{Read, Seek};

use zip::ZipArchive;

use crate::error::{ImportError, Result};

/// The ceilings the 1PUX reader enforces.
///
/// [`Limits::default`] is what a real import uses; the fields are public so a test can lower one
/// and exercise the refusal cheaply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Total uncompressed size of every entry, in bytes. 500 MB.
    ///
    /// A real export of a very large vault with documents is a few hundred megabytes; past this
    /// the file is not an export of a vault a person owns.
    pub max_total_uncompressed: u64,

    /// Largest ratio of uncompressed to compressed size any single entry may have. 1000:1.
    ///
    /// Deflate's theoretical best is about 1032:1, so this refuses only entries that are
    /// *deliberately* incompressible-looking — which is exactly what a zip bomb is.
    pub max_entry_ratio: u64,

    /// Entries whose compressed size is below this are exempt from
    /// [`Limits::max_entry_ratio`], in bytes.
    ///
    /// A 900-byte entry that inflates to 900 KB is not an attack, and a small entry's ratio is
    /// noise: the deflate header alone is a few bytes.
    pub ratio_floor: u64,

    /// Largest `export.data` this reader will hold in memory, in bytes. 256 MiB.
    ///
    /// `export.data` is the one entry that is read in full, so it gets its own ceiling and the
    /// read itself goes through [`Read::take`] — the declared size is checked first, and the cap
    /// holds even if the central directory lied.
    pub max_export_data: u64,

    /// Largest number of items in one archive. 100 000.
    pub max_items: usize,

    /// Largest number of fields on one item, login fields and section fields together. 10 000.
    pub max_fields_per_item: usize,

    /// Largest number of sections on one item. 1 000.
    pub max_sections_per_item: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_uncompressed: 500_000_000,
            max_entry_ratio: 1_000,
            ratio_floor: 1_024,
            max_export_data: 256 << 20,
            max_items: 100_000,
            max_fields_per_item: 10_000,
            max_sections_per_item: 1_000,
        }
    }
}

/// The name of each limit, as [`ImportError::LimitExceeded`] reports it.
///
/// `&'static str` because the error carries one, and because a limit's name is a fact about this
/// build rather than about the file being read.
pub(crate) mod names {
    /// [`super::Limits::max_total_uncompressed`].
    pub const TOTAL_UNCOMPRESSED: &str = "uncompressed archive size in bytes";
    /// [`super::Limits::max_entry_ratio`].
    pub const ENTRY_RATIO: &str = "compression ratio of a single archive entry";
    /// [`super::Limits::max_export_data`].
    pub const EXPORT_DATA: &str = "size of export.data in bytes";
    /// The ceiling on any other single entry this reader holds in memory.
    pub const ENTRY_SIZE: &str = "size of an archive entry in bytes";
    /// [`super::Limits::max_items`].
    pub const ITEMS: &str = "number of items in the export";
    /// [`super::Limits::max_fields_per_item`].
    pub const FIELDS: &str = "number of fields on one item";
    /// [`super::Limits::max_sections_per_item`].
    pub const SECTIONS: &str = "number of sections on one item";
}

/// Refuse an archive whose central directory already disqualifies it.
///
/// Walks every entry once, before a byte is decompressed, and checks three things: that the name
/// stays inside the archive ([`zip::read::ZipFile::enclosed_name`]), that the running total of
/// uncompressed sizes stays under [`Limits::max_total_uncompressed`], and that no single entry
/// claims a compression ratio past [`Limits::max_entry_ratio`].
///
/// Nothing is extracted here or anywhere else in this module tree; the reader has no code path
/// that writes an archive entry to disk.
///
/// # Errors
///
/// [`ImportError::UnsafeEntryName`] for a name that escapes the archive root,
/// [`ImportError::LimitExceeded`] for either size limit, and [`ImportError::Malformed`] if the
/// central directory itself cannot be walked.
pub(crate) fn check_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    limits: &Limits,
) -> Result<()> {
    let mut total: u64 = 0;

    for index in 0..archive.len() {
        // `by_index_raw` hands back the entry's metadata and a reader over the *compressed*
        // bytes. Nothing is inflated unless something reads from it, and nothing does.
        let entry = archive.by_index_raw(index).map_err(|_| {
            // The zip crate's message can quote an entry name; this one cannot.
            super::malformed("an entry in the archive's central directory could not be read")
        })?;

        if entry.enclosed_name().is_none() {
            return Err(ImportError::UnsafeEntryName);
        }

        let size = entry.size();
        let compressed = entry.compressed_size();

        total = total.saturating_add(size);
        if total > limits.max_total_uncompressed {
            return Err(ImportError::LimitExceeded {
                what: names::TOTAL_UNCOMPRESSED,
                limit: limits.max_total_uncompressed,
            });
        }

        if compressed >= limits.ratio_floor && size / compressed.max(1) > limits.max_entry_ratio {
            return Err(ImportError::LimitExceeded {
                what: names::ENTRY_RATIO,
                limit: limits.max_entry_ratio,
            });
        }
    }

    Ok(())
}

/// Refuse a count that is past its limit.
///
/// # Errors
///
/// [`ImportError::LimitExceeded`] naming `what` and `limit`.
pub(crate) fn check_count(count: usize, limit: usize, what: &'static str) -> Result<()> {
    if count > limit {
        return Err(ImportError::LimitExceeded {
            what,
            limit: limit as u64,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_numbers_the_plan_fixed() {
        let limits = Limits::default();
        assert_eq!(limits.max_total_uncompressed, 500_000_000);
        assert_eq!(limits.max_entry_ratio, 1_000);
        assert_eq!(limits.max_export_data, 268_435_456);
        assert_eq!(limits.max_items, 100_000);
        assert_eq!(limits.max_fields_per_item, 10_000);
        assert_eq!(limits.max_sections_per_item, 1_000);
    }

    #[test]
    fn a_count_at_the_limit_is_allowed_and_one_past_it_is_not() {
        assert!(check_count(10, 10, names::ITEMS).is_ok());
        let error = check_count(11, 10, names::ITEMS).unwrap_err();
        assert!(matches!(
            error,
            ImportError::LimitExceeded {
                what: names::ITEMS,
                limit: 10
            }
        ));
    }
}

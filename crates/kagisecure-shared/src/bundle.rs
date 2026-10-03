//! Bundles: everything a set of records for one shared vault looks like as a single file — one
//! whole export, handed over as an email attachment or carried on a USB stick (ADR-0035 §7;
//! addendum, "File magic", limits; decisions 60, 61).
//!
//! # The format
//!
//! ```text
//! magic     8 bytes    "KAGISBN\0" (the encoding contract's bundle magic)
//! version   1 byte     1
//! count     u32, BE    how many records follow; refused above MAX_BUNDLE_RECORDS before a
//!                      single one is read
//! records   `count` times, each:
//!   length  u32, BE    the record's length; refused above MAX_RECORD_BYTES before it is sliced
//!   record  `length` bytes   a record envelope, exactly as `record::Envelope::parse` reads one
//! ```
//!
//! Nothing beyond the whole input's length ([`MAX_BUNDLE_BYTES`]) and each length prefix is ever
//! trusted before the bytes it names are actually there: every limit here is checked before the
//! bytes it bounds are read, the same discipline [`crate::record::Envelope::parse`] uses for one
//! record (decision 60). The count and length fields are plain big-endian integers, not CBOR —
//! nothing about this container is signed or hashed, so it does not need the record format's
//! deterministic-encoding discipline, only bounds checked in the right order.
//!
//! [`encode`] always emits records in ascending order of their id, with duplicates — the same id
//! appearing more than once in the input — collapsed to one: two callers handed the same record
//! set in a different order, or one that repeats a record, produce byte-identical bundles either
//! way (decision 61). [`parse`] does the same collapsing on the way in, so a bundle built by
//! another implementation that did not deduplicate still parses to one envelope per id; it does
//! not, however, require a bundle's records to already be sorted on the way in — only what
//! [`parse`] hands back is.
//!
//! Verifying a record's signature, and everything that depends on it (the roster, the epoch, the
//! chain), is the caller's job: this module only reads the container and gives back the
//! [`Envelope`]s inside it, parsed but not verified — exactly as [`crate::exchange`] does for the
//! directory form of the same records (ADR-0035 addendum, step 11: "import returns envelopes
//! only").

use std::collections::BTreeMap;

use crate::error::{Result, SharedError};
use crate::record::{Envelope, MAX_RECORD_BYTES, RecordId};

/// A bundle file's first eight bytes (ADR-0035 addendum, "File magic").
pub const BUNDLE_MAGIC: [u8; 8] = *b"KAGISBN\0";
/// The bundle format version this build reads and writes.
pub const BUNDLE_VERSION: u8 = 1;
/// The largest a bundle may be, in bytes — checked against the whole input before a byte beyond
/// the magic is read (ADR-0035 addendum, limits).
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
/// The most records a bundle may hold (ADR-0035 addendum, limits).
pub const MAX_BUNDLE_RECORDS: usize = 200_000;

/// What every refusal below, other than a named limit or version, says went wrong.
const SHAPE: &str =
    "a bundle is the magic, a version, a bounded count and that many length-prefixed records";

/// Encode `envelopes` as a bundle: sorted by id, ascending, with duplicate ids collapsed to the
/// first one given (decision 61).
///
/// # Errors
///
/// [`SharedError::LimitExceeded`] if, after deduplication, there are more than
/// [`MAX_BUNDLE_RECORDS`] envelopes, or the encoded bundle would exceed [`MAX_BUNDLE_BYTES`].
pub fn encode(envelopes: &[Envelope]) -> Result<Vec<u8>> {
    let mut unique: BTreeMap<RecordId, &Envelope> = BTreeMap::new();
    for envelope in envelopes {
        unique.entry(envelope.id()).or_insert(envelope);
    }
    if unique.len() > MAX_BUNDLE_RECORDS {
        return Err(SharedError::LimitExceeded {
            what: "bundle records",
            limit: MAX_BUNDLE_RECORDS as u64,
        });
    }

    // Sized, and refused if too large, before a byte is copied: a record set over the limit
    // should not first cost a copy of the whole of it.
    let size = encoded_len(unique.values().copied());
    if size > MAX_BUNDLE_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "bundle",
            limit: MAX_BUNDLE_BYTES,
        });
    }
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    out.extend_from_slice(&BUNDLE_MAGIC);
    out.push(BUNDLE_VERSION);
    // `unique.len() <= MAX_BUNDLE_RECORDS`, which fits comfortably in a u32.
    out.extend_from_slice(&(unique.len() as u32).to_be_bytes());
    for envelope in unique.values() {
        let bytes = envelope.to_bytes();
        let len = u32::try_from(bytes.len()).map_err(|_| SharedError::LimitExceeded {
            what: "record",
            limit: MAX_RECORD_BYTES as u64,
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    debug_assert_eq!(out.len() as u64, size);
    Ok(out)
}

/// The length of the bundle holding `envelopes`: the magic, the version, the count, and a
/// length prefix and the bytes of each.
fn encoded_len<'a>(envelopes: impl Iterator<Item = &'a Envelope>) -> u64 {
    let header = BUNDLE_MAGIC.len() as u64 + 1 + 4;
    envelopes.fold(header, |total, envelope| {
        total.saturating_add(4 + envelope.to_bytes().len() as u64)
    })
}

/// Read a bundle, within the bounds [`encode`] writes to: the whole input against
/// [`MAX_BUNDLE_BYTES`], the declared count against [`MAX_BUNDLE_RECORDS`], and each record's
/// declared length against [`MAX_RECORD_BYTES`] — every one of them before the bytes it names are
/// read. Records are returned sorted by id, ascending, with duplicate ids collapsed to the first
/// one read (decision 61); their signatures are not checked, and neither is anything about the
/// roster or the epoch they claim — that is the caller's, in a later phase.
///
/// # Errors
///
/// [`SharedError::LimitExceeded`] for the whole-bundle, count or per-record limits above;
/// [`SharedError::UnsupportedVersion`] for a version other than [`BUNDLE_VERSION`];
/// [`SharedError::Malformed`] for a bad magic, a truncated or over-long container, or a record
/// that does not parse as an envelope.
pub fn parse(bytes: &[u8]) -> Result<Vec<Envelope>> {
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "bundle",
            limit: MAX_BUNDLE_BYTES,
        });
    }
    let mut rest = bytes;

    let magic = take(&mut rest, BUNDLE_MAGIC.len())?;
    if magic != BUNDLE_MAGIC {
        return Err(SharedError::Malformed(SHAPE));
    }
    let version = take(&mut rest, 1)?[0];
    if version != BUNDLE_VERSION {
        return Err(SharedError::UnsupportedVersion {
            what: "bundle",
            version: version.into(),
        });
    }
    let count = u32::from_be_bytes(take(&mut rest, 4)?.try_into().expect("exactly 4 bytes"));
    let count = count as usize;
    if count > MAX_BUNDLE_RECORDS {
        return Err(SharedError::LimitExceeded {
            what: "bundle records",
            limit: MAX_BUNDLE_RECORDS as u64,
        });
    }

    let mut unique: BTreeMap<RecordId, Envelope> = BTreeMap::new();
    for _ in 0..count {
        let len = u32::from_be_bytes(take(&mut rest, 4)?.try_into().expect("exactly 4 bytes"));
        let len = len as usize;
        if len > MAX_RECORD_BYTES {
            return Err(SharedError::LimitExceeded {
                what: "record",
                limit: MAX_RECORD_BYTES as u64,
            });
        }
        let record_bytes = take(&mut rest, len)?;
        let envelope = Envelope::parse(record_bytes)?;
        unique.entry(envelope.id()).or_insert(envelope);
    }
    if !rest.is_empty() {
        return Err(SharedError::Malformed(SHAPE));
    }
    Ok(unique.into_values().collect())
}

/// Take `n` bytes off the front of `rest`, refusing if there are not that many left.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if n > rest.len() {
        return Err(SharedError::Malformed(SHAPE));
    }
    let (taken, remainder) = rest.split_at(n);
    *rest = remainder;
    Ok(taken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_key::{EpochId, fixed_epoch_key};
    use crate::record::tests::vault;
    use crate::record::{NewRecord, RecordKind};
    use crate::test_support::golden_device;

    fn header(seq: u64) -> NewRecord {
        NewRecord {
            vault_id: vault(),
            seq,
            prev: (seq > 0).then_some(RecordId::from_bytes([seq as u8; 32])),
            parents: vec![],
            roster: vec![],
            epoch: Some(EpochId::from_bytes([9; 16])),
            created_at: 1,
        }
    }

    fn sealed(seq: u64) -> Envelope {
        Envelope::seal(
            &golden_device(),
            RecordKind::Item,
            header(seq),
            &fixed_epoch_key(1),
            format!("record {seq}").as_bytes(),
        )
        .unwrap()
    }

    /// A bundle's size is known before it is built, so one over the limit is refused without
    /// first copying the records into it.
    #[test]
    fn a_bundle_is_sized_before_it_is_built() {
        let envelopes = [sealed(0), sealed(1), sealed(2)];
        let bytes = encode(&envelopes).unwrap();
        assert_eq!(encoded_len(envelopes.iter()), bytes.len() as u64);
        assert_eq!(encoded_len(std::iter::empty()), 13);
    }

    #[test]
    fn a_bundle_round_trips_and_reads_back_sorted_by_id() {
        let records: Vec<Envelope> = (0..5).map(sealed).collect();
        let bytes = encode(&records).unwrap();
        assert_eq!(&bytes[..8], &BUNDLE_MAGIC);
        assert_eq!(bytes[8], BUNDLE_VERSION);

        let read = parse(&bytes).unwrap();
        let mut expected: Vec<RecordId> = records.iter().map(Envelope::id).collect();
        expected.sort();
        assert_eq!(read.iter().map(Envelope::id).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn encoding_is_independent_of_input_order_and_collapses_duplicates() {
        let records: Vec<Envelope> = (0..4).map(sealed).collect();
        let mut shuffled = records.clone();
        shuffled.reverse();
        shuffled.push(records[0].clone());
        shuffled.push(records[2].clone());
        assert_eq!(encode(&records).unwrap(), encode(&shuffled).unwrap());
    }

    #[test]
    fn an_empty_bundle_encodes_and_parses() {
        let bytes = encode(&[]).unwrap();
        assert!(parse(&bytes).unwrap().is_empty());
    }

    #[test]
    fn a_bundle_over_its_byte_limit_is_refused_before_reading() {
        // All zeros: not a valid bundle even at a legal size, so the only way this can fail with
        // the size limit named is if the size is checked before the magic.
        let huge = vec![0u8; MAX_BUNDLE_BYTES as usize + 1];
        assert!(matches!(
            parse(&huge),
            Err(SharedError::LimitExceeded { what: "bundle", .. })
        ));
    }

    #[test]
    fn a_declared_record_count_over_the_limit_is_refused_before_any_record_is_read() {
        let mut bytes = BUNDLE_MAGIC.to_vec();
        bytes.push(BUNDLE_VERSION);
        bytes.extend_from_slice(&((MAX_BUNDLE_RECORDS + 1) as u32).to_be_bytes());
        // No record bytes follow at all: if the count were checked only after reading a record,
        // this would fail as truncated instead, and the test would not exercise the right check.
        assert!(matches!(
            parse(&bytes),
            Err(SharedError::LimitExceeded {
                what: "bundle records",
                ..
            })
        ));
    }

    #[test]
    fn a_declared_record_length_over_the_record_limit_is_refused_before_it_is_sliced() {
        let mut bytes = BUNDLE_MAGIC.to_vec();
        bytes.push(BUNDLE_VERSION);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&(MAX_RECORD_BYTES as u32 + 1).to_be_bytes());
        // No record bytes follow; a check that read them before comparing the length would panic
        // slicing, not return an ordinary error.
        assert!(matches!(
            parse(&bytes),
            Err(SharedError::LimitExceeded { what: "record", .. })
        ));
    }

    #[test]
    fn truncated_and_garbage_bundles_are_refused() {
        let good = encode(&[sealed(0)]).unwrap();
        for cut in 0..good.len() {
            assert!(parse(&good[..cut]).is_err(), "cut at {cut}");
        }
        assert!(parse(&[0xffu8; 32]).is_err());
        assert!(parse(&[]).is_err());

        // Trailing garbage after the last declared record.
        let mut trailing = good;
        trailing.push(0);
        assert!(parse(&trailing).is_err());
    }

    #[test]
    fn wrong_magic_or_version_is_refused() {
        let mut bad_magic = encode(&[sealed(0)]).unwrap();
        bad_magic[0] ^= 0xff;
        assert!(matches!(parse(&bad_magic), Err(SharedError::Malformed(_))));

        let mut bad_version = encode(&[sealed(0)]).unwrap();
        bad_version[8] = 2;
        assert!(matches!(
            parse(&bad_version),
            Err(SharedError::UnsupportedVersion {
                what: "bundle",
                version: 2
            })
        ));
    }

    #[test]
    fn a_record_that_does_not_parse_as_an_envelope_is_refused() {
        let mut bytes = BUNDLE_MAGIC.to_vec();
        bytes.push(BUNDLE_VERSION);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        let garbage = vec![0xffu8; 16];
        bytes.extend_from_slice(&(garbage.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&garbage);
        assert!(parse(&bytes).is_err());
    }
}

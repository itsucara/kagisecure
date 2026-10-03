//! The exchange directory: one file per record, named by the record's own id, the way people hand
//! a shared vault's records to each other directly — a synced folder, a USB stick, a git
//! repository — without a bundle's single-file wrapper (ADR-0035 §7; addendum, "File magic";
//! decisions 62–64).
//!
//! # Layout
//!
//! Every record lives at `records/<64 lowercase hex id>.ksr` inside the exchange directory: the
//! record's own [`RecordId`] rendered as [`std::fmt::Display`] writes it, with the `.ksr`
//! extension. This module is handed that `records` subdirectory directly (its caller, a later
//! phase's `admin::exchange`, is the one that knows about anything else living beside it); there
//! is nothing else in it this module writes or expects — no descriptor, no index — because a
//! record's name already says everything the directory itself needs to say about it.
//!
//! # Never over the record itself
//!
//! [`export`] never replaces a file that already *is* the record — one that parses and whose id is
//! its name — so exporting a record twice writes it once. A record's name is a hash of its own
//! signed bytes, so a file under that name that is anything else — a short file a crash left on a
//! file system without hard links, a stale or tampered copy, a link — is not that record, and
//! export replaces it with the record, atomically (a temporary renamed over it; decision 75,
//! which replaces decision 63's "left alone"). A new file is created with
//! [`kagisecure_core::vault::atomic::write_new_file`]: a temporary written first, then
//! hard-linked into place, which fails rather than overwrites when the name is taken; on a file
//! system without hard links, it is created in place, create-new (decision 69).
//!
//! # Import: bounded, and quiet about what it skips
//!
//! [`import`] reads every entry in the directory once and returns only the files that are exactly
//! what their name claims: a name of the form `<64 lowercase hex>.ksr`, holding bytes that parse
//! as a record envelope whose own id ([`Envelope::id`]) is that same 64 hex. It counts only the
//! records that are what their name claims against [`MAX_EXCHANGE_ENTRIES`], so a directory stuffed
//! with other names, or with junk under record names, does not stop it; it refuses outright only
//! past that many records, past [`MAX_EXCHANGE_READ`] bytes read, or past [`MAX_EXCHANGE_LISTING`]
//! entries of any kind (decision 64, amended). A file is opened without
//! following a symbolic link and without waiting on a FIFO, and read only if the opened handle is
//! a regular file of at most a record's size. Everything else — a name that does not match that
//! shape, a link or a special file, a file too large to be a record, one that does not parse, or
//! one whose content's id is not its name — is skipped, not reported (decision 62): this step
//! returns envelopes only, the way the ADR-0035 addendum's step 11 contract asks; an accounting of
//! what was skipped and why is a later phase's, once there is a caller that would use it.
//! Signatures are not checked here either, for the same reason [`crate::bundle`] does not check
//! them: verification is the caller's, against a roster this module does not have.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kagisecure_core::vault::atomic::{write_atomically, write_new_file};

use crate::error::{Result, SharedError};
use crate::record::{Envelope, MAX_RECORD_BYTES, RECORD_ID_LEN, RecordId};

/// The suffix every record file carries, after its id.
const RECORD_SUFFIX: &str = ".ksr";

/// The most directory entries an [`import`] scan reads before refusing, whether or not they turn
/// out to be record files (decision 64): this bounds one call's work against a directory grown
/// unreasonably large, rather than a value this format ever hashes or signs, which is why it is
/// not in the ADR-0035 addendum's own limits list. Chosen the same order of magnitude as
/// [`crate::bundle::MAX_BUNDLE_RECORDS`], for the same reason: not a number anything depends on
/// being exact, only large enough for a real shared vault's history and small enough to bound the
/// work of one call.
pub const MAX_EXCHANGE_ENTRIES: usize = 200_000;

/// The most bytes an [`import`] reads, over every file it opens, before refusing: files named
/// like records whose content is not the record their name claims are skipped without
/// counting against [`MAX_EXCHANGE_ENTRIES`], so this is what bounds reading them (decision 64,
/// amended).
pub const MAX_EXCHANGE_READ: u64 = 4 * crate::bundle::MAX_BUNDLE_BYTES;

/// The most directory entries of any kind an [`import`] lists before refusing: a bound on the
/// work of one call against a directory filled with names that are not records, which do not
/// count against [`MAX_EXCHANGE_ENTRIES`] (decision 64, amended).
pub const MAX_EXCHANGE_LISTING: usize = 8 * MAX_EXCHANGE_ENTRIES;

/// Write `envelope` into `dir` as `<its id in hex>.ksr`, creating `dir` (and any missing parent)
/// first.
///
/// If a file is already there under that name and it is this record — it parses, and its id is
/// its name — it is left exactly as it is. Anything else under the name — a short file a crash
/// left, a tampered or stale copy, a link — is replaced with this record, atomically (decision
/// 75). A file that is the record is never replaced.
///
/// # Errors
///
/// An I/O error: `dir` could not be created, or the record could not be written for a reason
/// other than the name already being taken.
pub fn export(dir: &Path, envelope: &Envelope) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}{RECORD_SUFFIX}", envelope.id()));
    match write_new_file(&path, envelope.to_bytes(), &path) {
        Ok(()) => Ok(()),
        Err(kagisecure_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let matches = read_record_file(&path)
                .and_then(|bytes| Envelope::parse(&bytes).ok())
                .is_some_and(|existing| existing.id() == envelope.id());
            if !matches {
                write_atomically(&path, envelope.to_bytes())?;
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// [`export`] every envelope in `envelopes`, in order; the first error stops the rest.
///
/// # Errors
///
/// As [`export`].
pub fn export_all(dir: &Path, envelopes: &[Envelope]) -> Result<()> {
    for envelope in envelopes {
        export(dir, envelope)?;
    }
    Ok(())
}

/// Read every record `dir` holds, within [`MAX_EXCHANGE_ENTRIES`] entries: see the module
/// documentation's "Import" section for exactly what is accepted and what is quietly skipped. A
/// `dir` that does not exist reads as empty, the same as one with nothing in it — a device that
/// has never received anything through this exchange directory yet is not an error.
///
/// Returned in ascending order of record id, with duplicate ids collapsed to the first one read —
/// impossible from one directory (two different names cannot both be `<id>.ksr` for the same
/// `id`), but kept the same shape [`crate::bundle::parse`] returns, for a caller that merges both
/// sources.
///
/// # Errors
///
/// [`SharedError::LimitExceeded`] if the directory holds more than [`MAX_EXCHANGE_ENTRIES`]
/// entries; an I/O error reading the directory itself (not one entry, which is skipped instead).
pub fn import(dir: &Path) -> Result<Vec<Envelope>> {
    import_missing(dir, |_| false)
}

/// [`import`], but without opening any file whose name is a record `have` says the caller
/// already holds. A record's file name is its id, a hash of its content, so a name the caller
/// holds is a record it holds: a sync that finds nothing new reads no file at all.
///
/// # Errors
///
/// As [`import`].
pub fn import_missing(dir: &Path, have: impl Fn(&RecordId) -> bool) -> Result<Vec<Envelope>> {
    import_bounded(
        dir,
        MAX_EXCHANGE_ENTRIES,
        MAX_EXCHANGE_LISTING,
        MAX_EXCHANGE_READ,
        &have,
    )
}

/// The records `dir` holds files for, by name alone, without opening any. Names that are not of
/// the record shape are left out; a missing directory holds none.
///
/// # Errors
///
/// [`SharedError::LimitExceeded`] above [`MAX_EXCHANGE_LISTING`] entries; an I/O error reading
/// the directory.
pub fn listed(dir: &Path) -> Result<BTreeSet<RecordId>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(e.into()),
    };
    let mut names = BTreeSet::new();
    for (listed, entry) in entries.enumerate() {
        if listed >= MAX_EXCHANGE_LISTING {
            return Err(SharedError::LimitExceeded {
                what: "exchange directory entries",
                limit: MAX_EXCHANGE_LISTING as u64,
            });
        }
        if let Some(id) = entry?
            .file_name()
            .to_str()
            .and_then(record_id_from_file_name)
        {
            names.insert(id);
        }
    }
    Ok(names)
}

/// [`import`], with the bounds given explicitly — smaller ones are only ever handed in by this
/// module's own tests, so [`MAX_EXCHANGE_ENTRIES`] files do not have to be created just to
/// exercise the refusal.
fn import_bounded(
    dir: &Path,
    max_records: usize,
    max_listing: usize,
    max_read: u64,
    have: &dyn Fn(&RecordId) -> bool,
) -> Result<Vec<Envelope>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut accepted: BTreeMap<RecordId, Envelope> = BTreeMap::new();
    let mut listed = 0usize;
    let mut read = 0u64;
    for entry in entries {
        listed += 1;
        if listed > max_listing {
            return Err(SharedError::LimitExceeded {
                what: "exchange directory entries",
                limit: max_listing as u64,
            });
        }
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(claimed_id) = record_id_from_file_name(name) else {
            continue;
        };
        if have(&claimed_id) {
            continue;
        }
        let Some(bytes) = read_record_file(&entry.path()) else {
            continue;
        };
        read = read.saturating_add(bytes.len() as u64);
        if read > max_read {
            return Err(SharedError::LimitExceeded {
                what: "exchange directory bytes",
                limit: max_read,
            });
        }
        let Ok(envelope) = Envelope::parse(&bytes) else {
            continue;
        };
        if envelope.id() != claimed_id {
            // A misnamed file: its content is some other record's (decision 62).
            continue;
        }
        accepted.entry(envelope.id()).or_insert(envelope);
        // Only records that are what their name claims count: junk under record-shaped names
        // is skipped, not a reason to refuse the rest (decision 64, amended).
        if accepted.len() > max_records {
            return Err(SharedError::LimitExceeded {
                what: "exchange directory records",
                limit: max_records as u64,
            });
        }
    }
    Ok(accepted.into_values().collect())
}

/// The bytes of the regular file at `path`, if it is one and holds at most a record's worth.
///
/// Opened without following a symbolic link (`O_NOFOLLOW`) and without waiting for a writer
/// (`O_NONBLOCK`, which a FIFO would otherwise block on), and judged by the opened handle's own
/// metadata, so nothing swapped in between a listing and the open is read as a record. The read
/// is bounded too, since a file can grow after its length is read.
fn read_record_file(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;

    #[cfg(test)]
    FILES_READ.with(|n| n.set(n.get() + 1));
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_RECORD_BYTES).then_some(bytes)
}

#[cfg(test)]
thread_local! {
    /// How many record files this thread has opened: for tests that a sync with nothing new
    /// reads none.
    pub(crate) static FILES_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The [`RecordId`] a file name of the form `<64 lowercase hex digits>.ksr` claims, or `None` for
/// any other shape.
fn record_id_from_file_name(name: &str) -> Option<RecordId> {
    let hex = name.strip_suffix(RECORD_SUFFIX)?;
    if hex.len() != RECORD_ID_LEN * 2
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0u8; RECORD_ID_LEN];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(RecordId::from_bytes(bytes))
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
            epoch: Some(EpochId::from_bytes([7; 16])),
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

    #[test]
    fn a_record_round_trips_through_export_and_import() {
        let dir = tempfile::tempdir().unwrap();
        let records: Vec<Envelope> = (0..3).map(sealed).collect();
        export_all(dir.path(), &records).unwrap();

        let file_names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for record in &records {
            assert!(file_names.contains(&format!("{}.ksr", record.id())));
        }

        let read = import(dir.path()).unwrap();
        let mut expected: Vec<RecordId> = records.iter().map(Envelope::id).collect();
        expected.sort();
        assert_eq!(read.iter().map(Envelope::id).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn importing_a_directory_that_does_not_exist_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created");
        assert!(import(&missing).unwrap().is_empty());
    }

    #[test]
    fn a_file_that_is_the_record_is_kept_and_anything_else_is_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let record = sealed(0);
        std::fs::create_dir_all(dir.path()).unwrap();
        let path = dir.path().join(format!("{}.ksr", record.id()));
        // What a crash mid-write on a file system without hard links can leave: a short file.
        std::fs::write(&path, &record.to_bytes()[..10]).unwrap();
        export(dir.path(), &record).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), record.to_bytes());
        // Another record's bytes under this name: replaced too.
        std::fs::write(&path, sealed(1).to_bytes()).unwrap();
        export(dir.path(), &record).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), record.to_bytes());
        // The record itself: left exactly as it is, down to its modification time.
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        export(dir.path(), &record).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(import(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn a_misnamed_file_is_not_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let a = sealed(0);
        let b = sealed(1);
        std::fs::create_dir_all(dir.path()).unwrap();
        // b's bytes, saved under a's name.
        std::fs::write(dir.path().join(format!("{}.ksr", a.id())), b.to_bytes()).unwrap();

        assert!(import(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn oversize_truncated_and_garbage_files_are_skipped_not_accepted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let big_name = format!("{}.ksr", RecordId::from_bytes([0xaa; 32]));
        std::fs::write(dir.path().join(&big_name), vec![0u8; MAX_RECORD_BYTES + 1]).unwrap();
        let garbage_name = format!("{}.ksr", RecordId::from_bytes([0xbb; 32]));
        std::fs::write(dir.path().join(&garbage_name), b"not a record").unwrap();
        // A name that is not the right shape at all.
        std::fs::write(dir.path().join("not-a-record-name.ksr"), b"whatever").unwrap();
        std::fs::write(dir.path().join("README.txt"), b"ignored, wrong extension").unwrap();

        assert!(import(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn import_does_not_depend_on_the_directory_s_own_order() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let records: Vec<Envelope> = (0..4).map(sealed).collect();
        export_all(dir_a.path(), &records).unwrap();
        let mut reversed = records.clone();
        reversed.reverse();
        export_all(dir_b.path(), &reversed).unwrap();

        let read_a = import(dir_a.path()).unwrap();
        let read_b = import(dir_b.path()).unwrap();
        assert_eq!(
            read_a.iter().map(Envelope::id).collect::<Vec<_>>(),
            read_b.iter().map(Envelope::id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_directory_scan_over_its_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5u32 {
            std::fs::write(dir.path().join(format!("junk-{i}")), b"x").unwrap();
        }
        assert!(matches!(
            import_bounded(dir.path(), 3, 3, u64::MAX, &|_| false),
            Err(SharedError::LimitExceeded {
                what: "exchange directory entries",
                ..
            })
        ));
        assert!(import_bounded(dir.path(), 3, 5, u64::MAX, &|_| false).is_ok());
    }

    /// Files named like records whose content is not the record they name do not count against
    /// the record bound either; what bounds them is the bytes read.
    #[test]
    fn junk_under_record_names_is_skipped_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..5u8 {
            std::fs::write(
                dir.path()
                    .join(format!("{}.ksr", "0".repeat(63) + &n.to_string())),
                b"junk",
            )
            .unwrap();
        }
        export(dir.path(), &sealed(0)).unwrap();
        assert_eq!(
            import_bounded(dir.path(), 1, 100, u64::MAX, &|_| false)
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            import_bounded(dir.path(), 1, 100, 8, &|_| false),
            Err(SharedError::LimitExceeded {
                what: "exchange directory bytes",
                ..
            })
        ));
    }

    /// Names that are not records do not count against the record bound, so filling a
    /// directory with them does not stop an import; records past it do.
    #[test]
    fn other_names_do_not_count_against_the_record_bound() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5u32 {
            std::fs::write(dir.path().join(format!("junk-{i}")), b"x").unwrap();
        }
        let record = sealed(0);
        export(dir.path(), &record).unwrap();
        let got = import_bounded(dir.path(), 1, 100, u64::MAX, &|_| false).unwrap();
        assert_eq!(got.len(), 1);
        export(dir.path(), &sealed(1)).unwrap();
        assert!(matches!(
            import_bounded(dir.path(), 1, 100, u64::MAX, &|_| false),
            Err(SharedError::LimitExceeded {
                what: "exchange directory records",
                ..
            })
        ));
    }

    /// A symbolic link or a FIFO under a record's name is skipped: the link is not followed,
    /// and the FIFO is not waited on.
    #[cfg(unix)]
    #[test]
    fn a_link_or_a_fifo_under_a_records_name_is_skipped() {
        let elsewhere = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let record = sealed(0);
        export(elsewhere.path(), &record).unwrap();
        let name = format!("{}.ksr", record.id());
        std::os::unix::fs::symlink(elsewhere.path().join(&name), dir.path().join(&name)).unwrap();
        let other = sealed(1);
        let fifo = dir.path().join(format!("{}.ksr", other.id()));
        // Made with the system's own tool: this crate forbids the unsafe call to `mkfifo`.
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|status| status.success());
        assert!(!made || fifo.exists());
        // Returns — a FIFO opened without O_NONBLOCK would wait here for a writer forever.
        let got = import(dir.path()).unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn a_file_name_must_be_exactly_sixty_four_lowercase_hex_digits_and_the_suffix() {
        assert!(record_id_from_file_name("not-hex-at-all.ksr").is_none());
        assert!(record_id_from_file_name(&"a".repeat(63)).is_none());
        assert!(record_id_from_file_name(&format!("{}.ksr", "a".repeat(63))).is_none());
        assert!(record_id_from_file_name(&format!("{}.ksr", "A".repeat(64))).is_none());
        assert!(record_id_from_file_name(&format!("{}.KSR", "a".repeat(64))).is_none());
        assert!(record_id_from_file_name(&format!("{}.ksr", "a".repeat(64))).is_some());
    }
}

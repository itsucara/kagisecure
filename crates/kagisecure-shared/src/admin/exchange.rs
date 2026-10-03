//! Moving records between devices: importing and exporting an exchange directory or a bundle,
//! and syncing with the configured directory in one call (ADR-0035 §7; addendum, decision 85).
//!
//! An exchange directory keeps its records in `records/<64 hex>.ksr` ([`records_dir`]). Import
//! reads every record there — or in a bundle — and adds the new ones to the replica in **one**
//! transaction; it reports what changed by name only: the titles of the items and the names of
//! the environments whose versions changed, and whether the roster did — never a value.
//! Export writes every record the replica holds that the directory is missing, or the whole
//! replica as one bundle. [`sync`] does both against the configured directory, which is all a
//! person has to do to pick up and hand on everyone's changes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::device::DeviceSecret;
use crate::error::{Result, SharedError};
use crate::merge::{materialize_env, materialize_item};
use crate::record::{Envelope, RecordId};
use crate::replica::Replica;
use crate::view::{ObjectId, SharedView, Version};

/// Where an exchange directory keeps its records: its `records` subdirectory.
#[must_use]
pub fn records_dir(exchange_dir: &Path) -> PathBuf {
    exchange_dir.join("records")
}

/// `dir` as the text the local state keeps.
pub(crate) fn path_text(dir: &Path) -> Result<String> {
    dir.to_str().map(str::to_owned).ok_or(SharedError::Refused(
        "an exchange directory's path must be valid UTF-8",
    ))
}

/// What an import changed, by name only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// How many records were new to this replica.
    pub records_added: usize,
    /// The titles of the items whose versions changed, in id order; a deleted item's last title.
    pub items: Vec<String>,
    /// The names of the environments whose versions changed, in id order.
    pub envs: Vec<String>,
    /// Whether the roster changed: someone was added or removed, or a role changed.
    pub roster_changed: bool,
}

/// The name a person knows `object` by in `view`: its merged title or name — or, for one now
/// deleted, the last it had.
fn name_of(view: &SharedView, object: &ObjectId) -> String {
    let merged = match object {
        ObjectId::Item(id) => materialize_item(view, *id)
            .ok()
            .flatten()
            .and_then(|m| m.item.map(|item| item.title)),
        ObjectId::Env(id) => materialize_env(view, *id)
            .ok()
            .flatten()
            .and_then(|m| m.env.map(|env| env.name)),
    };
    merged
        .or_else(|| {
            view.versions_of(object)
                .iter()
                .rev()
                .find_map(|v| match v.version() {
                    Version::Item(v) => v.item().map(|item| item.title.clone()),
                    Version::Env(v) => v.env().map(|env| env.name.clone()),
                })
        })
        .unwrap_or_default()
}

/// Add `records` to `replica` in one transaction, and say what changed. With nothing new,
/// nothing is read, computed or written.
fn import(
    replica: &mut Replica,
    device: &DeviceSecret,
    records: Vec<Envelope>,
) -> Result<ImportSummary> {
    if records.iter().all(|r| replica.contains(&r.id())) {
        return Ok(ImportSummary::default());
    }
    replica.transact(device, |tx| {
        let added: Vec<RecordId> = records
            .into_iter()
            .filter_map(|r| {
                let id = r.id();
                tx.add(r).then_some(id)
            })
            .collect();
        let mut summary = ImportSummary {
            records_added: added.len(),
            ..ImportSummary::default()
        };
        if added.is_empty() {
            return Ok(summary);
        }
        // The state, once, after.
        let view = SharedView::compute(tx.vault_id(), &tx.genesis(), &tx.envelopes(), device)?;
        summary.roster_changed = added.iter().any(|id| view.roster().order().contains(id));
        let objects: BTreeSet<ObjectId> = added
            .iter()
            .filter_map(|id| view.version(id))
            .map(|v| v.version().object())
            .collect();
        for object in &objects {
            let name = name_of(&view, object);
            match object {
                ObjectId::Item(_) => summary.items.push(name),
                ObjectId::Env(_) => summary.envs.push(name),
            }
        }
        Ok(summary)
    })
}

/// Import every record of the exchange directory `dir` (module documentation).
///
/// # Errors
///
/// As [`crate::exchange::import`] and [`Replica::transact`].
pub fn import_dir(
    replica: &mut Replica,
    device: &DeviceSecret,
    dir: &Path,
) -> Result<ImportSummary> {
    // Files are named by their record's id: one this replica holds is never opened.
    let records = crate::exchange::import_missing(&records_dir(dir), |id| replica.contains(id))?;
    import(replica, device, records)
}

/// Import every record of a bundle file's `bytes`.
///
/// # Errors
///
/// As [`crate::bundle::parse`] and [`Replica::transact`].
pub fn import_bundle(
    replica: &mut Replica,
    device: &DeviceSecret,
    bytes: &[u8],
) -> Result<ImportSummary> {
    let records = crate::bundle::parse(bytes)?;
    import(replica, device, records)
}

/// Write every record of `replica` that the exchange directory `dir` has no file for, judged by
/// file name alone. Returns how many were written. A file under a record's name is taken to be
/// that record: a damaged one is not repaired here (decision 87).
///
/// # Errors
///
/// As [`crate::exchange::export`].
pub fn export_dir(replica: &Replica, dir: &Path) -> Result<usize> {
    let dir = records_dir(dir);
    // One listing, by name: a record whose file is there is not written or read again.
    let present = crate::exchange::listed(&dir)?;
    let mut written = 0;
    for record in replica.records().filter(|r| !present.contains(&r.id())) {
        crate::exchange::export(&dir, record)?;
        written += 1;
    }
    Ok(written)
}

/// Every record of `replica`, as one bundle file's bytes.
///
/// # Errors
///
/// As [`crate::bundle::encode`].
pub fn export_bundle(replica: &Replica) -> Result<Vec<u8>> {
    crate::bundle::encode(&replica.envelopes())
}

/// Configure `dir` as the exchange directory this device imports from and exports to — or
/// none.
///
/// # Errors
///
/// [`SharedError::Refused`] for a path that is not UTF-8; as [`Replica::transact`].
pub fn set_exchange_dir(
    replica: &mut Replica,
    device: &DeviceSecret,
    dir: Option<&Path>,
) -> Result<()> {
    let dir = dir.map(path_text).transpose()?;
    replica.transact(device, |tx| {
        tx.local_mut().exchange_dir = dir;
        Ok(())
    })
}

/// Import from the configured exchange directory, then export to it everything it is missing:
/// one call to pick up and hand on every change.
///
/// # Errors
///
/// [`SharedError::Refused`] if no exchange directory is configured; as [`import_dir`] and
/// [`export_dir`].
pub fn sync(replica: &mut Replica, device: &DeviceSecret) -> Result<ImportSummary> {
    let dir = replica
        .local()
        .exchange_dir
        .clone()
        .ok_or(SharedError::Refused("no exchange directory is configured"))?;
    let dir = PathBuf::from(dir);
    let summary = import_dir(replica, device, &dir)?;
    export_dir(replica, &dir)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::FILES_READ;
    use crate::test_support::Writer;

    #[test]
    fn a_sync_with_nothing_new_opens_no_record_file() {
        let dir = tempfile::tempdir().unwrap();
        let exchange = dir.path().join("exchange");
        let device = Writer::new(1).device;
        let mut replica = crate::admin::create::create(
            &dir.path().join("vault.kagivault"),
            &device,
            "Team",
            Some(&exchange),
            1,
        )
        .unwrap();
        sync(&mut replica, &device).unwrap();
        let before = std::fs::read(replica.path()).unwrap();
        FILES_READ.with(|n| n.set(0));
        let summary = sync(&mut replica, &device).unwrap();
        assert_eq!(summary, ImportSummary::default());
        assert_eq!(FILES_READ.with(std::cell::Cell::get), 0);
        assert_eq!(export_dir(&replica, &exchange).unwrap(), 0);
        // Nor was the replica rewritten.
        assert_eq!(std::fs::read(replica.path()).unwrap(), before);
    }
}

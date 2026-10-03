//! Writing to a shared vault: an item or an environment, put or deleted, as this device's next
//! record (ADR-0035 §6, §8; addendum, decision 81).
//!
//! Every write is one [`Replica::transact`]: it first takes in this device's own records from
//! the configured exchange directory — a copy of the replica restored from a backup would
//! otherwise reuse a `seq` it already published ([`next_seq`]; §9) — then computes the view,
//! checks that this device may write (a writer or an admin, holding the current epoch's key, on
//! a vault this build may write to), seals the version under the current epoch and adds it.
//! After the transaction, the new record is exported to the exchange directory, if one is
//! configured, so there is nothing else to remember to do.
//!
//! A version names as its parents the versions of the item nobody built on yet (at most
//! [`MAX_PARENTS`], the latest first): what [`crate::merge`] compares it against to see what it
//! changed. There is nothing to resolve: the merge is last-writer-wins (decision 80).
//!
//! What is this device's own about an item or environment — whether an agent may see it or a
//! field of it, whether it is a favourite, an environment's default paths — never goes into the
//! record (`crate::payload`); it is kept in the replica's local state instead.

use std::collections::BTreeSet;
use std::path::Path;

use kagisecure_core::model::{Environment, Item};
use kagisecure_core::proto::{EnvId, ItemId};

use crate::admin::exchange::records_dir;
use crate::device::DeviceSecret;
use crate::epoch_key::{EpochId, EpochKey};
use crate::error::{Result, SharedError};
use crate::payload::{EnvVersion, ItemVersion};
use crate::record::{Envelope, MAX_PARENTS, NewRecord, RecordId};
use crate::replica::{Replica, ReplicaTx};
use crate::roster::Role;
use crate::view::{ObjectId, SharedView};

/// Take in this device's own records from the configured exchange directory.
fn import_own(tx: &mut ReplicaTx<'_>, device: &DeviceSecret) -> Result<()> {
    let Some(dir) = tx.local().exchange_dir.clone() else {
        return Ok(());
    };
    for envelope in crate::exchange::import(&records_dir(Path::new(&dir)))? {
        if envelope.author() == device.id() {
            tx.add(envelope);
        }
    }
    Ok(())
}

/// This device's next `seq` and previous record, from its records in the transaction and the
/// rollback guard.
fn next_position(tx: &ReplicaTx<'_>, device: &DeviceSecret) -> Result<(u64, Option<RecordId>)> {
    let mut last: Option<(u64, RecordId)> = None;
    for envelope in tx.records() {
        if envelope.author() != device.id() {
            continue;
        }
        let Ok(body) = envelope.body_unverified() else {
            continue;
        };
        let candidate = (body.seq(), envelope.id());
        // The highest `seq`; between two at one `seq`, the smaller id.
        if last.is_none_or(|(seq, id)| body.seq() > seq || (body.seq() == seq && candidate.1 < id))
        {
            last = Some(candidate);
        }
    }
    let top = last.map(|(seq, _)| seq).max(tx.local().highest_seq);
    match (top, last) {
        (None, _) => Ok((0, None)),
        (Some(top), Some((_, prev))) => Ok((top + 1, Some(prev))),
        (Some(_), None) => Err(SharedError::Refused(
            "this device's earlier records are missing from its replica: import them first",
        )),
    }
}

/// The `seq` this device's next record in `replica` takes, after taking in its own records
/// from the configured exchange directory (§9: a replica restored from an older copy must not
/// reuse a `seq` this device already published).
///
/// # Errors
///
/// [`SharedError::Refused`] if the replica knows this device wrote records it no longer holds;
/// and whatever the transaction or reading the exchange directory refuse.
pub fn next_seq(replica: &mut Replica, device: &DeviceSecret) -> Result<u64> {
    replica.transact(device, |tx| {
        import_own(tx, device)?;
        next_position(tx, device).map(|(seq, _)| seq)
    })
}

/// A transaction's view and where this device's next records go.
pub(crate) struct Draft {
    pub(crate) view: SharedView,
    seq: u64,
    prev: Option<RecordId>,
}

impl Draft {
    /// Start writing in `tx`: this device's own records taken in, the view computed.
    pub(crate) fn begin(tx: &mut ReplicaTx<'_>, device: &DeviceSecret) -> Result<Self> {
        import_own(tx, device)?;
        let (seq, prev) = next_position(tx, device)?;
        let view = SharedView::compute(tx.vault_id(), &tx.genesis(), &tx.envelopes(), device)?;
        if view.roster().is_read_only() || view.key_ring().is_read_only() {
            return Err(SharedError::Refused(
                "a newer build wrote to this shared vault: update before writing",
            ));
        }
        Ok(Self { view, seq, prev })
    }

    /// Require this device to hold at least `role`.
    pub(crate) fn require(&self, device: &DeviceSecret, role: Role) -> Result<()> {
        match self.view.roster().role_of(&device.id()) {
            Some(held) if held >= role => Ok(()),
            _ if role == Role::Admin => Err(SharedError::Refused(
                "only an admin device may change who is in a shared vault",
            )),
            _ => Err(SharedError::Refused(
                "this device may not write to this shared vault",
            )),
        }
    }

    /// The header of this device's next record.
    pub(crate) fn header(
        &self,
        roster: Vec<RecordId>,
        parents: Vec<RecordId>,
        epoch: Option<EpochId>,
        now: u64,
    ) -> NewRecord {
        NewRecord {
            vault_id: *self.view.vault_id(),
            seq: self.seq,
            prev: self.prev,
            parents,
            roster,
            epoch,
            created_at: now,
        }
    }

    /// The `seq` of this device's next record.
    pub(crate) const fn seq(&self) -> u64 {
        self.seq
    }

    /// Count `envelope` as written, add it to `tx`, and return its id.
    pub(crate) fn wrote(&mut self, tx: &mut ReplicaTx<'_>, envelope: Envelope) -> RecordId {
        let id = envelope.id();
        self.seq += 1;
        self.prev = Some(id);
        tx.add(envelope);
        id
    }

    /// The epoch to write under and its key.
    pub(crate) fn current(&self) -> Result<(EpochId, &EpochKey)> {
        let ring = self.view.key_ring();
        ring.current_epoch()
            .zip(ring.current_key())
            .ok_or(SharedError::Refused(
                "this device holds no key of this shared vault yet",
            ))
    }

    /// The versions of `object` no other version names: at most [`MAX_PARENTS`], the latest.
    fn parents(&self, object: &ObjectId) -> Vec<RecordId> {
        let versions = self.view.versions_of(object);
        let named: BTreeSet<RecordId> = versions
            .iter()
            .flat_map(|v| v.parents().iter().copied())
            .collect();
        let mut heads: Vec<RecordId> = versions
            .iter()
            .rev()
            .map(|v| v.record())
            .filter(|id| !named.contains(id))
            .take(MAX_PARENTS)
            .collect();
        heads.sort();
        heads
    }
}

/// Export `records` of `replica` to its exchange directory, if one is configured.
pub(crate) fn publish(replica: &Replica, records: &[RecordId]) -> Result<()> {
    let Some(dir) = replica.local().exchange_dir.clone() else {
        return Ok(());
    };
    let dir = records_dir(Path::new(&dir));
    for envelope in replica.records().filter(|e| records.contains(&e.id())) {
        crate::exchange::export(&dir, envelope)?;
    }
    Ok(())
}

/// Write one version of `object` (module documentation).
fn write_version(
    replica: &mut Replica,
    device: &DeviceSecret,
    object: ObjectId,
    now: u64,
    seal: impl FnOnce(&DeviceSecret, NewRecord, &EpochKey) -> Result<Envelope>,
    local: impl FnOnce(&mut crate::replica::LocalState),
) -> Result<RecordId> {
    let id = replica.transact(device, |tx| {
        let mut draft = Draft::begin(tx, device)?;
        draft.require(device, Role::Writer)?;
        let (epoch, key) = draft.current()?;
        let header = draft.header(
            draft.view.roster().heads().to_vec(),
            draft.parents(&object),
            Some(epoch),
            now,
        );
        let envelope = seal(device, header, key)?;
        let id = draft.wrote(tx, envelope);
        local(tx.local_mut());
        Ok(id)
    })?;
    publish(replica, &[id])?;
    Ok(id)
}

/// Put `item` into the shared vault as it now is: a new item, or a new version of one. Its
/// agent visibility and favourite flag are kept in this device's local state, not the record.
///
/// # Errors
///
/// [`SharedError::Refused`] if this device is not a writer or an admin, holds no key yet, or
/// the vault was written by a newer build; and as [`Replica::transact`].
pub fn put_item(
    replica: &mut Replica,
    device: &DeviceSecret,
    item: Item,
    now: u64,
) -> Result<RecordId> {
    let id = item.id;
    let visible = item.agent_visible;
    let favorite = item.favorite;
    let fields: BTreeSet<_> = item
        .fields
        .iter()
        .filter(|f| f.agent_visible)
        .map(|f| f.id)
        .collect();
    let version = ItemVersion::put(*replica.vault_id(), item);
    write_version(
        replica,
        device,
        ObjectId::Item(id),
        now,
        |device, header, key| version.seal(device, header, key),
        |local| {
            set(&mut local.agent_visible_items, id, visible);
            set(&mut local.favorites, id, favorite);
            if fields.is_empty() {
                local.agent_visible_fields.remove(&id);
            } else {
                local.agent_visible_fields.insert(id, fields);
            }
        },
    )
}

/// Delete item `id`. A later edit brings it back (decision 80).
///
/// # Errors
///
/// As [`put_item`].
pub fn delete_item(
    replica: &mut Replica,
    device: &DeviceSecret,
    id: ItemId,
    now: u64,
) -> Result<RecordId> {
    let version = ItemVersion::delete(id);
    write_version(
        replica,
        device,
        ObjectId::Item(id),
        now,
        |device, header, key| version.seal(device, header, key),
        |local| {
            local.agent_visible_items.remove(&id);
            local.favorites.remove(&id);
            local.agent_visible_fields.remove(&id);
        },
    )
}

/// Put `env` into the shared vault as it now is. Its agent visibility and default paths are
/// kept in this device's local state, not the record.
///
/// # Errors
///
/// As [`put_item`].
pub fn put_env(
    replica: &mut Replica,
    device: &DeviceSecret,
    env: Environment,
    now: u64,
) -> Result<RecordId> {
    let id = env.id;
    let visible = env.agent_visible;
    let paths = env.default_paths.clone();
    let version = EnvVersion::put(*replica.vault_id(), env);
    write_version(
        replica,
        device,
        ObjectId::Env(id),
        now,
        |device, header, key| version.seal(device, header, key),
        |local| {
            set(&mut local.agent_visible_envs, id, visible);
            if paths.is_empty() {
                local.default_paths.remove(&id);
            } else {
                local.default_paths.insert(id, paths);
            }
        },
    )
}

/// Delete environment `id`.
///
/// # Errors
///
/// As [`put_item`].
pub fn delete_env(
    replica: &mut Replica,
    device: &DeviceSecret,
    id: EnvId,
    now: u64,
) -> Result<RecordId> {
    let version = EnvVersion::delete(id);
    write_version(
        replica,
        device,
        ObjectId::Env(id),
        now,
        |device, header, key| version.seal(device, header, key),
        |local| {
            local.agent_visible_envs.remove(&id);
            local.default_paths.remove(&id);
        },
    )
}

fn set<T: Ord>(set: &mut BTreeSet<T>, value: T, present: bool) {
    if present {
        set.insert(value);
    } else {
        set.remove(&value);
    }
}

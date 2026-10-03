//! Unattended copies of shared values (ADR-0042 §13, Phase 4): the vault's policy on them, and
//! the records that tell every member which device holds one.
//!
//! # Two record kinds
//!
//! * **`policy`** — whether members may copy this vault's values into a machine vault, where jobs
//!   may use them with nobody present. Written by an admin's device only; the latest by its
//!   author's claimed time, then record id, wins; a vault with none allows copies (owner's answer
//!   21). Enforced by honest builds only, and said so: any member can read a value and paste it
//!   anywhere (W-12).
//! * **`unattended_copy`** — "this device holds an unattended copy of environment E's variables
//!   V", or, later, that it no longer does. Written by the device that made or removed the copy,
//!   whatever its role — every role can read, so every role can copy (§13). For each device and
//!   copy, its latest record stands. It proves a copy exists; it cannot prove none does.
//!
//! Both are sealed under the current epoch like items and environments, so only members read
//! them, and a build that does not know them keeps and forwards them as unknown kinds.
//!
//! # Simplified (ADR-0042 implementation decision 35)
//!
//! The policy is an ordinary encrypted record an admin writes, not a roster-level record that
//! makes an older build read-only; the latest claimed time decides between two admins, with no
//! ancestry; and a copy record carries the holder's own description of itself, since device
//! labels are sealed to the roster.

use std::collections::BTreeMap;

use kagisecure_core::proto::EnvId;
use serde::{Deserialize, Serialize};

use crate::cbor::{self, Strictness};
use crate::device::{DeviceKeyId, DeviceSecret};
use crate::error::{Result, SharedError};
use crate::payload::encode;
use crate::record::{Envelope, RecordId, RecordKind, VerifiedRecord};
use crate::replica::Replica;
use crate::roster::Role;
use crate::view::SharedView;
use crate::write::{Draft, publish};

/// The longest description a holder gives of itself, in characters.
pub const MAX_HOLDER_CHARS: usize = 128;

#[derive(Serialize, Deserialize)]
struct PolicyWire {
    copies_allowed: bool,
}

#[derive(Serialize, Deserialize)]
struct CopyWire {
    copy: EnvId,
    source: EnvId,
    name: String,
    variables: Vec<String>,
    holder: String,
    held: bool,
}

/// What a device says about one unattended copy it made or removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyNote {
    /// The copy: the machine vault's environment id.
    pub copy: EnvId,
    /// The shared environment it was copied from.
    pub source: EnvId,
    /// That environment's name when copied.
    pub name: String,
    /// The variable names copied.
    pub variables: Vec<String>,
    /// How the holder describes itself, e.g. "Alice's MacBook".
    pub holder: String,
    /// `true` when the copy was made or updated, `false` when it was removed.
    pub held: bool,
}

/// One copy a device holds, as the latest record about it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldCopy {
    /// The device holding it.
    pub device: DeviceKeyId,
    /// How it describes itself.
    pub holder: String,
    /// Whether that device is still in the roster. A removed device's copy stays on it.
    pub holder_active: bool,
    /// The copy.
    pub copy: EnvId,
    /// The shared environment it came from.
    pub source: EnvId,
    /// That environment's name when copied.
    pub name: String,
    /// The variable names copied.
    pub variables: Vec<String>,
    /// When the holder said it copied it, unix seconds.
    pub at: u64,
}

/// What a shared vault says about unattended copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnattendedState {
    /// Whether members may copy values into a machine vault. `true` unless an admin said no.
    pub copies_allowed: bool,
    /// Every copy some device holds, by holder then copy.
    pub copies: Vec<HeldCopy>,
}

impl UnattendedState {
    /// The copies of shared environment `source`.
    pub fn copies_of<'a>(&'a self, source: &'a EnvId) -> impl Iterator<Item = &'a HeldCopy> {
        self.copies.iter().filter(move |c| c.source == *source)
    }
}

fn decode<T: for<'de> Deserialize<'de>>(record: &VerifiedRecord, view: &SharedView) -> Option<T> {
    let key = record.body().epoch().and_then(|e| view.key_ring().key(e))?;
    let bytes = record.open_payload(key).ok()?;
    cbor::scan(&bytes, Strictness::WellFormed).ok()?;
    ciborium::from_reader(bytes.as_slice()).ok()
}

/// Read the policy and the copies from `view` (module documentation). Records this device cannot
/// read, or whose author held no role for them, are skipped.
#[must_use]
pub fn unattended_state(view: &SharedView) -> UnattendedState {
    let roster = view.roster();
    let snapshot = roster.snapshot();
    let mut policy: Option<((u64, RecordId), bool)> = None;
    let mut latest: BTreeMap<(DeviceKeyId, EnvId), ((u64, RecordId), CopyWire)> = BTreeMap::new();
    for (id, record) in roster.verified_records() {
        let body = record.body();
        let order = (body.created_at(), *id);
        match body.kind() {
            RecordKind::Policy => {
                if roster.authority(id) != Ok(Role::Admin) {
                    continue;
                }
                let Some(wire) = decode::<PolicyWire>(record, view) else {
                    continue;
                };
                if policy.is_none_or(|(at, _)| order > at) {
                    policy = Some((order, wire.copies_allowed));
                }
            }
            RecordKind::Copy => {
                if roster.authority(id).is_err() {
                    continue;
                }
                let Some(wire) = decode::<CopyWire>(record, view) else {
                    continue;
                };
                // One author's own records: its sequence number orders them, so a removal written
                // in the same second as the copy it retracts still wins.
                let key = (record.author(), wire.copy);
                let order = (body.seq(), *id);
                if latest.get(&key).is_none_or(|(at, _)| order > *at) {
                    latest.insert(key, (order, wire));
                }
            }
            _ => {}
        }
    }
    let copies = latest
        .into_iter()
        .filter(|(_, (_, wire))| wire.held)
        .map(|((device, _), ((at, _), wire))| HeldCopy {
            device,
            holder: wire.holder,
            holder_active: snapshot.device(&device).is_some_and(|d| d.active),
            copy: wire.copy,
            source: wire.source,
            name: wire.name,
            variables: wire.variables,
            at,
        })
        .collect();
    UnattendedState {
        copies_allowed: policy.is_none_or(|(_, allowed)| allowed),
        copies,
    }
}

/// Write one record of `kind` carrying `payload`, as this device holding at least `role`.
fn write_note(
    replica: &mut Replica,
    device: &DeviceSecret,
    kind: RecordKind,
    role: Role,
    payload: &[u8],
    now: u64,
) -> Result<RecordId> {
    let id = replica.transact(device, |tx| {
        let mut draft = Draft::begin(tx, device)?;
        draft.require(device, role)?;
        let (epoch, key) = draft.current()?;
        let header = draft.header(
            draft.view.roster().heads().to_vec(),
            Vec::new(),
            Some(epoch),
            now,
        );
        let envelope = Envelope::seal(device, kind, header, key, payload)?;
        Ok(draft.wrote(tx, envelope))
    })?;
    publish(replica, &[id])?;
    Ok(id)
}

/// Allow or forbid unattended copies of this vault's values, as an admin.
///
/// # Errors
///
/// [`SharedError::Refused`] if this device is not an admin, holds no key yet, or the vault was
/// written by a newer build; and as [`Replica::transact`].
pub fn set_copies_allowed(
    replica: &mut Replica,
    device: &DeviceSecret,
    allowed: bool,
    now: u64,
) -> Result<RecordId> {
    let payload = encode(&PolicyWire {
        copies_allowed: allowed,
    })?;
    write_note(
        replica,
        device,
        RecordKind::Policy,
        Role::Admin,
        &payload,
        now,
    )
}

/// Tell every member that this device made, updated or removed an unattended copy.
///
/// # Errors
///
/// [`SharedError::Refused`] if this device is not a member, holds no key yet, or the vault was
/// written by a newer build; [`SharedError::Malformed`] for a holder description over
/// [`MAX_HOLDER_CHARS`]; and as [`Replica::transact`].
pub fn record_copy(
    replica: &mut Replica,
    device: &DeviceSecret,
    note: &CopyNote,
    now: u64,
) -> Result<RecordId> {
    if note.holder.chars().count() > MAX_HOLDER_CHARS {
        return Err(SharedError::Malformed("a holder description is too long"));
    }
    let payload = encode(&CopyWire {
        copy: note.copy,
        source: note.source,
        name: note.name.clone(),
        variables: note.variables.clone(),
        holder: note.holder.clone(),
        held: note.held,
    })?;
    write_note(
        replica,
        device,
        RecordKind::Copy,
        Role::Reader,
        &payload,
        now,
    )
}

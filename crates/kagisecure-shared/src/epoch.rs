//! Epochs: which epoch keys a shared vault has, which of them this device holds, and which one
//! new records are written under (ADR-0035 §3; addendum, "Amendment 2026-09-27: trusted-admin
//! simplification").
//!
//! Three operations ([`EpochOp`]) carry everything about epochs:
//!
//! - **`new`**, in an `epoch` record: a fresh epoch — its id, derived from the record that mints
//!   it; its height; and its key wrapped to each recipient device (HPKE, [`crate::hpke_wrap`]).
//!   One is minted when the vault is created, whenever a device is removed, and on demand.
//! - **`grant`**, in an `epoch` record: an existing epoch's key wrapped to more devices. A device
//!   added to the roster is granted the current key and every older one, so it reads the whole
//!   history.
//! - **`ack`**, in an `ack` record: a device's statement that it adopted an epoch.
//!
//! `new` and `grant` need a writer or an admin, `ack` any member, as of the roster heads the
//! record names ([`RosterState::authority`]). This device holds every key wrapped to it that
//! opens; readers use them all, and a writer writes under the newest epoch it holds (greatest
//! height, then smallest record id). Admins and writers are trusted: a wrap that opens to the
//! wrong key, or a writer racing to mint epochs, is not defended against (threat model).

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use kagisecure_core::proto::VaultId;
use sha2::{Digest, Sha256};

use crate::cbor;
use crate::device::{DeviceKeyId, DevicePublic, DeviceSecret};
use crate::epoch_key::{EpochId, EpochKey, vault_id_bytes};
use crate::error::{Result, SharedError};
use crate::hpke_wrap::{EpochWrap, unwrap_epoch_key, wrap_epoch_key};
use crate::record::{Envelope, NewRecord, RecordId, RecordKind, VerifiedRecord};
use crate::roster::{Ignored, MAX_DEVICES, Refusal, Role, RosterState, Waiting};

const OP_SHAPE: &str = "an epoch operation is a map of the fields its op names";
const DIGEST_DOMAIN: &str = "kagisecure/shared/key-ring/v2";

/// One epoch operation: the payload of an `epoch` or `ack` record.
#[derive(Clone, Debug)]
pub enum EpochOp {
    /// `"new"`: a new epoch.
    New {
        /// Its id: [`EpochId::derive`] of the record that mints it.
        epoch_id: EpochId,
        /// Its height: a new epoch is minted one above every epoch its writer knows.
        height: u64,
        /// The epoch key wrapped to each recipient device, by device id.
        wraps: BTreeMap<DeviceKeyId, EpochWrap>,
    },
    /// `"grant"`: an existing epoch's key wrapped to more devices.
    Grant {
        /// The epoch.
        epoch_id: EpochId,
        /// Its key wrapped to each device, by device id.
        wraps: BTreeMap<DeviceKeyId, EpochWrap>,
    },
    /// `"ack"`: the author adopted the epoch.
    Ack {
        /// The epoch.
        epoch_id: EpochId,
    },
    /// An operation this build does not understand. Kept, never applied; from a writer or an
    /// admin it makes the vault read-only for this build (decision 20).
    Unknown {
        /// The `op` it names.
        op: String,
    },
}

/// Wrap `key`, as epoch `epoch_id` of `vault_id`, to each of `recipients`.
fn wraps_to(
    vault_id: &VaultId,
    epoch_id: &EpochId,
    key: &EpochKey,
    recipients: &[&DevicePublic],
) -> Result<BTreeMap<DeviceKeyId, EpochWrap>> {
    if recipients.is_empty() || recipients.len() > MAX_DEVICES {
        return Err(SharedError::Malformed(
            "an epoch key is wrapped to between 1 and 64 devices",
        ));
    }
    recipients
        .iter()
        .map(|r| Ok((r.id(), wrap_epoch_key(r, vault_id, epoch_id, key)?)))
        .collect()
}

impl EpochOp {
    /// A new epoch `epoch_id` of `vault_id` at `height`, with key `key`, wrapped to `recipients`.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for no recipients or more than [`MAX_DEVICES`];
    /// [`SharedError::Core`] if the generator fails.
    pub fn new_epoch(
        vault_id: &VaultId,
        epoch_id: EpochId,
        height: u64,
        key: &EpochKey,
        recipients: &[&DevicePublic],
    ) -> Result<Self> {
        let wraps = wraps_to(vault_id, &epoch_id, key, recipients)?;
        Ok(Self::New {
            epoch_id,
            height,
            wraps,
        })
    }

    /// A grant of epoch `epoch_id`'s key `key` to `recipients`.
    ///
    /// # Errors
    ///
    /// As [`Self::new_epoch`].
    pub fn grant(
        vault_id: &VaultId,
        epoch_id: EpochId,
        key: &EpochKey,
        recipients: &[&DevicePublic],
    ) -> Result<Self> {
        let wraps = wraps_to(vault_id, &epoch_id, key, recipients)?;
        Ok(Self::Grant { epoch_id, wraps })
    }

    /// An acknowledgement of epoch `epoch_id`.
    #[must_use]
    pub const fn ack(epoch_id: EpochId) -> Self {
        Self::Ack { epoch_id }
    }

    /// The operation's `op` name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::New { .. } => "new",
            Self::Grant { .. } => "grant",
            Self::Ack { .. } => "ack",
            Self::Unknown { op } => op,
        }
    }

    /// The epoch the operation is about.
    #[must_use]
    pub const fn epoch_id(&self) -> Option<EpochId> {
        match self {
            Self::New { epoch_id, .. } | Self::Grant { epoch_id, .. } | Self::Ack { epoch_id } => {
                Some(*epoch_id)
            }
            Self::Unknown { .. } => None,
        }
    }

    /// The kind of record that carries it.
    #[must_use]
    pub const fn kind(&self) -> Option<RecordKind> {
        match self {
            Self::New { .. } | Self::Grant { .. } => Some(RecordKind::Epoch),
            Self::Ack { .. } => Some(RecordKind::Ack),
            Self::Unknown { .. } => None,
        }
    }

    /// The operation as a record's payload: deterministic CBOR.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for [`Self::Unknown`].
    pub fn to_payload(&self) -> Result<Vec<u8>> {
        let wraps = |w: &BTreeMap<DeviceKeyId, EpochWrap>| {
            let entries = w
                .iter()
                .map(|(d, w)| (cbor::bytes(d.as_bytes()), cbor::bytes(&w.to_bytes())));
            cbor::map(entries.collect())
        };
        let mut entries = vec![(cbor::text("op"), cbor::text(self.name()))];
        let (Some(epoch_id), false) = (self.epoch_id(), matches!(self, Self::Unknown { .. }))
        else {
            return Err(SharedError::Malformed(
                "this build writes only epoch operations it knows",
            ));
        };
        entries.push((cbor::text("epoch_id"), cbor::bytes(epoch_id.as_bytes())));
        match self {
            Self::New {
                height, wraps: w, ..
            } => {
                entries.push((cbor::text("height"), Value::Integer((*height).into())));
                entries.push((cbor::text("wraps"), wraps(w)));
            }
            Self::Grant { wraps: w, .. } => entries.push((cbor::text("wraps"), wraps(w))),
            _ => {}
        }
        Ok(cbor::encode(&cbor::map(entries)))
    }

    /// Read an `epoch` or `ack` record's payload. An operation this build does not understand
    /// is [`Self::Unknown`], not an error.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for anything that is not an epoch operation in deterministic
    /// CBOR, or a known one with a missing or ill-shaped field.
    pub fn from_payload(bytes: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(bytes)?;
        let mut fields: BTreeMap<String, Value> =
            cbor::text_map(value, OP_SHAPE)?.into_iter().collect();
        let Some(Value::Text(op)) = fields.remove("op") else {
            return Err(SharedError::Malformed(OP_SHAPE));
        };
        let known: &[&str] = match op.as_str() {
            "new" => &["epoch_id", "height", "wraps"],
            "grant" => &["epoch_id", "wraps"],
            "ack" => &["epoch_id"],
            _ => return Ok(Self::Unknown { op }),
        };
        if fields.keys().any(|key| !known.contains(&key.as_str())) {
            return Ok(Self::Unknown { op });
        }
        let mut take = |key: &str| fields.remove(key).ok_or(SharedError::Malformed(OP_SHAPE));
        let epoch_id = EpochId::from_bytes(cbor::fixed_bytes(&take("epoch_id")?, OP_SHAPE)?);
        let wraps = |value: Value| -> Result<BTreeMap<DeviceKeyId, EpochWrap>> {
            let Value::Map(entries) = value else {
                return Err(SharedError::Malformed(OP_SHAPE));
            };
            if entries.is_empty() || entries.len() > MAX_DEVICES {
                return Err(SharedError::Malformed(OP_SHAPE));
            }
            entries
                .iter()
                .map(|(device, wrap)| {
                    let device = DeviceKeyId::from_bytes(cbor::fixed_bytes(device, OP_SHAPE)?);
                    let Value::Bytes(wrap) = wrap else {
                        return Err(SharedError::Malformed(OP_SHAPE));
                    };
                    Ok((device, EpochWrap::from_bytes(wrap)?))
                })
                .collect()
        };
        Ok(match op.as_str() {
            "new" => {
                let height = cbor::uint(&take("height")?, OP_SHAPE)?;
                Self::New {
                    epoch_id,
                    height,
                    wraps: wraps(take("wraps")?)?,
                }
            }
            "grant" => Self::Grant {
                epoch_id,
                wraps: wraps(take("wraps")?)?,
            },
            _ => Self::Ack { epoch_id },
        })
    }

    /// Read a verified `epoch` or `ack` record's operation.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a record of another kind, or an operation that belongs in
    /// the other kind; and as [`Self::from_payload`].
    pub fn from_record(record: &VerifiedRecord) -> Result<Self> {
        let kind = record.body().kind();
        if kind != &RecordKind::Epoch && kind != &RecordKind::Ack {
            return Err(SharedError::Malformed(
                "not an epoch or acknowledgement record",
            ));
        }
        let op = Self::from_payload(record.body().payload())?;
        match op.kind() {
            Some(expected) if &expected != kind => Err(SharedError::Malformed(
                "an epoch operation in the wrong kind of record",
            )),
            _ => Ok(op),
        }
    }

    /// Write this operation as a record signed by `author`: `record.epoch` names the operation's
    /// epoch — for a `new`, [`EpochId::derive`] of this very record — `record.parents` is empty,
    /// and `record.roster` names the roster heads the author's authority is checked against.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a record that breaks those rules, and as
    /// [`Self::to_payload`] and [`Envelope::sign_plain`].
    pub fn sign(&self, author: &DeviceSecret, record: NewRecord) -> Result<Envelope> {
        let kind = self.check_record(author, &record)?;
        Envelope::sign_plain(author, kind, record, self.to_payload()?)
    }

    /// [`Self::sign`] with a given record salt, for golden vectors. Test builds only.
    #[cfg(test)]
    pub(crate) fn sign_with_salt(
        &self,
        author: &DeviceSecret,
        record: NewRecord,
        record_salt: [u8; crate::epoch_key::RECORD_SALT_LEN],
    ) -> Result<Envelope> {
        let kind = self.check_record(author, &record)?;
        Envelope::sign_plain_with_salt(author, kind, record, self.to_payload()?, record_salt)
    }

    fn check_record(&self, author: &DeviceSecret, record: &NewRecord) -> Result<RecordKind> {
        let (Some(kind), Some(epoch_id)) = (self.kind(), self.epoch_id()) else {
            return Err(SharedError::Malformed(
                "this build writes only epoch operations it knows",
            ));
        };
        let derived = EpochId::derive(&record.vault_id, &author.id(), record.seq);
        if record.epoch != Some(epoch_id)
            || !record.parents.is_empty()
            || record.roster.is_empty()
            || (matches!(self, Self::New { .. }) && epoch_id != derived)
        {
            return Err(SharedError::Malformed(
                "an epoch record names its epoch (derived, for a new one) and roster heads",
            ));
        }
        Ok(kind)
    }
}

/// An accepted epoch.
#[derive(Clone, Debug)]
pub struct EpochInfo {
    /// Its id.
    pub id: EpochId,
    /// The `new` record that minted it.
    pub record: RecordId,
    /// The device that minted it.
    pub author: DeviceKeyId,
    /// Its height.
    pub height: u64,
    /// Every device its key was wrapped to, by its `new` record or a grant.
    pub recipients: BTreeSet<DeviceKeyId>,
    /// The devices that acknowledged it (its minter counts).
    pub acknowledged: BTreeSet<DeviceKeyId>,
}

/// This device's view of a shared vault's epochs. See the module documentation.
pub struct KeyRing {
    vault_id: VaultId,
    device: DeviceKeyId,
    epochs: BTreeMap<EpochId, EpochInfo>,
    keys: BTreeMap<EpochId, EpochKey>,
    current: Option<EpochId>,
    active: BTreeSet<DeviceKeyId>,
    refused: BTreeMap<RecordId, Refusal>,
    read_only: bool,
}

impl KeyRing {
    /// Build `device`'s key ring from the epoch and acknowledgement records `roster` verified.
    #[must_use]
    pub fn build(roster: &RosterState, device: &DeviceSecret) -> Self {
        let vault_id = *roster.vault_id();
        let mut refused: BTreeMap<RecordId, Refusal> = BTreeMap::new();
        let mut read_only = false;
        let mut news = Vec::new();
        let mut others = Vec::new();
        for (id, record) in roster.verified_records() {
            let kind = record.body().kind();
            if kind != &RecordKind::Epoch && kind != &RecordKind::Ack {
                continue;
            }
            let op = match EpochOp::from_record(record) {
                Ok(op)
                    if record.body().epoch() == op.epoch_id().as_ref()
                        || op.epoch_id().is_none() =>
                {
                    op
                }
                _ => {
                    let why = Ignored::Malformed("the epoch operation is malformed");
                    refused.insert(*id, Refusal::Ignored(why));
                    continue;
                }
            };
            let role = match roster.authority(id) {
                Ok(role) => role,
                Err(refusal) => {
                    refused.insert(*id, refusal);
                    continue;
                }
            };
            let needs_writer = !matches!(op, EpochOp::Ack { .. });
            if needs_writer && role < Role::Writer {
                refused.insert(*id, Refusal::Ignored(Ignored::NotWriter));
                continue;
            }
            match op {
                EpochOp::Unknown { .. } => read_only = true,
                EpochOp::New { epoch_id, .. }
                    if epoch_id
                        != EpochId::derive(&vault_id, &record.author(), record.body().seq()) =>
                {
                    let why = Ignored::Invalid("an epoch's id is not the one its record derives");
                    refused.insert(*id, Refusal::Ignored(why));
                }
                EpochOp::New { .. } => news.push((*id, record.author(), op)),
                _ => others.push((*id, record.author(), op)),
            }
        }

        // One epoch per id: an author writing two at one `seq` keeps the smaller record id.
        let mut epochs: BTreeMap<EpochId, EpochInfo> = BTreeMap::new();
        let mut wraps_to_me: Vec<(EpochId, EpochWrap)> = Vec::new();
        for (id, author, op) in news {
            let EpochOp::New {
                epoch_id,
                height,
                wraps,
            } = op
            else {
                continue;
            };
            if epochs.contains_key(&epoch_id) {
                refused.insert(id, Refusal::Ignored(Ignored::Duplicate));
                continue;
            }
            wraps_to_me.extend(wraps.get(&device.id()).map(|w| (epoch_id, *w)));
            let info = EpochInfo {
                id: epoch_id,
                record: id,
                author,
                height,
                recipients: wraps.keys().copied().collect(),
                acknowledged: BTreeSet::from([author]),
            };
            epochs.insert(epoch_id, info);
        }
        for (id, author, op) in others {
            let epoch_id = op.epoch_id().expect("a known operation");
            let Some(info) = epochs.get_mut(&epoch_id) else {
                refused.insert(id, Refusal::Waiting(Waiting::MissingEpoch(epoch_id)));
                continue;
            };
            match op {
                EpochOp::Grant { wraps, .. } => {
                    info.recipients.extend(wraps.keys().copied());
                    wraps_to_me.extend(wraps.get(&device.id()).map(|w| (epoch_id, *w)));
                }
                _ => {
                    info.acknowledged.insert(author);
                }
            }
        }

        let mut keys: BTreeMap<EpochId, EpochKey> = BTreeMap::new();
        for (epoch_id, wrap) in wraps_to_me {
            if !keys.contains_key(&epoch_id)
                && let Ok(key) = unwrap_epoch_key(device, &vault_id, &epoch_id, &wrap)
            {
                keys.insert(epoch_id, key);
            }
        }
        let current = keys
            .keys()
            .map(|id| &epochs[id])
            .max_by(|a, b| a.height.cmp(&b.height).then(b.record.cmp(&a.record)))
            .map(|info| info.id);
        let active = roster
            .snapshot()
            .active_devices()
            .map(|d| d.public.id())
            .collect();
        Self {
            vault_id,
            device: device.id(),
            epochs,
            keys,
            current,
            active,
            refused,
            read_only,
        }
    }

    /// The shared vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// Every accepted epoch, by id.
    #[must_use]
    pub const fn epochs(&self) -> &BTreeMap<EpochId, EpochInfo> {
        &self.epochs
    }

    /// One accepted epoch.
    #[must_use]
    pub fn epoch(&self, id: &EpochId) -> Option<&EpochInfo> {
        self.epochs.get(id)
    }

    /// The epoch this device writes under: the newest one whose key it holds.
    #[must_use]
    pub const fn current_epoch(&self) -> Option<EpochId> {
        self.current
    }

    /// The current epoch's key.
    #[must_use]
    pub fn current_key(&self) -> Option<&EpochKey> {
        self.keys.get(&self.current?)
    }

    /// The key of `epoch`, for reading what was written under it, if this device holds it.
    #[must_use]
    pub fn key(&self, epoch: &EpochId) -> Option<&EpochKey> {
        self.keys.get(epoch)
    }

    /// The epochs whose keys this device holds.
    pub fn held(&self) -> impl Iterator<Item = &EpochId> {
        self.keys.keys()
    }

    /// Whether a new epoch is needed: this device holds none, or the current one was wrapped
    /// to a device no longer in the roster.
    #[must_use]
    pub fn needs_rotation(&self) -> bool {
        self.current
            .and_then(|id| self.epochs.get(&id))
            .is_none_or(|info| info.recipients.iter().any(|d| !self.active.contains(d)))
    }

    /// Devices in the roster with no wrap of `epoch`: a grant of it reaches them.
    #[must_use]
    pub fn missing_wraps(&self, epoch: &EpochId) -> Vec<DeviceKeyId> {
        let recipients = self.epochs.get(epoch).map(|info| &info.recipients);
        self.active
            .iter()
            .filter(|d| recipients.is_none_or(|r| !r.contains(d)))
            .copied()
            .collect()
    }

    /// The height a new epoch takes: one more than every accepted epoch's.
    #[must_use]
    pub fn next_height(&self) -> u64 {
        self.epochs
            .values()
            .map(|i| i.height.saturating_add(1))
            .max()
            .unwrap_or(0)
    }

    /// Epoch and acknowledgement records refused or waiting, with why.
    #[must_use]
    pub const fn refused(&self) -> &BTreeMap<RecordId, Refusal> {
        &self.refused
    }

    /// Whether this build must not write: an epoch operation it does not understand was
    /// written by a writer or an admin (decision 20).
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// A digest of everything this key ring says except the keys themselves. Local.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let epochs = self.epochs.values().map(|i| {
            let devices = |s: &BTreeSet<DeviceKeyId>| {
                Value::Array(s.iter().map(|d| cbor::bytes(d.as_bytes())).collect())
            };
            Value::Array(vec![
                cbor::bytes(i.id.as_bytes()),
                cbor::bytes(i.record.as_bytes()),
                Value::Integer(i.height.into()),
                devices(&i.recipients),
                devices(&i.acknowledged),
            ])
        });
        let refused = self.refused.iter().map(|(r, why)| {
            Value::Array(vec![
                cbor::bytes(r.as_bytes()),
                cbor::text(&format!("{why:?}")),
            ])
        });
        let value = Value::Array(vec![
            cbor::text(DIGEST_DOMAIN),
            cbor::bytes(vault_id_bytes(&self.vault_id)),
            cbor::bytes(self.device.as_bytes()),
            Value::Array(epochs.collect()),
            Value::Array(refused.collect()),
            Value::Array(
                self.keys
                    .keys()
                    .map(|e| cbor::bytes(e.as_bytes()))
                    .collect(),
            ),
            Value::Bool(self.read_only),
        ]);
        Sha256::digest(cbor::encode(&value)).into()
    }
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Epoch ids only: nothing of any key.
        f.debug_struct("KeyRing")
            .field("vault_id", &self.vault_id)
            .field("current", &self.current)
            .field("held", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::roster::tests::{
        Records, add_device, add_member, alice_and_bob, member, remove_device,
    };
    use crate::test_support::{Writer, test_vault};

    /// Write a new epoch as `writer`'s next record, wrapped to `to`; returns its id and key.
    fn mint(
        records: &mut Records,
        to: &[DevicePublic],
        writer: &mut Writer,
        heads: &[RecordId],
        height: u64,
    ) -> (EpochId, EpochKey) {
        let id = EpochId::derive(&test_vault(), &writer.id(), writer.seq());
        let key = EpochKey::generate().unwrap();
        let recipients: Vec<&DevicePublic> = to.iter().collect();
        let op = EpochOp::new_epoch(&test_vault(), id, height, &key, &recipients).unwrap();
        let envelope = op
            .sign(&writer.device, writer.header(heads, Some(id)))
            .unwrap();
        records.push(writer.wrote(envelope));
        (id, key)
    }

    fn write(
        records: &mut Records,
        op: &EpochOp,
        writer: &mut Writer,
        heads: &[RecordId],
    ) -> RecordId {
        let envelope = op
            .sign(&writer.device, writer.header(heads, op.epoch_id()))
            .unwrap();
        records.push(writer.wrote(envelope))
    }

    fn grant(id: EpochId, key: &EpochKey, to: &[DevicePublic]) -> EpochOp {
        let recipients: Vec<&DevicePublic> = to.iter().collect();
        EpochOp::grant(&test_vault(), id, key, &recipients).unwrap()
    }

    fn ring(records: &Records, writer: &Writer) -> KeyRing {
        KeyRing::build(&records.compute(), &writer.device)
    }

    /// Alice creates the vault and its first epoch; Bob joins as a writer and is granted it.
    struct World {
        alice: Writer,
        bob: Writer,
        records: Records,
        e0: EpochId,
        k0: EpochKey,
        head: RecordId,
    }

    fn world() -> World {
        let mut alice = Writer::new(1);
        let bob = Writer::new(2);
        let (mut records, head) = alice_and_bob(&mut alice, &bob, Role::Writer);
        let (e0, k0) = mint(&mut records, &[alice.public()], &mut alice, &[head], 0);
        write(
            &mut records,
            &grant(e0, &k0, &[bob.public()]),
            &mut alice,
            &[head],
        );
        World {
            alice,
            bob,
            records,
            e0,
            k0,
            head,
        }
    }

    #[test]
    fn the_first_epoch_and_a_grant_give_both_devices_the_key() {
        let mut w = world();
        for ring in [ring(&w.records, &w.alice), ring(&w.records, &w.bob)] {
            assert_eq!(ring.current_epoch(), Some(w.e0));
            assert_eq!(ring.current_key().unwrap().as_bytes(), w.k0.as_bytes());
            assert!(!ring.needs_rotation());
            assert!(ring.missing_wraps(&w.e0).is_empty());
            assert!(ring.refused().is_empty());
        }
        let head = w.head;
        write(&mut w.records, &EpochOp::ack(w.e0), &mut w.bob, &[head]);
        let ring = ring(&w.records, &w.alice);
        assert!(
            ring.epoch(&w.e0)
                .unwrap()
                .acknowledged
                .contains(&w.bob.id())
        );
    }

    /// A removal calls for a new epoch; the next one, wrapped without the removed device, is
    /// the current one, and the removed device reads the old epoch but not the new.
    #[test]
    fn a_new_epoch_after_a_removal_leaves_the_removed_device_out() {
        let mut w = world();
        let head = w.head;
        let removal = w
            .records
            .push(w.alice.roster(&remove_device(&w.bob), &[head]));
        assert!(ring(&w.records, &w.alice).needs_rotation());
        let (e1, k1) = mint(
            &mut w.records,
            &[w.alice.public()],
            &mut w.alice,
            &[removal],
            1,
        );
        let alice = ring(&w.records, &w.alice);
        assert_eq!(alice.current_epoch(), Some(e1));
        assert_eq!(alice.current_key().unwrap().as_bytes(), k1.as_bytes());
        assert!(!alice.needs_rotation());
        let bob = ring(&w.records, &w.bob);
        assert!(bob.key(&e1).is_none());
        assert!(bob.key(&w.e0).is_some());
    }

    /// A device added later is granted every older epoch's key, and reads the whole history.
    #[test]
    fn a_device_added_later_is_granted_older_keys() {
        let mut w = world();
        let head = w.head;
        let (e1, k1) = mint(
            &mut w.records,
            &[w.alice.public(), w.bob.public()],
            &mut w.alice,
            &[head],
            1,
        );
        let carol = Writer::new(3);
        let m = w.records.push(
            w.alice
                .roster(&add_member(member(3), Role::Reader), &[head]),
        );
        let head = w
            .records
            .push(w.alice.roster(&add_device(member(3), &carol), &[m]));
        let alice = ring(&w.records, &w.alice);
        assert_eq!(alice.missing_wraps(&w.e0), vec![carol.id()]);
        for (id, key) in [(w.e0, &w.k0), (e1, &k1)] {
            write(
                &mut w.records,
                &grant(id, key, &[carol.public()]),
                &mut w.alice,
                &[head],
            );
        }
        let carol = ring(&w.records, &carol);
        assert_eq!(carol.current_epoch(), Some(e1));
        assert_eq!(carol.key(&w.e0).unwrap().as_bytes(), w.k0.as_bytes());
    }

    #[test]
    fn a_reader_acknowledges_but_neither_mints_nor_grants() {
        let mut w = world();
        let mut carol = Writer::new(3);
        let head = w.head;
        let m = w.records.push(
            w.alice
                .roster(&add_member(member(3), Role::Reader), &[head]),
        );
        let head = w
            .records
            .push(w.alice.roster(&add_device(member(3), &carol), &[m]));
        let (e_carol, _) = mint(&mut w.records, &[carol.public()], &mut carol, &[head], 5);
        let granted = write(
            &mut w.records,
            &grant(w.e0, &w.k0, &[carol.public()]),
            &mut carol,
            &[head],
        );
        write(&mut w.records, &EpochOp::ack(w.e0), &mut carol, &[head]);
        let ring = ring(&w.records, &w.alice);
        assert!(ring.epoch(&e_carol).is_none());
        assert_eq!(
            ring.refused().get(&granted),
            Some(&Refusal::Ignored(Ignored::NotWriter))
        );
        assert!(
            ring.epoch(&w.e0)
                .unwrap()
                .acknowledged
                .contains(&carol.id())
        );
        assert_eq!(ring.current_epoch(), Some(w.e0));
    }

    #[test]
    fn a_new_epochs_id_is_derived_from_its_record() {
        let mut w = world();
        let head = w.head;
        let key = EpochKey::generate().unwrap();
        let bogus =
            EpochOp::new_epoch(&test_vault(), w.e0, 3, &key, &[w.bob.device.public()]).unwrap();
        assert!(
            bogus
                .sign(&w.bob.device, w.bob.header(&[head], Some(w.e0)))
                .is_err()
        );
        let header = w.bob.header(&[head], Some(w.e0));
        let payload = bogus.to_payload().unwrap();
        let written =
            Envelope::sign_plain(&w.bob.device, RecordKind::Epoch, header, payload).unwrap();
        let reused = w.records.push(w.bob.wrote(written));
        let ring = ring(&w.records, &w.alice);
        assert!(matches!(
            ring.refused().get(&reused),
            Some(Refusal::Ignored(Ignored::Invalid(_)))
        ));
        assert_eq!(ring.current_epoch(), Some(w.e0));
    }

    #[test]
    fn operations_round_trip_and_an_unknown_one_from_a_writer_is_read_only() {
        let mut w = world();
        let ops = [
            EpochOp::new_epoch(&test_vault(), w.e0, 0, &w.k0, &[w.alice.device.public()]).unwrap(),
            grant(w.e0, &w.k0, &[w.bob.public()]),
            EpochOp::ack(w.e0),
        ];
        for op in &ops {
            let payload = op.to_payload().unwrap();
            assert_eq!(
                EpochOp::from_payload(&payload)
                    .unwrap()
                    .to_payload()
                    .unwrap(),
                payload
            );
        }
        let payload = cbor::encode(&cbor::map(vec![(cbor::text("op"), cbor::text("retire"))]));
        assert!(matches!(
            EpochOp::from_payload(&payload).unwrap(),
            EpochOp::Unknown { .. }
        ));
        assert!(!ring(&w.records, &w.alice).is_read_only());
        let head = w.head;
        let header = w.bob.header(&[head], None);
        let unknown =
            Envelope::sign_plain(&w.bob.device, RecordKind::Epoch, header, payload).unwrap();
        w.records.push(w.bob.wrote(unknown));
        assert!(ring(&w.records, &w.alice).is_read_only());
    }

    #[test]
    fn debug_renders_no_key_material() {
        let w = world();
        let rendered = format!("{:?}", ring(&w.records, &w.alice));
        let key = crate::device::hex(w.k0.as_bytes());
        assert!(!rendered.contains(&key[..16]), "{rendered}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Any order: the same epochs, the same current one, the same keys held.
        #[test]
        fn the_key_ring_does_not_depend_on_the_order_records_arrive_in(
            keys in proptest::collection::vec(any::<u64>(), 16),
        ) {
            let mut w = world();
            let head = w.head;
            let (_, _) = mint(&mut w.records, &[w.alice.public(), w.bob.public()], &mut w.bob, &[head], 1);
            let expected = ring(&w.records, &w.alice).digest();
            let mut shuffled: Vec<(u64, Envelope)> = w.records.records.iter().enumerate()
                .map(|(i, e)| (keys[i % keys.len()] ^ (i as u64), e.clone()))
                .collect();
            shuffled.sort_by_key(|(key, _)| *key);
            let shuffled: Vec<Envelope> = shuffled.into_iter().map(|(_, e)| e).collect();
            let roster = RosterState::compute(&test_vault(), &w.records.genesis, &shuffled).unwrap();
            prop_assert_eq!(KeyRing::build(&roster, &w.alice.device).digest(), expected);
        }
    }
}

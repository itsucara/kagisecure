//! The view: which item and environment versions one device reads from a shared vault's record
//! set (ADR-0035 §6, §8; addendum, decision 79).
//!
//! # Computed, never stored
//!
//! [`SharedView::compute`] takes every record the replica holds — in any order, repeated or not
//! — and this device's key, and derives everything from them, so every replica that holds the
//! same records and the same keys reaches the same view ([`SharedView::state_digest`]).
//!
//! # When a version is accepted
//!
//! An item or environment record is accepted when
//!
//! 1. its signature verifies and its author is a device the roster has added (a record whose
//!    author is not known yet is simply not read until it is);
//! 2. its author holds a writer's or an admin's role at the roster heads the record names
//!    ([`RosterState::authority`], the trusted-admin amendment) — so a removed device's records
//!    are ignored from its removal on, and a record naming a head this replica lacks waits; and
//! 3. this device holds its epoch's key, and the payload decrypts and reads as one version.
//!
//! Nothing else is checked: parents that have not arrived and the author's own chain do not
//! hold a version back (decision 79). What the roster and the key ring say is read through one
//! small adapter, [`Access`], so the view follows a change to either by changing only it.
//!
//! How the accepted versions of one item or environment combine into what a person sees is
//! [`crate::merge`].

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use kagisecure_core::proto::{EnvId, ItemId, VaultId};
use sha2::{Digest, Sha256};

use crate::cbor;
use crate::device::{DeviceKeyId, DeviceSecret};
use crate::epoch::KeyRing;
use crate::epoch_key::{EpochId, EpochKey, vault_id_bytes};
use crate::error::Result;
use crate::payload::{EnvVersion, ItemVersion};
use crate::record::{Envelope, RecordId, RecordKind, VerifiedRecord};
use crate::roster::{Refusal, Role, RosterState};

const DIGEST_DOMAIN: &str = "kagisecure/shared/view-state/v1";

/// An item or an environment: what a set of versions is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectId {
    /// An item.
    Item(ItemId),
    /// An environment.
    Env(EnvId),
}

impl ObjectId {
    fn value(&self) -> Value {
        match self {
            Self::Item(id) => Value::Array(vec![cbor::text("item"), cbor::bytes(id.0.as_bytes())]),
            Self::Env(id) => Value::Array(vec![cbor::text("env"), cbor::bytes(id.0.as_bytes())]),
        }
    }
}

/// One decrypted version.
pub enum Version {
    /// An item's.
    Item(ItemVersion),
    /// An environment's.
    Env(EnvVersion),
}

impl Version {
    /// What it is a version of.
    #[must_use]
    pub const fn object(&self) -> ObjectId {
        match self {
            Self::Item(v) => ObjectId::Item(v.id()),
            Self::Env(v) => ObjectId::Env(v.id()),
        }
    }

    /// Whether it deletes its item or environment.
    #[must_use]
    pub const fn is_deletion(&self) -> bool {
        match self {
            Self::Item(v) => v.item().is_none(),
            Self::Env(v) => v.env().is_none(),
        }
    }
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // What it is of, never what it holds.
        f.debug_struct("Version")
            .field("object", &self.object())
            .field("deletion", &self.is_deletion())
            .finish_non_exhaustive()
    }
}

/// An accepted version: what it holds, and what the merge orders it by.
#[derive(Debug)]
pub struct Accepted {
    record: RecordId,
    author: DeviceKeyId,
    created_at: u64,
    parents: Vec<RecordId>,
    version: Version,
}

impl Accepted {
    /// The record.
    #[must_use]
    pub const fn record(&self) -> RecordId {
        self.record
    }

    /// The device that wrote it.
    #[must_use]
    pub const fn author(&self) -> DeviceKeyId {
        self.author
    }

    /// When its author says it was written, in unix seconds.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The versions it names as the ones it edits.
    #[must_use]
    pub fn parents(&self) -> &[RecordId] {
        &self.parents
    }

    /// What it holds.
    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }

    /// How it is ordered against a concurrent version — one neither descends from — in
    /// last-writer-wins order: its author's time, then its id (decision 80; [`crate::merge`]).
    #[must_use]
    pub const fn order_key(&self) -> (u64, RecordId) {
        (self.created_at, self.record)
    }
}

/// Why an item or environment record is not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// Its author's device was removed before it wrote it.
    AfterRemoval,
    /// Its author is not a device the roster added.
    NotADevice,
    /// Its author is a reader at the roster heads it names.
    NotWriter,
    /// It names a roster head this replica does not have yet: it is read once that arrives.
    Waiting,
    /// This device holds no key for its epoch, or the payload does not decrypt or read as a
    /// version.
    Unreadable,
}

impl Ignored {
    const fn name(self) -> &'static str {
        match self {
            Self::AfterRemoval => "after-removal",
            Self::NotADevice => "not-a-device",
            Self::NotWriter => "not-writer",
            Self::Waiting => "waiting",
            Self::Unreadable => "unreadable",
        }
    }
}

/// Whether a record's author may have written it, as the roster says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A writer's or an admin's device at the roster heads the record names.
    Member,
    /// A device the roster never added, or had not added yet at those heads.
    NotADevice,
    /// A device the roster removed at or before those heads.
    AfterRemoval,
    /// A reader's device at those heads.
    NotWriter,
    /// A roster head the record names is not here yet.
    Waiting,
}

/// Everything the view reads from the roster and the key ring, in one place (decision 79): a
/// simpler roster replaces the current one by changing only this.
pub struct Access<'a> {
    roster: &'a RosterState,
    ring: &'a KeyRing,
}

impl<'a> Access<'a> {
    /// Read `roster` and `ring`.
    #[must_use]
    pub const fn new(roster: &'a RosterState, ring: &'a KeyRing) -> Self {
        Self { roster, ring }
    }

    /// Every record whose signature verified, by id.
    #[must_use]
    pub const fn verified(&self) -> &'a BTreeMap<RecordId, VerifiedRecord> {
        self.roster.verified_records()
    }

    /// Whether `record`'s author may have written it: its role at the roster heads it names
    /// ([`RosterState::authority`], the trusted-admin amendment). A device removed at or before
    /// those heads holds no role there, so its records are ignored from its removal on.
    #[must_use]
    pub fn standing(&self, record: &VerifiedRecord) -> Standing {
        match self.roster.authority(&record.id()) {
            Ok(role) if role >= Role::Writer => Standing::Member,
            Ok(_) => Standing::NotWriter,
            Err(Refusal::Waiting(_)) => Standing::Waiting,
            Err(Refusal::Ignored(_)) => {
                let known = self.roster.snapshot().device(&record.author());
                if known.is_some_and(|device| !device.active) {
                    Standing::AfterRemoval
                } else {
                    Standing::NotADevice
                }
            }
        }
    }

    /// The key of `epoch`, if this device holds it.
    #[must_use]
    pub fn key(&self, epoch: &EpochId) -> Option<&'a EpochKey> {
        self.ring.key(epoch)
    }
}

/// One device's view of a shared vault. See the module documentation.
pub struct SharedView {
    roster: RosterState,
    ring: KeyRing,
    accepted: BTreeMap<RecordId, Accepted>,
    ignored: BTreeMap<RecordId, Ignored>,
    objects: BTreeMap<ObjectId, BTreeSet<RecordId>>,
}

impl SharedView {
    /// Compute `device`'s view of shared vault `vault_id`, whose genesis is `genesis` (from the
    /// replica's header or a verified invitation), from `records`: every record the replica
    /// holds, of any kind, in any order.
    ///
    /// # Errors
    ///
    /// As [`RosterState::compute`]: the genesis missing or invalid. Nothing about any other
    /// record is an error.
    pub fn compute(
        vault_id: &VaultId,
        genesis: &RecordId,
        records: &[Envelope],
        device: &DeviceSecret,
    ) -> Result<Self> {
        let roster = RosterState::compute(vault_id, genesis, records)?;
        let ring = KeyRing::build(&roster, device);
        let access = Access::new(&roster, &ring);
        let mut accepted = BTreeMap::new();
        let mut ignored = BTreeMap::new();
        let mut objects: BTreeMap<ObjectId, BTreeSet<RecordId>> = BTreeMap::new();
        for (id, record) in access.verified() {
            let body = record.body();
            if !matches!(body.kind(), RecordKind::Item | RecordKind::Env) {
                continue;
            }
            match access.standing(record) {
                Standing::Member => {}
                Standing::NotADevice => {
                    ignored.insert(*id, Ignored::NotADevice);
                    continue;
                }
                Standing::AfterRemoval => {
                    ignored.insert(*id, Ignored::AfterRemoval);
                    continue;
                }
                Standing::NotWriter => {
                    ignored.insert(*id, Ignored::NotWriter);
                    continue;
                }
                Standing::Waiting => {
                    ignored.insert(*id, Ignored::Waiting);
                    continue;
                }
            }
            let Some(key) = body.epoch().and_then(|epoch| access.key(epoch)) else {
                ignored.insert(*id, Ignored::Unreadable);
                continue;
            };
            let opened = match body.kind() {
                RecordKind::Item => ItemVersion::open(record, key).map(Version::Item),
                _ => EnvVersion::open(record, key).map(Version::Env),
            };
            let Ok(version) = opened else {
                ignored.insert(*id, Ignored::Unreadable);
                continue;
            };
            objects.entry(version.object()).or_default().insert(*id);
            accepted.insert(
                *id,
                Accepted {
                    record: *id,
                    author: record.author(),
                    created_at: body.created_at(),
                    parents: body.parents().to_vec(),
                    version,
                },
            );
        }
        Ok(Self {
            roster,
            ring,
            accepted,
            ignored,
            objects,
        })
    }

    /// The shared vault.
    #[must_use]
    pub fn vault_id(&self) -> &VaultId {
        self.roster.vault_id()
    }

    /// The roster.
    #[must_use]
    pub const fn roster(&self) -> &RosterState {
        &self.roster
    }

    /// This device's key ring.
    #[must_use]
    pub const fn key_ring(&self) -> &KeyRing {
        &self.ring
    }

    /// Every accepted version, by record id.
    #[must_use]
    pub const fn accepted(&self) -> &BTreeMap<RecordId, Accepted> {
        &self.accepted
    }

    /// One accepted version.
    #[must_use]
    pub fn version(&self, record: &RecordId) -> Option<&Accepted> {
        self.accepted.get(record)
    }

    /// Item and environment records not read, with why.
    #[must_use]
    pub const fn ignored(&self) -> &BTreeMap<RecordId, Ignored> {
        &self.ignored
    }

    /// Every item and environment with an accepted version, and its versions' records.
    #[must_use]
    pub const fn objects(&self) -> &BTreeMap<ObjectId, BTreeSet<RecordId>> {
        &self.objects
    }

    /// The accepted versions of one item or environment, in [`Accepted::order_key`] order.
    #[must_use]
    pub fn versions_of(&self, object: &ObjectId) -> Vec<&Accepted> {
        let mut versions: Vec<&Accepted> = self
            .objects
            .get(object)
            .into_iter()
            .flatten()
            .filter_map(|id| self.accepted.get(id))
            .collect();
        versions.sort_by_key(|v| v.order_key());
        versions
    }

    /// A digest of what this view decides — the roster, which versions are accepted and of
    /// what, which are ignored and why — for comparing two computations. The same record set
    /// gives the same digest in any order and with any repetition, and two devices holding the
    /// same keys get the same one. Local: never written anywhere.
    #[must_use]
    pub fn state_digest(&self) -> [u8; 32] {
        let id = |id: &RecordId| cbor::bytes(id.as_bytes());
        let accepted = self
            .accepted
            .values()
            .map(|a| {
                Value::Array(vec![
                    id(&a.record),
                    a.version.object().value(),
                    Value::Bool(a.version.is_deletion()),
                ])
            })
            .collect();
        let ignored = self
            .ignored
            .iter()
            .map(|(record, why)| Value::Array(vec![id(record), cbor::text(why.name())]))
            .collect();
        let value = Value::Array(vec![
            cbor::text(DIGEST_DOMAIN),
            cbor::bytes(vault_id_bytes(self.roster.vault_id())),
            cbor::bytes(&self.roster.digest()),
            Value::Array(accepted),
            Value::Array(ignored),
        ]);
        Sha256::digest(cbor::encode(&value)).into()
    }
}

impl std::fmt::Debug for SharedView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts and ids only: nothing any version holds.
        f.debug_struct("SharedView")
            .field("vault_id", self.roster.vault_id())
            .field("accepted", &self.accepted.len())
            .field("ignored", &self.ignored.len())
            .field("objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::epoch::EpochOp;
    use crate::roster::tests::{Records, add_device, add_member, member};
    use crate::roster::{RemovalReason, Role, RosterOp};
    use crate::test_support::{Writer, test_vault};
    use kagisecure_core::model::{Field, Item};
    use kagisecure_core::proto::{Category, FieldId};
    use proptest::prelude::*;

    /// Alice (admin) and Bob and Carol (writers), each on one device, with the creation epoch
    /// granted to all of them.
    pub(crate) struct World {
        pub(crate) alice: Writer,
        pub(crate) bob: Writer,
        pub(crate) carol: Writer,
        pub(crate) records: Records,
        pub(crate) k0: EpochKey,
        pub(crate) e0: EpochId,
        /// The roster head once everyone was added.
        pub(crate) head: RecordId,
    }

    fn mint(writer: &mut Writer, heads: &[RecordId], op: &EpochOp) -> Envelope {
        let envelope = op
            .sign(&writer.device, writer.header(heads, op.epoch_id()))
            .unwrap();
        writer.wrote(envelope)
    }

    pub(crate) fn world() -> World {
        let mut alice = Writer::new(1);
        let bob = Writer::new(2);
        let carol = Writer::new(3);
        let mut records = Records::create(&mut alice, member(1));
        let g = records.genesis;
        let k0 = EpochKey::generate().unwrap();
        let e0 = EpochId::derive(&test_vault(), &alice.id(), alice.seq());
        let op = EpochOp::new_epoch(&test_vault(), e0, 0, &k0, &[alice.device.public()]).unwrap();
        records.push(mint(&mut alice, &[g], &op));
        let mut head = g;
        for (n, who) in [(2, &bob), (3, &carol)] {
            head = records.push(alice.roster(&add_member(member(n), Role::Writer), &[head]));
            head = records.push(alice.roster(&add_device(member(n), who), &[head]));
        }
        let grant = EpochOp::grant(
            &test_vault(),
            e0,
            &k0,
            &[bob.device.public(), carol.device.public()],
        )
        .unwrap();
        records.push(mint(&mut alice, &[head], &grant));
        World {
            alice,
            bob,
            carol,
            records,
            k0,
            e0,
            head,
        }
    }

    /// A login item `id` with a fixed timestamp and the given fields.
    pub(crate) fn item(id: ItemId, title: &str, fields: &[(FieldId, &str, &str)]) -> Item {
        let mut item = Item::new(test_vault(), Category::Login, title);
        item.id = id;
        item.created_at = 1_790_000_000;
        item.updated_at = 1_790_000_000;
        for (field, label, value) in fields {
            let mut f = Field::public(*label, *value);
            f.id = *field;
            item.fields.push(f);
        }
        item
    }

    /// `writer` writes `version` at time `at`, naming `parents`.
    pub(crate) fn write(
        w: &mut World,
        who: u8,
        at: u64,
        parents: &[RecordId],
        version: &ItemVersion,
    ) -> RecordId {
        let (head, e0) = (w.head, w.e0);
        let writer = match who {
            1 => &mut w.alice,
            2 => &mut w.bob,
            _ => &mut w.carol,
        };
        let mut header = writer.header(&[head], Some(e0));
        header.parents = parents.to_vec();
        header.created_at = at;
        let envelope = version.seal(&writer.device, header, &w.k0).unwrap();
        let envelope = writer.wrote(envelope);
        w.records.push(envelope)
    }

    pub(crate) fn put(item: Item) -> ItemVersion {
        ItemVersion::put(test_vault(), item)
    }

    pub(crate) fn view(records: &Records, device: &Writer) -> SharedView {
        SharedView::compute(
            &test_vault(),
            &records.genesis,
            &records.records,
            &device.device,
        )
        .unwrap()
    }

    /// Shuffle `records`, deterministically from `seed`, repeating those `repeats` picks.
    pub(crate) fn shuffled(
        records: &[Envelope],
        seed: u64,
        repeats: &[prop::sample::Index],
    ) -> Vec<Envelope> {
        let mut out = records.to_vec();
        for index in repeats {
            out.push(index.get(records).clone());
        }
        let mut state = seed | 1;
        for i in (1..out.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let j = usize::try_from(state % (i as u64 + 1)).unwrap();
            out.swap(i, j);
        }
        out
    }

    #[test]
    fn a_members_version_is_accepted() {
        let mut w = world();
        let id = ItemId::new();
        let v1 = write(&mut w, 2, 10, &[], &put(item(id, "a", &[])));
        let v = view(&w.records, &w.alice);
        assert_eq!(v.versions_of(&ObjectId::Item(id)).len(), 1);
        let Version::Item(read) = v.version(&v1).unwrap().version() else {
            panic!("an item version")
        };
        assert_eq!(read.item().unwrap().title, "a");
        assert!(v.ignored().is_empty());
    }

    #[test]
    fn a_removed_devices_versions_after_its_removal_are_ignored() {
        let mut w = world();
        let before = write(&mut w, 3, 10, &[], &put(item(ItemId::new(), "a", &[])));
        let head = w.head;
        w.head = w.records.push(w.alice.roster(
            &RosterOp::RemoveMember {
                member: member(3),
                reason: RemovalReason::Left,
            },
            &[head],
        ));
        let after = write(&mut w, 3, 20, &[], &put(item(ItemId::new(), "b", &[])));
        // Naming heads from before the removal is still read: the trusted-admin model's limit.
        w.head = head;
        let backdated = write(&mut w, 3, 30, &[], &put(item(ItemId::new(), "c", &[])));
        let v = view(&w.records, &w.alice);
        assert!(v.version(&before).is_some());
        assert_eq!(v.ignored().get(&after), Some(&Ignored::AfterRemoval));
        assert!(v.version(&backdated).is_some());
    }

    #[test]
    fn a_version_from_a_device_the_roster_never_added_is_not_read() {
        let mut w = world();
        let mut stranger = Writer::new(9);
        let mut header = stranger.header(&[w.head], Some(w.e0));
        header.created_at = 5;
        let envelope = put(item(ItemId::new(), "?", &[]))
            .seal(&stranger.device, header, &w.k0)
            .unwrap();
        let id = w.records.push(stranger.wrote(envelope));
        let v = view(&w.records, &w.alice);
        assert!(v.version(&id).is_none());
        assert!(v.accepted().is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Any order, any repetition, and either device holding the keys: the same view.
        #[test]
        fn the_view_converges_whatever_the_order(
            seed in any::<u64>(),
            repeats in proptest::collection::vec(any::<prop::sample::Index>(), 0..6),
        ) {
            let mut w = world();
            let (a, b) = (ItemId::new(), ItemId::new());
            let a1 = write(&mut w, 2, 10, &[], &put(item(a, "a", &[])));
            write(&mut w, 3, 11, &[a1], &put(item(a, "a2", &[])));
            write(&mut w, 1, 11, &[a1], &ItemVersion::delete(a));
            write(&mut w, 3, 9, &[], &put(item(b, "b", &[])));
            let expected = view(&w.records, &w.alice).state_digest();
            let records = shuffled(&w.records.records, seed, &repeats);
            for device in [&w.alice, &w.bob] {
                let got = SharedView::compute(
                    &test_vault(), &w.records.genesis, &records, &device.device,
                ).unwrap();
                prop_assert_eq!(got.state_digest(), expected);
            }
        }
    }
}

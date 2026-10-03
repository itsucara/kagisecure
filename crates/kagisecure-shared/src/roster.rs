//! The roster: who is in a shared vault, with which role, on which devices (ADR-0035 §2, §6;
//! addendum, "Amendment 2026-09-27: trusted-admin simplification").
//!
//! # Records, not a table
//!
//! Membership is never stored. It is computed, every time, from the signed roster records in
//! the record set — [`RosterState::compute`] — so that every replica holding the same records
//! reaches the same roster, whatever order they arrived in.
//!
//! # How the state is computed
//!
//! 1. The genesis is the record the caller names — from the replica's own header or a verified
//!    invitation, never whichever record looks like one. Its key is read from its own body,
//!    bound to its author by the device key id, and its signature then checked.
//! 2. Every record whose author's key is known — from the genesis, then from every device a
//!    verified roster record adds — is verified as a record of this vault.
//! 3. Roster records are put in one order: a topological sort over the roster heads each names
//!    (and its author's previous record, when that is a roster record), the genesis first, ties
//!    by smallest record id. A record whose heads are missing waits. When one device wrote two
//!    roster records at one `seq`, the one with the smaller record id is kept and the other
//!    ignored. At most [`MAX_ROSTER_RECORDS`] are considered.
//! 4. The records are applied in that order. Each needs its author to be an active device of an
//!    admin member in the state reached so far, and its operation to make sense there;
//!    otherwise it is **ignored** — kept and forwarded, never applied.
//!
//! That is the whole model: **admins are trusted.** A removed device's records are ignored from
//! its removal on in the order; what was applied before stays. There are no cuts, no voiding of
//! earlier records and no special handling of concurrent removals. The threat model lists what
//! this leaves open (a malicious admin can take the vault over; a removed device's records
//! written concurrently with its removal may still apply; equivocation is not reported).
//!
//! Any other record — an item, an environment, an epoch, an acknowledgement — takes its
//! author's role from the state after the latest of the roster heads it names
//! ([`RosterState::authority`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ciborium::Value;
use kagisecure_core::proto::VaultId;
use sha2::{Digest, Sha256};

use crate::cbor;
use crate::device::{DeviceKeyId, DevicePublic};
use crate::epoch_key::vault_id_bytes;
use crate::error::{Result, SharedError};
use crate::record::{Envelope, RecordId, RecordKind, VerifiedRecord};
pub use crate::roster_op::{
    MAX_LABELS_BYTES, MEMBER_ID_LEN, MemberId, RemovalReason, Role, RosterOp, Verification,
};
use crate::suite::Suite;

/// The most members a shared vault has at once.
pub const MAX_MEMBERS: usize = 32;
/// The most devices a shared vault has at once.
pub const MAX_DEVICES: usize = 64;
/// The most roster records a vault's roster considers, in its order; later ones are ignored.
pub const MAX_ROSTER_RECORDS: usize = 4096;

const DIGEST_DOMAIN: &str = "kagisecure/shared/roster-state/v2";

/// A member, as the roster has them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberState {
    /// Their id.
    pub id: MemberId,
    /// Their role (their last one, if removed).
    pub role: Role,
    /// Whether they are still a member.
    pub active: bool,
    /// Sealed labels, as the record that added them carries them.
    pub labels: Option<Vec<u8>>,
}

/// A device, as the roster has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceState {
    /// Its public keys.
    pub public: DevicePublic,
    /// Whose device it is.
    pub member: MemberId,
    /// How its fingerprint was checked; `None` for the creator's device.
    pub verified: Option<Verification>,
    /// Whether it is still in the roster (it and its member).
    pub active: bool,
    /// Sealed labels, as the record that added it carries them.
    pub labels: Option<Vec<u8>>,
}

/// The members and devices at one point of the order. Removed ones stay, marked inactive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RosterSnapshot {
    members: BTreeMap<MemberId, MemberState>,
    devices: BTreeMap<DeviceKeyId, DeviceState>,
}

impl RosterSnapshot {
    /// A member, active or not.
    #[must_use]
    pub fn member(&self, id: &MemberId) -> Option<&MemberState> {
        self.members.get(id)
    }

    /// Every member ever added, in id order.
    pub fn members(&self) -> impl Iterator<Item = &MemberState> {
        self.members.values()
    }

    /// A device, active or not.
    #[must_use]
    pub fn device(&self, id: &DeviceKeyId) -> Option<&DeviceState> {
        self.devices.get(id)
    }

    /// The devices in the roster now, in id order.
    pub fn active_devices(&self) -> impl Iterator<Item = &DeviceState> {
        self.devices.values().filter(|d| d.active)
    }

    /// The role an active device holds, or `None` if it is not in the roster.
    #[must_use]
    pub fn role_of(&self, device: &DeviceKeyId) -> Option<Role> {
        let device = self.devices.get(device).filter(|d| d.active)?;
        self.members
            .get(&device.member)
            .filter(|m| m.active)
            .map(|m| m.role)
    }

    /// How many active members are admins with at least one active device.
    #[must_use]
    pub fn admin_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.active && m.role == Role::Admin)
            .filter(|m| self.devices.values().any(|d| d.active && d.member == m.id))
            .count()
    }

    fn active_member(&self, id: &MemberId) -> Option<&MemberState> {
        self.members.get(id).filter(|m| m.active)
    }

    /// Apply `op` to this state, or say why it does not apply.
    fn apply(&mut self, suite: Suite, op: &RosterOp) -> std::result::Result<(), Ignored> {
        match op {
            RosterOp::Genesis { .. } => return Err(Ignored::SecondGenesis),
            RosterOp::Unknown { .. } => {}
            RosterOp::AddMember {
                member,
                role,
                labels,
            } => {
                if self.members.contains_key(member) {
                    return Err(Ignored::Invalid("the member id is already in use"));
                }
                if self.members.values().filter(|m| m.active).count() >= MAX_MEMBERS {
                    return Err(Ignored::Invalid("too many members"));
                }
                let state = MemberState {
                    id: *member,
                    role: *role,
                    active: true,
                    labels: labels.clone(),
                };
                self.members.insert(*member, state);
            }
            RosterOp::AddDevice {
                member,
                device,
                verified,
                labels,
            } => {
                if self.active_member(member).is_none() {
                    return Err(Ignored::Invalid("the member is not in the roster"));
                }
                if device.suite() != suite {
                    return Err(Ignored::Invalid("the device is of another suite"));
                }
                if self.devices.values().any(|d| {
                    d.public.id() == device.id()
                        || d.public.kem_pk() == device.kem_pk()
                        || d.public.sig_pk() == device.sig_pk()
                }) {
                    return Err(Ignored::Invalid(
                        "the device is, or shares a key with, one already added",
                    ));
                }
                if self.active_devices().count() >= MAX_DEVICES {
                    return Err(Ignored::Invalid("too many devices"));
                }
                let state = DeviceState {
                    public: device.clone(),
                    member: *member,
                    verified: Some(*verified),
                    active: true,
                    labels: labels.clone(),
                };
                self.devices.insert(device.id(), state);
            }
            RosterOp::RemoveDevice { device, .. } => {
                let state = self.devices.get_mut(device).filter(|d| d.active);
                state
                    .ok_or(Ignored::Invalid("the device is not in the roster"))?
                    .active = false;
            }
            RosterOp::RemoveMember { member, .. } => {
                let state = self.members.get_mut(member).filter(|m| m.active);
                state
                    .ok_or(Ignored::Invalid("the member is not in the roster"))?
                    .active = false;
                for device in self.devices.values_mut().filter(|d| d.member == *member) {
                    device.active = false;
                }
            }
            RosterOp::SetRole { member, role } => {
                let state = self.members.get_mut(member).filter(|m| m.active);
                let state = state.ok_or(Ignored::Invalid("the member is not in the roster"))?;
                if state.role == *role {
                    return Err(Ignored::Invalid("the member already has that role"));
                }
                state.role = *role;
            }
        }
        Ok(())
    }
}

/// Why a record is ignored: kept and forwarded, never applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ignored {
    /// Its signature does not verify for the device it names.
    BadSignature,
    /// It is not what the format says it is.
    Malformed(&'static str),
    /// It belongs to another shared vault.
    WrongVault,
    /// A genesis other than the vault's.
    SecondGenesis,
    /// Its author wrote another roster record at the same `seq`, with a smaller record id.
    Duplicate,
    /// Its author is not an active device at that point.
    NotADevice,
    /// It changes the roster, and its author is not an admin at that point.
    NotAdmin,
    /// It needs a writer, and its author is a reader.
    NotWriter,
    /// Its operation does not make sense at that point.
    Invalid(&'static str),
    /// It lies past [`MAX_ROSTER_RECORDS`] in the order.
    LimitExceeded,
}

/// Why a record waits: kept, and reconsidered when the record set changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Waiting {
    /// No record in the set introduces its author.
    UnknownAuthor,
    /// It names a roster head that is not (yet) a roster record here.
    MissingHead(RecordId),
    /// Its body version is one this build does not read.
    Unreadable,
    /// It names an epoch no record in the set introduces.
    MissingEpoch(crate::epoch_key::EpochId),
}

/// Something about the roster a person should be told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterWarning {
    /// Fewer than two admins (members with an active device) are left: losing that one would
    /// freeze the roster. Add another admin.
    FewAdmins,
    /// No admin is left: the roster is frozen. No one can be added, removed or given another
    /// role; members keep their roles, and a vault that must change is re-created.
    Frozen,
}

/// A shared vault's roster, computed from its record set. See the module documentation.
pub struct RosterState {
    vault_id: VaultId,
    genesis: RecordId,
    snapshot: RosterSnapshot,
    order: Vec<RecordId>,
    position: BTreeMap<RecordId, usize>,
    /// Each device's standing through the order: `(position, role or None)`, in order.
    history: BTreeMap<DeviceKeyId, Vec<(usize, Option<Role>)>>,
    heads: Vec<RecordId>,
    ignored: BTreeMap<RecordId, Ignored>,
    waiting: BTreeMap<RecordId, Waiting>,
    read_only: bool,
    verified: BTreeMap<RecordId, VerifiedRecord>,
}

/// Check the record named as the genesis, and return it verified with its operation.
fn verify_genesis(vault_id: &VaultId, envelope: &Envelope) -> Result<(VerifiedRecord, RosterOp)> {
    let invalid = SharedError::InvalidGenesis;
    let body = envelope
        .body_unverified()
        .map_err(|_| invalid("its body cannot be read"))?;
    let op = RosterOp::from_payload(body.payload())
        .map_err(|_| invalid("its operation is malformed"))?;
    let RosterOp::Genesis { suite, device, .. } = &op else {
        return Err(invalid("it is not a genesis"));
    };
    if body.kind() != &RecordKind::Roster
        || device.id() != envelope.author()
        || device.suite() != *suite
    {
        return Err(invalid(
            "it is not a genesis signed by the device it introduces",
        ));
    }
    let record = envelope.verify(device, vault_id).map_err(|e| match e {
        SharedError::WrongVault => invalid("it belongs to another shared vault"),
        _ => invalid("its signature does not verify"),
    })?;
    let body = record.body();
    if body.seq() != 0 || !body.parents().is_empty() || !body.roster().is_empty() {
        return Err(invalid(
            "it names a previous record, parents or roster heads",
        ));
    }
    Ok((record, op))
}

impl RosterState {
    /// Compute the roster of shared vault `vault_id`, whose genesis is `genesis`, from
    /// `records` — every record of the vault this replica holds, of any kind, in any order,
    /// repeated or not. `genesis` comes from the replica's own header or a verified invitation.
    ///
    /// # Errors
    ///
    /// [`SharedError::GenesisMissing`] if `genesis` is not among `records`, and
    /// [`SharedError::InvalidGenesis`] if it is not a valid genesis of `vault_id`.
    pub fn compute(vault_id: &VaultId, genesis: &RecordId, records: &[Envelope]) -> Result<Self> {
        let envelopes: BTreeMap<RecordId, &Envelope> =
            records.iter().map(|e| (e.id(), e)).collect();
        let genesis_envelope = envelopes.get(genesis).ok_or(SharedError::GenesisMissing)?;
        let (genesis_record, genesis_op) = verify_genesis(vault_id, genesis_envelope)?;
        let RosterOp::Genesis {
            suite,
            device: creator,
            ..
        } = &genesis_op
        else {
            unreachable!("checked by verify_genesis");
        };
        let suite = *suite;

        // Verify every record whose author becomes known, learning devices as roster records
        // add them.
        let mut ignored: BTreeMap<RecordId, Ignored> = BTreeMap::new();
        let mut waiting: BTreeMap<RecordId, Waiting> = BTreeMap::new();
        let mut verified: BTreeMap<RecordId, VerifiedRecord> = BTreeMap::new();
        let mut ops: BTreeMap<RecordId, RosterOp> = BTreeMap::new();
        let mut unreadable_authors: Vec<DeviceKeyId> = Vec::new();
        let mut by_author: BTreeMap<DeviceKeyId, Vec<RecordId>> = BTreeMap::new();
        for (id, envelope) in &envelopes {
            if id != genesis {
                by_author.entry(envelope.author()).or_default().push(*id);
            }
        }
        let mut keys: BTreeMap<DeviceKeyId, DevicePublic> =
            BTreeMap::from([(creator.id(), creator.clone())]);
        let mut queue = VecDeque::from([creator.id()]);
        while let Some(author) = queue.pop_front() {
            for id in by_author.remove(&author).unwrap_or_default() {
                match envelopes[&id].verify(&keys[&author], vault_id) {
                    Ok(record) => {
                        if record.body().kind() == &RecordKind::Roster {
                            match RosterOp::from_record(&record) {
                                Ok(op) => {
                                    if let RosterOp::AddDevice { device, .. } = &op
                                        && !keys.contains_key(&device.id())
                                    {
                                        keys.insert(device.id(), device.clone());
                                        queue.push_back(device.id());
                                    }
                                    ops.insert(id, op);
                                }
                                Err(_) => {
                                    ignored.insert(
                                        id,
                                        Ignored::Malformed("the roster operation is malformed"),
                                    );
                                }
                            }
                        }
                        verified.insert(id, record);
                    }
                    Err(SharedError::UnsupportedVersion { .. }) => {
                        waiting.insert(id, Waiting::Unreadable);
                        unreadable_authors.push(author);
                    }
                    Err(SharedError::BadSignature) => {
                        ignored.insert(id, Ignored::BadSignature);
                    }
                    Err(SharedError::WrongVault) => {
                        ignored.insert(id, Ignored::WrongVault);
                    }
                    Err(_) => {
                        ignored.insert(
                            id,
                            Ignored::Malformed("the record body is not what the format says"),
                        );
                    }
                }
            }
        }
        for id in by_author.into_values().flatten() {
            waiting.insert(id, Waiting::UnknownAuthor);
        }
        verified.insert(*genesis, genesis_record);

        // One roster record per (device, seq): the smaller record id.
        let mut seen: BTreeSet<(DeviceKeyId, u64)> = BTreeSet::new();
        for (id, record) in &verified {
            if ops.contains_key(id) && !seen.insert((record.author(), record.body().seq())) {
                ignored.insert(*id, Ignored::Duplicate);
                ops.remove(id);
            }
        }

        // The graph of roster records: each one's heads, and its author's previous record when
        // that is a roster record too.
        let mut graph: BTreeMap<RecordId, Vec<RecordId>> = BTreeMap::from([(*genesis, vec![])]);
        for id in ops.keys() {
            let body = verified[id].body();
            let mut edges: Vec<RecordId> = body.roster().to_vec();
            if let Some(missing) = edges.iter().find(|h| !ops.contains_key(h) && *h != genesis) {
                waiting.insert(*id, Waiting::MissingHead(*missing));
                continue;
            }
            if body.roster().is_empty() || !body.parents().is_empty() {
                ignored.insert(
                    *id,
                    Ignored::Malformed("a roster record names heads and no parents"),
                );
                continue;
            }
            edges.extend(body.prev().filter(|prev| ops.contains_key(prev)));
            graph.insert(*id, edges);
        }
        let order = linearize(*genesis, &mut graph, &mut waiting);

        // Apply in order.
        let mut snapshot = RosterSnapshot::default();
        let genesis_state = |s: &mut RosterSnapshot| {
            let RosterOp::Genesis {
                member,
                device,
                labels,
                ..
            } = &genesis_op
            else {
                unreachable!("checked by verify_genesis");
            };
            s.members.insert(
                *member,
                MemberState {
                    id: *member,
                    role: Role::Admin,
                    active: true,
                    labels: labels.clone(),
                },
            );
            s.devices.insert(
                device.id(),
                DeviceState {
                    public: device.clone(),
                    member: *member,
                    verified: None,
                    active: true,
                    labels: None,
                },
            );
        };
        genesis_state(&mut snapshot);
        let mut applied = vec![*genesis];
        let mut read_only = false;
        let mut history: BTreeMap<DeviceKeyId, Vec<(usize, Option<Role>)>> = BTreeMap::new();
        let record_history =
            |s: &RosterSnapshot,
             at: usize,
             h: &mut BTreeMap<DeviceKeyId, Vec<(usize, Option<Role>)>>| {
                for id in s.devices.keys() {
                    let role = s.role_of(id);
                    let entries = h.entry(*id).or_default();
                    if entries.last().map(|(_, r)| *r) != Some(role) {
                        entries.push((at, role));
                    }
                }
            };
        record_history(&snapshot, 0, &mut history);
        for (at, id) in order.iter().enumerate().skip(1) {
            if at >= MAX_ROSTER_RECORDS {
                ignored.insert(*id, Ignored::LimitExceeded);
                continue;
            }
            let author = verified[id].author();
            let outcome = match snapshot.role_of(&author) {
                None => Err(Ignored::NotADevice),
                Some(role) if role != Role::Admin => Err(Ignored::NotAdmin),
                Some(_) => snapshot.apply(suite, &ops[id]),
            };
            match outcome {
                Ok(()) => {
                    read_only |= matches!(ops[id], RosterOp::Unknown { .. });
                    applied.push(*id);
                    record_history(&snapshot, at, &mut history);
                }
                Err(why) => {
                    ignored.insert(*id, why);
                }
            }
        }
        read_only |= unreadable_authors
            .iter()
            .any(|a| snapshot.role_of(a) == Some(Role::Admin));

        let named: BTreeSet<&RecordId> = applied.iter().flat_map(|id| &graph[id]).collect();
        let heads = applied
            .iter()
            .filter(|id| !named.contains(id))
            .copied()
            .collect();
        let position = order.iter().enumerate().map(|(at, id)| (*id, at)).collect();
        Ok(Self {
            vault_id: *vault_id,
            genesis: *genesis,
            snapshot,
            order: applied,
            position,
            history,
            heads,
            ignored,
            waiting,
            read_only,
            verified,
        })
    }

    /// The shared vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The genesis record.
    #[must_use]
    pub const fn genesis(&self) -> RecordId {
        self.genesis
    }

    /// The members and devices after the whole roster.
    #[must_use]
    pub const fn snapshot(&self) -> &RosterSnapshot {
        &self.snapshot
    }

    /// The role `device` holds now, or `None` if it is not in the roster.
    #[must_use]
    pub fn role_of(&self, device: &DeviceKeyId) -> Option<Role> {
        self.snapshot.role_of(device)
    }

    /// The roster heads a new record names: applied roster records no applied one builds on.
    #[must_use]
    pub fn heads(&self) -> &[RecordId] {
        &self.heads
    }

    /// The roster records applied, in order, starting with the genesis.
    #[must_use]
    pub fn order(&self) -> &[RecordId] {
        &self.order
    }

    /// The records ignored while computing the roster, with why.
    #[must_use]
    pub const fn ignored(&self) -> &BTreeMap<RecordId, Ignored> {
        &self.ignored
    }

    /// The records waiting for something, with what.
    #[must_use]
    pub const fn waiting(&self) -> &BTreeMap<RecordId, Waiting> {
        &self.waiting
    }

    /// Whether this build must not write to the vault: an admin wrote a roster operation, or a
    /// record in a body version, it does not understand (decision 20).
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Whether no admin is left, so no roster change can apply again.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.snapshot.admin_count() == 0
    }

    /// What a person should be told.
    #[must_use]
    pub fn warnings(&self) -> Vec<RosterWarning> {
        match self.snapshot.admin_count() {
            0 => vec![RosterWarning::Frozen],
            1 => vec![RosterWarning::FewAdmins],
            _ => vec![],
        }
    }

    /// Every record whose signature verified, of any kind, by id.
    #[must_use]
    pub const fn verified_records(&self) -> &BTreeMap<RecordId, VerifiedRecord> {
        &self.verified
    }

    /// One verified record.
    #[must_use]
    pub fn verified(&self, id: &RecordId) -> Option<&VerifiedRecord> {
        self.verified.get(id)
    }

    /// The role `device` held after the roster record at `position` in the order.
    fn role_at(&self, device: &DeviceKeyId, position: usize) -> Option<Role> {
        let history = self.history.get(device)?;
        history
            .iter()
            .take_while(|(at, _)| *at <= position)
            .last()
            .and_then(|(_, role)| *role)
    }

    /// The role `device` holds as of `heads`: after the latest of them in the order.
    ///
    /// # Errors
    ///
    /// [`Waiting::MissingHead`] if a head is not an ordered roster record here.
    pub fn role_at_heads(
        &self,
        device: &DeviceKeyId,
        heads: &[RecordId],
    ) -> std::result::Result<Option<Role>, Waiting> {
        let mut latest = 0;
        for head in heads {
            latest = latest.max(*self.position.get(head).ok_or(Waiting::MissingHead(*head))?);
        }
        Ok(self.role_at(device, latest))
    }

    /// The role the author of `record` — a verified record of any kind — holds for it: its role
    /// as of the roster heads the record names. A device removed before the latest of those
    /// heads holds none.
    ///
    /// # Errors
    ///
    /// [`Ignored::NotADevice`] if the author is not in the roster at that point,
    /// [`Ignored::Malformed`] for a record naming no roster heads or not verified here, and
    /// the [`Waiting`] reason if a head is missing — both as a [`Refusal`].
    pub fn authority(&self, record: &RecordId) -> std::result::Result<Role, Refusal> {
        let verified = self
            .verified
            .get(record)
            .ok_or(Refusal::Ignored(Ignored::Malformed(
                "not a record this roster verified",
            )))?;
        let heads = verified.body().roster();
        if heads.is_empty() {
            return Err(Refusal::Ignored(Ignored::Malformed(
                "a record names no roster heads",
            )));
        }
        self.role_at_heads(&verified.author(), heads)
            .map_err(Refusal::Waiting)?
            .ok_or(Refusal::Ignored(Ignored::NotADevice))
    }

    /// A digest of everything this state says, for comparing two computations. Local.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let id = |id: &RecordId| cbor::bytes(id.as_bytes());
        let members = self.snapshot.members().map(|m| {
            Value::Array(vec![
                cbor::bytes(m.id.as_bytes()),
                cbor::text(m.role.name()),
                Value::Bool(m.active),
            ])
        });
        let devices = self.snapshot.devices.values().map(|d| {
            Value::Array(vec![
                cbor::bytes(d.public.id().as_bytes()),
                cbor::bytes(d.member.as_bytes()),
                Value::Bool(d.active),
            ])
        });
        let ignored = self
            .ignored
            .iter()
            .map(|(r, why)| Value::Array(vec![id(r), cbor::text(&format!("{why:?}"))]));
        let waiting = self
            .waiting
            .iter()
            .map(|(r, why)| Value::Array(vec![id(r), cbor::text(&format!("{why:?}"))]));
        let value = Value::Array(vec![
            cbor::text(DIGEST_DOMAIN),
            cbor::bytes(vault_id_bytes(&self.vault_id)),
            Value::Array(members.collect()),
            Value::Array(devices.collect()),
            Value::Array(self.order.iter().map(id).collect()),
            Value::Array(ignored.collect()),
            Value::Array(waiting.collect()),
            Value::Bool(self.read_only),
        ]);
        Sha256::digest(cbor::encode(&value)).into()
    }
}

/// Why a record carries no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It never will, in this record set.
    Ignored(Ignored),
    /// It may, once what it waits for arrives.
    Waiting(Waiting),
}

impl std::fmt::Debug for RosterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RosterState")
            .field("vault_id", &self.vault_id)
            .field("members", &self.snapshot.members.len())
            .field("devices", &self.snapshot.devices.len())
            .field("heads", &self.heads)
            .finish_non_exhaustive()
    }
}

/// Kahn's topological order of `graph` from the genesis, ties by smallest record id. Records
/// that never become ready (a cycle, or an edge to a record left out) wait.
fn linearize(
    genesis: RecordId,
    graph: &mut BTreeMap<RecordId, Vec<RecordId>>,
    waiting: &mut BTreeMap<RecordId, Waiting>,
) -> Vec<RecordId> {
    let mut indegree: BTreeMap<RecordId, usize> = BTreeMap::new();
    let mut children: BTreeMap<RecordId, Vec<RecordId>> = BTreeMap::new();
    for (id, edges) in graph.iter() {
        indegree.insert(*id, edges.len());
        for edge in edges {
            children.entry(*edge).or_default().push(*id);
        }
    }
    let mut ready = BTreeSet::from([genesis]);
    let mut order = Vec::with_capacity(graph.len());
    while let Some(id) = ready.pop_first() {
        order.push(id);
        for child in children.get(&id).into_iter().flatten() {
            let remaining = indegree.get_mut(child).expect("every child is a node");
            *remaining -= 1;
            if *remaining == 0 {
                ready.insert(*child);
            }
        }
    }
    let ordered: BTreeSet<RecordId> = order.iter().copied().collect();
    graph.retain(|id, edges| {
        if ordered.contains(id) {
            return true;
        }
        let head = edges
            .iter()
            .find(|h| !ordered.contains(h))
            .copied()
            .unwrap_or(*id);
        waiting.insert(*id, Waiting::MissingHead(head));
        false
    });
    order
}

#[cfg(test)]
#[path = "roster_tests.rs"]
pub(crate) mod tests;

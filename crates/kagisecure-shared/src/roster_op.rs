//! Roster operations: what a roster record's payload says, and how it is encoded (ADR-0035
//! §6; addendum, decision 40, as simplified by the trusted-admin amendment). The roster
//! computed from them is [`crate::roster`].

use std::collections::BTreeMap;

use ciborium::Value;

use crate::cbor;
use crate::device::{DeviceKeyId, DevicePublic, DeviceSecret, hex};
use crate::error::{Result, SharedError};
use crate::record::{Envelope, NewRecord, RecordKind, VerifiedRecord};
use crate::suite::Suite;

/// The largest sealed labels a roster operation carries.
pub const MAX_LABELS_BYTES: usize = 4096;
/// Length of a member id.
pub const MEMBER_ID_LEN: usize = 16;

const OP_SHAPE: &str = "a roster operation is a map of the fields its op names";

/// A member's id: 16 random bytes, chosen when the member is added. Public.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId([u8; MEMBER_ID_LEN]);

impl MemberId {
    /// A fresh member id, from `kagisecure-core`'s generator.
    ///
    /// # Errors
    ///
    /// [`SharedError::Core`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(kagisecure_core::crypto::random::array()?))
    }

    /// A member id as read from a file.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MEMBER_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MEMBER_ID_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MemberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemberId({})", hex(&self.0))
    }
}

/// A member's role. Ordered: a reader is below a writer is below an admin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Reads and acknowledges.
    Reader,
    /// Also edits items and environments, and mints and grants epochs.
    Writer,
    /// Also changes the roster.
    Admin,
}

/// How the admin who added a device checked its fingerprint (ADR-0035 §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verification {
    /// Compared side by side, or scanned.
    InPerson,
    /// Read aloud over a call.
    Voice,
    /// Not compared: trust on first use.
    Unverified,
}

/// Why a device or a member was removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RemovalReason {
    /// A person left.
    Left,
    /// A computer was retired by its owner.
    Retired,
    /// A device was lost while unlocked, or its owner acted in bad faith.
    Compromised,
}

/// A name ↔ value table, for the enums written as text.
macro_rules! named {
    ($ty:ty { $($variant:ident => $name:literal),* $(,)? }) => {
        impl $ty {
            /// The name as written in a roster operation.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),* }
            }

            /// The value called `name`, if this build knows it.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name { $($name => Some(Self::$variant),)* _ => None }
            }
        }
    };
}

named!(Role { Reader => "reader", Writer => "writer", Admin => "admin" });
named!(Verification { InPerson => "in_person", Voice => "voice", Unverified => "unverified" });
named!(RemovalReason { Left => "left", Retired => "retired", Compromised => "compromised" });

/// One roster change: the payload of a roster record. A deterministic CBOR map with an `"op"`
/// text and exactly that operation's fields. `labels` are sealed names, opaque to the roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RosterOp {
    /// `"genesis"`: creates the vault under `suite`, with `member` as its first member, an
    /// admin, on `device` — the device that signs the record.
    Genesis {
        /// The vault's suite: every device added later must be of it.
        suite: Suite,
        /// The creator.
        member: MemberId,
        /// The creator's device.
        device: DevicePublic,
        /// Sealed labels, or none.
        labels: Option<Vec<u8>>,
    },
    /// `"add-member"`: a new member with `role` and, as yet, no device.
    AddMember {
        /// The new member's id.
        member: MemberId,
        /// Their role.
        role: Role,
        /// Sealed labels, or none.
        labels: Option<Vec<u8>>,
    },
    /// `"add-device"`: a device for an existing member.
    AddDevice {
        /// Whose device it is.
        member: MemberId,
        /// Its public keys.
        device: DevicePublic,
        /// How the adding admin compared its fingerprint.
        verified: Verification,
        /// Sealed labels, or none.
        labels: Option<Vec<u8>>,
    },
    /// `"remove-device"`: removes one device.
    RemoveDevice {
        /// The device removed.
        device: DeviceKeyId,
        /// Why.
        reason: RemovalReason,
    },
    /// `"remove-member"`: removes a member and every device of theirs.
    RemoveMember {
        /// The member removed.
        member: MemberId,
        /// Why.
        reason: RemovalReason,
    },
    /// `"set-role"`: changes a member's role.
    SetRole {
        /// The member.
        member: MemberId,
        /// Their new role.
        role: Role,
    },
    /// An operation this build does not understand. Kept and forwarded, never applied; written
    /// by an admin, it makes the vault read-only for this build (decision 20).
    Unknown {
        /// The `op` it names.
        op: String,
    },
}

impl RosterOp {
    /// The operation's `op` name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::AddMember { .. } => "add-member",
            Self::AddDevice { .. } => "add-device",
            Self::RemoveDevice { .. } => "remove-device",
            Self::RemoveMember { .. } => "remove-member",
            Self::SetRole { .. } => "set-role",
            Self::Unknown { op } => op,
        }
    }

    fn to_value(&self) -> Result<Value> {
        let labels = |l: &Option<Vec<u8>>| -> Result<Value> {
            match l {
                Some(l) if l.len() > MAX_LABELS_BYTES => Err(SharedError::LimitExceeded {
                    what: "roster labels",
                    limit: MAX_LABELS_BYTES as u64,
                }),
                Some(l) => Ok(cbor::bytes(l)),
                None => Ok(Value::Null),
            }
        };
        let member = |m: &MemberId| cbor::bytes(m.as_bytes());
        let mut entries = vec![(cbor::text("op"), cbor::text(self.name()))];
        match self {
            Self::Genesis {
                suite,
                member: m,
                device,
                labels: l,
            } => entries.extend([
                (cbor::text("suite"), cbor::text(suite.name())),
                (cbor::text("member"), member(m)),
                (cbor::text("device"), device.to_value()),
                (cbor::text("labels"), labels(l)?),
            ]),
            Self::AddMember {
                member: m,
                role,
                labels: l,
            } => entries.extend([
                (cbor::text("member"), member(m)),
                (cbor::text("role"), cbor::text(role.name())),
                (cbor::text("labels"), labels(l)?),
            ]),
            Self::AddDevice {
                member: m,
                device,
                verified,
                labels: l,
            } => entries.extend([
                (cbor::text("member"), member(m)),
                (cbor::text("device"), device.to_value()),
                (cbor::text("verified"), cbor::text(verified.name())),
                (cbor::text("labels"), labels(l)?),
            ]),
            Self::RemoveDevice { device, reason } => entries.extend([
                (cbor::text("device"), cbor::bytes(device.as_bytes())),
                (cbor::text("reason"), cbor::text(reason.name())),
            ]),
            Self::RemoveMember { member: m, reason } => entries.extend([
                (cbor::text("member"), member(m)),
                (cbor::text("reason"), cbor::text(reason.name())),
            ]),
            Self::SetRole { member: m, role } => entries.extend([
                (cbor::text("member"), member(m)),
                (cbor::text("role"), cbor::text(role.name())),
            ]),
            Self::Unknown { .. } => {
                return Err(SharedError::Malformed(
                    "this build writes only roster operations it knows",
                ));
            }
        }
        Ok(cbor::map(entries))
    }

    /// The operation as a roster record's payload: deterministic CBOR.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for [`Self::Unknown`]; [`SharedError::LimitExceeded`] for
    /// labels over [`MAX_LABELS_BYTES`].
    pub fn to_payload(&self) -> Result<Vec<u8>> {
        Ok(cbor::encode(&self.to_value()?))
    }

    /// Read a roster record's payload. An operation this build does not understand — an unknown
    /// `op`, a field, role, reason or suite it does not know — is [`Self::Unknown`].
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for anything that is not a roster operation in deterministic
    /// CBOR, or a known one missing a field; [`SharedError::InvalidPublicKey`] for a device key
    /// that fails its checks; [`SharedError::LimitExceeded`] for labels over the limit.
    pub fn from_payload(bytes: &[u8]) -> Result<Self> {
        decode_op(cbor::decode_canonical(bytes)?)
    }

    /// Read a verified roster record's operation.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a record of another kind, and as [`Self::from_payload`].
    pub fn from_record(record: &VerifiedRecord) -> Result<Self> {
        if record.body().kind() != &RecordKind::Roster {
            return Err(SharedError::Malformed("not a roster record"));
        }
        Self::from_payload(record.body().payload())
    }

    /// Write this operation as a roster record signed by `author`. A genesis is its author's
    /// first record, names no roster heads and introduces its author's own device; every other
    /// operation names at least one roster head. No roster record names `parents`.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a record that breaks those rules, and as
    /// [`Self::to_payload`] and [`Envelope::sign_plain`].
    pub fn sign(&self, author: &DeviceSecret, record: NewRecord) -> Result<Envelope> {
        self.check_record(author, &record)?;
        Envelope::sign_plain(author, RecordKind::Roster, record, self.to_payload()?)
    }

    /// [`Self::sign`] with a given record salt, for golden vectors. Test builds only.
    #[cfg(test)]
    pub(crate) fn sign_with_salt(
        &self,
        author: &DeviceSecret,
        record: NewRecord,
        record_salt: [u8; crate::epoch_key::RECORD_SALT_LEN],
    ) -> Result<Envelope> {
        self.check_record(author, &record)?;
        let payload = self.to_payload()?;
        Envelope::sign_plain_with_salt(author, RecordKind::Roster, record, payload, record_salt)
    }

    fn check_record(&self, author: &DeviceSecret, record: &NewRecord) -> Result<()> {
        if !record.parents.is_empty() {
            return Err(SharedError::Malformed("a roster record names no parents"));
        }
        match self {
            Self::Genesis { device, .. } => {
                if record.seq != 0 || !record.roster.is_empty() || device != author.public() {
                    return Err(SharedError::Malformed(
                        "a genesis is its own device's first record and names no roster heads",
                    ));
                }
            }
            _ if record.roster.is_empty() => {
                return Err(SharedError::Malformed(
                    "a roster record names the roster heads it builds on",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn decode_op(value: Value) -> Result<RosterOp> {
    let mut fields: BTreeMap<String, Value> =
        cbor::text_map(value, OP_SHAPE)?.into_iter().collect();
    let text = |v: Value| match v {
        Value::Text(t) => Ok(t),
        _ => Err(SharedError::Malformed(OP_SHAPE)),
    };
    let op = text(
        fields
            .remove("op")
            .ok_or(SharedError::Malformed(OP_SHAPE))?,
    )?;
    let known: &[&str] = match op.as_str() {
        "genesis" => &["suite", "member", "device", "labels"],
        "add-member" => &["member", "role", "labels"],
        "add-device" => &["member", "device", "verified", "labels"],
        "remove-device" => &["device", "reason"],
        "remove-member" => &["member", "reason"],
        "set-role" => &["member", "role"],
        _ => return Ok(RosterOp::Unknown { op }),
    };
    if fields.keys().any(|key| !known.contains(&key.as_str())) {
        return Ok(RosterOp::Unknown { op });
    }
    if fields.len() != known.len() {
        return Err(SharedError::Malformed(OP_SHAPE));
    }
    let mut take = |key: &str| fields.remove(key).ok_or(SharedError::Malformed(OP_SHAPE));
    let unknown = || Ok(RosterOp::Unknown { op: op.clone() });
    let member = |v: Value| Ok::<_, SharedError>(MemberId(cbor::fixed_bytes(&v, OP_SHAPE)?));
    let labels = |v: Value| match v {
        Value::Null => Ok(None),
        Value::Bytes(l) if l.len() <= MAX_LABELS_BYTES => Ok(Some(l)),
        Value::Bytes(_) => Err(SharedError::LimitExceeded {
            what: "roster labels",
            limit: MAX_LABELS_BYTES as u64,
        }),
        _ => Err(SharedError::Malformed(OP_SHAPE)),
    };
    // A device of a suite this build does not implement is not understood.
    let device = |v: Value| match DevicePublic::from_value(v) {
        Ok(device) => Ok(Some(device)),
        Err(SharedError::UnsupportedSuite(_)) => Ok(None),
        Err(other) => Err(other),
    };
    Ok(match op.as_str() {
        "genesis" => {
            let Ok(suite) = Suite::from_name(&text(take("suite")?)?) else {
                return unknown();
            };
            let member = member(take("member")?)?;
            let Some(device) = device(take("device")?)? else {
                return unknown();
            };
            RosterOp::Genesis {
                suite,
                member,
                device,
                labels: labels(take("labels")?)?,
            }
        }
        "add-member" => {
            let member = member(take("member")?)?;
            let Some(role) = Role::from_name(&text(take("role")?)?) else {
                return unknown();
            };
            RosterOp::AddMember {
                member,
                role,
                labels: labels(take("labels")?)?,
            }
        }
        "add-device" => {
            let member = member(take("member")?)?;
            let Some(device) = device(take("device")?)? else {
                return unknown();
            };
            let Some(verified) = Verification::from_name(&text(take("verified")?)?) else {
                return unknown();
            };
            RosterOp::AddDevice {
                member,
                device,
                verified,
                labels: labels(take("labels")?)?,
            }
        }
        "remove-device" => {
            let device = DeviceKeyId::from_bytes(cbor::fixed_bytes(&take("device")?, OP_SHAPE)?);
            let Some(reason) = RemovalReason::from_name(&text(take("reason")?)?) else {
                return unknown();
            };
            RosterOp::RemoveDevice { device, reason }
        }
        "remove-member" => {
            let member = member(take("member")?)?;
            let Some(reason) = RemovalReason::from_name(&text(take("reason")?)?) else {
                return unknown();
            };
            RosterOp::RemoveMember { member, reason }
        }
        _ => {
            let member = member(take("member")?)?;
            let Some(role) = Role::from_name(&text(take("role")?)?) else {
                return unknown();
            };
            RosterOp::SetRole { member, role }
        }
    })
}

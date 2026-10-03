//! Records: the signed, immutable unit every change to a shared vault is made of (ADR-0035 §6;
//! addendum, "Record envelope", "Payload AAD", "Limits", decisions 13, 15, 20; Correction G).
//!
//! # The envelope
//!
//! A record on disk is a CBOR array `[v, author, body, sig]`: the envelope version, the author's
//! 32-byte device key id, the body as a byte string, and a 64-byte Ed25519 signature over
//! `"kagisecure/shared/sig/record/v1" ‖ 0x00 ‖ author ‖ body`. Its id is
//! `SHA-256(signed message ‖ sig)`. The author sits outside the body but inside what the
//! signature covers, so a reader learns who signed before decoding anything, verifies over the
//! exact bytes, and only then decodes the body and, later, decrypts (Correction G).
//!
//! [`Envelope::parse`] reads that array by hand, not through a general CBOR decoder: the whole
//! input is refused above 1 MiB before a byte of it is looked at, every length is checked against
//! what is left before anything is sliced, and only the one encoding a deterministic writer
//! produces is accepted (decision 37). Nothing is allocated beyond a copy of the body.
//!
//! # The body
//!
//! A deterministic CBOR map (decision 33) with these keys, all always present:
//!
//! ```text
//! v            uint          body version, 1
//! kind         text          "roster" | "epoch" | "item" | "env" | "ack" | a kind this build does not know
//! vault_id     bytes(16)
//! seq          uint          the author's own counter, from 0
//! prev         bytes(32)|null  the author's previous record's id; null exactly when seq is 0
//! parents      [bytes(32)]   the versions this record edits (item, env); at most 16
//! roster       [bytes(32)]   the roster heads the author's authority is checked against; at most 16
//! epoch        bytes(16)|null  the epoch whose key encrypts the payload; present for item and env
//! created_at   uint          unix seconds, as the author claims; displayed, never decides anything
//! record_salt  bytes(16)     input to the record key
//! payload      bytes         item, env: nonce ‖ ciphertext ‖ tag under the record key
//! ```
//!
//! Keys this build does not know are kept ([`RecordBody::unknown`]), and so is a record of a kind
//! it does not know: it verifies, it is stored and forwarded byte for byte, and it is simply not
//! interpreted (decision 20). A body version this build does not know is refused as
//! [`SharedError::UnsupportedVersion`]; the envelope's bytes are still there to keep.
//!
//! # The payload
//!
//! An item or environment payload is sealed under the record key
//! (`crate::epoch_key::EpochKey::record_key`) with AAD
//! `["kagisecure/shared/payload/v1", vault_id, author, kind, parents, roster, epoch_id]` — so
//! another member who strips the signature and re-signs the ciphertext as their own produces a
//! record that verifies and then fails to decrypt (ADR-0035 §6).

use std::collections::BTreeMap;

use ciborium::Value;
use kagisecure_core::proto::VaultId;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor;
use crate::device::{DeviceKeyId, DevicePublic, DeviceSecret, hex};
use crate::epoch_key::{EPOCH_ID_LEN, EpochId, EpochKey, RECORD_SALT_LEN, vault_id_bytes};
use crate::error::{Result, SharedError};
use crate::sign::{SIGNATURE_LEN, Signature, Signed};

/// The largest record, in bytes, as it is on disk (ADR-0035 addendum, limits).
pub const MAX_RECORD_BYTES: usize = 1 << 20;
/// The most `parents` a record may name.
pub const MAX_PARENTS: usize = 16;
/// The most roster heads a record may name.
pub const MAX_ROSTER_HEADS: usize = 16;
/// The envelope version this build reads and writes.
pub const ENVELOPE_VERSION: u64 = 1;
/// The body version this build reads and writes.
pub const BODY_VERSION: u64 = 1;
/// Length of a record id.
pub const RECORD_ID_LEN: usize = 32;

const PAYLOAD_AAD_DOMAIN: &str = "kagisecure/shared/payload/v1";

/// A record's id: `SHA-256(signed message ‖ sig)`. Public.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId([u8; RECORD_ID_LEN]);

impl RecordId {
    /// An id as read from a file.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; RECORD_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RECORD_ID_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecordId({})", hex(&self.0))
    }
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

/// What a record is (ADR-0035 §6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// A roster change: genesis, add or remove a member or device, set a role.
    Roster,
    /// A new epoch, or a grant of one: its key wrapped to devices.
    Epoch,
    /// A version of an item. Encrypted.
    Item,
    /// A version of an environment. Encrypted.
    Env,
    /// A device's acknowledgement that it adopted an epoch.
    Ack,
    /// A shared vault's policy on unattended copies, written by an admin (ADR-0042 §13).
    /// Encrypted.
    Policy,
    /// A device's note that it holds, or no longer holds, an unattended copy of an environment
    /// (ADR-0042 §13). Encrypted.
    Copy,
    /// A kind this build does not know, kept by name and forwarded untouched (decision 20).
    Unknown(String),
}

impl RecordKind {
    /// The kind's name as written in the body.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Roster => "roster",
            Self::Epoch => "epoch",
            Self::Item => "item",
            Self::Env => "env",
            Self::Ack => "ack",
            Self::Policy => "policy",
            Self::Copy => "unattended_copy",
            Self::Unknown(name) => name,
        }
    }

    /// The kind called `name`; a name this build does not know is [`Self::Unknown`].
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "roster" => Self::Roster,
            "epoch" => Self::Epoch,
            "item" => Self::Item,
            "env" => Self::Env,
            "ack" => Self::Ack,
            "policy" => Self::Policy,
            "unattended_copy" => Self::Copy,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Whether this kind's payload is sealed under a record key.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Self::Item | Self::Env | Self::Policy | Self::Copy)
    }
}

/// The fields of a record a writer chooses; the rest (the salt, the payload, the signature) the
/// writing functions fill in.
#[derive(Clone, Debug)]
pub struct NewRecord {
    /// The shared vault.
    pub vault_id: VaultId,
    /// The author's own counter, from 0.
    pub seq: u64,
    /// The author's previous record: `None` exactly when `seq` is 0.
    pub prev: Option<RecordId>,
    /// The versions this record edits. At most [`MAX_PARENTS`].
    pub parents: Vec<RecordId>,
    /// The roster heads the author's authority is checked against. At most [`MAX_ROSTER_HEADS`].
    pub roster: Vec<RecordId>,
    /// The epoch whose key encrypts the payload: required for item and env records.
    pub epoch: Option<EpochId>,
    /// Unix seconds, as this device claims.
    pub created_at: u64,
}

/// A record's body, decoded — after its signature verified. See the module documentation.
#[derive(Clone, Debug)]
pub struct RecordBody {
    v: u64,
    kind: RecordKind,
    vault_id: VaultId,
    seq: u64,
    prev: Option<RecordId>,
    parents: Vec<RecordId>,
    roster: Vec<RecordId>,
    epoch: Option<EpochId>,
    created_at: u64,
    record_salt: [u8; RECORD_SALT_LEN],
    payload: Vec<u8>,
    unknown: BTreeMap<String, Value>,
}

/// Refuse lists over their limit and a `seq`/`prev` pair that cannot be a chain.
fn check_shape(
    seq: u64,
    prev: Option<&RecordId>,
    parents: usize,
    roster: usize,
    kind: &RecordKind,
    epoch: Option<&EpochId>,
) -> Result<()> {
    if parents > MAX_PARENTS {
        return Err(SharedError::LimitExceeded {
            what: "record parents",
            limit: MAX_PARENTS as u64,
        });
    }
    if roster > MAX_ROSTER_HEADS {
        return Err(SharedError::LimitExceeded {
            what: "record roster heads",
            limit: MAX_ROSTER_HEADS as u64,
        });
    }
    if prev.is_none() != (seq == 0) {
        return Err(SharedError::Malformed(
            "a record names a previous record exactly when its seq is not 0",
        ));
    }
    if kind.is_encrypted() && epoch.is_none() {
        return Err(SharedError::Malformed(
            "an item or environment record names its epoch",
        ));
    }
    Ok(())
}

fn id_list(ids: &[RecordId]) -> Value {
    Value::Array(ids.iter().map(|id| cbor::bytes(&id.0)).collect())
}

impl RecordBody {
    /// The body version.
    #[must_use]
    pub const fn v(&self) -> u64 {
        self.v
    }

    /// What the record is.
    #[must_use]
    pub const fn kind(&self) -> &RecordKind {
        &self.kind
    }

    /// The shared vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The author's counter.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The author's previous record.
    #[must_use]
    pub const fn prev(&self) -> Option<&RecordId> {
        self.prev.as_ref()
    }

    /// The versions this record edits.
    #[must_use]
    pub fn parents(&self) -> &[RecordId] {
        &self.parents
    }

    /// The roster heads the author's authority is checked against.
    #[must_use]
    pub fn roster(&self) -> &[RecordId] {
        &self.roster
    }

    /// The epoch whose key encrypts the payload.
    #[must_use]
    pub const fn epoch(&self) -> Option<&EpochId> {
        self.epoch.as_ref()
    }

    /// Unix seconds, as the author claims. Never used to decide anything.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The record's salt.
    #[must_use]
    pub const fn record_salt(&self) -> &[u8; RECORD_SALT_LEN] {
        &self.record_salt
    }

    /// The payload as it is in the record: ciphertext for item and env records.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Keys of the body this build does not know, kept as read.
    #[must_use]
    pub const fn unknown(&self) -> &BTreeMap<String, Value> {
        &self.unknown
    }

    /// The body's deterministic CBOR encoding.
    fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (cbor::text("v"), Value::Integer(self.v.into())),
            (cbor::text("kind"), cbor::text(self.kind.name())),
            (
                cbor::text("vault_id"),
                cbor::bytes(vault_id_bytes(&self.vault_id)),
            ),
            (cbor::text("seq"), Value::Integer(self.seq.into())),
            (
                cbor::text("prev"),
                self.prev.map_or(Value::Null, |id| cbor::bytes(&id.0)),
            ),
            (cbor::text("parents"), id_list(&self.parents)),
            (cbor::text("roster"), id_list(&self.roster)),
            (
                cbor::text("epoch"),
                self.epoch
                    .map_or(Value::Null, |e| cbor::bytes(e.as_bytes())),
            ),
            (
                cbor::text("created_at"),
                Value::Integer(self.created_at.into()),
            ),
            (cbor::text("record_salt"), cbor::bytes(&self.record_salt)),
            (cbor::text("payload"), Value::Bytes(self.payload.clone())),
        ];
        entries.extend(self.unknown.iter().map(|(k, v)| (cbor::text(k), v.clone())));
        cbor::encode(&cbor::map(entries))
    }

    /// Decode a body — only ever one whose signature already verified, or a genesis being
    /// checked (`Envelope::body_unverified`). With `expected`, the first thing checked about the
    /// decoded fields, right after the body version, is that its `vault_id` is that vault's.
    pub(crate) fn decode(bytes: &[u8], expected: Option<&VaultId>) -> Result<Self> {
        const SHAPE: &str = "a record body is a map of the fields the format names";
        let mut v = None;
        let mut kind = None;
        let mut vault_id = None;
        let mut seq = None;
        let mut prev = None;
        let mut parents = None;
        let mut roster = None;
        let mut epoch = None;
        let mut created_at = None;
        let mut record_salt = None;
        let mut payload = None;
        let mut unknown = BTreeMap::new();

        // The limits on `parents` and `roster` are counted from the encoded body, while it is
        // scanned and before any of it is decoded (ADR-0035 addendum, "Limits").
        let entries = cbor::scan_map(bytes, SHAPE)?;
        // Which vault, before anything else — even the body version: a body of another vault is
        // not this vault's to read, and must not make it read-only for naming a version this
        // build does not know (decision 13).
        if let Some(expected) = expected
            && let Some((_, value)) = entries
                .iter()
                .find(|(key, _)| cbor::is_text_key(key, "vault_id"))
            && let [0x50, id @ ..] = value
            && id.len() == 16
            && id != vault_id_bytes(expected)
        {
            return Err(SharedError::WrongVault);
        }
        for (key, value) in entries {
            for (name, limit, what) in [
                ("parents", MAX_PARENTS, "record parents"),
                ("roster", MAX_ROSTER_HEADS, "record roster heads"),
            ] {
                if cbor::is_text_key(key, name)
                    && cbor::array_len(value).is_some_and(|count| count > limit as u64)
                {
                    return Err(SharedError::LimitExceeded {
                        what,
                        limit: limit as u64,
                    });
                }
            }
        }
        let ids = |value: Value| -> Result<Vec<RecordId>> {
            let Value::Array(items) = value else {
                return Err(SharedError::Malformed(SHAPE));
            };
            items
                .iter()
                .map(|item| cbor::fixed_bytes(item, SHAPE).map(RecordId))
                .collect()
        };

        for (key, value) in cbor::text_map(cbor::decode_scanned(bytes)?, SHAPE)? {
            match key.as_str() {
                "v" => v = Some(cbor::uint(&value, SHAPE)?),
                "kind" => {
                    let Value::Text(name) = value else {
                        return Err(SharedError::Malformed(SHAPE));
                    };
                    kind = Some(RecordKind::from_name(&name));
                }
                "vault_id" => {
                    vault_id = Some(VaultId(Uuid::from_bytes(cbor::fixed_bytes(&value, SHAPE)?)));
                }
                "seq" => seq = Some(cbor::uint(&value, SHAPE)?),
                "prev" => {
                    prev = Some(match value {
                        Value::Null => None,
                        other => Some(RecordId(cbor::fixed_bytes(&other, SHAPE)?)),
                    });
                }
                "parents" => parents = Some(ids(value)?),
                "roster" => roster = Some(ids(value)?),
                "epoch" => {
                    epoch = Some(match value {
                        Value::Null => None,
                        other => Some(EpochId::from_bytes(cbor::fixed_bytes::<EPOCH_ID_LEN>(
                            &other, SHAPE,
                        )?)),
                    });
                }
                "created_at" => created_at = Some(cbor::uint(&value, SHAPE)?),
                "record_salt" => record_salt = Some(cbor::fixed_bytes(&value, SHAPE)?),
                "payload" => {
                    let Value::Bytes(data) = value else {
                        return Err(SharedError::Malformed(SHAPE));
                    };
                    payload = Some(data);
                }
                _ => {
                    unknown.insert(key, value);
                }
            }
        }

        let v = v.ok_or(SharedError::Malformed(SHAPE))?;
        if v != BODY_VERSION {
            return Err(SharedError::UnsupportedVersion {
                what: "record body",
                version: v,
            });
        }
        let (
            Some(kind),
            Some(vault_id),
            Some(seq),
            Some(prev),
            Some(parents),
            Some(roster),
            Some(epoch),
            Some(created_at),
            Some(record_salt),
            Some(payload),
        ) = (
            kind,
            vault_id,
            seq,
            prev,
            parents,
            roster,
            epoch,
            created_at,
            record_salt,
            payload,
        )
        else {
            return Err(SharedError::Malformed(SHAPE));
        };
        // The first check on a body's content: a record of another vault is not read as this
        // one's, however well it is formed (decision 13).
        if expected.is_some_and(|expected| *expected != vault_id) {
            return Err(SharedError::WrongVault);
        }
        check_shape(
            seq,
            prev.as_ref(),
            parents.len(),
            roster.len(),
            &kind,
            epoch.as_ref(),
        )?;
        Ok(Self {
            v,
            kind,
            vault_id,
            seq,
            prev,
            parents,
            roster,
            epoch,
            created_at,
            record_salt,
            payload,
            unknown,
        })
    }
}

/// The payload's AAD: `["kagisecure/shared/payload/v1", vault_id, author, kind, parents, roster,
/// epoch_id]`, as deterministic CBOR.
fn payload_aad(
    vault_id: &VaultId,
    author: &DeviceKeyId,
    kind: &RecordKind,
    parents: &[RecordId],
    roster: &[RecordId],
    epoch: &EpochId,
) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        cbor::text(PAYLOAD_AAD_DOMAIN),
        cbor::bytes(vault_id_bytes(vault_id)),
        cbor::bytes(author.as_bytes()),
        cbor::text(kind.name()),
        id_list(parents),
        id_list(roster),
        cbor::bytes(epoch.as_bytes()),
    ]))
}

/// A record as it travels: parsed, not yet verified. See the module documentation.
#[derive(Clone)]
pub struct Envelope {
    encoded: Vec<u8>,
    author: DeviceKeyId,
    body: Vec<u8>,
    signature: Signature,
    id: RecordId,
}

/// Reads the envelope's four items, each in its one deterministic form.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const SHAPE: &'static str = "a record is a CBOR array of version, author, body and signature";

    fn byte(&mut self) -> Result<u8> {
        let (&first, rest) = self
            .rest
            .split_first()
            .ok_or(SharedError::Malformed(Self::SHAPE))?;
        self.rest = rest;
        Ok(first)
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8]> {
        let len = usize::try_from(len).map_err(|_| SharedError::Malformed(Self::SHAPE))?;
        if len > self.rest.len() {
            return Err(SharedError::Malformed(Self::SHAPE));
        }
        let (taken, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(taken)
    }

    /// A head of major type `major` with its argument in the shortest form.
    fn head(&mut self, major: u8) -> Result<u64> {
        let first = self.byte()?;
        if first >> 5 != major {
            return Err(SharedError::Malformed(Self::SHAPE));
        }
        let info = first & 0x1f;
        let (value, shortest_from) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.byte()?), 24),
            25 => (u64::from_be_bytes(pad(self.take(2)?)), 1 << 8),
            26 => (u64::from_be_bytes(pad(self.take(4)?)), 1 << 16),
            27 => (u64::from_be_bytes(pad(self.take(8)?)), 1 << 32),
            // Reserved, or indefinite length: neither is deterministic.
            _ => return Err(SharedError::Malformed(Self::SHAPE)),
        };
        if value < shortest_from {
            return Err(SharedError::Malformed(Self::SHAPE));
        }
        Ok(value)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.head(2)?;
        self.take(len)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes()?
            .try_into()
            .map_err(|_| SharedError::Malformed(Self::SHAPE))
    }
}

/// Right-align up to eight big-endian bytes in a `u64`'s.
fn pad(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[8 - bytes.len()..].copy_from_slice(bytes);
    out
}

fn record_id(message: &[u8], signature: &Signature) -> RecordId {
    RecordId(
        Sha256::new()
            .chain_update(message)
            .chain_update(signature.as_bytes())
            .finalize()
            .into(),
    )
}

impl Envelope {
    /// Parse a record's bytes, without verifying it. See the module documentation for what is
    /// refused.
    ///
    /// # Errors
    ///
    /// [`SharedError::LimitExceeded`] for more than [`MAX_RECORD_BYTES`], before anything is
    /// read; [`SharedError::UnsupportedVersion`] for an envelope version other than
    /// [`ENVELOPE_VERSION`]; [`SharedError::Malformed`] for anything else that is not exactly
    /// the envelope.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(SharedError::LimitExceeded {
                what: "record",
                limit: MAX_RECORD_BYTES as u64,
            });
        }
        let mut reader = Reader { rest: bytes };
        if reader.head(4)? != 4 {
            return Err(SharedError::Malformed(Reader::SHAPE));
        }
        let v = reader.head(0)?;
        if v != ENVELOPE_VERSION {
            return Err(SharedError::UnsupportedVersion {
                what: "record envelope",
                version: v,
            });
        }
        let author = DeviceKeyId::from_bytes(reader.fixed()?);
        let body = reader.bytes()?.to_vec();
        let signature = Signature::from_bytes(reader.fixed::<SIGNATURE_LEN>()?);
        if !reader.rest.is_empty() {
            return Err(SharedError::Malformed(Reader::SHAPE));
        }
        let id = record_id(
            &Signed::Record {
                author: &author,
                body: &body,
            }
            .to_message(),
            &signature,
        );
        Ok(Self {
            encoded: bytes.to_vec(),
            author,
            body,
            signature,
            id,
        })
    }

    /// Sign `body` as `author` and build the envelope.
    fn sign_body(author: &DeviceSecret, body: Vec<u8>) -> Result<Self> {
        let author_id = author.id();
        let message = Signed::Record {
            author: &author_id,
            body: &body,
        }
        .to_message();
        let signature = author.sign_message(&message);
        let encoded = cbor::encode(&Value::Array(vec![
            Value::Integer(ENVELOPE_VERSION.into()),
            cbor::bytes(author_id.as_bytes()),
            Value::Bytes(body),
            cbor::bytes(signature.as_bytes()),
        ]));
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(SharedError::LimitExceeded {
                what: "record",
                limit: MAX_RECORD_BYTES as u64,
            });
        }
        Self::parse(&encoded)
    }

    /// Write an item or environment record: `plaintext` sealed under the record key of
    /// `epoch_key` (the key of `record.epoch`), then signed by `author`.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a kind that is not encrypted or a record that breaks the
    /// body's shape; [`SharedError::LimitExceeded`] for too many parents or roster heads, or a
    /// record over [`MAX_RECORD_BYTES`]; [`SharedError::Core`] if the generator fails.
    pub fn seal(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        epoch_key: &EpochKey,
        plaintext: &[u8],
    ) -> Result<Self> {
        let record_salt = kagisecure_core::crypto::random::array()?;
        let nonce = kagisecure_core::crypto::aead::nonce()?;
        Self::seal_salted(
            author,
            kind,
            record,
            epoch_key,
            plaintext,
            record_salt,
            nonce,
        )
    }

    /// [`Self::seal`] with a given salt and nonce, for golden vectors. Test builds only:
    /// production code has no way to choose a record's salt or nonce.
    #[cfg(test)]
    pub(crate) fn seal_with(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        epoch_key: &EpochKey,
        plaintext: &[u8],
        record_salt: [u8; RECORD_SALT_LEN],
        nonce: [u8; kagisecure_core::crypto::aead::NONCE_LEN],
    ) -> Result<Self> {
        Self::seal_salted(
            author,
            kind,
            record,
            epoch_key,
            plaintext,
            record_salt,
            nonce,
        )
    }

    fn seal_salted(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        epoch_key: &EpochKey,
        plaintext: &[u8],
        record_salt: [u8; RECORD_SALT_LEN],
        nonce: [u8; kagisecure_core::crypto::aead::NONCE_LEN],
    ) -> Result<Self> {
        if !kind.is_encrypted() {
            return Err(SharedError::Malformed(
                "only item and environment records are sealed",
            ));
        }
        check_shape(
            record.seq,
            record.prev.as_ref(),
            record.parents.len(),
            record.roster.len(),
            &kind,
            record.epoch.as_ref(),
        )?;
        let epoch = record.epoch.ok_or(SharedError::Malformed(
            "an encrypted record names its epoch",
        ))?;
        let aad = payload_aad(
            &record.vault_id,
            &author.id(),
            &kind,
            &record.parents,
            &record.roster,
            &epoch,
        );
        let payload = epoch_key
            .record_key(&record.vault_id, &record_salt)
            .seal_with_nonce(&aad, plaintext, nonce)?;
        Self::write(author, kind, record, record_salt, payload)
    }

    /// Write a record whose payload is not sealed under a record key — a roster change, an
    /// epoch, an acknowledgement — signed by `author`.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for an item or environment kind (those are [`Self::seal`]ed),
    /// a kind this build does not know, or a record that breaks the body's shape;
    /// [`SharedError::LimitExceeded`] as for [`Self::seal`].
    pub fn sign_plain(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        payload: Vec<u8>,
    ) -> Result<Self> {
        let record_salt = kagisecure_core::crypto::random::array()?;
        Self::sign_plain_salted(author, kind, record, payload, record_salt)
    }

    /// [`Self::sign_plain`] with a given salt, for golden vectors. Test builds only: production
    /// code has no way to choose a record's salt.
    #[cfg(test)]
    pub(crate) fn sign_plain_with_salt(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        payload: Vec<u8>,
        record_salt: [u8; RECORD_SALT_LEN],
    ) -> Result<Self> {
        Self::sign_plain_salted(author, kind, record, payload, record_salt)
    }

    pub(crate) fn sign_plain_salted(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        payload: Vec<u8>,
        record_salt: [u8; RECORD_SALT_LEN],
    ) -> Result<Self> {
        if kind.is_encrypted() {
            return Err(SharedError::Malformed(
                "item and environment records are sealed, not signed in the clear",
            ));
        }
        if matches!(kind, RecordKind::Unknown(_)) {
            return Err(SharedError::Malformed(
                "this build writes only record kinds it knows",
            ));
        }
        check_shape(
            record.seq,
            record.prev.as_ref(),
            record.parents.len(),
            record.roster.len(),
            &kind,
            record.epoch.as_ref(),
        )?;
        Self::write(author, kind, record, record_salt, payload)
    }

    fn write(
        author: &DeviceSecret,
        kind: RecordKind,
        record: NewRecord,
        record_salt: [u8; RECORD_SALT_LEN],
        payload: Vec<u8>,
    ) -> Result<Self> {
        // A payload over the record limit cannot make a record under it; refuse it before
        // copying it into a body.
        if payload.len() > MAX_RECORD_BYTES {
            return Err(SharedError::LimitExceeded {
                what: "record",
                limit: MAX_RECORD_BYTES as u64,
            });
        }
        let body = RecordBody {
            v: BODY_VERSION,
            kind,
            vault_id: record.vault_id,
            seq: record.seq,
            prev: record.prev,
            parents: record.parents,
            roster: record.roster,
            epoch: record.epoch,
            created_at: record.created_at,
            record_salt,
            payload,
            unknown: BTreeMap::new(),
        };
        Self::sign_body(author, body.encode())
    }

    /// The record's id.
    #[must_use]
    pub const fn id(&self) -> RecordId {
        self.id
    }

    /// Who the record says signed it. Unverified until [`Self::verify`].
    #[must_use]
    pub const fn author(&self) -> DeviceKeyId {
        self.author
    }

    /// The record's bytes, exactly as parsed or written — what is stored and forwarded.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Decode the body **without** verifying the signature. Used for one record only: a
    /// genesis, whose signing key is in its own body and is bound to [`Self::author`] by the
    /// device key id (ADR-0035 addendum, decision 41). The body is decoded again, from the same
    /// bytes, once the signature has verified; nothing read here is trusted before that.
    pub(crate) fn body_unverified(&self) -> Result<RecordBody> {
        RecordBody::decode(&self.body, None)
    }

    /// Verify the signature with `author`'s key, then decode the body as a record of shared
    /// vault `expected` — the vault the caller is reading, never the one the record names.
    ///
    /// # Errors
    ///
    /// [`SharedError::BadSignature`] if `author` is not the device the record names or the
    /// signature does not verify; [`SharedError::WrongVault`] if the body's `vault_id` is not
    /// `expected`; then whatever decoding the body refuses — a malformed or non-deterministic
    /// body, a list over its limit, a body version this build does not read.
    pub fn verify(&self, author: &DevicePublic, expected: &VaultId) -> Result<VerifiedRecord> {
        if author.id() != self.author {
            return Err(SharedError::BadSignature);
        }
        author.verify_strict(
            &Signed::Record {
                author: &self.author,
                body: &self.body,
            },
            &self.signature,
        )?;
        let body = RecordBody::decode(&self.body, Some(expected))?;
        Ok(VerifiedRecord {
            id: self.id,
            author: self.author,
            body,
        })
    }
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("id", &self.id)
            .field("author", &self.author)
            .field("len", &self.encoded.len())
            .finish_non_exhaustive()
    }
}

/// A record whose signature verified and whose body decoded as a record of the vault it was
/// verified for: its body's `vault_id` is that vault's, which is what [`Self::open_payload`]
/// binds the payload to.
#[derive(Clone, Debug)]
pub struct VerifiedRecord {
    id: RecordId,
    author: DeviceKeyId,
    body: RecordBody,
}

impl VerifiedRecord {
    /// The record's id.
    #[must_use]
    pub const fn id(&self) -> RecordId {
        self.id
    }

    /// The device that signed it.
    #[must_use]
    pub const fn author(&self) -> DeviceKeyId {
        self.author
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &RecordBody {
        &self.body
    }

    /// Decrypt an item or environment record's payload with `epoch_key`, the key of
    /// [`RecordBody::epoch`]. The plaintext is returned in a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a record whose payload is not encrypted;
    /// [`SharedError::Decrypt`] for the wrong epoch key, or a payload that another author
    /// re-signed or that was altered.
    pub fn open_payload(&self, epoch_key: &EpochKey) -> Result<Zeroizing<Vec<u8>>> {
        let body = &self.body;
        let Some(epoch) = body.epoch.as_ref().filter(|_| body.kind.is_encrypted()) else {
            return Err(SharedError::Malformed(
                "only item and environment records have an encrypted payload",
            ));
        };
        // `body.vault_id` is the vault this record was verified for (`Envelope::verify` refused
        // any other), so the AAD and the record key are that vault's.
        let aad = payload_aad(
            &body.vault_id,
            &self.author,
            &body.kind,
            &body.parents,
            &body.roster,
            epoch,
        );
        epoch_key
            .record_key(&body.vault_id, &body.record_salt)
            .open(&aad, &body.payload)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::epoch_key::fixed_epoch_key;
    use crate::test_support::{device_with_seed, golden_device};

    pub(crate) fn vault() -> VaultId {
        VaultId(Uuid::from_bytes([0x5a; 16]))
    }

    fn header(seq: u64) -> NewRecord {
        NewRecord {
            vault_id: vault(),
            seq,
            prev: (seq > 0).then_some(RecordId([seq as u8; 32])),
            parents: vec![RecordId([0x0a; 32])],
            roster: vec![RecordId([0x0b; 32])],
            epoch: Some(EpochId::from_bytes([0x0c; 16])),
            created_at: 1_790_000_000,
        }
    }

    fn sealed() -> Envelope {
        Envelope::seal(
            &golden_device(),
            RecordKind::Item,
            header(0),
            &fixed_epoch_key(1),
            b"an item",
        )
        .unwrap()
    }

    /// A body built by hand, for the shapes this build refuses to write.
    fn body_value(edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let mut entries = vec![
            (cbor::text("v"), Value::Integer(1.into())),
            (cbor::text("kind"), cbor::text("ack")),
            (cbor::text("vault_id"), cbor::bytes(&[0x5a; 16])),
            (cbor::text("seq"), Value::Integer(0.into())),
            (cbor::text("prev"), Value::Null),
            (cbor::text("parents"), Value::Array(vec![])),
            (cbor::text("roster"), Value::Array(vec![])),
            (cbor::text("epoch"), Value::Null),
            (cbor::text("created_at"), Value::Integer(1.into())),
            (cbor::text("record_salt"), cbor::bytes(&[1; 16])),
            (cbor::text("payload"), cbor::bytes(b"")),
        ];
        edit(&mut entries);
        cbor::encode(&cbor::map(entries))
    }

    fn set(entries: &mut [(Value, Value)], key: &str, value: Value) {
        entries
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(key))
            .expect("a key the body has")
            .1 = value;
    }

    #[test]
    fn a_sealed_record_parses_verifies_and_opens() {
        let device = golden_device();
        let envelope = sealed();
        let parsed = Envelope::parse(envelope.to_bytes()).unwrap();
        assert_eq!(parsed.id(), envelope.id());
        assert_eq!(parsed.author(), device.id());
        let record = parsed.verify(device.public(), &vault()).unwrap();
        assert_eq!(record.id(), envelope.id());
        let body = record.body();
        assert_eq!(body.kind(), &RecordKind::Item);
        assert_eq!(body.vault_id(), &vault());
        assert_eq!(body.seq(), 0);
        assert_eq!(body.prev(), None);
        assert_eq!(body.parents(), &[RecordId([0x0a; 32])]);
        assert_eq!(body.roster(), &[RecordId([0x0b; 32])]);
        assert_eq!(body.epoch(), Some(&EpochId::from_bytes([0x0c; 16])));
        assert_eq!(body.created_at(), 1_790_000_000);
        assert!(body.unknown().is_empty());
        assert_eq!(
            &record.open_payload(&fixed_epoch_key(1)).unwrap()[..],
            b"an item"
        );
        // A fresh salt and nonce every time.
        assert_ne!(sealed().id(), envelope.id());
    }

    #[test]
    fn the_id_and_the_signed_message_are_the_contracts() {
        let envelope = sealed();
        let mut message = b"kagisecure/shared/sig/record/v1\x00".to_vec();
        message.extend_from_slice(envelope.author.as_bytes());
        message.extend_from_slice(&envelope.body);
        let mut hashed = message.clone();
        hashed.extend_from_slice(envelope.signature.as_bytes());
        assert_eq!(envelope.id().0, <[u8; 32]>::from(Sha256::digest(&hashed)));
        golden_device()
            .public()
            .verify_message(&message, &envelope.signature)
            .unwrap();
        // The envelope is the deterministic CBOR array `[1, author, body, sig]`.
        let value = cbor::decode_canonical(envelope.to_bytes()).unwrap();
        assert_eq!(
            value,
            Value::Array(vec![
                Value::Integer(1.into()),
                cbor::bytes(envelope.author.as_bytes()),
                Value::Bytes(envelope.body.clone()),
                cbor::bytes(envelope.signature.as_bytes()),
            ])
        );
    }

    #[test]
    fn a_flipped_byte_anywhere_fails_to_parse_or_to_verify() {
        let device = golden_device();
        let bytes = sealed().to_bytes().to_vec();
        for i in 0..bytes.len() {
            for bit in [0x01, 0x80] {
                let mut flipped = bytes.clone();
                flipped[i] ^= bit;
                let outcome =
                    Envelope::parse(&flipped).and_then(|e| e.verify(device.public(), &vault()));
                assert!(outcome.is_err(), "byte {i} bit {bit:#x} still verified");
            }
        }
    }

    #[test]
    fn a_record_re_signed_by_another_device_verifies_for_it_and_then_fails_to_decrypt() {
        let original = sealed();
        let thief = device_with_seed([0x33; 32]);
        let stolen = Envelope::sign_body(&thief, original.body.clone()).unwrap();
        // The signature is the thief's own and good…
        let record = stolen.verify(thief.public(), &vault()).unwrap();
        // …but the payload was bound to the real author, so it does not open.
        assert!(matches!(
            record.open_payload(&fixed_epoch_key(1)),
            Err(SharedError::Decrypt)
        ));
        // And it does not pass as the real author's.
        assert!(matches!(
            stolen.verify(golden_device().public(), &vault()),
            Err(SharedError::BadSignature)
        ));
        // Nor does the original pass as the thief's.
        assert!(matches!(
            original.verify(thief.public(), &vault()),
            Err(SharedError::BadSignature)
        ));
    }

    /// A record is verified as a record of the vault the caller reads, not of the vault it
    /// names: a member of two shared vaults could otherwise replay another member's records from
    /// one into the other under an epoch id and key reused there, and they would read as that
    /// author's in the wrong vault.
    #[test]
    fn a_record_of_another_vault_is_refused_by_verification_itself() {
        let device = golden_device();
        let envelope = sealed();
        let elsewhere = VaultId(Uuid::from_bytes([0x5b; 16]));
        assert!(matches!(
            envelope.verify(device.public(), &elsewhere),
            Err(SharedError::WrongVault)
        ));
        // The same bytes verify, and open, as a record of their own vault.
        let record = envelope.verify(device.public(), &vault()).unwrap();
        assert_eq!(
            &record.open_payload(&fixed_epoch_key(1)).unwrap()[..],
            b"an item"
        );
        // A plain record of another vault is refused the same way.
        let foreign = body_value(|e| set(e, "vault_id", cbor::bytes(&[0x5b; 16])));
        assert!(matches!(
            Envelope::sign_body(&device, foreign)
                .unwrap()
                .verify(device.public(), &vault()),
            Err(SharedError::WrongVault)
        ));
    }

    /// A body of another vault is refused as such before its version is read, so a record from
    /// another vault in a version this build does not know cannot make this vault read-only.
    #[test]
    fn another_vaults_body_is_refused_before_its_version() {
        let device = golden_device();
        let foreign_v2 = body_value(|e| {
            set(e, "vault_id", cbor::bytes(&[0x5b; 16]));
            set(e, "v", Value::Integer(2.into()));
        });
        assert!(matches!(
            Envelope::sign_body(&device, foreign_v2)
                .unwrap()
                .verify(device.public(), &vault()),
            Err(SharedError::WrongVault)
        ));
    }

    #[test]
    fn the_wrong_epoch_key_does_not_open_the_payload() {
        let record = sealed().verify(golden_device().public(), &vault()).unwrap();
        assert!(matches!(
            record.open_payload(&fixed_epoch_key(2)),
            Err(SharedError::Decrypt)
        ));
    }

    #[test]
    fn an_oversize_record_is_refused_before_it_is_read() {
        // Garbage, but over the limit: the limit is what is reported, so nothing was decoded.
        let big = vec![0xffu8; MAX_RECORD_BYTES + 1];
        assert!(matches!(
            Envelope::parse(&big),
            Err(SharedError::LimitExceeded { what: "record", .. })
        ));
        // Writing one is refused too.
        let plaintext = vec![0u8; MAX_RECORD_BYTES];
        assert!(matches!(
            Envelope::seal(
                &golden_device(),
                RecordKind::Item,
                header(0),
                &fixed_epoch_key(1),
                &plaintext
            ),
            Err(SharedError::LimitExceeded { what: "record", .. })
        ));
    }

    #[test]
    fn too_many_parents_or_roster_heads_are_refused_on_writing_and_on_reading() {
        let device = golden_device();
        let mut record = header(0);
        record.parents = vec![RecordId([1; 32]); MAX_PARENTS + 1];
        assert!(matches!(
            Envelope::seal(&device, RecordKind::Item, record, &fixed_epoch_key(1), b"x"),
            Err(SharedError::LimitExceeded {
                what: "record parents",
                ..
            })
        ));
        let mut record = header(0);
        record.roster = vec![RecordId([1; 32]); MAX_ROSTER_HEADS + 1];
        assert!(matches!(
            Envelope::sign_plain(&device, RecordKind::Ack, record, vec![]),
            Err(SharedError::LimitExceeded {
                what: "record roster heads",
                ..
            })
        ));
        let mut exactly = header(0);
        exactly.parents = vec![RecordId([1; 32]); MAX_PARENTS];
        exactly.roster = vec![RecordId([1; 32]); MAX_ROSTER_HEADS];
        assert!(
            Envelope::seal(
                &device,
                RecordKind::Item,
                exactly,
                &fixed_epoch_key(1),
                b"x"
            )
            .is_ok()
        );

        // Counted from the encoded body before it is decoded: seventeen entries that are not
        // even record ids are refused for their number, not their shape.
        let body = body_value(|e| {
            set(
                e,
                "roster",
                Value::Array(vec![Value::Integer(0.into()); MAX_ROSTER_HEADS + 1]),
            );
        });
        assert!(matches!(
            Envelope::sign_body(&device, body)
                .unwrap()
                .verify(device.public(), &vault()),
            Err(SharedError::LimitExceeded {
                what: "record roster heads",
                ..
            })
        ));

        // A body someone else wrote with seventeen parents is refused after its signature.
        let body = body_value(|e| {
            set(
                e,
                "parents",
                Value::Array(vec![cbor::bytes(&[1; 32]); MAX_PARENTS + 1]),
            );
        });
        let envelope = Envelope::sign_body(&device, body).unwrap();
        assert!(matches!(
            envelope.verify(device.public(), &vault()),
            Err(SharedError::LimitExceeded {
                what: "record parents",
                ..
            })
        ));
    }

    #[test]
    fn a_record_of_an_unknown_kind_is_kept_whole() {
        let device = golden_device();
        let body = body_value(|e| {
            set(e, "kind", cbor::text("sticky-note"));
            e.push((cbor::text("colour"), cbor::text("yellow")));
        });
        let written = Envelope::sign_body(&device, body).unwrap();
        let bytes = written.to_bytes().to_vec();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(parsed.to_bytes(), bytes.as_slice());
        assert_eq!(parsed.id(), written.id());
        let record = parsed.verify(device.public(), &vault()).unwrap();
        assert_eq!(
            record.body().kind(),
            &RecordKind::Unknown("sticky-note".to_owned())
        );
        assert_eq!(
            record.body().unknown().get("colour"),
            Some(&cbor::text("yellow"))
        );
        // It is kept, not interpreted: there is no payload to open, and this build will not
        // write one.
        assert!(record.open_payload(&fixed_epoch_key(1)).is_err());
        assert!(
            Envelope::sign_plain(
                &device,
                RecordKind::Unknown("sticky-note".to_owned()),
                header(0),
                vec![]
            )
            .is_err()
        );
    }

    #[test]
    fn a_body_version_or_envelope_version_this_build_does_not_read_is_named() {
        let device = golden_device();
        let body = body_value(|e| set(e, "v", Value::Integer(2.into())));
        let envelope = Envelope::sign_body(&device, body).unwrap();
        assert!(matches!(
            envelope.verify(device.public(), &vault()),
            Err(SharedError::UnsupportedVersion {
                what: "record body",
                version: 2
            })
        ));
        let mut bytes = envelope.to_bytes().to_vec();
        bytes[1] = 0x02;
        assert!(matches!(
            Envelope::parse(&bytes),
            Err(SharedError::UnsupportedVersion {
                what: "record envelope",
                version: 2
            })
        ));
    }

    #[test]
    fn a_body_that_is_not_the_deterministic_encoding_is_refused() {
        let device = golden_device();
        // Keys out of order: the same map with its entries unsorted.
        let good = body_value(|_| {});
        let Value::Map(mut entries) = cbor::decode_canonical(&good).unwrap() else {
            unreachable!()
        };
        entries.reverse();
        let unsorted = cbor::encode(&Value::Map(entries));
        let envelope = Envelope::sign_body(&device, unsorted).unwrap();
        assert!(matches!(
            envelope.verify(device.public(), &vault()),
            Err(SharedError::Malformed(_))
        ));
        // A missing field.
        let missing = body_value(|e| e.retain(|(k, _)| k.as_text() != Some("roster")));
        assert!(
            Envelope::sign_body(&device, missing)
                .unwrap()
                .verify(device.public(), &vault())
                .is_err()
        );
        // A previous record at seq 0, and none at seq 1.
        let prev_at_zero = body_value(|e| set(e, "prev", cbor::bytes(&[1; 32])));
        let none_at_one = body_value(|e| set(e, "seq", Value::Integer(1.into())));
        for body in [prev_at_zero, none_at_one] {
            assert!(matches!(
                Envelope::sign_body(&device, body)
                    .unwrap()
                    .verify(device.public(), &vault()),
                Err(SharedError::Malformed(_))
            ));
        }
        // An item record without an epoch.
        let item_without_epoch = body_value(|e| set(e, "kind", cbor::text("item")));
        assert!(matches!(
            Envelope::sign_body(&device, item_without_epoch)
                .unwrap()
                .verify(device.public(), &vault()),
            Err(SharedError::Malformed(_))
        ));
    }

    #[test]
    fn an_envelope_head_in_a_longer_form_is_refused() {
        let bytes = sealed().to_bytes().to_vec();
        // The author's length (0x58 0x20) written as a two-byte length (0x59 0x00 0x20).
        assert_eq!(&bytes[2..4], &[0x58, 0x20]);
        let mut longer = bytes[..2].to_vec();
        longer.extend_from_slice(&[0x59, 0x00, 0x20]);
        longer.extend_from_slice(&bytes[4..]);
        assert!(matches!(
            Envelope::parse(&longer),
            Err(SharedError::Malformed(_))
        ));
        // An indefinite-length array, trailing bytes, and a truncated record.
        let mut indefinite = bytes.clone();
        indefinite[0] = 0x9f;
        let mut trailing = bytes.clone();
        trailing.push(0);
        for bad in [indefinite, trailing, bytes[..bytes.len() - 1].to_vec()] {
            assert!(Envelope::parse(&bad).is_err());
        }
    }

    #[test]
    fn a_plain_record_is_signed_and_an_encrypted_kind_is_not_written_in_the_clear() {
        let device = golden_device();
        let mut record = header(3);
        record.epoch = None;
        let ack = Envelope::sign_plain(&device, RecordKind::Ack, record.clone(), b"hi".to_vec())
            .unwrap()
            .verify(device.public(), &vault())
            .unwrap();
        assert_eq!(ack.body().payload(), b"hi");
        assert_eq!(ack.body().seq(), 3);
        assert!(ack.open_payload(&fixed_epoch_key(1)).is_err());
        assert!(Envelope::sign_plain(&device, RecordKind::Item, header(0), vec![]).is_err());
        assert!(
            Envelope::seal(
                &device,
                RecordKind::Roster,
                header(0),
                &fixed_epoch_key(1),
                b""
            )
            .is_err()
        );
        // An item record needs its epoch.
        assert!(
            Envelope::seal(&device, RecordKind::Item, record, &fixed_epoch_key(1), b"").is_err()
        );
    }
}

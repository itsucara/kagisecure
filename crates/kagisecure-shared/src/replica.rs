//! The local replica: this device's copy of one shared vault — every record it holds, and the
//! settings that are its own (ADR-0035 §1, §8, §9, §15; addendum, decisions 22, 23; Correction
//! B; "Local-section key", "File magic", limits).
//!
//! # Where it lives
//!
//! `<personal vault file>.shared/<32 hex vault id>.kagishared` ([`replica_path`]), beside a
//! `.lock` file of its own, in a directory created owner-only (`0700`), the way the personal
//! vault's own directory is (decision 23).
//!
//! # The file
//!
//! ```text
//! magic        8 bytes    "KAGISHR\0"
//! version      1 byte     1
//! header_len   u32, BE    refused above MAX_REPLICA_HEADER_BYTES before the header is read
//! header       header_len bytes of deterministic CBOR:
//!                { "v": 1, "vault_id": bytes(16), "genesis": bytes(32), "device": bytes(32),
//!                  "suite": text, "generation": uint, "created_at": uint, …unknown keys kept }
//! count        u32, BE    refused above MAX_REPLICA_RECORDS before a record is read
//! records      count times: length (u32, BE; refused above 1 MiB) and one record envelope,
//!              in strictly increasing record-id order — so one record set has one encoding
//! local_nonce  24 bytes
//! local_ct     XChaCha20-Poly1305 of the local state under the local-section key, with every
//!              byte before local_nonce — magic through the last record — as its AAD
//! ```
//!
//! The local-section key is `HKDF-SHA256(the device's secret keys, info =
//! "kagisecure/shared/local/v1" ‖ vault_id)` (the encoding contract), so only the device named
//! in the header opens its replica, and since the AAD is everything before the local section,
//! **the whole file is authenticated by it**: a record added, removed or altered by anything
//! but this device's own writer — a sync tool, another program, a byte flipped on disk — makes
//! the file refuse to open ([`SharedError::Decrypt`]), rather than quietly change what this
//! device believes it holds. Each record is still verified on its own when a view is computed
//! (`crate::view`); the replica only stores what it was given.
//!
//! The genesis in the header is the one this device trusts (decision 41): it was written when
//! the vault was created or joined, from the creator's own record or a verified invitation, and
//! the roster is always computed from it.
//!
//! # The local state never leaves this device
//!
//! [`LocalState`] is decision 22's list: which items, fields and environments this device lets
//! agents see, its favourites, environments' default paths, which versions it approved for
//! release, which devices it verified and first saw, where its exchange directory is, and the
//! highest `seq` it has written. It is in the encrypted local section only; nothing in this
//! crate ever writes it to a bundle or an exchange directory.
//!
//! # Transactions: a lock, then a union
//!
//! [`Replica::transact`] is ADR-0039's discipline on a file of its own (Correction B): take the
//! replica's [`FileLock`], read the file as it is **now**, run the caller's closure — in memory,
//! never across a prompt — and replace the file atomically. What the closure starts from is the
//! **union** of the records on disk and the records this handle already held (ADR-0035 §8): a
//! set of signed records only grows, so a record another process added while this handle was
//! open is kept, and so is one this handle holds that the file lost — a copy restored from a
//! backup or a sync tool's older version. The local state is the file's (another process's
//! change to a setting stands, as a toggle does in the personal vault), except the highest
//! `seq` written, which never goes down: it is the larger of the file's, this handle's and every
//! `seq` of this device's own records in the union (§9's rollback guard; Correction H). Nothing
//! is written when nothing changed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ciborium::Value;
use kagisecure_core::crypto::aead;
use kagisecure_core::proto::{EnvId, FieldId, ItemId, VaultId};
use kagisecure_core::vault::atomic::{read_file_bounded, write_atomically};
use kagisecure_core::vault::lock::{DEFAULT_LOCK_TIMEOUT, FileLock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cbor;
use crate::device::{DeviceKeyId, DeviceSecret, hex};
use crate::epoch_key::vault_id_bytes;
use crate::error::{Result, SharedError};
use crate::record::{Envelope, MAX_RECORD_BYTES, RecordId};
use crate::roster::{MEMBER_ID_LEN, MemberId};
use crate::suite::Suite;

/// A replica file's first eight bytes (ADR-0035 addendum, "File magic").
pub const REPLICA_MAGIC: [u8; 8] = *b"KAGISHR\0";
/// The replica file version this build reads and writes.
pub const REPLICA_VERSION: u8 = 1;
/// The header version this build reads and writes.
pub const REPLICA_HEADER_VERSION: u64 = 1;
/// The largest replica file, in bytes (ADR-0035 addendum, limits): refused before it is read,
/// and never written.
pub const MAX_REPLICA_BYTES: u64 = 256 * 1024 * 1024;
/// The most records a replica holds: a bundle's limit, since a replica must fit in one bundle
/// to be exported whole.
pub const MAX_REPLICA_RECORDS: usize = crate::bundle::MAX_BUNDLE_RECORDS;
/// The largest replica header, in bytes.
pub const MAX_REPLICA_HEADER_BYTES: usize = 64 * 1024;
/// A replica file's extension.
pub const REPLICA_EXTENSION: &str = "kagishared";

const SHAPE: &str = "a replica is the magic, a version, a header, a bounded record list and a \
                     local section";
const HEADER_SHAPE: &str = "a replica header is a map of the fields the format names";

/// The directory beside `personal_vault` that holds its shared vaults' replicas:
/// `<personal vault file>.shared` (decision 23).
#[must_use]
pub fn shared_dir(personal_vault: &Path) -> PathBuf {
    let mut name = personal_vault.file_name().map_or_else(
        || std::ffi::OsString::from("vault"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(".shared");
    personal_vault
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

/// Where the replica of shared vault `vault_id` lives beside `personal_vault`:
/// `<personal vault file>.shared/<32 lower-case hex vault id>.kagishared` (decision 23).
#[must_use]
pub fn replica_path(personal_vault: &Path, vault_id: &VaultId) -> PathBuf {
    shared_dir(personal_vault).join(format!(
        "{}.{REPLICA_EXTENSION}",
        hex(vault_id_bytes(vault_id))
    ))
}

/// The shared vaults that have a replica beside `personal_vault`, in id order: every file in
/// its `.shared` directory named `<32 lower-case hex>.kagishared`. Nothing else there is
/// looked at, and a missing directory is no shared vaults.
///
/// # Errors
///
/// [`SharedError::Io`] if the directory exists and cannot be read.
pub fn list_replicas(personal_vault: &Path) -> Result<Vec<VaultId>> {
    let dir = shared_dir(personal_vault);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut ids = BTreeSet::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(&format!(".{REPLICA_EXTENSION}")) else {
            continue;
        };
        if let Some(bytes) = parse_hex16(stem) {
            ids.insert(VaultId(Uuid::from_bytes(bytes)));
        }
    }
    Ok(ids.into_iter().collect())
}

/// Exactly 32 lower-case hex digits, as 16 bytes.
fn parse_hex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// This device's own settings for one shared vault (decision 22). Held only in the replica's
/// encrypted local section: never exported, never in a bundle or an exchange directory.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LocalState {
    /// Items this device lets its agents see (an item record never carries this: it is
    /// cleared on writing and on reading, `crate::payload`).
    pub agent_visible_items: BTreeSet<ItemId>,
    /// Fields, per item, this device lets its agents see.
    pub agent_visible_fields: BTreeMap<ItemId, BTreeSet<FieldId>>,
    /// Environments this device lets its agents see.
    pub agent_visible_envs: BTreeSet<EnvId>,
    /// This device's favourites.
    pub favorites: BTreeSet<ItemId>,
    /// Each environment's default paths on this device.
    pub default_paths: BTreeMap<EnvId, Vec<String>>,
    /// For each field this device approved for release, the record whose value it approved
    /// (decision 26: tracked per field, not per item).
    pub approved_fields: BTreeMap<ItemId, BTreeMap<FieldId, RecordId>>,
    /// For each environment variable this device approved for release, the record whose value
    /// it approved.
    pub approved_vars: BTreeMap<EnvId, BTreeMap<String, RecordId>>,
    /// Devices whose fingerprints this device's person compared, and when (unix seconds; §10).
    pub verified_devices: BTreeMap<DeviceKeyId, u64>,
    /// Devices this device first saw without a comparison, and when (TOFU, §10).
    pub first_seen: BTreeMap<DeviceKeyId, u64>,
    /// The exchange directory this device reads and writes, if one is configured.
    pub exchange_dir: Option<String>,
    /// The highest `seq` this device has written in this vault: never lowered (§9's rollback
    /// guard).
    pub highest_seq: Option<u64>,
    /// The vault's name, as this device knows it: set by its creator and carried by the
    /// invitation (decision 81). Never in a record.
    pub vault_name: Option<String>,
    /// The names this device's person knows other members by — typed when inviting them, or
    /// when naming them afterwards. Never in a record, since roster labels' sealing is still
    /// undecided (decision 81), so each device keeps its own.
    pub member_names: BTreeMap<MemberId, String>,
    /// Keys of the local state this build does not know, kept as read.
    pub unknown: BTreeMap<String, Value>,
}

/// [`LocalState`] as it is encoded: ids as byte strings.
#[derive(Serialize, Deserialize)]
struct LocalWire {
    #[serde(default)]
    agent_visible_items: BTreeSet<ItemId>,
    #[serde(default)]
    agent_visible_fields: BTreeMap<ItemId, BTreeSet<FieldId>>,
    #[serde(default)]
    agent_visible_envs: BTreeSet<EnvId>,
    #[serde(default)]
    favorites: BTreeSet<ItemId>,
    #[serde(default)]
    default_paths: BTreeMap<EnvId, Vec<String>>,
    #[serde(default)]
    approved_fields: BTreeMap<ItemId, BTreeMap<FieldId, serde_bytes::ByteBuf>>,
    #[serde(default)]
    approved_vars: BTreeMap<EnvId, BTreeMap<String, serde_bytes::ByteBuf>>,
    #[serde(default)]
    verified_devices: BTreeMap<serde_bytes::ByteBuf, u64>,
    #[serde(default)]
    first_seen: BTreeMap<serde_bytes::ByteBuf, u64>,
    #[serde(default)]
    exchange_dir: Option<String>,
    #[serde(default)]
    highest_seq: Option<u64>,
    #[serde(default)]
    vault_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    member_names: BTreeMap<serde_bytes::ByteBuf, String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, Value>,
}

const LOCAL_SHAPE: &str = "the replica's local state is a map of the fields the format names";

fn id32(bytes: &serde_bytes::ByteBuf) -> Result<[u8; 32]> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SharedError::Malformed(LOCAL_SHAPE))
}

impl LocalState {
    fn to_wire(&self) -> LocalWire {
        let record = |id: &RecordId| serde_bytes::ByteBuf::from(id.as_bytes().to_vec());
        let device = |id: &DeviceKeyId| serde_bytes::ByteBuf::from(id.as_bytes().to_vec());
        LocalWire {
            agent_visible_items: self.agent_visible_items.clone(),
            agent_visible_fields: self.agent_visible_fields.clone(),
            agent_visible_envs: self.agent_visible_envs.clone(),
            favorites: self.favorites.clone(),
            default_paths: self.default_paths.clone(),
            approved_fields: self
                .approved_fields
                .iter()
                .map(|(item, fields)| {
                    let fields = fields.iter().map(|(f, r)| (*f, record(r))).collect();
                    (*item, fields)
                })
                .collect(),
            approved_vars: self
                .approved_vars
                .iter()
                .map(|(env, vars)| {
                    let vars = vars.iter().map(|(v, r)| (v.clone(), record(r))).collect();
                    (*env, vars)
                })
                .collect(),
            verified_devices: self
                .verified_devices
                .iter()
                .map(|(d, at)| (device(d), *at))
                .collect(),
            first_seen: self
                .first_seen
                .iter()
                .map(|(d, at)| (device(d), *at))
                .collect(),
            exchange_dir: self.exchange_dir.clone(),
            highest_seq: self.highest_seq,
            vault_name: self.vault_name.clone(),
            member_names: self
                .member_names
                .iter()
                .map(|(m, name)| {
                    (
                        serde_bytes::ByteBuf::from(m.as_bytes().to_vec()),
                        name.clone(),
                    )
                })
                .collect(),
            unknown: self.unknown.clone(),
        }
    }

    fn from_wire(wire: LocalWire) -> Result<Self> {
        let record = |b: &serde_bytes::ByteBuf| id32(b).map(RecordId::from_bytes);
        let device = |b: &serde_bytes::ByteBuf| id32(b).map(DeviceKeyId::from_bytes);
        Ok(Self {
            agent_visible_items: wire.agent_visible_items,
            agent_visible_fields: wire.agent_visible_fields,
            agent_visible_envs: wire.agent_visible_envs,
            favorites: wire.favorites,
            default_paths: wire.default_paths,
            approved_fields: wire
                .approved_fields
                .iter()
                .map(|(item, fields)| {
                    let fields = fields
                        .iter()
                        .map(|(f, r)| Ok((*f, record(r)?)))
                        .collect::<Result<_>>()?;
                    Ok((*item, fields))
                })
                .collect::<Result<_>>()?,
            approved_vars: wire
                .approved_vars
                .iter()
                .map(|(env, vars)| {
                    let vars = vars
                        .iter()
                        .map(|(v, r)| Ok((v.clone(), record(r)?)))
                        .collect::<Result<_>>()?;
                    Ok((*env, vars))
                })
                .collect::<Result<_>>()?,
            verified_devices: wire
                .verified_devices
                .iter()
                .map(|(d, at)| Ok((device(d)?, *at)))
                .collect::<Result<_>>()?,
            first_seen: wire
                .first_seen
                .iter()
                .map(|(d, at)| Ok((device(d)?, *at)))
                .collect::<Result<_>>()?,
            exchange_dir: wire.exchange_dir,
            highest_seq: wire.highest_seq,
            vault_name: wire.vault_name,
            member_names: wire
                .member_names
                .into_iter()
                .map(|(m, name)| {
                    let bytes: [u8; MEMBER_ID_LEN] = m
                        .as_slice()
                        .try_into()
                        .map_err(|_| SharedError::Malformed(LOCAL_SHAPE))?;
                    Ok((MemberId::from_bytes(bytes), name))
                })
                .collect::<Result<_>>()?,
            unknown: wire.unknown,
        })
    }

    /// Raise [`Self::highest_seq`] to `seq` if it is lower. It is never lowered.
    pub fn saw_own_seq(&mut self, seq: u64) {
        self.highest_seq = Some(self.highest_seq.map_or(seq, |h| h.max(seq)));
    }
}

/// A replica's header: which vault, from which genesis, whose local section.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplicaHeader {
    vault_id: VaultId,
    genesis: RecordId,
    device: DeviceKeyId,
    suite: Suite,
    generation: u64,
    created_at: u64,
    unknown: BTreeMap<String, Value>,
}

impl ReplicaHeader {
    /// The shared vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The genesis this device trusts for the vault (decision 41).
    #[must_use]
    pub const fn genesis(&self) -> RecordId {
        self.genesis
    }

    /// The device whose replica this is: the only one whose key opens its local section.
    #[must_use]
    pub const fn device(&self) -> DeviceKeyId {
        self.device
    }

    /// The vault's suite.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// How many times the file has been written: 1 when created, one more on every write. A
    /// later rollback anchor (ADR-0041) compares it; nothing here decides anything by it.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// When the replica was created, in unix seconds, as this device's clock said.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (
                cbor::text("v"),
                Value::Integer(REPLICA_HEADER_VERSION.into()),
            ),
            (
                cbor::text("vault_id"),
                cbor::bytes(vault_id_bytes(&self.vault_id)),
            ),
            (cbor::text("genesis"), cbor::bytes(self.genesis.as_bytes())),
            (cbor::text("device"), cbor::bytes(self.device.as_bytes())),
            (cbor::text("suite"), cbor::text(self.suite.name())),
            (
                cbor::text("generation"),
                Value::Integer(self.generation.into()),
            ),
            (
                cbor::text("created_at"),
                Value::Integer(self.created_at.into()),
            ),
        ];
        entries.extend(self.unknown.iter().map(|(k, v)| (cbor::text(k), v.clone())));
        cbor::encode(&cbor::map(entries))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut v = None;
        let mut vault_id = None;
        let mut genesis = None;
        let mut device = None;
        let mut suite = None;
        let mut generation = None;
        let mut created_at = None;
        let mut unknown = BTreeMap::new();
        for (key, value) in cbor::text_map(cbor::decode_canonical(bytes)?, HEADER_SHAPE)? {
            match key.as_str() {
                "v" => v = Some(cbor::uint(&value, HEADER_SHAPE)?),
                "vault_id" => {
                    vault_id = Some(VaultId(Uuid::from_bytes(cbor::fixed_bytes(
                        &value,
                        HEADER_SHAPE,
                    )?)));
                }
                "genesis" => {
                    genesis = Some(RecordId::from_bytes(cbor::fixed_bytes(
                        &value,
                        HEADER_SHAPE,
                    )?));
                }
                "device" => {
                    device = Some(DeviceKeyId::from_bytes(cbor::fixed_bytes(
                        &value,
                        HEADER_SHAPE,
                    )?));
                }
                "suite" => {
                    let Value::Text(name) = value else {
                        return Err(SharedError::Malformed(HEADER_SHAPE));
                    };
                    suite = Some(Suite::from_name(&name)?);
                }
                "generation" => generation = Some(cbor::uint(&value, HEADER_SHAPE)?),
                "created_at" => created_at = Some(cbor::uint(&value, HEADER_SHAPE)?),
                _ => {
                    unknown.insert(key, value);
                }
            }
        }
        let v = v.ok_or(SharedError::Malformed(HEADER_SHAPE))?;
        if v != REPLICA_HEADER_VERSION {
            return Err(SharedError::UnsupportedVersion {
                what: "replica header",
                version: v,
            });
        }
        let (
            Some(vault_id),
            Some(genesis),
            Some(device),
            Some(suite),
            Some(generation),
            Some(created_at),
        ) = (vault_id, genesis, device, suite, generation, created_at)
        else {
            return Err(SharedError::Malformed(HEADER_SHAPE));
        };
        Ok(Self {
            vault_id,
            genesis,
            device,
            suite,
            generation,
            created_at,
            unknown,
        })
    }
}

/// What a replica file holds, read and authenticated.
struct Contents {
    header: ReplicaHeader,
    records: BTreeMap<RecordId, Envelope>,
    local: LocalState,
}

/// Reads the file's framing, each length checked before the bytes it names.
struct Framing<'a> {
    rest: &'a [u8],
}

impl<'a> Framing<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.rest.len() {
            return Err(SharedError::Malformed(SHAPE));
        }
        let (taken, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(taken)
    }

    fn u32(&mut self) -> Result<usize> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
        usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| SharedError::Malformed(SHAPE))
    }
}

/// Parse and authenticate a replica file's bytes as `device`'s.
fn decode(bytes: &[u8], device: &DeviceSecret) -> Result<Contents> {
    if bytes.len() as u64 > MAX_REPLICA_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "replica",
            limit: MAX_REPLICA_BYTES,
        });
    }
    let mut framing = Framing { rest: bytes };
    if framing.take(REPLICA_MAGIC.len())? != REPLICA_MAGIC {
        return Err(SharedError::Malformed("not a shared-vault replica"));
    }
    let version = framing.take(1)?[0];
    if version != REPLICA_VERSION {
        return Err(SharedError::UnsupportedVersion {
            what: "replica",
            version: u64::from(version),
        });
    }
    let header_len = framing.u32()?;
    if header_len > MAX_REPLICA_HEADER_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "replica header",
            limit: MAX_REPLICA_HEADER_BYTES as u64,
        });
    }
    let header = ReplicaHeader::decode(framing.take(header_len)?)?;
    if header.device != device.id() {
        return Err(SharedError::ReplicaMismatch(
            "it is another device's replica",
        ));
    }
    let count = framing.u32()?;
    if count > MAX_REPLICA_RECORDS {
        return Err(SharedError::LimitExceeded {
            what: "replica records",
            limit: MAX_REPLICA_RECORDS as u64,
        });
    }
    let mut records = BTreeMap::new();
    let mut previous: Option<RecordId> = None;
    for _ in 0..count {
        let len = framing.u32()?;
        if len > MAX_RECORD_BYTES {
            return Err(SharedError::LimitExceeded {
                what: "record",
                limit: MAX_RECORD_BYTES as u64,
            });
        }
        let envelope = Envelope::parse(framing.take(len)?)?;
        // One record set, one encoding: strictly increasing ids, so no record twice.
        if previous.is_some_and(|previous| previous >= envelope.id()) {
            return Err(SharedError::Malformed(
                "a replica's records are in increasing id order, each once",
            ));
        }
        previous = Some(envelope.id());
        records.insert(envelope.id(), envelope);
    }
    let aad_len = bytes.len() - framing.rest.len();
    let nonce: [u8; aead::NONCE_LEN] = framing
        .take(aead::NONCE_LEN)?
        .try_into()
        .expect("the nonce's length");
    let key = device.local_key(&header.vault_id);
    let plaintext = aead::open(&key, &nonce, &bytes[..aad_len], framing.rest)
        .map_err(|_| SharedError::Decrypt)?;
    cbor::scan(&plaintext, cbor::Strictness::WellFormed)
        .map_err(|_| SharedError::Malformed(LOCAL_SHAPE))?;
    let wire: LocalWire = ciborium::from_reader(plaintext.as_slice())
        .map_err(|_| SharedError::Malformed(LOCAL_SHAPE))?;
    Ok(Contents {
        header,
        records,
        local: LocalState::from_wire(wire)?,
    })
}

/// The header of a replica file's bytes, read **without authentication**: only for rebuilding a
/// replica whose file no longer opens ([`Replica::rebuild_from`]).
fn peek_header(bytes: &[u8]) -> Option<ReplicaHeader> {
    let mut framing = Framing { rest: bytes };
    if framing.take(REPLICA_MAGIC.len()).ok()? != REPLICA_MAGIC
        || framing.take(1).ok()? != [REPLICA_VERSION]
    {
        return None;
    }
    let len = framing.u32().ok()?;
    if len > MAX_REPLICA_HEADER_BYTES {
        return None;
    }
    ReplicaHeader::decode(framing.take(len).ok()?).ok()
}

/// Where [`Replica::rebuild_from`] takes the records from.
#[derive(Clone, Copy, Debug)]
pub enum RebuildSource<'a> {
    /// An exchange directory: its `records/<64 hex>.ksr` files.
    Dir(&'a Path),
    /// A bundle file's bytes.
    Bundle(&'a [u8]),
}

/// Encode a replica file, sealing its local section as `device`'s.
fn encode(
    header: &ReplicaHeader,
    records: &BTreeMap<RecordId, Envelope>,
    local: &LocalState,
    device: &DeviceSecret,
) -> Result<Vec<u8>> {
    if records.len() > MAX_REPLICA_RECORDS {
        return Err(SharedError::LimitExceeded {
            what: "replica records",
            limit: MAX_REPLICA_RECORDS as u64,
        });
    }
    let header_bytes = header.encode();
    if header_bytes.len() > MAX_REPLICA_HEADER_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "replica header",
            limit: MAX_REPLICA_HEADER_BYTES as u64,
        });
    }
    let plaintext = crate::payload::encode(&local.to_wire())?;
    let size = REPLICA_MAGIC.len() as u64
        + 1
        + 4
        + header_bytes.len() as u64
        + 4
        + records
            .values()
            .map(|r| 4 + r.to_bytes().len() as u64)
            .sum::<u64>()
        + aead::NONCE_LEN as u64
        + plaintext.len() as u64
        + aead::TAG_LEN as u64;
    if size > MAX_REPLICA_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "replica",
            limit: MAX_REPLICA_BYTES,
        });
    }
    let len = |n: usize| -> Result<[u8; 4]> {
        u32::try_from(n)
            .map(u32::to_be_bytes)
            .map_err(|_| SharedError::Malformed(SHAPE))
    };
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    out.extend_from_slice(&REPLICA_MAGIC);
    out.push(REPLICA_VERSION);
    out.extend_from_slice(&len(header_bytes.len())?);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&len(records.len())?);
    for record in records.values() {
        out.extend_from_slice(&len(record.to_bytes().len())?);
        out.extend_from_slice(record.to_bytes());
    }
    let nonce = aead::nonce()?;
    let key = device.local_key(&header.vault_id);
    let sealed = aead::seal(&key, &nonce, &out, &plaintext)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The highest `seq` among `device`'s own records in `records`. Read from bodies not verified
/// here — they are this device's own, and a number read from them can only raise the rollback
/// guard, never lower it.
fn own_highest_seq(records: &BTreeMap<RecordId, Envelope>, device: &DeviceKeyId) -> Option<u64> {
    records
        .values()
        .filter(|r| r.author() == *device)
        .filter_map(|r| r.body_unverified().ok().map(|b| b.seq()))
        .max()
}

/// Create the directory a replica lives in, owner-only (decision 23).
fn create_dir(path: &Path) -> Result<()> {
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    // Elsewhere the lock creates it, with the owner-only descriptor the atomic write uses.
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Read the replica at `path` as `device`'s; `None` if there is no file.
fn read(path: &Path, device: &DeviceSecret) -> Result<Option<Contents>> {
    match read_file_bounded(path, MAX_REPLICA_BYTES) {
        Ok(bytes) => decode(&bytes, device).map(Some),
        Err(kagisecure_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(kagisecure_core::Error::VaultTooLarge { .. }) => Err(SharedError::LimitExceeded {
            what: "replica",
            limit: MAX_REPLICA_BYTES,
        }),
        Err(e) => Err(e.into()),
    }
}

/// One shared vault's local replica, open. See the module documentation.
pub struct Replica {
    path: PathBuf,
    header: ReplicaHeader,
    records: BTreeMap<RecordId, Envelope>,
    local: LocalState,
    lock_timeout: Duration,
}

impl Replica {
    /// Create the replica of shared vault `vault_id` at `path` for `device`, holding `records`
    /// (the genesis among them) and `local`. `genesis` is the vault's genesis as this device
    /// trusts it — its own record when it creates the vault, a verified invitation's when it
    /// joins (decision 41). Refuses to replace a file already there.
    ///
    /// # Errors
    ///
    /// [`SharedError::GenesisMissing`] if `genesis` is not among `records`;
    /// [`SharedError::Io`] of kind [`std::io::ErrorKind::AlreadyExists`] if a replica is
    /// already at `path`; [`SharedError::LimitExceeded`] for a replica over the limits; and
    /// whatever the lock or the write refuse.
    pub fn create(
        path: &Path,
        device: &DeviceSecret,
        vault_id: VaultId,
        genesis: RecordId,
        records: &[Envelope],
        mut local: LocalState,
        created_at: u64,
    ) -> Result<Self> {
        let records: BTreeMap<RecordId, Envelope> =
            records.iter().map(|r| (r.id(), r.clone())).collect();
        if !records.contains_key(&genesis) {
            return Err(SharedError::GenesisMissing);
        }
        create_dir(path)?;
        let lock = FileLock::acquire(path, DEFAULT_LOCK_TIMEOUT)?;
        lock.sweep_stale_temporaries();
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "a shared-vault replica already exists at this path",
            )
            .into());
        }
        if let Some(seq) = own_highest_seq(&records, &device.id()) {
            local.saw_own_seq(seq);
        }
        let header = ReplicaHeader {
            vault_id,
            genesis,
            device: device.id(),
            suite: device.public().suite(),
            generation: 1,
            created_at,
            unknown: BTreeMap::new(),
        };
        let bytes = encode(&header, &records, &local, device)?;
        lock.ensure_current()?;
        write_atomically(path, &bytes)?;
        Ok(Self {
            path: path.to_owned(),
            header,
            records,
            local,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        })
    }

    /// Open the replica at `path` as `device`'s.
    ///
    /// # Errors
    ///
    /// [`SharedError::Io`] of kind [`std::io::ErrorKind::NotFound`] if there is none;
    /// [`SharedError::ReplicaMismatch`] if it is another device's; [`SharedError::Decrypt`] if
    /// its local section does not open — the file was altered, or written with another key;
    /// [`SharedError::Malformed`], [`SharedError::LimitExceeded`] or
    /// [`SharedError::UnsupportedVersion`] for a file that is not a replica this build reads.
    pub fn open(path: &Path, device: &DeviceSecret) -> Result<Self> {
        let contents = read(path, device)?.ok_or_else(|| {
            SharedError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no shared-vault replica at this path",
            ))
        })?;
        Ok(Self {
            path: path.to_owned(),
            header: contents.header,
            records: contents.records,
            local: contents.local,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        })
    }

    /// Rebuild the replica at `path` for `device` from `source`, when the file refuses to open
    /// (decision 85): a byte altered on disk, a sync tool's partial copy, a lost local section.
    ///
    /// Which vault and genesis: from the old file's header if it still parses and names this
    /// device — read without authentication, since the file no longer authenticates — else the
    /// vault id in the file's name and the one genesis among `source`'s records whose roster
    /// has this device in it. The old file, if any, is kept beside the new one as
    /// `<name>.damaged-<now>`, never deleted. The local state starts empty (the rollback guard
    /// is set from this device's own records), with a directory source as its exchange
    /// directory.
    ///
    /// # Errors
    ///
    /// [`SharedError::Refused`] if no single genesis fits, [`SharedError::GenesisMissing`] or
    /// [`SharedError::InvalidGenesis`] as for a roster, and whatever reading `source`, the
    /// rename or the write refuse.
    pub fn rebuild_from(
        path: &Path,
        device: &DeviceSecret,
        source: RebuildSource<'_>,
        now: u64,
    ) -> Result<Self> {
        let records = match source {
            RebuildSource::Dir(dir) => {
                crate::exchange::import(&crate::admin::exchange::records_dir(dir))?
            }
            RebuildSource::Bundle(bytes) => crate::bundle::parse(bytes)?,
        };
        let old = std::fs::read(path).ok();
        let from_header = old
            .as_deref()
            .and_then(peek_header)
            .filter(|header| header.device == device.id())
            .map(|header| (header.vault_id, header.genesis));
        let (vault_id, genesis) = match from_header {
            Some(found) => found,
            None => {
                let vault_id = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_suffix(&format!(".{REPLICA_EXTENSION}")))
                    .and_then(parse_hex16)
                    .map(|b| VaultId(Uuid::from_bytes(b)))
                    .ok_or(SharedError::Refused(
                        "the replica's file name does not name a shared vault",
                    ))?;
                let fits: Vec<RecordId> = records
                    .iter()
                    .filter(|r| {
                        r.body_unverified().is_ok_and(|b| {
                            b.seq() == 0
                                && b.kind() == &crate::record::RecordKind::Roster
                                && matches!(
                                    crate::roster::RosterOp::from_payload(b.payload()),
                                    Ok(crate::roster::RosterOp::Genesis { .. })
                                )
                        })
                    })
                    .map(Envelope::id)
                    .filter(|g| {
                        crate::roster::RosterState::compute(&vault_id, g, &records).is_ok_and(
                            |roster| {
                                roster
                                    .snapshot()
                                    .device(&device.id())
                                    .is_some_and(|d| d.active)
                            },
                        )
                    })
                    .collect();
                let [genesis] = fits[..] else {
                    return Err(SharedError::Refused(
                        "no single genesis among the records includes this device",
                    ));
                };
                (vault_id, genesis)
            }
        };
        // The roster must compute from that genesis before anything is moved.
        crate::roster::RosterState::compute(&vault_id, &genesis, &records)?;
        if old.is_some() {
            let mut damaged = path.as_os_str().to_owned();
            damaged.push(format!(".damaged-{now}"));
            std::fs::rename(path, PathBuf::from(damaged))?;
        }
        let local = LocalState {
            exchange_dir: match source {
                RebuildSource::Dir(dir) => Some(crate::admin::exchange::path_text(dir)?),
                RebuildSource::Bundle(_) => None,
            },
            ..LocalState::default()
        };
        Self::create(path, device, vault_id, genesis, &records, local, now)
    }

    /// How long [`Self::transact`] waits for another writer.
    pub fn set_lock_timeout(&mut self, timeout: Duration) {
        self.lock_timeout = timeout;
    }

    /// Where the replica is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Its header.
    #[must_use]
    pub const fn header(&self) -> &ReplicaHeader {
        &self.header
    }

    /// The shared vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.header.vault_id
    }

    /// The genesis this device trusts.
    #[must_use]
    pub const fn genesis(&self) -> RecordId {
        self.header.genesis
    }

    /// Every record it holds, in id order.
    pub fn records(&self) -> impl Iterator<Item = &Envelope> {
        self.records.values()
    }

    /// Every record it holds, in id order, as a list — what a view is computed from.
    #[must_use]
    pub fn envelopes(&self) -> Vec<Envelope> {
        self.records.values().cloned().collect()
    }

    /// Whether it holds `id`.
    #[must_use]
    pub fn contains(&self, id: &RecordId) -> bool {
        self.records.contains_key(id)
    }

    /// This device's own settings.
    #[must_use]
    pub const fn local(&self) -> &LocalState {
        &self.local
    }

    /// Run `f` as one transaction (module documentation): under the replica's lock, from the
    /// union of what is on disk and what this handle holds, then written atomically — or not
    /// at all, if `f` fails or changes nothing.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns, which leaves the file and this handle unchanged;
    /// [`SharedError::ReplicaMismatch`] if the file at the path is now another vault's,
    /// another genesis's or another device's; and whatever reading, the lock or the write
    /// refuse.
    pub fn transact<R>(
        &mut self,
        device: &DeviceSecret,
        f: impl FnOnce(&mut ReplicaTx<'_>) -> Result<R>,
    ) -> Result<R> {
        if device.id() != self.header.device {
            return Err(SharedError::ReplicaMismatch(
                "it is another device's replica",
            ));
        }
        let lock = FileLock::acquire(&self.path, self.lock_timeout)?;
        lock.sweep_stale_temporaries();
        let on_disk = read(&self.path, device)?;
        let mut records = self.records.clone();
        let (mut local, generation) = match &on_disk {
            Some(disk) => {
                if disk.header.vault_id != self.header.vault_id {
                    return Err(SharedError::ReplicaMismatch(
                        "it is another shared vault's replica",
                    ));
                }
                if disk.header.genesis != self.header.genesis {
                    return Err(SharedError::ReplicaMismatch("it names another genesis"));
                }
                for (id, record) in &disk.records {
                    records.entry(*id).or_insert_with(|| record.clone());
                }
                let mut local = disk.local.clone();
                if let Some(seq) = self.local.highest_seq {
                    local.saw_own_seq(seq);
                }
                (local, disk.header.generation.max(self.header.generation))
            }
            None => (self.local.clone(), self.header.generation),
        };
        let mut tx = ReplicaTx {
            vault_id: self.header.vault_id,
            genesis: self.header.genesis,
            records: &mut records,
            local: &mut local,
            added: Vec::new(),
        };
        let out = f(&mut tx)?;
        if let Some(seq) = own_highest_seq(&records, &device.id()) {
            local.saw_own_seq(seq);
        }
        let unchanged = on_disk.as_ref().is_some_and(|disk| {
            disk.local == local
                && disk.records.len() == records.len()
                && disk.records.keys().eq(records.keys())
        });
        if unchanged {
            // Nothing to write; this handle catches up with the file.
            let disk = on_disk.expect("unchanged only when there is a file");
            self.header = disk.header;
            self.records = records;
            self.local = local;
            return Ok(out);
        }
        let mut header = self.header.clone();
        if let Some(disk) = &on_disk {
            header.unknown.clone_from(&disk.header.unknown);
        }
        header.generation = generation.saturating_add(1);
        let bytes = encode(&header, &records, &local, device)?;
        lock.ensure_current()?;
        write_atomically(&self.path, &bytes)?;
        self.header = header;
        self.records = records;
        self.local = local;
        Ok(out)
    }
}

impl std::fmt::Debug for Replica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ids and counts only: nothing of the local state.
        f.debug_struct("Replica")
            .field("vault_id", &self.header.vault_id)
            .field("genesis", &self.header.genesis)
            .field("device", &self.header.device)
            .field("generation", &self.header.generation)
            .field("records", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// One transaction on a replica: the union of its records, and its local state, to change.
pub struct ReplicaTx<'a> {
    vault_id: VaultId,
    genesis: RecordId,
    records: &'a mut BTreeMap<RecordId, Envelope>,
    local: &'a mut LocalState,
    added: Vec<RecordId>,
}

impl ReplicaTx<'_> {
    /// The shared vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The genesis this device trusts.
    #[must_use]
    pub const fn genesis(&self) -> RecordId {
        self.genesis
    }

    /// Every record, in id order: what was on disk, what this handle held, and what this
    /// transaction added.
    pub fn records(&self) -> impl Iterator<Item = &Envelope> {
        self.records.values()
    }

    /// Every record, as a list.
    #[must_use]
    pub fn envelopes(&self) -> Vec<Envelope> {
        self.records.values().cloned().collect()
    }

    /// Whether the replica holds `id`.
    #[must_use]
    pub fn contains(&self, id: &RecordId) -> bool {
        self.records.contains_key(id)
    }

    /// Add a record; `true` if it is new. Records are only ever added: a replica is a
    /// grow-only set (ADR-0035 §8). Whether it is valid is decided when a view is computed, not
    /// here.
    pub fn add(&mut self, envelope: Envelope) -> bool {
        let id = envelope.id();
        if self.records.contains_key(&id) {
            return false;
        }
        self.records.insert(id, envelope);
        self.added.push(id);
        true
    }

    /// The records this transaction added, in the order they were added.
    #[must_use]
    pub fn added(&self) -> &[RecordId] {
        &self.added
    }

    /// This device's own settings.
    #[must_use]
    pub fn local(&self) -> &LocalState {
        self.local
    }

    /// This device's own settings, to change.
    pub fn local_mut(&mut self) -> &mut LocalState {
        self.local
    }
}

impl std::fmt::Debug for ReplicaTx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplicaTx")
            .field("vault_id", &self.vault_id)
            .field("records", &self.records.len())
            .field("added", &self.added.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::Role;
    use crate::roster::tests::{Records, add_member, member};
    use crate::test_support::{Writer, test_vault};

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A vault created by Alice, and a replica of it beside `personal` for her device.
    fn created(personal: &Path, alice: &mut Writer) -> (Replica, Records) {
        let records = Records::create(alice, member(1));
        let path = replica_path(personal, &test_vault());
        let replica = Replica::create(
            &path,
            &alice.device,
            test_vault(),
            records.genesis,
            &records.records,
            LocalState::default(),
            1_790_000_000,
        )
        .unwrap();
        (replica, records)
    }

    #[test]
    fn a_replica_lives_beside_the_personal_vault_under_its_vault_id() {
        let personal = Path::new("/home/someone/vault.kagivault");
        let path = replica_path(personal, &test_vault());
        assert_eq!(
            path,
            Path::new(
                "/home/someone/vault.kagivault.shared/5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a.kagishared"
            )
        );
        assert_eq!(
            kagisecure_core::vault::lock::lock_path(&path),
            Path::new(
                "/home/someone/vault.kagivault.shared/\
                 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a.kagishared.lock"
            )
        );
    }

    #[test]
    fn a_created_replica_opens_with_its_records_and_local_state() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut replica, records) = created(&personal, &mut alice);
        assert_eq!(replica.header().generation(), 1);
        // The genesis is Alice's seq 0: the rollback guard already knows it.
        assert_eq!(replica.local().highest_seq, Some(0));

        let item = ItemId::new();
        let field = FieldId::new();
        let other = Writer::new(9);
        replica
            .transact(&alice.device, |tx| {
                let local = tx.local_mut();
                local.agent_visible_items.insert(item);
                local
                    .agent_visible_fields
                    .entry(item)
                    .or_default()
                    .insert(field);
                local.favorites.insert(item);
                local
                    .approved_fields
                    .entry(item)
                    .or_default()
                    .insert(field, records.genesis);
                local.verified_devices.insert(other.id(), 7);
                local.exchange_dir = Some("/somewhere/exchange".to_owned());
                local
                    .member_names
                    .insert(MemberId::from_bytes([3; MEMBER_ID_LEN]), "Bob".to_owned());
                local
                    .unknown
                    .insert("later".to_owned(), Value::Integer(5.into()));
                Ok(())
            })
            .unwrap();
        assert_eq!(replica.header().generation(), 2);

        let opened = Replica::open(replica.path(), &alice.device).unwrap();
        assert_eq!(opened.local(), replica.local());
        assert_eq!(opened.genesis(), records.genesis);
        assert_eq!(
            opened.records().map(Envelope::id).collect::<Vec<_>>(),
            vec![records.genesis]
        );
        assert_eq!(list_replicas(&personal).unwrap(), vec![test_vault()]);
        assert!(list_replicas(&dir.path().join("none")).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_replica_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (replica, _) = created(&personal, &mut alice);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(replica.path()), 0o600);
        assert_eq!(mode(&shared_dir(&personal)), 0o700);
    }

    #[test]
    fn create_never_replaces_a_replica() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (replica, records) = created(&personal, &mut alice);
        let again = Replica::create(
            replica.path(),
            &alice.device,
            test_vault(),
            records.genesis,
            &records.records,
            LocalState::default(),
            0,
        );
        assert!(
            matches!(again, Err(SharedError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
        );
        let missing = Replica::create(
            &dir.path().join("other.kagishared"),
            &alice.device,
            test_vault(),
            RecordId::from_bytes([1; 32]),
            &records.records,
            LocalState::default(),
            0,
        );
        assert!(matches!(missing, Err(SharedError::GenesisMissing)));
    }

    #[test]
    fn only_the_device_it_belongs_to_opens_it() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut replica, _) = created(&personal, &mut alice);
        let bob = Writer::new(2);
        assert!(matches!(
            Replica::open(replica.path(), &bob.device),
            Err(SharedError::ReplicaMismatch(_))
        ));
        assert!(matches!(
            replica.transact(&bob.device, |_| Ok(())),
            Err(SharedError::ReplicaMismatch(_))
        ));
    }

    #[test]
    fn any_byte_altered_anywhere_refuses_the_file() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (replica, _) = created(&personal, &mut alice);
        let bytes = std::fs::read(replica.path()).unwrap();
        for at in 0..bytes.len() {
            let mut altered = bytes.clone();
            altered[at] ^= 0x01;
            assert!(
                decode(&altered, &alice.device).is_err(),
                "byte {at} altered and still read"
            );
        }
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len], &alice.device).is_err());
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer, &alice.device).is_err());
    }

    #[test]
    fn a_record_slipped_into_the_file_makes_it_refuse_to_open() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (replica, records) = created(&personal, &mut alice);
        let extra = alice.roster(&add_member(member(2), Role::Writer), &[records.genesis]);
        let old = std::fs::read(replica.path()).unwrap();
        let mut both = replica.records.clone();
        both.insert(extra.id(), extra);
        let rewritten = encode(replica.header(), &both, replica.local(), &alice.device).unwrap();
        // The records of the rewritten file, followed by the old file's local section: the
        // section's AAD no longer matches.
        let mut spliced = rewritten[..local_start(&rewritten)].to_vec();
        spliced.extend_from_slice(&old[local_start(&old)..]);
        assert!(matches!(
            decode(&spliced, &alice.device),
            Err(SharedError::Decrypt)
        ));
        assert!(decode(&rewritten, &alice.device).is_ok());
    }

    /// Where a replica's local section starts.
    fn local_start(bytes: &[u8]) -> usize {
        let mut framing = Framing { rest: bytes };
        framing.take(9).unwrap();
        let header_len = framing.u32().unwrap();
        framing.take(header_len).unwrap();
        let count = framing.u32().unwrap();
        for _ in 0..count {
            let len = framing.u32().unwrap();
            framing.take(len).unwrap();
        }
        bytes.len() - framing.rest.len()
    }

    #[test]
    fn a_wrong_magic_or_version_is_refused_by_name() {
        let alice = Writer::new(1);
        assert!(matches!(
            decode(b"KAGISBN\0\x01", &alice.device),
            Err(SharedError::Malformed(_))
        ));
        assert!(matches!(
            decode(b"KAGISHR\0\x02", &alice.device),
            Err(SharedError::UnsupportedVersion {
                what: "replica",
                version: 2
            })
        ));
    }

    #[test]
    fn two_handles_writing_in_turn_keep_both_records() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut first, records) = created(&personal, &mut alice);
        let mut second = Replica::open(first.path(), &alice.device).unwrap();
        let g = records.genesis;
        let one = alice.roster(&add_member(member(2), Role::Writer), &[g]);
        let two = alice.roster(&add_member(member(3), Role::Writer), &[one.id()]);
        let (one_id, two_id) = (one.id(), two.id());
        first.transact(&alice.device, |tx| Ok(tx.add(one))).unwrap();
        // `second` never saw `one`, but its transaction starts from the file.
        let added = second
            .transact(&alice.device, |tx| {
                assert!(tx.contains(&one_id));
                Ok(tx.add(two))
            })
            .unwrap();
        assert!(added);
        let opened = Replica::open(first.path(), &alice.device).unwrap();
        assert!(opened.contains(&one_id) && opened.contains(&two_id) && opened.contains(&g));
        assert_eq!(opened.local().highest_seq, Some(2));
        assert_eq!(opened.header().generation(), 3);
    }

    #[test]
    fn concurrent_writers_lose_no_record() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (replica, records) = created(&personal, &mut alice);
        let mut head = records.genesis;
        let mut written = Vec::new();
        for n in 0..8 {
            let record = alice.roster(&add_member(member(10 + n), Role::Reader), &[head]);
            head = record.id();
            written.push(record);
        }
        let ids: Vec<RecordId> = written.iter().map(Envelope::id).collect();
        let path = replica.path().to_owned();
        std::thread::scope(|scope| {
            for record in written {
                let path = path.clone();
                scope.spawn(move || {
                    let device = Writer::new(1).device;
                    let mut handle = Replica::open(&path, &device).unwrap();
                    handle.set_lock_timeout(Duration::from_secs(30));
                    handle.transact(&device, |tx| Ok(tx.add(record))).unwrap();
                });
            }
        });
        let opened = Replica::open(&path, &alice.device).unwrap();
        assert!(ids.iter().all(|id| opened.contains(id)));
        assert_eq!(opened.records().count(), 9);
        assert_eq!(opened.local().highest_seq, Some(8));
    }

    #[test]
    fn a_rolled_back_file_gets_its_records_back_and_the_seq_guard_never_drops() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut replica, records) = created(&personal, &mut alice);
        let old = std::fs::read(replica.path()).unwrap();
        let one = alice.roster(&add_member(member(2), Role::Writer), &[records.genesis]);
        let one_id = one.id();
        replica
            .transact(&alice.device, |tx| Ok(tx.add(one)))
            .unwrap();
        assert_eq!(replica.local().highest_seq, Some(1));

        // A sync tool puts the older file back.
        std::fs::write(replica.path(), &old).unwrap();
        assert!(
            !Replica::open(replica.path(), &alice.device)
                .unwrap()
                .contains(&one_id)
        );

        // The next transaction from a handle that held the record restores it.
        replica.transact(&alice.device, |_| Ok(())).unwrap();
        let opened = Replica::open(replica.path(), &alice.device).unwrap();
        assert!(opened.contains(&one_id));
        assert_eq!(opened.local().highest_seq, Some(1));

        // Even when every record of the seq is lost, the guard is kept by the handle.
        replica
            .transact(&alice.device, |tx| {
                tx.local_mut().saw_own_seq(9);
                Ok(())
            })
            .unwrap();
        std::fs::write(replica.path(), &old).unwrap();
        replica.transact(&alice.device, |_| Ok(())).unwrap();
        assert_eq!(
            Replica::open(replica.path(), &alice.device)
                .unwrap()
                .local()
                .highest_seq,
            Some(9)
        );
    }

    #[test]
    fn a_failed_or_empty_transaction_writes_nothing() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut replica, records) = created(&personal, &mut alice);
        let before = std::fs::read(replica.path()).unwrap();
        let one = alice.roster(&add_member(member(2), Role::Writer), &[records.genesis]);
        let failed: Result<()> = replica.transact(&alice.device, |tx| {
            tx.add(one);
            Err(SharedError::Malformed("the caller changed its mind"))
        });
        assert!(failed.is_err());
        assert_eq!(std::fs::read(replica.path()).unwrap(), before);
        assert_eq!(replica.records().count(), 1);
        replica
            .transact(&alice.device, |tx| {
                assert!(!tx.add(tx.envelopes()[0].clone()));
                Ok(())
            })
            .unwrap();
        assert_eq!(std::fs::read(replica.path()).unwrap(), before);
        assert_eq!(replica.header().generation(), 1);
    }

    #[test]
    fn a_file_of_another_vault_under_the_path_is_refused() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut replica, _) = created(&personal, &mut alice);
        // Another vault's replica copied over this one's path.
        let mut other_alice = Writer::new(1);
        let other = Records::create(&mut other_alice, member(7));
        let other_path = dir.path().join("other.kagishared");
        let other_vault = VaultId(Uuid::from_bytes([0x11; 16]));
        Replica::create(
            &other_path,
            &other_alice.device,
            other_vault,
            other.genesis,
            &other.records,
            LocalState::default(),
            0,
        )
        .unwrap();
        std::fs::copy(&other_path, replica.path()).unwrap();
        assert!(matches!(
            replica.transact(&alice.device, |_| Ok(())),
            Err(SharedError::ReplicaMismatch(_))
        ));
    }

    #[test]
    fn unknown_header_keys_survive_a_write() {
        let dir = temp();
        let personal = dir.path().join("vault.kagivault");
        let mut alice = Writer::new(1);
        let (mut replica, records) = created(&personal, &mut alice);
        let mut header = replica.header().clone();
        header
            .unknown
            .insert("later".to_owned(), cbor::text("kept"));
        let bytes = encode(&header, &replica.records, replica.local(), &alice.device).unwrap();
        std::fs::write(replica.path(), bytes).unwrap();
        let one = alice.roster(&add_member(member(2), Role::Writer), &[records.genesis]);
        replica
            .transact(&alice.device, |tx| Ok(tx.add(one)))
            .unwrap();
        let opened = Replica::open(replica.path(), &alice.device).unwrap();
        assert_eq!(
            opened.header().unknown.get("later"),
            Some(&cbor::text("kept"))
        );
    }
}

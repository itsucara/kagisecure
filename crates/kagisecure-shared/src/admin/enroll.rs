//! Inviting a device and joining a vault: one file and a passphrase (ADR-0035 §10, §11;
//! addendum, decision 86, under the trusted-admin amendment).
//!
//! 1. An admin runs [`invite`]. It generates the joining device's key pair **on the admin's
//!    device**, and in one transaction adds the person as a member (or the device to an
//!    existing member), adds the device, and grants it every epoch key the admin holds, so it
//!    reads the vault's whole history. It returns an invitation file and a six-word passphrase.
//! 2. The admin hands over the file one way (a shared folder, a message) and the passphrase
//!    another (said aloud, a second channel).
//! 3. The joining device runs [`join`] with the file and the passphrase: the device's key goes
//!    into the personal vault's device keys, the replica is created, and the genesis is trusted
//!    on first use. There is no second exchange and no request to send first. [`join`] is
//!    [`open_invitation`] — the passphrase's stretching and the file's checks, holding nothing
//!    — then [`join_opened`], the only part that needs the personal vault; an app calls the two
//!    itself so the vault is not held while Argon2id runs.
//!
//! The invitation is sealed with XChaCha20-Poly1305 under a key Argon2id derives from the
//! passphrase (the personal vault's own KDF, at its default cost), with the file's header as
//! AAD. It carries the device's secret keys, the vault's id, genesis and name, and every record
//! the admin's replica holds as a bundle. What this model accepts (threat model, "limits of the
//! trusted-admin model"): the admin knows the joining device's secret keys, and anyone holding
//! the file and the passphrase can join as that device.
//!
//! The Argon2id cost a file names is capped at [`MAX_KDF_COST_FACTOR`] times the default, both
//! to invite and to join: a file that names more is refused before any stretching, so a crafted
//! one cannot make joining take minutes or exhaust memory.

use std::path::Path;

use ciborium::Value;
use kagisecure_core::Secret;
use kagisecure_core::crypto::aead;
use kagisecure_core::crypto::kdf::{ALG_ARGON2ID, DEFAULT_M_KIB, DEFAULT_T, KdfParams};
use kagisecure_core::generator::{Recipe, Separator, WordOptions};
use kagisecure_core::proto::VaultId;
use kagisecure_core::vault::Vault;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::bundle;
use crate::cbor;
use crate::device::{DeviceKeyId, DeviceSecret};
use crate::epoch::EpochOp;
use crate::epoch_key::vault_id_bytes;
use crate::error::{Result, SharedError};
use crate::record::{Envelope, RecordId};
use crate::replica::{LocalState, Replica, replica_path};
use crate::roster::{MemberId, Role, RosterOp, Verification};
use crate::view::SharedView;
use crate::write::{Draft, publish};

/// An invitation's first eight bytes (ADR-0035 addendum, "File magic").
pub const INVITATION_MAGIC: [u8; 8] = *b"KAGISIV\0";
/// The invitation version this build reads and writes.
pub const INVITATION_VERSION: u8 = 1;
/// The largest invitation header.
pub const MAX_INVITATION_HEADER_BYTES: usize = 4 * 1024;
/// The largest invitation: a bundle, its metadata and the framing (decision 86 raises the
/// contract's 64 KiB, since the invitation carries the records).
pub const MAX_INVITATION_BYTES: u64 = bundle::MAX_BUNDLE_BYTES + 128 * 1024;
/// How many words a generated passphrase has: about 77 bits from the 7,776-word list.
pub const PASSPHRASE_WORDS: u32 = 6;
/// The personal vault's audit actor for a device key a join adds.
pub const JOIN_ACTOR: &str = "shared-join";
/// How many times the default Argon2id cost an invitation may name: its memory at most this
/// many times the default, and its memory times passes at most this many times the default's.
pub const MAX_KDF_COST_FACTOR: u32 = 4;

const SHAPE: &str = "an invitation is the magic, a version, a header, a nonce and a sealed body";
const SECRET_LEN: usize = 64;

/// Who the invited device joins as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joining {
    /// A new member with this role, on this device.
    NewMember(Role),
    /// Another device of an existing member.
    ExistingMember(MemberId),
}

/// What [`invite`] hands back: the file to send, and the passphrase to say.
pub struct Invite {
    /// The invitation file's bytes.
    pub file: Vec<u8>,
    /// The passphrase that opens it: six lower-case words joined by hyphens.
    pub passphrase: Secret,
    /// The invited device's id.
    pub device: DeviceKeyId,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the passphrase.
        f.debug_struct("Invite")
            .field("device", &self.device)
            .field("len", &self.file.len())
            .finish_non_exhaustive()
    }
}

/// A passphrase as typed, in its one form: lower case, words joined by single hyphens —
/// whatever spaces, hyphens or other separators the person used between them.
fn normalize(passphrase: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(passphrase.len()));
    for word in passphrase
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        if !out.is_empty() {
            out.push('-');
        }
        for c in word.chars() {
            // Only ASCII in the word list; `to_ascii_lowercase` never grows the string.
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The header: `{"v": 1, "kdf": {"alg", "salt", "m_kib", "t", "p"}}`, deterministic CBOR.
fn header(kdf: &KdfParams) -> Vec<u8> {
    cbor::encode(&cbor::map(vec![
        (cbor::text("v"), Value::Integer(1.into())),
        (
            cbor::text("kdf"),
            cbor::map(vec![
                (cbor::text("alg"), cbor::text(&kdf.alg)),
                (cbor::text("salt"), cbor::bytes(&kdf.salt)),
                (cbor::text("m_kib"), Value::Integer(kdf.m_kib.into())),
                (cbor::text("t"), Value::Integer(kdf.t.into())),
                (cbor::text("p"), Value::Integer(kdf.p.into())),
            ]),
        ),
    ]))
}

fn read_header(bytes: &[u8]) -> Result<KdfParams> {
    let mut kdf = None;
    for (key, value) in cbor::text_map(cbor::decode_canonical(bytes)?, SHAPE)? {
        match key.as_str() {
            "v" if cbor::uint(&value, SHAPE)? == 1 => {}
            "kdf" => {
                let (mut alg, mut salt, mut m_kib, mut t, mut p) = (None, None, None, None, None);
                for (key, value) in cbor::text_map(value, SHAPE)? {
                    let small = |v: &Value| {
                        u32::try_from(cbor::uint(v, SHAPE)?)
                            .map_err(|_| SharedError::Malformed(SHAPE))
                    };
                    match (key.as_str(), value) {
                        ("alg", Value::Text(text)) => alg = Some(text),
                        ("salt", Value::Bytes(bytes)) => salt = Some(bytes),
                        ("m_kib", v) => m_kib = Some(small(&v)?),
                        ("t", v) => t = Some(small(&v)?),
                        ("p", v) => p = Some(small(&v)?),
                        _ => return Err(SharedError::Malformed(SHAPE)),
                    }
                }
                let (Some(alg), Some(salt), Some(m_kib), Some(t), Some(p)) =
                    (alg, salt, m_kib, t, p)
                else {
                    return Err(SharedError::Malformed(SHAPE));
                };
                kdf = Some(KdfParams {
                    alg,
                    salt,
                    m_kib,
                    t,
                    p,
                    out_len: 32,
                    unknown: std::collections::BTreeMap::new(),
                });
            }
            _ => return Err(SharedError::Malformed(SHAPE)),
        }
    }
    kdf.ok_or(SharedError::Malformed(SHAPE))
}

/// Refuse a cost above [`MAX_KDF_COST_FACTOR`] times the default.
fn check_cost(kdf: &KdfParams) -> Result<()> {
    let max_m_kib = u64::from(DEFAULT_M_KIB) * u64::from(MAX_KDF_COST_FACTOR);
    if u64::from(kdf.m_kib) > max_m_kib {
        return Err(SharedError::LimitExceeded {
            what: "invitation passphrase memory cost, in KiB",
            limit: max_m_kib,
        });
    }
    let max_work = u64::from(DEFAULT_M_KIB) * u64::from(DEFAULT_T) * u64::from(MAX_KDF_COST_FACTOR);
    if u64::from(kdf.m_kib) * u64::from(kdf.t) > max_work {
        return Err(SharedError::LimitExceeded {
            what: "invitation passphrase cost, in KiB times passes",
            limit: max_work,
        });
    }
    Ok(())
}

/// An invitation, opened with its passphrase and checked: what [`join_opened`] joins with.
/// It holds the invited device's secret keys; they are wiped when it is dropped.
pub struct OpenedInvitation {
    vault_id: VaultId,
    genesis: RecordId,
    name: Option<String>,
    label: String,
    device: DeviceSecret,
    records: Vec<Envelope>,
    /// The roster's other active devices, recorded as first seen on joining.
    others: Vec<DeviceKeyId>,
    /// The member this device joins as (new or existing): the label becomes this device's own
    /// local name for it, if it does not already have one (follow-up to decision 86).
    member: MemberId,
}

impl OpenedInvitation {
    /// The shared vault it invites to.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The vault's name, as the admin's device knows it.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The invited device's id.
    #[must_use]
    pub fn device(&self) -> DeviceKeyId {
        self.device.id()
    }
}

impl std::fmt::Debug for OpenedInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the device's secret keys.
        f.debug_struct("OpenedInvitation")
            .field("vault_id", &self.vault_id)
            .field("device", &self.device.id())
            .field("records", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// What the sealed body carries.
struct Opened {
    vault_id: VaultId,
    genesis: RecordId,
    name: Option<String>,
    label: String,
    device: DeviceSecret,
    records: Vec<Envelope>,
}

/// The sealed body: a `u32` length and the metadata `{"vault_id", "genesis", "name", "label"}`,
/// then the device's 64 secret bytes, then a bundle.
fn seal(
    kdf: &KdfParams,
    passphrase: &str,
    meta: &[u8],
    secret: &[u8; SECRET_LEN],
    records: &[u8],
) -> Result<Vec<u8>> {
    let len = u32::try_from(meta.len()).map_err(|_| SharedError::Malformed(SHAPE))?;
    // Written at exactly its size, so the secret is never left behind by a reallocation.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        4 + meta.len() + SECRET_LEN + records.len(),
    ));
    plaintext.extend_from_slice(&len.to_be_bytes());
    plaintext.extend_from_slice(meta);
    plaintext.extend_from_slice(secret);
    plaintext.extend_from_slice(records);

    let header = header(kdf);
    let mut out = INVITATION_MAGIC.to_vec();
    out.push(INVITATION_VERSION);
    out.extend_from_slice(
        &u32::try_from(header.len())
            .map_err(|_| SharedError::Malformed(SHAPE))?
            .to_be_bytes(),
    );
    out.extend(header);
    let key = kdf.derive(normalize(passphrase).as_bytes())?;
    let nonce = aead::nonce()?;
    let sealed = aead::seal(&key, &nonce, &out, &plaintext)?;
    out.extend_from_slice(&nonce);
    out.extend(sealed);
    Ok(out)
}

/// Open an invitation file with `passphrase`.
fn open(file: &[u8], passphrase: &str) -> Result<Opened> {
    if file.len() as u64 > MAX_INVITATION_BYTES {
        return Err(SharedError::LimitExceeded {
            what: "invitation",
            limit: MAX_INVITATION_BYTES,
        });
    }
    let rest = file
        .strip_prefix(INVITATION_MAGIC.as_slice())
        .ok_or(SharedError::Malformed("not a shared-vault invitation"))?;
    let (&version, rest) = rest.split_first().ok_or(SharedError::Malformed(SHAPE))?;
    if version != INVITATION_VERSION {
        return Err(SharedError::UnsupportedVersion {
            what: "invitation",
            version: u64::from(version),
        });
    }
    let (len, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(SharedError::Malformed(SHAPE))?;
    let len = u32::from_be_bytes(*len) as usize;
    if len > MAX_INVITATION_HEADER_BYTES || len + aead::NONCE_LEN > rest.len() {
        return Err(SharedError::Malformed(SHAPE));
    }
    let kdf = read_header(&rest[..len])?;
    check_cost(&kdf)?;
    let aad = &file[..file.len() - rest.len() + len];
    let (nonce, sealed) = rest[len..].split_at(aead::NONCE_LEN);
    let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().expect("the nonce's length");
    let key = kdf.derive(normalize(passphrase).as_bytes())?;
    let plaintext = aead::open(&key, &nonce, aad, sealed).map_err(|_| SharedError::Decrypt)?;

    let (len, rest) = plaintext
        .split_first_chunk::<4>()
        .ok_or(SharedError::Malformed(SHAPE))?;
    let len = u32::from_be_bytes(*len) as usize;
    if len + SECRET_LEN > rest.len() {
        return Err(SharedError::Malformed(SHAPE));
    }
    let (meta, rest) = rest.split_at(len);
    let (secret, records) = rest.split_at(SECRET_LEN);
    let device = DeviceSecret::from_secret_bytes(secret)?;
    let (mut vault_id, mut genesis, mut name, mut label) = (None, None, None, None);
    for (key, value) in cbor::text_map(cbor::decode_canonical(meta)?, SHAPE)? {
        match (key.as_str(), value) {
            ("vault_id", v) => {
                vault_id = Some(VaultId(Uuid::from_bytes(cbor::fixed_bytes(&v, SHAPE)?)));
            }
            ("genesis", v) => genesis = Some(RecordId::from_bytes(cbor::fixed_bytes(&v, SHAPE)?)),
            ("name", Value::Null) => name = Some(None),
            ("name", Value::Text(text)) => {
                super::check_label(&text)?;
                name = Some(Some(text));
            }
            ("label", Value::Text(text)) => {
                super::check_label(&text)?;
                label = Some(text);
            }
            _ => return Err(SharedError::Malformed(SHAPE)),
        }
    }
    let (Some(vault_id), Some(genesis), Some(name), Some(label)) = (vault_id, genesis, name, label)
    else {
        return Err(SharedError::Malformed(SHAPE));
    };
    Ok(Opened {
        vault_id,
        genesis,
        name,
        label,
        device,
        records: bundle::parse(records)?,
    })
}

/// Invite a new device as `joining`, labelled `label` (at most 128 characters; it becomes the
/// device key's label in the joiner's personal vault). See the module documentation.
///
/// # Errors
///
/// [`SharedError::Refused`] unless this is an admin device, or if the member to add the device
/// to is not an active member; [`SharedError::LimitExceeded`] for a longer label; and as
/// [`Replica::transact`].
pub fn invite(
    replica: &mut Replica,
    admin: &DeviceSecret,
    joining: Joining,
    label: &str,
    now: u64,
) -> Result<Invite> {
    invite_with_kdf(replica, admin, joining, label, KdfParams::defaults()?, now)
}

/// [`invite`] with the passphrase stretched at `kdf`'s cost rather than the personal vault's
/// default: for tests, and for a device that must open it on slow hardware.
///
/// # Errors
///
/// As [`invite`]; [`SharedError::Core`] for KDF parameters out of range, and
/// [`SharedError::LimitExceeded`] for a cost above [`MAX_KDF_COST_FACTOR`] times the default.
pub fn invite_with_kdf(
    replica: &mut Replica,
    admin: &DeviceSecret,
    joining: Joining,
    label: &str,
    mut kdf: KdfParams,
    now: u64,
) -> Result<Invite> {
    super::check_label(label)?;
    check_cost(&kdf)?;
    kdf.reroll_salt()?;
    kdf.alg = ALG_ARGON2ID.to_owned();
    let joiner = DeviceSecret::generate()?;
    let public = joiner.public().clone();
    let written = replica.transact(admin, |tx| {
        let mut draft = Draft::begin(tx, admin)?;
        draft.require(admin, Role::Admin)?;
        let roster = draft.view.roster();
        let mut heads = roster.heads().to_vec();
        let mut written = Vec::new();
        let (member, is_new_member) = match joining {
            Joining::NewMember(role) => {
                let member = MemberId::generate()?;
                let op = RosterOp::AddMember {
                    member,
                    role,
                    labels: None,
                };
                let envelope = op.sign(admin, draft.header(heads, vec![], None, now))?;
                let id = draft.wrote(tx, envelope);
                written.push(id);
                heads = vec![id];
                (member, true)
            }
            Joining::ExistingMember(member) => {
                if !roster.snapshot().member(&member).is_some_and(|m| m.active) {
                    return Err(SharedError::Refused("that is not an active member"));
                }
                (member, false)
            }
        };
        let op = RosterOp::AddDevice {
            member,
            device: public.clone(),
            verified: Verification::Unverified,
            labels: None,
        };
        let added = draft.wrote(tx, op.sign(admin, draft.header(heads, vec![], None, now))?);
        written.push(added);
        // Every key this device holds, so the new device reads the whole history.
        let ring = draft.view.key_ring();
        let grants: Vec<EpochOp> = ring
            .held()
            .filter_map(|epoch| ring.key(epoch).map(|key| (*epoch, key)))
            .map(|(epoch, key)| EpochOp::grant(tx.vault_id(), epoch, key, &[&public]))
            .collect::<Result<_>>()?;
        for grant in grants {
            let header = draft.header(vec![added], vec![], grant.epoch_id(), now);
            written.push(draft.wrote(tx, grant.sign(admin, header)?));
        }
        tx.local_mut().first_seen.insert(public.id(), now);
        // A brand-new member has no local name anywhere yet: start it as the label the admin
        // invited them with (decision, "member names" follow-up), so it does not read as
        // "Unnamed member" on this device until someone renames them. An existing member
        // already has a name here, if any, so it is left alone.
        if is_new_member {
            tx.local_mut().member_names.insert(member, label.to_owned());
        }
        Ok(written)
    })?;
    publish(replica, &written)?;

    let meta = cbor::encode(&cbor::map(vec![
        (
            cbor::text("vault_id"),
            cbor::bytes(vault_id_bytes(replica.vault_id())),
        ),
        (
            cbor::text("genesis"),
            cbor::bytes(replica.genesis().as_bytes()),
        ),
        (
            cbor::text("name"),
            replica
                .local()
                .vault_name
                .as_deref()
                .map_or(Value::Null, cbor::text),
        ),
        (cbor::text("label"), cbor::text(label)),
    ]));
    let passphrase = Recipe::Words(WordOptions {
        words: PASSPHRASE_WORDS,
        separator: Separator::Hyphen,
        capitalize: false,
        include_digit: false,
    })
    .generate()?;
    let text = passphrase
        .expose_str()
        .ok_or(SharedError::Malformed("a generated passphrase is not text"))?;
    let file = seal(
        &kdf,
        text,
        &meta,
        &joiner.secret_bytes(),
        &bundle::encode(&replica.envelopes())?,
    )?;
    Ok(Invite {
        file,
        passphrase,
        device: public.id(),
    })
}

/// Join the vault an invitation file invites this computer to, with the passphrase that came
/// with it: the invited device's key is added to the personal vault `personal`, and the
/// replica is created beside it — or, joined before, the invitation's records are added to it.
/// Every other device of the roster is recorded as first seen (trust on first use). With
/// `exchange_dir`, that directory is configured for syncing. Returns the replica and the device.
///
/// [`open_invitation`] then [`join_opened`]; an app that must not hold the personal vault while
/// the passphrase is stretched calls the two itself.
///
/// # Errors
///
/// As [`open_invitation`] and [`join_opened`].
pub fn join(
    personal: &mut Vault,
    file: &[u8],
    passphrase: &str,
    exchange_dir: Option<&Path>,
    now: u64,
) -> Result<(Replica, DeviceSecret)> {
    let opened = open_invitation(file, passphrase)?;
    join_opened(personal, opened, exchange_dir, now)
}

/// Open an invitation file with its passphrase and check it: the slow part of joining — the
/// passphrase's stretching, the records' signatures — with no vault held.
///
/// # Errors
///
/// [`SharedError::Decrypt`] for a wrong passphrase or an altered file;
/// [`SharedError::LimitExceeded`] for a file too large or naming a passphrase cost above
/// [`MAX_KDF_COST_FACTOR`] times the default; [`SharedError::Malformed`] for a file that is not
/// an invitation; [`SharedError::Refused`] if the invitation does not make its device an active
/// member holding a key.
pub fn open_invitation(file: &[u8], passphrase: &str) -> Result<OpenedInvitation> {
    let opened = open(file, passphrase)?;
    let view = SharedView::compute(
        &opened.vault_id,
        &opened.genesis,
        &opened.records,
        &opened.device,
    )?;
    let roster = view.roster();
    let device = opened.device.id();
    if !roster.snapshot().device(&device).is_some_and(|d| d.active) {
        return Err(SharedError::Refused(
            "the invitation does not add its device to the vault",
        ));
    }
    if view.key_ring().current_key().is_none() {
        return Err(SharedError::Refused(
            "the invitation does not give its device a key",
        ));
    }
    let others: Vec<DeviceKeyId> = roster
        .snapshot()
        .active_devices()
        .map(|d| d.public.id())
        .filter(|id| *id != device)
        .collect();
    // Present: the earlier `device(&device).is_some_and(|d| d.active)` check above already
    // found this device in the roster.
    let member = roster
        .snapshot()
        .device(&device)
        .map(|d| d.member)
        .expect("this device is active in the roster, checked above");
    Ok(OpenedInvitation {
        vault_id: opened.vault_id,
        genesis: opened.genesis,
        name: opened.name,
        label: opened.label,
        device: opened.device,
        records: opened.records,
        others,
        member,
    })
}

/// Join with an invitation [`open_invitation`] opened: the rest of [`join`], the part that
/// needs the personal vault.
///
/// # Errors
///
/// [`SharedError::Core`] if the personal vault refuses the device key (one removed from it
/// before cannot come back); [`SharedError::ReplicaMismatch`] if a replica of the vault already
/// here names another genesis; and as [`Replica::create`].
pub fn join_opened(
    personal: &mut Vault,
    opened: OpenedInvitation,
    exchange_dir: Option<&Path>,
    now: u64,
) -> Result<(Replica, DeviceSecret)> {
    let exchange = exchange_dir.map(super::exchange::path_text).transpose()?;
    let OpenedInvitation {
        vault_id,
        genesis,
        name,
        label,
        device,
        records,
        others,
        member,
    } = opened;

    if !personal
        .device_keys()
        .iter()
        .any(|k| k.id() == device.id().as_bytes())
    {
        let key = device.to_device_key(&label, now)?;
        personal.transact(|tx| tx.add_device_key(key, JOIN_ACTOR))?;
    }

    let note = |local: &mut LocalState| {
        for id in &others {
            if !local.verified_devices.contains_key(id) {
                local.first_seen.entry(*id).or_insert(now);
            }
        }
        if local.vault_name.is_none() {
            local.vault_name.clone_from(&name);
        }
        if exchange.is_some() {
            local.exchange_dir.clone_from(&exchange);
        }
        // This device's own local name for the member it joins as, so this device does not
        // show itself as "Unnamed member" until "You" is recognized, and so a name is already
        // there for it if it is ever displayed to a device that is not this one.
        local
            .member_names
            .entry(member)
            .or_insert_with(|| label.clone());
    };
    let path = replica_path(personal.path(), &vault_id);
    if path.exists() {
        let mut replica = Replica::open(&path, &device)?;
        if replica.genesis() != genesis {
            return Err(SharedError::ReplicaMismatch("it names another genesis"));
        }
        replica.transact(&device, |tx| {
            for record in &records {
                tx.add(record.clone());
            }
            note(tx.local_mut());
            Ok(())
        })?;
        return Ok((replica, device));
    }
    let mut local = LocalState::default();
    note(&mut local);
    let replica = Replica::create(&path, &device, vault_id, genesis, &records, local, now)?;
    Ok((replica, device))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_passphrase_reads_the_same_however_it_is_typed() {
        assert_eq!(
            normalize(" Correct  horse-BATTERY staple\tone two ").as_str(),
            "correct-horse-battery-staple-one-two"
        );
        assert_eq!(normalize("yo-yo").as_str(), "yo-yo");
    }

    #[test]
    fn a_passphrase_cost_above_the_cap_is_refused_before_any_stretching() {
        let max = DEFAULT_M_KIB * MAX_KDF_COST_FACTOR;
        let cheap = KdfParams::new(64, 1, 1).unwrap();
        assert!(check_cost(&KdfParams::defaults().unwrap()).is_ok());
        assert!(check_cost(&KdfParams::new(max, DEFAULT_T, 1).unwrap()).is_ok());
        for (m_kib, t) in [
            (max + 1, 1),
            (DEFAULT_M_KIB, DEFAULT_T * MAX_KDF_COST_FACTOR + 1),
        ] {
            let costly = KdfParams::new(m_kib, t, 1).unwrap();
            assert!(matches!(
                check_cost(&costly),
                Err(SharedError::LimitExceeded { .. })
            ));
            // A file naming it: refused as too costly, not as a wrong passphrase — which it
            // would be only after the stretching.
            let mut file = seal(&cheap, "a-b", b"", &[0; SECRET_LEN], b"").unwrap();
            let header = header(&costly);
            let old_len = u32::from_be_bytes(file[9..13].try_into().unwrap()) as usize;
            file.splice(13..13 + old_len, header.iter().copied());
            file[9..13].copy_from_slice(&u32::try_from(header.len()).unwrap().to_be_bytes());
            assert!(matches!(
                open(&file, "a-b"),
                Err(SharedError::LimitExceeded { .. })
            ));
        }
    }
}

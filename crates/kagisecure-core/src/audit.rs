//! The append-only audit log and its hash chain (vault-format §8, mcp-server.md §6).
//!
//! Every tool call and every CLI action that touches an environment is recorded, **whether it
//! succeeded, was denied, or errored**. Denials are kept deliberately: a burst of them is the
//! only evidence a user will ever have that a prompt injection tried an exfiltration.
//!
//! Entries carry names, never values. That is enforced by construction — this module is compiled
//! with *and without* the `secret-material` feature, so [`Secret`](crate::model::Secret) is not
//! nameable from here in the configuration the MCP sidecar builds.
//!
//! # The chain
//!
//! ```text
//! entry_0.prev     = 32 zero bytes
//! entry_n.prev     = SHA-256(canonical(entry_{n-1}))
//! body.audit_head  = SHA-256(canonical(entry_last))   // 32 zero bytes when the log is empty
//! ```
//!
//! `canonical(e)` is the CBOR encoding of [`AuditEntry`], its known fields in declaration order.
//! For an entry built fresh by this process, that is exactly what `ciborium` produces
//! deterministically for a struct. For an entry decoded from a file, `canonical` instead re-emits
//! the exact CBOR map the entry was decoded from (see `AuditEntry::raw`), byte for byte — because
//! a future format version may add a field this build does not model, and this build must still
//! reproduce the *same* digest a build that does understand it would compute, or the chain would
//! appear broken for no reason other than reading it with an older build (vault-format §9). The
//! chain catches a *legitimately unlocked* process silently dropping or reordering entries
//! mid-log, and gives the UI a cheap check that the log is **internally consistent** — not that it
//! is complete, and not that the file holding it is the latest version. Both gaps below follow
//! from that distinction.
//!
//! # What the chain does not catch
//!
//! **Whole-file rollback.** The AEAD tag authenticates a file's contents, not its recency: an
//! attacker with file access but no key (same-user malware, or an injected coding agent with a
//! shell — threat actors T-2/T-3 in `docs/threat-model.md`) can copy the vault file, let the app
//! record whatever it will — e.g. the burst of denials that is the only evidence of an
//! exfiltration attempt — get the vault locked (any same-user client can send `lock` over the IPC
//! socket, or just wait for auto-lock), and copy the old file back. The restored file is fully
//! authentic and verifies cleanly; that history is gone. While the vault is unlocked every append
//! saves, so a restore then would be overwritten by the next save — the attack only works once
//! nothing is writing the file anymore.
//!
//! **Key-holder truncation.** `body.audit_head` lives in the same encrypted body as the entries
//! it attests. Anything holding the vault key can therefore drop the last *k* entries, store the
//! digest of the new last entry, and [`verify`] returns `Ok` — the log has simply lost its most
//! recent history. The chain detects reordering, editing and mid-log deletion; it does not detect
//! *tail truncation by a process that holds the key* (documented by two `#[ignore]`d tests in
//! `crates/kagisecure-core/tests/adversarial_audit.rs`).
//!
//! Both are the same missing property: **freshness**. A self-contained file cannot prove it is
//! its own latest version. An entry count or counter in the (AAD-authenticated) header would not
//! close either gap — a key holder re-seals it along with everything else, and a rollback swaps
//! header and body together. Detecting either needs state kept outside the file, e.g. an anchor
//! in the OS keychain; that is an open design item, not implemented. Until it exists, treat the
//! chain as an integrity check against accident, not as tamper-evidence against an attacker who
//! holds the key or who can swap the whole file.
//!
//! # Save failures
//!
//! [`append`] only updates the in-memory log; nothing here touches the disk. The vault
//! (`vault::Vault`) keeps every entry that has not reached the file yet — entries chained in
//! memory by the non-transactional `append_audit` + `save` path, and drafts in its **pending
//! queue** — and never discards one on a failed write:
//!
//! * a transaction whose write fails is rolled back by re-reading the file, and the drafts it
//!   carried go back into the queue, each keeping the time it was recorded ([`append_at`]);
//! * the next successful transaction chains the queue onto whatever head the file has by then,
//!   including entries another process appended in the meantime;
//! * `Vault::unsaved_audit_entries` and `Vault::last_save_error` expose the gap, and the macOS
//!   app's Audit view warns while it is non-zero.
//!
//! What remains is the crash window: a pending draft lives in memory until a write succeeds, so
//! a process that dies (or a vault that locks) before then loses it. The answer already returned
//! to the caller for the action that produced the entry is unaffected either way.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proto::{EnvId, ItemId, LeaseId, Outcome, VaultId};

/// Length of a chain link.
pub const DIGEST_LEN: usize = 32;

/// The chain value of an empty log, and the `prev` of its first entry.
#[must_use]
pub fn genesis() -> Vec<u8> {
    vec![0u8; DIGEST_LEN]
}

/// The named keys [`AuditEntry`] models. Anything else in the CBOR map is captured in
/// [`AuditEntry::unknown`] instead of being dropped.
const KNOWN_KEYS: [&str; 14] = [
    "seq",
    "timestamp",
    "actor",
    "client_pid",
    "tool",
    "vault_id",
    "environment_id",
    "item_id",
    "variables",
    "target_path",
    "lease_id",
    "outcome",
    "detail",
    "prev",
];

/// One recorded action.
///
/// Field order is part of the format: it decides the CBOR encoding, which decides the hash.
/// Adding a field to the middle of this struct breaks every existing chain.
///
/// `Serialize`/`Deserialize` are hand-written, not derived — see [`AuditEntry::unknown`] and
/// `raw` below for why.
#[derive(Clone, Debug, Default)]
pub struct AuditEntry {
    /// Position in the log, starting at 0.
    pub seq: u64,
    /// Unix seconds.
    pub timestamp: u64,
    /// Who asked: `"cli"`, or a verified-or-self-reported MCP client identity.
    pub actor: String,
    /// The peer process id, when the transport could tell us one.
    pub client_pid: Option<u32>,
    /// The tool or subcommand name, e.g. `"write_env_file"`.
    pub tool: String,
    /// Logical vault involved, if any.
    pub vault_id: Option<VaultId>,
    /// Environment involved, if any.
    pub environment_id: Option<EnvId>,
    /// Item involved, if any.
    pub item_id: Option<ItemId>,
    /// Variable **names** involved. Never values.
    pub variables: Vec<String>,
    /// Target path involved, if any.
    pub target_path: Option<String>,
    /// Lease minted or used, if any.
    pub lease_id: Option<LeaseId>,
    /// How it ended.
    pub outcome: Outcome,
    /// A short machine-readable reason, e.g. an error code from mcp-server.md §7.
    ///
    /// This is written from a fixed vocabulary by the daemon. It is never interpolated with a
    /// secret value, and nothing in this crate can put one here: `Secret` has no `Display`.
    pub detail: Option<String>,
    /// `SHA-256(canonical(previous entry))`, or [`genesis`] for the first entry.
    pub prev: Vec<u8>,
    /// Top-level keys this build does not recognize, decoded for inspection (vault-format §9
    /// rule 1). Empty for an entry this process created. Not consulted by [`canonical`] — see
    /// `raw`.
    pub unknown: BTreeMap<String, ciborium::Value>,
    /// The exact CBOR map this entry was decoded from, when it came from a file.
    ///
    /// The audit log is hash-chained (vault-format §8): `entry_n.prev` is
    /// `SHA-256(canonical(entry_{n-1}))`, and any reader — including a build older than whichever
    /// build wrote the entry — must be able to reproduce that exact digest to verify or extend the
    /// chain. A build that does not recognize every field cannot reconstruct byte-identical CBOR
    /// by re-serializing the fields above (an unknown field would land wherever this build puts
    /// unrecognized data — not necessarily where the original writer put it), so [`canonical`]
    /// uses these captured bytes verbatim instead of re-deriving them whenever they are available.
    /// `None` only for an entry built fresh by this process, which has no unknown fields to lose
    /// and so needs no captured form.
    raw: Option<ciborium::Value>,
}

/// [`AuditEntry`]'s named fields, decodable on their own from *any* deserializer — critically,
/// including the caller's original one, not only a [`ciborium::Value`] built from it (see
/// [`AuditEntry::from_value`] for why that distinction matters).
#[derive(Deserialize)]
struct Known {
    seq: u64,
    timestamp: u64,
    actor: String,
    client_pid: Option<u32>,
    tool: String,
    vault_id: Option<VaultId>,
    environment_id: Option<EnvId>,
    item_id: Option<ItemId>,
    variables: Vec<String>,
    target_path: Option<String>,
    lease_id: Option<LeaseId>,
    outcome: Outcome,
    detail: Option<String>,
    #[serde(deserialize_with = "deserialize_prev")]
    prev: Vec<u8>,
}

impl From<Known> for AuditEntry {
    fn from(known: Known) -> Self {
        Self {
            seq: known.seq,
            timestamp: known.timestamp,
            actor: known.actor,
            client_pid: known.client_pid,
            tool: known.tool,
            vault_id: known.vault_id,
            environment_id: known.environment_id,
            item_id: known.item_id,
            variables: known.variables,
            target_path: known.target_path,
            lease_id: known.lease_id,
            outcome: known.outcome,
            detail: known.detail,
            prev: known.prev,
            unknown: BTreeMap::new(),
            raw: None,
        }
    }
}

impl AuditEntry {
    /// Decode one entry from a generic CBOR-shaped value, keeping both a best-effort typed view
    /// and the exact value for [`canonical`] to hash later.
    ///
    /// Only for a **binary** source (vault-format §9 rule 1's forward compatibility needs the
    /// exact bytes back, and only a CBOR file needs that at all): going through
    /// [`ciborium::Value`] loses whether the deserializer that produced it was human-readable —
    /// `Value`'s own presents as binary regardless — so a `VaultId` or any other `Uuid`-backed
    /// field decoded through it expects the binary shape even when the original bytes were a JSON
    /// string. [`AuditEntry::deserialize`] therefore never takes this path for a human-readable
    /// deserializer; it decodes [`Known`] straight from that deserializer instead, which keeps its
    /// own answer to `is_human_readable()` intact.
    fn from_value(value: ciborium::Value) -> Result<Self, ciborium::value::Error> {
        let known: Known = value.deserialized()?;
        let mut unknown = BTreeMap::new();
        if let ciborium::Value::Map(pairs) = &value {
            for (k, v) in pairs {
                if let ciborium::Value::Text(key) = k
                    && !KNOWN_KEYS.contains(&key.as_str())
                {
                    unknown.insert(key.clone(), v.clone());
                }
            }
        }
        let mut entry = Self::from(known);
        entry.unknown = unknown;
        entry.raw = Some(value);
        Ok(entry)
    }
}

/// Compares the recognized fields and the decoded [`AuditEntry::unknown`] map, not the cached
/// `raw` value: `raw` is redundant with the two once they agree (it exists only so [`canonical`]
/// can reproduce it byte-for-byte), and comparing it directly would make two entries decoded
/// through different formats (CBOR on disk, JSON over IPC) compare unequal on `raw`'s own type
/// even when every field they expose is identical.
impl PartialEq for AuditEntry {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.timestamp == other.timestamp
            && self.actor == other.actor
            && self.client_pid == other.client_pid
            && self.tool == other.tool
            && self.vault_id == other.vault_id
            && self.environment_id == other.environment_id
            && self.item_id == other.item_id
            && self.variables == other.variables
            && self.target_path == other.target_path
            && self.lease_id == other.lease_id
            && self.outcome == other.outcome
            && self.detail == other.detail
            && self.prev == other.prev
            && self.unknown == other.unknown
    }
}

/// The vault format has no floating-point fields anywhere `unknown` could capture one, so the
/// `PartialEq` above is reflexive in practice; see its doc comment for what it compares.
impl Eq for AuditEntry {}

impl<'de> Deserialize<'de> for AuditEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Human-readable (JSON, over `kagisecure-ipc`): straight into `Known`, from this
        // deserializer — not a `ciborium::Value` built from it, which would answer
        // `is_human_readable()` as binary and break every `Uuid`-backed field
        // (`from_value`'s own documentation has why). No `unknown`/`raw` to capture: a JSON
        // caller reads entries to show them, never to extend the hash chain or re-verify it byte
        // for byte — that only ever happens against the vault file's own CBOR (vault-format §8).
        if deserializer.is_human_readable() {
            return Known::deserialize(deserializer).map(Self::from);
        }
        let value = ciborium::Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for AuditEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // An entry read from a file is re-emitted exactly as read, unknown fields included: see
        // the `raw` field's doc comment for why this is required for the hash chain, not just
        // convenient. That requirement is about `canonical`'s CBOR encoding specifically — the
        // only thing that has to reproduce the exact bytes a build that predates a newer field
        // would have written — so it is gated on `is_human_readable()` rather than applied to
        // every `Serialize` call this type ever receives. Un-gated, `kagisecure audit --json`
        // (and anything else asking this type for JSON) inherited the CBOR shortcut too: every id
        // typed `Uuid` is bytes on the wire when raw is `Some`, and Argon2-flavoured salts aside,
        // a JSON array of sixteen small integers where every other JSON surface in this codebase
        // prints a canonical `xxxxxxxx-xxxx-...` string is a regression a caller has to special-
        // case for no reason tied to the audit chain at all.
        if let Some(raw) = &self.raw
            && !serializer.is_human_readable()
        {
            return raw.serialize(serializer);
        }
        use serde::ser::SerializeMap;
        // Captured before `serializer` moves into `serialize_map` below.
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(Some(KNOWN_KEYS.len() + self.unknown.len()))?;
        map.serialize_entry("seq", &self.seq)?;
        map.serialize_entry("timestamp", &self.timestamp)?;
        map.serialize_entry("actor", &self.actor)?;
        map.serialize_entry("client_pid", &self.client_pid)?;
        map.serialize_entry("tool", &self.tool)?;
        map.serialize_entry("vault_id", &self.vault_id)?;
        map.serialize_entry("environment_id", &self.environment_id)?;
        map.serialize_entry("item_id", &self.item_id)?;
        map.serialize_entry("variables", &self.variables)?;
        map.serialize_entry("target_path", &self.target_path)?;
        map.serialize_entry("lease_id", &self.lease_id)?;
        map.serialize_entry("outcome", &self.outcome)?;
        map.serialize_entry("detail", &self.detail)?;
        // A byte string on the wire when it can be one (CBOR — the vault file), a hex string when
        // it cannot (JSON — the IPC client, `kagisecure audit --json`): the same choice `VaultId`,
        // `EnvId` and every other id here already make through `Uuid`'s own `Serialize`. `prev`
        // has no such type to lean on, so it is spelled out here instead — and `deserialize_prev`
        // below reads back whichever of the two it is given.
        if human_readable {
            map.serialize_entry("prev", &hex_encode(&self.prev))?;
        } else {
            map.serialize_entry("prev", serde_bytes::Bytes::new(&self.prev))?;
        }
        for (k, v) in &self.unknown {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// `prev`, from either a CBOR byte string (a vault file, or any binary transport) or a hex
/// string (the IPC client's JSON, which has no byte-string type) — the two shapes
/// [`AuditEntry`]'s `Serialize` impl can produce for it, matching `is_human_readable()`. Visited
/// directly rather than through `serde_bytes`, which has no fallback for the hex-string shape and
/// is exactly what answered "invalid type: sequence, expected bytes" for a JSON array of numbers
/// before this existed — the previous, inconsistent encoding of a human-readable `prev`.
fn deserialize_prev<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PrevVisitor;

    impl serde::de::Visitor<'_> for PrevVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a byte string or a hex string")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            hex_decode(v).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(PrevVisitor)
}

/// Lower-case hex, no separators.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The inverse of [`hex_encode`].
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{s:?} is not valid hex: odd length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("{s:?} is not valid hex"))
        })
        .collect()
}

/// Everything about an entry except its position in the chain.
///
/// The caller describes *what happened*; [`append`] decides `seq`, `timestamp` and `prev`.
#[derive(Clone, Debug, Default)]
pub struct AuditDraft {
    /// Who asked.
    pub actor: String,
    /// The peer process id, if known.
    pub client_pid: Option<u32>,
    /// The tool or subcommand name.
    pub tool: String,
    /// Logical vault involved.
    pub vault_id: Option<VaultId>,
    /// Environment involved.
    pub environment_id: Option<EnvId>,
    /// Item involved.
    pub item_id: Option<ItemId>,
    /// Variable names involved.
    pub variables: Vec<String>,
    /// Target path involved.
    pub target_path: Option<String>,
    /// Lease minted or used.
    pub lease_id: Option<LeaseId>,
    /// How it ended.
    pub outcome: Outcome,
    /// A short machine-readable reason.
    pub detail: Option<String>,
}

/// The canonical bytes of an entry: its CBOR encoding, fields in declaration order.
///
/// # Panics
///
/// Never in practice: `AuditEntry` contains only strings, integers, byte strings and unit enums,
/// all of which `ciborium` encodes infallibly into a `Vec<u8>`.
#[must_use]
pub fn canonical(entry: &AuditEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(entry, &mut buf)
        .expect("an AuditEntry contains only CBOR-encodable scalars");
    buf
}

/// `SHA-256(canonical(entry))`.
#[must_use]
pub fn digest(entry: &AuditEntry) -> Vec<u8> {
    Sha256::digest(canonical(entry)).to_vec()
}

/// Append `draft` to `entries`, returning the new chain head.
///
/// `head` must be the current head — [`genesis`] for an empty log. The appended entry's `prev` is
/// that head, so the caller cannot accidentally fork the chain by passing a stale value: the next
/// [`verify`] would fail.
pub fn append(entries: &mut Vec<AuditEntry>, head: &[u8], draft: AuditDraft) -> Vec<u8> {
    append_at(entries, head, draft, crate::unix_now())
}

/// [`append`], stamping the entry with `timestamp` instead of the current time.
///
/// For a draft that was recorded earlier than it could be chained: the vault keeps drafts whose
/// save failed in a pending queue and chains them onto whatever head the file has by the time a
/// later write succeeds — possibly after entries another process wrote in between. The entry's
/// timestamp must still say when the action happened, not when the disk came back, so the log
/// stays truthful about time even where `seq` order and time order differ.
pub fn append_at(
    entries: &mut Vec<AuditEntry>,
    head: &[u8],
    draft: AuditDraft,
    timestamp: u64,
) -> Vec<u8> {
    let entry = AuditEntry {
        seq: entries.len() as u64,
        timestamp,
        actor: draft.actor,
        client_pid: draft.client_pid,
        tool: draft.tool,
        vault_id: draft.vault_id,
        environment_id: draft.environment_id,
        item_id: draft.item_id,
        variables: draft.variables,
        target_path: draft.target_path,
        lease_id: draft.lease_id,
        outcome: draft.outcome,
        detail: draft.detail,
        prev: head.to_vec(),
        unknown: BTreeMap::new(),
        raw: None,
    };
    let new_head = digest(&entry);
    entries.push(entry);
    new_head
}

/// Why a chain did not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// An entry's `seq` is not its index.
    #[error("audit entry {index} claims sequence number {found}")]
    OutOfOrder {
        /// Index in the log.
        index: usize,
        /// The `seq` the entry claims.
        found: u64,
    },
    /// An entry's `prev` does not match the previous entry's digest.
    #[error("audit entry {index} does not follow from the entry before it")]
    BrokenLink {
        /// Index in the log.
        index: usize,
    },
    /// The stored head does not match the last entry's digest.
    #[error("the audit log head does not match the last entry")]
    HeadMismatch,
}

/// Verify the whole chain against a stored head.
///
/// # Errors
///
/// [`ChainError`] describing the first inconsistency found.
pub fn verify(entries: &[AuditEntry], head: &[u8]) -> Result<(), ChainError> {
    let mut expected = genesis();
    for (index, entry) in entries.iter().enumerate() {
        if entry.seq != index as u64 {
            return Err(ChainError::OutOfOrder {
                index,
                found: entry.seq,
            });
        }
        if entry.prev != expected {
            return Err(ChainError::BrokenLink { index });
        }
        expected = digest(entry);
    }
    if head == expected {
        Ok(())
    } else {
        Err(ChainError::HeadMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(tool: &str) -> AuditDraft {
        AuditDraft {
            actor: "cli".to_owned(),
            tool: tool.to_owned(),
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        }
    }

    #[test]
    fn an_empty_log_verifies_against_the_genesis_head() {
        assert_eq!(verify(&[], &genesis()), Ok(()));
    }

    #[test]
    fn appending_keeps_the_chain_intact() {
        let mut entries = Vec::new();
        let mut head = genesis();
        for tool in ["create_environment", "write_env_file", "revoke_env_file"] {
            head = append(&mut entries, &head, draft(tool));
        }
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].prev, genesis());
        assert_eq!(entries[1].prev, digest(&entries[0]));
        assert_eq!(verify(&entries, &head), Ok(()));
    }

    #[test]
    fn dropping_an_entry_from_the_middle_is_detected() {
        let mut entries = Vec::new();
        let mut head = genesis();
        for tool in ["a", "b", "c"] {
            head = append(&mut entries, &head, draft(tool));
        }
        entries.remove(1);
        assert!(matches!(
            verify(&entries, &head),
            Err(ChainError::OutOfOrder { index: 1, found: 2 })
        ));
    }

    #[test]
    fn editing_an_entry_is_detected() {
        let mut entries = Vec::new();
        let mut head = genesis();
        head = append(&mut entries, &head, draft("write_env_file"));
        head = append(&mut entries, &head, draft("revoke_env_file"));
        entries[0].outcome = Outcome::Denied;
        assert!(matches!(
            verify(&entries, &head),
            Err(ChainError::BrokenLink { index: 1 })
        ));
    }

    #[test]
    fn truncating_the_tail_is_detected_by_the_head() {
        let mut entries = Vec::new();
        let mut head = genesis();
        head = append(&mut entries, &head, draft("a"));
        head = append(&mut entries, &head, draft("b"));
        entries.pop();
        assert_eq!(verify(&entries, &head), Err(ChainError::HeadMismatch));
    }

    #[test]
    fn denials_are_recorded_like_anything_else() {
        let mut entries = Vec::new();
        let head = append(
            &mut entries,
            &genesis(),
            AuditDraft {
                actor: "claude-code".to_owned(),
                tool: "write_env_file".to_owned(),
                variables: vec!["STRIPE_SECRET_KEY".to_owned()],
                outcome: Outcome::Denied,
                detail: Some("USER_DENIED".to_owned()),
                ..AuditDraft::default()
            },
        );
        assert_eq!(entries[0].outcome, Outcome::Denied);
        assert_eq!(verify(&entries, &head), Ok(()));
    }

    /// The bug this guards against: `AuditEntry::serialize` used to write `prev` as
    /// `serde_bytes` unconditionally, which a human-readable format like JSON has no byte-string
    /// for and falls back to a plain array of numbers — and `deserialize_prev` (then plain
    /// `#[serde(with = "serde_bytes")]`) had no fallback for that shape, so the IPC client's
    /// `serde_json::from_slice` on a server's `Response::Audit` answered "invalid type: sequence,
    /// expected bytes" for every entry (reproduced with a personal vault alone, no shared vault
    /// needed). `prev` must now round-trip through JSON as it does through CBOR.
    #[test]
    fn prev_round_trips_through_json_like_every_other_format() {
        let entry = AuditEntry {
            seq: 3,
            timestamp: 1_700_000_000,
            actor: "claude-code".to_owned(),
            tool: "write_env_file".to_owned(),
            variables: vec!["STRIPE_SECRET_KEY".to_owned()],
            outcome: Outcome::Allowed,
            prev: digest(&AuditEntry {
                seq: 2,
                prev: genesis(),
                ..Default::default()
            }),
            // A UUID-backed field, which the same bug also broke: decoding through a
            // `ciborium::Value` built from the JSON deserializer answered `is_human_readable()`
            // as binary, so `Uuid::deserialize` expected sixteen bytes and was handed a string
            // instead ("invalid type: string ..., expected bytes").
            vault_id: Some(VaultId::new()),
            environment_id: Some(EnvId::new()),
            item_id: Some(ItemId::new()),
            ..Default::default()
        };

        let json = serde_json::to_string(&entry).expect("a JSON encode");
        // The bug, made visible: `prev` used to be a JSON array of small integers rather than a
        // string, the same shape every other id in this struct avoids by going through `Uuid`.
        let expected = format!("\"prev\":\"{}\"", hex_encode(&entry.prev));
        assert!(
            json.contains(&expected),
            "prev should be a hex string in JSON, got: {json}"
        );

        let back: AuditEntry = serde_json::from_str(&json).expect("a JSON decode");
        assert_eq!(back.prev, entry.prev);
        assert_eq!(back.seq, entry.seq);
        assert_eq!(back.tool, entry.tool);
        assert_eq!(back.variables, entry.variables);
        assert_eq!(back.vault_id, entry.vault_id);
        assert_eq!(back.environment_id, entry.environment_id);
        assert_eq!(back.item_id, entry.item_id);

        // The CBOR shape — a vault file, or `kagisecure-ipc`'s own binary framing were it ever
        // used for this type — is unaffected: still a byte string in, a byte string out.
        let mut cbor = Vec::new();
        ciborium::into_writer(&entry, &mut cbor).expect("a CBOR encode");
        let back: AuditEntry = ciborium::from_reader(cbor.as_slice()).expect("a CBOR decode");
        assert_eq!(back.prev, entry.prev);
    }

    #[test]
    fn the_encoding_is_stable_for_the_same_content() {
        let a = AuditEntry {
            seq: 0,
            timestamp: 1,
            actor: "cli".to_owned(),
            tool: "t".to_owned(),
            variables: vec!["A".to_owned()],
            outcome: Outcome::Allowed,
            prev: genesis(),
            ..Default::default()
        };
        let b = a.clone();
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(digest(&a).len(), DIGEST_LEN);
    }
}

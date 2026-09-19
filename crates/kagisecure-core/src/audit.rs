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
//! `canonical(e)` is the CBOR encoding of [`AuditEntry`] with its fields in declaration order,
//! which is what `ciborium` produces deterministically for a struct. The AEAD tag over the whole
//! body already stops an attacker who cannot decrypt from rewriting history; the chain catches a
//! *legitimately unlocked* process silently dropping or reordering entries, and gives the UI a
//! cheap "log intact" check.

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

/// One recorded action.
///
/// Field order is part of the format: it decides the CBOR encoding, which decides the hash.
/// Adding a field to the middle of this struct breaks every existing chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(with = "serde_bytes")]
    pub prev: Vec<u8>,
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
    let entry = AuditEntry {
        seq: entries.len() as u64,
        timestamp: crate::unix_now(),
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

    #[test]
    fn the_encoding_is_stable_for_the_same_content() {
        let a = AuditEntry {
            seq: 0,
            timestamp: 1,
            actor: "cli".to_owned(),
            client_pid: None,
            tool: "t".to_owned(),
            vault_id: None,
            environment_id: None,
            item_id: None,
            variables: vec!["A".to_owned()],
            target_path: None,
            lease_id: None,
            outcome: Outcome::Allowed,
            detail: None,
            prev: genesis(),
        };
        let b = a.clone();
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(digest(&a).len(), DIGEST_LEN);
    }
}

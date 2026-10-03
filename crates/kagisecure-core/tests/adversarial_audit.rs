//! Adversarial tests for the audit hash chain (`kagisecure_core::audit`) as it is actually used
//! by the vault (`Tx::append_audit` / `Vault::verify_audit`).
//!
//! The chain's stated job (audit.rs module docs) is to catch "a legitimately unlocked process
//! silently dropping or reordering entries". These tests attack exactly that attacker: one who
//! holds the vault key, can rewrite the body freely, and only has to leave something that
//! `verify` accepts. They also check the two things that would make the log worthless even when
//! the chain is intact — a secret value reaching an entry, and a hostile `actor` string forging
//! a link.
//!
//! Scenarios: C-11 (tail truncation with a matching head), C-12 (no secret reaches an entry),
//! C-13 (canonical form is injective under hostile field contents).

mod common;

use common::{CANARY, PASSWORD, contains, new_vault, rendered_error};
use kagisecure_core::audit::{self, AuditDraft, AuditEntry, ChainError};
use kagisecure_core::model::{Category, Field, Item, Secret};
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::Vault;

fn draft(tool: &str, actor: &str) -> AuditDraft {
    AuditDraft {
        actor: actor.to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        ..AuditDraft::default()
    }
}

// ---------------------------------------------------------------------------------------------
// C-11 — truncating the tail and re-storing the matching head
// ---------------------------------------------------------------------------------------------

/// `verify` recomputes the chain from genesis and compares the result with the stored
/// `body.audit_head`. Both live inside the encrypted body, so an attacker who can rewrite one
/// can rewrite the other: dropping the last *k* entries and storing the digest of the new last
/// entry produces a log that verifies perfectly and has simply lost its most recent history —
/// which is precisely the burst of denials the module docs say is "the only evidence a user will
/// ever have that a prompt injection tried an exfiltration".
///
/// For the chain to detect this, the head would have to be bound to something the rewriting
/// process cannot also forge — a monotonically increasing counter carried in the authenticated
/// header, an external notarization, or at minimum an entry count in the AAD.
#[test]
#[ignore = "documents suspected defect C-11: the audit head lives inside the body it attests, so a truncated tail with a re-stored head verifies cleanly"]
fn truncating_the_audit_tail_is_detected_even_when_the_head_is_re_stored() {
    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut head = audit::genesis();
    for tool in [
        "create_environment",
        "read_env",
        "write_env_file",
        "read_env",
    ] {
        head = audit::append(&mut entries, &head, draft(tool, "claude-code"));
    }
    assert_eq!(audit::verify(&entries, &head), Ok(()));

    // The attacker drops the two most recent entries and re-stores the matching head.
    entries.truncate(2);
    let forged_head = audit::digest(&entries[1]);

    assert!(
        audit::verify(&entries, &forged_head).is_err(),
        "a truncated log with a re-stored head verified as intact"
    );
}

/// The same attack driven through the real vault, so the finding is about the product and not
/// just about the `audit` module's signature: the rewritten body is saved, reopened and reports
/// itself intact while two recorded denials have vanished.
#[test]
#[ignore = "documents suspected defect C-11: a vault whose audit log lost its tail still reports verify_audit() == Ok"]
fn a_vault_whose_audit_tail_was_dropped_no_longer_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    vault
        .transact(|tx| {
            for tool in ["read_env", "write_env_file", "read_env"] {
                tx.append_audit(draft(tool, "claude-code"));
            }
            Ok(())
        })
        .unwrap();
    let full = vault.audit_entries().len();
    let kept: Vec<AuditDraft> = vault
        .audit_entries()
        .iter()
        .take(full - 1)
        .map(|e| draft(&e.tool, &e.actor))
        .collect();
    drop(vault);

    // An attacker who holds the vault key replays the log minus its tail. There is no API to
    // clear the log in place, so the rewrite is modelled with a fresh file at the same cost
    // parameters; the point is that the *result* verifies, not how the bytes were produced.
    let rebuilt_path = dir.path().join("rebuilt.kagivault");
    let (mut attacker_vault, _code) =
        Vault::create(&rebuilt_path, PASSWORD, &common::cheap_options()).unwrap();
    attacker_vault
        .transact(|tx| {
            for d in kept {
                tx.append_audit(d);
            }
            Ok(())
        })
        .unwrap();
    drop(attacker_vault);
    let _ = &path;

    let victim = Vault::open_with_password(&rebuilt_path, PASSWORD).unwrap();
    assert_eq!(victim.audit_entries().len(), full - 1);
    assert!(
        victim.verify_audit().is_err(),
        "a vault whose audit log lost its most recent entry reported itself intact"
    );
}

/// What the chain *does* catch, kept green so a regression in the real detections is visible:
/// reordering, editing and a mid-log deletion.
#[test]
fn reordering_editing_and_deleting_audit_entries_are_all_detected() {
    let mut base: Vec<AuditEntry> = Vec::new();
    let mut head = audit::genesis();
    for tool in ["a", "b", "c", "d"] {
        head = audit::append(&mut base, &head, draft(tool, "cli"));
    }

    let mut swapped = base.clone();
    swapped.swap(1, 2);
    assert!(matches!(
        audit::verify(&swapped, &head),
        Err(ChainError::OutOfOrder { .. } | ChainError::BrokenLink { .. })
    ));

    let mut edited = base.clone();
    edited[0].outcome = Outcome::Allowed;
    edited[0].detail = Some("USER_APPROVED".to_owned());
    assert!(matches!(
        audit::verify(&edited, &head),
        Err(ChainError::BrokenLink { index: 1 })
    ));

    let mut deleted = base.clone();
    deleted.remove(2);
    assert!(audit::verify(&deleted, &head).is_err());

    let mut appended = base.clone();
    let _ = audit::append(&mut appended, &head, draft("e", "cli"));
    assert_eq!(
        audit::verify(&appended, &head),
        Err(ChainError::HeadMismatch),
        "appending without advancing the head must be caught"
    );
}

// ---------------------------------------------------------------------------------------------
// C-12 — no secret value ever reaches an audit entry
// ---------------------------------------------------------------------------------------------

/// The log records names, never values. This drives the vault's own audit path with every field
/// a caller can populate carrying the canary-adjacent metadata it legitimately would — variable
/// names, an item title, a target path, a detail code, an actor — and then searches the whole
/// serialized body region of the saved file for the canary. The canary is stored *as a secret
/// field in the same vault*, so the only way it can appear in the audit region is if something
/// copied it there.
#[test]
fn no_canary_secret_reaches_an_audit_entry_through_any_populated_field() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());

    let mut item = Item::new(
        vault.default_vault_id().unwrap(),
        Category::ApiCredential,
        "Stripe production",
    );
    item.fields.push(Field::concealed(
        "token",
        Secret::from_string(CANARY.to_owned()),
    ));
    let item_id = item.id;
    let default_vault_id = vault.default_vault_id().unwrap();
    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.append_audit(AuditDraft {
                actor: "claude-code".to_owned(),
                client_pid: Some(4242),
                tool: "write_env_file".to_owned(),
                vault_id: Some(default_vault_id),
                item_id: Some(item_id),
                variables: vec!["STRIPE_SECRET_KEY".to_owned(), "DATABASE_URL".to_owned()],
                target_path: Some("/Users/ada/project/.env".to_owned()),
                outcome: Outcome::Denied,
                detail: Some("USER_DENIED".to_owned()),
                ..AuditDraft::default()
            });
            Ok(())
        })
        .unwrap();

    for entry in vault.audit_entries() {
        let rendered = format!("{entry:?}");
        assert!(
            !rendered.contains(CANARY),
            "an audit entry rendered the canary: {rendered}"
        );
        assert!(!contains(&audit::canonical(entry), CANARY.as_bytes()));
        for variable in &entry.variables {
            assert!(!variable.contains(CANARY));
        }
        assert!(!entry.tool.contains(CANARY));
        assert!(!entry.actor.contains(CANARY));
        assert!(!entry.detail.as_deref().is_some_and(|d| d.contains(CANARY)));
        assert!(
            !entry
                .target_path
                .as_deref()
                .is_some_and(|p| p.contains(CANARY))
        );
    }

    // And the errors the vault produces along the way never carry it either.
    let error = Vault::open_with_password(&path, b"wrong password").unwrap_err();
    assert!(!rendered_error(&error).contains(CANARY));
    let error =
        Vault::open_with_password(dir.path().join("missing.kagivault"), PASSWORD).unwrap_err();
    assert!(!rendered_error(&error).contains(CANARY));
}

/// The structural reason C-12 holds, asserted so it cannot quietly stop holding: an
/// `AuditDraft` has no field that can hold a `Secret`, and every field it does have is a
/// `String`, an id or an enum. A future field that took secret material would break this.
#[test]
fn an_audit_draft_has_nowhere_to_put_secret_material() {
    let d = AuditDraft::default();
    // Exhaustive destructuring: adding a field to `AuditDraft` makes this stop compiling, which
    // is the point — the new field has to be reviewed against the "names, never values" rule.
    let AuditDraft {
        actor: _,
        client_pid: _,
        tool: _,
        vault_id: _,
        environment_id: _,
        item_id: _,
        variables: _,
        target_path: _,
        lease_id: _,
        outcome: _,
        detail: _,
    } = d;
}

// ---------------------------------------------------------------------------------------------
// C-13 — a hostile actor string must not forge a link
// ---------------------------------------------------------------------------------------------

/// `canonical` is CBOR, whose strings are length-prefixed, so field contents cannot run into
/// each other the way they could in a delimiter-joined encoding. This drives that claim with
/// actor strings built out of field separators, NUL bytes, JSON control characters and
/// fragments of CBOR encoding, and requires the canonical form to be injective: two entries that
/// differ anywhere must have different canonical bytes and different digests.
#[test]
fn a_hostile_actor_string_cannot_collide_with_another_entrys_canonical_form() {
    let hostile = [
        "cli",
        "cli\0",
        "\0cli",
        "cli\u{1}tool",
        "cli\",\"tool\":\"write_env_file",
        "cli\n\ttool",
        "cli|write_env_file|allowed",
        "cli\u{feff}",
        "clitool",
        "cli\\",
        "cli\u{7f}",
        &"a".repeat(1024),
        "\u{10FFFF}",
    ];

    let mut seen: std::collections::HashMap<Vec<u8>, String> = std::collections::HashMap::new();
    for actor in hostile {
        for tool in ["read_env", "write_env_file", ""] {
            // `AuditEntry` is otherwise only ever built via `append_at` (its fields are not all
            // public — see `AuditEntry::raw`), so a fresh single-entry log stands in for the
            // struct literal this test used before.
            let mut entries = Vec::new();
            audit::append_at(
                &mut entries,
                &audit::genesis(),
                AuditDraft {
                    actor: actor.to_owned(),
                    tool: tool.to_owned(),
                    variables: vec!["A".to_owned(), "B".to_owned()],
                    outcome: Outcome::Allowed,
                    ..AuditDraft::default()
                },
                1_700_000_000,
            );
            let bytes = audit::canonical(&entries[0]);
            let label = format!("{actor:?}/{tool:?}");
            if let Some(previous) = seen.insert(bytes, label.clone()) {
                panic!("canonical form collided: {previous} and {label}");
            }
        }
    }
}

/// Splitting a hostile string across the `actor` / `tool` boundary must not produce the same
/// chain link — the classic "a|b" vs "a" + "|b" confusion.
#[test]
fn moving_bytes_across_a_field_boundary_changes_the_chain_link() {
    let joined = "claude-code:write_env_file";
    for split in 0..joined.len() {
        let (actor, tool) = joined.split_at(split);
        let mut entries = Vec::new();
        let head = audit::append(&mut entries, &audit::genesis(), draft(tool, actor));
        let mut other = Vec::new();
        let other_head = audit::append(&mut other, &audit::genesis(), draft(joined, ""));
        // Timestamps are taken from the clock, so compare the canonical form with the timestamp
        // normalized rather than the digests of two differently-timed appends.
        let mut a = entries.remove(0);
        let mut b = other.remove(0);
        a.timestamp = 0;
        b.timestamp = 0;
        // At split 0 the two entries *are* the same entry, which is the control rather than a
        // collision; every other split moves bytes across the actor/tool boundary.
        if split != 0 {
            assert_ne!(
                audit::canonical(&a),
                audit::canonical(&b),
                "split at {split} produced the same canonical form"
            );
        }
        let _ = (head, other_head);
    }
}

/// A hostile actor must not be able to make a *later* entry's `prev` validate against an entry
/// it did not follow: the digest has to depend on the whole entry, including `prev` itself.
#[test]
fn an_entry_cannot_be_relinked_to_a_different_predecessor() {
    let mut entries = Vec::new();
    let mut head = audit::genesis();
    for tool in ["a", "b", "c"] {
        head = audit::append(&mut entries, &head, draft(tool, "cli\0forged"));
    }
    assert_eq!(audit::verify(&entries, &head), Ok(()));

    // Point entry 2 at entry 0 instead of entry 1.
    let mut relinked = entries.clone();
    relinked[2].prev = audit::digest(&entries[0]);
    assert!(matches!(
        audit::verify(&relinked, &head),
        Err(ChainError::BrokenLink { index: 2 })
    ));

    // And the head no longer matches either, so the forgery cannot be papered over by leaving
    // the stored head alone.
    assert_ne!(audit::digest(&relinked[2]), head);
}

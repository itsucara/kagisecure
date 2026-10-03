//! C-13: the audit chain's canonical form must be injective and its verifier must not panic.
//!
//! The chain is only worth anything if two different entries cannot share a canonical encoding:
//! a hostile `actor` or `tool` string carrying field separators, NUL bytes or CBOR-looking
//! fragments must not be able to impersonate a neighbouring field. This target builds two
//! entries out of one input, splitting the same bytes across the `actor`/`tool` boundary at a
//! fuzzer-chosen point, and asserts that the digests differ whenever the entries do.

#![no_main]

use kagisecure_core::audit::{self, AuditEntry};
use kagisecure_core::proto::Outcome;
use libfuzzer_sys::fuzz_target;

fn entry(actor: &str, tool: &str, variables: Vec<String>) -> AuditEntry {
    // Field by field from the default: the entry's private `raw` (the map it was read from) stays
    // empty, as for an entry built in memory.
    let mut entry = AuditEntry::default();
    entry.seq = 0;
    entry.timestamp = 1_700_000_000;
    entry.actor = actor.to_owned();
    entry.client_pid = None;
    entry.tool = tool.to_owned();
    entry.vault_id = None;
    entry.environment_id = None;
    entry.item_id = None;
    entry.variables = variables;
    entry.target_path = None;
    entry.lease_id = None;
    entry.outcome = Outcome::Allowed;
    entry.detail = None;
    entry.prev = audit::genesis();
    entry
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(&data[1..]) else {
        return;
    };

    // Split the same bytes across the actor/tool boundary at a fuzzer-chosen character index.
    let boundary = text
        .char_indices()
        .nth(usize::from(data[0]) % (text.chars().count() + 1))
        .map_or(text.len(), |(i, _)| i);
    let (actor, tool) = text.split_at(boundary);

    let a = entry(actor, tool, vec!["A".to_owned()]);
    let b = entry(text, "", vec!["A".to_owned()]);

    if a != b {
        assert_ne!(
            audit::canonical(&a),
            audit::canonical(&b),
            "two different audit entries share a canonical encoding"
        );
        assert_ne!(audit::digest(&a), audit::digest(&b));
    }

    // The verifier runs on entries read back from a body an attacker may have rewritten.
    let mut entries = vec![a, b];
    let _ = audit::verify(&entries, &audit::genesis());
    entries[1].seq = 1;
    entries[1].prev = audit::digest(&entries[0]);
    let head = audit::digest(&entries[1]);
    assert!(audit::verify(&entries, &head).is_ok());
});

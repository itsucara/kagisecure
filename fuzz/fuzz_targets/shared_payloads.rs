//! The decoders a verified record's payload reaches — a roster operation, an epoch operation,
//! and an item or environment version's plaintext — must never panic on untrusted bytes.
//!
//! Every one of them runs only after a signature verifies (or, for a plaintext, after it
//! decrypts), so `shared_record.rs` does not reach them with fuzzed input; this target hands
//! each the raw bytes. A malicious member signs whatever they like, so the bytes are untrusted
//! all the same.

#![no_main]

use std::sync::OnceLock;

use kagisecure_core::proto::VaultId;
use kagisecure_shared::{EnvVersion, EpochOp, ItemVersion, RosterOp};
use libfuzzer_sys::fuzz_target;

/// A fixed vault id, so that a run is reproducible from its input alone.
fn vault() -> &'static VaultId {
    static VAULT: OnceLock<VaultId> = OnceLock::new();
    VAULT.get_or_init(|| {
        "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a"
            .parse()
            .expect("a well-formed id")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = RosterOp::from_payload(data);
    let _ = EpochOp::from_payload(data);
    let _ = ItemVersion::decode(data, vault());
    let _ = EnvVersion::decode(data, vault());
});

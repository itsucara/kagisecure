//! Step 11 (ADR-0035): the record envelope's hand-rolled reader must never panic on untrusted
//! bytes.
//!
//! A shared vault's records arrive from other people's computers — a sync folder, a USB stick, a
//! git repository — so `record::Envelope::parse` is the first thing a downloaded or corrupted
//! `.ksr` file or bundle entry reaches, the same role `vault_header.rs` plays for a personal
//! vault. This target drives parsing, verifying against a fixed device key, decoding the body and
//! opening the payload, none of which may panic whatever bytes they are given. A fuzzed record's
//! signature almost never verifies, so the body decoder is also driven directly, on whatever the
//! input holds where a body would be (`kagisecure_shared::fuzzing`, the `fuzzing` feature).

#![no_main]

use kagisecure_core::proto::VaultId;
use kagisecure_shared::record::Envelope;
use kagisecure_shared::{DeviceSecret, EpochKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A fixed device key, generated once: any key does, because an author id that does not match it
/// is refused before the signature machinery runs at all.
fn device() -> &'static DeviceSecret {
    static DEVICE: OnceLock<DeviceSecret> = OnceLock::new();
    DEVICE.get_or_init(|| DeviceSecret::generate().expect("the core generator does not fail here"))
}

/// The shared vault a record is verified as: fixed, like the device.
fn vault() -> &'static VaultId {
    static VAULT: OnceLock<VaultId> = OnceLock::new();
    VAULT.get_or_init(|| {
        "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a"
            .parse()
            .expect("a well-formed id")
    })
}

fuzz_target!(|data: &[u8]| {
    kagisecure_shared::fuzzing::decode_record_body(data);
    let Ok(envelope) = Envelope::parse(data) else {
        return;
    };
    let _ = envelope.to_bytes();
    let _ = envelope.author();
    let _ = envelope.id();

    if let Ok(record) = envelope.verify(device().public(), vault()) {
        let _ = format!("{record:?}");
        if let Ok(epoch_key) = EpochKey::generate() {
            let _ = record.open_payload(&epoch_key);
        }
    }
});

//! Computing a roster and a key ring from untrusted records must never panic, and must end.
//!
//! The input is read twice. As a bundle: its first record is named as the genesis, as a
//! replica's header would name one, and the roster and a fixed device's key ring are computed
//! from all of them — records a fuzzer writes rarely verify, so this drives the refusals a
//! hostile exchange copy is made of. And as a script (`kagisecure_shared::fuzzing::
//! roster_script`): which of four fixed test devices writes which roster operation, naming which
//! earlier records as heads and cutting where, signed by the harness — so every input is a
//! roster really computed, removals, cuts, equivocations and all.

#![no_main]

use std::sync::OnceLock;

use kagisecure_core::proto::VaultId;
use kagisecure_shared::{DeviceSecret, KeyRing, RosterState, bundle};
use libfuzzer_sys::fuzz_target;

fn device() -> &'static DeviceSecret {
    static DEVICE: OnceLock<DeviceSecret> = OnceLock::new();
    DEVICE.get_or_init(|| DeviceSecret::generate().expect("the core generator does not fail here"))
}

fn vault() -> &'static VaultId {
    static VAULT: OnceLock<VaultId> = OnceLock::new();
    VAULT.get_or_init(|| {
        "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a"
            .parse()
            .expect("a well-formed id")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = kagisecure_shared::fuzzing::drive_roster_script(data);
    let Ok(envelopes) = bundle::parse(data) else {
        return;
    };
    let Some(genesis) = envelopes.first().map(|e| e.id()) else {
        return;
    };
    let Ok(roster) = RosterState::compute(vault(), &genesis, &envelopes) else {
        return;
    };
    let _ = roster.digest();
    for envelope in &envelopes {
        let _ = roster.authority(&envelope.id());
    }
    let ring = KeyRing::build(&roster, device());
    let _ = ring.digest();
});

//! Runs the shared-vault fuzz targets' exact entry points — `fuzz/fuzz_targets/shared_record.rs`,
//! `shared_bundle.rs`, `shared_payloads.rs` and `shared_roster.rs` — over a small, fixed corpus,
//! on stable Rust. (`shared_record.rs` also drives the record body decoder directly, behind the
//! `fuzzing` feature this test does not enable.)
//!
//! `cargo-fuzz` needs a nightly toolchain, so the real fuzzer at the workspace root's `fuzz/`
//! crate is not part of the ordinary `cargo test` run anyone on stable can do. This test drives
//! the same two entry points — parse a record, verify and try to open it; parse a bundle, and
//! write back what parsed — over a corpus fixed here: empty and near-empty input, the bundle
//! magic alone and one byte short of it, and every truncation and a scattering of single-bit
//! flips of one real record and one real bundle. That covers the realistic corruption (an
//! interrupted write, a partial copy) and the shape most likely to expose an off-by-one in either
//! hand-rolled reader, so "never panics on untrusted bytes" for both is exercised wherever
//! `cargo test -p kagisecure-shared` runs, not only when someone with nightly and `cargo-fuzz`
//! happens to run the real fuzzer.

use kagisecure_core::proto::VaultId;
use kagisecure_shared::bundle;
use kagisecure_shared::record::{Envelope, NewRecord, RecordId, RecordKind};
use kagisecure_shared::{
    DeviceSecret, EnvVersion, EpochId, EpochKey, EpochOp, ItemVersion, KeyRing, MemberId, RosterOp,
    RosterState, Suite,
};

/// The shared vault the corpus's records are written for and verified as.
fn corpus_vault() -> VaultId {
    VaultId(uuid::Uuid::from_bytes([0x5a; 16]))
}

/// Exactly `fuzz/fuzz_targets/shared_record.rs`'s body.
fn drive_record(data: &[u8], device: &DeviceSecret) {
    let Ok(envelope) = Envelope::parse(data) else {
        return;
    };
    let _ = envelope.to_bytes();
    let _ = envelope.author();
    let _ = envelope.id();
    if let Ok(record) = envelope.verify(device.public(), &corpus_vault()) {
        let _ = format!("{record:?}");
        if let Ok(epoch_key) = EpochKey::generate() {
            let _ = record.open_payload(&epoch_key);
        }
    }
}

/// Exactly `fuzz/fuzz_targets/shared_bundle.rs`'s body.
fn drive_bundle(data: &[u8]) {
    if let Ok(envelopes) = bundle::parse(data) {
        let _ = bundle::encode(&envelopes);
    }
}

/// Exactly `fuzz/fuzz_targets/shared_payloads.rs`'s body.
fn drive_payloads(data: &[u8]) {
    let _ = RosterOp::from_payload(data);
    let _ = EpochOp::from_payload(data);
    let _ = ItemVersion::decode(data, &corpus_vault());
    let _ = EnvVersion::decode(data, &corpus_vault());
}

/// Exactly `fuzz/fuzz_targets/shared_roster.rs`'s body.
fn drive_roster(data: &[u8], device: &DeviceSecret) {
    let Ok(envelopes) = bundle::parse(data) else {
        return;
    };
    let Some(genesis) = envelopes.first().map(Envelope::id) else {
        return;
    };
    let Ok(roster) = RosterState::compute(&corpus_vault(), &genesis, &envelopes) else {
        return;
    };
    let _ = roster.digest();
    for envelope in &envelopes {
        let _ = roster.authority(&envelope.id());
    }
    let ring = KeyRing::build(&roster, device);
    let _ = ring.digest();
}

/// A real, well-formed record's bytes, freshly sealed by `device`.
fn sample_record(device: &DeviceSecret) -> Vec<u8> {
    let epoch_key = EpochKey::generate().expect("the core generator does not fail in a test run");
    let record = NewRecord {
        vault_id: corpus_vault(),
        seq: 0,
        prev: None,
        parents: vec![],
        roster: vec![],
        epoch: Some(EpochId::from_bytes([0x0e; 16])),
        created_at: 1_700_000_000,
    };
    Envelope::seal(
        device,
        RecordKind::Item,
        record,
        &epoch_key,
        b"a fuzz corpus seed",
    )
    .expect("a well-formed record seals")
    .to_bytes()
    .to_vec()
}

/// A real, well-formed one-record bundle's bytes.
fn sample_bundle(device: &DeviceSecret) -> Vec<u8> {
    let envelope = Envelope::parse(&sample_record(device)).expect("just sealed above");
    bundle::encode(&[envelope]).expect("a one-record bundle always encodes")
}

/// A real, whole shared vault as a bundle: a genesis and its creation epoch.
fn sample_vault(device: &DeviceSecret) -> Vec<u8> {
    let header = |seq: u64, prev: Option<RecordId>, roster: Vec<RecordId>, epoch| NewRecord {
        vault_id: corpus_vault(),
        seq,
        prev,
        parents: vec![],
        roster,
        epoch,
        created_at: 1_700_000_000,
    };
    let genesis = RosterOp::Genesis {
        suite: Suite::X25519Ed25519V1,
        member: MemberId::from_bytes([0x3c; 16]),
        device: device.public().clone(),
        labels: None,
    }
    .sign(device, header(0, None, vec![], None))
    .expect("a genesis signs");
    let epoch_id = EpochId::derive(&corpus_vault(), &device.id(), 1);
    let key = EpochKey::generate().expect("core generator");
    let op = EpochOp::new_epoch(&corpus_vault(), epoch_id, 0, &key, &[device.public()])
        .expect("a creation epoch");
    // A bundle is sorted by id and `shared_roster.rs` names its first record the genesis, so the
    // epoch record is signed again (a fresh salt) until it sorts after the genesis.
    let epoch = loop {
        let epoch = op
            .sign(
                device,
                header(1, Some(genesis.id()), vec![genesis.id()], Some(epoch_id)),
            )
            .expect("an epoch record signs");
        if epoch.id() > genesis.id() {
            break epoch;
        }
    };
    let records = vec![genesis, epoch];
    bundle::encode(&records).expect("a small bundle encodes")
}

/// The corpus: a handful of hand-picked edge cases, then every truncation and a sampling of
/// single-bit flips of one real record, one real bundle and one real vault.
fn corpus(device: &DeviceSecret) -> Vec<Vec<u8>> {
    let mut cases = vec![
        Vec::new(),
        vec![0u8],
        vec![0xffu8; 4],
        vec![0x84], // a CBOR array(4) head with nothing after it
        b"KAGISBN\0".to_vec(),
        b"KAGISBN".to_vec(), // one byte short of the bundle magic
        vec![0u8; 64],
        vec![0xffu8; 64],
    ];

    let record = sample_record(device);
    for cut in 0..=record.len() {
        cases.push(record[..cut].to_vec());
    }
    for i in (0..record.len()).step_by(7) {
        let mut flipped = record.clone();
        flipped[i] ^= 0x01;
        cases.push(flipped);
    }

    let bundle_bytes = sample_bundle(device);
    for cut in 0..=bundle_bytes.len() {
        cases.push(bundle_bytes[..cut].to_vec());
    }
    for i in (0..bundle_bytes.len()).step_by(11) {
        let mut flipped = bundle_bytes.clone();
        flipped[i] ^= 0x01;
        cases.push(flipped);
    }

    let vault = sample_vault(device);
    for cut in (0..=vault.len()).step_by(3) {
        cases.push(vault[..cut].to_vec());
    }
    for i in (0..vault.len()).step_by(13) {
        let mut flipped = vault.clone();
        flipped[i] ^= 0x01;
        cases.push(flipped);
    }
    cases.push(vault);

    cases
}

/// The corpus's whole vault computes as one: its genesis is the first record, and its device
/// holds the creation epoch's key — so the truncations and flips around it start from a vault
/// that reaches the key ring.
#[test]
fn the_sample_vault_is_a_vault() {
    let device = DeviceSecret::generate().expect("core generator");
    let envelopes = bundle::parse(&sample_vault(&device)).unwrap();
    let roster = RosterState::compute(&corpus_vault(), &envelopes[0].id(), &envelopes).unwrap();
    assert!(roster.role_of(&device.id()).is_some());
    let ring = KeyRing::build(&roster, &device);
    assert!(ring.current_key().is_some());
}

#[test]
fn the_record_and_bundle_readers_never_panic_on_the_fixed_corpus() {
    let device = DeviceSecret::generate().expect("core generator");
    for case in corpus(&device) {
        drive_record(&case, &device);
        drive_bundle(&case);
        drive_payloads(&case);
        drive_roster(&case, &device);
    }
}

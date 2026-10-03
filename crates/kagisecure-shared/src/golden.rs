//! Golden vectors (ADR-0035 §16; addendum, decision 31): files committed the day their format
//! ships and **never edited**. Each is built from public test keys only (RFC vectors) and fixed
//! inputs, so regenerating it gives the same bytes; the tests below check both that the committed
//! file still reads as it did and that this build still writes it byte for byte.
//!
//! A missing vector is written by the ignored test at the bottom, which refuses to overwrite an
//! existing file:
//!
//! ```text
//! cargo test -p kagisecure-shared --lib -- --ignored write_missing_golden_vectors
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kagisecure_core::Secret;
use kagisecure_core::model::{Category, Field, Item};
use kagisecure_core::proto::{FieldId, ItemId, VaultId};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::device::DevicePublic;
use crate::epoch::{EpochOp, KeyRing};
use crate::epoch_key::{EpochId, EpochKey};
use crate::hpke_wrap::{PrefilledRng, wrap_with_rng};
use crate::payload::ItemVersion;
use crate::record::{Envelope, NewRecord, RecordId, RecordKind};
use crate::roster::{MemberId, Role, RosterOp, RosterState};
use crate::suite::Suite;
use crate::test_support::golden_device;

/// The id of `record-item-v1.ksr`.
const GOLDEN_RECORD_ID: &str = "ef1230f929daf428e2e8ca92dba59908a4ed7fcb3880d13d9d0176454dfba9f5";
/// The id of `record-roster-genesis-v1.ksr`.
const GOLDEN_GENESIS_ID: &str = "3761f9951f4ce3600e771fcb5e7fc7aee64922d2f5831ae2da3ad0e2fe00c2ea";
/// The id of `record-epoch-new-v1.ksr`.
const GOLDEN_EPOCH_RECORD_ID: &str =
    "a53b8a9903c5c13db39e35247c9e9a59c769717892f73f151bbf16fd718119ab";

fn vector_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

fn read_vector(name: &str) -> Vec<u8> {
    let path = vector_path(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `device-v1.cbor`: the golden device's public keys.
fn device_v1() -> Vec<u8> {
    golden_device().public().to_cbor()
}

/// The golden record's shared vault, epoch and epoch key: fixed, public test values.
fn golden_vault() -> VaultId {
    VaultId(Uuid::from_u128(0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f))
}

fn golden_epoch() -> EpochId {
    EpochId::from_bytes([0xe0; 16])
}

fn golden_epoch_key() -> EpochKey {
    EpochKey::from_bytes(Zeroizing::new(std::array::from_fn(|i| {
        u8::try_from(i).expect("32 fits in a byte")
    })))
}

const USERNAME_FIELD: u128 = 0x1111_1111_1111_4111_8111_1111_1111_1111;
const PASSWORD_FIELD: u128 = 0x2222_2222_2222_4222_8222_2222_2222_2222;
const GOLDEN_ITEM: u128 = 0x3333_3333_3333_4333_8333_3333_3333_3333;

/// The golden item: a login with a public username and a concealed password.
fn golden_item() -> Item {
    let mut item = Item::new(golden_vault(), Category::Login, "Golden vector");
    item.id = ItemId(Uuid::from_u128(GOLDEN_ITEM));
    item.created_at = 1_790_000_000;
    item.updated_at = 1_790_000_100;
    let mut username = Field::public("username", "golden@example.com");
    username.id = FieldId(Uuid::from_u128(USERNAME_FIELD));
    let mut password = Field::concealed(
        "password",
        Secret::from_string("correct horse battery staple".to_owned()),
    );
    password.id = FieldId(Uuid::from_u128(PASSWORD_FIELD));
    item.fields = vec![username, password];
    item.urls = vec!["https://example.com/login".to_owned()];
    item.primary_secret = Some(FieldId(Uuid::from_u128(PASSWORD_FIELD)));
    item
}

/// `record-item-v1.ksr`: the golden device's first record, a version of the golden item in the
/// golden epoch, naming a stand-in genesis record as its roster head.
fn record_item_v1() -> Vec<u8> {
    let version = ItemVersion::put(golden_vault(), golden_item());
    let record = NewRecord {
        vault_id: golden_vault(),
        seq: 0,
        prev: None,
        parents: vec![],
        roster: vec![RecordId::from_bytes([0x77; 32])],
        epoch: Some(golden_epoch()),
        created_at: 1_790_000_100,
    };
    Envelope::seal_with(
        &golden_device(),
        RecordKind::Item,
        record,
        &golden_epoch_key(),
        &version.encode().unwrap(),
        [0x5a; 16],
        [0x24; 24],
    )
    .unwrap()
    .to_bytes()
    .to_vec()
}

/// The golden vault's creator: a fixed, public member id.
fn golden_member() -> MemberId {
    MemberId::from_bytes([0x3c; 16])
}

/// RFC 9180 A.2.1's `ikmE`: the golden epoch wrap's randomness.
const IKM_E: [u8; 32] = [
    0x90, 0x9a, 0x9b, 0x35, 0xd3, 0xdc, 0x47, 0x13, 0xa5, 0xe7, 0x2a, 0x4d, 0xa2, 0x74, 0xb5, 0x5d,
    0x3d, 0x38, 0x21, 0xa3, 0x7e, 0x5d, 0x09, 0x9e, 0x74, 0xa6, 0x47, 0xdb, 0x58, 0x3a, 0x90, 0x4b,
];

/// `record-roster-genesis-v1.ksr`: the golden vault's genesis — the golden device's first
/// record, making the golden member its first admin on the golden device.
fn record_roster_genesis_v1() -> Vec<u8> {
    let op = RosterOp::Genesis {
        suite: Suite::X25519Ed25519V1,
        member: golden_member(),
        device: golden_device().public().clone(),
        labels: None,
    };
    let record = NewRecord {
        vault_id: golden_vault(),
        seq: 0,
        prev: None,
        parents: vec![],
        roster: vec![],
        epoch: None,
        created_at: 1_790_000_000,
    };
    op.sign_with_salt(&golden_device(), record, [0x6a; 16])
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// The golden vault's creation epoch: its id derived from the record that mints it, the golden
/// device's record at `seq` 1 (decision 67).
fn golden_creation_epoch() -> EpochId {
    EpochId::derive(&golden_vault(), &golden_device().id(), 1)
}

/// `record-epoch-new-v1.ksr`: the golden vault's creation epoch — the golden device's second
/// record, naming the genesis as its roster head, wrapping the golden epoch key to itself with
/// RFC 9180's `ikmE` as the wrap's randomness.
fn record_epoch_new_v1() -> Vec<u8> {
    let genesis = Envelope::parse(&record_roster_genesis_v1()).unwrap().id();
    let device = golden_device();
    let mut rng = PrefilledRng::from_bytes(&IKM_E);
    let wrap = wrap_with_rng(
        device.public(),
        &golden_vault(),
        &golden_creation_epoch(),
        &golden_epoch_key(),
        &mut rng,
    )
    .unwrap();
    let op = EpochOp::New {
        epoch_id: golden_creation_epoch(),
        height: 0,
        wraps: BTreeMap::from([(device.id(), wrap)]),
    };
    let record = NewRecord {
        vault_id: golden_vault(),
        seq: 1,
        prev: Some(genesis),
        parents: vec![],
        roster: vec![genesis],
        epoch: Some(golden_creation_epoch()),
        created_at: 1_790_000_050,
    };
    op.sign_with_salt(&device, record, [0x6b; 16])
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// Every vector this crate commits, by file name, with how to build it.
fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("device-v1.cbor", device_v1()),
        ("record-item-v1.ksr", record_item_v1()),
        ("record-roster-genesis-v1.ksr", record_roster_genesis_v1()),
        ("record-epoch-new-v1.ksr", record_epoch_new_v1()),
    ]
}

/// The two records are a whole shared vault: its roster makes the golden device an admin, and
/// the golden device holds the golden epoch key through its wrap.
#[test]
fn the_roster_and_epoch_golden_vectors_are_a_vault_and_are_rewritten_byte_for_byte() {
    let genesis_bytes = read_vector("record-roster-genesis-v1.ksr");
    let epoch_bytes = read_vector("record-epoch-new-v1.ksr");
    let genesis = Envelope::parse(&genesis_bytes).unwrap();
    let epoch = Envelope::parse(&epoch_bytes).unwrap();
    assert_eq!(genesis.id().to_string(), GOLDEN_GENESIS_ID);
    assert_eq!(epoch.id().to_string(), GOLDEN_EPOCH_RECORD_ID);

    let record = genesis
        .verify(golden_device().public(), &golden_vault())
        .unwrap();
    assert_eq!(record.body().kind(), &RecordKind::Roster);
    assert_eq!(record.body().record_salt(), &[0x6a; 16]);
    let RosterOp::Genesis { member, device, .. } = RosterOp::from_record(&record).unwrap() else {
        panic!("not a genesis");
    };
    assert_eq!(member, golden_member());
    assert_eq!(&device, golden_device().public());

    let record = epoch
        .verify(golden_device().public(), &golden_vault())
        .unwrap();
    assert_eq!(record.body().kind(), &RecordKind::Epoch);
    assert_eq!(record.body().roster(), &[genesis.id()]);
    assert_eq!(record.body().prev(), Some(&genesis.id()));
    let EpochOp::New { height, wraps, .. } = EpochOp::from_record(&record).unwrap() else {
        panic!("not a new epoch");
    };
    assert_eq!(height, 0);
    assert_eq!(
        wraps.keys().copied().collect::<Vec<_>>(),
        [golden_device().id()]
    );

    let roster =
        RosterState::compute(&golden_vault(), &genesis.id(), &[epoch.clone(), genesis]).unwrap();
    assert_eq!(roster.role_of(&golden_device().id()), Some(Role::Admin));
    assert!(roster.ignored().is_empty() && roster.waiting().is_empty());
    let ring = KeyRing::build(&roster, &golden_device());
    assert_eq!(ring.current_epoch(), Some(golden_creation_epoch()));
    assert_eq!(
        ring.current_key().unwrap().as_bytes(),
        golden_epoch_key().as_bytes()
    );
    assert!(ring.refused().is_empty());

    assert_eq!(record_roster_genesis_v1(), genesis_bytes);
    assert_eq!(record_epoch_new_v1(), epoch_bytes);
}

#[test]
fn the_item_record_golden_vector_verifies_decrypts_and_is_rewritten_byte_for_byte() {
    let bytes = read_vector("record-item-v1.ksr");
    let envelope = Envelope::parse(&bytes).unwrap();
    assert_eq!(envelope.id().to_string(), GOLDEN_RECORD_ID);
    assert_eq!(envelope.author(), golden_device().id());
    let record = envelope
        .verify(golden_device().public(), &golden_vault())
        .unwrap();
    let body = record.body();
    assert_eq!(body.kind(), &RecordKind::Item);
    assert_eq!(body.vault_id(), &golden_vault());
    assert_eq!(body.seq(), 0);
    assert_eq!(body.roster(), &[RecordId::from_bytes([0x77; 32])]);
    assert_eq!(body.epoch(), Some(&golden_epoch()));
    assert_eq!(body.record_salt(), &[0x5a; 16]);

    let item = ItemVersion::open(&record, &golden_epoch_key())
        .unwrap()
        .into_item()
        .unwrap();
    assert_eq!(item.id, ItemId(Uuid::from_u128(GOLDEN_ITEM)));
    assert_eq!(item.title, "Golden vector");
    assert_eq!(item.username(), Some("golden@example.com"));
    assert_eq!(
        item.primary_secret_field()
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        b"correct horse battery staple"
    );
    assert!(!item.agent_visible && !item.favorite);

    assert_eq!(record_item_v1(), bytes);
}

#[test]
fn the_device_golden_vector_reads_back_and_is_rewritten_byte_for_byte() {
    let bytes = read_vector("device-v1.cbor");
    let public = DevicePublic::from_cbor(&bytes).unwrap();
    assert_eq!(
        public.id().to_string(),
        "1ccbda9a1b81bbf470d5ab39998783822db70612b841fca593e81d9222b05b8f"
    );
    assert_eq!(
        public.fingerprint().to_string(),
        "07371 55962 07041 48116 28885 43833 39303 33666 11703 01554"
    );
    assert_eq!(&public, golden_device().public());
    assert_eq!(device_v1(), bytes);
}

/// The device key `kagisecure-core`'s own golden vector stores loads here as the same device:
/// the id the core wrote as a constant is the id this crate derives from the key material.
#[test]
fn the_core_golden_vectors_device_key_is_the_golden_device() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kagisecure-core/tests/vectors/v2-devices-argon2id-64k.kagivault");
    let dir = tempfile::tempdir().unwrap();
    let working = dir.path().join("golden-v2.kagivault");
    std::fs::copy(&source, &working).unwrap();
    let vault =
        kagisecure_core::Vault::open_with_password(&working, b"golden vector password").unwrap();
    let keys: Vec<_> = vault.active_device_keys().collect();
    assert_eq!(keys.len(), 1);
    let device = crate::DeviceSecret::from_device_key(keys[0]).unwrap();
    assert_eq!(device.id(), golden_device().id());
    assert_eq!(device.public(), golden_device().public());
}

/// Known answers for the derivations and seals the golden files do not pin byte for byte on
/// their own (ADR-0035 addendum, "Epoch commitment", "Record key", "Epoch chain key", "Epoch
/// wrap"; decisions 35, 36), from the golden vault, epoch and key and fixed randomness. Each
/// value was cross-checked, when it was written, against a separate implementation of HKDF
/// (RFC 5869), XChaCha20-Poly1305 and HPKE Base mode (RFC 9180, reproducing its A.2.1 vector)
/// written from the specifications rather than from this crate. Like the files, these are never
/// edited: a change here is a format change.
mod known_answers {
    use super::*;
    use crate::device::hex;

    #[test]
    fn the_record_key() {
        let key = golden_epoch_key().record_key(&golden_vault(), &[0x5a; 16]);
        assert_eq!(
            hex(key.as_bytes()),
            "6d3f41f2ea2f3f02c220f20464c05a98b4084053e4d63fa73d6a85eda0988eb5"
        );
    }

    /// The golden epoch's key wrapped to the golden device, with RFC 9180's `ikmE` as the
    /// ephemeral key's randomness — so `enc` is the RFC's own.
    #[test]
    fn an_epoch_wrap() {
        let mut rng = PrefilledRng::from_bytes(&IKM_E);
        let wrap = wrap_with_rng(
            golden_device().public(),
            &golden_vault(),
            &golden_epoch(),
            &golden_epoch_key(),
            &mut rng,
        )
        .unwrap();
        let bytes = wrap.to_bytes();
        assert_eq!(
            hex(&bytes[..32]),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        );
        assert_eq!(
            hex(&bytes),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a\
             b19ea07353b8be8f0e8d80073e43e9a93d09954ef967adbae7ebbd2d3e19609a\
             07ea5d88ff06e0164bce85a12a70f8fd"
        );
        let opened = crate::hpke_wrap::unwrap_epoch_key(
            &golden_device(),
            &golden_vault(),
            &golden_epoch(),
            &wrap,
        )
        .unwrap();
        assert_eq!(opened.as_bytes(), golden_epoch_key().as_bytes());
    }
}

#[test]
fn every_golden_vector_is_committed() {
    for (name, _) in vectors() {
        assert!(vector_path(name).is_file(), "{name} is missing");
    }
}

#[test]
#[ignore = "writes missing golden vectors; run by hand when a format ships"]
fn write_missing_golden_vectors() {
    for (name, bytes) in vectors() {
        let path = vector_path(name);
        if path.exists() {
            continue;
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }
}

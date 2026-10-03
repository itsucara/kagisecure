//! Fixtures shared by this crate's unit tests. Public test data only: every key here is an RFC
//! test vector's, never a real one.

use kagisecure_core::Secret;
use kagisecure_core::vault::DeviceKey;

use crate::device::DeviceSecret;

/// RFC 7748 §6.1, Alice's private key: the golden device's X25519 secret.
pub(crate) const ALICE_X25519_SECRET: &str =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
/// RFC 8032 §7.1, TEST 1's secret key: the golden device's Ed25519 seed.
pub(crate) const TEST_1_ED25519_SEED: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

pub(crate) fn unhex32(text: &str) -> [u8; 32] {
    unhex(text).try_into().expect("32 bytes of hex")
}

/// A device with the golden X25519 secret and the given Ed25519 seed, loaded through the
/// personal vault's entry the way every real device is.
pub(crate) fn device_with_seed(seed: [u8; 32]) -> DeviceSecret {
    let mut secret = unhex(ALICE_X25519_SECRET);
    secret.extend_from_slice(&seed);
    let entry = DeviceKey::new(
        derive_id(&secret),
        "x25519-ed25519-v1",
        "Test device",
        0,
        Secret::new(secret),
    )
    .expect("a well-formed entry");
    DeviceSecret::from_device_key(&entry).expect("an RFC test key")
}

/// The id of a 64-byte `x25519-ed25519-v1` secret, from its public halves.
fn derive_id(secret: &[u8]) -> [u8; 32] {
    let x: [u8; 32] = secret[..32].try_into().unwrap();
    let seed: [u8; 32] = secret[32..].try_into().unwrap();
    let kem = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x));
    let sig = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    *crate::device::DeviceKeyId::derive(
        crate::suite::Suite::X25519Ed25519V1,
        kem.as_bytes(),
        sig.as_bytes(),
    )
    .as_bytes()
}

/// The golden device: RFC 7748 Alice's X25519 key and RFC 8032 TEST 1's Ed25519 key, the device
/// `kagisecure-core`'s golden vector `v2-devices-argon2id-64k.kagivault` holds.
pub(crate) fn golden_device() -> DeviceSecret {
    device_with_seed(unhex32(TEST_1_ED25519_SEED))
}

/// A test device with its own X25519 and Ed25519 keys, distinct for every `n`: the golden
/// device shares Alice's X25519 key with every [`device_with_seed`] device, and a roster refuses
/// two devices with one public key.
pub(crate) fn test_device(n: u8) -> DeviceSecret {
    let mut secret = vec![n ^ 0xa5; 32];
    secret[0] = n;
    secret.extend_from_slice(&[n; 32]);
    let entry = DeviceKey::new(
        derive_id(&secret),
        "x25519-ed25519-v1",
        "Test device",
        0,
        Secret::new(secret),
    )
    .expect("a well-formed entry");
    DeviceSecret::from_device_key(&entry).expect("a test key")
}

/// A test vault id.
pub(crate) fn test_vault() -> kagisecure_core::proto::VaultId {
    kagisecure_core::proto::VaultId(uuid::Uuid::from_bytes([0x5a; 16]))
}

/// A device writing records in order: it keeps its own `seq` and `prev`, as a real device does.
pub(crate) struct Writer {
    pub(crate) device: DeviceSecret,
    n: u8,
    seq: u64,
    prev: Option<crate::record::RecordId>,
}

impl Writer {
    pub(crate) fn new(n: u8) -> Self {
        Self {
            device: test_device(n),
            n,
            seq: 0,
            prev: None,
        }
    }

    /// The same device, at the same point of its chain: writing with both equivocates.
    pub(crate) fn fork(&self) -> Self {
        Self {
            device: test_device(self.n),
            n: self.n,
            seq: self.seq,
            prev: self.prev,
        }
    }

    pub(crate) fn id(&self) -> crate::device::DeviceKeyId {
        self.device.id()
    }

    /// The `seq` of this device's next record.
    pub(crate) const fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn public(&self) -> crate::device::DevicePublic {
        self.device.public().clone()
    }

    /// The header of this device's next record, in `test_vault`, naming `roster` heads.
    pub(crate) fn header(
        &self,
        roster: &[crate::record::RecordId],
        epoch: Option<crate::epoch_key::EpochId>,
    ) -> crate::record::NewRecord {
        crate::record::NewRecord {
            vault_id: test_vault(),
            seq: self.seq,
            prev: self.prev,
            parents: vec![],
            roster: roster.to_vec(),
            epoch,
            created_at: 1_790_000_000 + self.seq,
        }
    }

    /// Count `envelope` as this device's latest record.
    pub(crate) fn wrote(&mut self, envelope: crate::record::Envelope) -> crate::record::Envelope {
        assert_eq!(envelope.author(), self.device.id());
        self.seq += 1;
        self.prev = Some(envelope.id());
        envelope
    }

    /// Write a roster record.
    pub(crate) fn roster(
        &mut self,
        op: &crate::roster::RosterOp,
        heads: &[crate::record::RecordId],
    ) -> crate::record::Envelope {
        let envelope = op
            .sign(&self.device, self.header(heads, None))
            .expect("a roster record");
        self.wrote(envelope)
    }

    /// Write an acknowledgement-kind record with an arbitrary payload, as a stand-in for any
    /// non-roster record.
    pub(crate) fn ack(
        &mut self,
        heads: &[crate::record::RecordId],
        epoch: Option<crate::epoch_key::EpochId>,
        payload: Vec<u8>,
    ) -> crate::record::Envelope {
        let envelope = crate::record::Envelope::sign_plain(
            &self.device,
            crate::record::RecordKind::Ack,
            self.header(heads, epoch),
            payload,
        )
        .expect("a plain record");
        self.wrote(envelope)
    }
}

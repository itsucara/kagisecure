//! Device keys' public halves, their ids and fingerprints, and the secret half borrowed from the
//! personal vault (ADR-0035 §2, §5, §10; addendum, "Device key id" and "Fingerprint").
//!
//! A device is one computer's key pair in every shared vault it belongs to: an X25519 key that
//! epoch keys are wrapped to, and an Ed25519 key that signs its records. The secret half lives in
//! the personal vault's encrypted body as a `kagisecure_core::vault::DeviceKey`; this module
//! turns one into a [`DeviceSecret`] for as long as a signature or an unwrap needs it, and
//! generates new ones.
//!
//! # Strict public keys
//!
//! A [`DevicePublic`] can only be built from keys that pass every check this format makes, so a
//! value of the type is itself the proof that it passed them:
//!
//! - **X25519:** the canonical encoding of a field element (below 2^255 − 19, top bit clear), and
//!   not of small order — a key whose Diffie-Hellman output is the same for every sender, which
//!   would make every epoch key wrapped to it readable by anyone.
//! - **Ed25519:** a point on the curve, in its canonical encoding, not of small order — a weak
//!   key for which one signature can verify for almost any message — and torsion-free: in the
//!   prime-order subgroup, with no small-order component that cofactored and cofactorless
//!   verifiers could disagree about.
//!
//! The device key id covers both public keys and the suite, so neither half can be swapped
//! without the id — and so the fingerprint a person compares — changing.

use ciborium::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use kagisecure_core::Secret;
use kagisecure_core::vault::DeviceKey;
use kagisecure_core::vault::device::{DEVICE_KEY_ID_LEN, X25519_ED25519_V1_SECRET_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor;
use crate::error::{Result, SharedError};
use crate::suite::Suite;

/// Length of a raw X25519 or Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The device key id's domain-separation string (ADR-0035 addendum, "Device key id").
const DEVICE_ID_DOMAIN: &[u8] = b"kagisecure/shared/device/v1";

/// How many groups of five digits a fingerprint is read as.
pub const FINGERPRINT_GROUPS: usize = 10;

/// The QR payload's prefix (ADR-0035 addendum, "Fingerprint").
const QR_PREFIX: &str = "kagisecure-fp:1:";

/// A fixed, public X25519 scalar used only to test a peer's public key for small order: after
/// clamping it is a multiple of the cofactor, so its product with any point of small order — on
/// the curve or its twist — is the identity, and with any other point it is not.
const SMALL_ORDER_PROBE: [u8; 32] = [0x5a; 32];

/// Lower-case hex, for ids. Ids are public.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A device key id: `SHA-256("kagisecure/shared/device/v1" ‖ 0x00 ‖ suite ‖ 0x00 ‖ kem_pk ‖
/// sig_pk)`. Public: it names the device in every roster and every record it signs, and the
/// personal vault stores the same 32 bytes as its `device_key_id`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceKeyId([u8; DEVICE_KEY_ID_LEN]);

impl DeviceKeyId {
    /// The id of a device with these public keys under `suite`.
    #[must_use]
    pub fn derive(
        suite: Suite,
        kem_pk: &[u8; PUBLIC_KEY_LEN],
        sig_pk: &[u8; PUBLIC_KEY_LEN],
    ) -> Self {
        let digest = Sha256::new()
            .chain_update(DEVICE_ID_DOMAIN)
            .chain_update([0x00])
            .chain_update(suite.name().as_bytes())
            .chain_update([0x00])
            .chain_update(kem_pk)
            .chain_update(sig_pk)
            .finalize();
        Self(digest.into())
    }

    /// An id as read from a file. Whether a device with this id exists is the roster's question.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DEVICE_KEY_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_KEY_ID_LEN] {
        &self.0
    }

    /// The fingerprint a person compares for this device (ADR-0035 §10).
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        Fingerprint(self.0)
    }
}

impl std::fmt::Debug for DeviceKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceKeyId({})", hex(&self.0))
    }
}

impl std::fmt::Display for DeviceKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

/// A device's fingerprint, for a person to compare in full — never in part (ADR-0035 §10).
///
/// Rendered as ten groups of five decimal digits: the first 20 bytes of the device key id read as
/// ten big-endian `u16`s (160 bits, above §10's floor of 128). The QR payload carries the whole
/// 32-byte id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; DEVICE_KEY_ID_LEN]);

impl Fingerprint {
    /// The ten groups, each five zero-padded digits, in reading order.
    #[must_use]
    pub fn groups(&self) -> [String; FINGERPRINT_GROUPS] {
        std::array::from_fn(|i| {
            let group = u16::from_be_bytes([self.0[2 * i], self.0[2 * i + 1]]);
            format!("{group:05}")
        })
    }

    /// The QR code's text: `kagisecure-fp:1:` and the full device key id in lower-case hex.
    #[must_use]
    pub fn qr_payload(&self) -> String {
        format!("{QR_PREFIX}{}", hex(&self.0))
    }

    /// The device key id this is the fingerprint of.
    #[must_use]
    pub const fn device_key_id(&self) -> DeviceKeyId {
        DeviceKeyId(self.0)
    }
}

impl std::fmt::Display for Fingerprint {
    /// The ten groups separated by single spaces.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.groups().join(" "))
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Whether `pk` is the canonical encoding of a field element: top bit clear and below
/// 2^255 − 19.
fn x25519_is_canonical(pk: &[u8; PUBLIC_KEY_LEN]) -> bool {
    if pk[31] & 0x80 != 0 {
        return false;
    }
    // Only values from 2^255 − 19 to 2^255 − 1 are out of range: 0x7f, then thirty 0xff, then a
    // lowest byte of 0xed or more (little-endian).
    let at_least_p = pk[31] == 0x7f && pk[1..31].iter().all(|&b| b == 0xff) && pk[0] >= 0xed;
    !at_least_p
}

/// Refuse an X25519 public key this format does not accept (module documentation).
fn check_x25519_public(pk: &[u8; PUBLIC_KEY_LEN]) -> Result<()> {
    if !x25519_is_canonical(pk) {
        return Err(SharedError::InvalidPublicKey(
            "an X25519 public key is not canonically encoded",
        ));
    }
    let probe = x25519_dalek::StaticSecret::from(SMALL_ORDER_PROBE);
    if !probe
        .diffie_hellman(&x25519_dalek::PublicKey::from(*pk))
        .was_contributory()
    {
        return Err(SharedError::InvalidPublicKey(
            "an X25519 public key is of small order",
        ));
    }
    Ok(())
}

/// Refuse an Ed25519 public key this format does not accept (module documentation).
fn check_ed25519_public(pk: &[u8; PUBLIC_KEY_LEN]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(pk).map_err(|_| {
        SharedError::InvalidPublicKey("an Ed25519 public key is not a point on the curve")
    })?;
    if key.to_edwards().compress().to_bytes() != *pk {
        return Err(SharedError::InvalidPublicKey(
            "an Ed25519 public key is not canonically encoded",
        ));
    }
    if key.is_weak() {
        return Err(SharedError::InvalidPublicKey(
            "an Ed25519 public key is of small order",
        ));
    }
    // A key with a small-order component verifies differently under a cofactored and a
    // cofactorless verifier; an honest device's key never has one.
    if !key.to_edwards().is_torsion_free() {
        return Err(SharedError::InvalidPublicKey(
            "an Ed25519 public key has a small-order component",
        ));
    }
    Ok(key)
}

/// A device's public keys, checked strictly (module documentation). Public: it travels in
/// enrollment requests and rosters.
#[derive(Clone)]
pub struct DevicePublic {
    suite: Suite,
    kem_pk: [u8; PUBLIC_KEY_LEN],
    sig_pk: [u8; PUBLIC_KEY_LEN],
    verifying: VerifyingKey,
    id: DeviceKeyId,
}

impl DevicePublic {
    /// A device's public keys under `suite`, if they pass every check this format makes.
    ///
    /// # Errors
    ///
    /// [`SharedError::InvalidPublicKey`] naming the first rule a key breaks.
    pub fn new(
        suite: Suite,
        kem_pk: [u8; PUBLIC_KEY_LEN],
        sig_pk: [u8; PUBLIC_KEY_LEN],
    ) -> Result<Self> {
        match suite {
            Suite::X25519Ed25519V1 => {}
        }
        check_x25519_public(&kem_pk)?;
        let verifying = check_ed25519_public(&sig_pk)?;
        Ok(Self {
            suite,
            kem_pk,
            sig_pk,
            verifying,
            id: DeviceKeyId::derive(suite, &kem_pk, &sig_pk),
        })
    }

    /// The suite.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// The raw X25519 public key epoch keys are wrapped to.
    #[must_use]
    pub const fn kem_pk(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.kem_pk
    }

    /// The raw Ed25519 public key records are verified with.
    #[must_use]
    pub const fn sig_pk(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sig_pk
    }

    /// The device key id.
    #[must_use]
    pub const fn id(&self) -> DeviceKeyId {
        self.id
    }

    /// The fingerprint a person compares.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.id.fingerprint()
    }

    pub(crate) const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// The deterministic CBOR map `{"suite": text, "kem_pk": bytes(32), "sig_pk": bytes(32)}`
    /// (`tests/vectors/device-v1.cbor`).
    pub(crate) fn to_value(&self) -> Value {
        cbor::map(vec![
            (cbor::text("suite"), cbor::text(self.suite.name())),
            (cbor::text("kem_pk"), cbor::bytes(&self.kem_pk)),
            (cbor::text("sig_pk"), cbor::bytes(&self.sig_pk)),
        ])
    }

    /// Read [`Self::to_value`]'s map back: exactly those three keys, a known suite, and keys
    /// that pass [`Self::new`].
    pub(crate) fn from_value(value: Value) -> Result<Self> {
        const SHAPE: &str = "a device public key is a map of suite, kem_pk and sig_pk";
        let mut suite = None;
        let mut kem_pk = None;
        let mut sig_pk = None;
        for (key, value) in cbor::text_map(value, SHAPE)? {
            match key.as_str() {
                "suite" => {
                    let Value::Text(name) = value else {
                        return Err(SharedError::Malformed(SHAPE));
                    };
                    suite = Some(Suite::from_name(&name)?);
                }
                "kem_pk" => kem_pk = Some(cbor::fixed_bytes(&value, SHAPE)?),
                "sig_pk" => sig_pk = Some(cbor::fixed_bytes(&value, SHAPE)?),
                // A field this build does not know could change what the key means; a later
                // format that needs one names a new suite.
                _ => return Err(SharedError::Malformed(SHAPE)),
            }
        }
        match (suite, kem_pk, sig_pk) {
            (Some(suite), Some(kem_pk), Some(sig_pk)) => Self::new(suite, kem_pk, sig_pk),
            _ => Err(SharedError::Malformed(SHAPE)),
        }
    }

    /// This device's public keys as deterministic CBOR (`tests/vectors/device-v1.cbor`).
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// Read [`Self::to_cbor`]'s encoding. Anything but exactly that encoding is refused, and the
    /// keys are checked as [`Self::new`] checks them.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for another shape or a non-deterministic encoding,
    /// [`SharedError::UnsupportedSuite`] for an unknown suite, and
    /// [`SharedError::InvalidPublicKey`] for a key that fails a check.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        // A device public key is under a hundred bytes; anything much larger is not one, and is
        // refused before it is decoded.
        const MAX_DEVICE_PUBLIC_BYTES: usize = 256;
        if bytes.len() > MAX_DEVICE_PUBLIC_BYTES {
            return Err(SharedError::LimitExceeded {
                what: "device public key",
                limit: MAX_DEVICE_PUBLIC_BYTES as u64,
            });
        }
        Self::from_value(cbor::decode_canonical(bytes)?)
    }
}

impl PartialEq for DevicePublic {
    fn eq(&self, other: &Self) -> bool {
        self.suite == other.suite && self.kem_pk == other.kem_pk && self.sig_pk == other.sig_pk
    }
}

impl Eq for DevicePublic {}

impl std::fmt::Debug for DevicePublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePublic")
            .field("suite", &self.suite)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A device's secret keys, for as long as a signature or an unwrap needs them.
///
/// No `Clone`, no `Serialize`, and a `Debug` that shows the id alone. The X25519 secret is held
/// as the 32 bytes the personal vault stores, in a zeroizing buffer; the Ed25519 signing key
/// wipes itself on drop (`ed25519-dalek`'s `zeroize` feature). The one way out of this type is
/// back into the personal vault, through [`Self::to_device_key`].
pub struct DeviceSecret {
    x25519: Zeroizing<[u8; 32]>,
    signing: SigningKey,
    public: DevicePublic,
}

impl DeviceSecret {
    /// A new device key pair, from `kagisecure-core`'s generator — the one path to the operating
    /// system's CSPRNG in the workspace.
    ///
    /// # Errors
    ///
    /// [`SharedError::Core`] if the generator fails. There is no fallback.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; X25519_ED25519_V1_SECRET_LEN]);
        kagisecure_core::crypto::random::fill(bytes.as_mut_slice())?;
        Self::from_secret_bytes(bytes.as_slice())
    }

    /// The device key a personal vault holds, checked against the id it was stored under.
    ///
    /// # Errors
    ///
    /// [`SharedError::UnsupportedSuite`] for a suite this build does not implement,
    /// [`SharedError::Malformed`] for secret key material of the wrong length, and
    /// [`SharedError::DeviceKeyMismatch`] if the stored id is not the id of the key material.
    pub fn from_device_key(key: &DeviceKey) -> Result<Self> {
        Suite::from_name(key.suite())?;
        let secret = Self::from_secret_bytes(key.secret_keys().expose())?;
        // Compared as public values: a device key id is public.
        if secret.public.id.as_bytes() != key.id() {
            return Err(SharedError::DeviceKeyMismatch);
        }
        Ok(secret)
    }

    /// `x25519-ed25519-v1`'s 64 bytes: the X25519 secret key, then the Ed25519 seed.
    pub(crate) fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_ED25519_V1_SECRET_LEN {
            return Err(SharedError::Malformed(
                "an x25519-ed25519-v1 device key has 64 bytes of secret keys",
            ));
        }
        let mut x25519 = Zeroizing::new([0u8; 32]);
        x25519.copy_from_slice(&bytes[..32]);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[32..]);
        let signing = SigningKey::from_bytes(&seed);
        // Not `StaticSecret::from(*x25519)`: that would copy the secret by value onto the stack,
        // where nothing wipes it.
        let kem_pk = crate::hpke_wrap::x25519_public_key(&x25519)?;
        let public = DevicePublic::new(
            Suite::X25519Ed25519V1,
            kem_pk,
            signing.verifying_key().to_bytes(),
        )?;
        Ok(Self {
            x25519,
            signing,
            public,
        })
    }

    /// This device's key, for the personal vault to hold (`Tx::add_device_key`).
    ///
    /// # Errors
    ///
    /// [`SharedError::Core`] if the personal vault refuses the entry (a label longer than 128
    /// characters, for instance).
    pub fn to_device_key(&self, label: &str, created_at: u64) -> Result<DeviceKey> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(X25519_ED25519_V1_SECRET_LEN));
        bytes.extend_from_slice(self.x25519.as_slice());
        bytes.extend_from_slice(self.signing.as_bytes());
        Ok(DeviceKey::new(
            *self.public.id.as_bytes(),
            self.public.suite.name(),
            label,
            created_at,
            Secret::new(std::mem::take(&mut *bytes)),
        )?)
    }

    /// This device's public keys.
    #[must_use]
    pub const fn public(&self) -> &DevicePublic {
        &self.public
    }

    /// This device's key id.
    #[must_use]
    pub const fn id(&self) -> DeviceKeyId {
        self.public.id
    }

    /// The X25519 secret key, for unwrapping an epoch key.
    pub(crate) fn x25519_secret(&self) -> &[u8; 32] {
        &self.x25519
    }

    /// The Ed25519 signing key.
    pub(crate) const fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The 64 secret bytes — the X25519 secret key, then the Ed25519 seed — for sealing into
    /// an invitation (`admin::enroll`), in a zeroizing buffer.
    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; X25519_ED25519_V1_SECRET_LEN]> {
        let mut bytes = Zeroizing::new([0u8; X25519_ED25519_V1_SECRET_LEN]);
        bytes[..32].copy_from_slice(self.x25519.as_slice());
        bytes[32..].copy_from_slice(self.signing.as_bytes());
        bytes
    }

    /// The key of this device's local section in the replica of `vault_id` (ADR-0035 addendum,
    /// "Local-section key"): `HKDF-SHA256(IKM = the device's 64 secret bytes — the X25519 secret
    /// key, then the Ed25519 seed — no salt, info = "kagisecure/shared/local/v1" ‖ vault_id)`.
    pub(crate) fn local_key(
        &self,
        vault_id: &kagisecure_core::proto::VaultId,
    ) -> Zeroizing<[u8; 32]> {
        const LOCAL_INFO: &[u8] = b"kagisecure/shared/local/v1";
        let mut ikm = Zeroizing::new([0u8; X25519_ED25519_V1_SECRET_LEN]);
        ikm[..32].copy_from_slice(self.x25519.as_slice());
        ikm[32..].copy_from_slice(self.signing.as_bytes());
        let hk = hkdf::Hkdf::<Sha256>::new(None, ikm.as_slice());
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand_multi_info(
            &[LOCAL_INFO, crate::epoch_key::vault_id_bytes(vault_id)],
            key.as_mut_slice(),
        )
        .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }
}

impl std::fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The id only: nothing of either secret key is rendered, not even redacted.
        f.debug_struct("DeviceSecret")
            .field("id", &self.public.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        ALICE_X25519_SECRET, TEST_1_ED25519_SEED, golden_device, unhex, unhex32,
    };

    /// RFC 7748 §6.1, Alice's public key.
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    /// RFC 8032 §7.1, TEST 1's public key.
    const TEST_1_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// The id `kagisecure-core`'s golden vector `v2-devices-argon2id-64k.kagivault` stores.
    const GOLDEN_ID: &str = "1ccbda9a1b81bbf470d5ab39998783822db70612b841fca593e81d9222b05b8f";

    #[test]
    fn the_device_key_id_is_the_one_the_core_golden_vector_stores() {
        let id = DeviceKeyId::derive(
            Suite::X25519Ed25519V1,
            &unhex32(ALICE_PUBLIC),
            &unhex32(TEST_1_PUBLIC),
        );
        assert_eq!(id.to_string(), GOLDEN_ID);
        let device = golden_device();
        assert_eq!(device.public().kem_pk(), &unhex32(ALICE_PUBLIC));
        assert_eq!(device.public().sig_pk(), &unhex32(TEST_1_PUBLIC));
        assert_eq!(device.id(), id);
    }

    #[test]
    fn the_device_key_id_covers_the_suite_and_both_keys_in_order() {
        let a = unhex32(ALICE_PUBLIC);
        let b = unhex32(TEST_1_PUBLIC);
        let id = DeviceKeyId::derive(Suite::X25519Ed25519V1, &a, &b);
        assert_ne!(id, DeviceKeyId::derive(Suite::X25519Ed25519V1, &b, &a));
        let mut other = a;
        other[0] ^= 1;
        assert_ne!(id, DeviceKeyId::derive(Suite::X25519Ed25519V1, &other, &b));
    }

    #[test]
    fn the_fingerprint_is_ten_groups_of_five_digits_from_the_first_20_bytes() {
        let fingerprint = golden_device().public().fingerprint();
        assert_eq!(
            fingerprint.to_string(),
            "07371 55962 07041 48116 28885 43833 39303 33666 11703 01554"
        );
        assert_eq!(fingerprint.groups()[0], "07371");
        assert_eq!(
            fingerprint.qr_payload(),
            format!("kagisecure-fp:1:{GOLDEN_ID}")
        );
        assert_eq!(fingerprint.device_key_id(), golden_device().id());

        // The extremes of a group: 0x0000 and 0xffff.
        let mut id = [0u8; 32];
        id[2] = 0xff;
        id[3] = 0xff;
        let groups = DeviceKeyId::from_bytes(id).fingerprint().groups();
        assert_eq!(groups[0], "00000");
        assert_eq!(groups[1], "65535");
        // Bytes 20 and on are in the QR payload but not in the groups.
        let mut tail = [0u8; 32];
        tail[31] = 1;
        let fp = DeviceKeyId::from_bytes(tail).fingerprint();
        assert_eq!(
            fp.groups(),
            DeviceKeyId::from_bytes([0; 32]).fingerprint().groups()
        );
        assert!(fp.qr_payload().ends_with("01"));
    }

    #[test]
    fn small_order_and_non_canonical_x25519_keys_are_refused() {
        let good_sig = unhex32(TEST_1_PUBLIC);
        let p_minus_1 = {
            let mut k = [0xff; 32];
            k[0] = 0xec;
            k[31] = 0x7f;
            k
        };
        let refused: Vec<[u8; 32]> = vec![
            // 0 and 1.
            [0; 32],
            {
                let mut k = [0; 32];
                k[0] = 1;
                k
            },
            // The two points of order 8.
            unhex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            unhex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            // p − 1.
            p_minus_1,
            // p and p + 1: 0 and 1 again, not reduced.
            {
                let mut k = p_minus_1;
                k[0] = 0xed;
                k
            },
            {
                let mut k = p_minus_1;
                k[0] = 0xee;
                k
            },
            // Alice's key with the top bit set: the same point, not canonically encoded.
            {
                let mut k = unhex32(ALICE_PUBLIC);
                k[31] |= 0x80;
                k
            },
        ];
        for kem in refused {
            assert!(
                matches!(
                    DevicePublic::new(Suite::X25519Ed25519V1, kem, good_sig),
                    Err(SharedError::InvalidPublicKey(_))
                ),
                "{}",
                hex(&kem)
            );
        }
        assert!(DevicePublic::new(Suite::X25519Ed25519V1, unhex32(ALICE_PUBLIC), good_sig).is_ok());
    }

    #[test]
    fn weak_and_non_canonical_ed25519_keys_are_refused() {
        let good_kem = unhex32(ALICE_PUBLIC);
        let refused: Vec<[u8; 32]> = vec![
            // The identity (y = 1): weak.
            {
                let mut k = [0; 32];
                k[0] = 1;
                k
            },
            // y = −1, the point of order 2: weak.
            {
                let mut k = [0xff; 32];
                k[0] = 0xec;
                k[31] = 0x7f;
                k
            },
            // The identity again, with y = p + 1: not reduced.
            {
                let mut k = [0xff; 32];
                k[0] = 0xee;
                k[31] = 0x7f;
                k
            },
            // y = 2 is not on the curve.
            {
                let mut k = [0; 32];
                k[0] = 2;
                k
            },
        ];
        for sig in refused {
            assert!(
                matches!(
                    DevicePublic::new(Suite::X25519Ed25519V1, good_kem, sig),
                    Err(SharedError::InvalidPublicKey(_))
                ),
                "{}",
                hex(&sig)
            );
        }
    }

    /// A valid key plus a point of small order is on the curve, canonical and not itself of
    /// small order — only the torsion check refuses it.
    #[test]
    fn an_ed25519_key_with_a_small_order_component_is_refused() {
        let good = VerifyingKey::from_bytes(&unhex32(TEST_1_PUBLIC)).unwrap();
        // y = 0: (√−1, 0), a point of order 4.
        let order_4 = VerifyingKey::from_bytes(&[0; 32]).unwrap();
        assert!(order_4.is_weak());
        let mixed = (good.to_edwards() + order_4.to_edwards())
            .compress()
            .to_bytes();
        let mixed_key = VerifyingKey::from_bytes(&mixed).unwrap();
        assert!(!mixed_key.is_weak());
        assert_eq!(mixed_key.to_edwards().compress().to_bytes(), mixed);
        match DevicePublic::new(Suite::X25519Ed25519V1, unhex32(ALICE_PUBLIC), mixed) {
            Err(SharedError::InvalidPublicKey(rule)) => {
                assert!(rule.contains("small-order component"), "{rule}");
            }
            other => panic!("{other:?}"),
        }
        // The key alone is accepted.
        assert!(
            DevicePublic::new(
                Suite::X25519Ed25519V1,
                unhex32(ALICE_PUBLIC),
                good.to_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_generated_device_round_trips_through_the_personal_vault_entry() {
        let device = DeviceSecret::generate().unwrap();
        let entry = device.to_device_key("Work laptop", 1_790_000_000).unwrap();
        assert_eq!(entry.id(), device.id().as_bytes());
        assert_eq!(entry.suite(), "x25519-ed25519-v1");
        let back = DeviceSecret::from_device_key(&entry).unwrap();
        assert_eq!(back.public(), device.public());
        assert_ne!(DeviceSecret::generate().unwrap().id(), device.id());
    }

    #[test]
    fn a_stored_id_that_is_not_the_key_materials_is_refused() {
        let device = golden_device();
        let mut secret = unhex(ALICE_X25519_SECRET);
        secret.extend_from_slice(&unhex(TEST_1_ED25519_SEED));
        let mut wrong_id = *device.id().as_bytes();
        wrong_id[0] ^= 1;
        let entry = DeviceKey::new(
            wrong_id,
            "x25519-ed25519-v1",
            "Laptop",
            1,
            Secret::new(secret),
        )
        .unwrap();
        assert!(matches!(
            DeviceSecret::from_device_key(&entry),
            Err(SharedError::DeviceKeyMismatch)
        ));
    }

    #[test]
    fn debug_shows_the_id_and_nothing_of_the_secret_keys() {
        let device = golden_device();
        let rendered = format!("{device:?} {device:#?}");
        assert!(rendered.contains(GOLDEN_ID), "{rendered}");
        // Neither secret, in hex, nor any byte pattern of the seed.
        assert!(!rendered.contains("77076d0a"), "{rendered}");
        assert!(!rendered.contains("9d61b19d"), "{rendered}");
    }

    #[test]
    fn the_public_encoding_is_exact_and_strict() {
        let public = golden_device().public().clone();
        let bytes = public.to_cbor();
        assert_eq!(DevicePublic::from_cbor(&bytes).unwrap(), public);

        // An unknown suite is refused by name.
        let other_suite = cbor::encode(&cbor::map(vec![
            (cbor::text("suite"), cbor::text("p256-enclave-v1")),
            (cbor::text("kem_pk"), cbor::bytes(public.kem_pk())),
            (cbor::text("sig_pk"), cbor::bytes(public.sig_pk())),
        ]));
        assert!(matches!(
            DevicePublic::from_cbor(&other_suite),
            Err(SharedError::UnsupportedSuite(_))
        ));
        // A fourth key, a missing key, or a short key is refused.
        let extra = cbor::encode(&cbor::map(vec![
            (cbor::text("suite"), cbor::text("x25519-ed25519-v1")),
            (cbor::text("kem_pk"), cbor::bytes(public.kem_pk())),
            (cbor::text("sig_pk"), cbor::bytes(public.sig_pk())),
            (cbor::text("label"), cbor::text("Laptop")),
        ]));
        let missing = cbor::encode(&cbor::map(vec![
            (cbor::text("suite"), cbor::text("x25519-ed25519-v1")),
            (cbor::text("kem_pk"), cbor::bytes(public.kem_pk())),
        ]));
        let short = cbor::encode(&cbor::map(vec![
            (cbor::text("suite"), cbor::text("x25519-ed25519-v1")),
            (cbor::text("kem_pk"), cbor::bytes(&public.kem_pk()[..31])),
            (cbor::text("sig_pk"), cbor::bytes(public.sig_pk())),
        ]));
        for bytes in [extra, missing, short] {
            assert!(matches!(
                DevicePublic::from_cbor(&bytes),
                Err(SharedError::Malformed(_))
            ));
        }
        // A weak key inside a well-formed map is refused like one handed to `new`.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let weak = cbor::encode(&cbor::map(vec![
            (cbor::text("suite"), cbor::text("x25519-ed25519-v1")),
            (cbor::text("kem_pk"), cbor::bytes(public.kem_pk())),
            (cbor::text("sig_pk"), cbor::bytes(&weak)),
        ]));
        assert!(matches!(
            DevicePublic::from_cbor(&weak),
            Err(SharedError::InvalidPublicKey(_))
        ));
        // Oversize input is refused before it is decoded.
        assert!(matches!(
            DevicePublic::from_cbor(&[0u8; 257]),
            Err(SharedError::LimitExceeded { .. })
        ));
    }
}

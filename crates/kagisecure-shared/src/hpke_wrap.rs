//! Wrapping an epoch key to a device (ADR-0035 §3; addendum, decision 1 and "Epoch wrap").
//!
//! RFC 9180 Base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305 — and
//! nothing else: no PSK, no sender authentication, no other suite. The context string is
//! `info = "kagisecure/shared/epoch/v1" ‖ vault_id ‖ epoch_id` with empty AAD, so a wrap opens only
//! as the epoch of the vault it was made for; HPKE's own key schedule binds the recipient's public
//! key, so it opens only for the device it was made for.
//!
//! # Randomness
//!
//! `hpke` is built without its `getrandom` feature: this crate's only path to the operating
//! system's generator is `kagisecure-core`'s. So a wrap draws its randomness from the core first,
//! into a `PrefilledRng`, and hands `hpke` that. How much `hpke` 0.14.1 takes was confirmed by
//! reading it and is pinned by tests below: Base-mode setup draws randomness only to make the
//! ephemeral key pair, and `Kem::gen_keypair_with_rng` fills exactly `Nsk` = 32 bytes in one call
//! and runs RFC 9180 `DeriveKeyPair` over them — so the RFC's own `ikmE`, prefilled, reproduces
//! the RFC's `enc`. A `PrefilledRng` asked for more than it holds panics rather than hand out
//! anything predictable; that would be a change in `hpke`, caught here before a release.
//!
//! A wrap is `enc (32) ‖ ciphertext (32) ‖ tag (16)`, 80 bytes (addendum, decision 35).

use std::convert::Infallible;

use hpke::aead::{AeadTag, ChaCha20Poly1305};
use hpke::inout::InOutBuf;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use kagisecure_core::proto::VaultId;
use zeroize::{Zeroize, Zeroizing};

use crate::device::{DevicePublic, DeviceSecret};
use crate::epoch_key::{EPOCH_KEY_LEN, EpochId, EpochKey, vault_id_bytes};
use crate::error::{Result, SharedError};
use crate::suite::Suite;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Length of HPKE's encapsulated key for DHKEM(X25519, HKDF-SHA256).
const ENC_LEN: usize = 32;
/// Length of ChaCha20-Poly1305's tag.
const TAG_LEN: usize = 16;
/// Length of a wrapped epoch key.
pub const EPOCH_WRAP_LEN: usize = ENC_LEN + EPOCH_KEY_LEN + TAG_LEN;

/// The randomness one Base-mode seal takes: the ephemeral key's `ikm`, `Nsk` bytes.
const EPHEMERAL_IKM_LEN: usize = 32;

const EPOCH_INFO: &[u8] = b"kagisecure/shared/epoch/v1";

/// An epoch key wrapped to one device. Public: it is carried in the epoch's record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EpochWrap {
    enc: [u8; ENC_LEN],
    ciphertext: [u8; EPOCH_KEY_LEN],
    tag: [u8; TAG_LEN],
}

impl EpochWrap {
    /// The wrap's bytes: `enc ‖ ciphertext ‖ tag`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; EPOCH_WRAP_LEN] {
        let mut out = [0u8; EPOCH_WRAP_LEN];
        out[..ENC_LEN].copy_from_slice(&self.enc);
        out[ENC_LEN..ENC_LEN + EPOCH_KEY_LEN].copy_from_slice(&self.ciphertext);
        out[ENC_LEN + EPOCH_KEY_LEN..].copy_from_slice(&self.tag);
        out
    }

    /// A wrap as read from a file.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for anything but exactly [`EPOCH_WRAP_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EPOCH_WRAP_LEN {
            return Err(SharedError::Malformed("a wrapped epoch key is 80 bytes"));
        }
        let (enc, rest) = bytes.split_at(ENC_LEN);
        let (ciphertext, tag) = rest.split_at(EPOCH_KEY_LEN);
        Ok(Self {
            enc: enc.try_into().expect("split at the enc length"),
            ciphertext: ciphertext.try_into().expect("split at the key length"),
            tag: tag.try_into().expect("the rest is the tag"),
        })
    }
}

impl std::fmt::Debug for EpochWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochWrap(..)")
    }
}

/// `info = "kagisecure/shared/epoch/v1" ‖ vault_id ‖ epoch_id`.
fn wrap_info(vault_id: &VaultId, epoch_id: &EpochId) -> Vec<u8> {
    let mut info = Vec::with_capacity(EPOCH_INFO.len() + 32);
    info.extend_from_slice(EPOCH_INFO);
    info.extend_from_slice(vault_id_bytes(vault_id));
    info.extend_from_slice(epoch_id.as_bytes());
    info
}

/// Wrap `key`, as epoch `epoch_id` of `vault_id`, to `recipient`.
///
/// # Errors
///
/// [`SharedError::Core`] if the generator fails, and [`SharedError::InvalidPublicKey`] if HPKE
/// refuses the recipient's key (which [`DevicePublic`]'s own checks should already have done).
pub fn wrap_epoch_key(
    recipient: &DevicePublic,
    vault_id: &VaultId,
    epoch_id: &EpochId,
    key: &EpochKey,
) -> Result<EpochWrap> {
    let mut rng = PrefilledRng::from_core(EPHEMERAL_IKM_LEN)?;
    let wrap = wrap_with_rng(recipient, vault_id, epoch_id, key, &mut rng)?;
    debug_assert_eq!(
        rng.remaining(),
        0,
        "hpke took less randomness than expected"
    );
    Ok(wrap)
}

pub(crate) fn wrap_with_rng(
    recipient: &DevicePublic,
    vault_id: &VaultId,
    epoch_id: &EpochId,
    key: &EpochKey,
    rng: &mut PrefilledRng,
) -> Result<EpochWrap> {
    match recipient.suite() {
        Suite::X25519Ed25519V1 => {}
    }
    // Copied into the wiped buffer directly: `Zeroizing::new(*key.as_bytes())` would first
    // make an unwiped copy of the key on the stack.
    let mut buffer = Zeroizing::new([0u8; EPOCH_KEY_LEN]);
    buffer.copy_from_slice(key.as_bytes());
    let (enc, tag) = seal_base(
        recipient.kem_pk(),
        &wrap_info(vault_id, epoch_id),
        &[],
        buffer.as_mut_slice(),
        rng,
    )?;
    Ok(EpochWrap {
        enc,
        ciphertext: *buffer,
        tag,
    })
}

/// Unwrap `wrap` with this device's key, as epoch `epoch_id` of `vault_id`.
///
/// # Errors
///
/// [`SharedError::Decrypt`] if the wrap was made for another device, another vault or another
/// epoch, or was altered.
pub fn unwrap_epoch_key(
    device: &DeviceSecret,
    vault_id: &VaultId,
    epoch_id: &EpochId,
    wrap: &EpochWrap,
) -> Result<EpochKey> {
    // Opened in place, inside the key that will hold it: what goes in is the ciphertext, and
    // the plaintext is never moved or copied out of the wiped buffer it is decrypted into.
    let mut key = EpochKey::from_bytes(Zeroizing::new(wrap.ciphertext));
    open_base(
        device.x25519_secret(),
        &wrap.enc,
        &wrap_info(vault_id, epoch_id),
        &[],
        key.as_mut_bytes(),
        &wrap.tag,
    )?;
    Ok(key)
}

/// Seal `plaintext` to `recipient` with RFC 9180 Base mode under `info`: `enc ‖ ciphertext ‖ tag`.
/// For payloads of any length (a host bundle, ADR-0043 §7); epoch keys keep their fixed form.
pub(crate) fn seal_bytes(
    recipient: &DevicePublic,
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match recipient.suite() {
        Suite::X25519Ed25519V1 => {}
    }
    let mut rng = PrefilledRng::from_core(EPHEMERAL_IKM_LEN)?;
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let (enc, tag) = seal_base(
        recipient.kem_pk(),
        info,
        &[],
        buffer.as_mut_slice(),
        &mut rng,
    )?;
    let mut out = Vec::with_capacity(ENC_LEN + buffer.len() + TAG_LEN);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Open what [`seal_bytes`] made, with this device's key, under the same `info`.
pub(crate) fn open_bytes(
    device: &DeviceSecret,
    info: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < ENC_LEN + TAG_LEN {
        return Err(SharedError::Decrypt);
    }
    let (enc, rest) = sealed.split_at(ENC_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let enc: [u8; ENC_LEN] = enc.try_into().map_err(|_| SharedError::Decrypt)?;
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| SharedError::Decrypt)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    open_base(
        device.x25519_secret(),
        &enc,
        info,
        &[],
        buffer.as_mut_slice(),
        &tag,
    )?;
    Ok(buffer)
}

/// RFC 9180 `SealBase`, single shot, in place: `buffer` goes in as plaintext and comes out as
/// ciphertext; returns `enc` and the tag.
fn seal_base(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    rng: &mut PrefilledRng,
) -> Result<([u8; ENC_LEN], [u8; TAG_LEN])> {
    let recipient = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| SharedError::InvalidPublicKey("not an X25519 public key"))?;
    let (enc, tag) = hpke::single_shot_seal_inout_detached_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient,
        info,
        InOutBuf::from(buffer),
        aad,
        rng,
    )
    .map_err(|_| SharedError::InvalidPublicKey("cannot encapsulate to this X25519 key"))?;
    let mut enc_out = [0u8; ENC_LEN];
    enc_out.copy_from_slice(&enc.to_bytes());
    let mut tag_out = [0u8; TAG_LEN];
    tag_out.copy_from_slice(&tag.to_bytes());
    Ok((enc_out, tag_out))
}

/// RFC 9180 `OpenBase`, single shot, in place: `buffer` goes in as ciphertext and comes out as
/// plaintext.
fn open_base(
    secret: &[u8; 32],
    enc: &[u8; ENC_LEN],
    info: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    let secret =
        <Kem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|_| SharedError::Decrypt)?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| SharedError::Decrypt)?;
    let tag = AeadTag::<Aead>::from_bytes(tag).map_err(|_| SharedError::Decrypt)?;
    hpke::single_shot_open_inout_detached::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &secret,
        &enc,
        info,
        InOutBuf::from(buffer),
        aad,
        &tag,
    )
    .map_err(|_| SharedError::Decrypt)
}

/// The X25519 public key of `secret`, computed through HPKE's own private-key type, which copies
/// the secret only into itself and wipes its temporary and itself (no by-value copy of the
/// secret is made here).
pub(crate) fn x25519_public_key(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let secret = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret)
        .map_err(|_| SharedError::Malformed("an X25519 secret key is 32 bytes"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&<Kem as hpke::Kem>::sk_to_pk(&secret).to_bytes());
    Ok(out)
}

/// A generator that hands out bytes drawn beforehand from `kagisecure-core`'s, and nothing
/// more (module documentation). Each byte is wiped as it is handed out, and the rest on drop.
pub(crate) struct PrefilledRng {
    bytes: Zeroizing<Vec<u8>>,
    taken: usize,
}

impl PrefilledRng {
    /// `len` bytes from `kagisecure-core`'s generator.
    pub(crate) fn from_core(len: usize) -> Result<Self> {
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        kagisecure_core::crypto::random::fill(bytes.as_mut_slice())?;
        Ok(Self { bytes, taken: 0 })
    }

    /// Fixed bytes, for a known-answer test.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            taken: 0,
        }
    }

    /// How many bytes are left.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.taken
    }

    fn take(&mut self, dst: &mut [u8]) {
        let end = self
            .taken
            .checked_add(dst.len())
            .filter(|&end| end <= self.bytes.len())
            .expect("PrefilledRng exhausted: hpke asked for more randomness than was drawn for it");
        dst.copy_from_slice(&self.bytes[self.taken..end]);
        self.bytes[self.taken..end].zeroize();
        self.taken = end;
    }
}

impl TryRng for PrefilledRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.take(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.take(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Infallible> {
        self.take(dst);
        Ok(())
    }
}

// Every byte comes from the operating system's CSPRNG, through the core, drawn just before use.
impl TryCryptoRng for PrefilledRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_key::fixed_epoch_key;
    use crate::test_support::{device_with_seed, golden_device, unhex, unhex32};
    use uuid::Uuid;

    /// RFC 9180 Appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, Base
    /// setup — the suite this crate uses, and the first two of its encryptions.
    mod rfc_9180_a_2_1 {
        pub const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
        pub const IKM_E: &str = "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b";
        pub const PK_RM: &str = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a";
        pub const SK_RM: &str = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb";
        pub const ENC: &str = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a";
        pub const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
        pub const AAD_0: &str = "436f756e742d30";
        pub const CT_0: &str = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db\
                                21993c62ce81883d2dd1b51a28";
    }

    fn vault(byte: u8) -> VaultId {
        VaultId(Uuid::from_bytes([byte; 16]))
    }

    fn epoch(byte: u8) -> EpochId {
        EpochId::from_bytes([byte; 16])
    }

    /// The first encryption of the RFC's vector — sequence number 0, which is what a single-shot
    /// seal is — from the RFC's `ikmE`, byte for byte, and back.
    #[test]
    fn a_base_mode_seal_and_open_match_the_rfc_9180_a_2_1_vector() {
        use rfc_9180_a_2_1::*;
        let mut rng = PrefilledRng::from_bytes(&unhex(IKM_E));
        let mut buffer = unhex(PT);
        let (enc, tag) = seal_base(
            &unhex32(PK_RM),
            &unhex(INFO),
            &unhex(AAD_0),
            &mut buffer,
            &mut rng,
        )
        .unwrap();
        assert_eq!(rng.remaining(), 0);
        assert_eq!(enc, unhex32(ENC));
        let mut ct = buffer.clone();
        ct.extend_from_slice(&tag);
        assert_eq!(ct, unhex(CT_0));

        open_base(
            &unhex32(SK_RM),
            &enc,
            &unhex(INFO),
            &unhex(AAD_0),
            &mut buffer,
            &tag,
        )
        .unwrap();
        assert_eq!(buffer, unhex(PT));
    }

    /// How `hpke` consumes randomness: one wrap takes exactly 32 bytes, in order from the front,
    /// and a different 32 bytes give a different `enc`.
    #[test]
    fn one_wrap_takes_exactly_32_bytes_of_randomness() {
        let recipient = golden_device();
        let key = fixed_epoch_key(7);
        let mut ikm = unhex(rfc_9180_a_2_1::IKM_E);
        ikm.extend_from_slice(&[0xee; 32]);
        let mut rng = PrefilledRng::from_bytes(&ikm);
        let first =
            wrap_with_rng(recipient.public(), &vault(1), &epoch(1), &key, &mut rng).unwrap();
        assert_eq!(rng.remaining(), 32);
        // The RFC's ikmE gives the RFC's enc whoever the recipient is: the ephemeral key pair is
        // DeriveKeyPair(ikmE).
        assert_eq!(first.enc, unhex32(rfc_9180_a_2_1::ENC));
        let second =
            wrap_with_rng(recipient.public(), &vault(1), &epoch(1), &key, &mut rng).unwrap();
        assert_eq!(rng.remaining(), 0);
        assert_ne!(first.enc, second.enc);
    }

    #[test]
    #[should_panic(expected = "PrefilledRng exhausted")]
    fn a_prefilled_rng_asked_for_more_than_it_holds_panics() {
        let mut rng = PrefilledRng::from_bytes(&[1; 31]);
        let _ = wrap_with_rng(
            golden_device().public(),
            &vault(1),
            &epoch(1),
            &fixed_epoch_key(7),
            &mut rng,
        );
    }

    #[test]
    fn a_prefilled_rng_wipes_what_it_hands_out() {
        let mut rng = PrefilledRng::from_bytes(&[0xaa; 8]);
        let mut out = [0u8; 4];
        rng.try_fill_bytes(&mut out).unwrap();
        assert_eq!(out, [0xaa; 4]);
        assert_eq!(&rng.bytes[..4], &[0; 4]);
        assert_eq!(&rng.bytes[4..], &[0xaa; 4]);
    }

    #[test]
    fn a_wrap_opens_for_its_device_vault_and_epoch() {
        let device = golden_device();
        let key = EpochKey::generate().unwrap();
        let wrap = wrap_epoch_key(device.public(), &vault(1), &epoch(1), &key).unwrap();
        let opened = unwrap_epoch_key(&device, &vault(1), &epoch(1), &wrap).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        // Fresh randomness each time.
        let again = wrap_epoch_key(device.public(), &vault(1), &epoch(1), &key).unwrap();
        assert_ne!(again, wrap);
    }

    #[test]
    fn a_wrap_does_not_open_for_another_device_vault_or_epoch() {
        let device = golden_device();
        let other = device_with_seed([9; 32]);
        let stranger = DeviceSecret::generate().unwrap();
        let key = fixed_epoch_key(3);
        let wrap = wrap_epoch_key(device.public(), &vault(1), &epoch(1), &key).unwrap();
        let refused = [
            unwrap_epoch_key(&stranger, &vault(1), &epoch(1), &wrap),
            unwrap_epoch_key(&device, &vault(2), &epoch(1), &wrap),
            unwrap_epoch_key(&device, &vault(1), &epoch(2), &wrap),
        ];
        for result in refused {
            assert!(matches!(result, Err(SharedError::Decrypt)));
        }
        // HPKE binds a wrap to the recipient's X25519 key, not to its device id: `other` is a
        // test fixture sharing the golden device's X25519 key (real devices never share one), so
        // it opens. Which device a wrap is for is the epoch record's to say, and the roster's to
        // check.
        assert!(unwrap_epoch_key(&other, &vault(1), &epoch(1), &wrap).is_ok());
    }

    #[test]
    fn a_flipped_byte_anywhere_in_a_wrap_is_refused() {
        let device = golden_device();
        let key = fixed_epoch_key(3);
        let bytes = wrap_epoch_key(device.public(), &vault(1), &epoch(1), &key)
            .unwrap()
            .to_bytes();
        assert!(
            unwrap_epoch_key(
                &device,
                &vault(1),
                &epoch(1),
                &EpochWrap::from_bytes(&bytes).unwrap()
            )
            .is_ok()
        );
        for i in 0..EPOCH_WRAP_LEN {
            let mut flipped = bytes;
            flipped[i] ^= 0x01;
            let wrap = EpochWrap::from_bytes(&flipped).unwrap();
            assert!(
                unwrap_epoch_key(&device, &vault(1), &epoch(1), &wrap).is_err(),
                "byte {i}"
            );
        }
        assert!(EpochWrap::from_bytes(&bytes[..79]).is_err());
        assert!(EpochWrap::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn the_info_string_is_the_contracts() {
        let info = wrap_info(&vault(0x22), &epoch(0x44));
        let mut expected = b"kagisecure/shared/epoch/v1".to_vec();
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&[0x44; 16]);
        assert_eq!(info, expected);
    }
}

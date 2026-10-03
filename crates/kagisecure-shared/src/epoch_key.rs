//! Epoch keys and what is derived from them (ADR-0035 §3; addendum, "Record key"; Correction E).
//!
//! A shared vault's content is encrypted under its current **epoch key**: 32 random bytes, one
//! per epoch, wrapped to every device in the roster ([`crate::hpke_wrap`]). An epoch is named by a
//! 16-byte [`EpochId`], not a sequence number, because two devices can mint an epoch at the same
//! time with no coordinator to number them (Correction E) — and the id is derived from the record
//! that mints it (its vault, author and `seq`), not chosen, so that no one can mint an epoch under
//! another epoch's id (decision 67).
//!
//! From an epoch key comes each **record key** — `HKDF-SHA256(EK, salt = record_salt, info =
//! "kagisecure/shared/record/v1" ‖ vault_id)`, one per record, from the 16 random bytes the
//! record carries. (The epoch chain and the key commitment of the first design were dropped by
//! the trusted-admin simplification: a device added later is granted older keys directly.)
//!
//! Every key here is zeroized on drop and has no `Clone`, no `Serialize` and a `Debug` that
//! renders nothing of it. Every AEAD here is XChaCha20-Poly1305 with a random 24-byte nonce, the
//! same as the personal vault's body (addendum, decision 36).

use hkdf::Hkdf;
use kagisecure_core::crypto::aead;
use kagisecure_core::proto::VaultId;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::device::DeviceKeyId;
use crate::error::{Result, SharedError};

/// Length of an epoch key.
pub const EPOCH_KEY_LEN: usize = 32;
/// Length of an epoch id.
pub const EPOCH_ID_LEN: usize = 16;
/// Length of a record's salt.
pub const RECORD_SALT_LEN: usize = 16;

const RECORD_INFO: &[u8] = b"kagisecure/shared/record/v1";
const EPOCH_ID_DOMAIN: &[u8] = b"kagisecure/shared/epoch-id/v1";

/// A shared vault's id as the 16 bytes every derivation uses (addendum, decision 21).
pub(crate) fn vault_id_bytes(vault_id: &VaultId) -> &[u8; 16] {
    vault_id.0.as_bytes()
}

/// An epoch's id: 16 bytes derived from the record that mints the epoch. Public.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId([u8; EPOCH_ID_LEN]);

impl EpochId {
    /// The id of the epoch minted by `author`'s record at `seq` in `vault_id`: the first 16
    /// bytes of `SHA-256("kagisecure/shared/epoch-id/v1" ‖ vault_id (16) ‖ author (32) ‖ seq
    /// (u64, big-endian))` (decision 67). Every part is fixed-length. Only an equivocation — the
    /// same author writing twice at one `seq` — can mint two epochs under one id.
    #[must_use]
    pub fn derive(vault_id: &VaultId, author: &DeviceKeyId, seq: u64) -> Self {
        let digest = Sha256::new()
            .chain_update(EPOCH_ID_DOMAIN)
            .chain_update(vault_id_bytes(vault_id))
            .chain_update(author.as_bytes())
            .chain_update(seq.to_be_bytes())
            .finalize();
        let mut id = [0u8; EPOCH_ID_LEN];
        id.copy_from_slice(&digest[..EPOCH_ID_LEN]);
        Self(id)
    }

    /// An epoch id as read from a file.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EPOCH_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EPOCH_ID_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochId({})", crate::device::hex(&self.0))
    }
}

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::device::hex(&self.0))
    }
}

/// An epoch key. Secret: see the module documentation.
pub struct EpochKey(Zeroizing<[u8; EPOCH_KEY_LEN]>);

/// A record's key, derived from an epoch key and the record's salt. Secret.
pub struct RecordKey(Zeroizing<[u8; EPOCH_KEY_LEN]>);

impl EpochKey {
    /// A fresh epoch key, from `kagisecure-core`'s generator.
    ///
    /// # Errors
    ///
    /// [`SharedError::Core`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(kagisecure_core::crypto::random::key()?))
    }

    /// An epoch key from bytes an unwrap produced, or a test's fixed key.
    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; EPOCH_KEY_LEN]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; EPOCH_KEY_LEN] {
        &self.0
    }

    /// The key's buffer, for an unwrap that decrypts into it in place.
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    /// The key of the record carrying `record_salt` in `vault_id`.
    #[must_use]
    pub fn record_key(&self, vault_id: &VaultId, record_salt: &[u8; RECORD_SALT_LEN]) -> RecordKey {
        let hk = Hkdf::<Sha256>::new(Some(record_salt), self.0.as_slice());
        // Derived into the key's own buffer, so the derived bytes are never moved.
        let mut key = RecordKey(Zeroizing::new([0u8; EPOCH_KEY_LEN]));
        hk.expand_multi_info(
            &[RECORD_INFO, vault_id_bytes(vault_id)],
            key.0.as_mut_slice(),
        )
        .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }
}

impl std::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochKey(<redacted>)")
    }
}

impl RecordKey {
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8; EPOCH_KEY_LEN] {
        &self.0
    }

    /// Encrypt `plaintext` under this key, authenticating `aad`: XChaCha20-Poly1305 with a fresh
    /// random nonce, written as `nonce (24) ‖ ciphertext ‖ tag (16)` (addendum, decision 36).
    ///
    /// # Errors
    ///
    /// [`SharedError::Core`] if the generator fails to produce a nonce.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_nonce(aad, plaintext, aead::nonce()?)
    }

    /// [`Self::seal`] with a given nonce, for golden vectors.
    pub(crate) fn seal_with_nonce(
        &self,
        aad: &[u8],
        plaintext: &[u8],
        nonce: [u8; aead::NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let sealed = aead::seal(&self.0, &nonce, aad, plaintext)?;
        let mut out = Vec::with_capacity(aead::NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open what [`Self::seal`] wrote, with the same `aad`.
    ///
    /// # Errors
    ///
    /// [`SharedError::Decrypt`] if this is not the key it was sealed under, `aad` is not what it
    /// was sealed with, or the bytes were altered or cut short.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < aead::NONCE_LEN + aead::TAG_LEN {
            return Err(SharedError::Decrypt);
        }
        let (nonce, ciphertext) = sealed.split_at(aead::NONCE_LEN);
        let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().expect("split at the nonce length");
        aead::open(&self.0, &nonce, aad, ciphertext).map_err(|_| SharedError::Decrypt)
    }
}

impl std::fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordKey(<redacted>)")
    }
}

#[cfg(test)]
pub(crate) fn fixed_epoch_key(byte: u8) -> EpochKey {
    EpochKey(Zeroizing::new([byte; EPOCH_KEY_LEN]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn vault(byte: u8) -> VaultId {
        VaultId(Uuid::from_bytes([byte; 16]))
    }

    fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, &mut out)
            .unwrap();
        out
    }

    /// The derivations are the contract's, spelled out with the domain strings concatenated by
    /// hand rather than through the code under test.
    #[test]
    fn the_derivations_are_the_encoding_contracts() {
        let ek = fixed_epoch_key(0x11);
        let vault = vault(0x22);
        let salt = [0x33; 16];
        let mut info = b"kagisecure/shared/record/v1".to_vec();
        info.extend_from_slice(&[0x22; 16]);
        assert_eq!(
            ek.record_key(&vault, &salt).as_bytes(),
            &hkdf_sha256(Some(&salt), &[0x11; 32], &info)
        );
    }

    #[test]
    fn an_epoch_id_is_derived_from_its_minting_record() {
        let author = DeviceKeyId::from_bytes([0x66; 32]);
        let mut input = b"kagisecure/shared/epoch-id/v1".to_vec();
        input.extend_from_slice(&[0x22; 16]);
        input.extend_from_slice(&[0x66; 32]);
        input.extend_from_slice(&7u64.to_be_bytes());
        let digest = Sha256::digest(&input);
        let id = EpochId::derive(&vault(0x22), &author, 7);
        assert_eq!(id.as_bytes(), &digest[..16]);
        assert_ne!(id, EpochId::derive(&vault(0x22), &author, 8));
        assert_ne!(id, EpochId::derive(&vault(0x23), &author, 7));
        assert_ne!(
            id,
            EpochId::derive(&vault(0x22), &DeviceKeyId::from_bytes([0x67; 32]), 7)
        );
    }

    #[test]
    fn record_keys_differ_by_salt_vault_and_epoch_key() {
        let ek = fixed_epoch_key(1);
        let base = *ek.record_key(&vault(1), &[1; 16]).as_bytes();
        assert_ne!(base, *ek.record_key(&vault(1), &[2; 16]).as_bytes());
        assert_ne!(base, *ek.record_key(&vault(2), &[1; 16]).as_bytes());
        assert_ne!(
            base,
            *fixed_epoch_key(2)
                .record_key(&vault(1), &[1; 16])
                .as_bytes()
        );
        assert_eq!(base, *ek.record_key(&vault(1), &[1; 16]).as_bytes());
    }

    #[test]
    fn a_record_key_seals_with_a_fresh_nonce_and_opens_only_with_its_aad() {
        let key = fixed_epoch_key(1).record_key(&vault(1), &[1; 16]);
        let sealed = key.seal(b"aad", b"plaintext").unwrap();
        assert_eq!(sealed.len(), 24 + 9 + 16);
        assert_eq!(&key.open(b"aad", &sealed).unwrap()[..], b"plaintext");
        assert_ne!(key.seal(b"aad", b"plaintext").unwrap(), sealed);
        assert!(matches!(
            key.open(b"aaD", &sealed),
            Err(SharedError::Decrypt)
        ));
        let other = fixed_epoch_key(1).record_key(&vault(1), &[2; 16]);
        assert!(matches!(
            other.open(b"aad", &sealed),
            Err(SharedError::Decrypt)
        ));
        for i in 0..sealed.len() {
            let mut flipped = sealed.clone();
            flipped[i] ^= 1;
            assert!(key.open(b"aad", &flipped).is_err(), "byte {i}");
        }
        assert!(matches!(
            key.open(b"aad", &sealed[..39]),
            Err(SharedError::Decrypt)
        ));
        let fixed = key.seal_with_nonce(b"aad", b"x", [5; 24]).unwrap();
        assert_eq!(&fixed[..24], &[5; 24]);
    }

    #[test]
    fn debug_renders_no_key_material() {
        let ek = fixed_epoch_key(0xab);
        let rk = ek.record_key(&vault(1), &[1; 16]);
        let rendered = format!("{ek:?} {rk:?} {ek:#?}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert_eq!(format!("{ek:?}"), "EpochKey(<redacted>)");
    }
}

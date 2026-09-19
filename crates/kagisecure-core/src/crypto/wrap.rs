//! Wrapped-key slots (vault-format §3).
//!
//! The vault key is 32 random bytes generated once. It is never derived from the password, so a
//! password change re-wraps rather than re-encrypts. Each slot in the header holds one wrapped
//! copy, authenticated with `vault_id || kind || id` as AAD so that a wrapped key cannot be
//! transplanted between vaults or between slots.

use serde::{Deserialize, Serialize};

use super::aead::{self, NONCE_LEN};
use super::kdf::KdfParams;
use super::{KEY_LEN, Key};
use crate::error::{Error, Result};

/// Slot unlocked by the master password.
pub const KIND_PASSWORD: &str = "password";
/// Slot unlocked by a hardware-held key (Secure Enclave / TPM).
///
/// Implemented in M3 for macOS. Unlike the password and recovery slots, this crate does **not**
/// perform the wrapping: the ciphertext is produced and consumed by the platform keystore, which
/// is the only thing that can, and this crate stores and returns it opaquely. See
/// [`ALG_PLATFORM_OPAQUE`] and `Vault::install_platform_slot`.
pub const KIND_PLATFORM: &str = "platform";
/// Slot unlocked by the printable recovery code.
pub const KIND_RECOVERY: &str = "recovery";

/// The `aead` marker for a slot whose ciphertext this crate did not produce and cannot open.
///
/// A [`KIND_PLATFORM`] slot's `ct` is whatever the platform keystore returned — on macOS an
/// ECIES-X963-SHA256-AES-GCM blob from `SecKeyCreateEncryptedData`, whose internal framing is
/// Apple's business, not ours. Recording that plainly in the `aead` field means a reader that
/// does not know how to open the slot says so instead of guessing, and it keeps
/// [`WrappedKey::unwrap_with_kek`] honest: that function refuses this marker, because there is no
/// KEK that would work.
pub const ALG_PLATFORM_OPAQUE: &str = "platform-opaque";

/// Build a slot whose ciphertext came from a platform keystore.
///
/// `nonce` is empty: the keystore's blob carries its own framing, so there is nothing for this
/// crate to store alongside it. The AAD binding the other slot kinds get from
/// [`slot_aad`] is not available here either — the keystore encrypts what it is given and knows
/// nothing about vault ids — so the binding that a platform slot *does* have is that the wrapped
/// bytes are the vault key itself, and a key from another vault simply fails to decrypt the body.
#[must_use]
pub fn platform_slot(id: &str, label: &str, wrapped: Vec<u8>) -> WrappedKey {
    WrappedKey {
        kind: KIND_PLATFORM.to_owned(),
        id: id.to_owned(),
        label: label.to_owned(),
        aead: ALG_PLATFORM_OPAQUE.to_owned(),
        nonce: Vec::new(),
        ct: wrapped,
        added_at: crate::unix_now(),
        kdf: None,
    }
}

/// One wrapped copy of the vault key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    /// `"password"`, `"platform"` or `"recovery"`.
    pub kind: String,
    /// Stable slot identifier, e.g. `"master"` or `"macos-secure-enclave-<device-uuid>"`.
    pub id: String,
    /// Label for a UI, e.g. `"Master password"`.
    pub label: String,
    /// AEAD used for this wrap.
    pub aead: String,
    /// Per-slot random nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// The wrapped vault key.
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
    /// Unix seconds.
    pub added_at: u64,
    /// Per-slot KDF parameters.
    ///
    /// **Deviation from vault-format §2.1/§3.2, see ADR-0006.** The document puts a single `kdf`
    /// map in the header and says its salt is "regenerated on password change" — which would
    /// silently invalidate the recovery slot, whose whole purpose is to be independent of the
    /// master password. Slots that are unlocked by a stretched secret therefore carry their own
    /// KDF descriptor. When absent, the header's `kdf` map applies, so a file written strictly to
    /// the document still opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
}

/// The associated data that binds a slot to its vault and its position: `vault_id || kind || id`.
#[must_use]
pub fn slot_aad(vault_id: &[u8], kind: &str, id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_id.len() + kind.len() + id.len());
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(kind.as_bytes());
    aad.extend_from_slice(id.as_bytes());
    aad
}

impl WrappedKey {
    /// Wrap `vault_key` under `kek` into a new slot.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn wrap(
        vault_id: &[u8],
        kind: &str,
        id: &str,
        label: &str,
        kek: &[u8; KEY_LEN],
        vault_key: &[u8; KEY_LEN],
        kdf: Option<KdfParams>,
    ) -> Result<Self> {
        let nonce = aead::nonce()?;
        let ct = aead::seal(
            kek,
            &nonce,
            &slot_aad(vault_id, kind, id),
            vault_key.as_slice(),
        )?;
        Ok(Self {
            kind: kind.to_owned(),
            id: id.to_owned(),
            label: label.to_owned(),
            aead: aead::ALG_XCHACHA20POLY1305.to_owned(),
            nonce: nonce.to_vec(),
            ct,
            added_at: crate::unix_now(),
            kdf,
        })
    }

    /// Unwrap the vault key using an already-derived KEK.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] if the KEK is wrong or the slot has been tampered with,
    /// [`Error::Malformed`] if the slot's nonce or ciphertext length is wrong, and
    /// [`Error::Unsupported`] for an AEAD this build does not implement.
    pub fn unwrap_with_kek(&self, vault_id: &[u8], kek: &[u8; KEY_LEN]) -> Result<Key> {
        if self.aead == ALG_PLATFORM_OPAQUE {
            // There is no KEK that opens this slot; only the platform keystore can.
            return Err(Error::Unsupported {
                what: "wrapped-key slot",
                value: ALG_PLATFORM_OPAQUE.to_owned(),
            });
        }
        aead::check_alg(&self.aead)?;
        let nonce: [u8; NONCE_LEN] = self
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let plain = aead::open(
            kek,
            &nonce,
            &slot_aad(vault_id, &self.kind, &self.id),
            &self.ct,
        )?;
        let key: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| Error::Malformed)?;
        Ok(zeroize::Zeroizing::new(key))
    }

    /// The KDF parameters that apply to this slot, falling back to the header's.
    #[must_use]
    pub fn effective_kdf<'a>(&'a self, header_kdf: &'a KdfParams) -> &'a KdfParams {
        self.kdf.as_ref().unwrap_or(header_kdf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> [u8; KEY_LEN] {
        [9u8; KEY_LEN]
    }

    #[test]
    fn round_trips() {
        let vault_id = [1u8; 16];
        let vk = [42u8; KEY_LEN];
        let slot = WrappedKey::wrap(
            &vault_id,
            KIND_PASSWORD,
            "master",
            "Master password",
            &kek(),
            &vk,
            None,
        )
        .unwrap();
        assert_eq!(*slot.unwrap_with_kek(&vault_id, &kek()).unwrap(), vk);
    }

    #[test]
    fn a_slot_cannot_be_transplanted_to_another_vault() {
        let vk = [42u8; KEY_LEN];
        let slot =
            WrappedKey::wrap(&[1u8; 16], KIND_PASSWORD, "master", "m", &kek(), &vk, None).unwrap();
        assert!(matches!(
            slot.unwrap_with_kek(&[2u8; 16], &kek()),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn a_slot_cannot_be_relabelled_into_another_kind() {
        let vault_id = [1u8; 16];
        let vk = [42u8; KEY_LEN];
        let mut slot =
            WrappedKey::wrap(&vault_id, KIND_PASSWORD, "master", "m", &kek(), &vk, None).unwrap();
        slot.kind = KIND_RECOVERY.to_owned();
        assert!(matches!(
            slot.unwrap_with_kek(&vault_id, &kek()),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn a_platform_slot_cannot_be_opened_with_a_kek() {
        let slot = platform_slot("macos-se-1", "Touch ID", vec![1, 2, 3, 4]);
        assert!(matches!(
            slot.unwrap_with_kek(&[1u8; 16], &kek()),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn wrong_kek_fails() {
        let vault_id = [1u8; 16];
        let slot = WrappedKey::wrap(
            &vault_id,
            KIND_PASSWORD,
            "master",
            "m",
            &kek(),
            &[42u8; KEY_LEN],
            None,
        )
        .unwrap();
        assert!(matches!(
            slot.unwrap_with_kek(&vault_id, &[8u8; KEY_LEN]),
            Err(Error::Decrypt)
        ));
    }
}

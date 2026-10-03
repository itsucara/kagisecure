//! Key derivation, AEAD, key wrapping and CSPRNG access (vault-format §3, §4).

pub mod aead;
pub mod kdf;
pub mod random;
pub mod wrap;

/// Length of every symmetric key in the hierarchy.
pub const KEY_LEN: usize = 32;

/// A 32-byte symmetric key, zeroized on drop.
pub type Key = zeroize::Zeroizing<[u8; KEY_LEN]>;

/// HKDF-SHA256 `info` string for the body key (vault-format §3).
pub const INFO_BODY: &[u8] = b"kagisecure/body/v1";

/// HKDF-SHA256 `info` prefix for per-item keys. Derived but unused in format v1; specified now so
/// that a later format can adopt per-item encryption without a key-hierarchy change.
pub const INFO_ITEM_PREFIX: &[u8] = b"kagisecure/item/";

/// Derive a subkey from the vault key.
///
/// HKDF-SHA256 with no salt and the given `info`, per the key hierarchy in vault-format §3.
#[must_use]
pub fn derive_subkey(vault_key: &[u8; KEY_LEN], info: &[u8]) -> Key {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, vault_key.as_slice());
    let mut out = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    // 32 bytes of output from SHA-256 HKDF is always within the length limit, so this cannot fail.
    hk.expand(info, out.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Whether two keys are equal, in time that does not depend on where they first differ.
///
/// Every byte pair is XORed and folded into one accumulator, with `black_box` keeping the
/// optimiser from turning the loop back into an early-exit comparison.
#[must_use]
pub fn keys_equal(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

/// The body key for a vault key.
#[must_use]
pub fn body_key(vault_key: &[u8; KEY_LEN]) -> Key {
    derive_subkey(vault_key, INFO_BODY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_are_deterministic_and_domain_separated() {
        let vk = [7u8; KEY_LEN];
        assert_eq!(*body_key(&vk), *body_key(&vk));
        assert_ne!(*body_key(&vk), *derive_subkey(&vk, b"kagisecure/item/abc"));
        assert_ne!(*body_key(&vk), vk);
    }

    #[test]
    fn keys_equal_compares_every_byte() {
        let a = [7u8; KEY_LEN];
        let mut b = a;
        assert!(keys_equal(&a, &b));
        b[KEY_LEN - 1] ^= 1;
        assert!(!keys_equal(&a, &b));
        b = a;
        b[0] ^= 0x80;
        assert!(!keys_equal(&a, &b));
    }

    #[test]
    fn different_vault_keys_give_different_body_keys() {
        assert_ne!(*body_key(&[1u8; KEY_LEN]), *body_key(&[2u8; KEY_LEN]));
    }
}

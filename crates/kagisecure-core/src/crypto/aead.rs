//! AEAD sealing and opening (vault-format §4).
//!
//! v1 implements XChaCha20-Poly1305 only. Its 192-bit nonce means random nonces are safe
//! indefinitely, which is the property that matters for a file that is saved thousands of times
//! and may be restored from a backup and saved again. `aes256gcm` is a reserved `body_aead` value
//! and is rejected with [`Error::Unsupported`] rather than silently mishandled.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroizing;

use super::KEY_LEN;
use crate::error::{Error, Result};

/// Nonce length for XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;

/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// The `body_aead` value this build writes and can read.
pub const ALG_XCHACHA20POLY1305: &str = "xchacha20poly1305";

/// Reject any AEAD name this build does not implement.
///
/// # Errors
///
/// [`Error::Unsupported`] for anything other than [`ALG_XCHACHA20POLY1305`].
pub fn check_alg(name: &str) -> Result<()> {
    if name == ALG_XCHACHA20POLY1305 {
        Ok(())
    } else {
        Err(Error::Unsupported {
            what: "AEAD algorithm",
            value: name.to_owned(),
        })
    }
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Encrypt `plaintext` under `key` with `nonce`, authenticating `aad`.
///
/// Returns ciphertext with the 16-byte tag appended.
///
/// # Errors
///
/// [`Error::Decrypt`] is never returned here; encryption only fails on absurd input sizes, which
/// is surfaced as [`Error::Malformed`].
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Malformed)
}

/// Decrypt and authenticate `ciphertext`, which must carry its tag.
///
/// The plaintext is returned in a [`Zeroizing`] buffer: callers decode it and let it drop.
///
/// # Errors
///
/// [`Error::Decrypt`] if authentication fails. The caller must not distinguish "wrong key" from
/// "tampered bytes" in anything it reports (threat-model M-8).
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    cipher(key)
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// A fresh random nonce.
///
/// # Errors
///
/// [`Error::Rng`] if the operating system's generator fails.
pub fn nonce() -> Result<[u8; NONCE_LEN]> {
    super::random::array::<NONCE_LEN>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = [3u8; KEY_LEN];
        let n = nonce().unwrap();
        let ct = seal(&key, &n, b"header", b"body").unwrap();
        assert_eq!(ct.len(), 4 + TAG_LEN);
        assert_eq!(&open(&key, &n, b"header", &ct).unwrap()[..], b"body");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [3u8; KEY_LEN];
        let n = nonce().unwrap();
        let ct = seal(&key, &n, b"header", b"body").unwrap();
        assert!(matches!(
            open(&key, &n, b"heater", &ct),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let n = nonce().unwrap();
        let ct = seal(&[3u8; KEY_LEN], &n, b"", b"body").unwrap();
        assert!(matches!(
            open(&[4u8; KEY_LEN], &n, b"", &ct),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn flipped_ciphertext_bit_fails() {
        let key = [3u8; KEY_LEN];
        let n = nonce().unwrap();
        let mut ct = seal(&key, &n, b"", b"body").unwrap();
        ct[0] ^= 1;
        assert!(matches!(open(&key, &n, b"", &ct), Err(Error::Decrypt)));
    }

    #[test]
    fn only_xchacha_is_accepted() {
        assert!(check_alg(ALG_XCHACHA20POLY1305).is_ok());
        assert!(matches!(
            check_alg("aes256gcm"),
            Err(Error::Unsupported { .. })
        ));
    }
}

//! Host bundles: what a Mac hands a headless host (ADR-0043 §7) — sealed to the host's key and
//! signed by the owner's device key.
//!
//! The payload is opaque here (`kagisecure-host` defines what it carries: machine-vault
//! environments and the standing grants for that host). This module only makes and checks the
//! envelope, with the same primitives as shared vaults: HPKE Base mode to the host's X25519 key,
//! and a domain-separated, strictly verified Ed25519 signature by the owner's device.
//!
//! # Layout
//!
//! ```text
//! magic    "KGSHB\0\0\x01"   8
//! author   device key id       32   the signer
//! host     device key id       32   the only host that may open it
//! sequence u64, big-endian      8   a host refuses one not above the last it imported
//! len      u32, big-endian      4
//! sealed   enc ‖ ct ‖ tag     len   HPKE, info = HOST_INFO ‖ author ‖ host ‖ sequence
//! sig                          64   over Signed::HostBundle { author, host ‖ sequence ‖ len ‖ sealed }
//! ```
//!
//! Every part is fixed-length but `sealed`, whose length is stated before it, so the signed
//! message has one reading. The HPKE `info` binds the ciphertext to the header too: a sealed
//! payload lifted into another header does not open.

use zeroize::Zeroizing;

use kagisecure_core::vault::device::DEVICE_KEY_ID_LEN;

use crate::device::{DeviceKeyId, DevicePublic, DeviceSecret};
use crate::error::{Result, SharedError};
use crate::hpke_wrap::{open_bytes, seal_bytes};
use crate::sign::{SIGNATURE_LEN, Signature, Signed};

/// The first eight bytes of every host bundle.
pub const MAGIC: [u8; 8] = *b"KGSHB\0\0\x01";

/// The largest sealed payload accepted: far above a handful of environments and grants.
pub const MAX_SEALED_LEN: usize = 1024 * 1024;

const HOST_INFO: &[u8] = b"kagisecure/host-bundle/v1";
const HEADER_LEN: usize = MAGIC.len() + DEVICE_KEY_ID_LEN * 2 + 8 + 4;

/// A bundle that verified and opened.
pub struct OpenedHostBundle {
    /// The device that signed it.
    pub author: DeviceKeyId,
    /// Its sequence number.
    pub sequence: u64,
    /// The payload, in a wiped buffer: it carries credential values.
    pub payload: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedHostBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedHostBundle")
            .field("author", &self.author)
            .field("sequence", &self.sequence)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

fn info(author: &DeviceKeyId, host: &DeviceKeyId, sequence: u64) -> Vec<u8> {
    let mut info = Vec::with_capacity(HOST_INFO.len() + DEVICE_KEY_ID_LEN * 2 + 8);
    info.extend_from_slice(HOST_INFO);
    info.extend_from_slice(author.as_bytes());
    info.extend_from_slice(host.as_bytes());
    info.extend_from_slice(&sequence.to_be_bytes());
    info
}

/// Seal `payload` to `host` and sign the result as `author`.
///
/// # Errors
///
/// [`SharedError::LimitExceeded`] for a payload over [`MAX_SEALED_LEN`], and HPKE's errors.
pub fn seal_and_sign(
    author: &DeviceSecret,
    host: &DevicePublic,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let author_id = author.id();
    let host_id = host.id();
    let sealed = seal_bytes(host, &info(&author_id, &host_id, sequence), payload)?;
    let len = u32::try_from(sealed.len())
        .ok()
        .filter(|&l| l as usize <= MAX_SEALED_LEN)
        .ok_or(SharedError::LimitExceeded {
            what: "host bundle payload bytes",
            limit: MAX_SEALED_LEN as u64,
        })?;
    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len() + SIGNATURE_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(author_id.as_bytes());
    out.extend_from_slice(host_id.as_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&sealed);
    let body = &out[MAGIC.len() + DEVICE_KEY_ID_LEN..];
    let signature = author.sign(&Signed::HostBundle {
        author: &author_id,
        body,
    });
    out.extend_from_slice(signature.as_bytes());
    Ok(out)
}

/// The header of a bundle, read without verifying anything: for showing what a file claims to
/// be before importing it.
///
/// # Errors
///
/// [`SharedError::Malformed`] if the bytes are not a host bundle.
pub fn peek(bytes: &[u8]) -> Result<(DeviceKeyId, DeviceKeyId, u64)> {
    let parts = split(bytes)?;
    Ok((parts.author, parts.host, parts.sequence))
}

struct Parts<'a> {
    author: DeviceKeyId,
    host: DeviceKeyId,
    sequence: u64,
    body: &'a [u8],
    sealed: &'a [u8],
    signature: Signature,
}

fn split(bytes: &[u8]) -> Result<Parts<'_>> {
    const BAD: SharedError = SharedError::Malformed("not a kagisecure host bundle");
    if bytes.len() < HEADER_LEN + SIGNATURE_LEN || bytes[..MAGIC.len()] != MAGIC {
        return Err(BAD);
    }
    let id = |at: usize| -> DeviceKeyId {
        let mut b = [0u8; DEVICE_KEY_ID_LEN];
        b.copy_from_slice(&bytes[at..at + DEVICE_KEY_ID_LEN]);
        DeviceKeyId::from_bytes(b)
    };
    let author = id(MAGIC.len());
    let host = id(MAGIC.len() + DEVICE_KEY_ID_LEN);
    let at = MAGIC.len() + DEVICE_KEY_ID_LEN * 2;
    let sequence = u64::from_be_bytes(bytes[at..at + 8].try_into().map_err(|_| BAD)?);
    let len = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().map_err(|_| BAD)?) as usize;
    if len > MAX_SEALED_LEN || bytes.len() != HEADER_LEN + len + SIGNATURE_LEN {
        return Err(BAD);
    }
    let sealed = &bytes[HEADER_LEN..HEADER_LEN + len];
    let body = &bytes[MAGIC.len() + DEVICE_KEY_ID_LEN..HEADER_LEN + len];
    let sig: [u8; SIGNATURE_LEN] = bytes[HEADER_LEN + len..].try_into().map_err(|_| BAD)?;
    Ok(Parts {
        author,
        host,
        sequence,
        body,
        sealed,
        signature: Signature::from_bytes(sig),
    })
}

/// Verify that `bytes` is a bundle signed by `owner` for `host`, with a sequence above
/// `after_sequence`, and open it.
///
/// Checked in this order, and nothing is decrypted until the signature holds: the layout; the
/// signer is `owner`; the signature; the bundle names this host; the sequence; then the payload
/// opens under the header it was sealed with.
///
/// # Errors
///
/// [`SharedError::Malformed`] for a file that is not a bundle,
/// [`SharedError::HostBundleRefused`] for another signer, another host or an old sequence,
/// [`SharedError::BadSignature`] for an altered bundle, and [`SharedError::Decrypt`] for a
/// payload that does not open.
pub fn verify_and_open(
    bytes: &[u8],
    owner: &DevicePublic,
    host: &DeviceSecret,
    after_sequence: Option<u64>,
) -> Result<OpenedHostBundle> {
    let parts = split(bytes)?;
    if parts.author != owner.id() {
        return Err(SharedError::HostBundleRefused(
            "it is signed by a device this host does not trust",
        ));
    }
    owner.verify_strict(
        &Signed::HostBundle {
            author: &parts.author,
            body: parts.body,
        },
        &parts.signature,
    )?;
    if parts.host != host.id() {
        return Err(SharedError::HostBundleRefused(
            "it was made for another host",
        ));
    }
    if after_sequence.is_some_and(|last| parts.sequence <= last) {
        return Err(SharedError::HostBundleRefused(
            "it is not newer than the bundle this host already holds",
        ));
    }
    let payload = open_bytes(
        host,
        &info(&parts.author, &parts.host, parts.sequence),
        parts.sealed,
    )?;
    Ok(OpenedHostBundle {
        author: parts.author,
        sequence: parts.sequence,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (DeviceSecret, DeviceSecret) {
        (
            DeviceSecret::generate().unwrap(),
            DeviceSecret::generate().unwrap(),
        )
    }

    #[test]
    fn a_bundle_opens_for_its_host_under_its_owner() {
        let (owner, host) = pair();
        let bytes = seal_and_sign(&owner, host.public(), 7, b"payload").unwrap();
        assert_eq!(peek(&bytes).unwrap(), (owner.id(), host.id(), 7));
        let opened = verify_and_open(&bytes, owner.public(), &host, Some(6)).unwrap();
        assert_eq!(opened.sequence, 7);
        assert_eq!(opened.author, owner.id());
        assert_eq!(opened.payload.as_slice(), b"payload");
        assert!(
            !bytes.windows(7).any(|w| w == b"payload"),
            "the payload is sealed"
        );
    }

    #[test]
    fn any_altered_byte_is_refused() {
        let (owner, host) = pair();
        let bytes = seal_and_sign(&owner, host.public(), 1, b"payload").unwrap();
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            assert!(
                verify_and_open(&tampered, owner.public(), &host, None).is_err(),
                "byte {i} altered and still accepted"
            );
        }
    }

    #[test]
    fn another_signer_is_refused_even_with_a_valid_signature() {
        let (owner, host) = pair();
        let stranger = DeviceSecret::generate().unwrap();
        let bytes = seal_and_sign(&stranger, host.public(), 1, b"payload").unwrap();
        assert!(matches!(
            verify_and_open(&bytes, owner.public(), &host, None),
            Err(SharedError::HostBundleRefused(_))
        ));
    }

    #[test]
    fn another_host_and_an_old_sequence_are_refused() {
        let (owner, host) = pair();
        let other = DeviceSecret::generate().unwrap();
        let bytes = seal_and_sign(&owner, other.public(), 5, b"payload").unwrap();
        assert!(matches!(
            verify_and_open(&bytes, owner.public(), &host, None),
            Err(SharedError::HostBundleRefused(_))
        ));
        let bytes = seal_and_sign(&owner, host.public(), 5, b"payload").unwrap();
        assert!(matches!(
            verify_and_open(&bytes, owner.public(), &host, Some(5)),
            Err(SharedError::HostBundleRefused(_))
        ));
    }

    #[test]
    fn a_resigned_header_does_not_open_a_lifted_payload() {
        // The owner signs a fresh header around a sealed payload from sequence 1, at sequence 2:
        // the HPKE info no longer matches, so it does not open.
        let (owner, host) = pair();
        let one = seal_and_sign(&owner, host.public(), 1, b"payload").unwrap();
        let sealed = &one[HEADER_LEN..one.len() - SIGNATURE_LEN];
        let mut two = one[..HEADER_LEN].to_vec();
        two[MAGIC.len() + 2 * DEVICE_KEY_ID_LEN..MAGIC.len() + 2 * DEVICE_KEY_ID_LEN + 8]
            .copy_from_slice(&2u64.to_be_bytes());
        two.extend_from_slice(sealed);
        let author = owner.id();
        let sig = owner.sign(&Signed::HostBundle {
            author: &author,
            body: &two[MAGIC.len() + DEVICE_KEY_ID_LEN..],
        });
        two.extend_from_slice(sig.as_bytes());
        assert!(matches!(
            verify_and_open(&two, owner.public(), &host, None),
            Err(SharedError::Decrypt)
        ));
    }
}

//! Domain-separated Ed25519 signatures, verified strictly (ADR-0035 §4, §6; addendum,
//! decision 34).
//!
//! Every signature this format makes is over `domain ‖ 0x00 ‖ content`, where `domain` is an
//! ASCII string naming what is being signed — so a signature made for one purpose can never be
//! presented as one made for another. The domains are a closed list, [`SigDomain`]; the record's
//! is the ADR-0035 addendum's `"kagisecure/shared/sig/record/v1"`.
//!
//! # Framing: no two contents share one message
//!
//! What follows the domain is never a list of loose byte strings concatenated: two
//! variable-length parts written back to back cannot be told apart from a different split of the
//! same bytes, and a signature over one would vouch for the other. A signature is made and
//! checked only over a [`Signed`] — one variant per domain, whose parts are all fixed-length
//! except the last, and whose structured data, when a purpose has any, is one deterministic-CBOR
//! part (decision 34). The record's is its author's 32-byte device key id followed by the body.
//!
//! Verification is `ed25519-dalek`'s `verify_strict`: it refuses a non-canonical `S` (a
//! signature "malleated" into a second valid one by adding the group order), an `R` of small
//! order, and a public key of small order. [`DevicePublic`] has already refused weak,
//! non-canonical and torsion-carrying public keys when it was built.

use ed25519_dalek::Signer as _;

use crate::device::{DeviceKeyId, DevicePublic, DeviceSecret};
use crate::error::{Result, SharedError};

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// What a signature is for: the first bytes of every signed message.
///
/// `#[non_exhaustive]`: enrollment requests and invitations add theirs, each a new
/// `kagisecure/shared/sig/<purpose>/v1` string (ADR-0035 addendum, decision 34).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigDomain {
    /// A record: `"kagisecure/shared/sig/record/v1"`, over the author's id and the body bytes.
    Record,
}

impl SigDomain {
    /// The domain-separation string.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Record => b"kagisecure/shared/sig/record/v1",
        }
    }
}

/// Exactly what one signature covers, by domain (module documentation).
///
/// Each variant's parts are fixed-length but the last, so its message has one reading. A later
/// purpose adds a variant — never a way to sign loose parts — and signs anything structured as
/// one deterministic-CBOR part.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Signed<'a> {
    /// A record (ADR-0035 addendum, "Record envelope"): `author ‖ body`, the author's 32-byte
    /// device key id and then the body's bytes, to the end of the message.
    Record {
        /// The device the record names as its author.
        author: &'a DeviceKeyId,
        /// The body, exactly as it is in the envelope.
        body: &'a [u8],
    },
}

impl Signed<'_> {
    /// The domain this content is signed in.
    #[must_use]
    pub const fn domain(&self) -> SigDomain {
        match self {
            Self::Record { .. } => SigDomain::Record,
        }
    }

    /// The exact message a signature over this content covers: `domain ‖ 0x00 ‖ content`.
    #[must_use]
    pub fn to_message(&self) -> Vec<u8> {
        let domain = self.domain().as_bytes();
        match self {
            Self::Record { author, body } => {
                let author = author.as_bytes();
                let mut message = Vec::with_capacity(domain.len() + 1 + author.len() + body.len());
                message.extend_from_slice(domain);
                message.push(0x00);
                // Fixed-length, so where it ends and the body begins is never in question.
                message.extend_from_slice(author);
                message.extend_from_slice(body);
                message
            }
        }
    }
}

impl std::fmt::Debug for Signed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record { author, body } => f
                .debug_struct("Signed::Record")
                .field("author", author)
                .field("body_len", &body.len())
                .finish(),
        }
    }
}

/// An Ed25519 signature, as its 64 bytes. Public.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// A signature as read from a file. Whether it verifies is [`DevicePublic::verify_strict`]'s
    /// question.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The signature's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({})", crate::device::hex(&self.0))
    }
}

impl DeviceSecret {
    /// Sign `content`, in its domain.
    #[must_use]
    pub fn sign(&self, content: &Signed<'_>) -> Signature {
        self.sign_message(&content.to_message())
    }

    /// Sign a message [`Signed::to_message`] already assembled.
    pub(crate) fn sign_message(&self, message: &[u8]) -> Signature {
        Signature(self.signing_key().sign(message).to_bytes())
    }
}

impl DevicePublic {
    /// Verify, strictly, that `signature` is this device's over `content`, in its domain.
    ///
    /// # Errors
    ///
    /// [`SharedError::BadSignature`] if it is not — whatever the reason, which a signature
    /// failure does not report.
    pub fn verify_strict(&self, content: &Signed<'_>, signature: &Signature) -> Result<()> {
        self.verify_message(&content.to_message(), signature)
    }

    /// Verify a message [`Signed::to_message`] already assembled.
    pub(crate) fn verify_message(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let signature = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.verifying_key()
            .verify_strict(message, &signature)
            .map_err(|_| SharedError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{device_with_seed, golden_device, unhex, unhex32};

    /// RFC 8032 §7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc) — secret key, public key, message,
    /// signature.
    const RFC_8032_VECTORS: [(&str, &str, &str, &str); 4] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac\
             c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e\
             458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290\
             ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ec\
             fdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];

    fn sig64(hex: &str) -> Signature {
        Signature::from_bytes(unhex(hex).try_into().unwrap())
    }

    /// The primitive beneath the domain separation is RFC 8032's Ed25519, byte for byte.
    #[test]
    fn signing_and_strict_verification_match_the_rfc_8032_vectors() {
        for (secret, public, message, signature) in RFC_8032_VECTORS {
            let device = device_with_seed(unhex32(secret));
            assert_eq!(device.public().sig_pk(), &unhex32(public));
            let message = unhex(message);
            let expected = sig64(signature);
            assert_eq!(device.sign_message(&message), expected);
            device.public().verify_message(&message, &expected).unwrap();
        }
    }

    fn record<'a>(author: &'a DeviceKeyId, body: &'a [u8]) -> Signed<'a> {
        Signed::Record { author, body }
    }

    #[test]
    fn a_signature_verifies_only_over_its_own_content_in_its_own_domain() {
        let device = golden_device();
        let author = device.id();
        let signature = device.sign(&record(&author, b"body"));
        let public = device.public();
        public
            .verify_strict(&record(&author, b"body"), &signature)
            .unwrap();
        // Other bytes, another author, or the bare content without the domain: refused.
        let mut other = *author.as_bytes();
        other[31] ^= 1;
        let other = DeviceKeyId::from_bytes(other);
        for content in [record(&author, b"bodY"), record(&other, b"body")] {
            assert!(matches!(
                public.verify_strict(&content, &signature),
                Err(SharedError::BadSignature)
            ));
        }
        let mut bare = author.as_bytes().to_vec();
        bare.extend_from_slice(b"body");
        assert!(public.verify_message(&bare, &signature).is_err());
    }

    /// The record's message is the contract's `domain ‖ 0x00 ‖ author ‖ body`, byte for byte —
    /// the framing adds nothing to it, because its one variable-length part is the last.
    #[test]
    fn the_record_message_is_the_domain_the_fixed_author_and_the_body() {
        let author = DeviceKeyId::from_bytes([0xaa; 32]);
        let mut expected = b"kagisecure/shared/sig/record/v1\x00".to_vec();
        expected.extend_from_slice(&[0xaa; 32]);
        expected.extend_from_slice(b"ab");
        assert_eq!(record(&author, b"ab").to_message(), expected);
        assert_eq!(record(&author, b"ab").domain(), SigDomain::Record);
        // The author cannot absorb bytes of the body, or the body those of the author: the
        // first 32 bytes after the separator are always the author.
        let message = record(&author, b"").to_message();
        assert_eq!(message.len(), SigDomain::Record.as_bytes().len() + 1 + 32);
    }

    #[test]
    fn a_signature_from_another_device_does_not_verify() {
        let one = golden_device();
        let other = device_with_seed([7; 32]);
        let author = one.id();
        let signature = other.sign(&record(&author, b"x"));
        assert!(
            one.public()
                .verify_strict(&record(&author, b"x"), &signature)
                .is_err()
        );
    }

    /// Adding the group order ℓ to `S` gives the same point equation, so a lax verifier accepts
    /// both; strict verification requires `S < ℓ`.
    #[test]
    fn a_malleated_signature_is_refused() {
        // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
        const ELL: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let device = golden_device();
        let author = device.id();
        let signature = device.sign(&record(&author, b"message"));
        let mut bytes = *signature.as_bytes();
        let mut carry = 0u16;
        for (s, l) in bytes[32..].iter_mut().zip(ELL) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + ℓ fits in 256 bits");
        let malleated = Signature::from_bytes(bytes);
        assert_ne!(malleated, signature);
        assert!(matches!(
            device
                .public()
                .verify_strict(&record(&author, b"message"), &malleated),
            Err(SharedError::BadSignature)
        ));
    }

    /// A signature whose `R` is the identity (a point of small order) is refused, whatever `S`.
    #[test]
    fn a_signature_with_a_small_order_r_is_refused() {
        let device = golden_device();
        let author = device.id();
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes[0] = 1;
        assert!(
            device
                .public()
                .verify_strict(&record(&author, b"m"), &Signature::from_bytes(bytes))
                .is_err()
        );
    }
}

//! The plaintext, authenticated vault header (vault-format §2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::KdfParams;
use crate::crypto::wrap::WrappedKey;
use crate::error::{Error, Result};

/// File magic.
pub const MAGIC: [u8; 8] = *b"KAGIVLT\x00";
/// The `format_ver` this build writes for a new vault, and for any vault whose file already
/// carries it: a file keeps the `format_ver` it was read with (see `Vault::format_ver`).
///
/// Version 2 differs from version 1 in one respect only: the body may hold device keys for shared
/// vaults (ADR-0035 §5, §16). The byte layout is the same. The bump exists so that a build which
/// predates the unknown-key passthrough (vault-format §9 rule 1) refuses such a file outright
/// instead of opening it and silently dropping the keys on its next save.
///
/// Version 3 is the same again, for the machine vault (ADR-0042 §2): a personal body that holds
/// the machine vault's key, and every machine vault file.
pub const FORMAT_VERSION: u16 = 1;
/// The `format_ver` a vault holding shared-vault device keys is written with, at least (ADR-0035
/// §16). Writing the first device key into a version 1 file upgrades it, after a backup.
pub const DEVICE_KEYS_FORMAT_VERSION: u16 = 2;
/// The `format_ver` a personal vault holding the machine vault's key, and every machine vault, is
/// written with, at least (ADR-0042 §2). No data is converted: an older file is raised to it,
/// after the usual backup, the first time it gains a machine vault key.
pub const MACHINE_VAULT_FORMAT_VERSION: u16 = 3;
/// The highest `format_ver` this build can read. Anything newer is refused, never guessed at
/// (vault-format §9).
pub const MAX_READ_FORMAT_VERSION: u16 = 3;
/// The header CBOR schema version this build writes.
pub const HEADER_SCHEMA_VERSION: u16 = 1;
/// `MAGIC` + `format_ver` + `header_len`.
pub const PREFIX_LEN: usize = 8 + 2 + 4;
/// Sanity cap on `header_len`, so a corrupt length prefix cannot make us allocate wildly.
pub const MAX_HEADER_LEN: u32 = 1 << 20;
/// `compression` value for "no compression"; the only one v1 implements.
pub const COMPRESSION_NONE: &str = "none";

/// The header map (vault-format §2.1).
///
/// It is plaintext by necessity — it carries the KDF salt and parameters needed to derive the key
/// that decrypts everything else — and authenticated by being fed to the body's AEAD as
/// associated data. Downgrading Argon2id memory to 8 KiB therefore makes the body fail to
/// decrypt rather than making an attack cheaper.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// Header schema version, independent of `format_ver`.
    pub v: u16,
    /// Random 16-byte vault identifier, stable for the life of the file.
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    /// Unix seconds.
    pub created_at: u64,
    /// Default KDF descriptor. Slots may override it (see [`WrappedKey::kdf`]).
    pub kdf: KdfParams,
    /// AEAD used for the body.
    pub body_aead: String,
    /// Wrapped copies of the vault key.
    pub wrapped_keys: Vec<WrappedKey>,
    /// Body compression; `"none"` in v1.
    pub compression: String,
    /// Optional human note, e.g. `"desktop-2026"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_hint: Option<String>,
    /// Top-level header keys this build does not recognize, preserved verbatim so an older build
    /// opening a vault a newer one wrote never destroys them (vault-format §9 rule 1).
    ///
    /// Order and exact re-encoding are not guaranteed to match the original bytes — only the
    /// *value* survives — which is enough here: nothing hashes the header, and every write
    /// re-derives the on-disk bytes (and, from them, the body AEAD's associated data) from
    /// whatever `Header` holds at that moment, so a write is always self-consistent regardless of
    /// map key order (vault-format §4). Unlike [`crate::audit::AuditEntry`], the header carries no
    /// hash chain, so it has no byte-exactness requirement to meet.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl Header {
    /// Encode the header to CBOR.
    ///
    /// # Errors
    ///
    /// [`Error::HeaderDecode`] if CBOR encoding fails, which in practice it cannot.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::HeaderDecode(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a header from CBOR.
    ///
    /// # Errors
    ///
    /// [`Error::HeaderDecode`] if the bytes are not a well-formed header map.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|e| Error::HeaderDecode(e.to_string()))
    }

    /// Reject anything this build cannot honour, before any key material is touched.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for an unknown AEAD or compression scheme, and whatever
    /// [`KdfParams::validate`] returns for the default and per-slot KDF descriptors.
    pub fn validate(&self) -> Result<()> {
        crate::crypto::aead::check_alg(&self.body_aead)?;
        if self.compression != COMPRESSION_NONE {
            return Err(Error::Unsupported {
                what: "body compression",
                value: self.compression.clone(),
            });
        }
        self.kdf.validate()?;
        for slot in &self.wrapped_keys {
            if let Some(k) = &slot.kdf {
                k.validate()?;
            }
        }
        Ok(())
    }

    /// The first slot of the given kind.
    #[must_use]
    pub fn slot(&self, kind: &str) -> Option<&WrappedKey> {
        self.wrapped_keys.iter().find(|s| s.kind == kind)
    }

    /// Mutable access to the first slot of the given kind.
    pub fn slot_mut(&mut self, kind: &str) -> Option<&mut WrappedKey> {
        self.wrapped_keys.iter_mut().find(|s| s.kind == kind)
    }
}

/// The on-disk prefix — magic, format version, header length — followed by the header bytes.
///
/// This exact byte range is what the body's AEAD authenticates (vault-format §4). It is always
/// taken from the bytes actually written or actually read, never from a re-serialization, so a
/// re-encoding that differs by a byte cannot silently break or silently accept a file.
///
/// Always [`FORMAT_VERSION`]; [`framed_with_version`] writes another.
#[must_use]
pub fn framed(header_cbor: &[u8]) -> Vec<u8> {
    framed_with_version(header_cbor, FORMAT_VERSION)
}

/// [`framed`] with an explicit `format_ver`, for a file that must keep the version it was read
/// with. `format_ver` is inside the authenticated prefix, so it cannot be changed afterwards
/// without the body failing to open.
#[must_use]
pub fn framed_with_version(header_cbor: &[u8], format_ver: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX_LEN + header_cbor.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&format_ver.to_le_bytes());
    out.extend_from_slice(&(header_cbor.len() as u32).to_le_bytes());
    out.extend_from_slice(header_cbor);
    out
}

/// A vault file taken apart into its four regions.
#[derive(Debug)]
pub struct SplitFile<'a> {
    /// The file's `format_ver`, at most [`MAX_READ_FORMAT_VERSION`].
    pub format_ver: u16,
    /// Bytes 0 through the end of the header — the body AEAD's associated data.
    pub aad: &'a [u8],
    /// The decoded header.
    pub header: Header,
    /// The body's 24-byte nonce.
    pub body_nonce: [u8; 24],
    /// The body ciphertext, tag included.
    pub body_ct: &'a [u8],
}

/// Split a whole vault file into its regions.
///
/// # Errors
///
/// [`Error::BadMagic`], [`Error::UnsupportedFormatVersion`], [`Error::Malformed`] or
/// [`Error::HeaderDecode`] as appropriate. Nothing here touches key material, so it is safe to
/// run on wholly untrusted bytes.
pub fn split(file: &[u8]) -> Result<SplitFile<'_>> {
    if file.len() < PREFIX_LEN {
        return Err(Error::Malformed);
    }
    if file[..8] != MAGIC {
        return Err(Error::BadMagic);
    }
    let format_ver = u16::from_le_bytes([file[8], file[9]]);
    // No build has ever written version 0: it is damage, not a version.
    if format_ver == 0 {
        return Err(Error::Malformed);
    }
    if format_ver > MAX_READ_FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion {
            found: format_ver,
            supported: MAX_READ_FORMAT_VERSION,
        });
    }
    let header_len = u32::from_le_bytes([file[10], file[11], file[12], file[13]]);
    if header_len > MAX_HEADER_LEN {
        return Err(Error::Malformed);
    }
    let header_len = header_len as usize;
    let header_end = PREFIX_LEN.checked_add(header_len).ok_or(Error::Malformed)?;
    let nonce_end = header_end.checked_add(24).ok_or(Error::Malformed)?;
    if file.len() < nonce_end + crate::crypto::aead::TAG_LEN {
        return Err(Error::Malformed);
    }
    let header = Header::from_cbor(&file[PREFIX_LEN..header_end])?;
    let nonce: [u8; 24] = file[header_end..nonce_end]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    Ok(SplitFile {
        format_ver,
        aad: &file[..header_end],
        header,
        body_nonce: nonce,
        body_ct: &file[nonce_end..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            v: HEADER_SCHEMA_VERSION,
            vault_id: vec![7u8; 16],
            created_at: 1_757_000_000,
            kdf: KdfParams::new(64, 1, 1).unwrap(),
            body_aead: crate::crypto::aead::ALG_XCHACHA20POLY1305.to_owned(),
            wrapped_keys: Vec::new(),
            compression: COMPRESSION_NONE.to_owned(),
            kdf_hint: None,
            unknown: BTreeMap::new(),
        }
    }

    #[test]
    fn cbor_round_trips() {
        let h = sample();
        let decoded = Header::from_cbor(&h.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded.vault_id, h.vault_id);
        assert_eq!(decoded.kdf, h.kdf);
        assert_eq!(decoded.v, h.v);
    }

    #[test]
    fn unknown_header_keys_round_trip() {
        // A hypothetical field a newer build added, e.g. a shared-vault device key list
        // (vault-format §9 rule 1).
        let mut h = sample();
        h.unknown.insert(
            "device_keys".to_owned(),
            ciborium::Value::Array(vec![ciborium::Value::Text("device-1".to_owned())]),
        );
        let decoded = Header::from_cbor(&h.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded.unknown, h.unknown);
        // Named fields are unaffected by the presence of unknown ones.
        assert_eq!(decoded.vault_id, h.vault_id);
    }

    #[test]
    fn a_header_with_no_unknown_keys_encodes_identically_to_before() {
        // The flatten field must not add a key, or change the map length, when empty: the golden
        // vector (written before this field existed) must decode and re-encode unchanged.
        let cbor = sample().to_cbor().unwrap();
        let decoded = Header::from_cbor(&cbor).unwrap();
        assert!(decoded.unknown.is_empty());
        assert_eq!(decoded.to_cbor().unwrap(), cbor);
    }

    #[test]
    fn framing_with_a_version_writes_that_version_and_nothing_else_differs() {
        let cbor = sample().to_cbor().unwrap();
        let one = framed(&cbor);
        let two = framed_with_version(&cbor, 2);
        assert_eq!(one[8..10], 1u16.to_le_bytes());
        assert_eq!(two[8..10], 2u16.to_le_bytes());
        assert_eq!(one[..8], two[..8]);
        assert_eq!(one[10..], two[10..]);
    }

    #[test]
    fn salts_and_nonces_are_cbor_byte_strings_not_arrays() {
        // A CBOR byte string of 16 bytes is 0x50 followed by the bytes; an array of 16 small
        // integers would be 0x90.... This keeps the file compact and unambiguous (vault-format §2).
        let cbor = sample().to_cbor().unwrap();
        assert!(
            cbor.windows(2).any(|w| w == [0x50, 7]),
            "vault_id should be encoded as a CBOR byte string"
        );
    }

    #[test]
    fn split_rejects_rubbish() {
        assert!(matches!(split(b""), Err(Error::Malformed)));
        assert!(matches!(split(&[0u8; 64]), Err(Error::BadMagic)));

        let mut file = framed(&sample().to_cbor().unwrap());
        file.extend_from_slice(&[0u8; 24 + 16]);
        assert!(split(&file).is_ok());

        assert_eq!(split(&file).unwrap().format_ver, FORMAT_VERSION);

        // Version 2 — a vault holding device keys — is read, and says so.
        let mut second = file.clone();
        second[8] = 2;
        assert_eq!(split(&second).unwrap().format_ver, 2);

        // Version 0 was never written by anything: damage, refused as such.
        let mut zero = file.clone();
        zero[8] = 0;
        assert!(matches!(split(&zero), Err(Error::Malformed)));

        // Version 3 — a machine vault, or a personal vault holding its key — is read too.
        let mut third = file.clone();
        third[8] = 3;
        assert_eq!(split(&third).unwrap().format_ver, 3);

        // A future format version is refused, never guessed at.
        let mut newer = file.clone();
        newer[8] = 4;
        assert!(matches!(
            split(&newer),
            Err(Error::UnsupportedFormatVersion {
                found: 4,
                supported: 3
            })
        ));

        // A truncated file is refused.
        assert!(matches!(
            split(&file[..file.len() - 20]),
            Err(Error::Malformed)
        ));

        // An absurd header length is refused before allocating.
        let mut huge = file.clone();
        huge[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(split(&huge), Err(Error::Malformed)));
    }
}

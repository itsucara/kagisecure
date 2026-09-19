//! The printable recovery code (vault-format §3.2, roadmap M1).
//!
//! 256 bits of CSPRNG output, shown to the user once, as RFC 4648 Base32 with a 10-bit checksum,
//! grouped for transcription. The alphabet is `A`–`Z` and `2`–`7`, so the digits people most often
//! confuse with letters (`0`, `1`, `8`) cannot occur at all.
//!
//! The code is stretched with Argon2id — the same function and the same cost as the password path,
//! its own salt — and wraps the vault key into a `"recovery"` slot. It is independent of the
//! master password and of any enrolled biometric.

use zeroize::Zeroizing;

use crate::crypto::random;
use crate::error::{Error, Result};

/// Length of the raw recovery secret in bytes.
pub const CODE_LEN: usize = 32;

/// Base32 characters that encode the 32-byte secret (`ceil(256 / 5)`).
const BODY_CHARS: usize = 52;
/// Base32 characters of checksum.
const CHECK_CHARS: usize = 2;
/// Characters per printed group.
const GROUP: usize = 6;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A recovery code.
///
/// Holds the raw 256-bit secret, zeroized on drop. Like [`Secret`](crate::Secret) it has a
/// redacting `Debug` and no `Display`; the printable form is produced explicitly by
/// [`RecoveryCode::display`] so that reaching a terminal is always a deliberate act.
pub struct RecoveryCode(Zeroizing<[u8; CODE_LEN]>);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl PartialEq for RecoveryCode {
    fn eq(&self, other: &Self) -> bool {
        let mut acc = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }
}

impl Eq for RecoveryCode {}

impl RecoveryCode {
    /// Generate a fresh 256-bit code.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(random::array::<CODE_LEN>()?)))
    }

    /// The raw secret, as the input to Argon2id.
    #[must_use]
    pub fn material(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// The printable form: 54 Base32 characters in nine groups of six, separated by `-`.
    ///
    /// The returned `String` is zeroized on drop. Print it once and let it go.
    #[must_use]
    pub fn display(&self) -> Zeroizing<String> {
        let mut chars = base32_encode(self.0.as_slice());
        debug_assert_eq!(chars.len(), BODY_CHARS);
        let check = checksum(self.0.as_slice());
        chars.push(ALPHABET[usize::from(check >> 5)] as char);
        chars.push(ALPHABET[usize::from(check & 0x1f)] as char);

        let mut out = String::with_capacity(chars.len() + chars.len() / GROUP);
        for (i, c) in chars.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(c);
        }
        Zeroizing::new(out)
    }

    /// Parse a code the user typed back in.
    ///
    /// Separators (`-`, spaces, tabs) are ignored and lower case is accepted.
    ///
    /// # Errors
    ///
    /// [`Error::BadRecoveryCode`] if the length, the alphabet or the checksum is wrong. The three
    /// causes are not distinguished to the caller beyond this one error.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<Vec<u8>> = Zeroizing::new(
            input
                .bytes()
                .filter(|b| !matches!(b, b'-' | b' ' | b'\t' | b'\r' | b'\n' | b'_'))
                .map(|b| b.to_ascii_uppercase())
                .collect(),
        );
        if cleaned.len() != BODY_CHARS + CHECK_CHARS {
            return Err(Error::BadRecoveryCode);
        }
        let body = base32_decode(&cleaned[..BODY_CHARS])?;
        if body.len() != CODE_LEN {
            return Err(Error::BadRecoveryCode);
        }
        let given = u16::from(symbol(cleaned[BODY_CHARS])?) << 5
            | u16::from(symbol(cleaned[BODY_CHARS + 1])?);
        if given != checksum(&body) {
            return Err(Error::BadRecoveryCode);
        }
        let mut raw = Zeroizing::new([0u8; CODE_LEN]);
        raw.copy_from_slice(&body);
        Ok(Self(raw))
    }
}

/// Ten checksum bits derived from SHA-256 of the raw code.
fn checksum(bytes: &[u8]) -> u16 {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    (u16::from(digest[0]) << 2) | u16::from(digest[1] >> 6)
}

fn symbol(c: u8) -> Result<u8> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|p| p as u8)
        .ok_or(Error::BadRecoveryCode)
}

/// RFC 4648 Base32 without padding.
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for &b in bytes {
        acc = (acc << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[usize::from((acc >> bits) & 0x1f)] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[usize::from((acc << (5 - bits)) & 0x1f)] as char);
    }
    out
}

/// RFC 4648 Base32 without padding. Leftover bits must be zero.
fn base32_decode(chars: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(chars.len() * 5 / 8));
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for &c in chars {
        acc = (acc << 5) | u16::from(symbol(c)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(Error::BadRecoveryCode);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_printable_form() {
        let code = RecoveryCode::generate().unwrap();
        let printed = code.display();
        let parsed = RecoveryCode::parse(&printed).unwrap();
        assert_eq!(code, parsed);
        assert_eq!(parsed.material(), code.material());
    }

    #[test]
    fn printable_form_is_grouped_and_uses_only_the_alphabet() {
        let printed = RecoveryCode::generate().unwrap().display();
        let groups: Vec<&str> = printed.split('-').collect();
        assert_eq!(groups.len(), 9);
        assert!(groups.iter().all(|g| g.len() == GROUP));
        assert!(
            printed.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)),
            "unexpected character in printed code"
        );
        // The characters people mistype are not in the alphabet at all.
        assert!(!printed.contains('0'));
        assert!(!printed.contains('1'));
        assert!(!printed.contains('8'));
    }

    #[test]
    fn separators_and_case_are_forgiven() {
        let code = RecoveryCode::generate().unwrap();
        let printed = code.display();
        let messy = format!("  {}  ", printed.to_lowercase().replace('-', " "));
        assert_eq!(RecoveryCode::parse(&messy).unwrap(), code);
        assert_eq!(
            RecoveryCode::parse(&printed.replace('-', "")).unwrap(),
            code
        );
    }

    #[test]
    fn a_single_wrong_character_is_caught_by_the_checksum() {
        let printed = RecoveryCode::generate().unwrap().display();
        let mut bytes = printed.as_bytes().to_vec();
        // Flip the first body character to a different alphabet member.
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let corrupted = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            RecoveryCode::parse(&corrupted),
            Err(Error::BadRecoveryCode)
        ));
    }

    #[test]
    fn rubbish_is_refused() {
        for bad in ["", "hello", "0000000000", &"A".repeat(54)] {
            assert!(matches!(
                RecoveryCode::parse(bad),
                Err(Error::BadRecoveryCode)
            ));
        }
    }

    #[test]
    fn debug_is_redacted() {
        let code = RecoveryCode::generate().unwrap();
        assert_eq!(format!("{code:?}"), "RecoveryCode(<redacted>)");
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(&base32_decode(b"MZXW6YTBOI").unwrap()[..], b"foobar");
    }

    #[test]
    fn two_generated_codes_differ() {
        assert_ne!(
            RecoveryCode::generate().unwrap(),
            RecoveryCode::generate().unwrap()
        );
    }
}

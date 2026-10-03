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
        // A fixed body, not `RecoveryCode::generate()`: the checksum is 10 bits of SHA-256 of the
        // body, not an algebraic code that mathematically guarantees catching every
        // single-character substitution, so whether a *specific* substitution is caught depends
        // on the exact bytes involved. `single_character_substitutions_have_a_known_and_imperfect_
        // detection_rate` below sweeps every position and every substitution on fixed bodies,
        // including this one, and confirms the all-zero body's substitutions are all caught; this
        // test exercises that one concretely, deterministically, so it can never flake the way a
        // fresh random draw occasionally did.
        let code = RecoveryCode(Zeroizing::new([0u8; CODE_LEN]));
        let printed = code.display();
        let mut bytes = printed.as_bytes().to_vec();
        // The all-zero body's first body character encodes as 'A'; flip it to 'B'.
        assert_eq!(bytes[0], b'A');
        bytes[0] = b'B';
        let corrupted = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            RecoveryCode::parse(&corrupted),
            Err(Error::BadRecoveryCode)
        ));
    }

    /// How often the checksum actually catches a single wrong character, measured exhaustively
    /// rather than assumed.
    ///
    /// The checksum is 10 bits of SHA-256 of the 256-bit body — a collision-resistant digest, not
    /// an algebraic error-detecting code (like a mod-97 or Luhn check digit) that is constructed
    /// to guarantee catching every single-symbol substitution. With 52 body positions and 31
    /// alternate alphabet symbols at each, there are 1,612 possible single-character
    /// substitutions per code, against only 1,024 possible checksum values: by the pigeonhole
    /// principle some substitutions of some codes must land on the original checksum by chance
    /// and parse as a *different, wrong* code rather than being refused. That is a property of
    /// using a short checksum at all, not a bug in this implementation, and it must not be
    /// "fixed" by widening the checksum or changing the digest: either is a vault-format change
    /// that would stop already-issued recovery codes from parsing.
    ///
    /// This test is exhaustive over five fixed 32-byte bodies (never `RecoveryCode::generate()`),
    /// every one of the 52 body positions, and every one of the 31 alternate symbols at that
    /// position — 8,060 substitutions total, all of them deterministic, so this test cannot flake.
    /// It asserts the exact miss count measured for each body, so a future change to the checksum
    /// algorithm (which would change these counts) fails this test loudly instead of silently.
    #[test]
    fn single_character_substitutions_have_a_known_and_imperfect_detection_rate() {
        let bodies: [[u8; CODE_LEN]; 5] = [
            [0u8; CODE_LEN],
            [0xFFu8; CODE_LEN],
            std::array::from_fn(|i| i as u8),
            [0xAAu8; CODE_LEN],
            [
                3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3,
                2, 7, 9, 5,
            ],
        ];
        // Measured once and pinned here; see the doc comment above for why these are not zero.
        let expected_missed = [0, 5, 1, 1, 1];
        let substitutions_per_body = BODY_CHARS * (ALPHABET.len() - 1);
        assert_eq!(substitutions_per_body, 1612);

        for (body, &expected_missed) in bodies.iter().zip(&expected_missed) {
            let given = checksum(body);
            let printed: Vec<char> = base32_encode(body).chars().collect();
            assert_eq!(printed.len(), BODY_CHARS);

            let mut missed = 0usize;
            for pos in 0..BODY_CHARS {
                let original = printed[pos];
                for &alt in ALPHABET {
                    let alt = alt as char;
                    if alt == original {
                        continue;
                    }
                    let mut corrupted = printed.clone();
                    corrupted[pos] = alt;
                    let corrupted: String = corrupted.into_iter().collect();
                    // A substitution that does not even decode to a 32-byte body (the last
                    // position's leftover-bits check) is caught before the checksum is ever
                    // consulted; that is still a catch, just not the one this test is counting.
                    let Ok(corrupted_body) = base32_decode(corrupted.as_bytes()) else {
                        continue;
                    };
                    if corrupted_body.len() != CODE_LEN {
                        continue;
                    }
                    if checksum(&corrupted_body) == given {
                        // Not caught: a different body than the one this code actually is, whose
                        // checksum happens to match. Confirm it really is a different body — the
                        // silent-wrong-code risk this test measures, not a no-op edit.
                        assert_ne!(
                            &corrupted_body[..],
                            &body[..],
                            "a single-symbol substitution must change the body"
                        );
                        missed += 1;
                    }
                }
            }
            assert_eq!(
                missed,
                expected_missed,
                "detection rate for this fixed body: {}/{substitutions_per_body} substitutions caught",
                substitutions_per_body - missed
            );
        }
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

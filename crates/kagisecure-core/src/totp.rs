//! Time-based one-time passwords (RFC 6238), and the `otpauth://` URIs that carry them.
//!
//! # What is secret here
//!
//! Two things, and both are [`Secret`]:
//!
//! * the **seed** — the shared key a service handed the user, usually as Base32 in a QR code;
//! * the **code** — the six-to-eight digits derived from that seed and the current time.
//!
//! The code is short-lived, but "short-lived" is not "public": anyone holding it inside its
//! window can complete a second factor with it. So [`Totp::code_at`] returns a `Secret` like every
//! other value in this crate, and the only way to a `String` is the same explicitly named
//! [`Secret::expose_str`] escape hatch that a stored password needs (ADR-0005).
//!
//! The **parameters** — algorithm, digit count, period, issuer, account — are metadata. They say
//! nothing an attacker cannot guess from the service's own documentation.
//!
//! # Why this module is behind `secret-material`
//!
//! It cannot be compiled by a crate that must never hold plaintext. `kagisecure-mcp` and
//! `kagisecure-ipc` depend on the core with `default-features = false`, so they cannot name
//! [`Totp`], cannot call [`Totp::code_at`] and have no type in which a code could travel
//! (ADR-0002 §3, mcp-server.md §2.7). That is the enforcement; the canary test in
//! `crates/kagisecure-cli/tests/mcp.rs` is the assertion.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};
use crate::model::Secret;

/// HMAC over `counter`, keyed with `key`.
///
/// A macro rather than a generic function: the `hmac` crate's bounds for "any eager hash" pull
/// `digest`'s core-API traits into this module's signature for no gain, and the three call sites
/// are known at compile time.
macro_rules! hmac_of {
    ($hash:ty, $key:expr, $counter:expr) => {{
        // `new_from_slice` only rejects keys for fixed-key algorithms; HMAC takes any length.
        let mut mac = <Hmac<$hash> as KeyInit>::new_from_slice($key)
            .expect("HMAC accepts a key of any length");
        mac.update($counter);
        mac.finalize().into_bytes().to_vec()
    }};
}

/// The default period, in seconds. Every service that does not say otherwise means this.
pub const DEFAULT_PERIOD: u32 = 30;
/// The default digit count.
pub const DEFAULT_DIGITS: u8 = 6;

/// Which HMAC the code is derived with.
///
/// SHA-1 is the default because it is what RFC 6238 specifies and what essentially every service
/// issues. HOTP's use of HMAC-SHA-1 does not depend on the collision resistance SHA-1 lost, so
/// the usual "SHA-1 is broken" reflex does not apply; the alternative is being unable to read a
/// user's existing codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1. The default and the near-universal choice.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// The name as it appears in an `otpauth://` URI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

impl std::str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(Error::Totp("algorithm must be SHA1, SHA256 or SHA512")),
        }
    }
}

/// Everything about a TOTP field except the seed. Metadata, all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpParams {
    /// Which HMAC.
    pub algorithm: Algorithm,
    /// How many digits the code has: 6, 7 or 8.
    pub digits: u8,
    /// How long a code is valid, in seconds.
    pub period: u32,
    /// The service, e.g. `"GitHub"`. Shown next to the code.
    pub issuer: Option<String>,
    /// The account at that service, e.g. `"ada@example.com"`.
    pub account: Option<String>,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::default(),
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            issuer: None,
            account: None,
        }
    }
}

impl TotpParams {
    /// Reject a parameter set no code could be generated from.
    ///
    /// # Errors
    ///
    /// [`Error::Totp`] for a digit count outside 6–8 or a zero period.
    pub fn validate(&self) -> Result<()> {
        if !(6..=8).contains(&self.digits) {
            return Err(Error::Totp("a code must have 6, 7 or 8 digits"));
        }
        if self.period == 0 {
            return Err(Error::Totp("the period must be at least one second"));
        }
        Ok(())
    }

    /// The one-line description the UI puts under the code: `"GitHub · ada@example.com"`.
    #[must_use]
    pub fn caption(&self) -> Option<String> {
        match (self.issuer.as_deref(), self.account.as_deref()) {
            (Some(i), Some(a)) => Some(format!("{i} · {a}")),
            (Some(one), None) | (None, Some(one)) => Some(one.to_owned()),
            (None, None) => None,
        }
    }
}

/// A configured TOTP generator: a seed plus its parameters.
///
/// Holds no clock. Every method that needs the time takes it, so the countdown and the code are
/// testable and cannot disagree with each other about "now".
#[derive(Debug)]
pub struct Totp {
    secret: Secret,
    params: TotpParams,
}

impl Totp {
    /// Build from raw seed bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Totp`] for an empty seed or invalid parameters.
    pub fn new(secret: Secret, params: TotpParams) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::Totp("the shared secret is empty"));
        }
        params.validate()?;
        Ok(Self { secret, params })
    }

    /// Build from a Base32 seed as a service prints it.
    ///
    /// # Errors
    ///
    /// [`Error::Totp`] if the Base32 does not decode, or as [`Totp::new`].
    pub fn from_base32(secret: &str, params: TotpParams) -> Result<Self> {
        Self::new(Secret::new(base32_decode(secret)?), params)
    }

    /// The parameters. Metadata; safe to render.
    #[must_use]
    pub fn params(&self) -> &TotpParams {
        &self.params
    }

    /// The counter value RFC 6238 §4 derives from a Unix timestamp.
    #[must_use]
    pub fn counter_at(&self, unix_seconds: u64) -> u64 {
        unix_seconds / u64::from(self.params.period)
    }

    /// How many seconds the code generated at `unix_seconds` remains valid, counting the current
    /// second. Always in `1..=period`, so a ring driven by it is never empty and never full.
    #[must_use]
    pub fn seconds_remaining(&self, unix_seconds: u64) -> u32 {
        let period = u64::from(self.params.period);
        u32::try_from(period - (unix_seconds % period)).unwrap_or(self.params.period)
    }

    /// The code for the window containing `unix_seconds`.
    ///
    /// # Errors
    ///
    /// Never, for a [`Totp`] that was constructed successfully; the signature returns a `Result`
    /// so that a future keyed-hash failure has somewhere to go.
    pub fn code_at(&self, unix_seconds: u64) -> Result<Secret> {
        let counter = self.counter_at(unix_seconds).to_be_bytes();
        let key = self.secret.expose();
        let mac = match self.params.algorithm {
            Algorithm::Sha1 => hmac_of!(Sha1, key, &counter),
            Algorithm::Sha256 => hmac_of!(Sha256, key, &counter),
            Algorithm::Sha512 => hmac_of!(Sha512, key, &counter),
        };
        Ok(Secret::from_string(truncate(&mac, self.params.digits)))
    }

    /// The code for right now.
    ///
    /// # Errors
    ///
    /// As [`Totp::code_at`].
    pub fn code_now(&self) -> Result<Secret> {
        self.code_at(crate::unix_now())
    }

    /// Render as an `otpauth://` URI.
    ///
    /// The result contains the seed, so it is a [`Secret`] — the URI *is* the credential, which is
    /// exactly why a screenshotted QR code is as dangerous as a written-down password.
    #[must_use]
    pub fn to_uri(&self) -> Secret {
        let label = match (&self.params.issuer, &self.params.account) {
            (Some(issuer), Some(account)) => {
                format!("{}:{}", percent_encode(issuer), percent_encode(account))
            }
            (Some(issuer), None) => percent_encode(issuer),
            (None, Some(account)) => percent_encode(account),
            (None, None) => "kagisecure".to_owned(),
        };
        let mut uri = format!(
            "otpauth://totp/{label}?secret={}",
            base32_encode(self.secret.expose())
        );
        if let Some(issuer) = &self.params.issuer {
            uri.push_str(&format!("&issuer={}", percent_encode(issuer)));
        }
        uri.push_str(&format!(
            "&algorithm={}&digits={}&period={}",
            self.params.algorithm, self.params.digits, self.params.period
        ));
        Secret::from_string(uri)
    }

    /// Parse an `otpauth://totp/...` URI.
    ///
    /// Tolerant in the ways real services need: the `otpauth` scheme is matched case-
    /// insensitively, the label may or may not carry an `Issuer:` prefix, a separate `issuer=`
    /// parameter wins over the label prefix when both are present (as the Key Uri Format
    /// specifies), unknown parameters are ignored, and the secret goes through the same forgiving
    /// [`base32_decode`] a hand-typed seed does.
    ///
    /// # Errors
    ///
    /// [`Error::Totp`] if the scheme is not `otpauth`, the type is not `totp`, there is no
    /// `secret` parameter, or any parameter is out of range. The message never quotes the URI:
    /// the URI contains the seed.
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let rest = uri
            .get(..10)
            .filter(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
            .and_then(|_| uri.get(10..))
            .ok_or(Error::Totp("not an otpauth:// URI"))?;

        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, query),
            None => (rest, ""),
        };
        let (kind, label) = match path.split_once('/') {
            Some((kind, label)) => (kind, label),
            None => (path, ""),
        };
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::Totp(
                "only otpauth://totp/ URIs are supported; counter-based HOTP is not",
            ));
        }

        let mut secret_b32: Option<String> = None;
        let mut params = TotpParams::default();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret_b32 = Some(value),
                "issuer" => params.issuer = non_empty(value),
                "algorithm" => params.algorithm = value.parse()?,
                "digits" => {
                    params.digits = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::Totp("digits must be a number"))?;
                }
                "period" => {
                    params.period = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::Totp("period must be a number of seconds"))?;
                }
                _ => {}
            }
        }

        // The label is `Issuer:Account`, `Issuer%3AAccount`, or just `Account`.
        let label = percent_decode(label.trim_start_matches('/'));
        match label.split_once(':') {
            Some((issuer, account)) => {
                if params.issuer.is_none() {
                    params.issuer = non_empty(issuer.trim().to_owned());
                }
                params.account = non_empty(account.trim().to_owned());
            }
            None => params.account = non_empty(label.trim().to_owned()),
        }

        let secret = secret_b32.ok_or(Error::Totp("the URI has no secret= parameter"))?;
        Self::from_base32(&secret, params)
    }
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// RFC 4226 §5.3 dynamic truncation, rendered as `digits` zero-padded decimal digits.
fn truncate(mac: &[u8], digits: u8) -> String {
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let binary = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let modulus = 10u32.pow(u32::from(digits));
    format!("{:0width$}", binary % modulus, width = usize::from(digits))
}

// -------------------------------------------------------------------------------------------
// Base32 (RFC 4648, no padding required)
// -------------------------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode a Base32 seed.
///
/// Tolerant on purpose, because this is the one field a user retypes by hand from a web page:
/// case is ignored, `=` padding is optional, and every kind of whitespace (including the spaces
/// services insert every four characters) and `-` separators are skipped.
///
/// # Errors
///
/// [`Error::Totp`] for a character outside the alphabet or a length that cannot be a whole number
/// of bytes. The message never contains the input.
pub fn base32_decode(input: &str) -> Result<Vec<u8>> {
    let mut bits = 0u32;
    let mut width = 0u32;
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);

    for byte in input.bytes() {
        if byte.is_ascii_whitespace() || byte == b'-' || byte == b'=' {
            continue;
        }
        let upper = byte.to_ascii_uppercase();
        let value = BASE32_ALPHABET
            .iter()
            .position(|c| *c == upper)
            .ok_or(Error::Totp(
                "the secret is not Base32 (letters A–Z and digits 2–7 only)",
            ))?;
        bits = (bits << 5) | value as u32;
        width += 5;
        if width >= 8 {
            width -= 8;
            out.push(u8::try_from((bits >> width) & 0xff).unwrap_or(0));
        }
    }

    if out.is_empty() {
        return Err(Error::Totp("the secret is empty"));
    }
    // Left-over bits must be zero padding, not a truncated byte.
    if width > 0 && (bits & ((1 << width) - 1)) != 0 {
        return Err(Error::Totp("the secret is truncated"));
    }
    Ok(out)
}

/// Encode bytes as un-padded upper-case Base32.
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut bits = 0u32;
    let mut width = 0u32;
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    for byte in bytes {
        bits = (bits << 8) | u32::from(*byte);
        width += 8;
        while width >= 5 {
            width -= 5;
            out.push(char::from(
                BASE32_ALPHABET[((bits >> width) & 0x1f) as usize],
            ));
        }
    }
    if width > 0 {
        out.push(char::from(
            BASE32_ALPHABET[((bits << (5 - width)) & 0x1f) as usize],
        ));
    }
    out
}

// -------------------------------------------------------------------------------------------
// Percent-encoding, for URI labels
// -------------------------------------------------------------------------------------------

/// Percent-encode everything that is not unreserved, so a label containing `:`, `/`, `?`, `&` or
/// a space round-trips.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decode percent escapes, and `+` as a space. Invalid escapes are left verbatim rather than
/// rejected: a label is metadata, and refusing to import a whole seed over a stray `%` would be
/// the wrong trade.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(totp: &Totp, at: u64) -> String {
        totp.code_at(at)
            .unwrap()
            .expose_str()
            .expect("digits are ASCII")
            .to_owned()
    }

    /// RFC 6238 Appendix B.
    ///
    /// The RFC's seed is the ASCII string `12345678901234567890`, extended by repetition to the
    /// hash's block size for SHA-256 and SHA-512 — an "extension" the RFC's own reference
    /// implementation performs and its table depends on. All three columns of the published table
    /// are checked, which is what the roadmap's first M5 acceptance criterion asks for.
    #[test]
    fn rfc6238_appendix_b_vectors() {
        let sha1 = b"12345678901234567890".to_vec();
        let sha256 = b"12345678901234567890123456789012".to_vec();
        let sha512 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();

        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];

        for (time, expect_sha1, expect_sha256, expect_sha512) in cases {
            for (seed, algorithm, expected) in [
                (&sha1, Algorithm::Sha1, expect_sha1),
                (&sha256, Algorithm::Sha256, expect_sha256),
                (&sha512, Algorithm::Sha512, expect_sha512),
            ] {
                let totp = Totp::new(
                    Secret::new(seed.clone()),
                    TotpParams {
                        algorithm,
                        digits: 8,
                        period: 30,
                        ..TotpParams::default()
                    },
                )
                .unwrap();
                assert_eq!(code(&totp, time), expected, "{algorithm} at T={time}");
            }
        }
    }

    #[test]
    fn six_and_seven_digit_codes_are_the_low_digits_of_the_eight_digit_one() {
        let seed = Secret::new(b"12345678901234567890".to_vec());
        let eight = Totp::new(
            Secret::new(b"12345678901234567890".to_vec()),
            TotpParams {
                digits: 8,
                ..TotpParams::default()
            },
        )
        .unwrap();
        for digits in [6u8, 7] {
            let totp = Totp::new(
                Secret::new(seed.expose().to_vec()),
                TotpParams {
                    digits,
                    ..TotpParams::default()
                },
            )
            .unwrap();
            let short = code(&totp, 59);
            assert_eq!(short.len(), usize::from(digits));
            assert_eq!(short, code(&eight, 59)[8 - usize::from(digits)..]);
        }
    }

    #[test]
    fn the_code_changes_exactly_at_a_period_boundary() {
        let totp = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpParams::default()).unwrap();
        // 1_700_000_000 % 30 == 20, so the window containing it runs
        // 1_699_999_980..=1_700_000_009 and the next one starts at 1_700_000_010.
        assert_eq!(code(&totp, 1_699_999_980), code(&totp, 1_700_000_009));
        assert_ne!(code(&totp, 1_700_000_009), code(&totp, 1_700_000_010));
        assert_eq!(totp.seconds_remaining(1_699_999_980), 30);
        assert_eq!(totp.seconds_remaining(1_700_000_009), 1);
        assert_eq!(totp.seconds_remaining(1_700_000_010), 30);
    }

    #[test]
    fn seconds_remaining_is_never_zero_and_never_over_the_period() {
        for period in [15u32, 30, 60, 90] {
            let totp = Totp::from_base32(
                "JBSWY3DPEHPK3PXP",
                TotpParams {
                    period,
                    ..TotpParams::default()
                },
            )
            .unwrap();
            for offset in 0..200u64 {
                let left = totp.seconds_remaining(1_700_000_000 + offset);
                assert!((1..=period).contains(&left), "{period}/{offset}: {left}");
            }
        }
    }

    #[test]
    fn otpauth_round_trips() {
        let original = "otpauth://totp/ACME%20Co:ada%40example.com\
             ?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=45";
        let parsed = Totp::parse_uri(original).unwrap();
        assert_eq!(parsed.params().issuer.as_deref(), Some("ACME Co"));
        assert_eq!(parsed.params().account.as_deref(), Some("ada@example.com"));
        assert_eq!(parsed.params().algorithm, Algorithm::Sha256);
        assert_eq!(parsed.params().digits, 8);
        assert_eq!(parsed.params().period, 45);

        let rendered = parsed.to_uri();
        let again = Totp::parse_uri(rendered.expose_str().unwrap()).unwrap();
        assert_eq!(again.params(), parsed.params());
        assert_eq!(code(&again, 1_700_000_000), code(&parsed, 1_700_000_000));

        // …and a second round trip is byte-identical, so the format is a fixed point.
        assert_eq!(
            again.to_uri().expose_str().unwrap(),
            rendered.expose_str().unwrap()
        );
    }

    #[test]
    fn otpauth_defaults_fill_in_when_parameters_are_absent() {
        let parsed =
            Totp::parse_uri("otpauth://totp/ada@example.com?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(parsed.params().algorithm, Algorithm::Sha1);
        assert_eq!(parsed.params().digits, 6);
        assert_eq!(parsed.params().period, 30);
        assert_eq!(parsed.params().issuer, None);
        assert_eq!(parsed.params().account.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn a_separate_issuer_parameter_wins_over_the_label_prefix() {
        let parsed =
            Totp::parse_uri("otpauth://totp/Stale:ada?secret=JBSWY3DPEHPK3PXP&issuer=Fresh")
                .unwrap();
        assert_eq!(parsed.params().issuer.as_deref(), Some("Fresh"));
        assert_eq!(parsed.params().account.as_deref(), Some("ada"));
    }

    #[test]
    fn unknown_parameters_are_ignored_and_case_does_not_matter() {
        let parsed = Totp::parse_uri(
            "OTPAUTH://TOTP/ada?SECRET=jbswy3dpehpk3pxp&image=https://x/y.png&ALGORITHM=sha-1",
        )
        .unwrap();
        assert_eq!(parsed.params().algorithm, Algorithm::Sha1);
        assert_eq!(code(&parsed, 59).len(), 6);
    }

    #[test]
    fn bad_uris_are_refused_without_quoting_themselves() {
        for (uri, needle) in [
            ("https://example.com", "otpauth"),
            ("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=1", "HOTP"),
            ("otpauth://totp/a?issuer=x", "secret="),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=9",
                "digits",
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0",
                "period",
            ),
            (
                "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=md5",
                "SHA1",
            ),
            ("otpauth://totp/a?secret=1111!!!!", "Base32"),
        ] {
            let error = Totp::parse_uri(uri).expect_err(uri);
            let rendered = error.to_string();
            assert!(rendered.contains(needle), "{uri}: {rendered}");
            assert!(
                !rendered.contains("JBSWY3DPEHPK3PXP"),
                "the error quoted the seed: {rendered}"
            );
        }
    }

    #[test]
    fn base32_is_forgiving_about_case_padding_and_spacing() {
        let canonical = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        for variant in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSW-Y3DP-EHPK-3PXP",
            "JBSWY3DPEHPK3PXP======",
            " JBSWY3DPEHPK3PXP\n",
        ] {
            assert_eq!(base32_decode(variant).unwrap(), canonical, "{variant}");
        }
        assert_eq!(canonical, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn base32_round_trips_arbitrary_bytes() {
        for length in 1..40usize {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = base32_encode(&bytes);
            assert_eq!(base32_decode(&encoded).unwrap(), bytes, "{length} bytes");
        }
    }

    #[test]
    fn base32_refuses_junk() {
        assert!(base32_decode("").is_err());
        assert!(base32_decode("====").is_err());
        assert!(
            base32_decode("ABC0DEF").is_err(),
            "0 is not in the alphabet"
        );
        assert!(
            base32_decode("ABC1DEF").is_err(),
            "1 is not in the alphabet"
        );
    }

    #[test]
    fn an_empty_secret_is_refused() {
        assert!(Totp::new(Secret::new(Vec::new()), TotpParams::default()).is_err());
    }

    #[test]
    fn a_code_is_a_secret_and_debug_says_nothing() {
        let totp = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpParams::default()).unwrap();
        let code = totp.code_at(59).unwrap();
        assert_eq!(format!("{code:?}"), "Secret(<redacted>)");
        // …and neither does the generator's own Debug.
        assert!(!format!("{totp:?}").contains("Hello"));
    }

    #[test]
    fn the_caption_is_metadata_only() {
        let mut params = TotpParams::default();
        assert_eq!(params.caption(), None);
        params.issuer = Some("GitHub".to_owned());
        assert_eq!(params.caption().as_deref(), Some("GitHub"));
        params.account = Some("ada".to_owned());
        assert_eq!(params.caption().as_deref(), Some("GitHub · ada"));
    }
}

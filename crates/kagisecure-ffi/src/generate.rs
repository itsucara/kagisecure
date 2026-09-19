//! The generator and one-time-password surface (roadmap M5).
//!
//! Every function here is a pure translation of a `kagisecure_core` call: no state, no vault, no
//! clock of its own. The app passes the time it is rendering for, so the ring and the code in
//! ui-spec.md §4.2 cannot disagree about which window they are in.
//!
//! # The two new secret crossings
//!
//! [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) enumerates what may carry
//! plaintext across this boundary. M5 adds a fifth kind, and it points in both directions:
//!
//! * **out** — [`generate_password`] returns a freshly generated password, and
//!   [`totp_preview`] / `VaultSession::totp_code` return a one-time code. Both exist because the
//!   thing the user asked for *is* the value: a generator that could not show its output, or a
//!   TOTP field that could not show its code, would not be the feature.
//! * **in** — [`totp_preview`], [`totp_describe`] and [`totp_uri_from_parts`] take an
//!   `otpauth://` URI or a Base32 seed, which the user pasted or typed. This is the same shape as
//!   `FieldDraft.value` going in at save: one value, named by the caller.
//!
//! The granularity discipline from crossing 2 is kept. There is no call that returns codes for
//! several fields, no call that returns a code without an item and field id naming one, and the
//! returned strings are the whole of what the app gets — nothing here hands out a seed it was not
//! already given.
//!
//! # Zeroization, honestly
//!
//! The core holds these as `Secret` and wipes them on drop. Swift receives a `String`, which is
//! immutable, reference-counted and not zeroizable — the same limitation ADR-0008 records for a
//! revealed password, and it applies here in full. What the app *can* do, and does, is keep the
//! window short: a generated candidate lives only while the sheet is open, and a TOTP code is
//! recomputed each second rather than being cached.

use kagisecure_core::generator::{
    self, CharacterOptions, Recipe, Separator, StrengthLevel, WordOptions,
};
use kagisecure_core::totp::{Algorithm, Totp, TotpParams};

use crate::{FfiError, FfiResult};

/// Which of the generator's two modes a recipe is in (ui-spec.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum GeneratorMode {
    /// Random characters.
    Characters,
    /// Memorable words from the EFF list.
    Words,
}

/// What goes between the words of a memorable password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WordSeparator {
    /// `-`
    Hyphen,
    /// `_`
    Underscore,
    /// `.`
    Period,
    /// A space.
    Space,
    /// Nothing at all.
    None,
}

impl WordSeparator {
    fn to_core(self) -> Separator {
        match self {
            Self::Hyphen => Separator::Hyphen,
            Self::Underscore => Separator::Underscore,
            Self::Period => Separator::Period,
            Self::Space => Separator::Space,
            Self::None => Separator::None,
        }
    }
}

/// Every knob the generator sheet has, in one flat record.
///
/// Flat rather than an enum with two payloads because it is bound straight to a SwiftUI form:
/// the sheet keeps one value of this type in `@State`, the mode switch flips `mode`, and the
/// controls a mode does not use simply stay put instead of being reconstructed. The core's own
/// `Recipe` is the two-armed enum; the conversion is `GeneratorRecipe::to_core`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GeneratorRecipe {
    /// Which mode the sheet is in.
    pub mode: GeneratorMode,
    /// Characters mode: how many characters (8–128, clamped).
    pub length: u32,
    /// Characters mode: include `a`–`z`.
    pub lowercase: bool,
    /// Characters mode: include `A`–`Z`.
    pub uppercase: bool,
    /// Characters mode: include `0`–`9`.
    pub digits: bool,
    /// Characters mode: include symbols.
    pub symbols: bool,
    /// Characters mode: leave out `0`, `O`, `1`, `l` and `I`.
    pub avoid_ambiguous: bool,
    /// Words mode: how many words (3–10, clamped).
    pub words: u32,
    /// Words mode: what separates them.
    pub separator: WordSeparator,
    /// Words mode: capitalize each word.
    pub capitalize: bool,
    /// Words mode: append one random digit.
    pub include_digit: bool,
}

impl Default for GeneratorRecipe {
    fn default() -> Self {
        let characters = CharacterOptions::default();
        let words = WordOptions::default();
        Self {
            mode: GeneratorMode::Characters,
            length: characters.length,
            lowercase: characters.lowercase,
            uppercase: characters.uppercase,
            digits: characters.digits,
            symbols: characters.symbols,
            avoid_ambiguous: characters.avoid_ambiguous,
            words: words.words,
            separator: WordSeparator::Hyphen,
            capitalize: words.capitalize,
            include_digit: words.include_digit,
        }
    }
}

impl GeneratorRecipe {
    fn to_core(self) -> Recipe {
        match self.mode {
            GeneratorMode::Characters => Recipe::Characters(CharacterOptions {
                length: self.length,
                lowercase: self.lowercase,
                uppercase: self.uppercase,
                digits: self.digits,
                symbols: self.symbols,
                avoid_ambiguous: self.avoid_ambiguous,
            }),
            GeneratorMode::Words => Recipe::Words(WordOptions {
                words: self.words,
                separator: self.separator.to_core(),
                capitalize: self.capitalize,
                include_digit: self.include_digit,
            }),
        }
    }
}

/// The five buckets a strength meter labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StrengthBucket {
    /// Under 28 bits.
    VeryWeak,
    /// 28–39 bits.
    Weak,
    /// 40–59 bits.
    Fair,
    /// 60–79 bits.
    Good,
    /// 80 bits and up.
    Excellent,
}

/// What the meter under the generator's field shows.
#[derive(Clone, Debug, uniffi::Record)]
pub struct StrengthView {
    /// Estimated entropy in bits.
    pub bits: f64,
    /// The bucket.
    pub bucket: StrengthBucket,
    /// The label for that bucket, from the core so the CLI and the app agree on wording.
    pub label: String,
    /// How full a 0–1 bar should be.
    pub fraction: f64,
}

impl StrengthView {
    fn from_core(strength: generator::Strength) -> Self {
        Self {
            bits: strength.bits,
            bucket: match strength.level {
                StrengthLevel::VeryWeak => StrengthBucket::VeryWeak,
                StrengthLevel::Weak => StrengthBucket::Weak,
                StrengthLevel::Fair => StrengthBucket::Fair,
                StrengthLevel::Good => StrengthBucket::Good,
                StrengthLevel::Excellent => StrengthBucket::Excellent,
            },
            label: strength.level.label().to_owned(),
            fraction: StrengthLevel::fraction(strength.bits),
        }
    }
}

/// The bounds the sliders must not exceed, from the core rather than hardcoded in Swift.
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct GeneratorLimits {
    /// Shortest character-mode password.
    pub min_length: u32,
    /// Longest character-mode password.
    pub max_length: u32,
    /// Fewest words.
    pub min_words: u32,
    /// Most words.
    pub max_words: u32,
    /// How many words the embedded list holds — shown in the sheet's footnote, and the number the
    /// per-word entropy is the logarithm of.
    pub wordlist_size: u32,
}

/// The slider bounds and the wordlist size.
#[uniffi::export]
#[must_use]
pub fn generator_limits() -> GeneratorLimits {
    GeneratorLimits {
        min_length: generator::MIN_LENGTH,
        max_length: generator::MAX_LENGTH,
        min_words: generator::MIN_WORDS,
        max_words: generator::MAX_WORDS,
        wordlist_size: u32::try_from(generator::WORDLIST_LEN).unwrap_or(u32::MAX),
    }
}

/// Generate one password (ui-spec.md §8).
///
/// ADR-0008 crossing 5, outbound. Every call draws fresh randomness from `OsRng`; nothing is
/// cached, so "Regenerate" is this function again and the sheet's history list is Swift-side
/// state that dies with the sheet.
///
/// # Errors
///
/// [`FfiError::Invalid`] if the recipe turns every character class off, or if the operating
/// system generator fails.
#[uniffi::export]
pub fn generate_password(recipe: GeneratorRecipe) -> FfiResult<String> {
    let secret = recipe.to_core().generate()?;
    secret
        .expose_str()
        .map(str::to_owned)
        .ok_or_else(|| FfiError::invalid("the generator produced non-text output"))
}

/// The strength of what `recipe` will produce.
///
/// A property of the settings, so the meter moves monotonically as the user drags the slider
/// rather than jittering with each candidate.
#[uniffi::export]
#[must_use]
pub fn recipe_strength(recipe: GeneratorRecipe) -> StrengthView {
    StrengthView::from_core(recipe.to_core().strength())
}

/// The strength of a password that already exists — one the user typed, or one being replaced.
#[uniffi::export]
#[must_use]
pub fn password_strength(password: String) -> StrengthView {
    StrengthView::from_core(generator::estimate(&password))
}

// -------------------------------------------------------------------------------------------
// One-time passwords
// -------------------------------------------------------------------------------------------

/// Which HMAC a TOTP field uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the default and near-universal choice.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    fn to_core(self) -> Algorithm {
        match self {
            Self::Sha1 => Algorithm::Sha1,
            Self::Sha256 => Algorithm::Sha256,
            Self::Sha512 => Algorithm::Sha512,
        }
    }

    fn from_core(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha1 => Self::Sha1,
            Algorithm::Sha256 => Self::Sha256,
            Algorithm::Sha512 => Self::Sha512,
        }
    }
}

/// A TOTP field's parameters. Metadata: no seed, no code.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TotpParamsView {
    /// Which HMAC.
    pub algorithm: TotpAlgorithm,
    /// 6, 7 or 8.
    pub digits: u8,
    /// Seconds per code.
    pub period: u32,
    /// The service, if the URI named one.
    pub issuer: Option<String>,
    /// The account at that service, if the URI named one.
    pub account: Option<String>,
    /// `"GitHub · ada@example.com"`, for the line under the code.
    pub caption: Option<String>,
}

impl TotpParamsView {
    fn from_core(params: &TotpParams) -> Self {
        Self {
            algorithm: TotpAlgorithm::from_core(params.algorithm),
            digits: params.digits,
            period: params.period,
            issuer: params.issuer.clone(),
            account: params.account.clone(),
            caption: params.caption(),
        }
    }

    fn to_core(&self) -> TotpParams {
        TotpParams {
            algorithm: self.algorithm.to_core(),
            digits: self.digits,
            period: self.period,
            issuer: self.issuer.clone(),
            account: self.account.clone(),
        }
    }
}

/// A live code and everything the ring needs to draw itself.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TotpCodeView {
    /// The code. ADR-0008 crossing 5, outbound.
    pub code: String,
    /// Seconds left in this code's window, in `1..=period`.
    pub seconds_remaining: u32,
    /// The field's parameters, so a caller that has the code does not need a second call to draw
    /// the ring or the caption.
    pub params: TotpParamsView,
}

impl TotpCodeView {
    pub(crate) fn build(totp: &Totp, at: u64) -> FfiResult<Self> {
        let code = totp.code_at(at)?;
        Ok(Self {
            code: code
                .expose_str()
                .map(str::to_owned)
                .ok_or_else(|| FfiError::invalid("the code is not text"))?,
            seconds_remaining: totp.seconds_remaining(at),
            params: TotpParamsView::from_core(totp.params()),
        })
    }
}

/// Parse an `otpauth://` URI and report its parameters, without producing a code.
///
/// The setup sheet's validation step (ui-spec.md §9): it says whether the pasted URI is usable
/// and what service it is for, before anything is stored.
///
/// # Errors
///
/// [`FfiError::Invalid`] with a message that never quotes the URI — the URI carries the seed.
#[uniffi::export]
pub fn totp_describe(uri: String) -> FfiResult<TotpParamsView> {
    Ok(TotpParamsView::from_core(Totp::parse_uri(&uri)?.params()))
}

/// The code a not-yet-saved setup would produce, for the live preview in ui-spec.md §9.
///
/// `at` is the Unix time to render for; the caller passes its own clock so that the preview and
/// the ring around it are drawn from one instant.
///
/// # Errors
///
/// As [`totp_describe`].
#[uniffi::export]
pub fn totp_preview(uri: String, at: u64) -> FfiResult<TotpCodeView> {
    TotpCodeView::build(&Totp::parse_uri(&uri)?, at)
}

/// Build an `otpauth://` URI from a hand-typed Base32 seed and parameters (ui-spec.md §9's
/// manual-entry path).
///
/// The returned URI is what gets stored in the field, so it is secret material going *out* of
/// this call and straight back *in* at `save_item`. It exists because assembling a URI in Swift
/// would mean a second implementation of the escaping rules, and the one that already exists is
/// the one the parser round-trips against.
///
/// # Errors
///
/// [`FfiError::Invalid`] if the seed is not Base32 or the parameters are out of range.
#[uniffi::export]
pub fn totp_uri_from_parts(secret_base32: String, params: TotpParamsView) -> FfiResult<String> {
    let totp = Totp::from_base32(&secret_base32, params.to_core())?;
    totp.to_uri()
        .expose_str()
        .map(str::to_owned)
        .ok_or_else(|| FfiError::invalid("the URI is not text"))
}

/// Whether a string is a usable `otpauth://` URI. For enabling a "Save" button without throwing.
#[uniffi::export]
#[must_use]
pub fn totp_uri_is_valid(uri: String) -> bool {
    Totp::parse_uri(&uri).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/ACME:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME";

    #[test]
    fn the_default_recipe_produces_an_excellent_password() {
        let recipe = GeneratorRecipe::default();
        let password = generate_password(recipe).unwrap();
        assert_eq!(password.chars().count(), 20);
        assert_eq!(recipe_strength(recipe).bucket, StrengthBucket::Excellent);
        assert!(recipe_strength(recipe).bits > 120.0);
        assert_eq!(recipe_strength(recipe).label, "Excellent");
    }

    #[test]
    fn word_mode_uses_the_word_knobs_and_ignores_the_character_ones() {
        let recipe = GeneratorRecipe {
            mode: GeneratorMode::Words,
            length: 128,
            words: 5,
            separator: WordSeparator::Underscore,
            ..GeneratorRecipe::default()
        };
        let password = generate_password(recipe).unwrap();
        assert_eq!(password.split('_').count(), 5, "{password}");
        assert!(password.len() < 128, "{password}");
    }

    #[test]
    fn an_empty_alphabet_is_an_error_the_app_can_show() {
        let recipe = GeneratorRecipe {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..GeneratorRecipe::default()
        };
        assert!(matches!(
            generate_password(recipe),
            Err(FfiError::Invalid { .. })
        ));
    }

    #[test]
    fn the_meter_moves_monotonically_with_the_slider() {
        let limits = generator_limits();
        let mut previous = 0.0;
        for length in limits.min_length..=limits.max_length {
            let bits = recipe_strength(GeneratorRecipe {
                length,
                ..GeneratorRecipe::default()
            })
            .bits;
            assert!(bits > previous, "{length}");
            previous = bits;
        }
        assert_eq!(limits.wordlist_size, 7776);
    }

    #[test]
    fn an_existing_password_is_estimated_rather_than_assumed() {
        assert_eq!(
            password_strength("password".to_owned()).bucket,
            StrengthBucket::VeryWeak
        );
        assert_eq!(
            password_strength(generate_password(GeneratorRecipe::default()).unwrap()).bucket,
            StrengthBucket::Excellent
        );
    }

    #[test]
    fn a_uri_describes_itself_without_producing_a_code() {
        let params = totp_describe(URI.to_owned()).unwrap();
        assert_eq!(params.issuer.as_deref(), Some("ACME"));
        assert_eq!(params.account.as_deref(), Some("ada@example.com"));
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        assert_eq!(params.caption.as_deref(), Some("ACME · ada@example.com"));
        assert!(totp_uri_is_valid(URI.to_owned()));
        assert!(!totp_uri_is_valid("otpauth://totp/x".to_owned()));
    }

    #[test]
    fn a_preview_is_stable_within_a_window_and_changes_at_the_boundary() {
        let a = totp_preview(URI.to_owned(), 1_699_999_980).unwrap();
        let b = totp_preview(URI.to_owned(), 1_700_000_009).unwrap();
        let c = totp_preview(URI.to_owned(), 1_700_000_010).unwrap();
        assert_eq!(a.code, b.code);
        assert_ne!(b.code, c.code);
        assert_eq!(a.seconds_remaining, 30);
        assert_eq!(b.seconds_remaining, 1);
        assert_eq!(c.seconds_remaining, 30);
        assert_eq!(a.code.len(), 6);
    }

    #[test]
    fn manual_entry_round_trips_through_a_uri() {
        let params = TotpParamsView {
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period: 60,
            issuer: Some("Bank of Test".to_owned()),
            account: Some("ada".to_owned()),
            caption: None,
        };
        let uri = totp_uri_from_parts("jbsw y3dp ehpk 3pxp".to_owned(), params.clone()).unwrap();
        let described = totp_describe(uri.clone()).unwrap();
        assert_eq!(described.algorithm, TotpAlgorithm::Sha512);
        assert_eq!(described.digits, 8);
        assert_eq!(described.period, 60);
        assert_eq!(described.issuer.as_deref(), Some("Bank of Test"));
        assert_eq!(described.account.as_deref(), Some("ada"));
        assert_eq!(totp_preview(uri, 59).unwrap().code.len(), 8);
    }

    #[test]
    fn a_bad_uri_is_refused_without_echoing_itself() {
        let error = totp_describe("otpauth://totp/x?secret=!!!!".to_owned()).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("Base32"), "{rendered}");
        assert!(!rendered.contains("otpauth"), "{rendered}");
        assert!(totp_preview("nonsense".to_owned(), 0).is_err());
        assert!(
            totp_uri_from_parts(
                "!!!!".to_owned(),
                TotpParamsView {
                    algorithm: TotpAlgorithm::Sha1,
                    digits: 6,
                    period: 30,
                    issuer: None,
                    account: None,
                    caption: None,
                }
            )
            .is_err()
        );
    }
}

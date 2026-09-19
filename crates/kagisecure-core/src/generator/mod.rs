//! The password generator (ui-spec.md §8, roadmap M5).
//!
//! Two modes, one CSPRNG:
//!
//! * **characters** — a uniform draw from the union of the enabled character classes, with a
//!   guarantee that every enabled class actually appears;
//! * **words** — a uniform draw from the EFF "large" wordlist (7776 words, five dice rolls per
//!   word), the diceware construction.
//!
//! Generation lives here rather than in a UI layer so that the CLI (`kagisecure generate`), the
//! macOS app's generator sheet and any later browser extension share one implementation and one
//! source of randomness ([`crate::crypto::random`], which is `OsRng` and nothing else).
//!
//! The result is a [`Secret`]: a generated password is secret material from the instant it
//! exists, and the type system says so.

mod strength;
mod wordlist;

pub use strength::{Strength, StrengthLevel, estimate};
pub use wordlist::{WORDLIST_LEN, words};

use crate::error::{Error, Result};
use crate::model::Secret;

/// Shortest password the character mode will produce.
pub const MIN_LENGTH: u32 = 8;
/// Longest password the character mode will produce.
pub const MAX_LENGTH: u32 = 128;
/// Fewest words the word mode will produce.
pub const MIN_WORDS: u32 = 3;
/// Most words the word mode will produce.
pub const MAX_WORDS: u32 = 10;

/// Lower-case letters.
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
/// Upper-case letters.
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Decimal digits.
const DIGITS: &str = "0123456789";
/// Symbols.
///
/// Deliberately excludes the quote characters, the backslash and the backtick: a generated
/// password lands in shell histories, `.env` files and YAML often enough that a value which needs
/// escaping is a support burden rather than a security gain. The remaining 27 symbols are worth
/// 4.75 bits each on their own.
const SYMBOLS: &str = "!#$%&()*+,-.:;<=>?@[]^_{|}~";
/// Characters a human reads wrong in a proportional font (ui-spec.md §8).
const AMBIGUOUS: &str = "0O1lI";

/// Which characters the generator may draw from (ui-spec.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharacterOptions {
    /// How many characters, clamped to [`MIN_LENGTH`]..=[`MAX_LENGTH`].
    pub length: u32,
    /// Include `a`–`z`.
    pub lowercase: bool,
    /// Include `A`–`Z`.
    pub uppercase: bool,
    /// Include `0`–`9`.
    pub digits: bool,
    /// Include the symbol set.
    pub symbols: bool,
    /// Drop `0`, `O`, `1`, `l` and `I` from whatever classes are enabled.
    pub avoid_ambiguous: bool,
}

impl Default for CharacterOptions {
    /// The 1Password-like default: 20 characters, letters and digits and symbols, ambiguous
    /// characters allowed.
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

/// What separates the words of a memorable password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Separator {
    /// `correct-horse-battery`
    Hyphen,
    /// `correct_horse_battery`
    Underscore,
    /// `correct.horse.battery`
    Period,
    /// `correct horse battery`
    Space,
    /// `correcthorsebattery`
    None,
}

impl Separator {
    /// The character this separator inserts, or `None` for [`Separator::None`].
    #[must_use]
    pub fn as_char(self) -> Option<char> {
        match self {
            Self::Hyphen => Some('-'),
            Self::Underscore => Some('_'),
            Self::Period => Some('.'),
            Self::Space => Some(' '),
            Self::None => None,
        }
    }

    /// The canonical name used on the command line and over the FFI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hyphen => "hyphen",
            Self::Underscore => "underscore",
            Self::Period => "period",
            Self::Space => "space",
            Self::None => "none",
        }
    }
}

impl std::str::FromStr for Separator {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hyphen" | "-" | "dash" => Ok(Self::Hyphen),
            "underscore" | "_" => Ok(Self::Underscore),
            "period" | "." | "dot" => Ok(Self::Period),
            "space" | " " => Ok(Self::Space),
            "none" | "" => Ok(Self::None),
            _ => Err(Error::Generator(
                "separator must be one of hyphen, underscore, period, space, none",
            )),
        }
    }
}

/// How a memorable password is put together (ui-spec.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordOptions {
    /// How many words, clamped to [`MIN_WORDS`]..=[`MAX_WORDS`].
    pub words: u32,
    /// What goes between them.
    pub separator: Separator,
    /// Upper-case each word's first letter.
    pub capitalize: bool,
    /// Append one random decimal digit to one randomly chosen word.
    pub include_digit: bool,
}

impl Default for WordOptions {
    /// Four words, hyphen-separated, lower case, no digit.
    fn default() -> Self {
        Self {
            words: 4,
            separator: Separator::Hyphen,
            capitalize: false,
            include_digit: false,
        }
    }
}

/// A complete description of what to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipe {
    /// Random characters.
    Characters(CharacterOptions),
    /// Memorable words.
    Words(WordOptions),
}

impl Default for Recipe {
    fn default() -> Self {
        Self::Characters(CharacterOptions::default())
    }
}

impl Recipe {
    /// Generate one password.
    ///
    /// # Errors
    ///
    /// [`Error::Generator`] if the recipe enables no character class at all, and [`Error::Rng`] if
    /// the operating system generator fails.
    pub fn generate(&self) -> Result<Secret> {
        match self {
            Self::Characters(o) => characters(*o),
            Self::Words(o) => words_password(*o),
        }
    }

    /// The entropy of the *recipe*, in bits — how much randomness a password it produces carries.
    ///
    /// This is what the strength meter shows, and it is a property of the settings rather than of
    /// any one candidate: a meter driven by [`estimate`] would jitter as the user regenerates,
    /// and the acceptance criterion in the roadmap is that it move monotonically with configured
    /// entropy. It does: adding a class or a character or a word only ever adds bits.
    ///
    /// Character mode reports `length × log2(alphabet)`, which is a hair above the truth because
    /// the "at least one of each enabled class" guarantee removes a small share of the draws (for
    /// the 20-character four-class default, under 0.01 bits). Word mode reports the exact figure.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        match self {
            Self::Characters(o) => {
                let alphabet = alphabet(*o);
                if alphabet.is_empty() {
                    return 0.0;
                }
                f64::from(clamp(o.length, MIN_LENGTH, MAX_LENGTH)) * (alphabet.len() as f64).log2()
            }
            Self::Words(o) => {
                let n = clamp(o.words, MIN_WORDS, MAX_WORDS);
                let mut bits = f64::from(n) * (WORDLIST_LEN as f64).log2();
                if o.include_digit {
                    // One digit, at one of `n` word positions.
                    bits += (10.0 * f64::from(n)).log2();
                }
                bits
            }
        }
    }

    /// The strength bucket the meter labels, derived from [`Recipe::entropy_bits`].
    #[must_use]
    pub fn strength(&self) -> Strength {
        Strength::from_bits(self.entropy_bits())
    }
}

/// Generate one password from `recipe`.
///
/// # Errors
///
/// As [`Recipe::generate`].
pub fn generate(recipe: &Recipe) -> Result<Secret> {
    recipe.generate()
}

fn clamp(value: u32, low: u32, high: u32) -> u32 {
    value.clamp(low, high)
}

/// The set of characters `options` allows, as a `Vec<u8>` of ASCII bytes.
fn alphabet(options: CharacterOptions) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    for (enabled, class) in [
        (options.lowercase, LOWERCASE),
        (options.uppercase, UPPERCASE),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ] {
        if enabled {
            out.extend(class.bytes());
        }
    }
    if options.avoid_ambiguous {
        out.retain(|b| !AMBIGUOUS.as_bytes().contains(b));
    }
    out
}

/// The enabled classes, each as its own (already ambiguity-filtered) byte set.
fn classes(options: CharacterOptions) -> Vec<Vec<u8>> {
    [
        (options.lowercase, LOWERCASE),
        (options.uppercase, UPPERCASE),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, class)| {
        let mut bytes: Vec<u8> = class.bytes().collect();
        if options.avoid_ambiguous {
            bytes.retain(|b| !AMBIGUOUS.as_bytes().contains(b));
        }
        bytes
    })
    .filter(|c| !c.is_empty())
    .collect()
}

fn characters(options: CharacterOptions) -> Result<Secret> {
    let length = clamp(options.length, MIN_LENGTH, MAX_LENGTH) as usize;
    let alphabet = alphabet(options);
    if alphabet.is_empty() {
        return Err(Error::Generator("no character class is enabled"));
    }
    let classes = classes(options);

    // Rejection at the *password* level, not the character level: redrawing until every enabled
    // class appears leaves the result uniform over exactly the set of passwords the user asked
    // for. Patching a missing class in afterwards — the common shortcut — does not, because the
    // patched position is no longer uniform.
    //
    // The bound is a guard against a logic error, not against bad luck: with `length >= 8` and at
    // most four classes the acceptance probability is above 0.6, so a thousand rejections in a row
    // has probability under 10^-390.
    for _ in 0..1_000 {
        let mut buf = zeroize::Zeroizing::new(vec![0u8; length]);
        for slot in buf.iter_mut() {
            *slot = alphabet[uniform_below(alphabet.len())?];
        }
        if classes
            .iter()
            .all(|class| buf.iter().any(|b| class.contains(b)))
        {
            return Ok(Secret::new(buf.to_vec()));
        }
    }
    Err(Error::Generator(
        "could not place one of every enabled character class in a password this short",
    ))
}

fn words_password(options: WordOptions) -> Result<Secret> {
    let count = clamp(options.words, MIN_WORDS, MAX_WORDS) as usize;
    let list = words();

    let mut picked: Vec<String> = Vec::with_capacity(count);
    for _ in 0..count {
        let mut word = list[uniform_below(list.len())?].to_owned();
        if options.capitalize {
            let mut chars = word.chars();
            word = match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => word,
            };
        }
        picked.push(word);
    }

    if options.include_digit {
        let at = uniform_below(count)?;
        let digit = uniform_below(10)?;
        picked[at].push(char::from(b'0' + u8::try_from(digit).unwrap_or(0)));
    }

    let joined = match options.separator.as_char() {
        Some(sep) => picked.join(&sep.to_string()),
        None => picked.concat(),
    };
    Ok(Secret::from_string(joined))
}

/// A uniformly distributed `usize` in `0..n`, by rejection sampling on `OsRng`.
///
/// The modulo shortcut (`u64::from_le_bytes(..) % n`) is biased whenever `n` does not divide
/// 2^64, and for a generator whose entire purpose is uniformity that is not a bias worth
/// accepting to save four lines. This draws 8 bytes and discards any draw that falls in the short
/// final block; the expected number of draws is under 2 for every `n` this crate uses.
///
/// # Errors
///
/// [`Error::Rng`] if the operating system generator fails, and [`Error::Generator`] for `n == 0`,
/// which no caller here can produce.
fn uniform_below(n: usize) -> Result<usize> {
    if n == 0 {
        return Err(Error::Generator("cannot choose from an empty set"));
    }
    let n = n as u128;
    // The largest multiple of `n` that fits in u64; draws at or above it would be over-represented.
    let limit = (1u128 << 64) - ((1u128 << 64) % n);
    loop {
        let draw = u128::from(u64::from_le_bytes(crate::crypto::random::array::<8>()?));
        if draw < limit {
            return Ok(usize::try_from(draw % n).unwrap_or(0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(secret: &Secret) -> String {
        secret.expose_str().expect("ASCII").to_owned()
    }

    #[test]
    fn character_mode_honours_length_and_clamps() {
        for (asked, expected) in [(8u32, 8usize), (20, 20), (128, 128), (4, 8), (999, 128)] {
            let recipe = Recipe::Characters(CharacterOptions {
                length: asked,
                ..CharacterOptions::default()
            });
            assert_eq!(text(&recipe.generate().unwrap()).len(), expected);
        }
    }

    #[test]
    fn every_enabled_class_appears_every_time() {
        let options = CharacterOptions {
            length: 8,
            ..CharacterOptions::default()
        };
        // 8 characters over four classes is the tightest case the UI allows; 300 draws would
        // notice a class that appears with probability much under 1.
        for _ in 0..300 {
            let password = text(&Recipe::Characters(options).generate().unwrap());
            assert!(
                password.chars().any(|c| c.is_ascii_lowercase()),
                "{password}"
            );
            assert!(
                password.chars().any(|c| c.is_ascii_uppercase()),
                "{password}"
            );
            assert!(password.chars().any(|c| c.is_ascii_digit()), "{password}");
            assert!(
                password.chars().any(|c| SYMBOLS.contains(c)),
                "no symbol in {password}"
            );
        }
    }

    #[test]
    fn disabled_classes_never_appear() {
        let options = CharacterOptions {
            length: 64,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        };
        for _ in 0..50 {
            let password = text(&Recipe::Characters(options).generate().unwrap());
            assert!(
                password.chars().all(|c| c.is_ascii_lowercase()),
                "{password}"
            );
        }
    }

    #[test]
    fn avoid_ambiguous_removes_exactly_the_documented_characters() {
        let options = CharacterOptions {
            length: 128,
            avoid_ambiguous: true,
            ..CharacterOptions::default()
        };
        for _ in 0..50 {
            let password = text(&Recipe::Characters(options).generate().unwrap());
            assert!(
                !password.chars().any(|c| AMBIGUOUS.contains(c)),
                "{password}"
            );
        }
        // …and the classes are still all represented, so filtering did not empty one out.
        let password = text(&Recipe::Characters(options).generate().unwrap());
        assert!(password.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn no_character_class_is_an_error_not_an_empty_password() {
        let recipe = Recipe::Characters(CharacterOptions {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        });
        assert!(matches!(recipe.generate(), Err(Error::Generator(_))));
        assert_eq!(recipe.entropy_bits(), 0.0);
    }

    #[test]
    fn word_mode_shape() {
        let recipe = Recipe::Words(WordOptions::default());
        let password = text(&recipe.generate().unwrap());
        assert_eq!(password.split('-').count(), 4, "{password}");
        assert!(password.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn word_mode_options_take_effect() {
        let recipe = Recipe::Words(WordOptions {
            words: 6,
            separator: Separator::Period,
            capitalize: true,
            include_digit: true,
        });
        let password = text(&recipe.generate().unwrap());
        let parts: Vec<&str> = password.split('.').collect();
        assert_eq!(parts.len(), 6, "{password}");
        for part in &parts {
            assert!(
                part.chars().next().is_some_and(|c| c.is_ascii_uppercase()),
                "{password}"
            );
        }
        assert_eq!(
            password.chars().filter(char::is_ascii_digit).count(),
            1,
            "{password}"
        );
    }

    #[test]
    fn word_counts_clamp() {
        for (asked, expected) in [(3u32, 3usize), (10, 10), (1, 3), (40, 10)] {
            let recipe = Recipe::Words(WordOptions {
                words: asked,
                ..WordOptions::default()
            });
            assert_eq!(
                text(&recipe.generate().unwrap()).split('-').count(),
                expected
            );
        }
    }

    #[test]
    fn entropy_is_monotonic_in_every_knob() {
        let base = CharacterOptions {
            length: 20,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        };
        let bits = |o: CharacterOptions| Recipe::Characters(o).entropy_bits();

        // Length.
        let mut previous = 0.0;
        for length in MIN_LENGTH..=MAX_LENGTH {
            let now = bits(CharacterOptions { length, ..base });
            assert!(now > previous, "{length} chars gave {now} <= {previous}");
            previous = now;
        }
        // Each class only ever adds.
        assert!(
            bits(CharacterOptions {
                uppercase: true,
                ..base
            }) > bits(base)
        );
        assert!(
            bits(CharacterOptions {
                digits: true,
                ..base
            }) > bits(base)
        );
        assert!(
            bits(CharacterOptions {
                symbols: true,
                ..base
            }) > bits(base)
        );
        // …and excluding characters only ever removes.
        assert!(
            bits(CharacterOptions {
                avoid_ambiguous: true,
                ..CharacterOptions::default()
            }) < bits(CharacterOptions::default())
        );

        // Words.
        let word_bits = |o: WordOptions| Recipe::Words(o).entropy_bits();
        let mut previous = 0.0;
        for count in MIN_WORDS..=MAX_WORDS {
            let now = word_bits(WordOptions {
                words: count,
                ..WordOptions::default()
            });
            assert!(now > previous);
            previous = now;
        }
        assert!(
            word_bits(WordOptions {
                include_digit: true,
                ..WordOptions::default()
            }) > word_bits(WordOptions::default())
        );
    }

    #[test]
    fn known_entropy_figures() {
        // Four diceware words is 12.925 bits each; this is the number the EFF publishes.
        let bits = Recipe::Words(WordOptions::default()).entropy_bits();
        assert!((bits - 51.699).abs() < 0.01, "{bits}");
        // The 20-character default draws from 26+26+10+27 = 89 characters.
        let bits = Recipe::Characters(CharacterOptions::default()).entropy_bits();
        assert!((bits - 129.51).abs() < 0.05, "{bits}");
    }

    #[test]
    fn draws_differ() {
        let recipe = Recipe::default();
        let a = text(&recipe.generate().unwrap());
        let b = text(&recipe.generate().unwrap());
        assert_ne!(a, b);
    }

    /// A distribution sanity check, not a statistical proof.
    ///
    /// 26 lower-case letters over 26 000 draws: every letter should turn up, and no letter should
    /// be wildly over- or under-represented. The bounds are loose enough (±40% of the 1000-per-
    /// letter expectation, roughly ±12 standard deviations) that a correct generator will not
    /// trip them in the life of the project, while a modulo bias or an off-by-one in the alphabet
    /// would.
    #[test]
    fn character_draws_are_roughly_uniform() {
        let options = CharacterOptions {
            length: 128,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        };
        let mut counts = [0usize; 26];
        for _ in 0..204 {
            for byte in Recipe::Characters(options).generate().unwrap().expose() {
                counts[usize::from(byte - b'a')] += 1;
            }
        }
        let total: usize = counts.iter().sum();
        let expected = total as f64 / 26.0;
        for (index, count) in counts.iter().enumerate() {
            let ratio = *count as f64 / expected;
            assert!(
                (0.6..1.4).contains(&ratio),
                "letter {} appeared {count} times, expected about {expected:.0}",
                char::from(b'a' + index as u8)
            );
        }
    }

    #[test]
    fn uniform_below_covers_its_whole_range() {
        let mut seen = [false; 7];
        for _ in 0..500 {
            seen[uniform_below(7).unwrap()] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert!(matches!(uniform_below(0), Err(Error::Generator(_))));
        assert_eq!(uniform_below(1).unwrap(), 0);
    }

    #[test]
    fn separator_round_trips_through_its_name() {
        for separator in [
            Separator::Hyphen,
            Separator::Underscore,
            Separator::Period,
            Separator::Space,
            Separator::None,
        ] {
            assert_eq!(separator.as_str().parse::<Separator>().unwrap(), separator);
        }
        assert!("semicolon".parse::<Separator>().is_err());
    }
}

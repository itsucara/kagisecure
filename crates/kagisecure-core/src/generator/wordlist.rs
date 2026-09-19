//! The embedded EFF "large" wordlist.
//!
//! `eff_large_wordlist.txt` is the word column of the list the Electronic Frontier Foundation
//! published in 2016 (<https://www.eff.org/dice>), with the five-digit dice codes stripped: the
//! codes are an artefact of rolling physical dice, and this crate draws from `OsRng` instead. The
//! words themselves are unmodified and in the published order.
//!
//! It is embedded rather than loaded from disk so that a generated passphrase does not depend on
//! a file the user could lose, replace or shorten. 7776 = 6^5 words is 12.925 bits each.

use std::sync::LazyLock;

/// The raw asset, one word per line.
const RAW: &str = include_str!("eff_large_wordlist.txt");

/// How many words the list holds. Asserted against the asset by a test, so a truncated or
/// duplicated file fails the build's test run rather than silently costing entropy.
pub const WORDLIST_LEN: usize = 7776;

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    RAW.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
});

/// The wordlist, in published order.
#[must_use]
pub fn words() -> &'static [&'static str] {
    &WORDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_list_is_the_size_the_entropy_calculation_assumes() {
        assert_eq!(words().len(), WORDLIST_LEN);
    }

    #[test]
    fn every_word_is_distinct() {
        let unique: BTreeSet<&str> = words().iter().copied().collect();
        assert_eq!(unique.len(), WORDLIST_LEN, "the list has duplicates");
    }

    #[test]
    fn every_word_is_typeable_lower_case_ascii() {
        for word in words() {
            assert!(
                word.len() >= 3 && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "unexpected word {word:?}"
            );
        }
    }

    /// `strength::estimate` looks a candidate up with `binary_search`, so the asset being in
    /// byte order is load-bearing rather than cosmetic.
    #[test]
    fn the_list_is_in_byte_order() {
        assert!(words().windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn the_endpoints_are_the_published_ones() {
        assert_eq!(words()[0], "abacus");
        assert_eq!(words()[WORDLIST_LEN - 1], "zoom");
    }
}

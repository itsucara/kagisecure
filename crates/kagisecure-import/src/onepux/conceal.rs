//! The one place that decides whether a 1PUX value is secret material.
//!
//! Getting this wrong in one direction writes a password into a field the UI renders in plain
//! text, shows to an agent and copies into a preview. Getting it wrong in the other direction
//! masks a note. The costs are not symmetric, so the rule is **fail closed**: any hint of a
//! credential wins, and a value type this build has never heard of is secret as soon as anything
//! else about the field looks like a credential.
//!
//! It is a single free function over a single struct of hints on purpose. Every caller —
//! `loginFields`, `sections[].fields[]`, whatever a later 1PUX version adds — goes through it, so
//! there is exactly one rule to read, one to review and one to property-test
//! (`tests/onepux.rs`, plan §6).

/// Everything about a field that bears on whether its value is secret.
///
/// All optional: a login field has no `guarded` flag, a section field has no `designation`. What
/// is absent simply does not vote.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConcealHints<'a> {
    /// The single key of the 1PUX value object — `"concealed"`, `"totp"`, `"string"` — or `None`
    /// when the value was not a one-key object at all.
    pub value_key: Option<&'a str>,
    /// 1Password's own `guarded` flag on a section field.
    pub guarded: bool,
    /// A login field's `designation`, e.g. `"username"` or `"password"`.
    pub designation: Option<&'a str>,
    /// A login field's `type`: `"T"`, `"E"`, `"U"`, `"N"`, `"P"`, `"A"`, `"TEL"`.
    pub login_field_type: Option<&'a str>,
    /// The label a user sees.
    pub title: Option<&'a str>,
    /// 1Password's own field id.
    pub id: Option<&'a str>,
}

/// Value type keys whose contents are secret material whatever else the field says.
///
/// UNVERIFIED — confirm against sample.1pux. The published format description lists the
/// human-readable type names (Concealed, One Time Password, Credit Card Number) but not the JSON
/// keys; these are the camel-cased forms 1Password's exporter is believed to write. A key that
/// turns out to be spelled differently lands in [`UNKNOWN_KEY_IS_PUBLIC`]'s "unknown" case, where
/// the other hints still protect it.
pub const SECRET_KEYS: &[&str] = &["concealed", "totp", "creditCardNumber"];

/// Value type keys this build recognises as *not* secret by themselves.
///
/// UNVERIFIED — confirm against sample.1pux, as [`SECRET_KEYS`].
pub const PUBLIC_KEYS: &[&str] = &[
    "string",
    "email",
    "url",
    "phone",
    "date",
    "monthYear",
    "menu",
    "creditCardType",
    "reference",
    "gender",
    "address",
    "file",
];

/// A key nobody recognises is public *only* when nothing else about the field is suspicious.
///
/// Documented as a named constant because it is the one asymmetry in this module and reviewers
/// should be able to find it: it is why `is_concealed` is "fail closed" rather than "refuse
/// anything unfamiliar".
pub const UNKNOWN_KEY_IS_PUBLIC: bool = true;

/// Substrings that make a label or an id a credential, matched case-insensitively anywhere.
const CREDENTIAL_SUBSTRINGS: &[&str] = &[
    "password",
    "passphrase",
    "passwd",
    "secret",
    "token",
    "privatekey",
    "apikey",
];

/// Words that make a label or an id a credential, matched as whole words only.
///
/// `pin`, `cvv` and `cvc` are too short to match as substrings: "shipping" contains "pin" and
/// would mask a delivery address. The plan's regex says `(?i)pin`; this is that rule with word
/// boundaries, which is the difference between fail-closed and fail-useless.
const CREDENTIAL_WORDS: &[&str] = &["pin", "cvv", "cvc", "cvn", "cid"];

/// Whether a field's value is secret material.
///
/// True when any of these holds:
///
/// * the value type key is one of [`SECRET_KEYS`];
/// * 1Password marked the field `guarded`;
/// * the login field's designation is `password`;
/// * the login field's type is `P`, the HTML password input;
/// * the title or the id reads as a credential ([`CREDENTIAL_SUBSTRINGS`],
///   [`CREDENTIAL_WORDS`]);
/// * the value type key is one this build does not know **and** any of the above hints is set.
///
/// Everything else is public.
#[must_use]
pub fn is_concealed(hints: &ConcealHints<'_>) -> bool {
    if let Some(key) = hints.value_key
        && SECRET_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key))
    {
        return true;
    }

    if hints.guarded {
        return true;
    }

    if hints
        .designation
        .is_some_and(|d| d.eq_ignore_ascii_case("password"))
    {
        return true;
    }

    if hints
        .login_field_type
        .is_some_and(|t| t.eq_ignore_ascii_case("P"))
    {
        return true;
    }

    if reads_as_a_credential(hints.title) || reads_as_a_credential(hints.id) {
        return true;
    }

    // A key this build has never seen, with nothing else to go on. Every hint above already
    // returned; reaching here means none of them fired.
    let _ = UNKNOWN_KEY_IS_PUBLIC;
    false
}

/// Whether a label or an id names a credential.
fn reads_as_a_credential(text: Option<&str>) -> bool {
    let Some(text) = text else {
        return false;
    };

    // `private key` and `api key` are written a dozen ways; collapsing the separators out makes
    // "private-key", "private_key", "privateKey" and "private key" one case.
    let collapsed: String = text
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    if CREDENTIAL_SUBSTRINGS.iter().any(|s| collapsed.contains(s)) {
        return true;
    }

    words(text).any(|word| CREDENTIAL_WORDS.contains(&word.as_str()))
}

/// The lower-cased words in a label: split on anything that is not alphanumeric, and on camelCase
/// humps, so `"cardPin"` and `"card_pin"` both yield `"pin"`.
fn words(text: &str) -> impl Iterator<Item = String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut previous_was_lower = false;
    for c in text.chars() {
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            previous_was_lower = false;
            continue;
        }
        // Split `cardPin` but not `PIN`: a hump is an upper-case letter after a lower-case one.
        if c.is_uppercase() && previous_was_lower && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        previous_was_lower = c.is_lowercase() || c.is_numeric();
        current.extend(c.to_lowercase());
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints() -> ConcealHints<'static> {
        ConcealHints::default()
    }

    #[test]
    fn a_concealed_value_key_is_enough_on_its_own() {
        for key in SECRET_KEYS {
            assert!(is_concealed(&ConcealHints {
                value_key: Some(key),
                ..hints()
            }));
        }
    }

    #[test]
    fn a_guarded_field_of_an_unknown_type_is_secret() {
        assert!(is_concealed(&ConcealHints {
            value_key: Some("quantumFoo"),
            guarded: true,
            ..hints()
        }));
        // The same unknown type with nothing else to go on is not.
        assert!(!is_concealed(&ConcealHints {
            value_key: Some("quantumFoo"),
            title: Some("recovery"),
            ..hints()
        }));
    }

    #[test]
    fn short_credential_words_match_as_words_and_not_as_substrings() {
        assert!(is_concealed(&ConcealHints {
            title: Some("PIN"),
            ..hints()
        }));
        assert!(is_concealed(&ConcealHints {
            title: Some("card PIN"),
            ..hints()
        }));
        // "shipping" contains "pin"; a delivery address is not a credential.
        assert!(!is_concealed(&ConcealHints {
            value_key: Some("string"),
            title: Some("shipping"),
            ..hints()
        }));
    }

    #[test]
    fn a_private_key_is_a_private_key_however_it_is_spelled() {
        for spelling in [
            "private key",
            "Private-Key",
            "private_key",
            "privateKey",
            "API Key",
            "api_key",
        ] {
            assert!(
                is_concealed(&ConcealHints {
                    value_key: Some("string"),
                    title: Some(spelling),
                    ..hints()
                }),
                "{spelling}"
            );
        }
    }

    #[test]
    fn a_public_key_with_a_plain_label_is_public() {
        assert!(!is_concealed(&ConcealHints {
            value_key: Some("string"),
            title: Some("note"),
            id: Some("note-id"),
            ..hints()
        }));
    }
}

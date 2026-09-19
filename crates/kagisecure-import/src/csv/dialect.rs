//! Detecting a CSV dialect from its header row, and the small helpers every per-dialect module in
//! this directory shares.
//!
//! Detection reads **only** the header: normalized (BOM stripped, lowercased, unquoted by the
//! `csv` crate itself, trimmed) column names, matched as a set against the shapes plan §3 lists
//! for each format. Nothing here ever looks at what is *in* a column to guess what it means —
//! that is the rule the whole family follows, and it is also what makes an unrecognized or
//! ambiguous header an error instead of a coin flip.
//!
//! Matching is by exact set equality against each dialect's accepted variants, which is also why
//! column order in the source file never matters: a re-arranged header still detects and still
//! reads correctly, because every per-dialect `Columns::resolve` looks a column up by name.

use kagisecure_core::Totp;
use kagisecure_core::model::FieldKind;

use crate::error::{ImportError, Result};
use crate::ir::{ImportedField, ImportedValue, SourceKind};

/// Normalize one header cell: strip a stray UTF-8 BOM character, trim surrounding whitespace,
/// lowercase. The `csv` crate has already stripped quoting by the time this sees the cell, and a
/// leading byte-order-mark that survived encoding detection shows up as `'\u{feff}'` in the first
/// cell rather than as raw bytes.
///
/// Public so the property test below and this crate's own tests can hold it to its contract
/// without reaching into a private module, the same way [`crate::dedupe::fingerprint`] is.
#[must_use]
pub fn normalize_header_cell(raw: &str) -> String {
    raw.trim_start_matches('\u{feff}').trim().to_lowercase()
}

/// One dialect's accepted header shapes, as sets of normalized column names (plan §3).
struct Signature {
    source: SourceKind,
    variants: &'static [&'static [&'static str]],
}

const SIGNATURES: &[Signature] = &[
    Signature {
        source: SourceKind::AppleCsv,
        variants: &[&["title", "url", "username", "password", "notes", "otpauth"]],
    },
    Signature {
        source: SourceKind::ChromiumCsv,
        variants: &[
            &["name", "url", "username", "password", "note"],
            &["name", "url", "username", "password", "notes"],
            &["name", "url", "username", "password"],
        ],
    },
    Signature {
        source: SourceKind::FirefoxCsv,
        variants: &[&[
            "url",
            "username",
            "password",
            "httprealm",
            "formactionorigin",
            "guid",
            "timecreated",
            "timelastused",
            "timepasswordchanged",
        ]],
    },
    Signature {
        source: SourceKind::OnePasswordCsv,
        variants: &[
            &[
                "title", "url", "username", "password", "otpauth", "favorite", "archived", "tags",
                "notes",
            ],
            &[
                "title", "website", "username", "password", "otpauth", "favorite", "archived",
                "tags", "notes",
            ],
            &[
                "title",
                "url",
                "username",
                "password",
                "one-time password",
                "favorite",
                "archived",
                "tags",
                "notes",
            ],
            &[
                "title",
                "website",
                "username",
                "password",
                "one-time password",
                "favorite",
                "archived",
                "tags",
                "notes",
            ],
        ],
    },
];

/// Choose a dialect from normalized header cells by exact-set match against every accepted
/// variant.
///
/// # Errors
///
/// [`ImportError::UndetectedFormat`] when zero or more than one dialect's signature matches;
/// `candidates` names every distinct dialect that did (empty when none did). None of the four
/// signatures above share a column set, so two matches cannot occur with the built-in table; the
/// check stays because a header is arbitrary input, not because the table is expected to grow
/// into an overlap.
pub(crate) fn detect(normalized: &[String]) -> Result<SourceKind> {
    use std::collections::BTreeSet;

    let header: BTreeSet<&str> = normalized.iter().map(String::as_str).collect();
    let mut matched: Vec<SourceKind> = Vec::new();
    for signature in SIGNATURES {
        let hit = signature.variants.iter().any(|variant| {
            let variant_set: BTreeSet<&str> = variant.iter().copied().collect();
            variant_set == header
        });
        if hit {
            matched.push(signature.source);
        }
    }
    match matched.as_slice() {
        [only] => Ok(*only),
        _ => Err(ImportError::UndetectedFormat {
            candidates: matched,
        }),
    }
}

/// The index of the first header cell equal to one of `aliases`, if any.
#[must_use]
pub(crate) fn find(normalized: &[String], aliases: &[&str]) -> Option<usize> {
    normalized
        .iter()
        .position(|cell| aliases.iter().any(|alias| alias == cell))
}

/// [`find`], or [`ImportError::MissingColumn`] naming `canonical` when nothing matched.
pub(crate) fn require(
    normalized: &[String],
    source_kind: SourceKind,
    aliases: &[&str],
    canonical: &'static str,
) -> Result<usize> {
    find(normalized, aliases).ok_or(ImportError::MissingColumn {
        source_kind,
        column: canonical,
    })
}

/// A required column's cell, or `""` when `csv`'s lenient reader left a short row without it.
#[must_use]
pub(crate) fn cell(record: &::csv::StringRecord, index: usize) -> &str {
    record.get(index).unwrap_or("")
}

/// An optional column's cell — `""` when the column is absent from this header variant, or when
/// the row is short one.
#[must_use]
pub(crate) fn cell_opt(record: &::csv::StringRecord, index: Option<usize>) -> &str {
    index.and_then(|i| record.get(i)).unwrap_or("")
}

/// Whether a cell, ignoring surrounding whitespace, has nothing in it.
///
/// Used only to decide *whether* to keep a value, never to change the value itself: a stored
/// username or password is exactly the bytes the row had, whitespace included, because trimming a
/// credential is a content-based guess this crate does not make.
#[must_use]
pub(crate) fn is_blank(cell: &str) -> bool {
    cell.trim().is_empty()
}

/// `true`-ish spellings a source might use for a checkbox column. A short, explicit list rather
/// than a guess: anything else, including an empty cell, is `false`.
#[must_use]
pub(crate) fn is_truthy(cell: &str) -> bool {
    matches!(
        cell.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

/// Split a 1Password-style comma-separated tag cell into individual tags, trimmed and with
/// empties dropped.
#[must_use]
pub(crate) fn split_tags(cell: &str) -> Vec<String> {
    cell.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The title to give an item that has none of its own: the host of its first URL, or
/// `"Untitled"` when there is not even that (plan §3: "title = URL host when no title column").
#[must_use]
pub(crate) fn fallback_title(url: &str) -> String {
    crate::dedupe::url_host(url).unwrap_or_else(|| "Untitled".to_owned())
}

/// Validate a one-time-password column the way the plan's fail-closed TOTP rule asks for from
/// every source: a full `otpauth://` URI first, then a bare Base32 seed wrapped into one labelled
/// with the item's title, and — because a one-time-password column is still a credential and this
/// crate never drops one — a concealed field naming itself unrecognized when both fail.
#[must_use]
pub(crate) fn totp_field(item_title: &str, raw: &str) -> ImportedField {
    let trimmed = raw.trim();
    if let Ok(totp) = Totp::parse_uri(trimmed) {
        return ImportedField::new(
            "one-time password",
            FieldKind::Totp,
            ImportedValue::Secret(totp.to_uri()),
        );
    }
    let wrapped = format!(
        "otpauth://totp/{}?secret={trimmed}",
        percent_encode_label(item_title)
    );
    if let Ok(totp) = Totp::parse_uri(&wrapped) {
        return ImportedField::new(
            "one-time password",
            FieldKind::Totp,
            ImportedValue::Secret(totp.to_uri()),
        );
    }
    ImportedField::secret(
        "one-time password (unrecognized)",
        FieldKind::Concealed,
        trimmed.to_owned(),
    )
}

/// A minimal percent-encoder for the label half of a wrapped `otpauth://` URI.
///
/// Not reused from `kagisecure_core::totp`, whose own encoder is private to that module; this one
/// only has to keep a title's `/`, `?`, `:` and `%` out of the URI structure it gets embedded in,
/// not conform to any particular RFC profile.
fn percent_encode_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|c| (*c).to_owned()).collect()
    }

    #[test]
    fn each_signature_detects_its_own_dialect() {
        assert_eq!(
            detect(&owned(&[
                "title", "url", "username", "password", "notes", "otpauth"
            ]))
            .unwrap(),
            SourceKind::AppleCsv
        );
        assert_eq!(
            detect(&owned(&["name", "url", "username", "password"])).unwrap(),
            SourceKind::ChromiumCsv
        );
        assert_eq!(
            detect(&owned(&["name", "url", "username", "password", "note"])).unwrap(),
            SourceKind::ChromiumCsv
        );
        assert_eq!(
            detect(&owned(&[
                "url",
                "username",
                "password",
                "httprealm",
                "formactionorigin",
                "guid",
                "timecreated",
                "timelastused",
                "timepasswordchanged",
            ]))
            .unwrap(),
            SourceKind::FirefoxCsv
        );
        assert_eq!(
            detect(&owned(&[
                "title",
                "website",
                "username",
                "password",
                "one-time password",
                "favorite",
                "archived",
                "tags",
                "notes",
            ]))
            .unwrap(),
            SourceKind::OnePasswordCsv
        );
    }

    #[test]
    fn header_order_does_not_matter() {
        let forward = owned(&["title", "url", "username", "password", "notes", "otpauth"]);
        let shuffled = owned(&["otpauth", "notes", "password", "username", "url", "title"]);
        assert_eq!(detect(&forward).unwrap(), detect(&shuffled).unwrap());
    }

    #[test]
    fn an_unrecognized_header_is_undetected_with_no_candidates() {
        let err = detect(&owned(&["title", "url", "username", "password"])).unwrap_err();
        assert!(
            matches!(&err, ImportError::UndetectedFormat { candidates } if candidates.is_empty())
        );
        assert!(err.to_string().contains("--format"));
    }

    #[test]
    fn totp_wraps_a_bare_seed_and_falls_back_when_nothing_parses() {
        let field = totp_field("Acme", "JBSWY3DPEHPK3PXP");
        assert_eq!(field.label, "one-time password");
        assert_eq!(field.kind, FieldKind::Totp);

        let fallback = totp_field("Acme", "not a seed at all!!");
        assert_eq!(fallback.label, "one-time password (unrecognized)");
        assert_eq!(fallback.kind, FieldKind::Concealed);
    }
}

// -------------------------------------------------------------------------------------------
// Properties
// -------------------------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;

    proptest::proptest! {
        /// Normalizing is idempotent and always lowercase, whatever mix of case, whitespace and a
        /// leading BOM character the header cell carried.
        #[test]
        fn normalizing_a_header_cell_is_idempotent_and_lowercase(
            prefix in "(\\x{feff}|)",
            body in "[a-zA-Z0-9 _.-]{0,24}",
        ) {
            let raw = format!("{prefix}{body}");
            let once = normalize_header_cell(&raw);
            let twice = normalize_header_cell(&once);
            proptest::prop_assert_eq!(&once, &twice);
            proptest::prop_assert_eq!(&once, &once.to_lowercase());
            let bom = '\u{feff}';
            proptest::prop_assert!(!once.contains(bom));
        }

        /// Splitting tags never produces an empty tag and never loses a non-empty one to anything
        /// but trimming.
        #[test]
        fn split_tags_drops_only_empties(
            parts in proptest::collection::vec("[a-zA-Z0-9]{1,8}", 0..6),
        ) {
            let cell = parts.join(", ");
            let split = split_tags(&cell);
            proptest::prop_assert!(split.iter().all(|t| !t.is_empty()));
            proptest::prop_assert_eq!(split.len(), parts.iter().filter(|p| !p.is_empty()).count());
        }
    }
}

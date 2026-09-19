//! `categoryUuid` → [`Category`].
//!
//! 1Password identifies an item's category by a three-character string. The published 1PUX
//! description does not list them, so most of this table is inference from the app's behaviour
//! and from what other importers assume — which is why every row carries a [`Verified`] and why
//! only `"001"` says [`Verified::Yes`].
//!
//! Two things make an unverified table safe:
//!
//! * an id this build does not know becomes [`Category::Other`] holding the id verbatim, so a
//!   wrong guess is never a *lost* item, and
//! * `extra["onepassword_category_uuid"]` is written for **every** item, known or not, so a
//!   corrected table can be applied to an already-imported vault without re-importing.
//!
//! `probe_sample_categories` in `tests/onepux.rs` prints `categoryUuid → title` pairs from a real
//! export when `$KAGISECURE_1PUX_SAMPLE` points at one. That test is how a row graduates to
//! [`Verified::Yes`].

use kagisecure_core::model::Category;

/// Whether a row of [`CATEGORIES`] has been checked against a real export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verified {
    /// Confirmed against a real 1PUX archive or the published description.
    Yes,
    /// Inferred. Believed right, never seen.
    No,
}

/// One row of the category table.
#[derive(Debug)]
pub struct CategoryRow {
    /// The `categoryUuid` as the export writes it.
    pub uuid: &'static str,
    /// What this build maps it to.
    pub category: Category,
    /// Whether that mapping has been confirmed.
    pub verified: Verified,
}

/// The table.
///
/// `static` rather than `const` because [`Category`] has a `String` in one variant and so has
/// drop glue; a static is never dropped, which is exactly right for a table.
///
/// UNVERIFIED — every row but `"001"` is inference; confirm against sample.1pux.
pub static CATEGORIES: [CategoryRow; 11] = [
    // The one row the published description and every export ever seen agree on.
    CategoryRow {
        uuid: "001",
        category: Category::Login,
        verified: Verified::Yes,
    },
    CategoryRow {
        uuid: "002",
        category: Category::CreditCard,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "003",
        category: Category::SecureNote,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "004",
        category: Category::Identity,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "005",
        category: Category::Password,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "006",
        category: Category::Document,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "100",
        category: Category::SoftwareLicense,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "102",
        category: Category::Database,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "110",
        category: Category::Server,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "112",
        category: Category::ApiCredential,
        verified: Verified::No,
    },
    CategoryRow {
        uuid: "114",
        category: Category::SshKey,
        verified: Verified::No,
    },
];

/// The `Item::extra` key every imported item carries, whatever its category became.
pub const CATEGORY_UUID_KEY: &str = "onepassword_category_uuid";

/// The row for a `categoryUuid`, if this build has one.
#[must_use]
pub fn row(uuid: &str) -> Option<&'static CategoryRow> {
    CATEGORIES.iter().find(|row| row.uuid == uuid)
}

/// The category for a `categoryUuid`, and whether it is a guess.
///
/// An id the table knows but has not confirmed is a guess. An id the table does *not* know is
/// not: [`Category::Other`] preserves what the export said, verbatim, and guesses nothing.
#[must_use]
pub fn category_for(uuid: &str) -> (Category, bool) {
    match row(uuid) {
        Some(row) => (row.category.clone(), row.verified == Verified::No),
        None => (Category::Other(unknown_category_name(uuid)), false),
    }
}

/// What an unrecognised `categoryUuid` is called in the vault.
#[must_use]
pub fn unknown_category_name(uuid: &str) -> String {
    format!("1Password category {uuid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_is_the_only_confirmed_row() {
        let confirmed: Vec<&str> = CATEGORIES
            .iter()
            .filter(|r| r.verified == Verified::Yes)
            .map(|r| r.uuid)
            .collect();
        assert_eq!(confirmed, ["001"]);
    }

    #[test]
    fn every_uuid_appears_once() {
        for (i, row) in CATEGORIES.iter().enumerate() {
            assert!(
                CATEGORIES.iter().skip(i + 1).all(|r| r.uuid != row.uuid),
                "{} is in the table twice",
                row.uuid
            );
        }
    }

    #[test]
    fn a_known_but_unconfirmed_id_is_a_guess_and_an_unknown_one_is_not() {
        assert_eq!(category_for("001"), (Category::Login, false));
        assert_eq!(category_for("002"), (Category::CreditCard, true));
        assert_eq!(
            category_for("999"),
            (Category::Other("1Password category 999".to_owned()), false)
        );
    }
}

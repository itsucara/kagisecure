//! Deciding whether an imported item is one the vault already has.
//!
//! Importing the same export twice is the normal case, not the exotic one: a user re-runs it
//! after fixing a flag, or imports a fresh export six months later. Without an answer to "is this
//! the same item?" the second run doubles the vault.
//!
//! # Identity, in order
//!
//! 1. **The source's own id.** A 1Password item UUID or a Firefox login GUID, stored in
//!    [`kagisecure_core::model::Item::extra`] the first time (see [`crate::ir::ForeignId`]). This
//!    is the only exact answer available, so it is asked first.
//! 2. **A fingerprint of the metadata.** `SHA-256(lower(title) ‖ 0 ‖ lower(host) ‖ 0 ‖
//!    lower(username))`. Note what is *not* in there: the password. Fingerprinting the value
//!    would make the fingerprint a function of the secret, and a function of a secret is a
//!    partial disclosure of it (ADR-0002 §1 point 3) — quite apart from meaning that rotating a
//!    password turns an update into a duplicate, which is exactly backwards.
//! 3. **New.** Nothing matched.
//!
//! # Policy
//!
//! One policy per run, chosen by the user, never per item — there is no `interactive` mode,
//! because a prompt per item across four hundred items is not a workflow.

use kagisecure_core::Vault;
use kagisecure_core::model::{Item, ItemId};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ir::{ImportedItem, ImportedValue};

/// What to do when an imported item matches one that is already in the vault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DuplicatePolicy {
    /// Leave the existing item exactly as it is. The default: an import should not be able to
    /// destroy something the user typed by hand.
    #[default]
    Skip,
    /// Overwrite what the source carries, keep what only this vault knows.
    Update,
    /// Create a second item, titled `<title> (imported YYYY-MM-DD)`.
    KeepBoth,
}

impl DuplicatePolicy {
    /// Every policy, in the order the CLI lists them.
    pub const ALL: &'static [Self] = &[Self::Skip, Self::Update, Self::KeepBoth];

    /// The canonical name used by `--on-duplicate`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Update => "update",
            Self::KeepBoth => "keep-both",
        }
    }

    /// Parse a canonical name.
    #[must_use]
    pub fn parse_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == name)
    }
}

impl std::fmt::Display for DuplicatePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an imported item was considered a duplicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duplicate {
    /// The source's own id matched.
    ByForeignId(ItemId),
    /// Title, host and username matched.
    ByFingerprint(ItemId),
}

impl Duplicate {
    /// The existing item.
    #[must_use]
    pub fn item_id(self) -> ItemId {
        match self {
            Self::ByForeignId(id) | Self::ByFingerprint(id) => id,
        }
    }
}

/// What committing will do to one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemAction {
    /// Add it; nothing like it was there.
    Create,
    /// Overwrite the matching item's source-carried parts.
    Update,
    /// Leave the matching item alone and import nothing.
    Skip,
    /// Add it beside the matching item, with a dated title.
    KeepBoth,
}

impl ItemAction {
    /// The canonical name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Skip => "skip",
            Self::KeepBoth => "keep-both",
        }
    }
}

impl std::fmt::Display for ItemAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Find the existing item this imported one is a second copy of, if there is one.
#[must_use]
pub fn find_duplicate(vault: &Vault, imported: &ImportedItem) -> Option<Duplicate> {
    if let Some(foreign) = &imported.foreign_id {
        let hit = vault.items().iter().find(|item| {
            item.extra
                .get(&foreign.key)
                .and_then(ciborium::Value::as_text)
                == Some(foreign.value.as_str())
        });
        if let Some(item) = hit {
            return Some(Duplicate::ByForeignId(item.id));
        }
    }

    let wanted = imported_fingerprint(imported);
    vault
        .items()
        .iter()
        .find(|item| item_fingerprint(item) == wanted)
        .map(|item| Duplicate::ByFingerprint(item.id))
}

/// What committing `imported` into `vault` under `policy` would do, and to which item.
#[must_use]
pub fn resolve(
    vault: &Vault,
    imported: &ImportedItem,
    policy: DuplicatePolicy,
) -> (ItemAction, Option<ItemId>) {
    match find_duplicate(vault, imported) {
        None => (ItemAction::Create, None),
        Some(duplicate) => {
            let id = duplicate.item_id();
            match policy {
                DuplicatePolicy::Skip => (ItemAction::Skip, Some(id)),
                DuplicatePolicy::Update => (ItemAction::Update, Some(id)),
                DuplicatePolicy::KeepBoth => (ItemAction::KeepBoth, Some(id)),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------------------------

/// `SHA-256(lower(title) ‖ 0 ‖ lower(host) ‖ 0 ‖ lower(username))`, hex-encoded.
///
/// Three pieces of metadata and a domain separator between each, so that
/// `("ab", "", "")` and `("a", "b", "")` cannot collide. No value goes in here, ever.
#[must_use]
pub fn fingerprint(title: &str, host: Option<&str>, username: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(title.to_lowercase().as_bytes());
    hasher.update([0u8]);
    hasher.update(host.unwrap_or_default().to_lowercase().as_bytes());
    hasher.update([0u8]);
    hasher.update(username.unwrap_or_default().to_lowercase().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// The fingerprint of an item already in the vault.
#[must_use]
pub fn item_fingerprint(item: &Item) -> String {
    let host = item.urls.first().and_then(|u| url_host(u));
    let username = item
        .fields
        .iter()
        .filter(|f| !f.value.is_secret())
        .find(|f| is_username_label(&f.label))
        .and_then(|f| f.value.as_public())
        .map(str::to_owned);
    fingerprint(&item.title, host.as_deref(), username.as_deref())
}

/// The fingerprint of an item that is about to be imported.
#[must_use]
pub fn imported_fingerprint(imported: &ImportedItem) -> String {
    let host = imported.urls.first().and_then(|u| url_host(u));
    let username = imported
        .fields
        .iter()
        .filter(|f| !f.value.is_secret())
        .find(|f| is_username_label(&f.label))
        .and_then(|f| f.value.as_public())
        .map(str::to_owned);
    fingerprint(&imported.title, host.as_deref(), username.as_deref())
}

/// Whether a label names the field a human would call "the username".
///
/// `username` first, `email` only as a fallback, because an item can carry both and the two must
/// not fingerprint differently depending on field order.
fn is_username_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("username") || label.eq_ignore_ascii_case("email")
}

/// The host part of a URL, lowercased, without scheme, userinfo, port or path.
///
/// Hand-rolled rather than pulling in a URL crate: this needs the host of strings a browser
/// already accepted, not RFC 3986 conformance, and a parser dependency in the import graph is a
/// parser dependency in the audited graph.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    let rest = url
        .split_once("://")
        .map_or(url, |(_scheme, rest)| rest)
        .trim_start_matches("//");
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|s| !s.is_empty())?;
    // Userinfo, when present, is everything before the last `@`.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(end) = host_port.strip_prefix('[') {
        // An IPv6 literal keeps its brackets; the port is after the `]`.
        end.split_once(']')
            .map_or(host_port, |(inside, _)| inside)
            .to_owned()
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(h, _)| h)
            .to_owned()
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

// ---------------------------------------------------------------------------------------------
// History merge
// ---------------------------------------------------------------------------------------------

/// The key two history entries are considered the same by: the hash of the value and the moment
/// it was retired.
///
/// Hashing the value is what lets `update` run twice without doubling the history. The hash never
/// leaves this crate — it is not returned, reported or logged, so there is no partial-disclosure
/// surface here (contrast ADR-0002 §1 point 3, which is about hashes that are *returned*).
#[must_use]
pub(crate) fn revision_key(value: &[u8], retired_at: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(retired_at.to_be_bytes());
    hasher.update([0u8]);
    hasher.update(value);
    hasher.finalize().into()
}

/// The key for an imported revision, or `None` when it carries no secret material.
#[must_use]
pub(crate) fn imported_revision_key(value: &ImportedValue, retired_at: u64) -> Option<[u8; 32]> {
    match value {
        ImportedValue::Secret(secret) => Some(revision_key(secret.expose(), retired_at)),
        ImportedValue::Public(text) => Some(revision_key(text.as_bytes(), retired_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_is_case_insensitive_and_domain_separated() {
        assert_eq!(
            fingerprint("Acme", Some("Example.COM"), Some("Ada")),
            fingerprint("acme", Some("example.com"), Some("ada"))
        );
        assert_ne!(
            fingerprint("ab", None, None),
            fingerprint("a", Some("b"), None)
        );
        assert_ne!(
            fingerprint("Acme", Some("example.com"), Some("ada")),
            fingerprint("Acme", Some("example.org"), Some("ada"))
        );
        assert_eq!(fingerprint("a", None, None).len(), 64);
    }

    #[test]
    fn url_hosts_lose_the_scheme_userinfo_port_and_path() {
        assert_eq!(
            url_host("https://example.com/login"),
            Some("example.com".into())
        );
        assert_eq!(url_host("HTTPS://Example.COM"), Some("example.com".into()));
        assert_eq!(url_host("example.com"), Some("example.com".into()));
        assert_eq!(
            url_host("https://ada:pw@example.com:8443/x?y#z"),
            Some("example.com".into())
        );
        assert_eq!(url_host("http://[::1]:8080/"), Some("::1".into()));
        assert_eq!(url_host(""), None);
        assert_eq!(url_host("https://"), None);
    }

    #[test]
    fn policies_and_actions_round_trip_through_their_names() {
        for policy in DuplicatePolicy::ALL {
            assert_eq!(DuplicatePolicy::parse_name(policy.as_str()), Some(*policy));
        }
        assert_eq!(DuplicatePolicy::parse_name("interactive"), None);
        assert_eq!(DuplicatePolicy::default(), DuplicatePolicy::Skip);
    }

    #[test]
    fn a_revision_key_depends_on_both_the_value_and_the_timestamp() {
        assert_eq!(revision_key(b"a", 1), revision_key(b"a", 1));
        assert_ne!(revision_key(b"a", 1), revision_key(b"a", 2));
        assert_ne!(revision_key(b"a", 1), revision_key(b"b", 1));
    }
}

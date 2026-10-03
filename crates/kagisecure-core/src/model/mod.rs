//! The item model (vault-format §5).
//!
//! Only compiled with the `secret-material` feature; metadata-only mirrors of these types live in
//! [`crate::proto`] and are always available.

pub mod env;
mod secret;

pub use env::{EnvVar, Environment, VarSource};
/// The crate-private serde adapter for a [`Secret`], for the other body types that hold one (the
/// vault's device keys).
pub(crate) use secret::cbor as secret_cbor;
pub use secret::{Secret, SecretText};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::proto::{Category, EnvId, FieldId, FieldKind, ItemId, VaultId};
use crate::proto::{FieldSummary, ItemSummary, VaultSummary};

/// A logical vault inside the vault file. kagisecure keeps one file with several logical vaults
/// rather than one file per vault (vault-format §2.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Identifier.
    pub id: VaultId,
    /// Display name.
    pub name: String,
    /// Whether agents may see this vault at all. Default-deny (threat-model M-9).
    #[serde(default)]
    pub agent_visible: bool,
    /// Whether items created in this logical vault — by the app, the CLI or an import — start out
    /// visible to agents, with all their fields ("Show new items to agents", ADR-0007 amendment
    /// 2026-10-04). On by default, including for a vault written before this key existed: the
    /// owner chose convenience over default-deny for item metadata. Values are never exposed by
    /// this; every value release still needs its own approval.
    #[serde(default = "default_true")]
    pub new_items_agent_visible: bool,
    /// Unix seconds.
    #[serde(default)]
    pub created_at: u64,
    /// Top-level keys this build does not recognize, preserved verbatim (vault-format §9 rule 1).
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl VaultMeta {
    /// A fresh logical vault with the given display name, invisible to agents.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: VaultId::new(),
            name: name.into(),
            agent_visible: false,
            new_items_agent_visible: true,
            created_at: crate::unix_now(),
            unknown: BTreeMap::new(),
        }
    }

    /// Metadata-only view.
    #[must_use]
    pub fn summary(&self, item_count: usize, environment_count: usize) -> VaultSummary {
        VaultSummary {
            id: self.id,
            name: self.name.clone(),
            item_count,
            environment_count,
            agent_visible: self.agent_visible,
            shared: false,
        }
    }
}

/// The serde default of [`VaultMeta::new_items_agent_visible`].
const fn default_true() -> bool {
    true
}

/// The value a field holds.
///
/// v1 stores either a public string or secret material. The `Address` and `File` variants
/// sketched in vault-format §5 are not yet implemented; unmapped import data has a home in
/// [`Item::extra`] until they are.
///
/// There is deliberately no separate `Totp` variant. A one-time-password field is
/// [`FieldKind::Totp`] carrying a `Secret` whose bytes are the whole `otpauth://` URI, because
/// that URI *is* the credential — putting its parameters in a public sibling field would move
/// the issuer out of the encrypted-and-unreadable half of the record for no gain, and would need
/// a body-schema bump. [`Field::totp_generator`] reads them back out (ADR-0016).
#[derive(Debug, Serialize, Deserialize)]
pub enum FieldValue {
    /// A value that may be shown, including to an agent when `agent_visible` is set.
    Public(String),
    /// Secret material. Never leaves the process except through [`crate::inject`].
    Secret(#[serde(with = "secret::cbor")] Secret),
}

impl FieldValue {
    /// Whether this value is secret material.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }

    /// The secret, if this is one.
    #[must_use]
    pub fn as_secret(&self) -> Option<&Secret> {
        match self {
            Self::Secret(s) => Some(s),
            Self::Public(_) => None,
        }
    }

    /// The public string, if this is one.
    #[must_use]
    pub fn as_public(&self) -> Option<&str> {
        match self {
            Self::Public(s) => Some(s),
            Self::Secret(_) => None,
        }
    }

    /// Whether there is a value here at all.
    ///
    /// A boolean, deliberately not a length: `describe_item` returns this, and a length is a
    /// function of the secret (mcp-server.md §2.4).
    #[must_use]
    pub fn has_value(&self) -> bool {
        match self {
            Self::Public(s) => !s.is_empty(),
            Self::Secret(s) => !s.is_empty(),
        }
    }
}

/// One labelled field of an item.
#[derive(Debug, Serialize, Deserialize)]
pub struct Field {
    /// Identifier.
    pub id: FieldId,
    /// Human label. Metadata: visible to agents when the item is (threat-model A4).
    pub label: String,
    /// Descriptive kind.
    pub kind: FieldKind,
    /// The value.
    pub value: FieldValue,
    /// Optional 1PUX-style section name.
    #[serde(default)]
    pub section: Option<String>,
    /// Per-field agent visibility override.
    #[serde(default)]
    pub agent_visible: bool,
    /// Non-secret metadata a foreign format carried that this build has no typed home for
    /// (vault-format §9 rule 1), keyed by an importer-chosen name.
    ///
    /// **Rule: metadata only, never a value.** A `ciborium::Value` is `Serialize`, `Debug` and
    /// `Clone`; [`Secret`] is deliberately none of those. Putting a password, a token, a TOTP
    /// seed or any other credential in here would move it out of the guarded type and into
    /// something that a report, a log line or a `{:?}` could print — exactly the disclosure
    /// [`Secret`] exists to make impossible. Anything a source marks, hints at, or merely looks
    /// like a credential becomes a real [`FieldValue::Secret`] field instead; this map is for
    /// the surrounding facts (a foreign field id, a designation, a "guarded" flag).
    ///
    /// Additive and `#[serde(default)]`, skipped when empty, so it does not bump `body.schema`
    /// (vault-format §9) and an older file reads back with no extras.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, ciborium::Value>,
    /// Top-level `Field` keys this build does not recognize, preserved verbatim so an older build
    /// opening a vault a newer one wrote never destroys them (vault-format §9 rule 1).
    ///
    /// Distinct from [`Field::extra`]: `extra` is a single named key an *importer* fills with
    /// foreign metadata it has nowhere else to put; `unknown` is whatever top-level CBOR keys this
    /// build's own decoder does not have a field for at all, which by construction is exactly what
    /// `#[serde(flatten)]` captures and nothing else touches.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl Field {
    /// A public text field.
    #[must_use]
    pub fn public(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: FieldId::new(),
            label: label.into(),
            kind: FieldKind::Text,
            value: FieldValue::Public(value.into()),
            section: None,
            agent_visible: false,
            extra: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// A concealed field holding secret material.
    #[must_use]
    pub fn concealed(label: impl Into<String>, value: Secret) -> Self {
        Self {
            id: FieldId::new(),
            label: label.into(),
            kind: FieldKind::Concealed,
            value: FieldValue::Secret(value),
            section: None,
            agent_visible: false,
            extra: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// A one-time-password field.
    ///
    /// The stored value is the whole `otpauth://` URI, held as [`Secret`] because the URI *is*
    /// the credential (vault-format.md §5.3): the algorithm, digit count, period and issuer live
    /// inside it and are read back out by [`Field::totp_generator`] rather than being stored beside it.
    #[must_use]
    pub fn totp(label: impl Into<String>, uri: Secret) -> Self {
        Self {
            id: FieldId::new(),
            label: label.into(),
            kind: FieldKind::Totp,
            value: FieldValue::Secret(uri),
            section: None,
            agent_visible: false,
            extra: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// Whether this field could be an item's primary secret ([`Item::primary_secret_field`]):
    /// secret material, and not a one-time-password seed — filling or copying an `otpauth://`
    /// URI where a password belongs would be useless and a disclosure of the shared seed.
    #[must_use]
    pub fn is_primary_secret_candidate(&self) -> bool {
        self.value.is_secret() && self.kind != FieldKind::Totp
    }

    /// Whether this field holds a one-time-password seed.
    #[must_use]
    pub fn is_totp(&self) -> bool {
        self.kind == FieldKind::Totp && self.value.has_value()
    }

    /// The configured generator this field describes.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Totp`] if the field is not a TOTP field, holds no value, or holds
    /// something that is not a parseable `otpauth://` URI.
    pub fn totp_generator(&self) -> crate::Result<crate::totp::Totp> {
        if self.kind != FieldKind::Totp {
            return Err(crate::Error::Totp("that field is not a one-time password"));
        }
        let uri = self
            .value
            .as_secret()
            .and_then(Secret::expose_str)
            .ok_or(crate::Error::Totp(
                "that field has no one-time-password setup",
            ))?;
        crate::totp::Totp::parse_uri(uri)
    }

    /// Whether this is a one-time-password field whose setup would generate codes — what
    /// [`Self::totp_generator`] would answer with `Ok` — decided without decoding the seed.
    ///
    /// For a caller that asks before anything is approved and must not leave a copy of the seed
    /// behind for asking: it reads the URI where it lies, in this field's own zeroizing buffer
    /// ([`crate::totp::Totp::check_uri`]).
    #[must_use]
    pub fn has_working_totp(&self) -> bool {
        self.kind == FieldKind::Totp
            && self
                .value
                .as_secret()
                .and_then(Secret::expose_str)
                .is_some_and(|uri| crate::totp::Totp::check_uri(uri).is_ok())
    }

    /// Metadata-only view.
    #[must_use]
    pub fn summary(&self) -> FieldSummary {
        FieldSummary {
            id: self.id,
            label: self.label.clone(),
            kind: self.kind,
            concealed: self.value.is_secret(),
            has_value: self.value.has_value(),
            section: self.section.clone(),
            agent_visible: self.agent_visible,
        }
    }
}

/// One retired value of a field — a password the user has since rotated away from.
///
/// The value is a full [`FieldValue`], so a retired password is a [`Secret`] and lives under
/// exactly the same guarantees as the current one: no `Serialize` of its own, no `Display`, no
/// `Clone`, `Debug` redacted, zeroized on drop. That is the whole reason this type exists rather
/// than a string in [`Item::extra`] — `extra` is `ciborium::Value`, which is printable, and a
/// retired password is still a password.
///
/// The surrounding fields are metadata: a label, a kind, when the value stopped being current.
#[derive(Debug, Serialize, Deserialize)]
pub struct FieldRevision {
    /// The field this value used to be in, when that field is still on the item.
    ///
    /// `None` for a revision that arrived from an import, where the source's history entries are
    /// not tied to a field this build created.
    #[serde(default)]
    pub field_id: Option<FieldId>,
    /// The label the field carried at the time. Metadata.
    pub label: String,
    /// The kind the field carried at the time.
    pub kind: FieldKind,
    /// The retired value.
    pub value: FieldValue,
    /// When the value stopped being current, in Unix seconds.
    pub retired_at: u64,
    /// Keys this build does not recognize, preserved verbatim (vault-format §9 rule 1) — so an
    /// older build rewriting an item does not strip what a newer one recorded about a retired
    /// value.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl FieldRevision {
    /// A retired concealed value.
    #[must_use]
    pub fn concealed(label: impl Into<String>, value: Secret, retired_at: u64) -> Self {
        Self {
            field_id: None,
            label: label.into(),
            kind: FieldKind::Concealed,
            value: FieldValue::Secret(value),
            retired_at,
            unknown: BTreeMap::new(),
        }
    }
}

/// A stored item.
#[derive(Debug, Serialize, Deserialize)]
pub struct Item {
    /// Identifier.
    pub id: ItemId,
    /// The logical vault this item lives in.
    pub vault_id: VaultId,
    /// Category.
    pub category: Category,
    /// Title.
    pub title: String,
    /// Fields, in display order.
    pub fields: Vec<Field>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Associated URLs.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Free-form note — secret material, like a concealed field (ADR-0038 user decision 3).
    ///
    /// Secure Notes and free-text notes routinely hold recovery codes, PINs and security-question
    /// answers, so a note is held as [`SecretText`] in memory: redacted in `Debug`, never cloned,
    /// zeroized on drop, and absent from [`Item::summary`] and every other metadata view. It is
    /// never searched or matched, by the agent or by the app (see `kagisecure-ffi`'s
    /// `list_items`): a search over note text would be an oracle a UI-driving process could
    /// query one guess at a time without ever passing the presence gate.
    ///
    /// On disk it is exactly what it was as `Option<String>` — a CBOR text string or `null` — so
    /// this did not move `body.schema` (vault-format §5, §9).
    #[serde(default, with = "secret::cbor_text_opt")]
    pub notes: Option<SecretText>,
    /// Marked favourite in a UI.
    #[serde(default)]
    pub favorite: bool,
    /// Archived.
    #[serde(default)]
    pub archived: bool,
    /// When the item was moved to the trash, in Unix seconds; `None` if it is not in the trash.
    ///
    /// A soft delete. The UI's Trash section (ui-spec.md §2.2) needs to know *when* an item was
    /// binned so a retention window can be enforced later, so this is a timestamp rather than a
    /// boolean. Additive and `#[serde(default)]`, so it does not bump `body.schema`
    /// (vault-format.md §9) and an older file reads back as "not trashed".
    #[serde(default)]
    pub trashed_at: Option<u64>,
    /// Whether agents may see this item. Default-deny (threat-model M-9).
    #[serde(default)]
    pub agent_visible: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
    /// Retired values of this item's fields — password history — oldest first.
    ///
    /// Secret-typed on purpose (see [`FieldRevision`]), and deliberately *not* part of any
    /// metadata surface:
    ///
    /// * it is absent from [`Item::summary`], so `describe_item` and every other
    ///   [`crate::proto`]-shaped view cannot report it, not even a count. A crate without the
    ///   `secret-material` feature cannot name this field at all;
    /// * it is never searched or matched — [`Item::field`] looks only at [`Item::fields`], so a
    ///   retired password can never be resolved by a caller asking for a field;
    /// * `agent_visible` on the item grants nothing here. History is out of the agent's reach
    ///   regardless of what the user opted into for the current values (threat-model M-9).
    ///
    /// Additive, `#[serde(default)]` and skipped when empty, so a vault with no history is
    /// byte-identical to one written before this key existed and `body.schema` does not move
    /// (vault-format §9) — the same treatment [`Item::trashed_at`] got.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<FieldRevision>,
    /// Which field is this item's **primary secret** — the value "Copy password" (⇧⌘C, Quick
    /// Access ⏎), the detail pane's unfocused ⌘R, a browser fill and the presence prompt's
    /// "password" all mean — by [`FieldId`].
    ///
    /// By id, never by label or position: a label and the field order can both be changed in the
    /// edit sheet without a presence check, so a rule like "the field called *password*" or "the
    /// first concealed field" lets anything that can drive the UI relabel a PIN "password", or
    /// move it first, and have the next copy, fill or prompt pick it. The id cannot be moved that
    /// way. [`Item::from_template`] sets it; [`Item::pin_primary_secret`] fixes it, from the item
    /// as it stood before an edit, for an item written before this key existed. Read it through
    /// [`Item::primary_secret_field`].
    ///
    /// Additive, `#[serde(default)]` and skipped when `None`, so an item without it is
    /// byte-identical to one written before it existed and `body.schema` does not move
    /// (vault-format §9); an older build keeps it in [`Item::unknown`] and writes it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_secret: Option<FieldId>,
    /// Lossless passthrough for data a future or foreign version wrote and this build does not
    /// understand (vault-format §9 rule 1).
    #[serde(default)]
    pub extra: BTreeMap<String, ciborium::Value>,
    /// Top-level `Item` keys this build does not recognize, preserved verbatim (vault-format §9
    /// rule 1). See [`Field::unknown`] for why this is a field distinct from [`Item::extra`]:
    /// `extra` is importer-authored metadata under one named key, `unknown` is whatever top-level
    /// CBOR keys this build's decoder has no field for.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl Item {
    /// A new item in `vault_id` with the given category and title and no fields.
    #[must_use]
    pub fn new(vault_id: VaultId, category: Category, title: impl Into<String>) -> Self {
        let now = crate::unix_now();
        Self {
            id: ItemId::new(),
            vault_id,
            category,
            title: title.into(),
            fields: Vec::new(),
            tags: Vec::new(),
            urls: Vec::new(),
            notes: None,
            favorite: false,
            archived: false,
            trashed_at: None,
            agent_visible: false,
            created_at: now,
            updated_at: now,
            history: Vec::new(),
            primary_secret: None,
            extra: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// Show this item, and every one of its fields, to agents — or hide it and every field.
    ///
    /// The one switch bulk visibility changes and the "Show new items to agents" default use.
    /// Returns whether anything changed. Hiding clears the field flags too, so a later re-show
    /// does not bring back grants nobody remembers making (the single-item toggle's rule).
    pub fn set_agent_visible_all(&mut self, visible: bool) -> bool {
        let mut changed = self.agent_visible != visible;
        self.agent_visible = visible;
        for field in &mut self.fields {
            changed |= field.agent_visible != visible;
            field.agent_visible = visible;
        }
        changed
    }

    /// The item's primary secret ([`Item::primary_secret`]): the field "Copy password", a browser
    /// fill and the presence prompt's "password" all mean. `None` when there is none.
    ///
    /// * With a designation, exactly that field, and only while it is still secret material and
    ///   not a one-time-password seed. A designated field that was deleted is **not** replaced by
    ///   whatever concealed field is left: that would hand the role to a field nobody chose for
    ///   it.
    /// * Without one — an item written before the key existed, and not edited since — the first
    ///   field holding secret material that is not a one-time-password seed: what the app, the
    ///   extension and this designation's own [`Item::pin_primary_secret`] all agree on for such
    ///   an item. Never the label.
    #[must_use]
    pub fn primary_secret_field(&self) -> Option<&Field> {
        match self.primary_secret {
            Some(id) => self
                .fields
                .iter()
                .find(|f| f.id == id)
                .filter(|f| f.is_primary_secret_candidate()),
            None => self.fields.iter().find(|f| f.is_primary_secret_candidate()),
        }
    }

    /// Designate the primary secret of an item that has none recorded, from its fields as they
    /// are now — before an edit is applied, so the edit cannot choose it. Does nothing to an item
    /// that already has a designation, even a dangling one.
    pub fn pin_primary_secret(&mut self) {
        if self.primary_secret.is_none() {
            self.primary_secret = self
                .fields
                .iter()
                .find(|f| f.is_primary_secret_candidate())
                .map(|f| f.id);
        }
    }

    /// The item's username, if it has a public one: the field labelled `username`, or failing
    /// that `email` (case-insensitive), with a non-empty public value.
    ///
    /// A label is enough here, unlike for [`Item::primary_secret_field`]: a username is public —
    /// the list, the detail pane and a browser's `match` already show it — so a relabel can at
    /// worst make a copy pick another public value, never a secret one.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        let public = |label: &str| {
            self.fields
                .iter()
                .find(|f| f.label.eq_ignore_ascii_case(label))
                .and_then(|f| f.value.as_public())
                .filter(|v| !v.is_empty())
        };
        public("username").or_else(|| public("email"))
    }

    /// Look up a field by its id, or failing that by an exact label match.
    #[must_use]
    pub fn field(&self, reference: &str) -> Option<&Field> {
        if let Ok(id) = reference.parse::<FieldId>()
            && let Some(f) = self.fields.iter().find(|f| f.id == id)
        {
            return Some(f);
        }
        self.fields.iter().find(|f| f.label == reference)
    }

    /// Metadata-only view. This is what a future MCP surface is allowed to return.
    #[must_use]
    pub fn summary(&self) -> ItemSummary {
        ItemSummary {
            id: self.id,
            vault_id: self.vault_id,
            title: self.title.clone(),
            category: self.category.clone(),
            tags: self.tags.clone(),
            fields: self.fields.iter().map(Field::summary).collect(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            agent_visible: self.agent_visible,
            trashed: self.trashed_at.is_some(),
        }
    }

    /// Whether the item has a note with anything in it. A boolean, deliberately not a length —
    /// the same rule as [`FieldValue::has_value`].
    #[must_use]
    pub fn has_notes(&self) -> bool {
        self.notes.as_ref().is_some_and(|n| !n.is_empty())
    }

    /// Whether the item is in the trash.
    #[must_use]
    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    /// The item's first configured one-time-password field, if it has one.
    ///
    /// "First" rather than "the": nothing stops an item carrying two, and a caller that did not
    /// name a field wants the one the detail pane shows at the top.
    #[must_use]
    pub fn totp_field(&self) -> Option<&Field> {
        self.fields.iter().find(|f| f.is_totp())
    }

    /// Build an item from a category's default-field template (vault-format.md §5.4).
    ///
    /// The template lives in [`crate::proto`] so that every UI gets the same starting point from
    /// one place. Concealed fields start empty rather than absent, so the user sees the row they
    /// are expected to fill in.
    #[must_use]
    pub fn from_template(vault_id: VaultId, category: Category, title: impl Into<String>) -> Self {
        let mut item = Self::new(vault_id, category.clone(), title);
        for t in category.default_fields() {
            let mut field = if t.concealed {
                Field::concealed(t.label, Secret::new(Vec::new()))
            } else {
                Field::public(t.label, String::new())
            };
            field.kind = t.kind;
            item.fields.push(field);
        }
        // The template's first secret that is not a one-time password is the one its category is
        // about — a login's password, a card's number, an API credential's key — and recording it
        // now means no later relabel or reorder can move the role.
        item.pin_primary_secret();
        item
    }
}

#[cfg(test)]
mod primary_secret_tests {
    use super::*;

    fn concealed(label: &str, value: &str) -> Field {
        Field::concealed(label, Secret::new(value.as_bytes().to_vec()))
    }

    #[test]
    fn a_template_designates_its_primary_secret_by_id() {
        let login = Item::from_template(VaultId::new(), Category::Login, "L");
        let password = login.fields.iter().find(|f| f.label == "password").unwrap();
        assert_eq!(login.primary_secret, Some(password.id));

        let card = Item::from_template(VaultId::new(), Category::CreditCard, "C");
        let number = card.fields.iter().find(|f| f.label == "number").unwrap();
        assert_eq!(number.kind, FieldKind::CreditCardNumber);
        assert!(number.value.is_secret());
        assert_eq!(card.primary_secret, Some(number.id));

        let note = Item::from_template(VaultId::new(), Category::SecureNote, "N");
        assert_eq!(note.primary_secret, None);
        assert!(note.primary_secret_field().is_none());
    }

    #[test]
    fn relabelling_or_reordering_never_moves_the_primary_secret() {
        let mut item = Item::new(VaultId::new(), Category::Login, "Bank");
        item.fields.push(concealed("password", "the-password"));
        item.fields.push(concealed("PIN", "4321"));
        item.pin_primary_secret();
        let password = item.fields[0].id;

        // Relabel the PIN "password", the password something else, and move the PIN first.
        item.fields[1].label = "password".to_owned();
        item.fields[0].label = "old".to_owned();
        item.fields.swap(0, 1);
        assert_eq!(item.primary_secret_field().map(|f| f.id), Some(password));

        // A deleted designation is not handed to whatever concealed field is left.
        item.fields.retain(|f| f.id != password);
        assert!(item.primary_secret_field().is_none());
        item.pin_primary_secret();
        assert!(
            item.primary_secret_field().is_none(),
            "pinning never overwrites a designation, even a dangling one"
        );
    }

    #[test]
    fn an_undesignated_item_falls_back_to_its_first_non_totp_secret_and_pins_it() {
        let mut item = Item::new(VaultId::new(), Category::Login, "Legacy");
        item.fields.push(Field::public("username", "ada"));
        item.fields.push(Field::totp(
            "one-time password",
            Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec()),
        ));
        item.fields.push(concealed("passphrase", "pp"));
        item.fields.push(concealed("password", "pw"));
        let first_secret = item.fields[2].id;
        assert_eq!(
            item.primary_secret_field().map(|f| f.id),
            Some(first_secret),
            "position, never the label, and never the TOTP seed"
        );
        item.pin_primary_secret();
        assert_eq!(item.primary_secret, Some(first_secret));
        item.fields.swap(2, 3);
        assert_eq!(
            item.primary_secret_field().map(|f| f.id),
            Some(first_secret)
        );
    }

    #[test]
    fn a_designation_that_stopped_being_secret_is_no_primary_secret() {
        let mut item = Item::new(VaultId::new(), Category::Login, "L");
        item.fields.push(concealed("password", "pw"));
        item.pin_primary_secret();
        item.fields[0].value = FieldValue::Public("now public".to_owned());
        assert!(item.primary_secret_field().is_none());
    }

    #[test]
    fn the_username_is_a_public_username_or_email_field() {
        let mut item = Item::new(VaultId::new(), Category::Login, "L");
        assert_eq!(item.username(), None);
        item.fields.push(concealed("username", "secret-name"));
        assert_eq!(item.username(), None, "never a secret");
        item.fields.push(Field::public("email", "ada@example.com"));
        assert_eq!(item.username(), Some("ada@example.com"));
        item.fields.insert(0, Field::public("Username", "ada"));
        assert_eq!(item.username(), Some("ada"));
    }

    #[test]
    fn the_designation_round_trips_and_is_absent_when_unset() {
        let mut item = Item::new(VaultId::new(), Category::Login, "L");
        let mut bytes = Vec::new();
        ciborium::into_writer(&item, &mut bytes).unwrap();
        let map: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let keys: Vec<String> = map
            .as_map()
            .unwrap()
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_owned))
            .collect();
        assert!(!keys.iter().any(|k| k == "primary_secret"), "{keys:?}");

        item.fields.push(concealed("password", "pw"));
        item.pin_primary_secret();
        let mut bytes = Vec::new();
        ciborium::into_writer(&item, &mut bytes).unwrap();
        let back: Item = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.primary_secret, item.primary_secret);
        assert!(back.unknown.is_empty());
    }
}

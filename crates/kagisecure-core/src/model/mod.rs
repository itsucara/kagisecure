//! The item model (vault-format §5).
//!
//! Only compiled with the `secret-material` feature; metadata-only mirrors of these types live in
//! [`crate::proto`] and are always available.

pub mod env;
mod secret;

pub use env::{EnvVar, Environment, VarSource};
pub use secret::Secret;

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
    /// Unix seconds.
    #[serde(default)]
    pub created_at: u64,
}

impl VaultMeta {
    /// A fresh logical vault with the given display name, invisible to agents.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: VaultId::new(),
            name: name.into(),
            agent_visible: false,
            created_at: crate::unix_now(),
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
        }
    }
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
        }
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
    /// Free-form note.
    #[serde(default)]
    pub notes: Option<String>,
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
    /// Lossless passthrough for data a future or foreign version wrote and this build does not
    /// understand (vault-format §9 rule 1).
    #[serde(default)]
    pub extra: BTreeMap<String, ciborium::Value>,
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
            extra: BTreeMap::new(),
        }
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
        item
    }
}

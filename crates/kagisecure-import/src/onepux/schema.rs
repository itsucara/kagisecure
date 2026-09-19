//! `export.data` and `export.attributes`, as concrete Rust types.
//!
//! Everything here is a plain struct with `#[serde(default)]`, not a [`serde_json::Value`] tree.
//! That is a security property, not a style preference: a concrete struct bounds what a hostile
//! or corrupt export can make this process allocate, and it makes "which strings in this program
//! might be a password" answerable by reading one file.
//!
//! The two exceptions are the `extra` maps flattened onto [`ItemNode`], [`Overview`], [`Details`]
//! and [`SectionField`], which catch keys a later 1PUX version adds, and [`FieldValueNode`],
//! whose whole shape is "an object whose single key is the type". Both are bounded by
//! `serde_json`'s own 128-level recursion limit.
//!
//! **Nothing in this module is ever put in a report.** The structs hold the export's plaintext;
//! the strings that turn out to be secret material are *moved* into
//! [`kagisecure_core::Secret`], whose buffer is zeroized on drop, rather than copied out of
//! here.

use serde::Deserialize;
use serde_json::{Map, Value};

/// `export.attributes` — the archive's own header.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportAttributes {
    /// Format version. `3` in every export seen so far.
    pub version: Option<u32>,
    /// `"1Password Unencrypted Export"`.
    pub description: String,
    /// When the export was made. A string or a number depending on the build, so it is kept as
    /// written and only ever echoed as metadata.
    pub created_at: Option<Value>,
}

/// `export.data` — the whole export.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportData {
    /// One entry per 1Password account in the export.
    pub accounts: Vec<Account>,
}

/// One 1Password account.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Account {
    /// Account metadata.
    pub attrs: AccountAttrs,
    /// The account's vaults.
    pub vaults: Vec<VaultNode>,
}

/// `accounts[].attrs`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AccountAttrs {
    /// The account's name as the user set it.
    pub account_name: String,
    /// The person's name.
    pub name: String,
    /// The sign-in address. Metadata; never used in a report.
    pub email: String,
    /// The account's own identifier.
    pub uuid: String,
}

impl AccountAttrs {
    /// The name to show for this account, preferring the account's name over the person's.
    #[must_use]
    pub fn display_name(&self) -> &str {
        for candidate in [self.account_name.as_str(), self.name.as_str()] {
            if !candidate.trim().is_empty() {
                return candidate.trim();
            }
        }
        "1Password"
    }
}

/// One vault inside an account.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultNode {
    /// Vault metadata.
    pub attrs: VaultAttrs,
    /// The items in it.
    pub items: Vec<ItemNode>,
}

/// `accounts[].vaults[].attrs`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultAttrs {
    /// The vault's identifier.
    pub uuid: String,
    /// Its description.
    pub desc: String,
    /// Its display name.
    pub name: String,
    /// `"P"` personal, `"U"` user-created, `"E"` everyone.
    #[serde(rename = "type")]
    pub vault_type: String,
}

impl VaultAttrs {
    /// The name to show for this vault.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if self.name.trim().is_empty() {
            "1Password"
        } else {
            self.name.trim()
        }
    }
}

/// One item.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ItemNode {
    /// The item's identifier, kept as a dedupe key.
    pub uuid: String,
    /// Non-zero means the user marked it a favourite.
    pub fav_index: i64,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
    /// `"active"`, `"archived"` or `"trashed"`.
    pub state: String,
    /// The category id; see [`super::category`].
    pub category_uuid: String,
    /// What 1Password shows in a list.
    pub overview: Overview,
    /// Everything else.
    pub details: Details,
    /// Keys this build does not know. Only their *names* are ever kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `items[].overview`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Overview {
    /// The item's title.
    pub title: String,
    /// The line under it — usually the username. Metadata, not imported as a field.
    pub subtitle: String,
    /// The primary URL.
    pub url: Option<String>,
    /// Additional URLs.
    pub urls: Vec<UrlNode>,
    /// The user's tags.
    pub tags: Vec<String>,
    /// `ps`, `pbe`, `pgrng` and anything else: password-strength and generator state.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One `overview.urls[]` entry.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UrlNode {
    /// What the user called it.
    pub label: String,
    /// The URL.
    pub url: String,
}

/// `items[].details`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Details {
    /// The web form's fields.
    pub login_fields: Vec<LoginField>,
    /// The note, as plain text.
    pub notes_plain: Option<String>,
    /// Custom sections.
    pub sections: Vec<Section>,
    /// Retired passwords. Imported (plan §9 decision 2), not dropped.
    pub password_history: Vec<HistoryEntry>,
    /// The attachment on a Document item.
    pub document_attributes: Option<DocumentAttributes>,
    /// Keys this build does not know — `passkeys`, `watchtowerExclusions`, whatever comes next.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One `details.loginFields[]` entry.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoginField {
    /// What was in the form control.
    pub value: String,
    /// The form control's `name` attribute.
    pub name: String,
    /// `"T"`, `"E"`, `"U"`, `"N"`, `"P"`, `"A"` or `"TEL"` — the published list.
    #[serde(rename = "type")]
    pub field_type: String,
    /// `"username"`, `"password"`, or absent.
    pub designation: Option<String>,
}

impl LoginField {
    /// The label to give this field: its designation, else the form control's name.
    #[must_use]
    pub fn label(&self) -> &str {
        for candidate in [
            self.designation.as_deref().unwrap_or_default(),
            self.name.as_str(),
        ] {
            if !candidate.trim().is_empty() {
                return candidate.trim();
            }
        }
        "form field"
    }
}

/// One `details.sections[]` entry.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Section {
    /// The heading a user sees. Empty for the item's loose fields.
    pub title: String,
    /// 1Password's internal name for the section.
    pub name: String,
    /// The fields in it.
    pub fields: Vec<SectionField>,
}

impl Section {
    /// The section name to put on a field, or `None` for an untitled section.
    #[must_use]
    pub fn section_name(&self) -> Option<&str> {
        let title = self.title.trim();
        if title.is_empty() { None } else { Some(title) }
    }
}

/// One `details.sections[].fields[]` entry.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SectionField {
    /// The label a user sees.
    pub title: String,
    /// 1Password's own field id.
    pub id: String,
    /// The typed value.
    pub value: FieldValueNode,
    /// 1Password's "this is sensitive" flag. A hint [`super::conceal`] treats as decisive.
    pub guarded: bool,
    /// Whether the value is a multi-line string.
    pub multiline: bool,
    /// `inputTraits` and anything else.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SectionField {
    /// The label to give this field: its title, else its id.
    #[must_use]
    pub fn label(&self) -> &str {
        for candidate in [self.title.as_str(), self.id.as_str()] {
            if !candidate.trim().is_empty() {
                return candidate.trim();
            }
        }
        "field"
    }
}

/// One `details.passwordHistory[]` entry.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HistoryEntry {
    /// The retired password. Absent or empty means the entry cannot be imported.
    pub value: Option<String>,
    /// When it stopped being current, in Unix seconds. Often absent.
    pub time: Option<i64>,
}

/// `details.documentAttributes` — an attachment's metadata.
///
/// The bytes live in the archive's `files/` directory and are **not** read: a kagisecure item has
/// no attachments (plan §0), so the file is counted as dropped and only this metadata is kept.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DocumentAttributes {
    /// The file's name.
    pub file_name: String,
    /// Its identifier, which is also half of its `files/` entry name.
    pub document_id: String,
    /// Its size in bytes.
    pub decrypted_size: Option<u64>,
}

/// A 1PUX typed value: an object whose single key names the type.
///
/// `{"concealed": "hunter2"}`, `{"totp": "otpauth://..."}`, `{"address": { "street": ... }}`.
/// Held as a raw [`Value`] rather than an enum so that a key this build has never seen is data
/// rather than a parse failure — losing an item because 1Password added a field type would be a
/// worse outcome than not understanding the field.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct FieldValueNode(pub Value);

impl FieldValueNode {
    /// The type key and the value under it, when the node is a one-key object.
    ///
    /// A node with no keys, more than one key, or a shape that is not an object at all returns
    /// `None`; the caller then treats the type as unknown, which [`super::conceal`] handles by
    /// failing closed.
    #[must_use]
    pub fn single(&self) -> Option<(&str, &Value)> {
        let object = self.0.as_object()?;
        if object.len() != 1 {
            return None;
        }
        object.iter().next().map(|(k, v)| (k.as_str(), v))
    }

    /// The type key, when there is exactly one.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.single().map(|(key, _)| key)
    }

    /// Take the value out, leaving [`Value::Null`] behind.
    ///
    /// Taking rather than cloning matters: for a concealed field this string is a password, and
    /// the only copy of it should be the one that is about to be moved into a
    /// [`kagisecure_core::Secret`] and zeroized on drop.
    #[must_use]
    pub fn take_single(&mut self) -> Option<(String, Value)> {
        let object = self.0.as_object_mut()?;
        if object.len() != 1 {
            return None;
        }
        let key = object.keys().next()?.clone();
        let value = object.get_mut(&key).map(std::mem::take)?;
        Some((key, value))
    }

    /// Whether the node carries nothing at all.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        match &self.0 {
            Value::Null => true,
            Value::Object(o) => o.is_empty(),
            _ => false,
        }
    }
}

/// A scalar rendered as a string, taking ownership of it.
///
/// Numbers and booleans become their JSON spelling; objects and arrays have no scalar rendering
/// and return `None`, which is how the caller tells "a value I can store" from "a shape I have to
/// walk".
#[must_use]
pub fn take_scalar(value: &mut Value) -> Option<String> {
    match std::mem::take(value) {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_item_missing_every_optional_key_still_parses() {
        let node: ItemNode = serde_json::from_value(json!({ "uuid": "u1" })).unwrap();
        assert_eq!(node.uuid, "u1");
        assert_eq!(node.fav_index, 0);
        assert!(node.overview.title.is_empty());
        assert!(node.details.login_fields.is_empty());
        assert!(node.details.notes_plain.is_none());
    }

    #[test]
    fn a_null_note_is_no_note() {
        let details: Details = serde_json::from_value(json!({ "notesPlain": null })).unwrap();
        assert!(details.notes_plain.is_none());
    }

    #[test]
    fn unknown_keys_land_in_the_flattened_extras() {
        let node: ItemNode =
            serde_json::from_value(json!({ "uuid": "u1", "passkeys": [{ "credentialId": "a" }] }))
                .unwrap();
        assert!(node.extra.contains_key("passkeys"));

        let details: Details =
            serde_json::from_value(json!({ "watchtowerExclusions": ["weak"] })).unwrap();
        assert!(details.extra.contains_key("watchtowerExclusions"));
    }

    #[test]
    fn a_value_node_reports_its_single_key_and_gives_the_value_up_once() {
        let mut node: FieldValueNode =
            serde_json::from_value(json!({ "concealed": "hunter2" })).unwrap();
        assert_eq!(node.key(), Some("concealed"));
        let (key, mut value) = node.take_single().unwrap();
        assert_eq!(key, "concealed");
        assert_eq!(take_scalar(&mut value).as_deref(), Some("hunter2"));
        // The node no longer holds the password.
        assert_eq!(node.0["concealed"], Value::Null);
    }

    #[test]
    fn a_node_that_is_not_a_one_key_object_has_no_key() {
        for shape in [
            json!({}),
            json!("bare"),
            json!({ "a": 1, "b": 2 }),
            json!(null),
        ] {
            let node: FieldValueNode = serde_json::from_value(shape).unwrap();
            assert_eq!(node.key(), None);
        }
    }
}

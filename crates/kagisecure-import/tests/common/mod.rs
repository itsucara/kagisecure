//! Synthetic 1PUX fixtures, built in code.
//!
//! A real `sample.1pux` will turn up eventually and `probe_sample_categories` (WP1) will read it.
//! Until then — and afterwards too, for everything a real export cannot demonstrate — the tests
//! build their own archives here.
//!
//! Generating rather than checking in a binary fixture is the point:
//!
//! * a zip bomb has to be *constructed*, and a checked-in one is a 40 MB file in the repository
//!   that every clone pays for;
//! * a `../../etc/passwd` entry name has to survive `git checkout` on three platforms, which it
//!   does not;
//! * a hostile case ("10 001 fields", "a field whose type key nobody has ever seen") is one line
//!   here and an unreviewable blob otherwise;
//! * and a fixture nobody can read is a fixture nobody can change.
//!
//! [`ItemSpec`] is deliberately over-general: it can emit fields whose type key is arbitrary
//! JSON, sections with no title, history entries with no timestamp. WP1's parser has to cope with
//! all of that, so the fixture builder has to be able to produce it.
//!
//! Nothing here asserts anything. It only builds bytes.

#![allow(dead_code)]

use std::io::{Cursor, Write};

use serde_json::{Map, Value, json};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

// ---------------------------------------------------------------------------------------------
// Item specs
// ---------------------------------------------------------------------------------------------

/// One `details.loginFields[]` entry.
#[derive(Clone, Debug)]
pub struct LoginFieldSpec {
    /// `value`.
    pub value: String,
    /// `name` — the form control's name.
    pub name: String,
    /// `type` — `"T"`, `"E"`, `"U"`, `"N"`, `"P"`, `"A"`, `"TEL"`.
    pub field_type: String,
    /// `designation` — `"username"` or `"password"`, usually.
    pub designation: Option<String>,
}

impl LoginFieldSpec {
    /// A field of the given type.
    #[must_use]
    pub fn new(name: &str, field_type: &str, value: &str) -> Self {
        Self {
            value: value.to_owned(),
            name: name.to_owned(),
            field_type: field_type.to_owned(),
            designation: None,
        }
    }

    /// The standard username field.
    #[must_use]
    pub fn username(value: &str) -> Self {
        Self::new("username", "T", value).designated("username")
    }

    /// The standard password field.
    #[must_use]
    pub fn password(value: &str) -> Self {
        Self::new("password", "P", value).designated("password")
    }

    /// Give the field a designation.
    #[must_use]
    pub fn designated(mut self, designation: &str) -> Self {
        self.designation = Some(designation.to_owned());
        self
    }

    fn to_json(&self) -> Value {
        let mut node = json!({
            "value": self.value,
            "name": self.name,
            "type": self.field_type,
        });
        if let Some(designation) = &self.designation {
            node["designation"] = json!(designation);
        }
        node
    }
}

/// One `details.sections[].fields[]` entry.
///
/// `value` is the single-key object 1PUX uses for typed values — `{"concealed": "..."}`,
/// `{"totp": "..."}`, `{"address": {...}}` — and is given as a raw [`Value`] so a test can put
/// a key nobody has ever seen in there and check the fail-closed rule.
#[derive(Clone, Debug)]
pub struct SectionFieldSpec {
    /// `title` — the label a user sees.
    pub title: String,
    /// `id` — 1Password's own field id.
    pub id: String,
    /// `value`, as a whole JSON object.
    pub value: Value,
    /// `guarded`.
    pub guarded: bool,
    /// `multiline`.
    pub multiline: bool,
    /// Anything else, flattened into the field node.
    pub extra: Map<String, Value>,
}

impl SectionFieldSpec {
    /// A field whose value object is `{ <type_key>: <value> }`.
    #[must_use]
    pub fn typed(title: &str, type_key: &str, value: Value) -> Self {
        Self {
            title: title.to_owned(),
            id: format!("{title}-id"),
            value: json!({ type_key: value }),
            guarded: false,
            multiline: false,
            extra: Map::new(),
        }
    }

    /// A `{"string": "..."}` field.
    #[must_use]
    pub fn string(title: &str, value: &str) -> Self {
        Self::typed(title, "string", json!(value))
    }

    /// A `{"concealed": "..."}` field.
    #[must_use]
    pub fn concealed(title: &str, value: &str) -> Self {
        Self::typed(title, "concealed", json!(value))
    }

    /// A `{"totp": "..."}` field.
    #[must_use]
    pub fn totp(title: &str, value: &str) -> Self {
        Self::typed(title, "totp", json!(value))
    }

    /// Set the field's 1Password id.
    #[must_use]
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = id.to_owned();
        self
    }

    /// Set `guarded`.
    #[must_use]
    pub fn guarded(mut self, guarded: bool) -> Self {
        self.guarded = guarded;
        self
    }

    /// Set `multiline`.
    #[must_use]
    pub fn multiline(mut self, multiline: bool) -> Self {
        self.multiline = multiline;
        self
    }

    /// Add an arbitrary key to the field node.
    #[must_use]
    pub fn with_extra(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_owned(), value);
        self
    }

    fn to_json(&self) -> Value {
        let mut node = Map::new();
        node.insert("title".to_owned(), json!(self.title));
        node.insert("id".to_owned(), json!(self.id));
        node.insert("value".to_owned(), self.value.clone());
        node.insert("guarded".to_owned(), json!(self.guarded));
        node.insert("multiline".to_owned(), json!(self.multiline));
        for (key, value) in &self.extra {
            node.insert(key.clone(), value.clone());
        }
        Value::Object(node)
    }
}

/// One `details.sections[]` entry.
#[derive(Clone, Debug)]
pub struct SectionSpec {
    /// `title` — becomes `Field::section`.
    pub title: String,
    /// `name` — 1Password's internal section name.
    pub name: String,
    /// The fields in it.
    pub fields: Vec<SectionFieldSpec>,
}

impl SectionSpec {
    /// A named section holding these fields.
    #[must_use]
    pub fn new(title: &str, fields: Vec<SectionFieldSpec>) -> Self {
        Self {
            title: title.to_owned(),
            name: format!("{title}-name"),
            fields,
        }
    }

    /// A section with no title, as 1Password writes for an item's top-level extra fields.
    #[must_use]
    pub fn untitled(fields: Vec<SectionFieldSpec>) -> Self {
        Self {
            title: String::new(),
            name: "Section_untitled".to_owned(),
            fields,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "title": self.title,
            "name": self.name,
            "fields": self.fields.iter().map(SectionFieldSpec::to_json).collect::<Vec<_>>(),
        })
    }
}

/// One `details.passwordHistory[]` entry — a retired password and when it stopped being current.
///
/// History is **imported**, not dropped (plan §9 decision 2), so these values are real secrets in
/// the fixture and `tests/report_canary.rs` seeds a marker through one of them.
#[derive(Clone, Debug)]
pub struct HistorySpec {
    /// `value`.
    pub value: String,
    /// `time`, in Unix seconds. `None` writes an entry with no timestamp, which the parser has to
    /// cope with.
    pub time: Option<i64>,
}

impl HistorySpec {
    /// A retired value with a timestamp.
    #[must_use]
    pub fn new(value: &str, time: i64) -> Self {
        Self {
            value: value.to_owned(),
            time: Some(time),
        }
    }

    /// A retired value the export gave no timestamp for.
    #[must_use]
    pub fn undated(value: &str) -> Self {
        Self {
            value: value.to_owned(),
            time: None,
        }
    }

    fn to_json(&self) -> Value {
        match self.time {
            Some(time) => json!({ "value": self.value, "time": time }),
            None => json!({ "value": self.value }),
        }
    }
}

/// One `details.documentAttributes` / attachment entry, plus the bytes to put in `files/`.
#[derive(Clone, Debug)]
pub struct DocumentSpec {
    /// `documentId`.
    pub document_id: String,
    /// `fileName`.
    pub file_name: String,
    /// `decryptedSize`.
    pub decrypted_size: u64,
    /// The bytes written to `files/<documentId>___<fileName>`.
    pub contents: Vec<u8>,
}

impl DocumentSpec {
    /// An attachment with the given name and contents.
    #[must_use]
    pub fn new(document_id: &str, file_name: &str, contents: &[u8]) -> Self {
        Self {
            document_id: document_id.to_owned(),
            file_name: file_name.to_owned(),
            decrypted_size: contents.len() as u64,
            contents: contents.to_vec(),
        }
    }

    /// The entry name 1PUX gives this attachment.
    #[must_use]
    pub fn entry_name(&self) -> String {
        format!("files/{}___{}", self.document_id, self.file_name)
    }

    fn to_json(&self) -> Value {
        json!({
            "fileName": self.file_name,
            "documentId": self.document_id,
            "decryptedSize": self.decrypted_size,
        })
    }
}

/// One item, and which account and vault it lives in.
#[derive(Clone, Debug)]
pub struct ItemSpec {
    /// The account's display name. Items are grouped by this; more than one account changes how
    /// vaults are named (plan §9 decision 7).
    pub account: String,
    /// The vault's display name.
    pub vault: String,
    /// The vault's `type` — `"P"` personal, `"U"` user-created, `"E"` everyone.
    pub vault_type: String,
    /// `uuid`.
    pub uuid: String,
    /// `categoryUuid` — `"001"` login, `"002"` credit card, and so on.
    pub category_uuid: String,
    /// `overview.title`.
    pub title: String,
    /// `overview.subtitle`.
    pub subtitle: String,
    /// `overview.url`.
    pub url: Option<String>,
    /// `overview.urls[]`, as `(label, url)`.
    pub urls: Vec<(String, String)>,
    /// `overview.tags[]`.
    pub tags: Vec<String>,
    /// `favIndex`. Non-zero means favourite.
    pub fav_index: i64,
    /// `state` — `"active"`, `"archived"` or `"trashed"`.
    pub state: String,
    /// `createdAt`, Unix seconds.
    pub created_at: i64,
    /// `updatedAt`, Unix seconds.
    pub updated_at: i64,
    /// `details.loginFields[]`.
    pub login_fields: Vec<LoginFieldSpec>,
    /// `details.sections[]`.
    pub sections: Vec<SectionSpec>,
    /// `details.notesPlain`.
    pub notes_plain: Option<String>,
    /// `details.passwordHistory[]`.
    pub password_history: Vec<HistorySpec>,
    /// `details.documentAttributes` and the `files/` entries that go with them.
    pub documents: Vec<DocumentSpec>,
    /// Arbitrary keys flattened into the item node, for "what does the parser do with a key it
    /// has never seen" tests.
    pub extra: Map<String, Value>,
    /// Arbitrary keys flattened into the `details` node.
    pub details_extra: Map<String, Value>,
}

impl Default for ItemSpec {
    fn default() -> Self {
        Self {
            account: "Ada Lovelace".to_owned(),
            vault: "Personal".to_owned(),
            vault_type: "P".to_owned(),
            uuid: "aaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            category_uuid: "001".to_owned(),
            title: "Untitled".to_owned(),
            subtitle: String::new(),
            url: None,
            urls: Vec::new(),
            tags: Vec::new(),
            fav_index: 0,
            state: "active".to_owned(),
            created_at: 1_600_000_000,
            updated_at: 1_700_000_000,
            login_fields: Vec::new(),
            sections: Vec::new(),
            notes_plain: None,
            password_history: Vec::new(),
            documents: Vec::new(),
            extra: Map::new(),
            details_extra: Map::new(),
        }
    }
}

impl ItemSpec {
    /// A login item with a title, a URL, a username and a password.
    #[must_use]
    pub fn login(uuid: &str, title: &str, url: &str, username: &str, password: &str) -> Self {
        Self {
            uuid: uuid.to_owned(),
            title: title.to_owned(),
            url: Some(url.to_owned()),
            login_fields: vec![
                LoginFieldSpec::username(username),
                LoginFieldSpec::password(password),
            ],
            ..Self::default()
        }
    }

    /// Put this item in a named vault.
    #[must_use]
    pub fn in_vault(mut self, vault: &str) -> Self {
        self.vault = vault.to_owned();
        self
    }

    /// Put this item in a named account.
    #[must_use]
    pub fn in_account(mut self, account: &str) -> Self {
        self.account = account.to_owned();
        self
    }

    /// Set the category uuid.
    #[must_use]
    pub fn category(mut self, category_uuid: &str) -> Self {
        self.category_uuid = category_uuid.to_owned();
        self
    }

    /// Set `state`.
    #[must_use]
    pub fn state(mut self, state: &str) -> Self {
        self.state = state.to_owned();
        self
    }

    /// Set `favIndex`.
    #[must_use]
    pub fn fav_index(mut self, fav_index: i64) -> Self {
        self.fav_index = fav_index;
        self
    }

    /// Set the timestamps.
    #[must_use]
    pub fn timestamps(mut self, created_at: i64, updated_at: i64) -> Self {
        self.created_at = created_at;
        self.updated_at = updated_at;
        self
    }

    /// Add tags.
    #[must_use]
    pub fn tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(|t| (*t).to_owned()).collect();
        self
    }

    /// Add an `overview.urls[]` entry.
    #[must_use]
    pub fn with_url(mut self, label: &str, url: &str) -> Self {
        self.urls.push((label.to_owned(), url.to_owned()));
        self
    }

    /// Set `details.notesPlain`.
    #[must_use]
    pub fn notes(mut self, notes: &str) -> Self {
        self.notes_plain = Some(notes.to_owned());
        self
    }

    /// Add a section.
    #[must_use]
    pub fn with_section(mut self, section: SectionSpec) -> Self {
        self.sections.push(section);
        self
    }

    /// Add a login field.
    #[must_use]
    pub fn with_login_field(mut self, field: LoginFieldSpec) -> Self {
        self.login_fields.push(field);
        self
    }

    /// Add a password-history entry.
    #[must_use]
    pub fn with_history(mut self, entry: HistorySpec) -> Self {
        self.password_history.push(entry);
        self
    }

    /// Add an attachment.
    #[must_use]
    pub fn with_document(mut self, document: DocumentSpec) -> Self {
        self.documents.push(document);
        self
    }

    /// Add an arbitrary key to the item node.
    #[must_use]
    pub fn with_extra(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_owned(), value);
        self
    }

    /// Add an arbitrary key to the `details` node.
    #[must_use]
    pub fn with_details_extra(mut self, key: &str, value: Value) -> Self {
        self.details_extra.insert(key.to_owned(), value);
        self
    }

    fn to_json(&self) -> Value {
        let mut overview = Map::new();
        overview.insert("title".to_owned(), json!(self.title));
        overview.insert("subtitle".to_owned(), json!(self.subtitle));
        if let Some(url) = &self.url {
            overview.insert("url".to_owned(), json!(url));
        }
        overview.insert(
            "urls".to_owned(),
            json!(
                self.urls
                    .iter()
                    .map(|(label, url)| json!({ "label": label, "url": url }))
                    .collect::<Vec<_>>()
            ),
        );
        overview.insert("tags".to_owned(), json!(self.tags));

        let mut details = Map::new();
        details.insert(
            "loginFields".to_owned(),
            json!(
                self.login_fields
                    .iter()
                    .map(LoginFieldSpec::to_json)
                    .collect::<Vec<_>>()
            ),
        );
        details.insert(
            "notesPlain".to_owned(),
            self.notes_plain.as_ref().map_or(Value::Null, |n| json!(n)),
        );
        details.insert(
            "sections".to_owned(),
            json!(
                self.sections
                    .iter()
                    .map(SectionSpec::to_json)
                    .collect::<Vec<_>>()
            ),
        );
        details.insert(
            "passwordHistory".to_owned(),
            json!(
                self.password_history
                    .iter()
                    .map(HistorySpec::to_json)
                    .collect::<Vec<_>>()
            ),
        );
        if let Some(document) = self.documents.first() {
            details.insert("documentAttributes".to_owned(), document.to_json());
        }
        for (key, value) in &self.details_extra {
            details.insert(key.clone(), value.clone());
        }

        let mut item = Map::new();
        item.insert("uuid".to_owned(), json!(self.uuid));
        item.insert("favIndex".to_owned(), json!(self.fav_index));
        item.insert("createdAt".to_owned(), json!(self.created_at));
        item.insert("updatedAt".to_owned(), json!(self.updated_at));
        item.insert("state".to_owned(), json!(self.state));
        item.insert("categoryUuid".to_owned(), json!(self.category_uuid));
        item.insert("overview".to_owned(), Value::Object(overview));
        item.insert("details".to_owned(), Value::Object(details));
        for (key, value) in &self.extra {
            item.insert(key.clone(), value.clone());
        }
        Value::Object(item)
    }
}

// ---------------------------------------------------------------------------------------------
// Archive
// ---------------------------------------------------------------------------------------------

/// One vault while `export.data` is being grouped: name, `type`, and the items in it.
type VaultGroup<'a> = (String, String, Vec<&'a ItemSpec>);

/// One account while `export.data` is being grouped: name and its vaults.
type AccountGroup<'a> = (String, Vec<VaultGroup<'a>>);

/// Everything about the archive that is not an item: extra entries, a broken `export.data`, a
/// bomb.
#[derive(Clone, Debug, Default)]
pub struct ArchiveSpec {
    /// The items. Grouped into accounts and vaults by their `account` and `vault` fields.
    pub items: Vec<ItemSpec>,
    /// Entries added verbatim, by name. Nothing sanitises these: `"../../etc/passwd"` and
    /// `"nested/dir/export.data"` both land in the central directory exactly as written, which is
    /// the whole point for the traversal tests.
    pub extra_entries: Vec<(String, Vec<u8>)>,
    /// Replaces the generated `export.data` — malformed JSON, truncated bytes, a bomb.
    pub raw_export_data: Option<Vec<u8>>,
    /// Replaces the generated `export.attributes`.
    pub raw_export_attributes: Option<Vec<u8>>,
    /// Leave `export.data` out of the archive entirely.
    pub omit_export_data: bool,
    /// Leave `export.attributes` out of the archive entirely.
    pub omit_export_attributes: bool,
    /// Write every entry under this prefix, e.g. `"export/"`, to exercise the one-level-nested
    /// layout some 1Password builds produce.
    pub entry_prefix: String,
}

impl ArchiveSpec {
    /// An archive holding these items and nothing unusual.
    #[must_use]
    pub fn new(items: &[ItemSpec]) -> Self {
        Self {
            items: items.to_vec(),
            ..Self::default()
        }
    }

    /// Add a verbatim entry.
    #[must_use]
    pub fn with_entry(mut self, name: &str, contents: Vec<u8>) -> Self {
        self.extra_entries.push((name.to_owned(), contents));
        self
    }

    /// Replace `export.data` with these bytes.
    #[must_use]
    pub fn with_raw_export_data(mut self, bytes: Vec<u8>) -> Self {
        self.raw_export_data = Some(bytes);
        self
    }

    /// Write everything under a directory prefix.
    #[must_use]
    pub fn nested_under(mut self, prefix: &str) -> Self {
        self.entry_prefix = prefix.to_owned();
        self
    }

    /// The `export.data` JSON this spec describes.
    #[must_use]
    pub fn export_data(&self) -> Value {
        let mut accounts: Vec<AccountGroup<'_>> = Vec::new();
        for item in &self.items {
            let account = match accounts.iter_mut().find(|(name, _)| *name == item.account) {
                Some(entry) => entry,
                None => {
                    accounts.push((item.account.clone(), Vec::new()));
                    accounts.last_mut().expect("just pushed")
                }
            };
            match account
                .1
                .iter_mut()
                .find(|(name, _, _)| *name == item.vault)
            {
                Some((_, _, items)) => items.push(item),
                None => account
                    .1
                    .push((item.vault.clone(), item.vault_type.clone(), vec![item])),
            }
        }

        let accounts: Vec<Value> = accounts
            .iter()
            .enumerate()
            .map(|(i, (name, vaults))| {
                json!({
                    "attrs": {
                        "accountName": name,
                        "name": name,
                        "avatar": "",
                        "email": format!("user{i}@example.com"),
                        "uuid": format!("account-{i}"),
                        "domain": "https://my.1password.com/",
                    },
                    "vaults": vaults.iter().enumerate().map(|(v, (vault, vault_type, items))| json!({
                        "attrs": {
                            "uuid": format!("vault-{i}-{v}"),
                            "desc": "",
                            "avatar": "",
                            "name": vault,
                            "type": vault_type,
                        },
                        "items": items.iter().map(|item| item.to_json()).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();

        json!({ "accounts": accounts })
    }

    /// The `export.attributes` JSON this spec describes.
    #[must_use]
    pub fn export_attributes(&self) -> Value {
        json!({
            "version": 3,
            "description": "1Password Unencrypted Export",
            "createdAt": "2026-09-13T09:00:00.000Z",
        })
    }

    /// Build the archive.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let prefix = &self.entry_prefix;

        if !self.omit_export_attributes {
            let bytes = self.raw_export_attributes.clone().unwrap_or_else(|| {
                serde_json::to_vec(&self.export_attributes()).expect("attributes serialize")
            });
            writer
                .start_file(format!("{prefix}export.attributes"), options)
                .expect("start export.attributes");
            writer.write_all(&bytes).expect("write export.attributes");
        }

        if !self.omit_export_data {
            let bytes = self.raw_export_data.clone().unwrap_or_else(|| {
                serde_json::to_vec(&self.export_data()).expect("export data serializes")
            });
            writer
                .start_file(format!("{prefix}export.data"), options)
                .expect("start export.data");
            writer.write_all(&bytes).expect("write export.data");
        }

        for item in &self.items {
            for document in &item.documents {
                writer
                    .start_file(format!("{prefix}{}", document.entry_name()), options)
                    .expect("start attachment");
                writer
                    .write_all(&document.contents)
                    .expect("write attachment");
            }
        }

        for (name, contents) in &self.extra_entries {
            writer
                .start_file(name.clone(), options)
                .expect("start extra entry");
            writer.write_all(contents).expect("write extra entry");
        }

        writer.finish().expect("finish archive").into_inner()
    }
}

/// Build a 1PUX archive holding these items.
///
/// The straight path, and what most tests want. For an archive that is *wrong* on purpose — a
/// `../` entry name, malformed JSON, a bomb — go through [`ArchiveSpec`].
#[must_use]
pub fn build_1pux(items: &[ItemSpec]) -> Vec<u8> {
    ArchiveSpec::new(items).build()
}

/// Bytes that compress to almost nothing: `len` copies of one byte.
///
/// A 500 MB entry of these deflates to a few hundred kilobytes, which is exactly the shape of the
/// attack the limits in `onepux/limits.rs` exist to refuse. Cheap to generate and cheap to hold —
/// the *compressed* archive is what the test carries around.
#[must_use]
pub fn compressible_payload(len: usize) -> Vec<u8> {
    vec![b'A'; len]
}

/// Write an archive to a file and hand back the path's directory guard.
///
/// The parsers take a path, so most tests need the bytes on disk. The returned
/// [`tempfile::TempDir`] must be kept alive for as long as the path is used.
#[must_use]
pub fn write_temp(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("write fixture");
    (dir, path)
}

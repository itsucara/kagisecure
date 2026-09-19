//! The 1PUX parser — 1Password's own unencrypted export, and the highest-fidelity way into
//! kagisecure.
//!
//! A 1PUX file is a zip holding two JSON entries and a directory of attachments:
//!
//! ```text
//! export.attributes      { "version": 3, "description": ..., "createdAt": ... }
//! export.data            { "accounts": [ { "attrs", "vaults": [ { "attrs", "items" } ] } ] }
//! files/<id>___<name>    one entry per attachment
//! ```
//!
//! Some builds write those entries at the archive root and some write them one directory down;
//! both are read. Entry names are matched *exactly*, every name goes through
//! [`zip::read::ZipFile::enclosed_name`] before anything else happens, and **no entry is ever
//! extracted to disk** — `export.data` is read through [`std::io::Read::take`] into a
//! [`Zeroizing`] buffer and the `files/` entries are not read at all.
//!
//! # What this module refuses before it allocates
//!
//! [`limits`] walks the central directory first: an entry name that escapes the archive root, a
//! total uncompressed size past 500 MB or a single entry claiming better than 1000:1 compression
//! all fail before a byte is inflated (threat-model M-21).
//!
//! # What it fails closed on
//!
//! [`conceal::is_concealed`] is the only thing that decides whether a value becomes a
//! [`kagisecure_core::Secret`], and it says yes on any hint. A field type this build has never
//! seen, next to a `guarded` flag or a title reading "recovery token", is secret.
//!
//! # What it cannot bring across
//!
//! Attachments and passkeys, each counted in the report with their metadata kept in
//! `Item::extra`. Password history **is** imported (plan §9 decision 2); only an entry whose
//! value is missing is counted as [`DropKind::PasswordHistory`].
//!
//! # Unverified assumptions
//!
//! The published format description names the human-readable value types but not the JSON keys,
//! and lists no `categoryUuid` values at all. [`VALUE_KEYS`], [`conceal::SECRET_KEYS`],
//! [`conceal::PUBLIC_KEYS`] and [`category::CATEGORIES`] are therefore marked UNVERIFIED, and
//! `probe_sample_categories` in `tests/onepux.rs` is how they get confirmed against a real
//! export.

pub mod category;
pub mod conceal;
pub mod limits;
pub mod schema;

use std::io::{Read, Seek};
use std::path::Path;

use ciborium::Value as Cbor;
use kagisecure_core::Totp;
use kagisecure_core::model::FieldKind;
use serde_json::Value;
use zeroize::Zeroizing;
use zip::ZipArchive;

use crate::error::{ImportError, Result};
use crate::ir::{
    DropKind, ForeignId, ImportPlan, ImportedField, ImportedItem, ImportedRevision, ImportedValue,
    SourceKind, TargetVault,
};
use conceal::ConcealHints;
use limits::Limits;
use schema::{Details, ExportData, ItemNode, LoginField, Overview, SectionField, take_scalar};

// ---------------------------------------------------------------------------------------------
// Entry names and other constants
// ---------------------------------------------------------------------------------------------

/// The archive entry holding the export's own header.
pub const EXPORT_ATTRIBUTES: &str = "export.attributes";

/// The archive entry holding everything else.
pub const EXPORT_DATA: &str = "export.data";

/// The largest `export.attributes` this reader will hold, in bytes. It is three keys.
const MAX_EXPORT_ATTRIBUTES: u64 = 1 << 20;

/// The `Item::extra` key holding the metadata of attachments that were not imported.
pub const DOCUMENTS_KEY: &str = "onepassword_documents";

/// The `Item::extra` key holding the names — never the contents — of item-level keys this build
/// did not recognise.
pub const UNKNOWN_KEYS_KEY: &str = "onepassword_unknown_keys";

/// The `Field::extra` key holding a login field's `designation`.
pub const DESIGNATION_KEY: &str = "onepassword_designation";

/// The `Field::extra` key holding a login field's form-control `name`.
pub const FORM_NAME_KEY: &str = "onepassword_form_name";

/// The `Field::extra` key holding 1Password's own field id.
pub const FIELD_ID_KEY: &str = "onepassword_field_id";

/// The label given to a one-time password this build could not make sense of.
pub const UNRECOGNIZED_TOTP_LABEL: &str = "one-time password (unrecognized)";

/// `details` keys that mean "this item has a passkey".
///
/// UNVERIFIED — confirm against sample.1pux.
const PASSKEY_KEYS: &[&str] = &["passkey", "passkeys"];

/// Keys whose presence means Watchtower or generator state that is recomputed, not imported.
///
/// `ps` is the password's strength score, `pbe` its entropy in bits and `pgrng` whether the
/// generator made it. UNVERIFIED — confirm against sample.1pux.
const WATCHTOWER_KEYS: &[&str] = &[
    "ps",
    "pbe",
    "pgrng",
    "watchtowerExclusions",
    "watchtower",
    "passwordStrength",
];

/// The 1PUX value type keys this build maps, and what it maps them to.
///
/// UNVERIFIED — confirm against sample.1pux. The published description lists the types by their
/// display names (Address, Concealed, Credit Card Number, Credit Card Type, Date, Email, Gender,
/// Menu, Month Year, One Time Password, Phone, Reference, String, URL) and not by the keys the
/// JSON actually uses; these are the camel-cased spellings 1Password is believed to write.
///
/// `"address"` and `"file"` are handled structurally rather than through this table, and
/// `"totp"` goes through [`Totp::parse_uri`] first. Anything absent from here is an unknown type
/// and [`conceal::is_concealed`] decides what happens to it.
pub const VALUE_KEYS: &[(&str, FieldKind)] = &[
    ("string", FieldKind::Text),
    ("concealed", FieldKind::Concealed),
    ("email", FieldKind::Email),
    ("url", FieldKind::Url),
    ("phone", FieldKind::Phone),
    ("date", FieldKind::Date),
    ("monthYear", FieldKind::MonthYear),
    ("menu", FieldKind::Menu),
    ("totp", FieldKind::Totp),
    ("creditCardNumber", FieldKind::CreditCardNumber),
    ("creditCardType", FieldKind::CreditCardType),
    ("reference", FieldKind::Reference),
    ("gender", FieldKind::Text),
    ("address", FieldKind::Address),
    ("file", FieldKind::File),
];

/// The `loginFields[].type` values, and what they map to.
///
/// These *are* documented: they are the HTML input types 1Password records for a web form.
pub const LOGIN_FIELD_KINDS: &[(&str, FieldKind)] = &[
    ("T", FieldKind::Text),
    ("E", FieldKind::Email),
    ("U", FieldKind::Url),
    ("N", FieldKind::Text),
    ("P", FieldKind::Concealed),
    ("A", FieldKind::Text),
    ("TEL", FieldKind::Phone),
];

/// The components of an `{"address": {...}}` value, in the order they are composed.
const ADDRESS_COMPONENTS: &[&str] = &["street", "city", "state", "zip", "country"];

// ---------------------------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------------------------

/// How to read an archive.
///
/// The plain [`parse`] uses [`Options::default`], which is what the CLI's defaults mean: skip the
/// trash, enforce the real limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Import items the user put in 1Password's trash, with their `trashed_at` set. `--include-trashed`.
    pub include_trashed: bool,
    /// The ceilings to enforce. Lowered by tests; never by the CLI.
    pub limits: Limits,
}

impl Options {
    /// Also import what the user threw away.
    #[must_use]
    pub fn include_trashed(mut self, include: bool) -> Self {
        self.include_trashed = include;
        self
    }

    /// Use different limits. For tests: proving the 100 000-item refusal should not cost 100 000
    /// items.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

/// A structural complaint about a 1PUX archive.
///
/// Goes through one constructor so that no call site can accidentally interpolate something read
/// out of the file (`error.rs`, and `tests/onepux.rs`'s canary).
pub(crate) fn malformed(detail: impl Into<String>) -> ImportError {
    ImportError::Malformed {
        source_kind: SourceKind::OnePux,
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------------------------

/// Parse a 1PUX archive into a plan.
///
/// # Errors
///
/// [`ImportError::SourceNotFound`] if the path is not there, [`ImportError::UnsafeEntryName`] for
/// an entry name that escapes the archive root, [`ImportError::LimitExceeded`] for an archive
/// past any of [`Limits`], and [`ImportError::Malformed`] for a zip or a JSON document this
/// reader cannot make sense of. No variant carries anything read out of the file.
pub fn parse(path: &Path) -> Result<ImportPlan> {
    parse_with(path, &Options::default())
}

/// Parse a 1PUX archive with explicit options.
///
/// # Errors
///
/// As [`parse`].
pub fn parse_with(path: &Path, options: &Options) -> Result<ImportPlan> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ImportError::SourceNotFound(path.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };

    let mut archive = ZipArchive::new(file)
        .map_err(|_| malformed("the file is not a zip archive this build can read"))?;

    // Before anything is decompressed.
    limits::check_archive(&mut archive, &options.limits)?;

    let mut plan = ImportPlan::new(SourceKind::OnePux, path);

    let attributes_index = find_entry(&archive, EXPORT_ATTRIBUTES);
    let data_index = find_entry(&archive, EXPORT_DATA).ok_or_else(|| {
        malformed("the archive has no export.data entry, so it is not a 1PUX export")
    })?;

    if let Some(index) = attributes_index {
        let bytes = read_entry(
            &mut archive,
            index,
            MAX_EXPORT_ATTRIBUTES,
            limits::names::ENTRY_SIZE,
        )?;
        // A header this reader cannot parse is not a reason to refuse the export: everything that
        // matters is in `export.data`. Note it and carry on.
        match serde_json::from_slice::<schema::ExportAttributes>(&bytes) {
            Ok(attributes) => {
                if let Some(version) = attributes.version {
                    plan.note("onepux-version", format!("1PUX format version {version}"));
                }
            }
            Err(_) => plan.note(
                "onepux-attributes-unreadable",
                "export.attributes could not be parsed; reading export.data anyway",
            ),
        }
    } else {
        plan.note(
            "onepux-attributes-missing",
            "the archive has no export.attributes entry; reading export.data anyway",
        );
    }

    if let Some(prefix) = entry_prefix(&archive, data_index) {
        plan.note(
            "onepux-nested-layout",
            format!("the export's entries are nested one directory down, under {prefix:?}"),
        );
    }

    let data = read_entry(
        &mut archive,
        data_index,
        options.limits.max_export_data,
        limits::names::EXPORT_DATA,
    )?;
    // The archive is not touched again: attachments are counted from their metadata, never read.
    drop(archive);

    let export: ExportData = serde_json::from_slice(&data).map_err(|e| {
        // Line and column, never the token: a serde message can quote what it choked on.
        malformed(format!(
            "export.data is not valid 1PUX JSON (line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;
    drop(data);

    build_plan(&mut plan, export, options)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// Archive plumbing
// ---------------------------------------------------------------------------------------------

/// The index of the entry named `wanted`, at the archive root or one directory down.
///
/// Matching is exact on the final component and the layout is limited to one level, so
/// `export.data`, `export/export.data` and `1password/export.data` are found and
/// `a/b/export.data`, `export.data.bak` and `myexport.data` are not.
fn find_entry<R: Read + Seek>(archive: &ZipArchive<R>, wanted: &str) -> Option<usize> {
    (0..archive.len()).find(|index| {
        archive
            .name_for_index(*index)
            .is_some_and(|name| entry_matches(name, wanted))
    })
}

/// Whether an entry name is `wanted`, flat or nested one level.
fn entry_matches(name: &str, wanted: &str) -> bool {
    let mut parts = name.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(only), None, _) => only == wanted,
        (Some(directory), Some(last), None) => !directory.is_empty() && last == wanted,
        _ => false,
    }
}

/// The directory an entry sits in, when it is nested rather than at the root.
fn entry_prefix<R: Read + Seek>(archive: &ZipArchive<R>, index: usize) -> Option<String> {
    let name = archive.name_for_index(index)?;
    let (directory, _) = name.rsplit_once('/')?;
    Some(format!("{directory}/"))
}

/// Read one entry into memory, capped.
///
/// Three things are true of every byte that comes out of here: it was read through
/// [`std::io::Read::take`], it landed in a buffer that zeroizes itself on drop, and it never
/// touched the filesystem.
fn read_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    cap: u64,
    limit_name: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let entry = archive
        .by_index(index)
        .map_err(|_| malformed("an archive entry could not be opened"))?;

    let declared = entry.size();
    if declared > cap {
        return Err(ImportError::LimitExceeded {
            what: limit_name,
            limit: cap,
        });
    }

    let mut buffer = Zeroizing::new(Vec::with_capacity(usize::try_from(declared).unwrap_or(0)));
    // `cap + 1` so that a central directory which understated the size is caught rather than
    // silently truncated.
    entry
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|_| malformed("an archive entry could not be decompressed"))?;

    if buffer.len() as u64 > cap {
        return Err(ImportError::LimitExceeded {
            what: limit_name,
            limit: cap,
        });
    }

    Ok(buffer)
}

// ---------------------------------------------------------------------------------------------
// Accounts, vaults, items
// ---------------------------------------------------------------------------------------------

/// Turn a parsed `export.data` into items on the plan.
fn build_plan(plan: &mut ImportPlan, export: ExportData, options: &Options) -> Result<()> {
    let multi_account = export.accounts.len() > 1;
    if multi_account {
        plan.note(
            "onepux-multi-account",
            format!(
                "the export holds {} accounts; each vault is named \"Account / Vault\"",
                export.accounts.len()
            ),
        );
    }

    let total_items: usize = export
        .accounts
        .iter()
        .flat_map(|a| a.vaults.iter())
        .map(|v| v.items.len())
        .sum();
    limits::check_count(total_items, options.limits.max_items, limits::names::ITEMS)?;

    let mut trashed_skipped = 0usize;
    let mut guessed_categories = 0usize;
    let mut unrecognized_totp = 0usize;

    for account in export.accounts {
        let account_name = account.attrs.display_name().to_owned();
        for vault in account.vaults {
            let vault_name = if multi_account {
                format!("{account_name} / {}", vault.attrs.display_name())
            } else {
                vault.attrs.display_name().to_owned()
            };

            for node in vault.items {
                let state = node.state.trim().to_ascii_lowercase();
                if state == "trashed" && !options.include_trashed {
                    trashed_skipped += 1;
                    continue;
                }

                let item = build_item(node, &vault_name, options, &mut unrecognized_totp)?;
                if item.category_was_guessed {
                    guessed_categories += 1;
                }
                plan.push(item);
            }
        }
    }

    if trashed_skipped > 0 {
        plan.note(
            "onepux-trashed-skipped",
            format!(
                "{trashed_skipped} items were in the trash and were not imported; \
                 use --include-trashed to bring them across"
            ),
        );
    }
    if guessed_categories > 0 {
        plan.note(
            "onepux-category-unverified",
            format!(
                "{guessed_categories} items used a 1Password category id this build maps but has \
                 not confirmed; the id is kept on each item"
            ),
        );
    }
    if unrecognized_totp > 0 {
        plan.note(
            "onepux-totp-unrecognized",
            format!(
                "{unrecognized_totp} one-time-password fields were not a readable otpauth URI or \
                 Base32 seed; each was kept as a concealed field rather than dropped"
            ),
        );
    }

    Ok(())
}

/// Turn one `items[]` node into an [`ImportedItem`].
fn build_item(
    mut node: ItemNode,
    vault_name: &str,
    options: &Options,
    unrecognized_totp: &mut usize,
) -> Result<ImportedItem> {
    let field_count = node.details.login_fields.len()
        + node
            .details
            .sections
            .iter()
            .map(|s| s.fields.len())
            .sum::<usize>();
    limits::check_count(
        field_count,
        options.limits.max_fields_per_item,
        limits::names::FIELDS,
    )?;
    limits::check_count(
        node.details.sections.len(),
        options.limits.max_sections_per_item,
        limits::names::SECTIONS,
    )?;

    let (category, guessed) = category::category_for(node.category_uuid.trim());
    let title = {
        let title = node.overview.title.trim();
        if title.is_empty() {
            "Untitled".to_owned()
        } else {
            title.to_owned()
        }
    };

    let mut item = ImportedItem::new(title, category);
    item.category_was_guessed = guessed;
    item.target_vault = TargetVault::Named(vault_name.to_owned());
    item.extra.insert(
        category::CATEGORY_UUID_KEY.to_owned(),
        Cbor::Text(node.category_uuid.clone()),
    );

    if !node.uuid.trim().is_empty() {
        item.foreign_id = Some(ForeignId::onepassword(node.uuid.trim()));
    }

    let state = node.state.trim().to_ascii_lowercase();
    item.archived = state == "archived";
    item.favorite = node.fav_index != 0;
    item.created_at = unix_seconds(node.created_at);
    item.updated_at = unix_seconds(node.updated_at);
    if state == "trashed" {
        // Only reachable with `--include-trashed`; the export gives no separate deletion time, so
        // the last change is the closest thing there is.
        item.trashed_at = unix_seconds(node.updated_at).or(Some(0));
    }

    apply_overview(&mut item, &mut node.overview);

    let title_for_totp = item.title.clone();
    let mut documents: Vec<Cbor> = Vec::new();
    apply_details(
        &mut item,
        &mut node.details,
        &title_for_totp,
        &mut documents,
        unrecognized_totp,
    );

    if !documents.is_empty() {
        item.extra
            .insert(DOCUMENTS_KEY.to_owned(), Cbor::Array(documents));
    }

    // Item-level keys this build does not know: their names are kept, their contents are not.
    let unknown = note_unknown_keys(&mut item, &node.extra);
    if !unknown.is_empty() {
        item.extra.insert(
            UNKNOWN_KEYS_KEY.to_owned(),
            Cbor::Array(unknown.into_iter().map(Cbor::Text).collect()),
        );
    }

    Ok(item)
}

/// Titles, URLs and tags.
fn apply_overview(item: &mut ImportedItem, overview: &mut Overview) {
    if let Some(url) = overview.url.take() {
        item.push_url(url.trim());
    }
    for entry in std::mem::take(&mut overview.urls) {
        item.push_url(entry.url.trim());
    }

    for tag in std::mem::take(&mut overview.tags) {
        let tag = tag.trim();
        if !tag.is_empty() {
            item.push_tag(tag);
        }
    }
    item.push_tag(SourceKind::OnePux.import_tag());

    if overview.extra.keys().any(|key| is_watchtower_key(key)) {
        item.report.note_dropped(DropKind::WatchtowerFlag);
    }
}

/// Notes, login fields, sections, history and attachments.
fn apply_details(
    item: &mut ImportedItem,
    details: &mut Details,
    title: &str,
    documents: &mut Vec<Cbor>,
    unrecognized_totp: &mut usize,
) {
    if let Some(notes) = details.notes_plain.take()
        && !notes.trim().is_empty()
    {
        item.notes = Some(notes);
    }

    for field in std::mem::take(&mut details.login_fields) {
        apply_login_field(item, field, title, unrecognized_totp);
    }

    for mut section in std::mem::take(&mut details.sections) {
        let section_name = section.section_name().map(str::to_owned);
        for field in std::mem::take(&mut section.fields) {
            apply_section_field(
                item,
                field,
                section_name.as_deref(),
                title,
                documents,
                unrecognized_totp,
            );
        }
    }

    for entry in std::mem::take(&mut details.password_history) {
        let schema::HistoryEntry { value, time } = entry;
        match value {
            Some(value) if !value.is_empty() => {
                // The label stays `None`: `ImportedRevision`'s contract is that `None` means the
                // item's own password, which is exactly what `passwordHistory` holds.
                item.push_revision(ImportedRevision::secret(value, time.and_then(unix_seconds)));
            }
            // No value, or an empty one: there is nothing to keep and nothing to say about it
            // beyond the count.
            _ => item.report.note_dropped(DropKind::PasswordHistory),
        }
    }

    if let Some(document) = details.document_attributes.take() {
        item.report.note_dropped(DropKind::Attachment);
        documents.push(document_metadata(
            &document.file_name,
            &document.document_id,
            document.decrypted_size,
        ));
    }

    // `details` keys this build does not know, with the two it does.
    let mut passkeys = 0usize;
    let mut watchtower = false;
    let mut unknown: Vec<String> = Vec::new();
    for (key, value) in &details.extra {
        if PASSKEY_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            // `passkeys: [ ... ]` counts one per credential; anything else counts as one.
            passkeys += value.as_array().map_or(1, Vec::len);
        } else if is_watchtower_key(key) {
            watchtower = true;
        } else {
            unknown.push(key.clone());
        }
    }
    if passkeys > 0 {
        item.report.note_dropped_n(DropKind::Passkey, passkeys);
    }
    if watchtower {
        item.report.note_dropped(DropKind::WatchtowerFlag);
    }
    item.report
        .note_dropped_n(DropKind::UnknownEntry, unknown.len());
}

/// Record the item-level keys this build does not know, returning their names.
fn note_unknown_keys(
    item: &mut ImportedItem,
    extra: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let mut passkeys = 0usize;
    let mut unknown = Vec::new();
    for (key, value) in extra {
        if PASSKEY_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            passkeys += value.as_array().map_or(1, Vec::len);
        } else if is_watchtower_key(key) {
            item.report.note_dropped(DropKind::WatchtowerFlag);
        } else {
            unknown.push(key.clone());
        }
    }
    if passkeys > 0 {
        item.report.note_dropped_n(DropKind::Passkey, passkeys);
    }
    item.report
        .note_dropped_n(DropKind::UnknownEntry, unknown.len());
    unknown
}

/// Whether a key names Watchtower or password-generator state.
fn is_watchtower_key(key: &str) -> bool {
    WATCHTOWER_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key))
}

/// The metadata kept for an attachment whose bytes were not imported.
fn document_metadata(file_name: &str, document_id: &str, size: Option<u64>) -> Cbor {
    let mut entries = vec![
        (
            Cbor::Text("fileName".to_owned()),
            Cbor::Text(file_name.to_owned()),
        ),
        (
            Cbor::Text("documentId".to_owned()),
            Cbor::Text(document_id.to_owned()),
        ),
    ];
    if let Some(size) = size {
        entries.push((
            Cbor::Text("decryptedSize".to_owned()),
            Cbor::Integer(size.into()),
        ));
    }
    Cbor::Map(entries)
}

// ---------------------------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------------------------

/// One `details.loginFields[]` entry.
fn apply_login_field(
    item: &mut ImportedItem,
    field: LoginField,
    title: &str,
    unrecognized_totp: &mut usize,
) {
    if field.value.is_empty() {
        item.report.note_dropped(DropKind::EmptyFormField);
        return;
    }

    let label = field.label().to_owned();
    let kind = LOGIN_FIELD_KINDS
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(field.field_type.trim()))
        .map_or(FieldKind::Text, |(_, kind)| *kind);

    let concealed = conceal::is_concealed(&ConcealHints {
        value_key: None,
        guarded: false,
        designation: field.designation.as_deref(),
        login_field_type: Some(field.field_type.trim()),
        title: Some(&label),
        id: Some(&field.name),
    });

    // A form control 1Password designated as a one-time password is still a TOTP seed.
    let designation_is_totp = field
        .designation
        .as_deref()
        .is_some_and(|d| d.eq_ignore_ascii_case("totp") || d.eq_ignore_ascii_case("otp"));

    let mut imported = if designation_is_totp {
        totp_field(label, field.value, title, unrecognized_totp)
    } else if concealed {
        ImportedField::secret(label, FieldKind::Concealed, field.value)
    } else {
        ImportedField::public(label, kind, field.value)
    };

    if let Some(designation) = &field.designation
        && !designation.is_empty()
    {
        imported
            .extra
            .insert(DESIGNATION_KEY.to_owned(), Cbor::Text(designation.clone()));
    }
    if !field.name.is_empty() {
        imported
            .extra
            .insert(FORM_NAME_KEY.to_owned(), Cbor::Text(field.name.clone()));
    }

    item.push_field(imported);
}

/// One `details.sections[].fields[]` entry.
fn apply_section_field(
    item: &mut ImportedItem,
    mut field: SectionField,
    section: Option<&str>,
    title: &str,
    documents: &mut Vec<Cbor>,
    unrecognized_totp: &mut usize,
) {
    let label = field.label().to_owned();
    let field_id = field.id.clone();

    if field.value.is_absent() {
        item.report.note_dropped(DropKind::EmptyFormField);
        return;
    }

    let hints = ConcealHints {
        value_key: field.value.key(),
        guarded: field.guarded,
        designation: None,
        login_field_type: None,
        title: Some(&label),
        id: Some(&field_id),
    };
    let concealed = conceal::is_concealed(&hints);

    let Some((key, mut value)) = field.value.take_single() else {
        // Not a one-key object at all. There is no value to store and no shape to walk.
        item.report.note_dropped(DropKind::UnknownEntry);
        return;
    };

    // An attachment: the bytes stay in the archive, the metadata comes across.
    if key.eq_ignore_ascii_case("file") {
        item.report.note_dropped(DropKind::Attachment);
        documents.push(file_value_metadata(&value));
        return;
    }

    // A passkey: nothing useful survives an export, so it is counted and left behind.
    if PASSKEY_KEYS.iter().any(|k| k.eq_ignore_ascii_case(&key)) {
        item.report.note_dropped(DropKind::Passkey);
        return;
    }

    if key.eq_ignore_ascii_case("address") {
        apply_address(item, &label, section, &mut value);
        return;
    }

    let kind = VALUE_KEYS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&key))
        .map(|(_, kind)| *kind);

    let Some(text) = take_scalar(&mut value) else {
        // A known key whose value is an object or an array this build has no shape for.
        item.report.note_dropped(DropKind::UnknownEntry);
        return;
    };

    if text.is_empty() {
        item.report.note_dropped(DropKind::EmptyFormField);
        return;
    }

    let mut imported = if kind == Some(FieldKind::Totp) {
        totp_field(label, text, title, unrecognized_totp)
    } else if concealed {
        // A value this build is concealing gets a concealed *kind* too, unless the type already
        // says something more specific: a card number stays a card number.
        let kind = match kind {
            None | Some(FieldKind::Text) => FieldKind::Concealed,
            Some(kind) => kind,
        };
        ImportedField::secret(label, kind, text)
    } else {
        let known = kind.is_some();
        let mut imported = ImportedField::public(label, kind.unwrap_or(FieldKind::Text), text);
        if !known {
            // Kept, but this build does not know what it is.
            imported = imported.preserved();
        }
        imported
    };

    if let Some(section) = section {
        imported = imported.in_section(section);
    }
    if !field_id.is_empty() {
        imported
            .extra
            .insert(FIELD_ID_KEY.to_owned(), Cbor::Text(field_id));
    }

    item.push_field(imported);
}

/// The metadata of a `{"file": {...}}` value, whose bytes are not imported.
fn file_value_metadata(value: &Value) -> Cbor {
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    document_metadata(
        &text("fileName"),
        &text("documentId"),
        value.get("decryptedSize").and_then(Value::as_u64),
    )
}

/// An `{"address": {...}}` value: one [`FieldKind::Address`] line plus a field per component.
fn apply_address(item: &mut ImportedItem, label: &str, section: Option<&str>, value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        item.report.note_dropped(DropKind::UnknownEntry);
        return;
    };

    // The documented components first, in postal order, then anything else alphabetically so the
    // result is stable whatever order the export wrote.
    let mut keys: Vec<String> = ADDRESS_COMPONENTS
        .iter()
        .filter(|c| object.contains_key(**c))
        .map(|c| (*c).to_owned())
        .collect();
    let mut rest: Vec<String> = object
        .keys()
        .filter(|k| !ADDRESS_COMPONENTS.contains(&k.as_str()))
        .cloned()
        .collect();
    rest.sort();
    keys.extend(rest);

    let mut parts: Vec<String> = Vec::new();
    let mut components: Vec<(String, String)> = Vec::new();
    for key in keys {
        let Some(slot) = object.get_mut(&key) else {
            continue;
        };
        let Some(text) = take_scalar(slot) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        parts.push(text.clone());
        components.push((key, text));
    }

    if parts.is_empty() {
        item.report.note_dropped(DropKind::EmptyFormField);
        return;
    }

    let mut line = ImportedField::public(label, FieldKind::Address, parts.join(", "));
    if let Some(section) = section {
        line = line.in_section(section);
    }
    item.push_field(line);

    for (component, text) in components {
        let mut field =
            ImportedField::public(format!("{label} {component}"), FieldKind::Text, text)
                .preserved();
        if let Some(section) = section {
            field = field.in_section(section);
        }
        item.push_field(field);
    }
}

// ---------------------------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------------------------

/// A one-time-password field, validated.
///
/// An `otpauth://` URI is kept as it is. A bare Base32 seed — which is what 1Password stores when
/// the user typed the seed rather than scanning a code — is wrapped into a URI so that everything
/// downstream sees one shape. Anything else is kept as a concealed field under
/// [`UNRECOGNIZED_TOTP_LABEL`]: a seed this build cannot read is still a secret, and dropping it
/// would lose the user their second factor silently.
fn totp_field(
    label: String,
    value: String,
    title: &str,
    unrecognized: &mut usize,
) -> ImportedField {
    if Totp::parse_uri(&value).is_ok() {
        return ImportedField::new(label, FieldKind::Totp, ImportedValue::secret(value));
    }

    let wrapped = format!(
        "otpauth://totp/{}?secret={}",
        percent_encode(title),
        value.trim()
    );
    if Totp::parse_uri(&wrapped).is_ok() {
        return ImportedField::new(label, FieldKind::Totp, ImportedValue::secret(wrapped));
    }

    *unrecognized += 1;
    ImportedField::new(
        UNRECOGNIZED_TOTP_LABEL.to_owned(),
        FieldKind::Concealed,
        ImportedValue::secret(value),
    )
}

/// Percent-encode everything that is not unreserved, for the label half of an `otpauth://` URI.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A timestamp the export gave, if it is one this build can store.
///
/// 1Password writes Unix seconds. A negative value is before 1970 and is not a timestamp for an
/// item in a password manager; it is dropped rather than wrapped into a huge `u64`.
fn unix_seconds(value: i64) -> Option<u64> {
    u64::try_from(value).ok().filter(|v| *v > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_match_flat_and_one_level_nested_and_nothing_else() {
        assert!(entry_matches("export.data", EXPORT_DATA));
        assert!(entry_matches("export/export.data", EXPORT_DATA));
        assert!(entry_matches("1password/export.data", EXPORT_DATA));
        assert!(!entry_matches("a/b/export.data", EXPORT_DATA));
        assert!(!entry_matches("export.data.bak", EXPORT_DATA));
        assert!(!entry_matches("myexport.data", EXPORT_DATA));
        assert!(!entry_matches("/export.data", EXPORT_DATA));
        assert!(!entry_matches("files/doc___a.pdf", EXPORT_DATA));
    }

    #[test]
    fn the_value_key_table_and_the_conceal_tables_agree() {
        for key in conceal::SECRET_KEYS {
            assert!(
                VALUE_KEYS.iter().any(|(k, _)| k == key),
                "{key} is secret but has no field kind"
            );
        }
        for key in conceal::PUBLIC_KEYS {
            assert!(
                VALUE_KEYS.iter().any(|(k, _)| k == key),
                "{key} is public but has no field kind"
            );
        }
        assert_eq!(
            VALUE_KEYS.len(),
            conceal::SECRET_KEYS.len() + conceal::PUBLIC_KEYS.len()
        );
    }

    #[test]
    fn a_label_becomes_a_usable_otpauth_path() {
        assert_eq!(percent_encode("Acme Staging"), "Acme%20Staging");
        assert_eq!(percent_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert!(
            Totp::parse_uri(&format!(
                "otpauth://totp/{}?secret=JBSWY3DPEHPK3PXP",
                percent_encode("Acme / Staging")
            ))
            .is_ok()
        );
    }

    #[test]
    fn only_a_sane_timestamp_survives() {
        assert_eq!(unix_seconds(1_700_000_000), Some(1_700_000_000));
        assert_eq!(unix_seconds(0), None);
        assert_eq!(unix_seconds(-1), None);
    }
}

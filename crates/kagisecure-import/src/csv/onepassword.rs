//! 1Password's own CSV export — lower fidelity than 1PUX (`--format 1password-csv`, plan §3).
//!
//! Column names are unverified against a real export: `url` may instead be `website`, and
//! `otpauth` may instead be `one-time password`.

use kagisecure_core::model::{Category, FieldKind};

use super::dialect::{cell, fallback_title, is_blank, is_truthy, require, split_tags, totp_field};
use crate::error::Result;
use crate::ir::{ImportedField, ImportedItem, SourceKind};

/// What this run-level note tells the user 1Password's CSV export cannot carry.
pub(crate) const LOSS_NOTE: &str = "1Password's CSV export carries no sections, item history or \
    vault structure.";

/// The header, resolved to column indices once per parse.
pub(crate) struct Columns {
    title: usize,
    url: usize,
    username: usize,
    password: usize,
    otpauth: usize,
    favorite: usize,
    archived: usize,
    tags: usize,
    notes: usize,
}

impl Columns {
    /// Resolve every column this dialect needs against a normalized header.
    ///
    /// # Errors
    ///
    /// [`crate::error::ImportError::MissingColumn`] naming whichever column is absent.
    pub(crate) fn resolve(normalized: &[String]) -> Result<Self> {
        let source_kind = SourceKind::OnePasswordCsv;
        Ok(Self {
            title: require(normalized, source_kind, &["title"], "title")?,
            url: require(normalized, source_kind, &["url", "website"], "url")?,
            username: require(normalized, source_kind, &["username"], "username")?,
            password: require(normalized, source_kind, &["password"], "password")?,
            otpauth: require(
                normalized,
                source_kind,
                &["otpauth", "one-time password"],
                "otpauth",
            )?,
            favorite: require(normalized, source_kind, &["favorite"], "favorite")?,
            archived: require(normalized, source_kind, &["archived"], "archived")?,
            tags: require(normalized, source_kind, &["tags"], "tags")?,
            notes: require(normalized, source_kind, &["notes"], "notes")?,
        })
    }
}

/// Map one row into an item, or `None` when the row has neither a username nor a password and
/// should be skipped and counted rather than imported as an empty shell (plan §3).
pub(crate) fn map_row(record: &::csv::StringRecord, columns: &Columns) -> Option<ImportedItem> {
    let title = cell(record, columns.title);
    let url = cell(record, columns.url);
    let username = cell(record, columns.username);
    let password = cell(record, columns.password);
    let otpauth = cell(record, columns.otpauth);
    let favorite = cell(record, columns.favorite);
    let archived = cell(record, columns.archived);
    let tags = cell(record, columns.tags);
    let notes = cell(record, columns.notes);

    if is_blank(username) && is_blank(password) {
        return None;
    }

    let display_title = if is_blank(title) {
        fallback_title(url)
    } else {
        title.to_owned()
    };
    let mut item = ImportedItem::new(display_title, Category::Login);
    item.push_url(url);
    item.push_tag(SourceKind::OnePasswordCsv.import_tag());

    if !is_blank(username) {
        item.push_field(ImportedField::public("username", FieldKind::Text, username));
    }
    if !is_blank(password) {
        item.push_field(ImportedField::secret(
            "password",
            FieldKind::Concealed,
            password.to_owned(),
        ));
    }
    if !is_blank(otpauth) {
        let title_for_totp = item.title.clone();
        item.push_field(totp_field(&title_for_totp, otpauth));
    }
    if !notes.is_empty() {
        item.notes = Some(notes.to_owned());
    }
    for tag in split_tags(tags) {
        item.push_tag(tag);
    }

    item.favorite = is_truthy(favorite);
    item.archived = is_truthy(archived);

    Some(item)
}

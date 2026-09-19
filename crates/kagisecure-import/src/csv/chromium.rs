//! The Chromium-family (Chrome, Edge, Brave, ...) password CSV export.
//!
//! `name,url,username,password[,note|notes]` — the note column is optional, both spellings are
//! accepted, and the pre-2021 export leaves it out entirely (plan §3).

use kagisecure_core::model::{Category, FieldKind};

use super::dialect::{cell, cell_opt, fallback_title, find, is_blank, require};
use crate::error::Result;
use crate::ir::{ImportedField, ImportedItem, SourceKind};

/// What this run-level note tells the user Chromium's export cannot carry.
pub(crate) const LOSS_NOTE: &str = "Chromium's CSV export carries only a name, URL, username, \
    password and an optional note per item — no one-time passwords, tags, favourites, history or \
    attachments.";

/// The header, resolved to column indices once per parse.
pub(crate) struct Columns {
    name: usize,
    url: usize,
    username: usize,
    password: usize,
    note: Option<usize>,
}

impl Columns {
    /// Resolve every column this dialect needs against a normalized header.
    ///
    /// # Errors
    ///
    /// [`crate::error::ImportError::MissingColumn`] naming whichever required column is absent.
    /// The note column is optional in every accepted variant, so its absence is never an error.
    pub(crate) fn resolve(normalized: &[String]) -> Result<Self> {
        let source_kind = SourceKind::ChromiumCsv;
        Ok(Self {
            name: require(normalized, source_kind, &["name"], "name")?,
            url: require(normalized, source_kind, &["url"], "url")?,
            username: require(normalized, source_kind, &["username"], "username")?,
            password: require(normalized, source_kind, &["password"], "password")?,
            note: find(normalized, &["note", "notes"]),
        })
    }
}

/// Map one row into an item, or `None` when the row has neither a username nor a password and
/// should be skipped and counted rather than imported as an empty shell (plan §3).
pub(crate) fn map_row(record: &::csv::StringRecord, columns: &Columns) -> Option<ImportedItem> {
    let name = cell(record, columns.name);
    let url = cell(record, columns.url);
    let username = cell(record, columns.username);
    let password = cell(record, columns.password);
    let note = cell_opt(record, columns.note);

    if is_blank(username) && is_blank(password) {
        return None;
    }

    let title = if is_blank(name) {
        fallback_title(url)
    } else {
        name.to_owned()
    };
    let mut item = ImportedItem::new(title, Category::Login);
    item.push_url(url);
    item.push_tag(SourceKind::ChromiumCsv.import_tag());

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
    if !note.is_empty() {
        item.notes = Some(note.to_owned());
    }

    Some(item)
}

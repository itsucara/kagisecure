//! Apple's Passwords app / iCloud Keychain CSV export.
//!
//! Six columns — `Title,URL,Username,Password,Notes,OTPAuth` — read by header name rather than
//! position, so a re-ordered header still works. Everything becomes `Category::Login`; the format
//! gives a parser nothing to guess a richer category from (plan §3).

use kagisecure_core::model::{Category, FieldKind};

use super::dialect::{cell, fallback_title, is_blank, require, totp_field};
use crate::error::Result;
use crate::ir::{ImportedField, ImportedItem, SourceKind};

/// What this run-level note tells the user Apple's export cannot carry.
pub(crate) const LOSS_NOTE: &str = "Apple's CSV export carries only a title, URL, username, \
    password, notes and one one-time-password seed per item — no sections, tags, favourites, \
    history or attachments.";

/// The header, resolved to column indices once per parse.
pub(crate) struct Columns {
    title: usize,
    url: usize,
    username: usize,
    password: usize,
    notes: usize,
    otpauth: usize,
}

impl Columns {
    /// Resolve every column this dialect needs against a normalized header.
    ///
    /// # Errors
    ///
    /// [`crate::error::ImportError::MissingColumn`] naming whichever column is absent.
    pub(crate) fn resolve(normalized: &[String]) -> Result<Self> {
        let source_kind = SourceKind::AppleCsv;
        Ok(Self {
            title: require(normalized, source_kind, &["title"], "title")?,
            url: require(normalized, source_kind, &["url"], "url")?,
            username: require(normalized, source_kind, &["username"], "username")?,
            password: require(normalized, source_kind, &["password"], "password")?,
            notes: require(normalized, source_kind, &["notes"], "notes")?,
            otpauth: require(normalized, source_kind, &["otpauth"], "otpauth")?,
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
    let notes = cell(record, columns.notes);
    let otpauth = cell(record, columns.otpauth);

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
    item.push_tag(SourceKind::AppleCsv.import_tag());

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

    Some(item)
}

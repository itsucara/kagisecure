//! Firefox's password CSV export.
//!
//! Firefox has no title column, so an item's title falls back to its URL's host. Its `guid` is
//! the one CSV export in this family with a real foreign key, so a re-import recognises what it
//! already created the same way the 1PUX path does with a 1Password uuid (plan §3).

use kagisecure_core::model::{Category, FieldKind};

use super::dialect::{cell, fallback_title, is_blank, require};
use crate::error::Result;
use crate::ir::{ForeignId, ImportedField, ImportedItem, SourceKind};

/// What this run-level note tells the user Firefox's export cannot carry.
pub(crate) const LOSS_NOTE: &str = "Firefox's CSV export carries no title, tags, favourites, \
    one-time passwords or password history — only a URL, username, password and the site's \
    stored realm and form-action origin.";

/// The `Item::extra` key holding a Firefox login's `httpRealm`.
pub(crate) const HTTP_REALM_KEY: &str = "firefox_http_realm";
/// The `Item::extra` key holding a Firefox login's `formActionOrigin`.
pub(crate) const FORM_ACTION_ORIGIN_KEY: &str = "firefox_form_action_origin";

/// The header, resolved to column indices once per parse.
pub(crate) struct Columns {
    url: usize,
    username: usize,
    password: usize,
    http_realm: usize,
    form_action_origin: usize,
    guid: usize,
    time_created: usize,
    time_password_changed: usize,
    // `timeLastUsed` is part of the header signature (plan §3) so it takes part in dialect
    // detection, but nothing in the plan gives it a home, so it is not resolved to a column here.
}

impl Columns {
    /// Resolve every column this dialect needs against a normalized header.
    ///
    /// # Errors
    ///
    /// [`crate::error::ImportError::MissingColumn`] naming whichever column is absent.
    pub(crate) fn resolve(normalized: &[String]) -> Result<Self> {
        let source_kind = SourceKind::FirefoxCsv;
        Ok(Self {
            url: require(normalized, source_kind, &["url"], "url")?,
            username: require(normalized, source_kind, &["username"], "username")?,
            password: require(normalized, source_kind, &["password"], "password")?,
            http_realm: require(normalized, source_kind, &["httprealm"], "httpRealm")?,
            form_action_origin: require(
                normalized,
                source_kind,
                &["formactionorigin"],
                "formActionOrigin",
            )?,
            guid: require(normalized, source_kind, &["guid"], "guid")?,
            time_created: require(normalized, source_kind, &["timecreated"], "timeCreated")?,
            time_password_changed: require(
                normalized,
                source_kind,
                &["timepasswordchanged"],
                "timePasswordChanged",
            )?,
        })
    }
}

/// Milliseconds since the epoch, as Firefox writes `timeCreated` and `timePasswordChanged`, to
/// Unix seconds. Anything that does not parse as a non-negative integer is treated as absent
/// rather than guessed at.
fn millis_to_unix_seconds(cell: &str) -> Option<u64> {
    let millis: u64 = cell.trim().parse().ok()?;
    Some(millis / 1000)
}

/// Map one row into an item, or `None` when the row has neither a username nor a password and
/// should be skipped and counted rather than imported as an empty shell (plan §3).
pub(crate) fn map_row(record: &::csv::StringRecord, columns: &Columns) -> Option<ImportedItem> {
    let url = cell(record, columns.url);
    let username = cell(record, columns.username);
    let password = cell(record, columns.password);
    let http_realm = cell(record, columns.http_realm);
    let form_action_origin = cell(record, columns.form_action_origin);
    let guid = cell(record, columns.guid);
    let time_created = cell(record, columns.time_created);
    let time_password_changed = cell(record, columns.time_password_changed);

    if is_blank(username) && is_blank(password) {
        return None;
    }

    let mut item = ImportedItem::new(fallback_title(url), Category::Login);
    item.push_url(url);
    item.push_tag(SourceKind::FirefoxCsv.import_tag());

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

    if !is_blank(guid) {
        item.foreign_id = Some(ForeignId::firefox(guid.to_owned()));
    }
    if !is_blank(http_realm) {
        item.extra.insert(
            HTTP_REALM_KEY.to_owned(),
            ciborium::Value::Text(http_realm.to_owned()),
        );
        item.report.note_preserved("httpRealm");
    }
    if !is_blank(form_action_origin) {
        item.extra.insert(
            FORM_ACTION_ORIGIN_KEY.to_owned(),
            ciborium::Value::Text(form_action_origin.to_owned()),
        );
        item.report.note_preserved("formActionOrigin");
    }

    item.created_at = millis_to_unix_seconds(time_created);
    item.updated_at = millis_to_unix_seconds(time_password_changed);

    Some(item)
}

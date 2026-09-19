//! The source-agnostic intermediate representation every parser produces.
//!
//! A parser's whole job is to turn one foreign export into a [`ImportPlan`]. Nothing downstream —
//! dedupe, commit, the CLI, the app — knows whether the plan came out of a 1PUX archive or a
//! Firefox CSV. That is what makes "add a fifth source" a parser-sized change rather than a
//! product-sized one.
//!
//! # The property that makes the preview safe
//!
//! The types in this module split cleanly in two:
//!
//! * **Carriers.** [`ImportedValue`], [`ImportedField`], [`ImportedRevision`], [`ImportedItem`],
//!   [`ImportPlan`]. These hold real values. None of them derive [`serde::Serialize`], and
//!   [`ImportedValue::Secret`] wraps [`Secret`], which cannot be serialized, cloned or displayed
//!   at all.
//! * **Reports.** [`ItemReport`], [`DropNote`], [`Tier`], [`DropKind`] here, and everything in
//!   [`crate::report`]. These derive `Serialize` and hold only names, kinds and counts.
//!
//! The preview a user sees, the JSON the CLI prints and the record the FFI layer hands to Swift
//! are all built from the second group. Adding a value to a report is therefore not a review
//! failure waiting to happen — it is a compile error, because the field you would have to add is
//! a `Secret` and `Secret: !Serialize` (ADR-0002 §3 point 1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kagisecure_core::model::{Category, FieldKind, FieldValue, Secret};
use serde::Serialize;

// ---------------------------------------------------------------------------------------------
// Where the data came from
// ---------------------------------------------------------------------------------------------

/// The export format a plan was parsed from.
///
/// All five variants exist from the start so that the CLI's `--format` values, the FFI enum and
/// the dialect table are fixed before any parser is written; WP1 and WP2 fill in behaviour
/// without widening this type (plan §8, collision rules).
///
/// `Serialize` is spelled out per variant, rather than derived with `#[serde(rename_all = ...)]`,
/// so the JSON a report prints is always [`SourceKind::as_str()`] — the same spelling `--format`
/// takes and the CLI's plain-text summary prints. A derived `kebab-case` would agree for four of
/// the five variants but render `OnePux` as `"one-pux"` and `OnePasswordCsv` as
/// `"one-password-csv"`, silently disagreeing with `"1pux"` and `"1password-csv"` everywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum SourceKind {
    /// 1Password's own archive format, the highest-fidelity path.
    #[serde(rename = "1pux")]
    OnePux,
    /// Passwords exported from Apple's Passwords app / iCloud Keychain.
    #[serde(rename = "apple-csv")]
    AppleCsv,
    /// Passwords exported from Chrome, Edge or another Chromium browser.
    #[serde(rename = "chromium-csv")]
    ChromiumCsv,
    /// Passwords exported from Firefox.
    #[serde(rename = "firefox-csv")]
    FirefoxCsv,
    /// 1Password's CSV export — lower fidelity than `1pux`.
    #[serde(rename = "1password-csv")]
    OnePasswordCsv,
}

impl SourceKind {
    /// Every format this build knows, in the order the CLI lists them.
    pub const ALL: &'static [Self] = &[
        Self::OnePux,
        Self::AppleCsv,
        Self::ChromiumCsv,
        Self::FirefoxCsv,
        Self::OnePasswordCsv,
    ];

    /// The canonical name used on the command line and in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnePux => "1pux",
            Self::AppleCsv => "apple-csv",
            Self::ChromiumCsv => "chromium-csv",
            Self::FirefoxCsv => "firefox-csv",
            Self::OnePasswordCsv => "1password-csv",
        }
    }

    /// Parse a canonical name, as `--format` gives it.
    #[must_use]
    pub fn parse_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == name)
    }

    /// Whether this format is one of the CSV dialects.
    #[must_use]
    pub fn is_csv(self) -> bool {
        !matches!(self, Self::OnePux)
    }

    /// The tag this format adds to every item it imports.
    #[must_use]
    pub fn import_tag(self) -> &'static str {
        match self {
            Self::OnePux | Self::OnePasswordCsv => "imported:1password",
            Self::AppleCsv => "imported:apple",
            Self::ChromiumCsv => "imported:chromium",
            Self::FirefoxCsv => "imported:firefox",
        }
    }
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An identifier the source assigned, kept so a re-import recognises what it already created.
///
/// Stored in [`kagisecure_core::model::Item::extra`] under [`ForeignId::key`]. Metadata: a UUID
/// is not a credential, and dedupe by id is the only alternative to dedupe by guesswork.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ForeignId {
    /// The `Item::extra` key the id is stored under.
    pub key: String,
    /// The identifier itself.
    pub value: String,
}

impl ForeignId {
    /// The `extra` key for a 1Password item UUID.
    pub const ONEPASSWORD_UUID: &'static str = "onepassword_uuid";
    /// The `extra` key for a Firefox login GUID.
    pub const FIREFOX_GUID: &'static str = "firefox_guid";

    /// An identifier under an arbitrary key.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// A 1Password item UUID.
    #[must_use]
    pub fn onepassword(uuid: impl Into<String>) -> Self {
        Self::new(Self::ONEPASSWORD_UUID, uuid)
    }

    /// A Firefox login GUID.
    #[must_use]
    pub fn firefox(guid: impl Into<String>) -> Self {
        Self::new(Self::FIREFOX_GUID, guid)
    }
}

/// Which logical vault an item should land in.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetVault {
    /// The vault file's first logical vault ([`kagisecure_core::Vault::default_vault_id`]).
    Default,
    /// A named logical vault, created if it does not exist.
    Named(String),
}

impl TargetVault {
    /// The name shown in a report.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::Default => "(default)",
            Self::Named(name) => name,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

/// A value a parser read out of an export.
///
/// Deliberately not `Clone` and not `Serialize`: [`Secret`] is neither, and making the enum
/// either would either fail to compile or require unwrapping the secret to do it. `Debug` is
/// derived and is safe — `Secret`'s own `Debug` prints `Secret(<redacted>)`.
#[derive(Debug)]
pub enum ImportedValue {
    /// A value that may be shown: a username, a URL, a card brand.
    Public(String),
    /// Secret material. Constructed only in this crate, which is why this crate is the only one
    /// besides the CLI and the FFI layer that enables `secret-material`.
    Secret(Secret),
}

impl ImportedValue {
    /// A secret from a plaintext string, whose buffer is moved in and zeroized on drop.
    #[must_use]
    pub fn secret(value: String) -> Self {
        Self::Secret(Secret::from_string(value))
    }

    /// A public string.
    #[must_use]
    pub fn public(value: impl Into<String>) -> Self {
        Self::Public(value.into())
    }

    /// Whether this is secret material.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }

    /// Whether there is anything here at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Public(s) => s.is_empty(),
            Self::Secret(s) => s.is_empty(),
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

    /// The secret, if this is one.
    #[must_use]
    pub fn as_secret(&self) -> Option<&Secret> {
        match self {
            Self::Secret(s) => Some(s),
            Self::Public(_) => None,
        }
    }

    /// Convert into the vault's own value type. The one-way door into storage.
    #[must_use]
    pub fn into_field_value(self) -> FieldValue {
        match self {
            Self::Public(s) => FieldValue::Public(s),
            Self::Secret(s) => FieldValue::Secret(s),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Report vocabulary
// ---------------------------------------------------------------------------------------------

/// How faithfully a field survived the crossing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// It landed in a typed field this build understands.
    Mapped,
    /// It was kept, but only as metadata in an `extra` map — readable, not first-class.
    Preserved,
}

/// A kind of thing an import could not bring across.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DropKind {
    /// A file attached to an item. `Item` has no attachments (plan §0).
    Attachment,
    /// A passkey / WebAuthn credential.
    Passkey,
    /// A history entry that could not be parsed.
    ///
    /// History itself **is** imported (plan §9 decision 2, [`ImportedItem::history`]); this
    /// counts only entries whose value or timestamp the parser could not make sense of.
    PasswordHistory,
    /// A Watchtower / breach-report flag.
    WatchtowerFlag,
    /// A form field the source carried with no value in it.
    EmptyFormField,
    /// Something in the export this build has no idea about.
    UnknownEntry,
}

impl DropKind {
    /// Every kind, so a report can list them in a stable order.
    pub const ALL: &'static [Self] = &[
        Self::Attachment,
        Self::Passkey,
        Self::PasswordHistory,
        Self::WatchtowerFlag,
        Self::EmptyFormField,
        Self::UnknownEntry,
    ];

    /// The short name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attachment => "attachment",
            Self::Passkey => "passkey",
            Self::PasswordHistory => "password history entry",
            Self::WatchtowerFlag => "watchtower flag",
            Self::EmptyFormField => "empty form field",
            Self::UnknownEntry => "unrecognized entry",
        }
    }

    /// One sentence a UI can put beside the counter, so "17 dropped" is not a mystery.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Attachment => {
                "kagisecure items do not hold files yet; keep these in the source app"
            }
            Self::Passkey => "passkeys cannot be exported meaningfully; keep them where they are",
            Self::PasswordHistory => "this history entry had no readable value or timestamp",
            Self::WatchtowerFlag => "breach-report state is recomputed, not imported",
            Self::EmptyFormField => "the source carried this field with nothing in it",
            Self::UnknownEntry => "this build does not recognize this part of the export",
        }
    }
}

impl std::fmt::Display for DropKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How many of one [`DropKind`] were left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DropNote {
    /// What was dropped.
    pub what: DropKind,
    /// How many.
    pub count: usize,
}

/// What happened to one item, in names and counts only.
///
/// `mapped` and `preserved` hold field *labels*, which are metadata and are disclosed by design
/// (threat-model A4). They never hold a value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ItemReport {
    /// Labels of fields that became typed fields.
    pub mapped: Vec<String>,
    /// Labels of things kept only as metadata.
    pub preserved: Vec<String>,
    /// Everything left behind, grouped.
    pub dropped: Vec<DropNote>,
}

impl ItemReport {
    /// Record a field that landed in a typed field.
    pub fn note_mapped(&mut self, label: impl Into<String>) {
        self.mapped.push(label.into());
    }

    /// Record something kept only as metadata.
    pub fn note_preserved(&mut self, label: impl Into<String>) {
        self.preserved.push(label.into());
    }

    /// Record one dropped thing, merging into an existing counter for the same kind.
    pub fn note_dropped(&mut self, what: DropKind) {
        self.note_dropped_n(what, 1);
    }

    /// Record `count` dropped things of one kind.
    pub fn note_dropped_n(&mut self, what: DropKind, count: usize) {
        if count == 0 {
            return;
        }
        match self.dropped.iter_mut().find(|d| d.what == what) {
            Some(note) => note.count += count,
            None => self.dropped.push(DropNote { what, count }),
        }
    }

    /// How many things of one kind were dropped.
    #[must_use]
    pub fn dropped_count(&self, what: DropKind) -> usize {
        self.dropped
            .iter()
            .find(|d| d.what == what)
            .map_or(0, |d| d.count)
    }

    /// Total dropped, across every kind.
    #[must_use]
    pub fn total_dropped(&self) -> usize {
        self.dropped.iter().map(|d| d.count).sum()
    }
}

/// A note about the run as a whole rather than about one item.
///
/// "I picked `firefox-csv` from the header signature", "`1password-csv` is the lower-fidelity
/// path". Shown above the per-item table so a user can see what was decided for them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    /// A short machine-readable tag, e.g. `"format-detected"`.
    pub code: String,
    /// One sentence for a human. Metadata only: never a value.
    pub detail: String,
}

impl Decision {
    /// A decision with the given tag and explanation.
    #[must_use]
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------------------------

/// One field read out of an export.
#[derive(Debug)]
pub struct ImportedField {
    /// The label to give it. Metadata.
    pub label: String,
    /// The kind to give it.
    pub kind: FieldKind,
    /// The value.
    pub value: ImportedValue,
    /// The section it sat in, if the source had sections.
    pub section: Option<String>,
    /// How faithfully it crossed.
    pub tier: Tier,
    /// Non-secret metadata about the field itself — the source's field id, its designation.
    ///
    /// Becomes [`kagisecure_core::model::Field::extra`], which carries the same rule: metadata
    /// only, never a value.
    pub extra: BTreeMap<String, ciborium::Value>,
}

impl ImportedField {
    /// A public field.
    #[must_use]
    pub fn public(label: impl Into<String>, kind: FieldKind, value: impl Into<String>) -> Self {
        Self::new(label, kind, ImportedValue::public(value))
    }

    /// A field holding secret material.
    #[must_use]
    pub fn secret(label: impl Into<String>, kind: FieldKind, value: String) -> Self {
        Self::new(label, kind, ImportedValue::secret(value))
    }

    /// A field with an already-built value.
    #[must_use]
    pub fn new(label: impl Into<String>, kind: FieldKind, value: ImportedValue) -> Self {
        Self {
            label: label.into(),
            kind,
            value,
            section: None,
            tier: Tier::Mapped,
            extra: BTreeMap::new(),
        }
    }

    /// Put this field in a section.
    #[must_use]
    pub fn in_section(mut self, section: impl Into<String>) -> Self {
        self.section = Some(section.into());
        self
    }

    /// Mark this field as preserved rather than mapped.
    #[must_use]
    pub fn preserved(mut self) -> Self {
        self.tier = Tier::Preserved;
        self
    }
}

/// A value the source says is no longer current — an entry of its password history.
///
/// The value is an [`ImportedValue`] and in practice always the [`ImportedValue::Secret`]
/// variant: a retired password is still a password (plan §9 decision 2). It becomes a
/// [`kagisecure_core::model::FieldRevision`] on commit.
#[derive(Debug)]
pub struct ImportedRevision {
    /// The retired value.
    pub value: ImportedValue,
    /// When it stopped being current, in Unix seconds. `None` when the source did not say.
    pub retired_at: Option<u64>,
    /// The label of the field it used to be in. `None` means "the item's password".
    pub label: Option<String>,
}

impl ImportedRevision {
    /// A retired secret value.
    #[must_use]
    pub fn secret(value: String, retired_at: Option<u64>) -> Self {
        Self {
            value: ImportedValue::secret(value),
            retired_at,
            label: None,
        }
    }

    /// Name the field this value used to be in.
    #[must_use]
    pub fn labelled(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// One item, as read out of an export and before anything has touched the vault.
#[derive(Debug)]
pub struct ImportedItem {
    /// The id the source assigned, if it had one. Used first by [`crate::dedupe`].
    pub foreign_id: Option<ForeignId>,
    /// Which logical vault it should land in.
    pub target_vault: TargetVault,
    /// The category to give it.
    pub category: Category,
    /// Whether [`ImportedItem::category`] is a guess rather than something the source stated.
    pub category_was_guessed: bool,
    /// Title. Metadata.
    pub title: String,
    /// Fields, in display order.
    pub fields: Vec<ImportedField>,
    /// Retired values (password history).
    pub history: Vec<ImportedRevision>,
    /// Tags, including the `imported:<source>` one.
    pub tags: Vec<String>,
    /// Associated URLs, deduped by the parser.
    pub urls: Vec<String>,
    /// Free-form note.
    pub notes: Option<String>,
    /// Marked favourite in the source.
    pub favorite: bool,
    /// Archived in the source.
    pub archived: bool,
    /// In the source's trash, and when.
    pub trashed_at: Option<u64>,
    /// Created, in Unix seconds, when the source said.
    pub created_at: Option<u64>,
    /// Last changed, in Unix seconds, when the source said.
    pub updated_at: Option<u64>,
    /// Non-secret metadata with no typed home — becomes
    /// [`kagisecure_core::model::Item::extra`]. Metadata only, never a value.
    pub extra: BTreeMap<String, ciborium::Value>,
    /// What happened to this item, in names and counts.
    pub report: ItemReport,
}

impl ImportedItem {
    /// A new item with a title and a category and nothing else.
    #[must_use]
    pub fn new(title: impl Into<String>, category: Category) -> Self {
        Self {
            foreign_id: None,
            target_vault: TargetVault::Default,
            category,
            category_was_guessed: false,
            title: title.into(),
            fields: Vec::new(),
            history: Vec::new(),
            tags: Vec::new(),
            urls: Vec::new(),
            notes: None,
            favorite: false,
            archived: false,
            trashed_at: None,
            created_at: None,
            updated_at: None,
            extra: BTreeMap::new(),
            report: ItemReport::default(),
        }
    }

    /// Add a field and record it in the item's report at its own tier.
    ///
    /// Going through this rather than pushing onto [`ImportedItem::fields`] directly is what
    /// keeps "what the report says" and "what was actually imported" from drifting apart.
    pub fn push_field(&mut self, field: ImportedField) {
        match field.tier {
            Tier::Mapped => self.report.note_mapped(field.label.clone()),
            Tier::Preserved => self.report.note_preserved(field.label.clone()),
        }
        self.fields.push(field);
    }

    /// Add a retired value.
    pub fn push_revision(&mut self, revision: ImportedRevision) {
        self.history.push(revision);
    }

    /// Add a tag if it is not already there.
    pub fn push_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Add a URL if it is not already there, ignoring empties.
    pub fn push_url(&mut self, url: impl Into<String>) {
        let url = url.into();
        if !url.is_empty() && !self.urls.contains(&url) {
            self.urls.push(url);
        }
    }

    /// The first field whose label matches, case-insensitively.
    #[must_use]
    pub fn field(&self, label: &str) -> Option<&ImportedField> {
        self.fields
            .iter()
            .find(|f| f.label.eq_ignore_ascii_case(label))
    }
}

// ---------------------------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------------------------

/// Everything one parse produced: the whole import, decided but not yet applied.
///
/// Parsing is complete before [`crate::commit::commit`] runs, so a malformed export fails with
/// the vault untouched and a `--dry-run` is exactly a parse with no commit.
#[derive(Debug)]
pub struct ImportPlan {
    /// What was parsed.
    pub source: SourceKind,
    /// Where it was parsed from. Only the file *name* ever reaches a report or the audit log.
    pub source_path: PathBuf,
    /// The items, in source order.
    pub items: Vec<ImportedItem>,
    /// Run-level notes.
    pub decisions: Vec<Decision>,
}

impl ImportPlan {
    /// An empty plan for the given source.
    #[must_use]
    pub fn new(source: SourceKind, source_path: impl Into<PathBuf>) -> Self {
        Self {
            source,
            source_path: source_path.into(),
            items: Vec::new(),
            decisions: Vec::new(),
        }
    }

    /// Add an item.
    pub fn push(&mut self, item: ImportedItem) {
        self.items.push(item);
    }

    /// Add a run-level note.
    pub fn note(&mut self, code: impl Into<String>, detail: impl Into<String>) {
        self.decisions.push(Decision::new(code, detail));
    }

    /// How many items the plan holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the plan would import nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The source file's name, with the directories it lived in removed.
    ///
    /// A path is not a secret, but it is the user's home directory and often their employer's
    /// project name, and the audit log and the report are both things people paste into issues.
    #[must_use]
    pub fn source_file_name(&self) -> String {
        self.source_path.file_name().map_or_else(
            || self.source.as_str().to_owned(),
            |n| n.to_string_lossy().into_owned(),
        )
    }

    /// Send every item to one logical vault, whatever the source said.
    ///
    /// This is `--logical-vault <NAME>`: collapse a 1PUX export's vault layout into one
    /// destination.
    pub fn retarget_all(&mut self, target: &TargetVault) {
        for item in &mut self.items {
            item.target_vault = target.clone();
        }
    }

    /// The names of the logical vaults this plan wants, in first-seen order.
    #[must_use]
    pub fn target_vault_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for item in &self.items {
            if let TargetVault::Named(name) = &item.target_vault
                && !names.contains(name)
            {
                names.push(name.clone());
            }
        }
        names
    }
}

/// The extension a 1PUX archive uses, for sniffing a format from a path.
pub(crate) const ONEPUX_EXTENSION: &str = "1pux";

/// Whether a path looks like a 1PUX archive by its name alone.
pub(crate) fn looks_like_onepux_name(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ONEPUX_EXTENSION))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_kind_round_trips_through_its_name() {
        for kind in SourceKind::ALL {
            assert_eq!(SourceKind::parse_name(kind.as_str()), Some(*kind));
        }
        assert_eq!(SourceKind::parse_name("lastpass"), None);
        // The five the plan fixed, no more and no fewer (plan §8: WP1/WP2 never edit this).
        assert_eq!(SourceKind::ALL.len(), 5);
    }

    #[test]
    fn source_kind_serializes_to_its_as_str_spelling() {
        // `Serialize` is spelled out per variant precisely so it never drifts from `as_str()` —
        // a derived `kebab-case` would render `OnePux` as `"one-pux"` and `OnePasswordCsv` as
        // `"one-password-csv"`, disagreeing with the `"1pux"` / `"1password-csv"` that `--format`
        // and every report headline use.
        for kind in SourceKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            assert_eq!(json, format!("{:?}", kind.as_str()), "{kind:?}");
        }
    }

    #[test]
    fn dropped_notes_merge_rather_than_accumulating_duplicates() {
        let mut report = ItemReport::default();
        report.note_dropped(DropKind::Attachment);
        report.note_dropped_n(DropKind::Attachment, 4);
        report.note_dropped(DropKind::Passkey);
        report.note_dropped_n(DropKind::UnknownEntry, 0);

        assert_eq!(report.dropped.len(), 2);
        assert_eq!(report.dropped_count(DropKind::Attachment), 5);
        assert_eq!(report.dropped_count(DropKind::UnknownEntry), 0);
        assert_eq!(report.total_dropped(), 6);
    }

    #[test]
    fn pushing_a_field_records_it_at_its_own_tier() {
        let mut item = ImportedItem::new("Acme", Category::Login);
        item.push_field(ImportedField::public("username", FieldKind::Text, "deploy"));
        item.push_field(ImportedField::public("designation", FieldKind::Text, "x").preserved());
        item.push_field(ImportedField::secret(
            "password",
            FieldKind::Concealed,
            "hunter2".to_owned(),
        ));

        assert_eq!(item.report.mapped, ["username", "password"]);
        assert_eq!(item.report.preserved, ["designation"]);
        assert!(item.field("USERNAME").is_some());
    }

    #[test]
    fn the_debug_rendering_of_a_plan_never_shows_a_secret() {
        let mut item = ImportedItem::new("Acme", Category::Login);
        item.push_field(ImportedField::secret(
            "password",
            FieldKind::Concealed,
            "marker-8f3a91c2".to_owned(),
        ));
        item.push_revision(ImportedRevision::secret(
            "marker-retired-77a1".to_owned(),
            Some(1),
        ));
        let mut plan = ImportPlan::new(SourceKind::OnePux, "/tmp/x.1pux");
        plan.push(item);

        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("marker-8f3a91c2"), "{rendered}");
        assert!(!rendered.contains("marker-retired-77a1"), "{rendered}");
        assert!(rendered.contains("Secret(<redacted>)"), "{rendered}");
    }

    #[test]
    fn target_vault_names_are_first_seen_order_without_duplicates() {
        let mut plan = ImportPlan::new(SourceKind::OnePux, "/tmp/export.1pux");
        for name in ["Private", "Shared", "Private"] {
            let mut item = ImportedItem::new(name, Category::Login);
            item.target_vault = TargetVault::Named(name.to_owned());
            plan.push(item);
        }
        let mut item = ImportedItem::new("Loose", Category::Login);
        item.target_vault = TargetVault::Default;
        plan.push(item);

        assert_eq!(plan.target_vault_names(), ["Private", "Shared"]);
        assert_eq!(plan.source_file_name(), "export.1pux");

        plan.retarget_all(&TargetVault::Named("Everything".to_owned()));
        assert_eq!(plan.target_vault_names(), ["Everything"]);
    }
}

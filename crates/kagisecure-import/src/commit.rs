//! Applying a parsed plan to an open vault.
//!
//! The split between [`crate::ir::ImportPlan`] and this function is the safety property of the
//! whole feature: **parsing is finished before anything is written**. A malformed archive, a zip
//! bomb, a row with a broken encoding — all of those fail during the parse, with the vault
//! untouched and nothing on disk changed. By the time `commit` runs there is nothing left that
//! can fail on the source's account.
//!
//! `commit` mutates only the in-memory [`kagisecure_core::vault::Body`]. The caller then calls
//! [`kagisecure_core::Vault::save`], which is atomic and `0600` already. `--dry-run` is simply a
//! run that never calls it.
//!
//! Two invariants this module is responsible for:
//!
//! * **Every imported item is `agent_visible = false`** (threat-model M-9). An import is a bulk
//!   operation over data the user has not looked at yet; opting four hundred items into agent
//!   visibility because the source had a "shared" flag would be the worst possible default.
//!   Asserted in `tests/dedupe.rs`.
//! * **The audit entry carries no labels and no values** — a source kind, three counts and the
//!   source's *file name* (plan §1).

use std::collections::{BTreeMap, HashSet};

use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{
    Field, FieldRevision, FieldValue, Item, ItemId, Secret, VaultId, VaultMeta,
};
use kagisecure_core::proto::Outcome;
use serde::Serialize;

use crate::dedupe::{DuplicatePolicy, ItemAction, imported_revision_key, resolve, revision_key};
use crate::error::Result;
use crate::ir::{ImportPlan, ImportedItem, TargetVault};
use crate::report::ImportReport;

/// What an import actually did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportOutcome {
    /// Items added.
    pub created: usize,
    /// Items overwritten in place.
    pub updated: usize,
    /// Items left alone because the vault already had them.
    pub skipped: usize,
    /// Items added beside an existing one under `keep-both`.
    pub kept_both: usize,
    /// Retired values added to items' password history. A count, deliberately and only.
    pub history_added: usize,
    /// Names of the logical vaults that had to be created.
    pub vaults_created: Vec<String>,
    /// The preview, as it stood when the decision was made.
    pub report: ImportReport,
}

impl ImportOutcome {
    /// One line for a terminal.
    #[must_use]
    pub fn headline(&self) -> String {
        format!(
            "Imported {} item{}. {} updated, {} skipped, {} kept alongside.",
            self.created + self.kept_both,
            if self.created + self.kept_both == 1 {
                ""
            } else {
                "s"
            },
            self.updated,
            self.skipped,
            self.kept_both,
        )
    }

    /// The audit log's `detail`: a source kind and three counts, and nothing else.
    #[must_use]
    fn audit_detail(&self, source: &str) -> String {
        format!(
            "{source}: {} created, {} updated, {} skipped",
            self.created, self.updated, self.skipped
        )
    }
}

/// Apply `plan` to `vault`.
///
/// Creates any logical vault the plan names and the file does not have, resolves every item
/// against [`crate::dedupe`], and appends exactly one audit entry for the run. Nothing here
/// touches the disk; call [`kagisecure_core::Vault::save`] afterwards.
///
/// # Errors
///
/// [`crate::error::ImportError::Vault`] if the vault refuses a change — in practice only if the
/// body somehow has no logical vault to default to.
pub fn commit(
    vault: &mut Vault,
    plan: ImportPlan,
    policy: DuplicatePolicy,
) -> Result<ImportOutcome> {
    let report = plan.report_against(vault, policy);
    let source = plan.source;
    let source_file = plan.source_file_name();

    let default_vault_id = vault.default_vault_id()?;
    let mut vaults_created = Vec::new();
    let mut vault_ids: BTreeMap<String, VaultId> = BTreeMap::new();
    for name in plan.target_vault_names() {
        let id = match existing_vault_named(vault, &name) {
            Some(id) => id,
            None => {
                vaults_created.push(name.clone());
                vault.add_logical_vault(VaultMeta::new(name.clone()))
            }
        };
        vault_ids.insert(name, id);
    }

    let now = kagisecure_core::unix_now();
    let today = iso_date(now);

    let mut outcome = ImportOutcome {
        created: 0,
        updated: 0,
        skipped: 0,
        kept_both: 0,
        history_added: 0,
        vaults_created,
        report,
    };

    for imported in plan.items {
        let target = match &imported.target_vault {
            TargetVault::Default => default_vault_id,
            TargetVault::Named(name) => vault_ids.get(name).copied().unwrap_or(default_vault_id),
        };
        let (action, existing) = resolve(vault, &imported, policy);
        match action {
            ItemAction::Skip => outcome.skipped += 1,
            ItemAction::Create => {
                let item = build_item(imported, target, now);
                outcome.history_added += item.history.len();
                vault.add_item(item);
                outcome.created += 1;
            }
            ItemAction::KeepBoth => {
                let mut item = build_item(imported, target, now);
                item.title = format!("{} (imported {today})", item.title);
                outcome.history_added += item.history.len();
                vault.add_item(item);
                outcome.kept_both += 1;
            }
            ItemAction::Update => {
                // `resolve` returns `Some` for every non-`Create` action; falling back to a
                // create rather than unwrapping keeps a future policy from panicking here.
                let Some(id) = existing else {
                    let item = build_item(imported, target, now);
                    outcome.history_added += item.history.len();
                    vault.add_item(item);
                    outcome.created += 1;
                    continue;
                };
                outcome.history_added += apply_update(vault, id, imported, now)?;
                outcome.updated += 1;
            }
        }
    }

    vault.append_audit(AuditDraft {
        actor: "import".to_owned(),
        tool: "import".to_owned(),
        vault_id: Some(default_vault_id),
        target_path: Some(source_file),
        outcome: Outcome::Allowed,
        detail: Some(outcome.audit_detail(source.as_str())),
        ..AuditDraft::default()
    });

    Ok(outcome)
}

/// The id of the logical vault with exactly this display name.
///
/// [`Vault::find_vault`] also matches ids and id prefixes, which is right for a
/// user-typed reference and wrong here: an import must not adopt a vault because its uuid happens
/// to start with the four letters of a 1Password vault's name. Two vaults with the same name are
/// not an error — the first one wins, the same way the UI's list would show them.
fn existing_vault_named(vault: &Vault, name: &str) -> Option<VaultId> {
    vault
        .vault_summaries()
        .into_iter()
        .find(|v| v.name == name)
        .map(|v| v.id)
}

/// Turn an imported item into a stored one.
fn build_item(imported: ImportedItem, vault_id: VaultId, now: u64) -> Item {
    let ImportedItem {
        foreign_id,
        category,
        title,
        fields,
        history,
        tags,
        urls,
        notes,
        favorite,
        archived,
        trashed_at,
        created_at,
        updated_at,
        mut extra,
        ..
    } = imported;

    let mut item = Item::new(vault_id, category, title);
    item.created_at = created_at.unwrap_or(now);
    item.updated_at = updated_at.or(created_at).unwrap_or(now);
    item.tags = tags;
    item.urls = urls;
    item.notes = notes;
    item.favorite = favorite;
    item.archived = archived;
    item.trashed_at = trashed_at;
    // Never, whatever the source said (threat-model M-9).
    item.agent_visible = false;

    if let Some(foreign) = foreign_id {
        extra.insert(foreign.key, ciborium::Value::Text(foreign.value));
    }
    item.extra = extra;

    for field in fields {
        let mut stored = Field {
            id: kagisecure_core::model::FieldId::new(),
            label: field.label,
            kind: field.kind,
            value: field.value.into_field_value(),
            section: field.section,
            agent_visible: false,
            extra: field.extra,
        };
        // A section is metadata the source gave us; nothing else about the field is inferred.
        stored.section = stored.section.filter(|s| !s.is_empty());
        item.fields.push(stored);
    }

    for revision in history {
        let retired_at = revision.retired_at.unwrap_or(item.updated_at);
        item.history.push(FieldRevision {
            field_id: None,
            label: revision.label.unwrap_or_else(|| "password".to_owned()),
            kind: kagisecure_core::model::FieldKind::Concealed,
            value: revision.value.into_field_value(),
            retired_at,
        });
    }
    item.history.sort_by_key(|r| r.retired_at);

    item
}

/// Overwrite the parts of an existing item that the source carries, and keep the rest.
///
/// Kept, deliberately:
///
/// * **`agent_visible`**, on the item and on every field. An import must never widen what an
///   agent can see; the user opted in by hand and re-running an export is not a reason to
///   revisit that.
/// * **Existing [`kagisecure_core::model::FieldId`]s**, which is why a matching field is
///   overwritten in place rather than replaced. An [`kagisecure_core::model::Environment`]
///   binds a variable to `(item, field)` — replacing the field would silently break every
///   binding that pointed at it.
/// * **Local tags.** The source's tags are added; tags only this vault knows stay.
/// * **`trashed_at`.** If the user binned it here, re-importing does not un-bin it.
/// * **`created_at`**, and any field the source does not carry at all.
///
/// One thing is *not* kept: when a matching field already holds secret material and the source
/// carries a different value for it, the old value is retired into [`Item::history`] before it is
/// overwritten — a rotated password found by re-running an import is exactly the same event as one
/// rotated by hand, and both go through the same [`FieldRevision`] home (plan §9 decision 2).
/// Retirement is keyed the same way the history merge below is — by value and moment — so running
/// the identical update twice retires the old value once, not twice.
///
/// Returns how many history entries were added, from both sources: a field's own rotation and the
/// source's own `passwordHistory`-style entries.
fn apply_update(vault: &mut Vault, id: ItemId, imported: ImportedItem, now: u64) -> Result<usize> {
    let reference = id.to_string();
    let item = vault.find_item_mut(&reference)?;

    if !imported.category_was_guessed {
        item.category = imported.category;
    }
    item.title = imported.title;
    if imported.notes.is_some() {
        item.notes = imported.notes;
    }
    item.favorite = imported.favorite;
    item.archived = imported.archived;
    item.updated_at = imported.updated_at.unwrap_or(now);

    for tag in imported.tags {
        if !item.tags.contains(&tag) {
            item.tags.push(tag);
        }
    }
    for url in imported.urls {
        if !item.urls.contains(&url) {
            item.urls.push(url);
        }
    }
    for (key, value) in imported.extra {
        item.extra.insert(key, value);
    }
    if let Some(foreign) = imported.foreign_id {
        item.extra
            .insert(foreign.key, ciborium::Value::Text(foreign.value));
    }

    // Built before the field loop below so a rotated field's old value can be deduped against
    // history the same way the imported `passwordHistory`-style entries are.
    let mut seen: HashSet<[u8; 32]> = item
        .history
        .iter()
        .map(|r| revision_key(field_value_bytes(&r.value), r.retired_at))
        .collect();
    let mut added = 0;

    for field in imported.fields {
        let existing = item
            .fields
            .iter_mut()
            .find(|f| f.label.eq_ignore_ascii_case(&field.label) && f.section == field.section);
        match existing {
            Some(slot) => {
                let new_value = field.value.into_field_value();
                if let FieldValue::Secret(old_secret) = &slot.value {
                    let changed = old_secret.expose() != field_value_bytes(&new_value);
                    if changed {
                        let retired_at = now;
                        let key = revision_key(old_secret.expose(), retired_at);
                        if seen.insert(key) {
                            item.history.push(FieldRevision {
                                field_id: Some(slot.id),
                                label: slot.label.clone(),
                                kind: slot.kind,
                                value: FieldValue::Secret(Secret::new(
                                    old_secret.expose().to_vec(),
                                )),
                                retired_at,
                            });
                            added += 1;
                        }
                    }
                }
                slot.kind = field.kind;
                slot.value = new_value;
                for (key, value) in field.extra {
                    slot.extra.insert(key, value);
                }
                // `slot.id` and `slot.agent_visible` are untouched on purpose.
            }
            None => {
                item.fields.push(Field {
                    id: kagisecure_core::model::FieldId::new(),
                    label: field.label,
                    kind: field.kind,
                    value: field.value.into_field_value(),
                    section: field.section.filter(|s| !s.is_empty()),
                    agent_visible: false,
                    extra: field.extra,
                });
            }
        }
    }

    for revision in imported.history {
        let retired_at = revision.retired_at.unwrap_or(item.updated_at);
        let Some(key) = imported_revision_key(&revision.value, retired_at) else {
            continue;
        };
        if !seen.insert(key) {
            continue;
        }
        item.history.push(FieldRevision {
            field_id: None,
            label: revision.label.unwrap_or_else(|| "password".to_owned()),
            kind: kagisecure_core::model::FieldKind::Concealed,
            value: revision.value.into_field_value(),
            retired_at,
        });
        added += 1;
    }
    item.history.sort_by_key(|r| r.retired_at);

    Ok(added)
}

/// The bytes a stored [`FieldValue`] carries, for the history-merge key — never for anything a
/// report or an error could show.
fn field_value_bytes(value: &FieldValue) -> &[u8] {
    match value {
        FieldValue::Secret(s) => s.expose(),
        FieldValue::Public(text) => text.as_bytes(),
    }
}

/// `YYYY-MM-DD` for a Unix timestamp, in UTC.
///
/// Hand-rolled rather than adding a date crate for one format string. Howard Hinnant's
/// `civil_from_days`, which is exact for every day the proleptic Gregorian calendar covers.
#[must_use]
pub fn iso_date(unix_seconds: u64) -> String {
    let days = i64::try_from(unix_seconds / 86_400).unwrap_or(i64::MAX);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates_match_known_epochs() {
        assert_eq!(iso_date(0), "1970-01-01");
        assert_eq!(iso_date(86_399), "1970-01-01");
        assert_eq!(iso_date(86_400), "1970-01-02");
        // 2000-02-29: the leap-year rule that catches naive implementations.
        assert_eq!(iso_date(951_782_400), "2000-02-29");
        assert_eq!(iso_date(1_757_721_600), "2025-09-13");
    }

    #[test]
    fn the_audit_detail_is_counts_and_a_source_name() {
        let outcome = ImportOutcome {
            created: 412,
            updated: 8,
            skipped: 3,
            kept_both: 0,
            history_added: 19,
            vaults_created: Vec::new(),
            report: crate::ir::ImportPlan::new(crate::ir::SourceKind::OnePux, "x.1pux").report(),
        };
        assert_eq!(
            outcome.audit_detail("1pux"),
            "1pux: 412 created, 8 updated, 3 skipped"
        );
    }
}

//! The preview — and the only thing about an import that is allowed to leave the process.
//!
//! Everything here derives [`Serialize`] and holds names, kinds, counts and timestamps. Nothing
//! here can hold a value, because the types that hold values ([`crate::ir::ImportedValue`],
//! [`kagisecure_core::Secret`]) do not implement `Serialize` and cannot be put in a struct that
//! does without a compile error. That is the enforcement (ADR-0002 §3 point 1), and
//! `tests/report_canary.rs` is the belt to its braces.
//!
//! Password history is the sharpest case. It is imported (plan §9 decision 2) and it is made of
//! retired passwords, so the report carries **a count and nothing else**: no value, no label, no
//! timestamp.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::dedupe::ItemAction;
use crate::ir::{Decision, DropKind, DropNote, ImportPlan, SourceKind};

/// Run-level counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// Items in the plan.
    pub items: usize,
    /// Fields that became typed fields.
    pub fields_mapped: usize,
    /// Things kept only as metadata.
    pub fields_preserved: usize,
    /// Things left behind, across every [`DropKind`].
    pub fields_dropped: usize,
    /// Retired values that will be imported. A count, deliberately and only.
    pub history_entries: usize,
}

/// One row of the per-item table a preview shows.
///
/// Title, category and vault name are metadata (threat-model A4). There is no value column and
/// there is no way to add one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ItemRow {
    /// The item's title.
    pub title: String,
    /// Its category's canonical name.
    pub category: String,
    /// Whether the category was guessed rather than stated by the source.
    pub category_was_guessed: bool,
    /// The logical vault it is headed for.
    pub vault: String,
    /// How many fields it brings.
    pub fields: usize,
    /// How many retired values it brings. A count, deliberately and only.
    pub history_entries: usize,
    /// What was left behind for this item.
    pub dropped: Vec<DropNote>,
    /// What committing would do to it, when the report was built against a vault.
    ///
    /// `None` from [`ImportPlan::report`], which knows nothing about any vault;
    /// [`ImportPlan::report_against`] fills it in.
    pub action: Option<ItemAction>,
}

/// What an import would do, or did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    /// The format that was read.
    pub source: SourceKind,
    /// The source file's *name*. Never the directory it lived in.
    pub source_file: String,
    /// Run-level counts.
    pub totals: Totals,
    /// Item counts by category name.
    pub by_category: BTreeMap<String, usize>,
    /// Everything left behind, across the whole run.
    pub dropped: Vec<DropNote>,
    /// Run-level notes from the parser.
    pub decisions: Vec<Decision>,
    /// Counts by what committing would do, when the report was built against a vault.
    pub by_action: BTreeMap<String, usize>,
    /// One row per item.
    pub items: Vec<ItemRow>,
}

impl ImportReport {
    /// How many of one kind were dropped across the run.
    #[must_use]
    pub fn dropped_count(&self, what: DropKind) -> usize {
        self.dropped
            .iter()
            .find(|d| d.what == what)
            .map_or(0, |d| d.count)
    }

    /// How many items would be handled one way.
    #[must_use]
    pub fn action_count(&self, action: ItemAction) -> usize {
        self.by_action.get(action.as_str()).copied().unwrap_or(0)
    }

    /// One line for a terminal: what this import will do, in a sentence.
    #[must_use]
    pub fn headline(&self) -> String {
        let dropped = self.totals.fields_dropped;
        let mut line = format!(
            "{} item{} from {} ({})",
            self.totals.items,
            if self.totals.items == 1 { "" } else { "s" },
            self.source_file,
            self.source
        );
        if self.totals.history_entries > 0 {
            line.push_str(&format!(
                ", {} retired value{}",
                self.totals.history_entries,
                if self.totals.history_entries == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }
        if dropped > 0 {
            line.push_str(&format!(
                ", {dropped} thing{} not imported",
                if dropped == 1 { "" } else { "s" }
            ));
        }
        line
    }

    /// The whole report as Markdown, for `--report <PATH>`.
    ///
    /// Written by the CLI at mode `0600` even though it holds no values: it is still a complete
    /// inventory of what a person has accounts with, which is worth as much to an attacker as
    /// several of the passwords would be.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# kagisecure import report\n\n");
        out.push_str(&format!("- Source file: `{}`\n", self.source_file));
        out.push_str(&format!("- Format: `{}`\n", self.source));
        out.push_str(&format!("- Items: {}\n", self.totals.items));
        out.push_str(&format!(
            "- Fields mapped: {} | preserved as metadata: {}\n",
            self.totals.fields_mapped, self.totals.fields_preserved
        ));
        out.push_str(&format!(
            "- Retired values (password history) imported: {}\n",
            self.totals.history_entries
        ));
        out.push_str(
            "\nThis report contains no values. Titles, labels and counts only, by construction.\n",
        );

        if !self.decisions.is_empty() {
            out.push_str("\n## Decisions\n\n");
            for decision in &self.decisions {
                out.push_str(&format!("- **{}** — {}\n", decision.code, decision.detail));
            }
        }

        if !self.by_category.is_empty() {
            out.push_str("\n## By category\n\n| Category | Items |\n| --- | ---: |\n");
            for (category, count) in &self.by_category {
                out.push_str(&format!("| {category} | {count} |\n"));
            }
        }

        if !self.by_action.is_empty() {
            out.push_str("\n## What will happen\n\n| Action | Items |\n| --- | ---: |\n");
            for (action, count) in &self.by_action {
                out.push_str(&format!("| {action} | {count} |\n"));
            }
        }

        if self.dropped.is_empty() {
            out.push_str("\n## Not imported\n\nNothing.\n");
        } else {
            out.push_str("\n## Not imported\n\n| What | Count | Why |\n| --- | ---: | --- |\n");
            for note in &self.dropped {
                out.push_str(&format!(
                    "| {} | {} | {} |\n",
                    note.what,
                    note.count,
                    note.what.explanation()
                ));
            }
        }

        out.push_str("\n## Items\n\n| Title | Category | Vault | Action | Fields | History | Not imported |\n");
        out.push_str("| --- | --- | --- | --- | ---: | ---: | --- |\n");
        for row in &self.items {
            let dropped = if row.dropped.is_empty() {
                "—".to_owned()
            } else {
                row.dropped
                    .iter()
                    .map(|d| format!("{} ×{}", d.what, d.count))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let category = if row.category_was_guessed {
                format!("{} (guessed)", row.category)
            } else {
                row.category.clone()
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                escape_cell(&row.title),
                category,
                escape_cell(&row.vault),
                row.action.map_or("—", ItemAction::as_str),
                row.fields,
                row.history_entries,
                dropped,
            ));
        }
        out
    }
}

/// Keep a title containing `|` or a newline from breaking the table it sits in.
fn escape_cell(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

impl ImportPlan {
    /// The report for this plan on its own, with no vault in sight.
    ///
    /// Every [`ItemRow::action`] is `None`: without a vault there is no way to know whether an
    /// item is a duplicate. Use [`ImportPlan::report_against`] for a real preview.
    #[must_use]
    pub fn report(&self) -> ImportReport {
        self.build_report(|_| None)
    }

    /// The report for applying this plan to `vault` under `policy`.
    ///
    /// Reads the vault; writes nothing to it.
    #[must_use]
    pub fn report_against(
        &self,
        vault: &kagisecure_core::Vault,
        policy: crate::dedupe::DuplicatePolicy,
    ) -> ImportReport {
        self.build_report(|item| Some(crate::dedupe::resolve(vault, item, policy).0))
    }

    fn build_report(
        &self,
        action_for: impl Fn(&crate::ir::ImportedItem) -> Option<ItemAction>,
    ) -> ImportReport {
        let mut totals = Totals {
            items: self.items.len(),
            ..Totals::default()
        };
        let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_action: BTreeMap<String, usize> = BTreeMap::new();
        let mut dropped: Vec<DropNote> = Vec::new();
        let mut rows = Vec::with_capacity(self.items.len());

        for item in &self.items {
            totals.fields_mapped += item.report.mapped.len();
            totals.fields_preserved += item.report.preserved.len();
            totals.fields_dropped += item.report.total_dropped();
            totals.history_entries += item.history.len();
            *by_category
                .entry(item.category.as_str().to_owned())
                .or_default() += 1;

            for note in &item.report.dropped {
                match dropped.iter_mut().find(|d| d.what == note.what) {
                    Some(existing) => existing.count += note.count,
                    None => dropped.push(*note),
                }
            }

            let action = action_for(item);
            if let Some(action) = action {
                *by_action.entry(action.as_str().to_owned()).or_default() += 1;
            }

            rows.push(ItemRow {
                title: item.title.clone(),
                category: item.category.as_str().to_owned(),
                category_was_guessed: item.category_was_guessed,
                vault: item.target_vault.display_name().to_owned(),
                fields: item.fields.len(),
                history_entries: item.history.len(),
                dropped: item.report.dropped.clone(),
                action,
            });
        }

        dropped.sort_by_key(|d| d.what);

        ImportReport {
            source: self.source,
            source_file: self.source_file_name(),
            totals,
            by_category,
            dropped,
            decisions: self.decisions.clone(),
            by_action,
            items: rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use kagisecure_core::model::{Category, FieldKind};

    use super::*;
    use crate::ir::{ImportedField, ImportedItem, ImportedRevision, TargetVault};

    fn plan() -> ImportPlan {
        let mut plan = ImportPlan::new(SourceKind::OnePux, "/home/ada/secret-project/export.1pux");
        plan.note("format-given", "the format was named on the command line");

        let mut login = ImportedItem::new("Acme | staging", Category::Login);
        login.target_vault = TargetVault::Named("Work".to_owned());
        login.push_field(ImportedField::public("username", FieldKind::Text, "deploy"));
        login.push_field(ImportedField::secret(
            "password",
            FieldKind::Concealed,
            "hunter2".to_owned(),
        ));
        login.push_revision(ImportedRevision::secret("older".to_owned(), Some(10)));
        login.report.note_dropped(DropKind::Attachment);
        login.report.note_dropped(DropKind::Attachment);
        plan.push(login);

        let mut note = ImportedItem::new("Router", Category::SecureNote);
        note.category_was_guessed = true;
        note.report.note_dropped(DropKind::Passkey);
        plan.push(note);
        plan
    }

    #[test]
    fn the_report_aggregates_counts_and_leaves_the_action_column_unset() {
        let report = plan().report();
        assert_eq!(report.totals.items, 2);
        assert_eq!(report.totals.fields_mapped, 2);
        assert_eq!(report.totals.history_entries, 1);
        assert_eq!(report.totals.fields_dropped, 3);
        assert_eq!(report.dropped_count(DropKind::Attachment), 2);
        assert_eq!(report.dropped_count(DropKind::Passkey), 1);
        assert_eq!(report.by_category["login"], 1);
        assert_eq!(report.by_category["secure-note"], 1);
        assert!(report.items.iter().all(|r| r.action.is_none()));
        assert!(report.by_action.is_empty());
        // The directory the export sat in is not the report's business.
        assert_eq!(report.source_file, "export.1pux");
        assert!(!report.headline().contains("secret-project"));
    }

    #[test]
    fn markdown_and_json_carry_no_value_and_survive_a_pipe_in_a_title() {
        let report = plan().report();
        let markdown = report.to_markdown();
        let json = serde_json::to_string(&report).unwrap();

        for rendering in [&markdown, &json] {
            assert!(!rendering.contains("hunter2"), "{rendering}");
            assert!(!rendering.contains("deploy"), "{rendering}");
            assert!(!rendering.contains("older"), "{rendering}");
            assert!(!rendering.contains("secret-project"), "{rendering}");
        }
        // The label is metadata and is expected; the value beside it is not.
        assert!(markdown.contains("Acme \\| staging"), "{markdown}");
        assert!(markdown.contains("(guessed)"), "{markdown}");
        assert!(
            markdown.contains("Retired values (password history) imported: 1"),
            "{markdown}"
        );
    }
}

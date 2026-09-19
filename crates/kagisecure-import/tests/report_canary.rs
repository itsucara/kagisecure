//! The canary: a marker seeded as a value must appear in no byte of anything an import shows
//! anyone (plan §6).
//!
//! `crates/kagisecure-cli/tests/mcp.rs` does this for the MCP sidecar, which is where the claim
//! matters most. This is the same idea aimed at the import path, because the import path is the
//! one that holds a whole foreign vault in memory and then *prints a summary of it*. A report
//! that leaked one password would be worse than no import feature at all.
//!
//! The structural argument is in [`kagisecure_import::report`]: report types derive `Serialize`,
//! value types do not, so a value cannot reach a report without a compile error. This file is the
//! belt to that braces — it asserts the property on actual bytes, so that a future `impl
//! Serialize` or a hand-rolled `Display` is caught by a test and not by a user.
//!
//! WP1 and WP2 extend this: seed the marker through each parser's own fixture and assert the same
//! thing about the plan that comes out. The helpers here are written to make that a few lines.

mod common;

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Category, FieldKind};
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_import::commit::commit;
use kagisecure_import::dedupe::DuplicatePolicy;
use kagisecure_import::error::ImportError;
use kagisecure_import::ir::{
    DropKind, ForeignId, ImportPlan, ImportedField, ImportedItem, ImportedRevision, SourceKind,
    TargetVault,
};

/// Seeded as the current password. If these bytes ever reach a report, the feature has failed at
/// the one thing it has to get right.
const MARKER: &str = "K4G1-1MP0RT-C4N4RY-7b19d4e0a53f8c26";

/// Seeded as a *retired* password. History is imported (plan §9 decision 2), so it is a second,
/// independent canary: the report is allowed to say "3 retired values", and nothing else.
const HISTORY_MARKER: &str = "K4G1-H1ST0RY-C4N4RY-2f0c81ab64d97e35";

/// Seeded as a note, a tag and a field label, to catch a leak through a path that is not the
/// obvious one.
const NOTE_MARKER: &str = "K4G1-N0TE-C4N4RY-90e7c1fa38b52d64";

const PASSWORD: &[u8] = b"correct horse battery staple";

/// The markers that are secret material. These must not appear in *anything* — a report, an
/// error, a `Debug` rendering, the audit log.
const SECRET_MARKERS: &[&str] = &[MARKER, HISTORY_MARKER];

/// Every marker, including the one seeded into a note.
///
/// A note is not secret material in this product's model: [`kagisecure_core::model::Item`] holds
/// it as a plain `Option<String>` with a derived `Debug`, exactly as this crate's
/// [`ImportedItem`] does, so a `{:?}` of either shows it. What a note must never do is reach a
/// *report*, which is the thing that gets printed, written to a file and handed across the FFI
/// boundary — so the note marker is checked there and not in `Debug`.
const MARKERS: &[&str] = &[MARKER, HISTORY_MARKER, NOTE_MARKER];

/// A plan built by hand, seeded with every marker in every place a value can hide.
fn seeded_plan() -> ImportPlan {
    let mut item = ImportedItem::new("Acme staging", Category::Login);
    item.foreign_id = Some(ForeignId::onepassword("acme-uuid-0001"));
    item.target_vault = TargetVault::Named("Imported".to_owned());
    item.push_url("https://acme.example.com/login");
    item.push_tag("imported:1password");
    item.push_field(ImportedField::public("username", FieldKind::Text, "deploy"));
    item.push_field(ImportedField::secret(
        "password",
        FieldKind::Concealed,
        MARKER.to_owned(),
    ));
    item.push_field(
        ImportedField::secret(
            "one-time password",
            FieldKind::Totp,
            format!("otpauth://totp/Acme?secret={MARKER}"),
        )
        .in_section("security"),
    );
    item.push_field(
        ImportedField::secret("api token", FieldKind::Concealed, MARKER.to_owned()).preserved(),
    );
    item.push_revision(ImportedRevision::secret(
        HISTORY_MARKER.to_owned(),
        Some(1_500_000_000),
    ));
    item.push_revision(
        ImportedRevision::secret(HISTORY_MARKER.to_owned(), Some(1_500_000_001))
            .labelled("password"),
    );
    item.notes = Some(format!("recovery phrase: {NOTE_MARKER}"));
    item.report.note_dropped(DropKind::Attachment);
    item.report.note_dropped(DropKind::PasswordHistory);

    let mut plan = ImportPlan::new(
        SourceKind::OnePux,
        "/home/ada/Downloads/1password-export.1pux",
    );
    plan.note("format-detected", "the archive begins with the zip magic");
    plan.push(item);
    plan
}

/// Assert `haystack` holds none of `markers`, naming which one leaked and from where.
fn assert_none_of(markers: &[&str], what: &str, haystack: &str) {
    for marker in markers {
        assert!(
            !haystack.contains(marker),
            "{what} leaked {marker}:\n{haystack}"
        );
    }
}

/// Assert `haystack` holds no marker at all — for anything a user is shown.
fn assert_clean(what: &str, haystack: &str) {
    assert_none_of(MARKERS, what, haystack);
}

/// Assert `haystack` holds no secret marker — for a `Debug` rendering, where a note is expected.
fn assert_no_secret(what: &str, haystack: &str) {
    assert_none_of(SECRET_MARKERS, what, haystack);
}

#[test]
fn no_marker_reaches_the_markdown_report_the_json_report_or_a_debug_rendering() {
    let plan = seeded_plan();
    let report = plan.report();

    assert_clean("the Markdown report", &report.to_markdown());
    assert_clean(
        "the JSON report",
        &serde_json::to_string_pretty(&report).unwrap(),
    );
    assert_clean("the report's Debug", &format!("{report:?}"));
    assert_clean("the headline", &report.headline());
    assert_no_secret("the plan's Debug", &format!("{plan:?}"));
    assert_no_secret("the items' Debug", &format!("{:?}", plan.items));
    // Every secret in the plan renders as the redacted form and nothing else.
    assert!(format!("{plan:?}").contains("Secret(<redacted>)"));

    // The counts the report *is* allowed to give, so the assertions above are not vacuous.
    assert_eq!(report.totals.items, 1);
    assert_eq!(report.totals.history_entries, 2);
    assert_eq!(report.totals.fields_mapped, 3);
    assert_eq!(report.totals.fields_preserved, 1);
    assert_eq!(report.dropped_count(DropKind::Attachment), 1);
    // Labels are metadata and are disclosed by design (threat-model A4).
    assert!(report.to_markdown().contains("Acme staging"));
    // The directory the export sat in is not.
    assert!(!report.to_markdown().contains("/home/ada"));
}

#[test]
fn no_marker_reaches_a_report_taken_after_a_real_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (mut vault, _code) = Vault::create(
        &path,
        PASSWORD,
        &CreateOptions {
            kdf: KdfParams::new(64, 1, 1).unwrap(),
            vault_name: "Personal".to_owned(),
            kdf_hint: None,
        },
    )
    .unwrap();

    let outcome = commit(&mut vault, seeded_plan(), DuplicatePolicy::Skip).unwrap();
    assert_eq!(outcome.created, 1);
    assert_eq!(outcome.history_added, 2);

    assert_clean(
        "the outcome's JSON",
        &serde_json::to_string(&outcome).unwrap(),
    );
    assert_no_secret("the outcome's Debug", &format!("{outcome:?}"));
    assert_clean("the outcome's headline", &outcome.headline());
    assert_clean(
        "the audit log",
        &serde_json::to_string(vault.audit_entries()).unwrap(),
    );
    assert_clean(
        "the item summaries",
        &serde_json::to_string(&vault.item_summaries()).unwrap(),
    );

    // Proof the markers really did land, so none of the above is passing by accident.
    let item = vault.find_item("Acme staging").unwrap();
    assert_eq!(
        item.field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        MARKER.as_bytes()
    );
    assert_eq!(item.history.len(), 2);
    assert_eq!(
        item.history[0].value.as_secret().unwrap().expose(),
        HISTORY_MARKER.as_bytes()
    );
    // Notes are not a value type — they are metadata the user wrote — but they are not in any
    // report either, and the summary must not carry them.
    assert!(item.notes.as_deref().unwrap().contains(NOTE_MARKER));
}

#[test]
fn no_marker_reaches_an_error_message() {
    // Every error this crate can currently produce, rendered. WP1 and WP2 add variants; each
    // one has to be added here, which is the point of listing them exhaustively rather than
    // sampling.
    let errors: Vec<ImportError> = vec![
        ImportError::Unsupported,
        ImportError::Io(std::io::Error::other("device is on fire")),
        ImportError::Vault(kagisecure_core::Error::ItemNotFound("Acme".to_owned())),
        ImportError::SourceNotFound(std::path::PathBuf::from("/home/ada/export.1pux")),
        ImportError::Malformed {
            source_kind: SourceKind::OnePux,
            detail: "export.data is not a JSON object".to_owned(),
        },
        ImportError::UndetectedFormat {
            candidates: vec![SourceKind::AppleCsv, SourceKind::ChromiumCsv],
        },
        ImportError::MissingColumn {
            source_kind: SourceKind::FirefoxCsv,
            column: "guid",
        },
        ImportError::Encoding {
            detail: "the file is UTF-16; re-export or re-save it as UTF-8".to_owned(),
            offset: Some(4_096),
            row: Some(17),
        },
        ImportError::LimitExceeded {
            what: "uncompressed archive size in bytes",
            limit: 500_000_000,
        },
        ImportError::UnsafeEntryName,
        ImportError::TargetVaultNotFound("Work".to_owned()),
    ];

    for error in &errors {
        assert_clean("an error's Display", &error.to_string());
        assert_none_of(MARKERS, "an error's Debug", &format!("{error:?}"));
    }

    // A parse of a file that is not what it claims fails without echoing its contents.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.csv");
    std::fs::write(&path, format!("title,password\nAcme,{MARKER}\n")).unwrap();
    let error = kagisecure_import::parse(&path, None).unwrap_err();
    assert_clean("a real parse error", &error.to_string());
    assert_none_of(MARKERS, "a real parse error's Debug", &format!("{error:?}"));
}

/// The fixture builder writes the marker into an archive on purpose — an export *is* plaintext,
/// that is the whole problem — and shredding it is how it stops being.
#[test]
fn the_source_file_is_plaintext_and_shredding_removes_it() {
    let bytes = common::build_1pux(&[common::ItemSpec::login(
        "acme-uuid-0001",
        "Acme staging",
        "https://acme.example.com/login",
        "deploy",
        MARKER,
    )
    .with_history(common::HistorySpec::new(HISTORY_MARKER, 1_500_000_000))]);

    let (dir, path) = common::write_temp("export.1pux", &bytes);
    let outcome = kagisecure_import::shred_file(&path).unwrap();
    assert!(outcome.overwritten);
    assert!(outcome.removed);
    assert!(!path.exists());
    assert!(outcome.caveat().contains("Best effort"));
    drop(dir);
}

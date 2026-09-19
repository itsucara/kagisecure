//! The 1PUX parser, against archives built in code (plan §6).
//!
//! Three kinds of test live here and they are worth telling apart:
//!
//! * **Mapping.** What a category id, a value type, a tag or a timestamp becomes. These are the
//!   tests that fail when the unverified tables in `src/onepux/` turn out to be wrong, which is
//!   the point of writing them against a fixture builder rather than a checked-in blob.
//! * **Refusal.** A zip bomb, a `../../etc/passwd` entry name, a truncated archive, a hundred
//!   thousand items. Each of these is a resource or a traversal attack that a password manager
//!   is squarely in the way of, and each has to fail *fast* and say so without quoting the file.
//! * **The canary.** A marker seeded as a current password and as a retired one, asserted absent
//!   from every rendering anyone is ever shown. `tests/report_canary.rs` makes the same claim
//!   about a hand-built plan; this makes it about a real parse.

mod common;

use std::collections::BTreeMap;

use common::{
    ArchiveSpec, DocumentSpec, HistorySpec, ItemSpec, LoginFieldSpec, SectionFieldSpec,
    SectionSpec, build_1pux, compressible_payload, write_temp,
};
use kagisecure_core::model::{Category, FieldKind};
use kagisecure_import::error::ImportError;
use kagisecure_import::ir::{DropKind, ImportPlan, ImportedItem, TargetVault, Tier};
use kagisecure_import::onepux::category::{CATEGORY_UUID_KEY, Verified};
use kagisecure_import::onepux::conceal::{ConcealHints, SECRET_KEYS, is_concealed};
use kagisecure_import::onepux::limits::Limits;
use kagisecure_import::onepux::{
    DOCUMENTS_KEY, Options, UNKNOWN_KEYS_KEY, UNRECOGNIZED_TOTP_LABEL, category, parse_with,
};
use proptest::prelude::*;
use serde_json::json;

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Parse archive bytes, with the file on disk only for as long as the parse takes.
fn parse_bytes(bytes: &[u8], options: &Options) -> Result<ImportPlan, ImportError> {
    let (dir, path) = write_temp("export.1pux", bytes);
    let parsed = parse_with(&path, options);
    drop(dir);
    parsed
}

/// Parse an archive built from these items, with the default options.
fn parse_items(items: &[ItemSpec]) -> ImportPlan {
    parse_bytes(&build_1pux(items), &Options::default()).expect("the archive parses")
}

/// Parse an archive spec, with the default options.
fn parse_archive(spec: &ArchiveSpec) -> Result<ImportPlan, ImportError> {
    parse_bytes(&spec.build(), &Options::default())
}

/// The plaintext of a field, whether it is public or secret.
///
/// Only a test may do this, and only because the alternative is asserting nothing about what was
/// actually imported.
fn value_of(item: &ImportedItem, label: &str) -> String {
    let field = item
        .field(label)
        .unwrap_or_else(|| panic!("no field {label:?} on {:?}", item.report.mapped));
    match &field.value {
        kagisecure_import::ir::ImportedValue::Public(s) => s.clone(),
        kagisecure_import::ir::ImportedValue::Secret(s) => {
            String::from_utf8(s.expose().to_vec()).expect("utf-8")
        }
    }
}

/// The `onepassword_category_uuid` an item carries.
fn category_uuid(item: &ImportedItem) -> &str {
    match item.extra.get(CATEGORY_UUID_KEY) {
        Some(ciborium::Value::Text(s)) => s,
        other => panic!("no category uuid: {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------------------------

#[test]
fn a_login_item_crosses_with_its_username_password_url_and_ids() {
    let plan = parse_items(&[ItemSpec::login(
        "uuid-1",
        "Acme",
        "https://acme.example.com",
        "ada",
        "hunter2",
    )]);

    assert_eq!(plan.len(), 1);
    let item = &plan.items[0];
    assert_eq!(item.title, "Acme");
    assert_eq!(item.category, Category::Login);
    assert!(!item.category_was_guessed);
    assert_eq!(item.urls, ["https://acme.example.com"]);
    assert_eq!(item.target_vault, TargetVault::Named("Personal".to_owned()));
    assert_eq!(
        item.foreign_id.as_ref().map(|f| f.value.as_str()),
        Some("uuid-1")
    );
    assert_eq!(category_uuid(item), "001");
    assert_eq!(item.tags, ["imported:1password"]);

    assert_eq!(value_of(item, "username"), "ada");
    assert_eq!(value_of(item, "password"), "hunter2");
    // The password is secret material and the username is not.
    assert!(item.field("password").unwrap().value.is_secret());
    assert!(!item.field("username").unwrap().value.is_secret());
    assert_eq!(item.field("password").unwrap().kind, FieldKind::Concealed);
}

#[test]
fn the_flags_the_overview_carries_all_survive() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p")
            .fav_index(3)
            .state("archived")
            .timestamps(1_000, 2_000)
            .tags(&["work", "finance"])
            .with_url("admin", "https://admin.acme.example")
            .with_url("duplicate", "https://acme.example")
            .notes("line one\nline two"),
    ]);

    let item = &plan.items[0];
    assert!(item.favorite);
    assert!(item.archived);
    assert_eq!(item.created_at, Some(1_000));
    assert_eq!(item.updated_at, Some(2_000));
    assert_eq!(item.tags, ["work", "finance", "imported:1password"]);
    assert_eq!(item.notes.as_deref(), Some("line one\nline two"));
    // `overview.url` first, then `overview.urls[]`, and the repeat is not repeated.
    assert_eq!(
        item.urls,
        ["https://acme.example", "https://admin.acme.example"]
    );
}

#[test]
fn an_item_with_no_title_is_called_untitled() {
    let plan = parse_items(&[ItemSpec {
        title: String::new(),
        ..ItemSpec::default()
    }]);
    assert_eq!(plan.items[0].title, "Untitled");
}

#[test]
fn sections_become_field_sections_and_an_untitled_section_becomes_none() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p")
            .with_section(SectionSpec::new(
                "security",
                vec![SectionFieldSpec::string("note", "visible")],
            ))
            .with_section(SectionSpec::untitled(vec![SectionFieldSpec::string(
                "loose", "value",
            )])),
    ]);

    let item = &plan.items[0];
    assert_eq!(
        item.field("note").unwrap().section.as_deref(),
        Some("security")
    );
    assert_eq!(item.field("loose").unwrap().section, None);
}

#[test]
fn an_empty_login_field_is_dropped_and_counted() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p")
            .with_login_field(LoginFieldSpec::new("remember", "T", ""))
            .with_section(SectionSpec::new(
                "extras",
                vec![SectionFieldSpec::string("blank", "")],
            )),
    ]);

    let item = &plan.items[0];
    assert_eq!(item.report.dropped_count(DropKind::EmptyFormField), 2);
    assert!(item.field("remember").is_none());
    assert!(item.field("blank").is_none());
}

// ---------------------------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------------------------

#[test]
fn categories_map_through_the_table_and_an_unknown_id_is_preserved_verbatim() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Login", "https://a.example", "a", "b").category("001"),
        ItemSpec::login("u2", "Card", "https://b.example", "a", "b").category("002"),
        ItemSpec::login("u3", "Key", "https://c.example", "a", "b").category("114"),
        ItemSpec::login("u4", "Martian", "https://d.example", "a", "b").category("999"),
    ]);

    assert_eq!(plan.items[0].category, Category::Login);
    assert_eq!(plan.items[1].category, Category::CreditCard);
    assert_eq!(plan.items[2].category, Category::SshKey);
    assert_eq!(
        plan.items[3].category,
        Category::Other("1Password category 999".to_owned())
    );

    // Only the confirmed row is not a guess.
    assert!(!plan.items[0].category_was_guessed);
    assert!(plan.items[1].category_was_guessed);
    // An unknown id is preserved, not guessed at.
    assert!(!plan.items[3].category_was_guessed);

    // Every item keeps the id, so a corrected table can be applied without re-importing.
    for (item, uuid) in plan.items.iter().zip(["001", "002", "114", "999"]) {
        assert_eq!(category_uuid(item), uuid);
    }
}

#[test]
fn only_the_login_row_of_the_category_table_claims_to_be_verified() {
    assert_eq!(
        category::row("001").map(|r| r.verified),
        Some(Verified::Yes)
    );
    for uuid in [
        "002", "003", "004", "005", "006", "100", "102", "110", "112", "114",
    ] {
        assert_eq!(
            category::row(uuid).map(|r| r.verified),
            Some(Verified::No),
            "{uuid}"
        );
    }
    assert!(category::row("999").is_none());
}

// ---------------------------------------------------------------------------------------------
// Concealment
// ---------------------------------------------------------------------------------------------

#[test]
fn a_guarded_field_of_an_unknown_type_becomes_a_secret() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p").with_section(
            SectionSpec::new(
                "security",
                vec![
                    SectionFieldSpec::typed("recovery", "quantumFoo", json!("classified"))
                        .guarded(true),
                    SectionFieldSpec::typed("colour", "quantumFoo", json!("blue")),
                    SectionFieldSpec::typed(
                        "recovery token",
                        "quantumFoo",
                        json!("also classified"),
                    ),
                ],
            ),
        ),
    ]);

    let item = &plan.items[0];
    // Guarded wins over "I have never heard of this type".
    assert!(item.field("recovery").unwrap().value.is_secret());
    assert_eq!(value_of(item, "recovery"), "classified");
    // An unknown type with a suspicious title is secret too.
    assert!(item.field("recovery token").unwrap().value.is_secret());
    // An unknown type with nothing suspicious about it is kept, publicly, and marked preserved
    // rather than mapped: this build does not know what it is.
    let colour = item.field("colour").unwrap();
    assert!(!colour.value.is_secret());
    assert_eq!(colour.tier, Tier::Preserved);
    assert_eq!(value_of(item, "colour"), "blue");
}

#[test]
fn the_documented_value_types_get_the_field_kinds_they_should() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p").with_section(
            SectionSpec::new(
                "everything",
                vec![
                    SectionFieldSpec::string("note", "text"),
                    SectionFieldSpec::typed("contact", "email", json!("ada@example.com")),
                    SectionFieldSpec::typed("site", "url", json!("https://example.com")),
                    SectionFieldSpec::typed("mobile", "phone", json!("+44 20 7946 0000")),
                    SectionFieldSpec::typed("expiry", "monthYear", json!(202_612)),
                    SectionFieldSpec::typed("brand", "creditCardType", json!("visa")),
                    SectionFieldSpec::typed(
                        "number",
                        "creditCardNumber",
                        json!("4111111111111111"),
                    ),
                ],
            ),
        ),
    ]);

    let item = &plan.items[0];
    assert_eq!(item.field("note").unwrap().kind, FieldKind::Text);
    assert_eq!(item.field("contact").unwrap().kind, FieldKind::Email);
    assert_eq!(item.field("site").unwrap().kind, FieldKind::Url);
    assert_eq!(item.field("mobile").unwrap().kind, FieldKind::Phone);
    assert_eq!(item.field("expiry").unwrap().kind, FieldKind::MonthYear);
    // A number is rendered as its JSON spelling rather than dropped.
    assert_eq!(value_of(item, "expiry"), "202612");
    assert_eq!(item.field("brand").unwrap().kind, FieldKind::CreditCardType);
    assert!(!item.field("brand").unwrap().value.is_secret());
    // A card number is secret material whatever its label says.
    let number = item.field("number").unwrap();
    assert_eq!(number.kind, FieldKind::CreditCardNumber);
    assert!(number.value.is_secret());
}

#[test]
fn an_address_becomes_one_address_line_and_a_field_per_component() {
    let plan = parse_items(&[ItemSpec::login(
        "u1",
        "Ada",
        "https://acme.example",
        "ada",
        "p",
    )
    .with_section(SectionSpec::new(
        "address",
        vec![SectionFieldSpec::typed(
            "home",
            "address",
            json!({ "street": "1 Test Street", "city": "London", "zip": "E1 6AN", "country": "gb" }),
        )],
    ))]);

    let item = &plan.items[0];
    let line = item.field("home").unwrap();
    assert_eq!(line.kind, FieldKind::Address);
    assert_eq!(value_of(item, "home"), "1 Test Street, London, E1 6AN, gb");
    assert_eq!(value_of(item, "home street"), "1 Test Street");
    assert_eq!(value_of(item, "home country"), "gb");
    assert_eq!(item.field("home city").unwrap().tier, Tier::Preserved);
    // "shipping" contains "pin"; an address is not a credential.
    assert!(!item.field("home street").unwrap().value.is_secret());
}

// ---------------------------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------------------------

#[test]
fn a_totp_uri_crosses_unchanged_a_bare_seed_is_wrapped_and_neither_is_ever_public() {
    const URI: &str = "otpauth://totp/Acme:ada?secret=JBSWY3DPEHPK3PXP&issuer=Acme";

    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p").with_section(
            SectionSpec::new(
                "security",
                vec![SectionFieldSpec::totp("one-time password", URI)],
            ),
        ),
        ItemSpec::login("u2", "Bare", "https://bare.example", "ada", "p").with_section(
            SectionSpec::new(
                "security",
                vec![SectionFieldSpec::totp(
                    "one-time password",
                    "JBSWY3DPEHPK3PXP",
                )],
            ),
        ),
    ]);

    let with_uri = &plan.items[0];
    assert_eq!(
        with_uri.field("one-time password").unwrap().kind,
        FieldKind::Totp
    );
    assert!(
        with_uri
            .field("one-time password")
            .unwrap()
            .value
            .is_secret()
    );
    assert_eq!(value_of(with_uri, "one-time password"), URI);

    let bare = &plan.items[1];
    let wrapped = value_of(bare, "one-time password");
    assert!(wrapped.starts_with("otpauth://totp/"), "{wrapped}");
    assert!(wrapped.contains("secret=JBSWY3DPEHPK3PXP"), "{wrapped}");
    assert!(kagisecure_core::Totp::parse_uri(&wrapped).is_ok());
}

#[test]
fn a_one_time_password_this_build_cannot_read_is_kept_rather_than_dropped() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p").with_section(
            SectionSpec::new(
                "security",
                vec![SectionFieldSpec::totp("one-time password", "not a seed!!")],
            ),
        ),
    ]);

    let item = &plan.items[0];
    let field = item.field(UNRECOGNIZED_TOTP_LABEL).expect("kept");
    assert_eq!(field.kind, FieldKind::Concealed);
    assert!(field.value.is_secret());
    assert_eq!(value_of(item, UNRECOGNIZED_TOTP_LABEL), "not a seed!!");
    // Nothing was dropped: a seed this build cannot read is still the user's second factor.
    assert_eq!(item.report.total_dropped(), 0);
    assert!(
        plan.decisions
            .iter()
            .any(|d| d.code == "onepux-totp-unrecognized")
    );
}

// ---------------------------------------------------------------------------------------------
// History, attachments, passkeys
// ---------------------------------------------------------------------------------------------

#[test]
fn password_history_is_imported_and_only_an_unreadable_entry_is_dropped() {
    let plan =
        parse_items(&[
            ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "current")
                .with_history(HistorySpec::new("older-2019", 1_100))
                .with_history(HistorySpec::undated("oldest"))
                .with_history(HistorySpec::new("", 1_200)),
        ]);

    let item = &plan.items[0];
    assert_eq!(item.history.len(), 2);

    assert_eq!(
        item.history[0].value.as_secret().unwrap().expose(),
        b"older-2019"
    );
    assert_eq!(item.history[0].retired_at, Some(1_100));
    // `None` means "the item's own password", which is what `passwordHistory` holds.
    assert_eq!(item.history[0].label, None);

    assert_eq!(
        item.history[1].value.as_secret().unwrap().expose(),
        b"oldest"
    );
    assert_eq!(item.history[1].retired_at, None);

    // Only the valueless entry counts as dropped.
    assert_eq!(item.report.dropped_count(DropKind::PasswordHistory), 1);
    assert_eq!(plan.report().totals.history_entries, 2);
}

#[test]
fn attachments_are_counted_and_their_metadata_kept_while_their_bytes_stay_behind() {
    let plan = parse_items(&[ItemSpec::login(
        "u1",
        "Contract",
        "https://acme.example",
        "ada",
        "p",
    )
    .category("006")
    .with_document(DocumentSpec::new("doc-1", "contract.pdf", b"%PDF-1.7\n"))
    .with_section(SectionSpec::new(
        "files",
        vec![SectionFieldSpec::typed(
            "attachment",
            "file",
            json!({ "fileName": "notes.txt", "documentId": "doc-2", "decryptedSize": 11 }),
        )],
    ))]);

    let item = &plan.items[0];
    assert_eq!(item.report.dropped_count(DropKind::Attachment), 2);
    assert!(item.field("attachment").is_none());

    let Some(ciborium::Value::Array(documents)) = item.extra.get(DOCUMENTS_KEY) else {
        panic!("no document metadata: {:?}", item.extra.keys());
    };
    assert_eq!(documents.len(), 2);
    let rendered = format!("{documents:?}");
    assert!(rendered.contains("contract.pdf"), "{rendered}");
    assert!(rendered.contains("notes.txt"), "{rendered}");
    assert!(rendered.contains("doc-2"), "{rendered}");
}

#[test]
fn passkeys_watchtower_state_and_keys_nobody_knows_are_counted_not_invented() {
    let plan = parse_items(&[
        ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "p")
            .with_extra(
                "passkeys",
                json!([{ "credentialId": "abc" }, { "credentialId": "def" }]),
            )
            .with_extra("quantumField", json!({ "a": 1 }))
            .with_details_extra("watchtowerExclusions", json!(["weak-password"])),
    ]);

    let item = &plan.items[0];
    assert_eq!(item.report.dropped_count(DropKind::Passkey), 2);
    assert_eq!(item.report.dropped_count(DropKind::WatchtowerFlag), 1);
    assert_eq!(item.report.dropped_count(DropKind::UnknownEntry), 1);

    // The *name* of a key nobody knows is kept. Its contents are not.
    let Some(ciborium::Value::Array(unknown)) = item.extra.get(UNKNOWN_KEYS_KEY) else {
        panic!("no unknown-key list: {:?}", item.extra.keys());
    };
    assert_eq!(unknown, &[ciborium::Value::Text("quantumField".to_owned())]);
}

// ---------------------------------------------------------------------------------------------
// Vaults, accounts and the trash
// ---------------------------------------------------------------------------------------------

#[test]
fn one_account_names_vaults_plainly_and_more_than_one_qualifies_them() {
    let single = parse_items(&[
        ItemSpec::login("u1", "One", "https://a.example", "a", "p").in_vault("Personal"),
        ItemSpec::login("u2", "Two", "https://b.example", "a", "p").in_vault("Shared"),
    ]);
    assert_eq!(
        single.target_vault_names(),
        ["Personal".to_owned(), "Shared".to_owned()]
    );

    let multi = parse_items(&[
        ItemSpec::login("u1", "One", "https://a.example", "a", "p")
            .in_account("Ada Lovelace")
            .in_vault("Personal"),
        ItemSpec::login("u2", "Two", "https://b.example", "a", "p")
            .in_account("Work Inc")
            .in_vault("Engineering"),
    ]);
    assert_eq!(
        multi.target_vault_names(),
        [
            "Ada Lovelace / Personal".to_owned(),
            "Work Inc / Engineering".to_owned()
        ]
    );
    assert!(
        multi
            .decisions
            .iter()
            .any(|d| d.code == "onepux-multi-account")
    );
}

#[test]
fn the_trash_is_skipped_unless_it_is_asked_for() {
    let items = [
        ItemSpec::login("u1", "Live", "https://a.example", "a", "p"),
        ItemSpec::login("u2", "Deleted", "https://b.example", "a", "p")
            .state("trashed")
            .timestamps(1_000, 2_000),
    ];
    let bytes = build_1pux(&items);

    let skipped = parse_bytes(&bytes, &Options::default()).unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped.items[0].title, "Live");
    assert!(
        skipped
            .decisions
            .iter()
            .any(|d| d.code == "onepux-trashed-skipped")
    );

    let included = parse_bytes(&bytes, &Options::default().include_trashed(true)).unwrap();
    assert_eq!(included.len(), 2);
    assert_eq!(included.items[1].trashed_at, Some(2_000));
}

// ---------------------------------------------------------------------------------------------
// Archive shapes
// ---------------------------------------------------------------------------------------------

#[test]
fn the_one_level_nested_layout_is_read_like_the_flat_one() {
    let spec = ArchiveSpec::new(&[ItemSpec::login(
        "u1",
        "Acme",
        "https://acme.example",
        "ada",
        "p",
    )])
    .nested_under("export/");

    let plan = parse_archive(&spec).expect("nested archives parse");
    assert_eq!(plan.len(), 1);
    assert!(
        plan.decisions
            .iter()
            .any(|d| d.code == "onepux-nested-layout")
    );
}

#[test]
fn an_entry_name_that_escapes_the_archive_root_is_refused() {
    for name in ["../../etc/passwd", "files/../../escape.txt"] {
        let spec = ArchiveSpec::new(&[]).with_entry(name, b"nope".to_vec());
        let error = parse_archive(&spec).unwrap_err();
        assert!(
            matches!(error, ImportError::UnsafeEntryName),
            "{name}: {error:?}"
        );
        // The complaint does not repeat the name, let alone the contents.
        assert!(!error.to_string().contains(".."), "{error}");
    }
}

#[test]
fn a_zip_bomb_is_refused_from_the_central_directory_without_inflating_it() {
    // 16 MiB of one byte: `tests/fixtures.rs` proves this compresses past 1000:1. The archive
    // itself stays small, and the parser never allocates the 16 MiB — it reads the ratio out of
    // the central directory and stops.
    const SIZE: usize = 16 << 20;
    let spec = ArchiveSpec::new(&[ItemSpec::login(
        "u1",
        "Acme",
        "https://acme.example",
        "ada",
        "p",
    )])
    .with_entry("bomb.bin", compressible_payload(SIZE));
    let bytes = spec.build();
    assert!(bytes.len() < SIZE / 100, "the bomb did not compress");

    let error = parse_bytes(&bytes, &Options::default()).unwrap_err();
    match error {
        ImportError::LimitExceeded { what, limit } => {
            assert!(what.contains("compression ratio"), "{what}");
            assert_eq!(limit, 1_000);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_archive_bigger_than_the_total_limit_is_refused_before_anything_is_read() {
    let bytes = build_1pux(&[ItemSpec::login(
        "u1",
        "Acme",
        "https://acme.example",
        "ada",
        "p",
    )]);
    let options = Options::default().with_limits(Limits {
        max_total_uncompressed: 16,
        ..Limits::default()
    });

    let error = parse_bytes(&bytes, &options).unwrap_err();
    assert!(matches!(
        error,
        ImportError::LimitExceeded {
            what: "uncompressed archive size in bytes",
            limit: 16
        }
    ));
}

#[test]
fn an_export_data_bigger_than_its_own_cap_is_refused() {
    let bytes = build_1pux(&[ItemSpec::login(
        "u1",
        "Acme",
        "https://acme.example",
        "ada",
        "p",
    )]);
    let options = Options::default().with_limits(Limits {
        max_export_data: 8,
        ..Limits::default()
    });

    let error = parse_bytes(&bytes, &options).unwrap_err();
    match error {
        ImportError::LimitExceeded { what, limit } => {
            assert_eq!(what, "size of export.data in bytes");
            assert_eq!(limit, 8);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_truncated_archive_a_malformed_document_and_a_missing_one_all_say_so_structurally() {
    let mut truncated = build_1pux(&[ItemSpec::login(
        "u1",
        "Acme",
        "https://acme.example",
        "ada",
        "p",
    )]);
    truncated.truncate(truncated.len() / 2);
    let error = parse_bytes(&truncated, &Options::default()).unwrap_err();
    assert!(
        matches!(error, ImportError::Malformed { .. }),
        "truncated: {error:?}"
    );

    let malformed = ArchiveSpec::new(&[]).with_raw_export_data(b"{not json".to_vec());
    let error = parse_archive(&malformed).unwrap_err();
    match &error {
        ImportError::Malformed { detail, .. } => {
            assert!(detail.contains("line"), "{detail}");
            // The complaint carries a position, never the token it choked on.
            assert!(!detail.contains("not json"), "{detail}");
        }
        other => panic!("{other:?}"),
    }

    let missing = ArchiveSpec {
        omit_export_data: true,
        ..ArchiveSpec::new(&[])
    };
    let error = parse_bytes(&missing.build(), &Options::default()).unwrap_err();
    match &error {
        ImportError::Malformed { detail, .. } => {
            assert!(detail.contains("export.data"), "{detail}")
        }
        other => panic!("{other:?}"),
    }

    // A header that cannot be read is noted, not fatal: everything that matters is elsewhere.
    let bad_header = ArchiveSpec {
        raw_export_attributes: Some(b"{".to_vec()),
        ..ArchiveSpec::new(&[ItemSpec::login(
            "u1",
            "Acme",
            "https://acme.example",
            "ada",
            "p",
        )])
    };
    let plan = parse_bytes(&bad_header.build(), &Options::default()).unwrap();
    assert_eq!(plan.len(), 1);
    assert!(
        plan.decisions
            .iter()
            .any(|d| d.code == "onepux-attributes-unreadable")
    );
}

#[test]
fn a_file_that_is_not_there_is_named_rather_than_parsed() {
    let error = parse_with(
        std::path::Path::new("/nonexistent/kagisecure/export.1pux"),
        &Options::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ImportError::SourceNotFound(_)), "{error:?}");
}

// ---------------------------------------------------------------------------------------------
// Counting limits
// ---------------------------------------------------------------------------------------------

#[test]
fn too_many_items_too_many_fields_and_too_many_sections_are_each_refused() {
    let items: Vec<ItemSpec> = (0..3)
        .map(|i| ItemSpec::login(&format!("u{i}"), "Acme", "https://a.example", "a", "p"))
        .collect();
    let error = parse_bytes(
        &build_1pux(&items),
        &Options::default().with_limits(Limits {
            max_items: 2,
            ..Limits::default()
        }),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ImportError::LimitExceeded {
            what: "number of items in the export",
            limit: 2
        }
    ));

    let mut wide = ItemSpec::login("u1", "Acme", "https://a.example", "a", "p");
    for i in 0..8 {
        wide = wide.with_login_field(LoginFieldSpec::new(&format!("f{i}"), "T", "value"));
    }
    let error = parse_bytes(
        &build_1pux(&[wide]),
        &Options::default().with_limits(Limits {
            max_fields_per_item: 4,
            ..Limits::default()
        }),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ImportError::LimitExceeded {
            what: "number of fields on one item",
            limit: 4
        }
    ));

    let mut sectioned = ItemSpec::login("u1", "Acme", "https://a.example", "a", "p");
    for i in 0..4 {
        sectioned = sectioned.with_section(SectionSpec::new(
            &format!("s{i}"),
            vec![SectionFieldSpec::string("note", "value")],
        ));
    }
    let error = parse_bytes(
        &build_1pux(&[sectioned]),
        &Options::default().with_limits(Limits {
            max_sections_per_item: 2,
            max_fields_per_item: 100,
            ..Limits::default()
        }),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ImportError::LimitExceeded {
            what: "number of sections on one item",
            limit: 2
        }
    ));
}

// ---------------------------------------------------------------------------------------------
// The canary
// ---------------------------------------------------------------------------------------------

/// Seeded as the current password of an imported item.
const MARKER: &str = "K4G1-1PUX-C4N4RY-4d81f0b7c2e95a63";

/// Seeded as a retired password. History is imported, so it needs its own marker.
const HISTORY_MARKER: &str = "K4G1-1PUX-H1ST0RY-7c3e0a915bd4826f";

/// Seeded as a TOTP seed and a guarded custom field.
const FIELD_MARKER: &str = "K4G1-1PUX-F13LD-2b6d94af07e3518c";

#[test]
fn no_seeded_marker_reaches_a_report_a_debug_rendering_or_an_error() {
    let markers = [MARKER, HISTORY_MARKER, FIELD_MARKER];

    let bytes = build_1pux(&[ItemSpec::login(
        "u1",
        "Acme staging",
        "https://acme.example",
        "deploy",
        MARKER,
    )
    .with_history(HistorySpec::new(HISTORY_MARKER, 1_500_000_000))
    .with_section(SectionSpec::new(
        "security",
        vec![
            SectionFieldSpec::totp("one-time password", FIELD_MARKER),
            SectionFieldSpec::typed("recovery", "quantumFoo", json!(FIELD_MARKER)).guarded(true),
        ],
    ))]);

    let plan = parse_bytes(&bytes, &Options::default()).expect("parses");
    let report = plan.report();

    let renderings: BTreeMap<&str, String> = BTreeMap::from([
        ("the Markdown report", report.to_markdown()),
        (
            "the JSON report",
            serde_json::to_string_pretty(&report).unwrap(),
        ),
        ("the report's Debug", format!("{report:?}")),
        ("the headline", report.headline()),
        ("the plan's Debug", format!("{plan:?}")),
        ("the decisions", format!("{:?}", plan.decisions)),
    ]);
    for (what, rendering) in &renderings {
        for marker in markers {
            assert!(!rendering.contains(marker), "{what} leaked {marker}");
        }
    }
    assert!(format!("{plan:?}").contains("Secret(<redacted>)"));

    // And the markers really did land, so none of the above is vacuous.
    let item = &plan.items[0];
    assert_eq!(value_of(item, "password"), MARKER);
    assert_eq!(
        item.history[0].value.as_secret().unwrap().expose(),
        HISTORY_MARKER.as_bytes()
    );
    assert_eq!(value_of(item, "recovery"), FIELD_MARKER);
    // Labels are metadata and are disclosed by design (threat-model A4).
    assert!(report.to_markdown().contains("Acme staging"));

    // An error raised while the marker is in the file says nothing about it either.
    let poisoned = ArchiveSpec::new(&[])
        .with_raw_export_data(format!("{{\"accounts\": [{MARKER}]}}").into_bytes())
        .build();
    let error = parse_bytes(&poisoned, &Options::default()).unwrap_err();
    for marker in markers {
        assert!(!error.to_string().contains(marker), "{error}");
        assert!(!format!("{error:?}").contains(marker), "{error:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

proptest! {
    /// Adding a hint can only ever make a field *more* secret. This is the property that makes
    /// "fail closed" mean something: no combination of labels, ids or types can talk the rule out
    /// of a concealment it had already decided on.
    #[test]
    fn a_hint_never_makes_a_field_public(
        key in prop::option::of("[a-zA-Z]{0,12}"),
        title in prop::option::of("[\\PC]{0,24}"),
        id in prop::option::of("[\\PC]{0,16}"),
        designation in prop::option::of("[a-zA-Z]{0,12}"),
        login_type in prop::option::of("[A-Z]{0,3}"),
        guarded in any::<bool>(),
    ) {
        let base = ConcealHints {
            value_key: key.as_deref(),
            guarded,
            designation: designation.as_deref(),
            login_field_type: login_type.as_deref(),
            title: title.as_deref(),
            id: id.as_deref(),
        };
        let before = is_concealed(&base);

        let guarded_too = is_concealed(&ConcealHints { guarded: true, ..base });
        let designated = is_concealed(&ConcealHints { designation: Some("password"), ..base });
        let typed_password = is_concealed(&ConcealHints { login_field_type: Some("P"), ..base });
        let named_a_key = is_concealed(&ConcealHints { title: Some("api key"), ..base });
        let typed_concealed = is_concealed(&ConcealHints { value_key: Some("concealed"), ..base });

        prop_assert!(guarded_too >= before);
        prop_assert!(designated >= before);
        prop_assert!(typed_password >= before);
        prop_assert!(named_a_key >= before);
        prop_assert!(typed_concealed);

        // Pure: the same hints always answer the same way.
        let again = is_concealed(&base);
        prop_assert_eq!(again, before);
    }

    /// A secret value type is secret whatever else the field looks like.
    #[test]
    fn a_secret_value_type_is_always_secret(
        index in 0usize..SECRET_KEYS.len(),
        title in "[\\PC]{0,24}",
    ) {
        let concealed = is_concealed(&ConcealHints {
            value_key: Some(SECRET_KEYS[index]),
            title: Some(&title),
            ..ConcealHints::default()
        });
        prop_assert!(concealed);
    }
}

// ---------------------------------------------------------------------------------------------
// The real export, when there is one
// ---------------------------------------------------------------------------------------------

/// Print the `categoryUuid → title` pairs a real export actually contains.
///
/// Ignored by default and run by hand:
///
/// ```text
/// KAGISECURE_1PUX_SAMPLE=~/Workspace/kagisecure-fixtures/sample.1pux \
///   cargo test -p kagisecure-import probe_sample_categories -- --ignored --nocapture
/// ```
///
/// This is how a row of `category::CATEGORIES` and a key of `onepux::VALUE_KEYS` graduate from
/// `Verified::No`. It prints ids, titles, field labels and value-type keys — all metadata — and
/// **no values**: nothing here touches `ImportedValue`.
#[test]
#[ignore = "needs a real 1PUX export in $KAGISECURE_1PUX_SAMPLE"]
fn probe_sample_categories() {
    let Ok(path) = std::env::var("KAGISECURE_1PUX_SAMPLE") else {
        panic!("set KAGISECURE_1PUX_SAMPLE to a real .1pux file");
    };

    let plan = parse_with(
        std::path::Path::new(&path),
        &Options::default().include_trashed(true),
    )
    .expect("the sample parses");

    let mut by_uuid: BTreeMap<String, (usize, Vec<String>, String)> = BTreeMap::new();
    for item in &plan.items {
        let uuid = category_uuid(item).to_owned();
        let entry = by_uuid
            .entry(uuid)
            .or_insert_with(|| (0, Vec::new(), item.category.as_str().to_owned()));
        entry.0 += 1;
        if entry.1.len() < 3 {
            entry.1.push(item.title.clone());
        }
    }

    println!("\n{} items, {} categories", plan.len(), by_uuid.len());
    println!("{:<6} {:<7} {:<20} titles", "uuid", "items", "mapped to");
    for (uuid, (count, titles, mapped)) in &by_uuid {
        let known = if category::row(uuid).is_some() {
            ""
        } else {
            "  <- NOT IN THE TABLE"
        };
        println!("{uuid:<6} {count:<7} {mapped:<20} {titles:?}{known}");
    }

    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    for item in &plan.items {
        for field in &item.fields {
            *labels
                .entry(format!("{} ({})", field.label, field.kind))
                .or_default() += 1;
        }
    }
    println!("\nfield labels and kinds:");
    for (label, count) in &labels {
        println!("  {count:<5} {label}");
    }

    println!("\ndecisions:");
    for decision in &plan.decisions {
        println!("  {}: {}", decision.code, decision.detail);
    }

    let report = plan.report();
    println!("\n{}", report.headline());
    for note in &report.dropped {
        println!("  dropped {} x {}", note.count, note.what);
    }
}

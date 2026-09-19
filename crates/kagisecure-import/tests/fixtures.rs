//! The fixture builder, checked against itself.
//!
//! `tests/common/mod.rs` is the input side of every 1PUX test WP1 will write, so it needs its own
//! tests: a fixture that is subtly wrong produces a parser that is subtly wrong and a suite that
//! agrees with it. These assertions read an archive back with the same `zip` and `serde_json` the
//! parser will use, and check that what came out is the shape 1Password documents.

mod common;

use std::io::Read;

use common::{
    ArchiveSpec, DocumentSpec, HistorySpec, ItemSpec, LoginFieldSpec, SectionFieldSpec,
    SectionSpec, build_1pux, compressible_payload,
};
use serde_json::{Value, json};

/// Read one entry out of an archive.
fn entry(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("zip");
    let mut file = archive
        .by_name(name)
        .unwrap_or_else(|e| panic!("no entry {name:?}: {e}"));
    let mut out = Vec::new();
    file.read_to_end(&mut out).expect("read entry");
    out
}

/// Every entry name in an archive, in central-directory order.
fn entry_names(bytes: &[u8]) -> Vec<String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("zip");
    (0..archive.len())
        .map(|i| archive.by_index(i).expect("entry").name().to_owned())
        .collect()
}

fn export_data(bytes: &[u8]) -> Value {
    serde_json::from_slice(&entry(bytes, "export.data")).expect("export.data is JSON")
}

#[test]
fn a_minimal_archive_has_the_two_documented_entries() {
    let bytes = build_1pux(&[ItemSpec::login(
        "uuid-1",
        "Acme",
        "https://acme.example.com",
        "ada",
        "hunter2",
    )]);

    let names = entry_names(&bytes);
    assert!(names.contains(&"export.attributes".to_owned()), "{names:?}");
    assert!(names.contains(&"export.data".to_owned()), "{names:?}");

    let attributes: Value =
        serde_json::from_slice(&entry(&bytes, "export.attributes")).expect("attributes");
    assert_eq!(attributes["version"], 3);

    let data = export_data(&bytes);
    let item = &data["accounts"][0]["vaults"][0]["items"][0];
    assert_eq!(item["uuid"], "uuid-1");
    assert_eq!(item["categoryUuid"], "001");
    assert_eq!(item["state"], "active");
    assert_eq!(item["overview"]["title"], "Acme");
    assert_eq!(item["overview"]["url"], "https://acme.example.com");
    assert_eq!(item["details"]["loginFields"][0]["designation"], "username");
    assert_eq!(item["details"]["loginFields"][1]["type"], "P");
    assert_eq!(item["details"]["loginFields"][1]["value"], "hunter2");
}

#[test]
fn items_group_into_the_accounts_and_vaults_they_name() {
    let bytes = build_1pux(&[
        ItemSpec::login("u1", "One", "https://a.example", "ada", "p1").in_vault("Personal"),
        ItemSpec::login("u2", "Two", "https://b.example", "ada", "p2").in_vault("Shared"),
        ItemSpec::login("u3", "Three", "https://c.example", "ada", "p3")
            .in_account("Work Inc")
            .in_vault("Engineering"),
    ]);

    let data = export_data(&bytes);
    let accounts = data["accounts"].as_array().expect("accounts");
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0]["attrs"]["name"], "Ada Lovelace");
    let vaults = accounts[0]["vaults"].as_array().expect("vaults");
    assert_eq!(vaults.len(), 2);
    assert_eq!(vaults[0]["attrs"]["name"], "Personal");
    assert_eq!(vaults[1]["attrs"]["name"], "Shared");
    assert_eq!(accounts[1]["vaults"][0]["attrs"]["name"], "Engineering");
    // Multi-account naming (plan §9 decision 7) needs to be able to tell them apart.
    assert_ne!(accounts[0]["attrs"]["uuid"], accounts[1]["attrs"]["uuid"]);
}

#[test]
fn every_documented_item_feature_can_be_expressed() {
    let spec = ItemSpec::login("u1", "Acme", "https://acme.example", "ada", "hunter2")
        .category("002")
        .state("archived")
        .fav_index(3)
        .timestamps(1_000, 2_000)
        .tags(&["work", "finance"])
        .with_url("admin", "https://admin.acme.example")
        .notes("line one\nline two")
        .with_login_field(LoginFieldSpec::new("phone", "TEL", "+44 20 7946 0000"))
        .with_section(SectionSpec::new(
            "security",
            vec![
                SectionFieldSpec::concealed("PIN", "0451").guarded(true),
                SectionFieldSpec::totp("one-time password", "otpauth://totp/Acme?secret=AAAA"),
                SectionFieldSpec::string("note", "visible").multiline(true),
                // A type key nobody has ever seen, with a hint beside it: the fail-closed case.
                SectionFieldSpec::typed("recovery", "quantumFoo", json!("value"))
                    .with_id("f-recovery")
                    .with_extra("inputTraits", json!({ "keyboard": "default" })),
            ],
        ))
        .with_section(SectionSpec::untitled(vec![SectionFieldSpec::string(
            "loose", "value",
        )]))
        .with_history(HistorySpec::new("older-2019", 1_100))
        .with_history(HistorySpec::undated("oldest"))
        .with_document(DocumentSpec::new("doc-1", "contract.pdf", b"%PDF-1.7\n"))
        .with_extra("passkeys", json!([{ "credentialId": "abc" }]))
        .with_details_extra("watchtowerExclusions", json!(["weak-password"]));

    let bytes = build_1pux(&[spec]);
    let data = export_data(&bytes);
    let item = &data["accounts"][0]["vaults"][0]["items"][0];

    assert_eq!(item["categoryUuid"], "002");
    assert_eq!(item["state"], "archived");
    assert_eq!(item["favIndex"], 3);
    assert_eq!(item["createdAt"], 1_000);
    assert_eq!(item["updatedAt"], 2_000);
    assert_eq!(item["overview"]["tags"], json!(["work", "finance"]));
    assert_eq!(item["overview"]["urls"][0]["label"], "admin");
    assert_eq!(item["details"]["notesPlain"], "line one\nline two");
    assert_eq!(item["details"]["loginFields"][2]["type"], "TEL");

    let sections = item["details"]["sections"].as_array().expect("sections");
    assert_eq!(sections.len(), 2);
    assert_eq!(sections[0]["title"], "security");
    let fields = sections[0]["fields"].as_array().expect("fields");
    assert_eq!(fields[0]["value"]["concealed"], "0451");
    assert_eq!(fields[0]["guarded"], true);
    assert!(fields[1]["value"]["totp"].is_string());
    assert_eq!(fields[2]["multiline"], true);
    assert_eq!(fields[3]["value"]["quantumFoo"], "value");
    assert_eq!(fields[3]["id"], "f-recovery");
    assert!(fields[3]["inputTraits"].is_object());
    assert_eq!(sections[1]["title"], "");

    // History: `value` + `time`, and an entry the export gave no time for.
    let history = item["details"]["passwordHistory"]
        .as_array()
        .expect("passwordHistory");
    assert_eq!(history[0], json!({ "value": "older-2019", "time": 1_100 }));
    assert_eq!(history[1], json!({ "value": "oldest" }));

    assert_eq!(
        item["details"]["documentAttributes"]["fileName"],
        "contract.pdf"
    );
    assert_eq!(item["details"]["documentAttributes"]["decryptedSize"], 9);
    assert_eq!(entry(&bytes, "files/doc-1___contract.pdf"), b"%PDF-1.7\n");

    // Arbitrary keys land where they were put, so "what does the parser do with this" is
    // answerable without editing the builder.
    assert_eq!(item["passkeys"][0]["credentialId"], "abc");
    assert_eq!(item["details"]["watchtowerExclusions"][0], "weak-password");
}

#[test]
fn an_archive_can_be_wrong_on_purpose() {
    // A traversal entry name, kept verbatim: `ZipFile::enclosed_name()` is what has to refuse it,
    // and it cannot be tested against an archive that never contained one.
    let bytes = ArchiveSpec::new(&[])
        .with_entry("../../etc/passwd", b"root:x:0:0\n".to_vec())
        .with_entry("files/../../escape.txt", b"nope".to_vec())
        .build();
    let names = entry_names(&bytes);
    assert!(names.contains(&"../../etc/passwd".to_owned()), "{names:?}");
    assert!(
        names.contains(&"files/../../escape.txt".to_owned()),
        "{names:?}"
    );

    // Malformed JSON where `export.data` should be.
    let bytes = ArchiveSpec::new(&[])
        .with_raw_export_data(b"{not json".to_vec())
        .build();
    assert_eq!(entry(&bytes, "export.data"), b"{not json");

    // No `export.data` at all.
    let bytes = ArchiveSpec {
        omit_export_data: true,
        ..ArchiveSpec::new(&[])
    }
    .build();
    assert!(!entry_names(&bytes).contains(&"export.data".to_owned()));

    // The one-level-nested layout.
    let bytes = ArchiveSpec::new(&[]).nested_under("export/").build();
    assert!(entry_names(&bytes).contains(&"export/export.data".to_owned()));
}

#[test]
fn a_compressible_payload_really_does_compress() {
    // The shape of the zip-bomb test WP1 writes: 16 MiB of one byte, in an archive small enough
    // that this test costs nothing. The limits in `onepux/limits.rs` read the *uncompressed*
    // size from the central directory, which is why the ratio has to be real.
    const SIZE: usize = 16 << 20;
    let bytes = ArchiveSpec::new(&[])
        .with_entry("bomb.bin", compressible_payload(SIZE))
        .build();

    assert!(
        bytes.len() < SIZE / 100,
        "the payload did not compress: {} bytes for {SIZE}",
        bytes.len()
    );

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("zip");
    let file = archive.by_name("bomb.bin").expect("bomb entry");
    assert_eq!(file.size(), SIZE as u64);
    assert!(file.compressed_size() * 1_000 < file.size());
}

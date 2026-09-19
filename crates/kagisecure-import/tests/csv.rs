//! The CSV family: dialect detection, encoding handling and per-format mapping (plan §6).
//!
//! Every dialect is exercised through [`kagisecure_import::csv::parse`] directly — the top-level
//! [`kagisecure_import::parse`] only has to pick *a* parser (`tests/csv.rs`'s sibling in `lib.rs`
//! covers that), and the sniff for "is this a zip" is not this module's concern.

use std::fs::File;
use std::io::Write;

use kagisecure_core::model::{Category, FieldKind};
use kagisecure_import::csv::parse;
use kagisecure_import::error::ImportError;
use kagisecure_import::ir::SourceKind;

/// Write `contents` (already including any BOM bytes the caller wants) to a fresh temp file and
/// hand back the directory guard alongside its path.
fn write_csv(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.csv");
    std::fs::write(&path, contents).unwrap();
    (dir, path)
}

// ---------------------------------------------------------------------------------------------
// Dialect detection
// ---------------------------------------------------------------------------------------------

#[test]
fn apple_csv_is_detected_from_its_header_and_maps_every_column() {
    let (_dir, path) = write_csv(
        b"Title,URL,Username,Password,Notes,OTPAuth\n\
          Acme,https://acme.example.com/login,ada,hunter2,a note,JBSWY3DPEHPK3PXP\n",
    );

    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::AppleCsv);
    assert_eq!(plan.len(), 1);

    let item = &plan.items[0];
    assert_eq!(item.title, "Acme");
    assert_eq!(item.category, Category::Login);
    assert!(!item.category_was_guessed);
    assert_eq!(item.urls, ["https://acme.example.com/login"]);
    assert!(item.tags.contains(&"imported:apple".to_owned()));
    assert_eq!(
        item.field("username").unwrap().value.as_public(),
        Some("ada")
    );
    assert_eq!(
        item.field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        b"hunter2"
    );
    assert_eq!(item.field("password").unwrap().kind, FieldKind::Concealed);
    assert_eq!(item.notes.as_deref(), Some("a note"));
    let otp = item.field("one-time password").unwrap();
    assert_eq!(otp.kind, FieldKind::Totp);
    assert!(
        otp.value
            .as_secret()
            .unwrap()
            .expose_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    // Apple/Chromium carry no timestamps of their own; commit fills both in at import time.
    assert_eq!(item.created_at, None);
    assert_eq!(item.updated_at, None);
}

#[test]
fn chromium_csv_is_detected_in_its_five_and_four_column_forms() {
    let (_dir, five) = write_csv(
        b"name,url,username,password,note\n\
          Acme,https://acme.example.com,ada,hunter2,a note\n",
    );
    let plan = parse(&five, None).unwrap();
    assert_eq!(plan.source, SourceKind::ChromiumCsv);
    assert_eq!(plan.items[0].notes.as_deref(), Some("a note"));

    let (_dir, four) = write_csv(
        b"name,url,username,password\n\
          Acme,https://acme.example.com,ada,hunter2\n",
    );
    let plan = parse(&four, None).unwrap();
    assert_eq!(plan.source, SourceKind::ChromiumCsv);
    assert_eq!(plan.items[0].notes, None);
    assert!(plan.items[0].tags.contains(&"imported:chromium".to_owned()));
}

#[test]
fn firefox_csv_maps_millisecond_timestamps_and_the_guid_foreign_key() {
    let (_dir, path) = write_csv(
        b"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n\
          https://acme.example.com/login,ada,hunter2,,https://acme.example.com,{guid-0001},1700000000000,1700000100000,1700000200000\n",
    );

    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::FirefoxCsv);
    let item = &plan.items[0];

    // No title column at all: the host of the URL stands in.
    assert_eq!(item.title, "acme.example.com");
    assert_eq!(item.created_at, Some(1_700_000_000));
    assert_eq!(item.updated_at, Some(1_700_000_200));
    assert_eq!(item.foreign_id.as_ref().unwrap().value, "{guid-0001}");
    assert_eq!(
        item.extra
            .get("firefox_form_action_origin")
            .and_then(ciborium::Value::as_text),
        Some("https://acme.example.com")
    );
    assert!(
        item.report
            .preserved
            .contains(&"formActionOrigin".to_owned())
    );
    // An empty httpRealm cell is not preserved as metadata.
    assert!(!item.extra.contains_key("firefox_http_realm"));
}

#[test]
fn one_password_csv_is_detected_with_the_website_and_one_time_password_aliases() {
    let (_dir, path) = write_csv(
        b"title,website,username,password,one-time password,favorite,archived,tags,notes\n\
          Acme,https://acme.example.com,ada,hunter2,,1,0,\"work, prod\",a note\n",
    );

    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::OnePasswordCsv);
    let item = &plan.items[0];
    assert!(item.favorite);
    assert!(!item.archived);
    assert!(item.tags.contains(&"work".to_owned()));
    assert!(item.tags.contains(&"prod".to_owned()));
    assert!(item.tags.contains(&"imported:1password".to_owned()));
    assert_eq!(item.notes.as_deref(), Some("a note"));
    assert!(
        plan.decisions
            .iter()
            .any(|d| d.code == "higher-fidelity-path" && d.detail.contains("1PUX"))
    );
}

#[test]
fn header_order_does_not_affect_detection_or_extraction() {
    let (_dir, path) = write_csv(
        b"Password,Username,Title,OTPAuth,Notes,URL\n\
          hunter2,ada,Acme,,,https://acme.example.com\n",
    );
    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::AppleCsv);
    assert_eq!(plan.items[0].title, "Acme");
    assert_eq!(
        plan.items[0].field("username").unwrap().value.as_public(),
        Some("ada")
    );
}

#[test]
fn an_unrecognized_header_names_the_format_flag() {
    let (_dir, path) = write_csv(b"title,url,username,password\nAcme,https://a,ada,hunter2\n");
    let err = parse(&path, None).unwrap_err();
    assert!(matches!(err, ImportError::UndetectedFormat { .. }));
    assert!(err.to_string().contains("--format"));
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

#[test]
fn a_utf8_bom_is_stripped_before_detection() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(
        b"title,url,username,password,notes,otpauth\nAcme,https://a,ada,hunter2,,\n",
    );
    let (_dir, path) = write_csv(&bytes);

    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::AppleCsv);
    assert_eq!(plan.items[0].title, "Acme");
}

#[test]
fn a_utf16_bom_is_a_hard_error_naming_re_encoding() {
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend_from_slice(b"t\0i\0t\0l\0e\0\n\0");
    let (_dir, path) = write_csv(&bytes);

    let err = parse(&path, None).unwrap_err();
    match &err {
        ImportError::Encoding { detail, .. } => {
            assert!(detail.to_lowercase().contains("utf-16"));
            assert!(detail.to_lowercase().contains("utf-8"));
        }
        other => panic!("expected an encoding error, got {other:?}"),
    }
}

#[test]
fn invalid_utf8_names_a_position_and_never_the_row() {
    let mut bytes = b"title,url,username,password,notes,otpauth\n".to_vec();
    bytes.extend_from_slice(b"Acme,https://a,ada,");
    bytes.extend_from_slice(&[0xFF, 0xFE]); // not valid UTF-8 in a text field
    bytes.extend_from_slice(b",,\n");
    let (_dir, path) = write_csv(&bytes);

    let err = parse(&path, None).unwrap_err();
    match &err {
        ImportError::Encoding { offset, row, .. } => {
            assert!(offset.is_some());
            assert!(row.is_some());
        }
        other => panic!("expected an encoding error, got {other:?}"),
    }
    assert!(!err.to_string().contains("Acme"));
}

// ---------------------------------------------------------------------------------------------
// Quoting, multiline, CRLF, Unicode
// ---------------------------------------------------------------------------------------------

#[test]
fn quoted_commas_and_multiline_notes_survive_the_round_trip() {
    let (_dir, path) = write_csv(
        b"title,url,username,password,notes,otpauth\r\n\
          \"Acme, Inc.\",https://a,ada,hunter2,\"line one\nline two\",\r\n",
    );
    let plan = parse(&path, None).unwrap();
    let item = &plan.items[0];
    assert_eq!(item.title, "Acme, Inc.");
    assert_eq!(item.notes.as_deref(), Some("line one\nline two"));
}

#[test]
fn crlf_line_endings_are_handled_without_leaking_into_values() {
    let (_dir, path) = write_csv(
        b"name,url,username,password\r\nAcme,https://a,ada,hunter2\r\nOther,https://b,eve,secret\r\n",
    );
    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.len(), 2);
    assert!(!plan.items[0].title.contains('\r'));
    assert_eq!(plan.items[1].title, "Other");
}

#[test]
fn unicode_titles_round_trip() {
    let (_dir, path) = write_csv(
        "title,url,username,password,notes,otpauth\n\u{5bb6}\u{65cf}\u{30d1}\u{30b9}\u{30ef}\u{30fc}\u{30c9},https://a,ada,hunter2,,\n"
            .as_bytes(),
    );
    let plan = parse(&path, None).unwrap();
    assert_eq!(
        plan.items[0].title,
        "\u{5bb6}\u{65cf}\u{30d1}\u{30b9}\u{30ef}\u{30fc}\u{30c9}"
    );
}

// ---------------------------------------------------------------------------------------------
// Explicit --format
// ---------------------------------------------------------------------------------------------

#[test]
fn an_explicit_format_skips_detection_but_still_validates_columns() {
    // This header would never detect as anything (it is missing `guid` and the timestamps), but
    // an explicit `--format firefox-csv` should at least try, and fail on the real gap.
    let (_dir, path) = write_csv(b"url,username,password\nhttps://a,ada,hunter2\n");
    let err = parse(&path, Some(SourceKind::FirefoxCsv)).unwrap_err();
    assert!(matches!(
        err,
        ImportError::MissingColumn {
            source_kind: SourceKind::FirefoxCsv,
            ..
        }
    ));
}

#[test]
fn an_explicit_format_overrides_a_header_that_would_detect_differently() {
    // A legitimate Chromium 4-column header, but the caller insists it is Apple's. Apple's
    // required columns (title, notes, otpauth) are absent, so this must fail rather than guess.
    let (_dir, path) = write_csv(b"name,url,username,password\nAcme,https://a,ada,hunter2\n");
    let err = parse(&path, Some(SourceKind::AppleCsv)).unwrap_err();
    assert!(matches!(
        err,
        ImportError::MissingColumn {
            source_kind: SourceKind::AppleCsv,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------------------------
// Skipped rows
// ---------------------------------------------------------------------------------------------

#[test]
fn rows_with_no_username_and_no_password_are_skipped_and_reported() {
    let (_dir, path) = write_csv(
        b"name,url,username,password\n\
          Acme,https://a,ada,hunter2\n\
          Empty,https://b,,\n\
          Also empty,https://c,,\n",
    );
    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.len(), 1);
    assert!(
        plan.decisions
            .iter()
            .any(|d| d.code == "rows-skipped-empty" && d.detail.contains('2'))
    );
}

// ---------------------------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------------------------

#[test]
fn a_bare_totp_seed_is_wrapped_and_a_garbage_one_falls_back_unrecognized() {
    let (_dir, path) = write_csv(
        b"title,url,username,password,notes,otpauth\n\
          Good,https://a,ada,hunter2,,JBSWY3DPEHPK3PXP\n\
          Bad,https://b,eve,hunter3,,not-a-real-seed!!\n",
    );
    let plan = parse(&path, None).unwrap();

    let good = plan.items.iter().find(|i| i.title == "Good").unwrap();
    let otp = good.field("one-time password").unwrap();
    assert_eq!(otp.kind, FieldKind::Totp);

    let bad = plan.items.iter().find(|i| i.title == "Bad").unwrap();
    let fallback = bad.field("one-time password (unrecognized)").unwrap();
    assert_eq!(fallback.kind, FieldKind::Concealed);
    assert_eq!(
        fallback.value.as_secret().unwrap().expose(),
        b"not-a-real-seed!!"
    );
}

// ---------------------------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fifty_megabyte_csv_streams_row_by_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.csv");
    {
        let file = File::create(&path).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(b"title,url,username,password,notes,otpauth\n")
            .unwrap();
        let row = b"Example Site,https://example.com/login,user@example.com,correct-horse-battery-staple,,\n";
        let target: usize = 50 * 1024 * 1024;
        let mut written = 0usize;
        while written < target {
            writer.write_all(row).unwrap();
            written += row.len();
        }
        writer.flush().unwrap();
    }

    let plan = parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::AppleCsv);
    assert!(plan.len() > 400_000, "only {} items", plan.len());
    assert!(plan.items.iter().all(|i| i.title == "Example Site"));
}

// ---------------------------------------------------------------------------------------------
// Canary: a marker password and TOTP seed must never appear in a report, its JSON, its Debug,
// or an error string.
// ---------------------------------------------------------------------------------------------

const MARKER: &str = "K4G1-CSV-C4N4RY-3f9a7c21e8b04d6a";

#[test]
fn the_marker_password_and_totp_seed_never_reach_a_report_or_an_error() {
    let (_dir, path) = write_csv(
        format!(
            "title,url,username,password,notes,otpauth\nAcme,https://a,ada,{MARKER},,{MARKER}\n"
        )
        .as_bytes(),
    );
    let plan = parse(&path, None).unwrap();
    let report = plan.report();

    assert!(!report.to_markdown().contains(MARKER));
    assert!(!serde_json::to_string(&report).unwrap().contains(MARKER));
    assert!(!format!("{report:?}").contains(MARKER));
    assert!(!format!("{plan:?}").contains(MARKER));

    // And through the error path: a marker planted in a column that fails detection must not
    // leak either.
    let (_dir, bad_path) = write_csv(format!("title,password\nAcme,{MARKER}\n").as_bytes());
    let err = kagisecure_import::parse(&bad_path, None).unwrap_err();
    assert!(!err.to_string().contains(MARKER));
    assert!(!format!("{err:?}").contains(MARKER));
}

#[test]
fn top_level_parse_routes_a_plain_csv_file_to_the_csv_parser() {
    let (_dir, path) = write_csv(b"name,url,username,password\nAcme,https://a,ada,hunter2\n");
    let plan = kagisecure_import::parse(&path, None).unwrap();
    assert_eq!(plan.source, SourceKind::ChromiumCsv);
}

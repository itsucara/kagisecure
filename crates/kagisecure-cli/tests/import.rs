//! End-to-end tests for `kagisecure import`.
//!
//! WP1's 1PUX parser and WP2's CSV parsers both landed while this file was being written. The
//! first half of the file exercises the CLI's own plumbing — argument validation, exit codes,
//! the dry-run invariant, and that nothing ever echoes source content — against inputs that fail
//! to parse, which holds regardless of what any parser does. The second half needs a source a
//! parser actually accepts, so it builds one: a plain CSV for the dialects, and a tiny
//! hand-written 1PUX archive (via the `zip` crate) for the format that needs one.

use std::io::Write;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::str::contains;

const PASSWORD: &str = "correct horse battery staple";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("test.kagivault");
        Self { _dir: dir, vault }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("kagisecure").unwrap();
        cmd.arg("--vault").arg(&self.vault).arg("--password-stdin");
        // Make sure an ambient environment variable cannot influence the test.
        cmd.env_remove("KAGISECURE_VAULT");
        cmd
    }

    fn init(&self) {
        self.cmd()
            .args(["vault", "init", "--kdf-m-kib", "64", "--kdf-t", "1"])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success();
    }
}

/// A file that is not any supported export, for the tests that only need parsing to fail.
fn garbage_file(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"not an export of anything\n").unwrap();
    path
}

// ---------------------------------------------------------------------------------------------
// Failure paths: hold no matter what a parser does with a well-formed source
// ---------------------------------------------------------------------------------------------

#[test]
fn a_garbage_source_fails_with_exit_7() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.csv");

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap()])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7);
}

#[test]
fn an_explicit_csv_dialect_that_the_file_does_not_match_fails_with_exit_7_not_2() {
    // `apple-csv` is a real `SourceKind` and `--format` skips detection, but the CSV parser still
    // validates that the columns a dialect needs are present. A file that has none of them is an
    // import failure (missing columns), not a usage error: the flag itself was fine.
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.csv");

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap(), "--format", "apple-csv"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7)
        .stderr(contains("column"));
}

#[test]
fn a_malformed_1pux_archive_fails_with_exit_7() {
    // WP1's 1PUX parser is real: a `.1pux` that is not actually a zip is a parse failure, not
    // "unsupported" — still exit 7, with a structural complaint and none of the file's bytes.
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.1pux");

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap(), "--format", "1pux"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7)
        .stderr(contains("not a zip archive"));
}

#[test]
fn dry_run_never_writes_to_the_vault_even_when_the_parse_fails() {
    let fixture = Fixture::new();
    fixture.init();
    let before = std::fs::read(&fixture.vault).unwrap();
    let before_modified = std::fs::metadata(&fixture.vault)
        .unwrap()
        .modified()
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.1pux");

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap(), "--dry-run"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7);

    let after = std::fs::read(&fixture.vault).unwrap();
    let after_modified = std::fs::metadata(&fixture.vault)
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(before, after, "dry-run must never touch the vault file");
    assert_eq!(before_modified, after_modified);
}

#[test]
fn an_unknown_format_is_a_usage_error_not_an_import_failure() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.csv");

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap(), "--format", "lastpass"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(2)
        .stderr(contains("--format"));
}

#[test]
fn an_unknown_on_duplicate_value_is_a_usage_error() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.csv");

    fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--on-duplicate",
            "interactive",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(2)
        .stderr(contains("--on-duplicate"));
}

#[test]
fn every_documented_on_duplicate_value_reaches_the_importer() {
    // None of these succeed yet (the parsers are stubs), but all three must get past argument
    // parsing and fail as an *import* failure (exit 7), not a usage error (exit 2) — proof the
    // value was accepted, not rejected before it got there.
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.csv");

    for policy in ["skip", "update", "keep-both"] {
        fixture
            .cmd()
            .args(["import", source.to_str().unwrap(), "--on-duplicate", policy])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .code(7);
    }
}

#[test]
fn logical_vault_is_independent_of_the_global_vault_flag() {
    // The global `--vault` names the vault *file*; `import --logical-vault` names a vault
    // *inside* it. This is the reason the CLI grammar does not spell the second one `--vault`
    // too (see `cli::ImportArgs::logical_vault`) — asserted here by using both in one
    // invocation and checking the file `--vault` pointed at is the one that got opened.
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = garbage_file(dir.path(), "export.csv");

    fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--logical-vault",
            "Personal",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7);
    assert!(fixture.vault.exists());
}

#[test]
fn a_parse_failure_never_echoes_the_source_files_bytes() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let marker = "K4G1-CLI-CANARY-9f1c3e77";
    let source = dir.path().join("export.csv");
    std::fs::write(&source, format!("title,password\nAcme,{marker}\n")).unwrap();

    let assertion = fixture
        .cmd()
        .args(["import", source.to_str().unwrap()])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7);
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(!stderr.contains(marker), "{stderr}");
    assert!(!stdout.contains(marker), "{stdout}");
}

// ---------------------------------------------------------------------------------------------
// Success paths: a source a real parser accepts
// ---------------------------------------------------------------------------------------------

/// A minimal, otherwise-valid Apple CSV export: header signature plus one row.
fn apple_csv(password: &str) -> String {
    format!(
        "title,url,username,password,notes,otpauth\nAcme staging,https://acme.example.com/login,ada,{password},,\n"
    )
}

/// A minimal hand-written 1PUX archive, built from the shape `docs/import.md` §2.1 describes.
///
/// Field names marked "unverified" there are reproduced as documented; this is a best effort so
/// the test has something plausible to run against once WP1 lands, not a claim that the shape is
/// confirmed against a real export.
fn build_1pux(password: &str) -> Vec<u8> {
    build_1pux_items(vec![login_item(
        "item-0001",
        "Acme staging",
        "active",
        password,
    )])
}

/// The same fixture, plus a second item already in 1Password's trash — for proving
/// `--include-trashed` actually changes what a real import brings in.
fn build_1pux_with_trashed(password: &str) -> Vec<u8> {
    build_1pux_items(vec![
        login_item("item-0001", "Acme staging", "active", password),
        login_item("item-0002", "Old site", "trashed", "retired-password"),
    ])
}

/// One `details.loginFields[]`-carrying item node, as `docs/import.md` §2.1 describes it.
fn login_item(uuid: &str, title: &str, state: &str, password: &str) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid,
        "favIndex": 0,
        "createdAt": 1_700_000_000i64,
        "updatedAt": 1_700_000_000i64,
        "state": state,
        "categoryUuid": "001",
        "overview": {
            "title": title,
            "url": "https://acme.example.com/login",
            "urls": [{ "label": "website", "url": "https://acme.example.com/login" }],
            "tags": [],
        },
        "details": {
            "loginFields": [
                { "value": "ada", "name": "username", "type": "T", "designation": "username" },
                { "value": password, "name": "password", "type": "P", "designation": "password" },
            ],
            "notesPlain": "",
            "sections": [],
            "passwordHistory": [],
        },
    })
}

/// Wrap `items` in the account/vault/export shell every 1PUX fixture in this file needs.
fn build_1pux_items(items: Vec<serde_json::Value>) -> Vec<u8> {
    use std::io::Cursor;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    let attributes = serde_json::json!({
        "version": 1,
        "description": "kagisecure CLI test fixture",
        "createdAt": 1_700_000_000i64,
    });

    let data = serde_json::json!({
        "accounts": [{
            "attrs": {
                "accountName": "Test Account",
                "name": "Ada",
                "email": "ada@example.com",
                "uuid": "account-0001",
            },
            "vaults": [{
                "attrs": { "uuid": "vault-0001", "desc": "", "name": "Personal", "type": "U" },
                "items": items,
            }],
        }],
    });

    let mut buf = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut buf);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("export.attributes", options).unwrap();
        zip.write_all(attributes.to_string().as_bytes()).unwrap();
        zip.start_file("export.data", options).unwrap();
        zip.write_all(data.to_string().as_bytes()).unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn json_output_is_the_serialized_report() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.csv");
    std::fs::write(&source, apple_csv("hunter2")).unwrap();

    let assertion = fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--format",
            "apple-csv",
            "--json",
            "--dry-run",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = assertion.get_output().stdout.clone();
    let value: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(value["totals"]["items"], 1);
    assert_eq!(value["source"], "apple-csv");
    assert!(!String::from_utf8_lossy(&stdout).contains("hunter2"));
}

#[test]
fn report_file_is_written_with_mode_0600() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.csv");
    std::fs::write(&source, apple_csv("hunter2")).unwrap();
    let report_path = dir.path().join("report.md");

    fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--format",
            "apple-csv",
            "--dry-run",
            "--report",
        ])
        .arg(&report_path)
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    let contents = std::fs::read_to_string(&report_path).unwrap();
    assert!(!contents.contains("hunter2"));
    assert!(contents.contains("Acme staging"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&report_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }
}

#[test]
fn json_output_from_a_real_1pux_import_is_the_serialized_report() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.1pux");
    std::fs::write(&source, build_1pux("hunter2")).unwrap();

    let assertion = fixture
        .cmd()
        .args(["import", source.to_str().unwrap(), "--json", "--dry-run"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = assertion.get_output().stdout.clone();
    let value: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(value["totals"]["items"], 1);
    // `SourceKind` serializes to `SourceKind::as_str()`'s spelling — the same one the CLI's own
    // `--format 1pux` and the human-readable headline use.
    assert_eq!(value["source"], "1pux");
    assert!(!String::from_utf8_lossy(&stdout).contains("hunter2"));
    // `--dry-run`: the source is left exactly as it was.
    assert!(source.exists());
}

#[test]
fn report_file_from_a_real_1pux_import_is_written_with_mode_0600() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.1pux");
    std::fs::write(&source, build_1pux("hunter2")).unwrap();
    let report_path = dir.path().join("report.md");

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap(), "--dry-run", "--report"])
        .arg(&report_path)
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    let contents = std::fs::read_to_string(&report_path).unwrap();
    assert!(!contents.contains("hunter2"));
    assert!(contents.contains("Acme staging"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&report_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }
}

#[test]
fn a_real_import_lands_in_the_vault_and_a_second_run_with_skip_adds_nothing() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.1pux");
    std::fs::write(&source, build_1pux("hunter2")).unwrap();

    fixture
        .cmd()
        .args(["import", source.to_str().unwrap()])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("Imported 1 item"));

    let list = fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(list.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Acme staging"), "{stdout}");

    // The default policy is `skip`: importing the same source again must not double the item.
    fixture
        .cmd()
        .args(["import", source.to_str().unwrap()])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("0 updated, 1 skipped"));
}

#[test]
fn include_trashed_changes_what_a_real_1pux_import_brings_in() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.1pux");
    std::fs::write(&source, build_1pux_with_trashed("hunter2")).unwrap();

    // `--format 1pux` is explicit in both invocations: today `--include-trashed` is wired only
    // through `onepux::parse_with`, which the CLI only reaches for an explicit `--format 1pux`
    // (see the comment in `commands::import::import`) — auto-detection still goes through the
    // frozen `kagisecure_import::parse`, which has no options argument to carry it.
    let without = fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--format",
            "1pux",
            "--json",
            "--dry-run",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let value: serde_json::Value = serde_json::from_slice(&without.get_output().stdout).unwrap();
    assert_eq!(
        value["totals"]["items"], 1,
        "the trashed item is skipped by default"
    );

    let with = fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--format",
            "1pux",
            "--include-trashed",
            "--json",
            "--dry-run",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let value: serde_json::Value = serde_json::from_slice(&with.get_output().stdout).unwrap();
    assert_eq!(
        value["totals"]["items"], 2,
        "--include-trashed brings the second item in"
    );
}

#[test]
fn shred_source_removes_the_file_only_after_a_successful_import() {
    let fixture = Fixture::new();
    fixture.init();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.1pux");
    std::fs::write(&source, build_1pux("hunter2")).unwrap();

    fixture
        .cmd()
        .args([
            "import",
            source.to_str().unwrap(),
            "--shred-source",
            "--yes",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    assert!(
        !source.exists(),
        "the source file should have been shredded"
    );
}

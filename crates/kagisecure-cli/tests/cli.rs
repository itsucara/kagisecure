//! End-to-end tests driving the `kagisecure` binary against a temporary vault.
//!
//! Every invocation passes `--password-stdin` so the tests never need a controlling terminal, and
//! `--kdf-m-kib 64 --kdf-t 1` so the suite is not dominated by Argon2.

use assert_cmd::Command;
use kagisecure_core::Vault;
use kagisecure_core::proto::Outcome;
use predicates::str::contains;
use std::path::{Path, PathBuf};

const PASSWORD: &str = "correct horse battery staple";
const TOKEN: &str = "sk_live_kagisecure_integration_canary";

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

    fn init(&self) -> String {
        let out = self
            .cmd()
            .args(["vault", "init", "--kdf-m-kib", "64", "--kdf-t", "1"])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success();
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    }

    /// Turn "Show new items to agents" off, for tests that need an item to start hidden.
    fn hide_new_items(&self) {
        self.cmd()
            .args(["vault", "new-items-agent-visible", "off"])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success();
    }

    fn add_sample(&self) {
        self.cmd()
            .args([
                "item",
                "add",
                "--title",
                "Acme staging",
                "--category",
                "api-credential",
                "--field",
                "username=deploy",
                "--secret",
                "token",
                "--value-stdin",
                "--tag",
                "staging",
            ])
            .write_stdin(format!("{PASSWORD}\n{TOKEN}\n"))
            .assert()
            .success();
    }
}

fn recovery_code_from(init_output: &str) -> String {
    init_output
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 62 && l.matches('-').count() == 8)
        .expect("init should print a grouped recovery code")
        .to_owned()
}

#[test]
fn init_creates_a_vault_and_prints_a_recovery_code_once() {
    let fixture = Fixture::new();
    let output = fixture.init();

    assert!(fixture.vault.exists());
    assert!(output.contains("Your one-time recovery code"));
    let code = recovery_code_from(&output);
    assert_eq!(code.split('-').count(), 9);
    assert!(!output.contains(PASSWORD));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&fixture.vault)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn init_refuses_to_overwrite_an_existing_vault() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .args(["vault", "init"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(5)
        .stderr(contains("already exists"));
}

#[test]
fn unlock_reports_the_vault_without_printing_a_value() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let assertion = fixture
        .cmd()
        .args(["vault", "unlock"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("1 item(s) in total"))
        .stdout(contains("key slots: password, recovery"));
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(TOKEN));
}

#[test]
fn a_wrong_password_fails_cleanly_with_no_partial_output() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let assertion = fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin("not the password\n")
        .assert()
        .code(3)
        .stderr(contains("decryption failed"));

    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.is_empty(),
        "wrong password produced output: {stdout}"
    );
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();
    assert!(!stderr.contains(TOKEN));
    assert!(!stderr.contains("Acme"));
}

#[test]
fn a_missing_vault_is_reported_before_a_password_is_asked_for() {
    let fixture = Fixture::new();
    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin("")
        .assert()
        .code(4)
        .stderr(contains("no vault at"));
}

#[test]
fn list_shows_metadata_and_never_a_value() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let assertion = fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("Acme staging"))
        .stdout(contains("api-credential"));
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(TOKEN));
}

#[test]
fn list_json_is_metadata_only() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let assertion = fixture
        .cmd()
        .args(["item", "list", "--json"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(TOKEN));
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed[0]["title"], "Acme staging");
    assert_eq!(parsed[0]["fields"][1]["label"], "token");
    assert_eq!(parsed[0]["fields"][1]["concealed"], true);
    assert!(parsed[0]["fields"][1].get("value").is_none());
}

#[test]
fn show_hides_concealed_values_by_default_and_reveals_only_on_request() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let hidden = fixture
        .cmd()
        .args(["item", "show", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("<concealed>"))
        .stdout(contains("deploy"));
    let stdout = String::from_utf8(hidden.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(TOKEN));

    fixture
        .cmd()
        .args(["item", "show", "Acme staging", "--reveal"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains(TOKEN));
}

#[test]
fn show_json_stays_metadata_only_even_with_reveal() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let assertion = fixture
        .cmd()
        .args(["item", "show", "Acme staging", "--json", "--reveal"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains(TOKEN),
        "--json must never carry a value, even with --reveal"
    );
}

/// ADR-0038's CLI decision: notes are secret like any other field, so `item show` prints them only
/// with `--reveal` — and, unlike a wrong or missing password, every `--reveal` is audited
/// (best-effort, actor `cli`, tool `reveal_field`) rather than silently trusted just because the
/// CLI already asked for the master password to open the vault at all.
///
/// The note itself comes in through `--note --value-stdin`, never `--note TEXT` on argv — see
/// `a_note_value_cannot_be_given_on_the_command_line` for the flag that used to allow that.
#[test]
fn show_hides_notes_by_default_and_reveals_and_audits_on_request() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "Acme staging",
            "--note",
            "--value-stdin",
        ])
        .write_stdin(format!("{PASSWORD}\na secret note about staging\n"))
        .assert()
        .success();

    let hidden = fixture
        .cmd()
        .args(["item", "show", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("(hidden, use --reveal)"));
    let stdout = String::from_utf8(hidden.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains("a secret note about staging"));

    fixture
        .cmd()
        .args(["item", "show", "Acme staging", "--reveal"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("a secret note about staging"));

    let vault = Vault::open_with_password(&fixture.vault, PASSWORD.as_bytes()).unwrap();
    let entry = vault
        .audit_entries()
        .iter()
        .find(|e| e.tool == "reveal_field")
        .expect("the reveal should have been audited");
    assert_eq!(entry.actor, "cli");
    assert_eq!(entry.outcome, Outcome::Allowed);
    assert!(
        entry.variables.contains(&"notes".to_owned()),
        "{:?}",
        entry.variables
    );
    assert_eq!(entry.detail.as_deref(), Some("MASTER_PASSWORD"));
}

/// `--note` used to take the note's text directly (`--note "some text"`), which put a secret value
/// in argv, `ps` output and shell history — exactly what `--secret` and `--totp` never do. It is
/// now a bare switch, so that old invocation is refused by clap itself before the vault is even
/// opened: a usage error (exit 2), not a silently-accepted note.
#[test]
fn a_note_value_cannot_be_given_on_the_command_line() {
    let fixture = Fixture::new();
    fixture.init();

    fixture
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "Old style",
            "--note",
            "a note typed straight on the command line",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(2)
        .stderr(contains("unexpected argument"));

    // Nothing was written: the item from the refused invocation above does not exist.
    fixture
        .cmd()
        .args(["item", "show", "Old style"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(6)
        .stderr(contains("no item matches"));
}

/// The multi-line path `--note` and `--value-stdin` cannot offer, since both stop at the first
/// line break: `--note-file` reads the file's bytes verbatim, trimming only one trailing newline.
#[test]
fn note_file_carries_a_note_with_more_than_one_line() {
    let fixture = Fixture::new();
    fixture.init();

    let note_path = fixture.vault.with_file_name("note.txt");
    std::fs::write(&note_path, "line one\nline two\nline three\n").unwrap();

    fixture
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "Multiline",
            "--note-file",
            note_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    let assertion = fixture
        .cmd()
        .args(["item", "show", "Multiline", "--reveal"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("line one\nline two\nline three"),
        "the note's embedded newlines should survive verbatim: {stdout}"
    );
    assert!(
        !stdout.contains("line three\n\n"),
        "the file's one trailing newline should have been trimmed, not stored as a blank line: \
         {stdout}"
    );
}

/// `--note` and `--note-file` are two different sources for the same one note; passing both is a
/// usage mistake, not a "last one wins" or "concatenate them" situation.
#[test]
fn note_and_note_file_are_mutually_exclusive() {
    let fixture = Fixture::new();
    fixture.init();

    fixture
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "Both",
            "--note",
            "--note-file",
            "/nonexistent/path/does/not/matter",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(2)
        .stderr(contains("cannot be used with"));
}

#[test]
fn an_unknown_item_is_a_distinct_exit_code() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .args(["item", "show", "no such item"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(6)
        .stderr(contains("no item matches"));
}

#[test]
fn rm_removes_the_item() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    fixture
        .cmd()
        .args(["item", "rm", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("Removed"));

    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("No items yet"));
}

#[test]
fn run_injects_the_value_and_masks_it_out_of_the_output() {
    if cfg!(windows) {
        return;
    }
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let assertion = fixture
        .cmd()
        .args([
            "run",
            "--env",
            "TOKEN=Acme staging/token",
            "--",
            "printenv",
            "TOKEN",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("[kagisecure:redacted:TOKEN]"));
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(TOKEN), "masking let the value through");
}

#[test]
fn run_with_no_masking_prints_the_value_to_the_users_own_terminal() {
    if cfg!(windows) {
        return;
    }
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    fixture
        .cmd()
        .args([
            "run",
            "--no-masking",
            "--env",
            "TOKEN=Acme staging/token",
            "--",
            "printenv",
            "TOKEN",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains(TOKEN));
}

#[test]
fn run_can_inject_a_public_field_too() {
    if cfg!(windows) {
        return;
    }
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    fixture
        .cmd()
        .args([
            "run",
            "--no-masking",
            "--env",
            "USER_NAME=Acme staging/username",
            "--",
            "printenv",
            "USER_NAME",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("deploy"));
}

#[test]
fn run_propagates_the_childs_exit_code() {
    if cfg!(windows) {
        return;
    }
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    fixture
        .cmd()
        .args([
            "run",
            "--env",
            "TOKEN=Acme staging/token",
            "--",
            "sh",
            "-c",
            "exit 7",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(7);
}

/// mcp-server.md §2.8: no shell. An argument that looks like a shell command is an argument.
#[test]
fn run_does_not_invoke_a_shell() {
    if cfg!(windows) {
        return;
    }
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();
    let marker = fixture.vault.parent().unwrap().join("pwned");

    fixture
        .cmd()
        .args([
            "run",
            "--env",
            "TOKEN=Acme staging/token",
            "--",
            "echo",
            &format!("hello; touch {}", marker.display()),
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    assert!(!marker.exists(), "the argument reached a shell");
}

#[test]
fn run_reports_an_unknown_field_without_naming_a_value() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    fixture
        .cmd()
        .args([
            "run",
            "--env",
            "TOKEN=Acme staging/nonexistent",
            "--",
            "echo",
            "unreached",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(6)
        .stderr(contains("has no field"));
}

#[test]
fn recover_unlocks_with_the_code_and_sets_a_new_password() {
    let fixture = Fixture::new();
    let code = recovery_code_from(&fixture.init());
    fixture.add_sample();

    fixture
        .cmd()
        .arg("recover")
        .write_stdin(format!("{code}\na brand new password\n"))
        .assert()
        .success()
        .stdout(contains("with the recovery code (1 item(s))"))
        .stdout(contains("master password has been replaced"));

    // The new password works ...
    fixture
        .cmd()
        .args(["vault", "unlock"])
        .write_stdin("a brand new password\n")
        .assert()
        .success();

    // ... and the old one does not.
    fixture
        .cmd()
        .args(["vault", "unlock"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(3);
}

#[test]
fn recover_can_reissue_the_recovery_code() {
    let fixture = Fixture::new();
    let old = recovery_code_from(&fixture.init());

    let assertion = fixture
        .cmd()
        .args(["recover", "--reissue-recovery-code"])
        .write_stdin(format!("{old}\nnew password\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    let new = recovery_code_from(&stdout);
    assert_ne!(new, old);

    fixture
        .cmd()
        .arg("recover")
        .write_stdin(format!("{old}\nanother password\n"))
        .assert()
        .code(3);
}

#[test]
fn a_malformed_recovery_code_is_refused() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .arg("recover")
        .write_stdin("not-a-recovery-code\nwhatever\n")
        .assert()
        .code(3)
        .stderr(contains("not valid"));
}

#[test]
fn the_vault_path_can_come_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("env.kagivault");

    Command::cargo_bin("kagisecure")
        .unwrap()
        .env("KAGISECURE_VAULT", &vault)
        .args([
            "--password-stdin",
            "vault",
            "init",
            "--kdf-m-kib",
            "64",
            "--kdf-t",
            "1",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    assert!(vault.exists());
}

#[test]
fn help_documents_the_exit_codes() {
    Command::cargo_bin("kagisecure")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Exit codes:"))
        .stdout(contains("no vault at the given path"));
}

#[test]
fn a_secret_value_cannot_be_given_on_the_command_line() {
    // `--secret` takes a label. There is no `--secret-value`; if one is ever added by accident,
    // this test fails and asks why. The same goes for `--note`, which used to take the note's text
    // directly (`--note <TEXT>`) and is now a bare switch — if it is ever given a value again by
    // accident, `--note <TEXT>` would reappear in `--help` and this test would catch it.
    let output = Command::cargo_bin("kagisecure")
        .unwrap()
        .args(["item", "add", "--help"])
        .assert()
        .success();
    let help = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(help.contains("--secret <LABEL>"));
    assert!(!help.contains("--secret-value"));
    assert!(help.contains("--value-stdin"));
    assert!(!help.contains("--note <TEXT>"));
    assert!(!help.contains("--note <NOTE>"));
    assert!(help.contains("--note-file <PATH>"));
}

/// The vault is written atomically, so a save leaves no stray files behind.
#[test]
fn saving_leaves_no_temporary_files() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let dir: &Path = fixture.vault.parent().unwrap();
    let strays: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(strays.is_empty(), "{strays:?}");
}

// ---------------------------------------------------------------------------------------------
// M5: `kagisecure generate` and `kagisecure totp`
// ---------------------------------------------------------------------------------------------

/// The seed from RFC 4648's Base32 examples, used here only because its decoding is well known.
const TOTP_URI: &str =
    "otpauth://totp/ACME:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8";

#[test]
fn generate_needs_no_vault_and_honours_its_switches() {
    // No `--vault`, no `--password-stdin`, no vault file anywhere: generating is a pure function.
    let out = Command::cargo_bin("kagisecure")
        .unwrap()
        .args([
            "generate",
            "--length",
            "32",
            "--no-symbols",
            "--avoid-ambiguous",
        ])
        .assert()
        .success();
    let password = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let password = password.trim();
    assert_eq!(password.chars().count(), 32, "{password}");
    assert!(password.chars().all(char::is_alphanumeric), "{password}");
    assert!(!password.chars().any(|c| "0O1lI".contains(c)), "{password}");
}

#[test]
fn generate_prints_one_line_per_count_and_never_repeats() {
    let out = Command::cargo_bin("kagisecure")
        .unwrap()
        .args(["generate", "--count", "5"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5);
    let mut unique = lines.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 5, "the generator repeated itself: {stdout}");
}

#[test]
fn generate_word_mode_and_its_strength_line() {
    let out = Command::cargo_bin("kagisecure")
        .unwrap()
        .args([
            "generate",
            "--words",
            "5",
            "--separator",
            "period",
            "--strength",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.trim().split('.').count(), 5, "{stdout}");
    // The strength line is on standard error, so `generate | pbcopy` copies only the password.
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("bits"), "{stderr}");
    assert!(!stdout.contains("bits"), "{stdout}");
}

#[test]
fn generate_refuses_an_impossible_recipe() {
    Command::cargo_bin("kagisecure")
        .unwrap()
        .args([
            "generate",
            "--no-lowercase",
            "--no-uppercase",
            "--no-digits",
            "--no-symbols",
        ])
        .assert()
        .failure()
        .stderr(contains("no character class is enabled"));
}

#[test]
fn totp_prints_a_code_for_the_items_only_one_time_password() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "GitHub",
            "--totp",
            "one-time password",
            "--value-stdin",
        ])
        .write_stdin(format!("{PASSWORD}\n{TOTP_URI}\n"))
        .assert()
        .success();

    let out = fixture
        .cmd()
        .args(["totp", "GitHub"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let code = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let code = code.trim();
    assert_eq!(code.len(), 8, "the URI asked for 8 digits: {code:?}");
    assert!(code.chars().all(|c| c.is_ascii_digit()), "{code:?}");
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("valid for"), "{stderr}");

    // Naming the field explicitly gives the same answer.
    fixture
        .cmd()
        .args(["totp", "GitHub/one-time password"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains(code));
}

#[test]
fn totp_refuses_a_field_that_is_not_one() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    fixture
        .cmd()
        .args(["totp", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .failure()
        .stderr(contains("one-time password"));

    fixture
        .cmd()
        .args(["totp", "Acme staging/token"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .failure()
        .stderr(contains("not a one-time password"));
}

#[test]
fn a_malformed_otpauth_uri_is_refused_at_add_time_and_never_echoed() {
    let fixture = Fixture::new();
    fixture.init();
    let assertion = fixture
        .cmd()
        .args([
            "item",
            "add",
            "--title",
            "Broken",
            "--totp",
            "otp",
            "--value-stdin",
        ])
        .write_stdin(format!("{PASSWORD}\notpauth://totp/x?secret=!!!!\n"))
        .assert()
        .failure();
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("Base32"), "{stderr}");
    assert!(
        !stderr.contains("otpauth://"),
        "the error echoed the URI: {stderr}"
    );
}

// -------------------------------------------------------------------------------------------
// A damaged vault file
// -------------------------------------------------------------------------------------------
//
// Exit 3 is documented as "could not unlock: wrong password or recovery code, or the vault was
// tampered with". These three tests pin all three ways a file can be damaged to that one code,
// because which one a given corruption produces depends only on *where* the bytes fell — a caller
// branching on the exit status cannot be asked to care.

/// Flip one bit at `offset` in the vault file.
fn flip_bit_at(vault: &Path, offset: usize) {
    let mut bytes = std::fs::read(vault).unwrap();
    assert!(
        offset < bytes.len(),
        "offset {offset} is past the end of the file"
    );
    bytes[offset] ^= 0x01;
    std::fs::write(vault, bytes).unwrap();
}

#[test]
fn a_flipped_bit_in_the_ciphertext_exits_three() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let len = std::fs::metadata(&fixture.vault).unwrap().len() as usize;
    flip_bit_at(&fixture.vault, len - 8);

    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(3)
        .stderr(contains("tampered"));
}

/// A flipped bit in the header that leaves the CBOR *well formed*.
///
/// The header is plaintext but authenticated: the byte range from `MAGIC` through the end of the
/// header is the body AEAD's associated data (vault-format §2). Changing a value inside it must
/// therefore fail the tag exactly as changing the ciphertext does.
#[test]
fn a_flipped_bit_in_an_authenticated_header_value_exits_three() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    // Locate the `vault_id` key in the plaintext CBOR and flip a bit in the 16-byte string that
    // follows it, past the one-byte `bytes(16)` marker. The map stays well formed, so this
    // reaches the AEAD rather than the CBOR decoder.
    let bytes = std::fs::read(&fixture.vault).unwrap();
    let key = b"vault_id";
    let at = bytes
        .windows(key.len())
        .position(|w| w == key)
        .expect("the header names vault_id");
    flip_bit_at(&fixture.vault, at + key.len() + 1);

    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(3)
        .stderr(contains("tampered"));
}

/// A flipped bit in the header that breaks the CBOR structure itself.
///
/// This one never reaches the AEAD: the decoder rejects the map first. It is still a damaged
/// vault, so it still exits 3 — that is the regression this test exists for, because it used to
/// exit 1 ("an unexpected error") purely because the corruption landed on a type byte rather than
/// on a value byte a few bytes further along.
#[test]
fn a_structurally_broken_header_exits_three_too() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    // Byte 24 is inside the CBOR map, on the key `vault_id`'s text-string header.
    flip_bit_at(&fixture.vault, 24);

    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(3);
}

#[test]
fn a_truncated_vault_exits_three() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_sample();

    let bytes = std::fs::read(&fixture.vault).unwrap();
    std::fs::write(&fixture.vault, &bytes[..bytes.len() / 2]).unwrap();

    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(3);
}

/// A file that is not a vault at all stays at exit 1.
///
/// The boundary matters: exit 3 means "this vault did not open", and a caller that gets it should
/// tell the user their password may be wrong or their file may be damaged. A `--vault` pointing at
/// a README is neither, and saying so would be misleading.
#[test]
fn a_file_that_is_not_a_vault_is_still_an_ordinary_error() {
    let fixture = Fixture::new();
    std::fs::write(
        &fixture.vault,
        b"this is not a kagisecure vault file at all\n",
    )
    .unwrap();

    fixture
        .cmd()
        .args(["item", "list"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(1)
        .stderr(contains("not a kagisecure vault"));
}

/// `env agent-access` says what it changed only once the change is on disk. A later target in
/// the same command that does not exist rolls the whole transaction back — and nothing may have
/// been printed claiming the earlier one was allowed.
#[test]
fn agent_access_reports_nothing_that_did_not_commit() {
    let fx = Fixture::new();
    fx.init();
    // Start from a hidden item: this test is about turning access on.
    fx.hide_new_items();
    fx.add_sample();

    let out = fx
        .cmd()
        .args([
            "env",
            "agent-access",
            "--allow",
            "--item",
            "Acme staging",
            "--environment",
            "no-such-environment",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .failure();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains("agent access allowed"),
        "claimed a change that was rolled back: {stdout}"
    );
    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    assert!(!vault.find_item("Acme staging").unwrap().agent_visible);

    // The same change on its own commits, and then says so, naming the item by id.
    let out = fx
        .cmd()
        .args(["env", "agent-access", "--allow", "--item", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    let item = vault.find_item("Acme staging").unwrap();
    assert!(item.agent_visible);
    assert!(
        stdout.contains(&format!("item {}: agent access allowed", item.id)),
        "{stdout}"
    );
}

/// `env agent-access --item --field` toggles one field's own agent-visibility override, leaving
/// the item's and every other field's alone — the CLI's route to the state
/// `docs/mcp-server.md` §2.6 requires before an agent's `add_variables` may `bind_to` it, which
/// until this was added only the app's `VaultSession::set_field_agent_visible` could produce.
#[test]
fn agent_access_can_target_one_field() {
    let fx = Fixture::new();
    fx.init();
    // Start from a hidden item: this test is about turning access on.
    fx.hide_new_items();
    fx.add_sample();

    {
        let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
        let item = vault.find_item("Acme staging").unwrap();
        let token_field = item.fields.iter().find(|f| f.label == "token").unwrap();
        assert!(!token_field.agent_visible);
    }

    let out = fx
        .cmd()
        .args([
            "env",
            "agent-access",
            "--allow",
            "--item",
            "Acme staging",
            "--field",
            "token",
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();

    {
        let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
        let item = vault.find_item("Acme staging").unwrap();
        let token_field = item.fields.iter().find(|f| f.label == "token").unwrap();
        let username_field = item.fields.iter().find(|f| f.label == "username").unwrap();
        assert!(token_field.agent_visible, "the named field is now shared");
        assert!(
            !item.agent_visible,
            "--field must not also grant the item, which is a separate, broader decision"
        );
        assert!(
            !username_field.agent_visible,
            "an unrelated field on the same item is untouched"
        );
        assert!(
            stdout.contains(&format!("item {} field {}", item.id, token_field.id)),
            "{stdout}"
        );
    }

    // Revoking the item's own visibility clears every field's override with it — the same
    // cascade `VaultSession::set_agent_visible` performs — so a later re-share never silently
    // brings back a per-field grant the user forgot about.
    fx.cmd()
        .args(["env", "agent-access", "--allow", "--item", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    fx.cmd()
        .args(["env", "agent-access", "--deny", "--item", "Acme staging"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    let item = vault.find_item("Acme staging").unwrap();
    let token_field = item.fields.iter().find(|f| f.label == "token").unwrap();
    assert!(
        !token_field.agent_visible,
        "denying the item cascades to clear its fields' overrides too"
    );
}

/// `--field` without `--item` is a usage error, not a silent no-op: a field is meaningless
/// without knowing which item it belongs to.
#[test]
fn agent_access_field_without_item_is_a_usage_error() {
    let fx = Fixture::new();
    fx.init();
    fx.add_sample();

    fx.cmd()
        .args(["env", "agent-access", "--allow", "--field", "token"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(2);
}

/// Ctrl-C, or closing the terminal, reaches the child of `kagisecure run` — the terminal signals
/// its foreground process *group*, and the child has to be in it.
///
/// A regression put every injected child in a process group of its own (the MCP agent's reason
/// for that — ending a whole group on lock — does not apply to a terminal the user is watching),
/// so a `SIGINT` from the terminal ended `kagisecure run` and left the child running, detached,
/// with the secret in its environment. This drives the binary the way a shell does — in a job of
/// its own, then signalled as a group — and checks the child dies with it.
#[cfg(unix)]
#[test]
fn a_terminal_interrupt_reaches_the_child_of_run() {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    fn alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    for signal in ["INT", "HUP"] {
        let fixture = Fixture::new();
        fixture.init();
        fixture.add_sample();
        let pid_file = fixture._dir.path().join("child.pid");

        let mut cli = std::process::Command::new(assert_cmd::cargo::cargo_bin!("kagisecure"));
        cli.arg("--vault")
            .arg(&fixture.vault)
            .arg("--password-stdin")
            .env_remove("KAGISECURE_VAULT")
            .args([
                "run",
                "--env",
                "TOKEN=Acme staging/token",
                "--",
                "sh",
                "-c",
                &format!("echo $$ > {}; exec sleep 30", pid_file.display()),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            // What a job-control shell does for a foreground job: a group of its own, which the
            // terminal then signals as a whole.
            .process_group(0);
        let mut cli = cli.spawn().expect("spawn kagisecure");
        cli.stdin
            .take()
            .expect("stdin")
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .expect("password");

        let started = std::time::Instant::now();
        let child_pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file)
                && !text.trim().is_empty()
            {
                break text.trim().to_owned();
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "the child never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        };

        // The terminal's Ctrl-C (or hang-up): the signal goes to the foreground job's group.
        let group = format!("-{}", cli.id());
        std::process::Command::new("kill")
            .args([&format!("-{signal}"), "--", &group])
            .status()
            .expect("kill");

        let started = std::time::Instant::now();
        while alive(&child_pid) {
            if started.elapsed() > std::time::Duration::from_secs(10) {
                // Do not leave the child behind for the rest of the suite.
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", &child_pid])
                    .status();
                panic!("SIG{signal} to the terminal's job did not reach the child of `run`");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = cli.wait();
    }
}

/// `env add-var` refuses a name that is not an identifier, as a usage error, before it asks for
/// the password: the name would otherwise be written verbatim as a `.env` key by `env write`,
/// where a newline or `=` becomes a line of its own.
#[test]
fn env_add_var_refuses_a_name_that_is_not_an_identifier() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .args(["env", "create", "prod"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    for bad in ["A=B", "OK\nPATH=/tmp/evil", "1ST", "DASH-ED"] {
        fixture
            .cmd()
            .args([
                "env",
                "add-var",
                "--environment",
                "prod",
                "--name",
                bad,
                "--literal",
            ])
            .write_stdin(format!("{PASSWORD}\nvalue\n"))
            .assert()
            .code(2)
            .stderr(contains("not a usable variable name"));
    }
}

// ---------------------------------------------------------------------------------------------
// "Show new items to agents" and bulk agent visibility (ADR-0007 amendment 2026-10-04)
// ---------------------------------------------------------------------------------------------

#[test]
fn item_add_follows_the_show_new_items_setting() {
    let fx = Fixture::new();
    fx.init();
    fx.add_sample();
    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    let item = vault.find_item("Acme staging").unwrap();
    assert!(item.agent_visible && item.fields.iter().all(|f| f.agent_visible));
    drop(vault);

    fx.cmd()
        .args(["vault", "new-items-agent-visible", "off"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("not be shown"));
    fx.cmd()
        .args(["item", "add", "--title", "Later"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    assert!(!vault.find_item("Later").unwrap().agent_visible);
    assert!(!vault.new_items_agent_visible(vault.default_vault_id().unwrap()));
}

#[test]
fn item_agent_visible_by_tag_changes_every_tagged_item_with_one_audit_entry() {
    let fx = Fixture::new();
    fx.init();
    fx.hide_new_items();
    for title in ["One", "Two"] {
        fx.cmd()
            .args([
                "item",
                "add",
                "--title",
                title,
                "--tag",
                "imported:chromium",
            ])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success();
    }
    fx.add_sample();
    let before = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes())
        .unwrap()
        .audit_entries()
        .len();

    fx.cmd()
        .args(["item", "agent-visible", "on", "--tag", "imported:chromium"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("Showed 2 item(s)"));

    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    assert!(vault.find_item("One").unwrap().agent_visible);
    assert!(vault.find_item("Two").unwrap().agent_visible);
    assert!(!vault.find_item("Acme staging").unwrap().agent_visible);
    let new_entries = &vault.audit_entries()[before..];
    assert_eq!(new_entries.len(), 1);
    assert_eq!(new_entries[0].tool, "set_agent_visible_bulk");
    assert_eq!(new_entries[0].actor, "cli");
    let detail = new_entries[0].detail.as_deref().unwrap();
    assert!(
        !detail.contains("chromium") && !detail.contains(TOKEN),
        "{detail}"
    );
    drop(vault);

    fx.cmd()
        .args(["item", "agent-visible", "off", "--item", "One"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    let vault = Vault::open_with_password(&fx.vault, PASSWORD.as_bytes()).unwrap();
    assert!(!vault.find_item("One").unwrap().agent_visible);
    assert!(vault.find_item("Two").unwrap().agent_visible);
}

#[test]
fn item_agent_visible_needs_a_scope() {
    let fx = Fixture::new();
    fx.init();
    fx.cmd()
        .args(["item", "agent-visible", "on"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .failure();
}

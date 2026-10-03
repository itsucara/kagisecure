//! Cross-process transaction tests: the `kagisecure` binary as one writer among several `Vault`
//! handles open on the same file, exercising the same lock-and-catch-up protocol
//! `crates/kagisecure-core/tests/concurrent_writers.rs` tests inside one process.
//!
//! Every CLI invocation passes `--password-stdin` and a cheap KDF, same as `tests/cli.rs`.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use kagisecure_core::model::{Category, Item};
use kagisecure_core::proto::Outcome;
use kagisecure_core::{RecoveryCode, Vault};
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

    fn init(&self) -> String {
        let out = self
            .cmd()
            .args(["vault", "init", "--kdf-m-kib", "64", "--kdf-t", "1"])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success();
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    }

    fn open(&self) -> Vault {
        Vault::open_with_password(&self.vault, PASSWORD.as_bytes()).unwrap()
    }

    /// Add an item with one concealed field, named so a test can reference it as `ITEM/FIELD`.
    fn add_item_with_secret(&self, title: &str, field: &str, value: &str) {
        self.cmd()
            .args(["item", "add", "--title", title, "--secret", field])
            .write_stdin(format!("{PASSWORD}\n{value}\n"))
            .assert()
            .success();
    }
}

/// Hold the vault's lock in a background thread until the closure returns, using a `Vault` handle
/// separate from the CLI process under test — the same technique
/// `a_held_lock_makes_the_cli_wait_then_exit_busy` uses to force a real, deterministic
/// [`kagisecure_core::Error::VaultBusy`] rather than simulating one.
///
/// The closure runs with the lock held; the returned [`std::thread::JoinHandle`] must be
/// `join`ed after the CLI invocation under test has returned, or the lock outlives the test.
fn hold_lock_for(
    vault_path: PathBuf,
    hold: Duration,
) -> (mpsc::Receiver<()>, std::thread::JoinHandle<()>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let holder = std::thread::spawn(move || {
        let mut vault = Vault::open_with_password(&vault_path, PASSWORD.as_bytes()).unwrap();
        vault
            .transact(|tx| {
                let _ = ready_tx.send(());
                std::thread::sleep(hold);
                add_named_item(tx, "held for the audit-first gate")
            })
            .unwrap();
    });
    (ready_rx, holder)
}

/// Same recognizer `tests/cli.rs` uses: a recovery code is the only line `kagisecure` ever prints
/// that is 62 characters of grouped hex with 8 dashes.
fn recovery_code_from(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 62 && l.matches('-').count() == 8)
        .expect("should print a grouped recovery code")
        .to_owned()
}

/// A trivial mutation for a `Vault` handle's own transaction: add one item, named so the test can
/// tell it apart from anything the CLI wrote.
fn add_named_item(
    tx: &mut kagisecure_core::vault::Tx<'_>,
    title: &str,
) -> kagisecure_core::Result<()> {
    let vault_id = tx.default_vault_id()?;
    tx.add_item(Item::new(vault_id, Category::Login, title.to_owned()));
    Ok(())
}

/// `item add`, run as the CLI's own process, alongside a `Vault` handle that opened the file
/// beforehand and only commits its own change afterwards — deliberately stale by the time it
/// does. Its transaction has to catch up to what the CLI already wrote and commit its own item on
/// top, not silently overwrite the CLI's item or the audit entry that describes it.
#[test]
fn item_add_and_its_audit_entry_survive_a_concurrent_handles_later_save() {
    let fixture = Fixture::new();
    fixture.init();

    let mut other = fixture.open();

    fixture
        .cmd()
        .args(["item", "add", "--title", "From the CLI"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    other
        .transact(|tx| add_named_item(tx, "From the other handle"))
        .unwrap();

    let reopened = fixture.open();
    let titles: Vec<&str> = reopened.items().iter().map(|i| i.title.as_str()).collect();
    assert!(titles.contains(&"From the CLI"), "{titles:?}");
    assert!(titles.contains(&"From the other handle"), "{titles:?}");

    assert!(
        reopened
            .audit_entries()
            .iter()
            .any(|e| e.actor == "cli" && e.tool == "item add"),
        "the CLI's own audit entry did not survive: {:?}",
        reopened.audit_entries()
    );
    reopened.verify_audit().unwrap();
}

/// `recover --reissue-recovery-code`, run as the CLI's own process, alongside a `Vault` handle
/// opened with the password that run is about to retire. The handle's *next* transaction — wholly
/// unrelated to the header — has to pick up the fresh password and recovery slots rather than
/// reverting them, because it re-reads the file under the lock before running its own closure.
#[test]
fn a_reissued_recovery_code_and_new_password_survive_a_concurrent_handles_next_transaction() {
    let fixture = Fixture::new();
    let old_code = recovery_code_from(&fixture.init());

    let mut other = fixture.open();

    let assertion = fixture
        .cmd()
        .args(["recover", "--reissue-recovery-code"])
        .write_stdin(format!("{old_code}\na brand new password\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    let new_code = recovery_code_from(&stdout);
    assert_ne!(new_code, old_code);

    other
        .transact(|tx| add_named_item(tx, "From the other handle"))
        .unwrap();

    assert!(
        Vault::open_with_password(&fixture.vault, b"a brand new password").is_ok(),
        "the new password should open the vault"
    );
    assert!(
        Vault::open_with_password(&fixture.vault, PASSWORD.as_bytes()).is_err(),
        "the old password should no longer open the vault"
    );

    let new = RecoveryCode::parse(&new_code).unwrap();
    let old = RecoveryCode::parse(&old_code).unwrap();
    assert!(
        Vault::open_with_recovery_code(&fixture.vault, &new).is_ok(),
        "the reissued recovery code should open the vault"
    );
    assert!(
        Vault::open_with_recovery_code(&fixture.vault, &old).is_err(),
        "the retired recovery code should no longer open the vault"
    );

    let reopened = Vault::open_with_password(&fixture.vault, b"a brand new password").unwrap();
    assert!(
        reopened
            .items()
            .iter()
            .any(|i| i.title == "From the other handle"),
        "the other handle's own transaction should have gone through too"
    );

    // ADR-0040 step 10: both credential changes are in the log, written by the same transaction
    // that made them.
    let entries = reopened.audit_entries();
    let change = entries
        .iter()
        .find(|e| e.tool == "change_master_password")
        .expect("the password change is audited");
    assert_eq!(change.actor, "cli");
    assert_eq!(change.detail.as_deref(), Some("RECOVERY_CODE"));
    let reissue = entries
        .iter()
        .find(|e| e.tool == "reissue_recovery_code")
        .expect("the reissue is audited");
    assert_eq!(reissue.actor, "cli");
    reopened.verify_audit().unwrap();
}

/// A process holding the vault's lock across a slow transaction makes the CLI wait rather than
/// fail immediately, tell the user why on stderr once the wait is no longer instant, and then
/// give up with exit 8 well before the holder is done — never silently, and never by writing
/// anything of its own.
///
/// `KAGISECURE_TEST_LOCK_QUIET_MS` / `KAGISECURE_TEST_LOCK_TIMEOUT_MS` only take effect in a debug
/// build (see `commands::transact_patiently`); this test relies on that to keep it fast.
#[test]
fn a_held_lock_makes_the_cli_wait_then_exit_busy() {
    let fixture = Fixture::new();
    fixture.init();

    let (ready_tx, ready_rx) = mpsc::channel();
    let vault_path = fixture.vault.clone();
    let holder = std::thread::spawn(move || {
        let mut vault = Vault::open_with_password(&vault_path, PASSWORD.as_bytes()).unwrap();
        vault
            .transact(|tx| {
                // The lock is held from here until this closure returns — signal only once that
                // is guaranteed true.
                let _ = ready_tx.send(());
                std::thread::sleep(Duration::from_millis(900));
                add_named_item(tx, "held")
            })
            .unwrap();
    });
    ready_rx.recv().unwrap();

    let started = Instant::now();
    fixture
        .cmd()
        .env("KAGISECURE_TEST_LOCK_QUIET_MS", "50")
        .env("KAGISECURE_TEST_LOCK_TIMEOUT_MS", "250")
        .args(["item", "add", "--title", "should never be written"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(8)
        .stderr(contains("waiting for another kagisecure process"));
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_millis(700),
        "the CLI should have given up long before the holder finished: {waited:?}"
    );

    holder.join().unwrap();

    let reopened = fixture.open();
    assert!(
        !reopened
            .items()
            .iter()
            .any(|i| i.title == "should never be written"),
        "a busy write must not reach the file"
    );
    assert!(reopened.items().iter().any(|i| i.title == "held"));
}

/// `env write` is audit-first (design doc "transactions-and-audit" part B, step 9): the `Allowed`
/// entry has to be appended and durably saved *before* the `.env` file is written. When that
/// transaction cannot be made durable — here, simulated by another process holding the vault's
/// lock past the usual wait, the same `VaultBusy` a real disk failure or a diverged/replaced file
/// would also produce — the release is refused with exit 9
/// ([`kagisecure_cli`]'s `EXIT_AUDIT_UNAVAILABLE`, not the ordinary busy exit 8: `env write` wraps
/// the audit-first gate's transaction error in its own type precisely so this case is
/// distinguishable), and nothing is written at all.
#[test]
fn env_write_refuses_with_audit_unavailable_when_permission_cannot_be_made_durable() {
    let fixture = Fixture::new();
    fixture.init();
    fixture
        .cmd()
        .args(["env", "create", "prod"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    fixture
        .cmd()
        .args([
            "env",
            "add-var",
            "--environment",
            "prod",
            "--name",
            "TOKEN",
            "--literal",
        ])
        .write_stdin(format!("{PASSWORD}\na literal value\n"))
        .assert()
        .success();

    let (ready_rx, holder) = hold_lock_for(fixture.vault.clone(), Duration::from_millis(900));
    ready_rx.recv().unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let env_file = out_dir.path().join(".env");

    fixture
        .cmd()
        .env("KAGISECURE_TEST_LOCK_QUIET_MS", "50")
        .env("KAGISECURE_TEST_LOCK_TIMEOUT_MS", "250")
        .args([
            "env",
            "write",
            "--environment",
            "prod",
            "--dir",
            out_dir.path().to_str().unwrap(),
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(9);

    holder.join().unwrap();

    assert!(
        !env_file.exists(),
        "a release whose audit entry could not be made durable must write nothing"
    );
}

/// The same audit-first gate on `kagisecure run`: if permission cannot be made durable, the child
/// must never start.
#[test]
fn run_refuses_with_audit_unavailable_when_permission_cannot_be_made_durable_and_never_starts_the_child()
 {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_item_with_secret("Acme", "token", "sk_live_should_never_run");

    let (ready_rx, holder) = hold_lock_for(fixture.vault.clone(), Duration::from_millis(900));
    ready_rx.recv().unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let marker = out_dir.path().join("marker");

    fixture
        .cmd()
        .env("KAGISECURE_TEST_LOCK_QUIET_MS", "50")
        .env("KAGISECURE_TEST_LOCK_TIMEOUT_MS", "250")
        .args([
            "run",
            "--env",
            "TOKEN=Acme/token",
            "--",
            "touch",
            marker.to_str().unwrap(),
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(9);

    holder.join().unwrap();

    assert!(
        !marker.exists(),
        "the child must never be spawned when permission could not be made durable"
    );
}

/// Durable-before-act proof (design doc "transactions-and-audit" part B, step 9): the `Allowed`
/// audit entry for `run` is on disk *before* the child is spawned, not merely before `run` returns.
/// The child here is `cp`, copying the vault file to a snapshot the instant it starts — if the
/// entry were written after spawning (or the lock were held across the spawn, letting the copy run
/// against a half-written file), the snapshot could miss it or catch a torn file. It does neither:
/// the snapshot's last audit entry is already the `Allowed` entry this run appended.
#[test]
fn run_commits_the_allowed_entry_before_the_child_starts() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_item_with_secret("Acme", "token", "sk_live_durable_before_act");

    let out_dir = tempfile::tempdir().unwrap();
    let snapshot = out_dir.path().join("snapshot.kagivault");

    fixture
        .cmd()
        .args([
            "run",
            "--env",
            "TOKEN=Acme/token",
            "--",
            "cp",
            fixture.vault.to_str().unwrap(),
            snapshot.to_str().unwrap(),
        ])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    let snap = Vault::open_with_password(&snapshot, PASSWORD.as_bytes())
        .expect("the child's copy should be a byte-identical, openable vault file");
    let last = snap
        .audit_entries()
        .last()
        .expect("the snapshot should already contain at least the run's own Allowed entry");
    assert_eq!(last.tool, "run");
    assert_eq!(last.outcome, Outcome::Allowed);
    assert_eq!(last.variables, vec!["TOKEN".to_owned()]);
}

/// `item show --reveal` never blocks the value on its own audit save succeeding (design doc
/// "transactions-and-audit" part B, user decision 1: "own reveals ... AUDIT them, best-effort,
/// NEVER blocking"). The vault is held busy by another process for longer than the reveal's own
/// short, non-retrying audit-save timeout
/// (`KAGISECURE_TEST_BEST_EFFORT_AUDIT_TIMEOUT_MS`, see `commands::best_effort_audit_timeout`), so
/// the save is guaranteed to fail — and the value is still on stdout, with only a warning on
/// stderr, not a nonzero exit.
#[test]
fn show_reveal_prints_the_value_even_when_its_audit_save_fails() {
    let fixture = Fixture::new();
    fixture.init();
    fixture.add_item_with_secret("Acme", "token", "sk_live_should_still_print");

    let (ready_rx, holder) = hold_lock_for(fixture.vault.clone(), Duration::from_millis(400));
    ready_rx.recv().unwrap();

    fixture
        .cmd()
        .env("KAGISECURE_TEST_BEST_EFFORT_AUDIT_TIMEOUT_MS", "50")
        .args(["item", "show", "Acme", "--reveal"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("sk_live_should_still_print"))
        .stderr(contains("could not record this in the audit log"));

    holder.join().unwrap();
}

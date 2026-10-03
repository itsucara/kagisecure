//! Audit before release (`kagisecure_agent::release`), over the real socket.
//!
//! A value leaves the vault — a `.env` written, a command started — only after an `Allowed`
//! entry describing it is on disk. When that entry cannot be written the release does not
//! happen (`AUDIT_UNAVAILABLE`), the lease this call minted dies, and the refusal is queued for
//! the next write. When a committed release then fails, a `Failed` entry names the `Allowed` one.
//!
//! Unix-only: the commands run here are unix binaries, and the way a save is broken (a directory
//! where the vault file was) needs a unix `rename(2)` to fail the way a full disk would.
#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{
    Fixture, MARKER, REAL_DOTENV, allow_session, error_code, error_message, fixture, with_ui,
    write_env_file,
};
use kagisecure_agent::approval::Decision;
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{OutputMode, Request, Response};

fn vault_path(fx: &Fixture) -> PathBuf {
    fx.dir.path().join("test.kagivault")
}

/// A directory where the vault file was: every write fails, as on a full disk. Returns the
/// file's bytes, for [`repair`].
fn break_saves(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read the vault");
    std::fs::remove_file(path).expect("remove the vault file");
    std::fs::create_dir(path).expect("put a directory in its place");
    bytes
}

fn repair(path: &Path, bytes: &[u8]) {
    std::fs::remove_dir(path).expect("remove the directory");
    std::fs::write(path, bytes).expect("put the vault file back");
}

/// The audit log as the file on disk holds it, read by a third party.
fn on_disk(path: &Path) -> Vec<AuditEntry> {
    let vault = Vault::open_with_password(path, b"pw").expect("open the vault file");
    vault.verify_audit().expect("the chain verifies");
    vault.audit_entries().to_vec()
}

fn unsaved(fx: &Fixture) -> usize {
    fx.handle
        .with(Vault::unsaved_audit_entries)
        .expect("unlocked")
}

fn run(fx: &Fixture, command: &str, args: &[&str], timeout_seconds: u64) -> Request {
    Request::RunWithEnv {
        environment_id: fx.env_id.parse().expect("env id"),
        command: command.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        cwd: fx.canonical_project().display().to_string(),
        variables: None,
        timeout_seconds,
        output: OutputMode::Scrubbed,
    }
}

fn lease_of(reply: &Response) -> kagisecure_core::proto::LeaseId {
    match reply {
        Response::Ran { lease_id, .. } | Response::WroteEnvFile { lease_id, .. } => *lease_id,
        other => panic!("expected a release, got {other:?}"),
    }
}

/// The entries for one tool, on disk.
fn entries_for<'a>(entries: &'a [AuditEntry], tool: &str) -> Vec<&'a AuditEntry> {
    entries.iter().filter(|e| e.tool == tool).collect()
}

#[test]
fn a_write_env_file_whose_entry_cannot_be_written_writes_nothing() {
    let fx = fixture();
    let path = vault_path(&fx);
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);
    let bytes = break_saves(&path);

    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("audit-first")
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });

    assert_eq!(seen.len(), 1, "nothing was pending, so the human was asked");
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("AUDIT_UNAVAILABLE"),
        "{reply:?}"
    );
    let message = error_message(&reply).expect("message");
    assert!(message.contains("nothing was released"), "{message}");
    assert!(message.contains("do not retry in a loop"), "{message}");
    assert!(!message.contains(MARKER));
    assert!(!target.exists(), "a value left the vault with no record");
    assert!(
        fx.agent.leases().is_empty(),
        "the lease minted by that approval must not survive the refusal"
    );
    assert!(unsaved(&fx) > 0, "the refusal is queued, not lost");

    // Once the file can be written again, the refusal reaches it — and no `Allowed` entry does.
    repair(&path, &bytes);
    fx.handle.flush_best_effort(Duration::from_secs(5));
    assert_eq!(unsaved(&fx), 0);
    let entries = on_disk(&path);
    let written = entries_for(&entries, "write_env_file");
    assert_eq!(written.len(), 1, "{written:?}");
    assert_eq!(written[0].outcome, Outcome::Failed);
    assert_eq!(written[0].detail.as_deref(), Some("AUDIT_UNAVAILABLE"));
    assert_eq!(written[0].variables, vec!["TOKEN".to_owned()]);
    assert!(
        written[0].lease_id.is_some(),
        "it names the lease it killed"
    );
}

#[test]
fn a_run_with_env_whose_entry_cannot_be_written_runs_nothing_and_its_lease_is_gone() {
    let fx = fixture();
    let path = vault_path(&fx);
    let marker = fx.canonical_project().join("ran");
    let bytes = break_saves(&path);

    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("audit-first")
            .call(&run(&fx, "/usr/bin/touch", &["ran"], 5))
            .expect("call")
    });
    assert_eq!(seen.len(), 1);
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("AUDIT_UNAVAILABLE"),
        "{reply:?}"
    );
    assert!(!marker.exists(), "the command ran with no record of it");
    assert!(fx.agent.leases().is_empty());

    // The approval did not survive as a lease: the same request is a new question.
    repair(&path, &bytes);
    let (again, seen) = with_ui(&fx.agent, Decision::Deny, || {
        fx.client("audit-first")
            .call(&run(&fx, "/usr/bin/touch", &["ran"], 5))
            .expect("call")
    });
    assert_eq!(seen.len(), 1, "a refused release leaves nothing to reuse");
    assert_eq!(error_code(&again).as_deref(), Some("USER_DENIED"));
    assert!(!marker.exists());

    let entries = on_disk(&path);
    let runs = entries_for(&entries, "run_with_env");
    assert!(
        runs.iter()
            .any(|e| e.outcome == Outcome::Failed
                && e.detail.as_deref() == Some("AUDIT_UNAVAILABLE")),
        "{runs:?}"
    );
    assert!(
        !runs.iter().any(|e| e.outcome == Outcome::Allowed),
        "{runs:?}"
    );
}

#[test]
fn a_release_blocked_by_another_writers_lock_releases_nothing() {
    let fx = fixture();
    let path = vault_path(&fx);
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);

    // Another process takes the write lock and keeps it past the agent's wait.
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        Vault::open_with_password(&holder_path, b"pw")
            .expect("a second process opens the vault")
            .transact(|_| {
                locked_tx.send(()).expect("signal");
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
                Ok(())
            })
            .expect("the holder commits");
    });
    locked_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the holder has the lock");

    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("audit-first")
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    release_tx.send(()).expect("release");
    holder.join().expect("holder");

    assert_eq!(seen.len(), 1);
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("AUDIT_UNAVAILABLE"),
        "{reply:?}"
    );
    assert!(!target.exists());
    assert!(fx.agent.leases().is_empty());
    assert!(unsaved(&fx) > 0);

    fx.handle.flush_best_effort(Duration::from_secs(5));
    let entries = on_disk(&path);
    let written = entries_for(&entries, "write_env_file");
    assert_eq!(written.len(), 1, "{written:?}");
    assert_eq!(written[0].detail.as_deref(), Some("AUDIT_UNAVAILABLE"));
}

/// The proof that the entry is durable **before** the release: the released command itself
/// copies the vault file, and the copy — taken while the command ran — already holds the entry
/// that authorized it, as its last one.
#[test]
fn the_allowed_entry_is_on_disk_before_the_command_starts() {
    let fx = fixture();
    let path = vault_path(&fx);
    let snapshot = fx.canonical_project().join("snap");

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("audit-first")
            .call(&run(
                &fx,
                "/bin/cp",
                &[
                    path.to_str().expect("utf-8 path"),
                    snapshot.to_str().expect("utf-8 path"),
                ],
                30,
            ))
            .expect("call")
    });
    let Response::Ran { exit_code, .. } = &reply else {
        panic!("expected the command to run: {reply:?}");
    };
    assert_eq!(*exit_code, Some(0));
    let lease_id = lease_of(&reply);

    let copied = on_disk(&snapshot);
    let last = copied.last().expect("the copy has an audit log");
    assert_eq!(last.tool, "run_with_env", "{copied:?}");
    assert_eq!(last.outcome, Outcome::Allowed);
    assert_eq!(last.lease_id, Some(lease_id));
    assert_eq!(last.variables, vec!["TOKEN".to_owned()]);

    // And nothing followed it: the command ended normally.
    let entries = on_disk(&path);
    assert_eq!(entries_for(&entries, "run_with_env").len(), 1);
}

#[test]
fn a_command_that_cannot_start_is_recorded_as_failed_after_its_allowed_entry() {
    let fx = fixture();
    let path = vault_path(&fx);

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("audit-first")
            .call(&run(&fx, "/definitely/not/a/program-kagisecure", &[], 5))
            .expect("call")
    });
    assert!(error_code(&reply).is_some(), "{reply:?}");
    assert!(
        fx.agent.leases().is_empty(),
        "the minted lease died with it"
    );

    let entries = on_disk(&path);
    let runs = entries_for(&entries, "run_with_env");
    assert_eq!(runs.len(), 2, "{runs:?}");
    let (allowed, failed) = (runs[0], runs[1]);
    assert_eq!(allowed.outcome, Outcome::Allowed);
    assert_eq!(failed.outcome, Outcome::Failed);
    assert_eq!(
        failed.detail.as_deref(),
        Some(format!("SPAWN_FAILED (entry {})", allowed.seq).as_str())
    );
    assert_eq!(failed.lease_id, allowed.lease_id);
    assert_eq!(failed.target_path, allowed.target_path);
    assert_eq!(failed.variables, allowed.variables);
}

#[test]
fn a_command_killed_at_its_timeout_is_recorded_as_such() {
    let fx = fixture();
    let path = vault_path(&fx);

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("audit-first")
            .call(&run(&fx, "/bin/sleep", &["30"], 1))
            .expect("call")
    });
    let Response::Ran { exit_code, .. } = &reply else {
        panic!("a timed-out command still answers with its result: {reply:?}");
    };
    assert_eq!(*exit_code, None, "killed");
    assert_eq!(
        fx.agent.leases().len(),
        1,
        "the command did run: the lease stands"
    );

    let entries = on_disk(&path);
    let runs = entries_for(&entries, "run_with_env");
    assert_eq!(runs.len(), 2, "{runs:?}");
    assert_eq!(runs[0].outcome, Outcome::Allowed);
    assert_eq!(
        runs[1].detail.as_deref(),
        Some(format!("TIMED_OUT (entry {})", runs[0].seq).as_str())
    );
}

/// Entries that could not be written a moment ago mean the release's own entry would fail the
/// same way: the request is refused before a human is asked to approve it.
#[test]
fn an_audit_backlog_that_still_cannot_be_written_refuses_without_asking() {
    let fx = fixture();
    let path = vault_path(&fx);
    let dir = fx.canonical_project().display().to_string();
    let bytes = break_saves(&path);

    // A metadata tool still answers — best-effort — and leaves its entry queued.
    let listed = fx
        .client("audit-first")
        .call(&Request::ListVaults)
        .expect("call");
    assert!(matches!(listed, Response::Vaults { .. }), "{listed:?}");
    assert!(unsaved(&fx) > 0);

    let (replies, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("audit-first");
        (
            client
                .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
                .expect("call"),
            client
                .call(&run(&fx, "/usr/bin/touch", &["ran"], 5))
                .expect("call"),
        )
    });
    assert!(seen.is_empty(), "nobody may be asked: {seen:?}");
    assert_eq!(error_code(&replies.0).as_deref(), Some("AUDIT_UNAVAILABLE"));
    assert_eq!(error_code(&replies.1).as_deref(), Some("AUDIT_UNAVAILABLE"));
    assert!(!fx.canonical_project().join(REAL_DOTENV).exists());
    assert!(!fx.canonical_project().join("ran").exists());
    assert!(fx.agent.leases().is_empty());

    repair(&path, &bytes);
    fx.handle.flush_best_effort(Duration::from_secs(5));
    let entries = on_disk(&path);
    assert!(entries.iter().any(|e| e.tool == "list_vaults"));
    for tool in ["write_env_file", "run_with_env"] {
        let refused = entries_for(&entries, tool);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0].outcome, Outcome::Failed);
        assert_eq!(refused[0].detail.as_deref(), Some("AUDIT_UNAVAILABLE"));
    }
}

/// The child runs with no lock held: another request is answered while it is still running.
#[test]
fn a_long_running_command_does_not_block_other_requests() {
    let fx = fixture();
    let started = fx.canonical_project().join("started");
    let finished = AtomicBool::new(false);

    let (_, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        std::thread::scope(|scope| {
            let runner = scope.spawn(|| {
                let reply = fx
                    .client("audit-first-runner")
                    .call(&run(&fx, "/bin/sh", &["-c", "touch started; sleep 4"], 30))
                    .expect("call");
                finished.store(true, Ordering::SeqCst);
                reply
            });

            let deadline = Instant::now() + Duration::from_secs(20);
            while !started.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(started.exists(), "the command never started");

            let asked = Instant::now();
            let listed = fx
                .client("audit-first-other")
                .call(&Request::ListVaults)
                .expect("call");
            let took = asked.elapsed();
            assert!(matches!(listed, Response::Vaults { .. }), "{listed:?}");
            assert!(
                !finished.load(Ordering::SeqCst),
                "the command finished first, so this proves nothing"
            );
            assert!(
                took < Duration::from_secs(2),
                "another request waited {took:?} for a running command"
            );

            let reply = runner.join().expect("runner");
            assert!(matches!(reply, Response::Ran { .. }), "{reply:?}");
        });
    });
}

/// The agent clamps `timeout_seconds` itself, to the documented 1–3600: a caller that skips the
/// sidecar cannot get a child killed at once, nor overflow the deadline.
#[test]
fn run_timeouts_are_clamped_by_the_agent_itself() {
    let fx = fixture();

    let (replies, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("audit-first");
        (
            // Zero becomes one second: long enough for this command to finish.
            client
                .call(&run(&fx, "/bin/sleep", &["0.3"], 0))
                .expect("call"),
            // The maximum is not an overflow waiting to happen.
            client
                .call(&run(&fx, "/usr/bin/true", &[], u64::MAX))
                .expect("the connection survives a hostile timeout"),
        )
    });
    let Response::Ran { exit_code, .. } = &replies.0 else {
        panic!("{:?}", replies.0);
    };
    assert_eq!(
        *exit_code,
        Some(0),
        "a zero timeout killed the child at once"
    );
    let Response::Ran { exit_code, .. } = &replies.1 else {
        panic!("{:?}", replies.1);
    };
    assert_eq!(*exit_code, Some(0));
}

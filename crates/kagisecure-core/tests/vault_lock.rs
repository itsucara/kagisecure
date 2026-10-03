//! The vault's lock file, driven through the public API (`Vault::transact`, `Vault::create`) the
//! way separate processes and separate `Vault` values meet it.
//!
//! The lock is what turns "several writers" from a lost-update bug into a queue: exactly one
//! writer at a time, a bounded wait for everyone else, and a lock the kernel takes back from a
//! writer that dies. `vault::lock`'s own unit tests cover the primitive; these cover what a
//! caller can observe.

mod common;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{PASSWORD, cheap_options, new_vault};
use kagisecure_core::Error;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::{Vault, lock};

fn draft(tool: &str) -> AuditDraft {
    AuditDraft {
        actor: "lock-test".to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        ..AuditDraft::default()
    }
}

/// Hold `holder`'s lock inside a transaction until told to let go, reporting when it has it.
/// Returns the transaction's result.
fn hold_until(
    holder: &mut Vault,
    held: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
) -> kagisecure_core::Result<()> {
    holder.transact(|tx| {
        tx.append_audit(draft("holder"));
        held.send(()).unwrap();
        release.recv().unwrap();
        Ok(())
    })
}

#[test]
fn two_handles_on_one_vault_exclude_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let (mut holder, _code, path) = new_vault(dir.path());
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    other.set_lock_timeout(Duration::from_millis(150));

    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let holding = scope.spawn(|| hold_until(&mut holder, held_tx, release_rx));
        held_rx.recv().unwrap();

        // A write waits, then gives up with a clear error rather than writing anyway.
        let busy = other.transact(|tx| {
            tx.append_audit(draft("other"));
            Ok(())
        });
        assert!(matches!(busy, Err(Error::VaultBusy { .. })), "{busy:?}");
        // A refused write is visible on the vault, like any other failed write.
        assert!(other.last_save_error().unwrap().contains("gave up waiting"));
        assert_eq!(
            other.unsaved_audit_entries(),
            0,
            "a busy transaction queues nothing"
        );

        release_tx.send(()).unwrap();
        holding.join().unwrap().unwrap();
    });

    // Once the holder is done, the other handle's transaction builds on what it wrote.
    other
        .transact(|tx| {
            tx.append_audit(draft("other"));
            Ok(())
        })
        .unwrap();
    let tools: Vec<String> = Vault::open_with_password(&path, PASSWORD)
        .unwrap()
        .audit_entries()
        .iter()
        .map(|e| e.tool.clone())
        .collect();
    assert_eq!(tools, ["holder", "other"]);
}

#[test]
fn the_lock_is_released_however_a_transaction_ends() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let mut probe = Vault::open_with_password(&path, PASSWORD).unwrap();
    probe.set_lock_timeout(Duration::from_millis(200));
    let mut probe_can_write = |label: &str| {
        probe
            .transact(|_| Ok(()))
            .unwrap_or_else(|e| panic!("after {label}, the lock was still held: {e}"));
    };

    vault.transact(|_| Ok(())).unwrap();
    probe_can_write("a committed transaction");

    let failed: kagisecure_core::Result<()> =
        vault.transact(|_| Err(Error::ItemNotFound("x".to_owned())));
    assert!(failed.is_err());
    probe_can_write("a closure error");

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = vault.transact(|_| -> kagisecure_core::Result<()> { panic!("closure bug") });
    }));
    assert!(panicked.is_err());
    probe_can_write("a panicking closure");
}

#[test]
fn a_busy_vault_gives_up_after_the_callers_timeout_not_before_and_not_much_after() {
    let dir = tempfile::tempdir().unwrap();
    let (mut holder, _code, path) = new_vault(dir.path());
    let mut waiter = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(waiter.lock_timeout(), lock::DEFAULT_LOCK_TIMEOUT);
    let timeout = Duration::from_millis(300);
    waiter.set_lock_timeout(timeout);

    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let holding = scope.spawn(|| hold_until(&mut holder, held_tx, release_rx));
        held_rx.recv().unwrap();

        let started = Instant::now();
        let result = waiter.transact(|_| Ok(()));
        let elapsed = started.elapsed();
        match result {
            Err(Error::VaultBusy {
                path: reported,
                waited,
            }) => {
                assert_eq!(
                    reported, path,
                    "the error names the vault, not its lock file"
                );
                assert_eq!(waited, timeout);
            }
            other => panic!("expected VaultBusy, got {other:?}"),
        }
        assert!(elapsed >= timeout, "gave up after {elapsed:?}");
        // Generous: a loaded CI machine can oversleep, but not by seconds.
        assert!(elapsed < timeout + Duration::from_secs(2), "{elapsed:?}");

        release_tx.send(()).unwrap();
        holding.join().unwrap().unwrap();
    });
}

/// The holder's re-check before writing: once the lock file is renamed away, a newcomer can
/// create and lock a fresh one immediately, so the old holder must not write.
#[test]
#[cfg(unix)]
fn a_lock_file_renamed_while_held_stops_the_holder_from_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut holder, _code, path) = new_vault(dir.path());
    let before = std::fs::read(&path).unwrap();
    let lock_file = lock::lock_path(&path);

    let result = holder.transact(|tx| {
        tx.append_audit(draft("holder"));
        std::fs::rename(&lock_file, dir.path().join("moved-away.lock")).unwrap();
        // A second process could now lock a brand-new file at the same path.
        let mut newcomer = Vault::open_with_password(&path, PASSWORD).unwrap();
        newcomer.set_lock_timeout(Duration::from_millis(100));
        newcomer.transact(|_| Ok(())).unwrap();
        Ok(())
    });
    assert!(matches!(result, Err(Error::LockLost(_))), "{result:?}");
    // The newcomer wrote (an empty transaction); the holder did not, and has rolled back to it.
    assert_ne!(std::fs::read(&path).unwrap(), before);
    assert!(holder.audit_entries().is_empty());
    assert!(holder.last_save_error().is_some());

    // With the lock file restored to a single one at the path, the holder writes normally.
    holder.transact(|_| Ok(())).unwrap();
}

/// `create` holds the lock across "is anything there?" and its first write, so of several
/// processes creating the same vault exactly one wins — none silently replaces another's file.
#[test]
fn of_several_simultaneous_creates_exactly_one_succeeds() {
    const CREATORS: usize = 6;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contested.kagivault");
    let barrier = std::sync::Barrier::new(CREATORS);
    let mut results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..CREATORS)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    Vault::create(&path, PASSWORD, &cheap_options()).map(|(v, _code)| v)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for loser in results.iter().filter_map(|r| r.as_ref().err()) {
        assert!(matches!(loser, Error::VaultExists(_)), "{loser}");
    }
    let mut winners: Vec<&mut Vault> = results.iter_mut().filter_map(|r| r.as_mut().ok()).collect();
    assert_eq!(winners.len(), 1);
    // The file on disk is the winner's: its session can keep writing without a conflict.
    winners[0].transact(|_| Ok(())).unwrap();
}

/// The environment variable that turns this test binary into the lock-holding child.
#[cfg(unix)]
const HOLDER_VAR: &str = "KAGISECURE_LOCK_HOLDER_VAULT";

/// What the child prints once it is inside the transaction, holding the lock.
#[cfg(unix)]
const HOLDING: &str = "kagisecure-lock-holder-holding\n";

/// The kernel releases a lock whose holder is `SIGKILL`ed mid-transaction — no stale-lock
/// cleanup, no timeout to wait out, no manual step.
#[test]
#[cfg(unix)]
fn a_lock_held_by_a_killed_process_is_free_as_soon_as_it_dies() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    drop(vault);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "lock_holder_child_entry_point",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env(HOLDER_VAR, &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the test binary should re-execute");

    // libtest prints its own banner to the same stdout, so read lines until the marker.
    let mut reader = std::io::BufReader::new(child.stdout.take().expect("piped"));
    let mut holding = false;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == HOLDING => {
                holding = true;
                break;
            }
            Ok(_) => {}
            Err(e) => panic!("reading the child's stdout failed: {e}"),
        }
    }
    if !holding {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the child never reported holding the lock");
    }

    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();
    vault.set_lock_timeout(Duration::from_millis(200));
    let busy = vault.transact(|_| Ok(()));
    assert!(
        matches!(busy, Err(Error::VaultBusy { .. })),
        "the child should be holding the lock: {busy:?}"
    );

    child.kill().unwrap(); // SIGKILL: no destructor, no unlock, no cleanup of any kind
    let _ = child.wait();
    drop(reader);

    vault.set_lock_timeout(Duration::from_secs(10));
    let started = Instant::now();
    vault
        .transact(|tx| {
            tx.append_audit(draft("after-kill"));
            Ok(())
        })
        .expect("a dead holder's lock must be free");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the lock was free at once, not after a timeout"
    );
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.audit_entries().len(), 1);
    reopened.verify_audit().unwrap();
}

/// Not a test: the child half of `a_lock_held_by_a_killed_process_is_free_as_soon_as_it_dies`.
///
/// `#[ignore]`d so a normal run skips it, and it returns at once unless the parent set the
/// environment variable naming the vault. Inside a transaction it reports that it holds the lock
/// and then never returns, so the only way out is the parent's `SIGKILL`.
#[test]
#[ignore = "child process entry point for the killed-lock-holder test, not a test of its own"]
#[cfg(unix)]
fn lock_holder_child_entry_point() {
    use std::io::Write;

    let Ok(path) = std::env::var(HOLDER_VAR) else {
        return;
    };
    let Ok(mut vault) = Vault::open_with_password(&path, PASSWORD) else {
        return;
    };
    let _ = vault.transact(|tx| -> kagisecure_core::Result<()> {
        tx.append_audit(draft("never-committed"));
        let mut out = std::io::stdout();
        let _ = out.write_all(HOLDING.as_bytes());
        let _ = out.flush();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

//! Locking must end a `run_with_env` child still running under an injected environment —
//! `docs/mcp-server.md`'s "lock ends what an approval started", the process half of it. The file
//! half (a lease that ran out of uses before the lock, "Allow once") is
//! `tests/adversarial_lease.rs`'s
//! `locking_shreds_a_file_written_under_a_lease_that_had_already_run_out_of_uses`.
//!
//! Before this fix, `run_with_env`'s child ran on a connection thread with no lock of any kind
//! held (by design, since step 7 of the audit-first work: a long command must not hold up another
//! writer or another request). That also meant nothing *ended* it on lock: the thread stayed
//! blocked in the child's own wait loop, the injected value stayed live in its environment, and
//! the user who had just been told the vault was locked had no way to know a value it granted was
//! still reachable by a process it no longer controlled.
//!
//! Unix-only: the commands run here (`sleep`, `sh`) are unix binaries, and the process-group kill
//! this test exercises is `kagisecure-childproc`'s Unix mechanism (its own crate has the
//! Windows-flavoured unit tests for the job-object equivalent, which needs no real agent around
//! it to exercise).
#![cfg(unix)]

mod common;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{fixture, with_ui};
use kagisecure_agent::approval::Decision;
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{OutputMode, Request, Response};

/// Whether a pid is still alive, via the same `kill(2)` a real supervisor would use — `kill -0`
/// sends no signal and only reports whether the process exists and is signalable.
fn pid_is_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Wait up to `timeout` for `pid` to stop being alive.
fn wait_for_death(pid: u32, timeout: Duration) {
    let started = Instant::now();
    while pid_is_alive(pid) {
        assert!(
            started.elapsed() < timeout,
            "pid {pid} should have died within {timeout:?} of the kill"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The audit log as the file on disk holds it, read by a third party — the same technique
/// `tests/audit_first.rs` uses, so a reader with no view into this process's own `VaultHandle`
/// sees the same thing a human opening `kagisecure audit` would.
fn on_disk(fx: &common::Fixture) -> Vec<AuditEntry> {
    let path = fx.dir.path().join("test.kagivault");
    let vault = Vault::open_with_password(&path, b"pw").expect("open the vault file");
    vault.verify_audit().expect("the chain verifies");
    vault.audit_entries().to_vec()
}

#[test]
fn locking_kills_a_run_with_env_child_and_its_grandchild_within_the_grace_period() {
    let fx = fixture();
    let dir = fx.canonical_project();
    let grandchild_pid_file = dir.join("grandchild.pid");

    // `sh` (the tracked child) forks a real grandchild (`sleep 30`, backgrounded) and writes its
    // pid to a file before waiting on it — a genuine second process in the same group, not the
    // same pid re-exec'd into a different image, so killing the *group* is what has to reach it.
    let request = Request::RunWithEnv {
        environment_id: fx.env_id.parse().expect("env id"),
        command: "sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            format!(
                "sleep 30 & echo $! > {} ; wait",
                grandchild_pid_file.display()
            ),
        ],
        cwd: dir.display().to_string(),
        variables: None,
        timeout_seconds: 60,
        output: OutputMode::Scrubbed,
        delivery: kagisecure_ipc::protocol::Delivery::Environment,
    };

    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            // `with_ui` blocks its calling thread until the closure returns, i.e. until the
            // `RunWithEnv` call itself does — which, absent a lock, would be ~30s. Running it on
            // its own thread is what lets this test's main thread go on to lock concurrently.
            let (response, _seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
                let mut client = fx.client("run-with-env-lock");
                client
                    .call(&request)
                    .expect("the call itself should succeed")
            });
            let _ = tx.send(response);
        });

        // Give the child (and its grandchild) time to actually start and for the grandchild's pid
        // to be written, rather than locking before the approval has even been granted.
        let grandchild_pid = {
            let started = Instant::now();
            loop {
                if let Ok(text) = std::fs::read_to_string(&grandchild_pid_file)
                    && let Ok(pid) = text.trim().parse::<u32>()
                {
                    break pid;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "the grandchild never reported its pid"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        assert!(
            pid_is_alive(grandchild_pid),
            "precondition: the grandchild is actually running"
        );

        // What the host does on `kagisecure lock`.
        drop(fx.handle.take());

        // The kill hook's own `SIGKILL` runs on a thread of its own (see
        // `ChildKillHandle::kill`'s doc comment) with a short grace period, so both the child and
        // the grandchild it forked should be gone well inside a generous test timeout — nowhere
        // near the 30s either was told to sleep for.
        wait_for_death(grandchild_pid, Duration::from_secs(10));
    });

    let response = rx
        .recv()
        .expect("the run_with_env call should have returned");
    assert!(
        matches!(&response, Response::Error { .. }),
        "the reply must say the vault locked out from under this call, not report a result as \
         though it were still open; got {response:?}"
    );
    assert_eq!(
        kagisecure_ipc::protocol::ErrorCode::VaultLocked,
        match &response {
            Response::Error { code, .. } => *code,
            _ => unreachable!(),
        },
        "got {response:?}"
    );

    // The audit entry: a `Failed` follow-up naming the `Allowed` entry it completes, with detail
    // `KILLED_ON_LOCK (entry <seq>)` — queued directly on the vault by the lock hook itself (see
    // `kagisecure_agent::children`), since by the time an ordinary best-effort write would run,
    // the vault is already gone from the handle.
    let entries = on_disk(&fx);
    let allowed = entries
        .iter()
        .find(|e| e.tool == "run_with_env" && e.outcome == Outcome::Allowed)
        .expect("the Allowed entry committed before the child ran");
    let failed = entries
        .iter()
        .find(|e| e.tool == "run_with_env" && e.outcome == Outcome::Failed)
        .unwrap_or_else(|| {
            panic!("expected a Failed/KILLED_ON_LOCK follow-up; entries were {entries:#?}")
        });
    assert_eq!(
        failed.detail.as_deref(),
        Some(format!("KILLED_ON_LOCK (entry {})", allowed.seq).as_str())
    );
}

/// The same guarantee, reached the other way: `kagisecure lock` sent over the socket
/// (`Request::Lock`) rather than the host calling `VaultHandle::take` directly.
///
/// `Service::lock` does not remove the vault from the handle itself — the host does that on its
/// own schedule, up to one poll interval later (`tests/sidecar.rs`'s
/// `the_socket_stops_serving_the_moment_a_lock_is_acknowledged` is the regression for that window
/// for leases). This test never calls `take_lock_request`/`VaultHandle::take` at all, so it proves
/// `Service::kill_running_children` — the early-cleanup counterpart to `Service::kill_leases` —
/// ends the child on its own, through the ordinary best-effort audit path, while the key is still
/// in memory.
#[test]
fn a_socket_level_lock_kills_a_running_child_before_the_host_ever_takes_the_vault() {
    let fx = fixture();
    let dir = fx.canonical_project();
    let pid_file = dir.join("child.pid");

    // Reports its own pid before sleeping, so the test can tell the child has actually started —
    // an "Allow once" lease is consumed the instant it is granted (`uses_remaining` drops to 0
    // in `Service::reserve` before the child is even spawned), so `fx.agent.leases()` becoming
    // non-empty is not a usable signal here the way it is for a longer-lived lease.
    let request = Request::RunWithEnv {
        environment_id: fx.env_id.parse().expect("env id"),
        command: "sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            format!("echo $$ > {} ; exec sleep 30", pid_file.display()),
        ],
        cwd: dir.display().to_string(),
        variables: None,
        timeout_seconds: 60,
        output: OutputMode::Scrubbed,
        delivery: kagisecure_ipc::protocol::Delivery::Environment,
    };

    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let (response, _seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
                let mut client = fx.client("run-with-env-lock-socket");
                client
                    .call(&request)
                    .expect("the call itself should succeed")
            });
            let _ = tx.send(response);
        });

        // Give the child time to actually start and report its pid.
        let child_pid = {
            let started = Instant::now();
            loop {
                if let Ok(text) = std::fs::read_to_string(&pid_file)
                    && let Ok(pid) = text.trim().parse::<u32>()
                {
                    break pid;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "the child never reported its pid"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        assert!(
            pid_is_alive(child_pid),
            "precondition: the child is actually running"
        );

        // `kagisecure lock`, over the socket — never `fx.handle.take()`.
        let mut lock_client = fx.client("lock-window");
        let reply = lock_client.call(&Request::Lock).expect("lock");
        assert!(
            matches!(reply, Response::Locked),
            "the lock should be acknowledged: {reply:?}"
        );
        assert!(
            fx.handle.is_unlocked(),
            "this test is only meaningful while the host has not yet taken the vault"
        );

        wait_for_death(child_pid, Duration::from_secs(10));
    });

    let response = rx
        .recv()
        .expect("the run_with_env call should have returned");
    assert!(
        matches!(&response, Response::Error { .. }),
        "got {response:?}"
    );

    let entries = on_disk(&fx);
    let allowed = entries
        .iter()
        .find(|e| e.tool == "run_with_env" && e.outcome == Outcome::Allowed)
        .expect("the Allowed entry committed before the child ran");
    let failed = entries
        .iter()
        .find(|e| e.tool == "run_with_env" && e.outcome == Outcome::Failed)
        .unwrap_or_else(|| {
            panic!("expected a Failed/KILLED_ON_LOCK follow-up; entries were {entries:#?}")
        });
    assert_eq!(
        failed.detail.as_deref(),
        Some(format!("KILLED_ON_LOCK (entry {})", allowed.seq).as_str())
    );
}

//! Adversarial tests for the lease scoping rules at the MCP → app trust boundary.
//!
//! A lease is the unit of granted access: once one exists, `Service::write_env_file` and
//! `Service::run_with_env` skip the human entirely. So the question these tests ask is not
//! "does an approval work" — `tests/sidecar.rs` answers that — but "is the lease *exactly* as
//! wide as the sentence the human read on the sheet, and not one inch wider".
//!
//! Every test here drives the real `Agent` over a real local socket with a real
//! `kagisecure-ipc` client, deliberately **not** through `kagisecure-mcp`. The sidecar clamps
//! `ttl_seconds` and defaults `filename` before forwarding, and a hostile caller would simply
//! not run it. The socket is the boundary, so the socket is what is attacked.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{
    DECOY_DOTENV, MARKER, REAL_DOTENV, allow_session, error_code, fixture, with_ui,
    with_ui_answering, write_env_file,
};
use kagisecure_agent::approval::Decision;
use kagisecure_agent::service::human_path;
use kagisecure_core::lease::{MAX_TTL_SECONDS, MIN_TTL_SECONDS};
use kagisecure_ipc::protocol::{OutputMode, Request, Response};

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// D-2 / A-01: the approved filename is not part of the lease, so one approval covers every file.
///
/// `LeaseRequest` (`kagisecure-core/src/lease.rs`) carries the environment, the canonical
/// directory, the variable names and the kind. It does **not** carry the filename, and
/// `Lease::covers` therefore cannot compare one. The only place a filename appears is
/// `ApprovalRequest::target_path`, which is built for the sheet and then discarded.
///
/// The attack that follows is the whole point of the field being missing: ask for
/// `.env.example`, which is a file a human reads as documentation and approves without much
/// thought, and then write `.env`, which is the file the toolchain loads — with no second
/// prompt, because the lease from the first approval already "covers" it.
#[test]
// FIXED (D-2): `LeaseRequest` now carries the file name and `Lease::covers` compares it.
// UNVERIFIED — this machine cannot run test binaries.
fn a_lease_approved_for_one_filename_does_not_cover_another_filename() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        // The human is shown `.env.example` and approves it.
        let first = client
            .call(&write_env_file(&fx, &dir, DECOY_DOTENV, false, 900))
            .expect("call");
        assert!(
            error_code(&first).is_none(),
            "the decoy write should succeed: {first:?}"
        );
        // The caller now writes the file a toolchain actually reads, and clobbers it.
        let second = client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call");
        assert!(
            error_code(&second).is_none(),
            "the real write should succeed: {second:?}"
        );
    });

    let sheets: Vec<&str> = seen
        .iter()
        .filter_map(|r| r.target_path.as_deref())
        .collect();
    assert!(
        sheets.iter().any(|p| p.ends_with(REAL_DOTENV)),
        "a write to {REAL_DOTENV} must be approved by a human; the sheets shown were {sheets:?}"
    );
}

/// The same defect stated as the fact a reader can check without judging intent: two different
/// files land on disk from one approval.
#[test]
// FIXED (D-2): one approval now covers one file name. UNVERIFIED — never executed.
fn one_approval_writes_exactly_one_file() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        for name in [DECOY_DOTENV, REAL_DOTENV, ".env.production"] {
            let _ = client.call(&write_env_file(&fx, &dir, name, true, 900));
        }
    });

    let written: Vec<String> = std::fs::read_dir(fx.canonical_project())
        .expect("read project dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".env"))
        .collect();
    assert_eq!(
        written.len(),
        seen.len(),
        "each written file should have cost one approval; wrote {written:?} after {} sheet(s)",
        seen.len()
    );
}

/// The other half of the `revoke_env_file` fix: genuine revocation still works.
///
/// `Service::revoke` now shreds only what this vault wrote. The record of what it wrote lives in
/// `LeaseStore` and deliberately outlives the lease itself, so revoking by path works after the
/// lease has been spent — which is the common case, because "Allow once" consumes its lease
/// during the very write that created the file.
#[test]
// UNVERIFIED — this machine cannot run test binaries.
fn a_file_this_agent_wrote_is_still_shredded_by_path_after_its_lease_is_gone() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);

    // "Allow once": the lease is consumed to nothing by the write that mints it.
    let (_, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert_eq!(seen.len(), 1);
    assert!(target.exists(), "precondition: the file was written");
    assert!(
        fx.agent.leases().is_empty(),
        "precondition: the lease is already spent"
    );

    let mut client = fx.client("adversarial-lease");
    let reply = client
        .call(&Request::RevokeEnvFile {
            lease_id: None,
            path: Some(target.display().to_string()),
        })
        .expect("call");
    match reply {
        Response::Revoked { shredded } => assert_eq!(
            shredded,
            // Not `target.display()`: on Windows that is the verbatim `\\?\C:\...` form
            // `canonicalize()` returns, and the audit/response path the agent hands back is the
            // human-facing one `human_path` produces (service.rs's `TODO(windows)` fix) — the
            // same transform the sheet and the audit log go through.
            vec![human_path(&target)],
            "a file this agent wrote must still be shreddable once its lease has gone"
        ),
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert!(!target.exists(), "and it is gone from disk");
}

/// Locking must shred a file written under a lease that had already run out of uses — "Allow
/// once" is the common case, since the lease is consumed by the very write that mints it.
///
/// `LeaseStore::revoke_all` used to return only the `written_paths` still attached to a *live*
/// lease. An "Allow once" lease is gone from the store the instant its file is written, so by the
/// time the user locked, the file it wrote was not on that list at all — a live secret sat on
/// disk right after the user had just been told every lease and everything written under one was
/// gone. `revoke_all` now returns the store's own `written` ledger, which deliberately outlives
/// the lease (see its doc comment and `kagisecure-core`'s `lease.rs` unit tests); this is that fix
/// exercised through the real agent, the real lock hook and a real file on disk.
#[test]
fn locking_shreds_a_file_written_under_a_lease_that_had_already_run_out_of_uses() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);

    // "Allow once": the lease is consumed to nothing by the write that mints it.
    let (_, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert_eq!(seen.len(), 1);
    assert!(target.exists(), "precondition: the file was written");
    assert!(
        fx.agent.leases().is_empty(),
        "precondition: the lease is already spent, before the lock ever happens"
    );

    // What the host does on `kagisecure lock`: take the vault out of the handle, which runs the
    // agent's lock hook.
    drop(fx.handle.take());

    assert!(
        !target.exists(),
        "a file written under a lease with no uses left must still be shredded on lock"
    );
}

/// A-12: a hostile `ttl_seconds` cannot buy a lease longer than the documented ceiling.
///
/// `outcome_for` clamps to `max_ttl_seconds` and `LeaseStore::grant` clamps again, so this is a
/// belt-and-braces check that the two clamps agree even when the caller asks for a century —
/// a value the sidecar would have reduced to 86 400 but a raw socket client will not.
#[test]
fn an_absurd_requested_ttl_is_clamped_to_the_documented_maximum() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let before = unix_now();
    let a_century = MAX_TTL_SECONDS * 36_500;

    let (_, seen) = with_ui(&fx.agent, allow_session(a_century, u32::MAX), || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, a_century))
            .expect("call")
    });

    assert_eq!(seen.len(), 1, "one sheet");
    assert_eq!(
        seen[0].max_ttl_seconds, MAX_TTL_SECONDS,
        "the sheet must state the ceiling its control has to respect"
    );

    let after = unix_now();

    let leases = fx.agent.leases();
    assert_eq!(leases.len(), 1, "one lease");
    // The agent reads the clock somewhere between `before` and `after`, so the ceiling is
    // measured from `after` and the floor from `before`: measuring both from `before` fails
    // whenever the call straddles a second boundary.
    let expires_at = leases[0].expires_at;
    assert!(
        expires_at <= after.saturating_add(MAX_TTL_SECONDS),
        "a lease may not outlive {MAX_TTL_SECONDS}s; this one lives {}s",
        expires_at.saturating_sub(after)
    );
    assert!(
        expires_at.saturating_sub(before) >= MIN_TTL_SECONDS,
        "and it must still be a real lease, not a zero-length one"
    );
}

/// D-11, escalated: the unclamped fallback is evaluated **eagerly**, so a hostile `ttl_seconds`
/// arithmetic-overflows and takes the connection thread down with it.
///
/// `service.rs` ends the write with
/// `leases.summaries(now).into_iter().find(..).map_or(now + ttl_seconds, |l| l.expires_at)`.
/// `map_or`'s default is an argument, not a closure, so `now + ttl_seconds` is computed on every
/// call whether or not the lease was found. With `ttl_seconds: u64::MAX` that addition overflows:
/// a debug build panics inside the per-connection thread of the process holding the unlocked
/// vault key, and a release build silently wraps to a nonsense expiry.
///
/// A caller reaches this by sending one frame to the socket. The MCP sidecar clamps
/// `ttl_seconds` to 60..=86 400 before forwarding, which is why the shipped path does not hit it
/// — but the sidecar is a convenience for models, not a control, and the socket is the boundary.
#[test]
// FIXED (D-11): the fallback is a closure now, and the arithmetic saturates after the TTL has
// been clamped to the documented range. UNVERIFIED — never executed.
fn a_hostile_ttl_does_not_crash_the_connection_serving_it() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        client.call(&write_env_file(&fx, &dir, REAL_DOTENV, true, u64::MAX))
    });

    let reply = reply.expect("the connection survived a hostile ttl_seconds");
    assert!(
        error_code(&reply).is_none() || error_code(&reply).as_deref() == Some("INVALID_PATH"),
        "reply was {reply:?}"
    );

    // And the agent is still serving afterwards.
    let mut client = fx.client("adversarial-lease");
    let alive = client
        .call(&Request::ListLeases)
        .expect("the agent is still up");
    assert!(error_code(&alive).is_none(), "reply was {alive:?}");
}

/// D-11 / A-31: the `expires_at` reported to the caller must never exceed the lease that exists.
///
/// `Service::write_env_file` looks the lease up again after the write to report its expiry, and
/// falls back to `now + ttl_seconds` — the **unclamped, caller-supplied** TTL — when the lookup
/// misses. It misses exactly when the lease was consumed to nothing, which is every "Allow once"
/// grant. So an "Allow once" caller asking for `u64::MAX` seconds is told its access lasts until
/// the heat death of the universe, when in fact it lasted one call.
#[test]
// PREDICTED FAILURE (D-11), from source reading only: an "Allow once" lease is consumed to
// zero and pruned before the expiry lookup, so the eagerly-evaluated `now + ttl_seconds`
// fallback is what gets reported. Never executed.
fn the_reported_expiry_never_exceeds_the_lease_that_backs_it() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let requested_ttl = MAX_TTL_SECONDS * 1000;

    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, requested_ttl))
            .expect("call")
    });
    // Measured *after* the call returns, not before it starts: the server computes
    // `its_own_now + MAX_TTL_SECONDS` from a clock read somewhere during the call, so a
    // timestamp taken before the call started can be up to a second behind that read, and the
    // wall clock ticking over during the call would fail this assertion for a reason that has
    // nothing to do with the invariant under test. A timestamp taken after the call returns is
    // provably no earlier than the server's own reading, so the inequality below holds without
    // being at the mercy of a clock tick.
    let after = unix_now();

    let Response::WroteEnvFile { expires_at, .. } = &reply else {
        panic!("the write should have succeeded: {reply:?}");
    };
    let reported = chrono_secs(expires_at);
    assert!(
        reported.saturating_sub(after) <= MAX_TTL_SECONDS,
        "the reply promises access until {expires_at}, which is more than {MAX_TTL_SECONDS}s away"
    );
}

/// Parse the RFC 3339 timestamp the agent reports back into unix seconds.
fn chrono_secs(rfc3339: &str) -> u64 {
    // The agent formats with `kagisecure_core::rfc3339`, which is always `...Z`. Parsing by hand
    // keeps the test free of a dependency the crate does not otherwise carry.
    let bytes = rfc3339.as_bytes();
    assert!(bytes.len() >= 20, "unexpected timestamp {rfc3339:?}");
    let num = |range: std::ops::Range<usize>| -> i64 {
        rfc3339[range].parse().unwrap_or_else(|_| {
            panic!("unexpected timestamp {rfc3339:?}");
        })
    };
    let (y, mo, d) = (num(0..4), num(5..7), num(8..10));
    let (h, mi, s) = (num(11..13), num(14..16), num(17..19));
    // Days since the epoch, by the civil-from-days algorithm (Howard Hinnant's, public domain).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + s).expect("after the epoch")
}

/// A-13: "Allow once" means one use, whatever TTL the caller asked for.
///
/// The risk is a UI that reads `ttl_seconds` off an `AllowOnce` decision and grants a day of
/// access to something the human understood as a single action. `outcome_for` hard-codes
/// `uses: 1` for `AllowOnce`, so the intended policy is *uses win over time*: the second call
/// must re-prompt even though the first lease has 23 hours left on the clock.
#[test]
fn allow_once_with_a_day_long_ttl_is_still_exactly_one_use() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (_, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let mut client = fx.client("adversarial-lease");
        for _ in 0..3 {
            let reply = client
                .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 86_400))
                .expect("call");
            assert!(error_code(&reply).is_none(), "reply was {reply:?}");
        }
    });

    assert_eq!(
        seen.len(),
        3,
        "\"Allow once\" is one use regardless of ttl_seconds (ui-spec.md §10.3)"
    );
    assert!(
        fx.agent.leases().is_empty(),
        "and it leaves no lease behind once it has been spent"
    );
}

/// A-11: an expired lease is never usable, even though nothing prunes it in the background.
///
/// `LeaseStore::find` is the only pruner, so an expired lease sits in the store until someone
/// asks for one. That is fine as long as `covers` checks `is_live`, which is what this asserts:
/// the lease is still *listed* after its TTL, but it cannot authorize anything.
#[test]
fn a_lease_past_its_ttl_authorizes_nothing_even_though_nothing_swept_it() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    // The shortest lease the system will mint, so the test waits seconds and not minutes.
    let (_, first) = with_ui(&fx.agent, allow_session(MIN_TTL_SECONDS, 10), || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(
                &fx,
                &dir,
                REAL_DOTENV,
                true,
                MIN_TTL_SECONDS,
            ))
            .expect("call")
    });
    assert_eq!(first.len(), 1);
    let granted = fx.agent.leases();
    assert_eq!(granted.len(), 1);
    let expiry = granted[0].expires_at;

    // Rather than sleep out a 60-second TTL, assert the property the pruning question is really
    // about: `covers` is time-checked, so a lease whose expiry has passed cannot match.
    let request = kagisecure_core::lease::LeaseRequest {
        environment_id: fx.env_id.parse().expect("env id"),
        directory: fx.canonical_project(),
        filename: Some(REAL_DOTENV.to_owned()),
        variables: ["TOKEN".to_owned()].into_iter().collect(),
        kind: kagisecure_core::proto::LeaseKind::EnvFile,
        command: None,
        replaces_unowned_file: false,
    };
    let mut store = kagisecure_core::lease::LeaseStore::new();
    let now = unix_now();
    store.grant(&request, "adversarial test", MIN_TTL_SECONDS, 10, now);
    assert!(
        store.find(&request, now).is_some(),
        "the lease covers the request while it is live"
    );
    assert!(
        store.find(&request, expiry + 1).is_none(),
        "and never after its expiry, whether or not anything swept it"
    );
    assert!(
        store.summaries(expiry + 1).is_empty(),
        "nor is an expired lease reported as live"
    );
}

/// A-06 / D-8: a lease with one use left may not serve two concurrent callers.
///
/// The lock on the `LeaseStore` is released between `find` (which picks the lease) and `consume`
/// (which decrements it), with the resolution and the file write in between. Two connections
/// racing through that window can both see `uses_remaining: 1`.
///
/// The agent is thread-per-connection, so this is two real client threads on two real sockets,
/// which is exactly the shape a model running two tool calls in parallel produces.
#[test]
// PREDICTED FAILURE (D-8), from source reading only: `find` and `consume` are two separate
// lock acquisitions with the resolution and the write in between. Never executed, and the
// outcome is timing-dependent even when it is.
fn a_single_use_lease_serves_exactly_one_of_two_racing_callers() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let prompts = AtomicUsize::new(0);

    // Grant exactly one use, then race two writes against it.
    let (_, _) = with_ui_answering(
        &fx.agent,
        |_| {
            prompts.fetch_add(1, Ordering::SeqCst);
            Some(allow_session(900, 1))
        },
        || {
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..2)
                    .map(|i| {
                        let dir = dir.clone();
                        let fx = &fx;
                        scope.spawn(move || {
                            let mut client = fx.client("adversarial-race");
                            client
                                .call(&write_env_file(
                                    fx,
                                    &dir,
                                    &format!(".env.racer{i}"),
                                    true,
                                    900,
                                ))
                                .expect("call")
                        })
                    })
                    .collect();
                for handle in handles {
                    let _ = handle.join();
                }
            });
        },
    );

    let asked = prompts.load(Ordering::SeqCst);
    let written = std::fs::read_dir(fx.canonical_project())
        .expect("read project dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".env.racer"))
        .count();
    assert!(
        written <= asked,
        "{written} file(s) were written under {asked} approval(s) of one use each"
    );
}

/// A-14: locking the vault while a sheet is up must abort the action, not race it.
///
/// `ApprovalQueue::deny_all` clears the pending queue and closes it, so the blocked `ask`
/// returns `VAULT_LOCKED` rather than a grant. Nothing may reach disk and no lease may survive.
#[test]
fn locking_the_vault_while_a_sheet_is_up_refuses_the_request_and_writes_nothing() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);

    let (reply, seen) = with_ui_answering(
        &fx.agent,
        |_| {
            // The "user" never answers. The lock does, from the other thread below.
            None
        },
        || {
            std::thread::scope(|scope| {
                let caller = scope.spawn(|| {
                    let mut client = fx.client("adversarial-lock");
                    client
                        .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
                        .expect("call")
                });
                // Wait until the question has actually reached the queue, then lock.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while fx.agent.pending_requests().is_empty() && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                fx.agent.queue().deny_all();
                caller.join().expect("caller thread")
            })
        },
    );

    assert_eq!(
        error_code(&reply).as_deref(),
        Some("VAULT_LOCKED"),
        "a lock mid-sheet is VAULT_LOCKED, not a grant and not USER_DENIED: {reply:?}"
    );
    assert!(
        !target.exists(),
        "a request the lock swept must not have written {target:?}"
    );
    assert!(
        fx.agent.leases().is_empty(),
        "nor left a lease behind: {:?}",
        fx.agent.leases()
    );
    let rendered = format!("{seen:?} {reply:?}");
    assert!(!rendered.contains(MARKER), "no value may appear anywhere");
}

/// A lease is scoped to the directory the human saw, with no prefix matching.
///
/// This is the invariant `lease.rs` documents in its header, and the one that keeps an approval
/// for `~/code/project` from authorizing `~/code/project/.git` or its parent.
#[test]
fn a_lease_for_one_directory_does_not_cover_a_subdirectory_or_its_parent() {
    let fx = fixture();
    let parent = fx.canonical_project();
    let child = parent.join("nested");
    std::fs::create_dir_all(&child).expect("nested dir");

    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        for dir in [&parent, &child] {
            let reply = client
                .call(&write_env_file(
                    &fx,
                    &dir.display().to_string(),
                    REAL_DOTENV,
                    true,
                    900,
                ))
                .expect("call");
            assert!(error_code(&reply).is_none(), "reply was {reply:?}");
        }
    });

    assert_eq!(
        seen.len(),
        2,
        "each directory is its own approval; the sheets were {:?}",
        seen.iter().map(|r| r.directory.clone()).collect::<Vec<_>>()
    );
}

/// Revoking a lease shreds what it wrote and stops it serving, over the real socket.
#[test]
fn revoking_a_lease_shreds_its_file_and_ends_its_authority() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    let Response::WroteEnvFile { lease_id, .. } = &reply else {
        panic!("expected a write: {reply:?}");
    };
    assert!(target.is_file());
    assert!(
        std::fs::read_to_string(&target)
            .expect("read")
            .contains(MARKER)
    );

    let mut client = fx.client("adversarial-lease");
    let revoked = client
        .call(&Request::RevokeEnvFile {
            lease_id: Some(*lease_id),
            path: None,
        })
        .expect("call");
    assert!(error_code(&revoked).is_none(), "reply was {revoked:?}");
    assert!(!target.exists(), "a revoke shreds what the lease wrote");
    assert!(fx.agent.leases().is_empty(), "and ends the lease");
}

/// A lease minted for a call that then fails must not survive the call.
///
/// `write_env_file` mints a multi-use lease as soon as the sheet is approved, then resolves the
/// environment and writes the file. Before this fix, every `Err` path after the grant (this one:
/// `envfile::write` refusing because the target exists and `overwrite` is false) returned early
/// without revoking it, leaving a live lease that would silently authorize a *later* write to the
/// same directory and filename with no second sheet — even though the human never saw this write
/// succeed.
#[test]
fn a_write_env_file_failure_after_grant_revokes_the_freshly_minted_lease() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    // Something is already at the target path, so the write below fails for a reason that has
    // nothing to do with the filename or the directory: `Error::EnvFileExists`.
    std::fs::write(fx.canonical_project().join(REAL_DOTENV), b"pre-existing\n").expect("seed");

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, false, 900))
            .expect("call")
    });

    assert_eq!(
        error_code(&reply).as_deref(),
        Some("FILE_EXISTS"),
        "expected the write to fail because the target already exists: {reply:?}"
    );
    assert!(
        fx.agent.leases().is_empty(),
        "a lease minted for a call that then failed must not survive it: {:?}",
        fx.agent.leases()
    );
}

/// The same defect, on `run_with_env`: a lease minted for a command that never even started must
/// not survive the failure to start it.
#[test]
fn a_run_with_env_spawn_failure_after_grant_revokes_the_freshly_minted_lease() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&Request::RunWithEnv {
                environment_id: fx.env_id.parse().expect("env id"),
                command: "/definitely/not/a/real/program-kagisecure-test".to_owned(),
                args: vec![],
                cwd: dir.clone(),
                variables: None,
                timeout_seconds: 5,
                output: OutputMode::Scrubbed,
                delivery: kagisecure_ipc::protocol::Delivery::Environment,
            })
            .expect("call")
    });

    assert!(
        error_code(&reply).is_some(),
        "expected the run to fail because the program cannot be spawned: {reply:?}"
    );
    assert!(
        fx.agent.leases().is_empty(),
        "a lease minted for a call whose spawn then failed must not survive it: {:?}",
        fx.agent.leases()
    );
}

/// The other side of the same fix: a lease that pre-dated a call is not this call's to revoke,
/// even when the call it covers then fails.
///
/// Without this property, the fix for the two tests above could overreach — revoking *any* lease
/// on any failure — and silently break the common case where "Allow session" is meant to keep
/// authorizing a directory across several calls, some of which fail for reasons of their own.
#[test]
fn a_preexisting_lease_survives_a_later_failing_call_it_covers() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    // First call mints a multi-use, multi-call lease and succeeds.
    let (first, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-lease");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert!(error_code(&first).is_none(), "reply was {first:?}");
    assert_eq!(
        fx.agent.leases().len(),
        1,
        "one lease minted by the first call, still live"
    );

    // Second call to the exact same directory and filename is covered by that existing lease —
    // no sheet is shown — but fails for a reason of its own: the file is there now and this call
    // asks not to overwrite it.
    let mut client = fx.client("adversarial-lease");
    let second = client
        .call(&write_env_file(&fx, &dir, REAL_DOTENV, false, 900))
        .expect("call");
    assert_eq!(
        error_code(&second).as_deref(),
        Some("FILE_EXISTS"),
        "reply was {second:?}"
    );
    assert_eq!(
        fx.agent.leases().len(),
        1,
        "a lease this call did not mint must not be revoked by this call's failure"
    );
}

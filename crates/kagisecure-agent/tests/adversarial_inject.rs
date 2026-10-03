//! Adversarial tests for path handling, the visibility gate and the error oracle.
//!
//! Three separate questions about the same surface, all of them about what a caller can learn or
//! reach that the human never agreed to:
//!
//! * **Paths.** `Service::write_env_file` builds the sheet's `target_path` with
//!   `canonical.join(filename)` and only validates the filename much later, inside
//!   `envfile::write`. Anything between those two points is a chance for the sheet to describe a
//!   path that is not the path, or for a lease to be minted for a call that cannot succeed.
//! * **Visibility.** `agent_visible` is the switch a user flips to say "not this one". With it
//!   off everywhere, every tool must be a dead end, and the *name* of the hidden thing must not
//!   leak through a message.
//! * **The oracle.** "Exists but denied" and "does not exist" must be indistinguishable, or the
//!   agent becomes an enumeration primitive for a vault it cannot read (threat-model M-8).
//!
//! As elsewhere in this suite the tests speak to the real agent over a real socket, because the
//! sidecar's defaulting of `filename` is a convenience and not a control.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{
    MARKER, REAL_DOTENV, allow_session, error_code, error_message, fixture, invisible_fixture,
    with_ui, with_ui_answering, write_env_file,
};
use kagisecure_agent::approval::Decision;
use kagisecure_ipc::protocol::{OutputMode, Request, Response};

/// A traversal that, joined onto the approved directory, escapes it.
const TRAVERSAL_FILENAME: &str = "../../../tmp/kagisecure-escape.env";

/// An absolute filename, which `Path::join` replaces the whole base with.
const ABSOLUTE_FILENAME: &str = "/etc/kagisecure.env";

/// A-03: a traversing filename must never be approvable, and must never mint a lease.
///
/// `envfile::validate_filename` rejects anything containing a separator, so the write itself is
/// refused — but that check runs *after* the human has been asked and after the lease has been
/// granted. Two things therefore have to hold and are asserted separately below: the sheet never
/// shows an unnormalized path, and a request that cannot possibly succeed leaves no authority
/// behind.
#[test]
fn a_traversing_filename_is_refused() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let escape = std::path::Path::new("/tmp/kagisecure-escape.env");
    let _ = std::fs::remove_file(escape);

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-inject");
        client
            .call(&write_env_file(&fx, &dir, TRAVERSAL_FILENAME, true, 900))
            .expect("call")
    });

    assert_eq!(
        error_code(&reply).as_deref(),
        Some("INVALID_PATH"),
        "a filename with separators in it is not a filename: {reply:?}"
    );
    assert!(
        !escape.exists(),
        "the traversal reached {escape:?}, outside the approved directory"
    );
}

/// A-03, continued: the sheet must show the path that would actually be written.
///
/// `canonical.join("../../../tmp/x")` renders as `/approved/dir/../../../tmp/x`. A human reading
/// that sheet sees their project directory at the front of the string and a `.env`-ish name at
/// the end. The path is never normalized before being shown, so the sheet's own text disagrees
/// with the `directory` field printed next to it.
#[test]
// PREDICTED FAILURE (A-03), from source reading only: `service.rs` builds `target_path` as
// `canonical.join(filename).display()`, which keeps the `..` components verbatim. Never
// executed.
fn the_sheet_never_shows_an_unnormalized_target_path() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-inject");
        client
            .call(&write_env_file(&fx, &dir, TRAVERSAL_FILENAME, true, 900))
            .expect("call")
    });

    for request in &seen {
        let Some(shown) = request.target_path.as_deref() else {
            continue;
        };
        assert!(
            !shown.contains("/../"),
            "a human was shown {shown:?}, which is not where the bytes would land"
        );
    }
}

/// A-03, continued: nothing that cannot succeed may leave authority behind.
///
/// The lease is granted before the filename is validated, so a request guaranteed to fail still
/// mints one — and that lease, being filename-blind (see `adversarial_lease.rs`), then covers
/// every legitimate filename in the directory without a second prompt.
#[test]
// PREDICTED FAILURE (A-03), from source reading only: the lease is granted before
// `envfile::write` validates the filename, and nothing revokes it when the write fails.
// Never executed.
fn a_request_that_cannot_succeed_mints_no_lease() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-inject");
        client
            .call(&write_env_file(&fx, &dir, TRAVERSAL_FILENAME, true, 900))
            .expect("call")
    });
    assert_eq!(error_code(&reply).as_deref(), Some("INVALID_PATH"));

    assert!(
        fx.agent.leases().is_empty(),
        "a failed write left {} lease(s) behind: {:?}",
        fx.agent.leases().len(),
        fx.agent.leases()
    );
}

/// A-04: an absolute filename is refused, and no `/etc/...` path is ever put in front of a human.
///
/// `Path::join` with an absolute argument discards the base entirely, so
/// `canonical.join("/etc/kagisecure.env")` is `/etc/kagisecure.env`. The write is refused — the
/// filename has separators — but the refusal must come before, not after, a sheet that reads
/// "write /etc/kagisecure.env" while its `directory` field says something else.
#[test]
fn an_absolute_filename_is_refused() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (reply, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-inject");
        client
            .call(&write_env_file(&fx, &dir, ABSOLUTE_FILENAME, true, 900))
            .expect("call")
    });

    assert_eq!(
        error_code(&reply).as_deref(),
        Some("INVALID_PATH"),
        "an absolute path is not a filename: {reply:?}"
    );
    assert!(
        !std::path::Path::new(ABSOLUTE_FILENAME).exists(),
        "nothing may have been written to {ABSOLUTE_FILENAME}"
    );
}

/// A-04, continued: the sheet must not describe a write outside the directory it names.
#[test]
// PREDICTED FAILURE (A-04), from source reading only: `Path::join` with an absolute
// argument discards the base, so `target_path` escapes the `directory` on the same sheet.
// Never executed.
fn the_sheet_target_path_always_lies_inside_the_sheet_directory() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-inject");
        let _ = client.call(&write_env_file(&fx, &dir, ABSOLUTE_FILENAME, true, 900));
        let _ = client.call(&write_env_file(&fx, &dir, TRAVERSAL_FILENAME, true, 900));
    });

    for request in &seen {
        let (Some(shown_dir), Some(shown_target)) =
            (request.directory.as_deref(), request.target_path.as_deref())
        else {
            continue;
        };
        assert!(
            shown_target.starts_with(shown_dir),
            "the sheet says directory {shown_dir:?} but target {shown_target:?}"
        );
    }
}

/// A-05 (TOCTOU): between the approval and the write, the approved directory becomes a symlink.
///
/// `envfile::write` deliberately does not re-canonicalize — resolving twice would let the sheet
/// and the write disagree. The consequence is that whoever can replace the directory between
/// the two can redirect the write. On a single-user machine that is the same user, so this is a
/// hardening question rather than a privilege boundary; what must hold is the weaker but still
/// real property that the bytes land under the canonical directory the human approved, or not
/// at all.
#[test]
fn a_directory_swapped_for_a_symlink_mid_approval_does_not_redirect_the_write() {
    let fx = fixture();
    let approved = fx.dir.path().join("approved");
    let elsewhere = fx.dir.path().join("elsewhere");
    std::fs::create_dir_all(&approved).expect("approved dir");
    std::fs::create_dir_all(&elsewhere).expect("elsewhere dir");
    let approved_canonical = approved.canonicalize().expect("canonical");
    let elsewhere_canonical = elsewhere.canonicalize().expect("canonical");
    let dir = approved_canonical.display().to_string();

    let swapped = std::sync::atomic::AtomicBool::new(false);
    let (reply, _) = with_ui_answering(
        &fx.agent,
        |_| {
            // The sheet is up. Swap the directory for a symlink to somewhere else, *then* allow.
            if !swapped.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let _ = std::fs::remove_dir_all(&approved);
                #[cfg(unix)]
                let _ = std::os::unix::fs::symlink(&elsewhere_canonical, &approved);
            }
            Some(allow_session(900, 10))
        },
        || {
            let mut client = fx.client("adversarial-inject");
            client
                .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
                .expect("call")
        },
    );

    let redirected = elsewhere_canonical.join(REAL_DOTENV);
    match &reply {
        Response::Error { .. } => {
            assert!(
                !redirected.exists(),
                "a refused write still landed at {redirected:?}"
            );
        }
        Response::WroteEnvFile { path, .. } => {
            let written = std::path::Path::new(path);
            let parent = written
                .parent()
                .and_then(|p| p.canonicalize().ok())
                .unwrap_or_default();
            assert_eq!(
                parent, approved_canonical,
                "the write landed under {parent:?}, not the approved {approved_canonical:?}"
            );
        }
        other => panic!("unexpected reply {other:?}"),
    }
}

/// A-05 (TOCTOU), `run_with_env`'s equivalent: the same symlink swap, but against the directory a
/// command is spawned into rather than the directory a file is written into.
///
/// `Service::run_with_env` canonicalizes `cwd`, shows the sheet, and — before this fix — spawned
/// the child with `cwd: Some(&canonical)` with no re-check. `std::process::Command::current_dir`
/// resolves that path at spawn time, following a symlink exactly as the write path does, so
/// swapping the approved directory for a symlink while the sheet is up redirects the command to
/// wherever the symlink points, with no further prompt. This runs a command that leaves a marker
/// file in its own working directory and asserts the marker never lands under the swapped-to
/// directory: either the run is refused, or it truly landed under the approved directory.
#[test]
#[cfg(unix)]
fn a_directory_swapped_for_a_symlink_mid_approval_does_not_redirect_run_with_env() {
    let fx = fixture();
    let approved = fx.dir.path().join("approved-run");
    let elsewhere = fx.dir.path().join("elsewhere-run");
    std::fs::create_dir_all(&approved).expect("approved dir");
    std::fs::create_dir_all(&elsewhere).expect("elsewhere dir");
    let approved_canonical = approved.canonicalize().expect("canonical");
    let elsewhere_canonical = elsewhere.canonicalize().expect("canonical");
    let dir = approved_canonical.display().to_string();

    let swapped = std::sync::atomic::AtomicBool::new(false);
    let (reply, _) = with_ui_answering(
        &fx.agent,
        |_| {
            // The sheet is up. Swap the directory for a symlink to somewhere else, *then* allow.
            if !swapped.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let _ = std::fs::remove_dir_all(&approved);
                let _ = std::os::unix::fs::symlink(&elsewhere_canonical, &approved);
            }
            Some(allow_session(900, 10))
        },
        || {
            let mut client = fx.client("adversarial-inject");
            client
                .call(&Request::RunWithEnv {
                    environment_id: fx.env_id.parse().expect("env id"),
                    command: "/usr/bin/touch".to_owned(),
                    args: vec!["marker".to_owned()],
                    cwd: dir.clone(),
                    variables: None,
                    timeout_seconds: 5,
                    output: OutputMode::Scrubbed,
                })
                .expect("call")
        },
    );

    let redirected = elsewhere_canonical.join("marker");
    assert!(
        !redirected.exists(),
        "the command ran in {redirected:?}, outside the approved directory"
    );
    assert!(
        matches!(reply, Response::Error { .. }),
        "expected the run to be refused once the approved directory was swapped for a symlink \
         mid-approval, got {reply:?}"
    );
}

/// A-25: with `agent_visible` off everywhere, every tool is a dead end and leaks no names.
///
/// The ids are the *real* ids of the *real* hidden objects, handed to the test by the fixture —
/// which is the strongest form of the question, because a caller that somehow learned an id
/// from a shoulder-surf or an old log must still get nothing.
#[test]
fn nothing_is_reachable_when_the_user_has_made_nothing_visible() {
    let fx = invisible_fixture();
    let dir = fx.canonical_project().display().to_string();
    let mut client = fx.client("adversarial-inject");

    let mut replies: Vec<Response> = vec![
        client.call(&Request::ListVaults).expect("call"),
        client
            .call(&Request::ListItems {
                vault_id: None,
                query: None,
                category: None,
                limit: 50,
                cursor: None,
            })
            .expect("call"),
        client
            .call(&Request::ListEnvironments { vault_id: None })
            .expect("call"),
        client
            .call(&Request::DescribeItem {
                item_id: fx.item_id.parse().expect("item id"),
            })
            .expect("call"),
    ];

    // The approving tools, with a UI standing by to say yes. Nothing should reach it.
    let (approving, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let mut client = fx.client("adversarial-inject");
        vec![
            client
                .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
                .expect("call"),
            client
                .call(&Request::RunWithEnv {
                    environment_id: fx.env_id.parse().expect("env id"),
                    command: "/bin/echo".to_owned(),
                    args: vec!["hi".to_owned()],
                    cwd: dir.clone(),
                    variables: None,
                    timeout_seconds: 5,
                    output: OutputMode::Scrubbed,
                })
                .expect("call"),
        ]
    });
    replies.extend(approving);

    // The structural listings answer, but with nothing in them.
    for reply in &replies {
        match reply {
            Response::Vaults { vaults } => assert!(vaults.is_empty(), "{vaults:?}"),
            Response::Items { items, .. } => assert!(items.is_empty(), "{items:?}"),
            Response::Environments { environments } => {
                assert!(environments.is_empty(), "{environments:?}");
            }
            Response::Error { code, .. } => assert_eq!(
                code.as_str(),
                "NOT_FOUND",
                "a hidden object must be indistinguishable from a missing one: {reply:?}"
            ),
            other => panic!("a hidden vault served {other:?}"),
        }
    }

    assert!(
        seen.is_empty(),
        "nothing hidden may reach a human for approval: {seen:?}"
    );

    // And no name of anything hidden appears in a single byte of any reply.
    let rendered = format!("{replies:?}");
    for leaked in [
        "Acme staging",
        "acme / staging",
        "Personal",
        "token",
        MARKER,
    ] {
        assert!(
            !rendered.contains(leaked),
            "{leaked:?} leaked through a reply: {rendered}"
        );
    }
}

/// A-24 (M-8): "exists but hidden" and "does not exist" must be one answer, byte for byte.
///
/// Otherwise `describe_item` is an oracle: a caller walks ids and learns which ones name
/// something real, which is exactly the enumeration `agent_visible` exists to prevent.
#[test]
// PREDICTED FAILURE (A-24), from source reading only: `Service::describe_item` returns
// `NOT_AGENT_VISIBLE` with its own message for a hidden item and `NOT_FOUND` for an absent
// one, which is the oracle M-8 forbids. Never executed.
fn a_hidden_item_is_indistinguishable_from_one_that_does_not_exist() {
    let fx = invisible_fixture();
    let mut client = fx.client("adversarial-inject");

    let hidden = client
        .call(&Request::DescribeItem {
            item_id: fx.item_id.parse().expect("item id"),
        })
        .expect("call");
    let absent = client
        .call(&Request::DescribeItem {
            item_id: "00000000-0000-4000-8000-000000000000"
                .parse()
                .expect("uuid"),
        })
        .expect("call");

    assert_eq!(
        error_code(&hidden),
        error_code(&absent),
        "the code distinguishes a real item from an imaginary one"
    );
    assert_eq!(
        error_message(&hidden),
        error_message(&absent),
        "the message distinguishes a real item from an imaginary one"
    );
}

/// The same oracle question for `write_env_file`, where the environment is the thing being
/// probed. Here the two answers already are the same, which is the behaviour to keep.
#[test]
fn a_hidden_environment_is_indistinguishable_from_one_that_does_not_exist() {
    let fx = invisible_fixture();
    let dir = fx.canonical_project().display().to_string();
    let mut client = fx.client("adversarial-inject");

    let hidden = client
        .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
        .expect("call");
    let absent = client
        .call(&Request::WriteEnvFile {
            environment_id: "00000000-0000-4000-8000-000000000000"
                .parse()
                .expect("uuid"),
            directory: dir.clone(),
            filename: REAL_DOTENV.to_owned(),
            variables: None,
            overwrite: true,
            ttl_seconds: 900,
        })
        .expect("call");

    assert_eq!(error_code(&hidden), error_code(&absent));
    assert_eq!(error_message(&hidden), error_message(&absent));
    assert_eq!(error_code(&hidden).as_deref(), Some("NOT_FOUND"));
}

/// A-26: hostile pagination arguments produce a bounded answer and no panic.
///
/// `list_items` parses the cursor with `unwrap_or(0)` and bounds the page with `saturating_*`,
/// so the contract is: anything the caller sends is either a valid offset or the beginning, and
/// the reply is never larger than the vault.
#[test]
fn hostile_pagination_arguments_are_bounded_and_never_panic() {
    let fx = fixture();
    let mut client = fx.client("adversarial-inject");

    let hostile_cursors = [
        Some("-1".to_owned()),
        Some("99999999999999999999".to_owned()),
        Some(String::new()),
        Some("0x10".to_owned()),
        Some("１".to_owned()),
        Some("A".repeat(4096)),
        Some(format!("{}", usize::MAX)),
        None,
    ];
    let hostile_limits = [0_usize, 1, usize::MAX, usize::MAX - 1];

    for cursor in &hostile_cursors {
        for limit in hostile_limits {
            let started = Instant::now();
            let reply = client
                .call(&Request::ListItems {
                    vault_id: None,
                    query: Some("\u{0}\u{1b}[2K'\"--".to_owned()),
                    category: Some("definitely-not-a-category".to_owned()),
                    limit,
                    cursor: cursor.clone(),
                })
                .expect("the agent stayed up");
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "cursor {cursor:?} limit {limit} took {:?}",
                started.elapsed()
            );
            match &reply {
                Response::Items { items, .. } => assert!(
                    items.len() <= 1,
                    "the fixture holds one item; got {}",
                    items.len()
                ),
                Response::Error { .. } => {}
                other => panic!("unexpected reply {other:?}"),
            }
            assert!(
                !format!("{reply:?}").contains(MARKER),
                "a listing carried a value"
            );
        }
    }

    // Still serving afterwards.
    let alive = client.call(&Request::ListVaults).expect("call");
    assert!(error_code(&alive).is_none(), "reply was {alive:?}");
}

/// A filename that is a plain name but not a `.env`-ish one is still just a filename.
///
/// `validate_filename` allows alphanumerics, `.`, `_` and `-`, which means a caller can write
/// `Makefile` or `id_rsa` into the approved directory. That is within the approval's stated
/// scope — the sheet shows the exact target — so what this asserts is that the sheet really did
/// show it, rather than the `.env` the human expected.
#[test]
fn the_sheet_names_the_exact_file_even_when_it_is_not_a_dotenv() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-inject");
        client
            .call(&write_env_file(&fx, &dir, "id_rsa", true, 900))
            .expect("call")
    });
    assert!(error_code(&reply).is_none(), "reply was {reply:?}");
    assert_eq!(seen.len(), 1);
    // Compared by path component, not by a `/`-joined string literal, so this holds regardless
    // of the platform's separator (see the identical note in `tests/sidecar.rs`).
    assert!(
        seen[0]
            .target_path
            .as_deref()
            .is_some_and(|p| Path::new(p).ends_with("id_rsa")),
        "the sheet must name the real target: {:?}",
        seen[0].target_path
    );
}

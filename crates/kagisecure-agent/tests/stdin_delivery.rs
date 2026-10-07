//! `run_with_env` with `delivery: "stdin"` (ADR-0047), over the real socket.
//!
//! The values go to the command's standard input as `NAME\0VALUE\0` pairs and nowhere else; every
//! such run is its own approval, granted for that one run whatever the UI answers; a variable with
//! no value is named before any sheet; and the audit entry says which command the values went to.
//!
//! Unix-only: the commands run here are unix binaries.
#![cfg(unix)]

mod common;

use common::{Fixture, MARKER, allow_session, error_code, error_message, fixture, with_ui};
use kagisecure_agent::approval::{ApprovalKind, Decision};
use kagisecure_core::proto::Outcome;
use kagisecure_ipc::protocol::{Delivery, OutputMode, Request, Response, VariableRequest};

fn run(fx: &Fixture, script: &str, variables: Option<&[&str]>, delivery: Delivery) -> Request {
    Request::RunWithEnv {
        environment_id: fx.env_id.parse().expect("env id"),
        command: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script.to_owned()],
        cwd: fx.canonical_project().display().to_string(),
        variables: variables.map(|names| names.iter().map(|n| (*n).to_owned()).collect()),
        timeout_seconds: 30,
        output: OutputMode::Scrubbed,
        delivery,
    }
}

fn exit_code(reply: &Response) -> Option<i32> {
    match reply {
        Response::Ran { exit_code, .. } => *exit_code,
        other => panic!("expected a run, got {other:?}"),
    }
}

#[test]
fn the_value_reaches_standard_input_only_and_the_sheet_says_so() {
    let fx = fixture();
    let project = fx.canonical_project();
    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("stdin")
            .call(&run(
                &fx,
                "cat > stdin.bin; env > environment.txt; echo read",
                None,
                Delivery::Stdin,
            ))
            .expect("call")
    });

    assert_eq!(exit_code(&reply), Some(0), "{reply:?}");
    assert_eq!(
        std::fs::read(project.join("stdin.bin")).expect("stdin written"),
        format!("TOKEN\0{MARKER}\0").as_bytes()
    );
    let environment = std::fs::read_to_string(project.join("environment.txt")).expect("env");
    assert!(
        !environment.contains(MARKER),
        "the value reached the environment"
    );
    assert!(
        !environment.lines().any(|line| line.starts_with("TOKEN=")),
        "the variable reached the environment"
    );

    assert_eq!(seen.len(), 1);
    let sheet = &seen[0];
    assert_eq!(sheet.kind, ApprovalKind::RunWithEnv);
    assert!(
        sheet.stdin_delivery,
        "the sheet must say where the values go"
    );
    assert_eq!(sheet.requested_uses, 1);
    assert_eq!(sheet.variables, ["TOKEN"]);
    assert!(!format!("{sheet:?}").contains(MARKER));
    assert!(!format!("{reply:?}").contains(MARKER));

    // Allowed "for the session", granted for this run alone: nothing is left to reuse.
    assert!(
        fx.agent.leases().iter().all(|l| l.uses_remaining == 0),
        "{:?}",
        fx.agent.leases()
    );
}

#[test]
fn every_stdin_run_asks_again_and_no_environment_lease_covers_one() {
    let fx = fixture();
    let (replies, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("stdin");
        // A session lease for the same command, directory and variables, delivered the old way.
        let first = client
            .call(&run(&fx, "cat > /dev/null", None, Delivery::Environment))
            .expect("call");
        let second = client
            .call(&run(&fx, "cat > /dev/null", None, Delivery::Stdin))
            .expect("call");
        let third = client
            .call(&run(&fx, "cat > /dev/null", None, Delivery::Stdin))
            .expect("call");
        [first, second, third]
    });
    for reply in &replies {
        assert_eq!(exit_code(reply), Some(0), "{reply:?}");
    }
    assert_eq!(
        seen.len(),
        3,
        "neither the environment lease nor the first stdin approval may cover a stdin run"
    );
    assert!(!seen[0].stdin_delivery);
    assert!(seen[1].stdin_delivery && seen[2].stdin_delivery);
}

#[test]
fn a_denied_stdin_run_starts_nothing() {
    let fx = fixture();
    let project = fx.canonical_project();
    let (reply, seen) = with_ui(&fx.agent, Decision::Deny, || {
        fx.client("stdin")
            .call(&run(&fx, "cat > stdin.bin", None, Delivery::Stdin))
            .expect("call")
    });
    assert_eq!(seen.len(), 1);
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("USER_DENIED"),
        "{reply:?}"
    );
    assert!(!project.join("stdin.bin").exists(), "the command ran");
}

#[test]
fn variables_without_a_value_are_named_before_any_sheet() {
    let fx = fixture();
    // An agent declares a variable the user has not filled in yet.
    let (declared, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("stdin")
            .call(&Request::AddVariables {
                environment_id: fx.env_id.parse().expect("env id"),
                variables: vec![VariableRequest {
                    name: "cloudflare_turn_api_token".to_owned(),
                    bind_to: None,
                    hint: Some("TURN API token".to_owned()),
                }],
            })
            .expect("call")
    });
    assert!(error_code(&declared).is_none(), "{declared:?}");

    let project = fx.canonical_project();
    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("stdin")
            .call(&run(
                &fx,
                "cat > stdin.bin",
                Some(&["TOKEN", "cloudflare_turn_api_token"]),
                Delivery::Stdin,
            ))
            .expect("call")
    });
    assert!(
        seen.is_empty(),
        "no sheet for a run that cannot succeed: {seen:?}"
    );
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("NOT_POPULATED"),
        "{reply:?}"
    );
    let message = error_message(&reply).expect("message");
    assert!(message.contains("cloudflare_turn_api_token"), "{message}");
    assert!(
        !message.contains("TOKEN,"),
        "only the missing one is named: {message}"
    );
    assert!(!message.contains(MARKER));
    assert!(!project.join("stdin.bin").exists(), "the command ran");
}

#[test]
fn the_audit_entry_names_the_command_and_never_the_value() {
    let fx = fixture();
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("stdin")
            .call(&run(&fx, "cat > /dev/null", None, Delivery::Stdin))
            .expect("call")
    });
    assert_eq!(exit_code(&reply), Some(0), "{reply:?}");

    let entries = fx
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let allowed = entries
        .iter()
        .rev()
        .find(|e| e.tool == "run_with_env" && e.outcome == Outcome::Allowed)
        .expect("an Allowed entry");
    let detail = allowed.detail.as_deref().expect("detail");
    assert_eq!(detail, r#"STDIN ["/bin/sh", "-c", "cat > /dev/null"]"#);
    assert_eq!(allowed.variables, ["TOKEN"]);
    for entry in &entries {
        assert!(!format!("{entry:?}").contains(MARKER), "{entry:?}");
    }
}

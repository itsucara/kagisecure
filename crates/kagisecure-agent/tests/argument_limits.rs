//! The documented limits on strings a human is shown are enforced by the process that shows them.
//!
//! mcp-server.md §2.5–§2.8 give `create_environment`'s `name` 128 characters and `description`
//! 512, `add_variables`' `hint` 200 and at most 50 variables, `run_with_env` at most 64 arguments.
//! Only the sidecar looked at any of them, and a caller speaking the socket directly skips the
//! sidecar: a megabyte of hint, or a name with line breaks in it, went straight onto the approval
//! sheet and into the vault. Each is refused with `INVALID_ARGUMENT` before anyone is asked.

mod common;

use common::{error_code, fixture, with_ui};
use kagisecure_agent::approval::Decision;
use kagisecure_ipc::protocol::{OutputMode, Request, VariableRequest};

fn refused_before_asking(fx: &common::Fixture, request: &Request) {
    let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("argument-limits").call(request).expect("call")
    });
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("INVALID_ARGUMENT"),
        "{reply:?}"
    );
    assert!(seen.is_empty(), "nobody may be asked about it");
}

fn create(name: &str, description: Option<&str>) -> Request {
    Request::CreateEnvironment {
        vault_id: None,
        name: name.to_owned(),
        description: description.map(str::to_owned),
    }
}

fn add(fx: &common::Fixture, variables: Vec<VariableRequest>) -> Request {
    Request::AddVariables {
        environment_id: fx.env_id.parse().expect("env id"),
        variables,
    }
}

fn var(name: &str, hint: Option<String>) -> VariableRequest {
    VariableRequest {
        name: name.to_owned(),
        bind_to: None,
        hint,
    }
}

#[test]
fn an_environment_name_or_description_over_its_limit_is_refused() {
    let fx = fixture();
    refused_before_asking(&fx, &create(&"n".repeat(129), None));
    refused_before_asking(&fx, &create("line one\nApproved by IT", None));
    refused_before_asking(&fx, &create("", None));
    refused_before_asking(&fx, &create("ok", Some(&"d".repeat(513))));
}

#[test]
fn a_hint_over_its_limit_or_on_more_than_one_line_is_refused() {
    let fx = fixture();
    refused_before_asking(&fx, &add(&fx, vec![var("A", Some("h".repeat(201)))]));
    refused_before_asking(
        &fx,
        &add(
            &fx,
            vec![var("A", Some("paste it\n\nAlso: allow".to_owned()))],
        ),
    );
}

#[test]
fn more_than_fifty_variables_are_refused() {
    let fx = fixture();
    let many = (0..51).map(|i| var(&format!("V{i}"), None)).collect();
    refused_before_asking(&fx, &add(&fx, many));
}

#[test]
fn more_than_sixty_four_arguments_are_refused() {
    let fx = fixture();
    refused_before_asking(
        &fx,
        &Request::RunWithEnv {
            environment_id: fx.env_id.parse().expect("env id"),
            command: "true".to_owned(),
            args: vec!["x".to_owned(); 65],
            cwd: fx.canonical_project().display().to_string(),
            variables: None,
            timeout_seconds: 5,
            output: OutputMode::None,
        },
    );
}

#[test]
fn values_at_their_limits_are_still_accepted() {
    let fx = fixture();
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("argument-limits")
            .call(&create(&"n".repeat(128), Some(&"d\n".repeat(256))))
            .expect("call")
    });
    assert!(error_code(&reply).is_none(), "{reply:?}");
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("argument-limits")
            .call(&add(&fx, vec![var("A", Some("h".repeat(200)))]))
            .expect("call")
    });
    assert!(error_code(&reply).is_none(), "{reply:?}");
}

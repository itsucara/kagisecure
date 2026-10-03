//! A variable name is a name, not a line of a `.env` file.
//!
//! `docs/mcp-server.md` §2.6 documents the pattern `^[A-Za-z_][A-Za-z0-9_]*$`. Nothing enforced
//! it: `add_variables` stored whatever string an agent sent, and the `.env` writer printed
//! `NAME=value` with the name verbatim — so a name carrying `=` or a newline wrote lines of the
//! agent's choosing into the file (`PATH=/tmp/evil`, `NODE_OPTIONS=--require …`), and handed a
//! child process an environment entry it never asked for. These tests drive the real agent over
//! its socket, as a hostile caller would, bypassing the sidecar.

mod common;

use common::{REAL_DOTENV, error_code, fixture, with_ui, write_env_file};
use kagisecure_agent::approval::Decision;
use kagisecure_core::model::{EnvVar, Secret, VarSource};
use kagisecure_ipc::protocol::{Request, Response, VariableRequest};

fn add(fx: &common::Fixture, name: &str) -> Response {
    let request = Request::AddVariables {
        environment_id: fx.env_id.parse().expect("env id"),
        variables: vec![VariableRequest {
            name: name.to_owned(),
            bind_to: None,
            hint: None,
        }],
    };
    let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("variable-names").call(&request).expect("call")
    });
    if error_code(&reply).is_some() {
        assert!(
            seen.is_empty(),
            "an invalid request must be refused before a human is asked about it"
        );
    }
    reply
}

fn variable_names(fx: &common::Fixture) -> Vec<String> {
    fx.handle
        .with(|v| {
            v.find_environment(&fx.env_id)
                .expect("env")
                .vars
                .iter()
                .map(|var| var.name.clone())
                .collect()
        })
        .expect("unlocked")
}

#[test]
fn a_name_that_is_not_an_identifier_is_refused_with_invalid_argument() {
    let fx = fixture();
    for bad in [
        "A=B",
        "OK\nPATH=/tmp/evil",
        "OK\rX",
        "",
        "1LEADING_DIGIT",
        "SPACE IN",
        "DASH-ED",
        "NUL\0",
        "ÜNICODE",
    ] {
        let reply = add(&fx, bad);
        assert_eq!(
            error_code(&reply).as_deref(),
            Some("INVALID_ARGUMENT"),
            "{bad:?} must be refused: {reply:?}"
        );
    }
    assert_eq!(variable_names(&fx), ["TOKEN"], "nothing was added");
}

/// `add_variables` declares variables; it does not replace them. `Environment::set_var` replaces
/// by name, so a request naming `TOKEN` — already bound by the user to a real credential — used to
/// swap that binding for a pending placeholder, or for a binding to a different field of the
/// agent's choosing, under a sheet that read like an addition. There is no tool to remove a
/// variable either: changing an existing one is the user's, in kagisecure.
#[test]
fn an_existing_variable_is_not_replaced() {
    let fx = fixture();
    let before = fx
        .handle
        .with(|v| {
            format!(
                "{:?}",
                v.find_environment(&fx.env_id)
                    .expect("env")
                    .var("TOKEN")
                    .expect("TOKEN")
                    .source
                    .kind()
            )
        })
        .expect("unlocked");

    let reply = add(&fx, "TOKEN");
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("INVALID_ARGUMENT"),
        "{reply:?}"
    );
    let after = fx
        .handle
        .with(|v| {
            format!(
                "{:?}",
                v.find_environment(&fx.env_id)
                    .expect("env")
                    .var("TOKEN")
                    .expect("TOKEN")
                    .source
                    .kind()
            )
        })
        .expect("unlocked");
    assert_eq!(before, after, "the user's binding is untouched");
}

#[test]
fn a_well_formed_name_is_still_accepted() {
    let fx = fixture();
    for good in ["_", "A", "_private", "STRIPE_SECRET_KEY", "lower_case9"] {
        let reply = add(&fx, good);
        assert!(error_code(&reply).is_none(), "{good:?}: {reply:?}");
    }
}

#[test]
fn a_malformed_name_already_in_the_vault_is_never_rendered_into_a_file() {
    // Defence in depth: a vault written by an older build, or edited by something that did not
    // validate, can already hold such a name. The writer refuses it rather than printing it.
    let fx = fixture();
    fx.handle
        .transact(std::time::Duration::from_secs(5), |tx| {
            let env = tx.find_environment_mut(&fx.env_id)?;
            env.vars.push(EnvVar {
                name: "X\nINJECTED".to_owned(),
                source: VarSource::Literal(Secret::from_string("1".to_owned())),
            });
            Ok(())
        })
        .expect("unlocked")
        .expect("commit");

    let dir = fx.canonical_project();
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("variable-names")
            .call(&write_env_file(
                &fx,
                &dir.display().to_string(),
                REAL_DOTENV,
                false,
                900,
            ))
            .expect("call")
    });
    assert!(
        error_code(&reply).is_some(),
        "the write must be refused: {reply:?}"
    );
    let text = std::fs::read_to_string(dir.join(REAL_DOTENV)).unwrap_or_default();
    assert!(
        !text.lines().any(|l| l.starts_with("INJECTED")),
        "no injected line may reach the file: {text:?}"
    );
}

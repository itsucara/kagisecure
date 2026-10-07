//! `kagisecure run` — the one place a secret value legitimately reaches a process the user asked
//! for.

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::{Delivery, EnvInjection, RunRequest, run_with_env};
use kagisecure_core::model::{FieldValue, Secret};
use kagisecure_core::proto::{Outcome, VarName};
use kagisecure_core::{Error, Vault};

use crate::cli::RunArgs;
use crate::commands::{
    AuditUnavailable, cli_draft, failure_detail, record_audit_best_effort, transact_patiently,
};
use crate::prompt::SecretInput;

/// Split `NAME=item/field` into its three parts.
///
/// The item reference may itself contain `/`, so the *last* `/` separates item from field.
///
/// # Errors
///
/// If the specification is not of the expected shape.
pub fn parse_env_spec(spec: &str) -> Result<(&str, &str, &str)> {
    let Some((name, reference)) = spec.split_once('=') else {
        bail!("--env expects NAME=ITEM/FIELD, got {spec:?}");
    };
    if name.is_empty() {
        bail!("--env needs a variable name before the '=' in {spec:?}");
    }
    if !VarName::is_valid(name) {
        bail!(
            "--env variable name {name:?} must match {} (letters, digits and underscores, not \
             starting with a digit)",
            VarName::PATTERN
        );
    }
    let Some((item, field)) = reference.rsplit_once('/') else {
        bail!("--env expects NAME=ITEM/FIELD; {reference:?} has no '/' separating item from field");
    };
    if item.is_empty() || field.is_empty() {
        bail!("--env expects NAME=ITEM/FIELD, got {spec:?}");
    }
    Ok((name, item, field))
}

/// Run a child process with the requested variables injected.
///
/// Audit-first (design doc "transactions-and-audit", part B, step 9): the `Allowed` entry naming
/// every variable this run is about to inject is appended and durably saved *before* the child is
/// spawned. If that transaction cannot be made durable — the vault is busy past the usual wait,
/// diverged, replaced, or a save fails outright — this refuses with exit 9
/// ([`crate::cli::EXIT_AUDIT_UNAVAILABLE`]) and starts nothing.
///
/// The child is spawned only after the lock is released, so nothing about running it — however
/// long it takes — can hold up another writer. If it cannot be started at all, or is killed by a
/// signal rather than exiting, that does not undo the permission already granted; it is recorded
/// as a best-effort `Failed` follow-up instead. An ordinary nonzero exit is just the command doing
/// what it does and is not itself a failure of this audited action, so it gets no follow-up.
///
/// Returns the exit status to hand back to the shell.
///
/// # Errors
///
/// If the vault cannot be opened, a reference does not resolve, permission cannot be made durable
/// (exit 9), or the child cannot be started.
pub fn run(path: &Path, args: &RunArgs, input: &mut SecretInput) -> Result<u8> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let mut vault = Vault::open_with_password(path, password.as_bytes())?;
    drop(password);

    // Parsed up front: a malformed `--env` is a usage mistake, independent of vault state, and
    // `parse_env_spec`'s own `anyhow::Result` cannot be returned from the transaction's closure
    // below, which — like every `Vault::transact` closure — answers in `kagisecure_core::Result`.
    let specs: Vec<(&str, &str, &str)> = args
        .env
        .iter()
        .map(|spec| parse_env_spec(spec))
        .collect::<Result<_>>()?;

    // Step 1 — audit first. Every field is resolved fresh inside the transaction, so an item
    // renamed or a field removed since this process opened the vault is reflected in what the
    // audit entry — and, in step 2, the child's environment — actually contain.
    let resolved = transact_patiently(&mut vault, |tx| {
        let mut injections: Vec<EnvInjection> = Vec::with_capacity(specs.len());
        let mut names: Vec<String> = Vec::with_capacity(specs.len());
        for &(name, item_ref, field_ref) in &specs {
            let item = tx.find_item(item_ref)?;
            let field = item.field(field_ref).ok_or_else(|| Error::FieldNotFound {
                item: item_ref.to_owned(),
                field: field_ref.to_owned(),
            })?;
            let value = match &field.value {
                FieldValue::Secret(s) => Secret::new(s.expose().to_vec()),
                // A public field is a perfectly reasonable thing to inject (a username, a host).
                // It still goes through the masking path, which costs nothing and cannot hurt.
                FieldValue::Public(v) => Secret::from_string(v.clone()),
            };
            names.push(name.to_owned());
            injections.push(EnvInjection {
                name: VarName::new(name)?,
                value,
            });
        }
        tx.append_audit(AuditDraft {
            variables: names.clone(),
            ..cli_draft("run")
        });
        let allowed_seq = tx
            .audit_entries()
            .last()
            .expect("append_audit just added one")
            .seq;
        Ok((injections, names, allowed_seq))
    });
    let (injections, names, allowed_seq) = match resolved {
        Ok(v) => v,
        // A reference that never resolved (`ItemNotFound`, `FieldNotFound`, …) is a usage
        // mistake, not a durability failure: the closure returned before ever calling
        // `append_audit`, so nothing was left half-committed. It keeps its ordinary exit code
        // (`crate::cli::EXIT_NOT_FOUND`) instead of becoming `AuditUnavailable`.
        Err(e) if crate::commands::is_audit_gate_failure(&e) => {
            return Err(AuditUnavailable(e).into());
        }
        Err(e) => return Err(e.into()),
    };

    let (program, rest) = args
        .command
        .split_first()
        .expect("clap requires at least one word after --");

    let request = RunRequest {
        program,
        args: rest,
        env: &injections,
        delivery: Delivery::Environment,
        cwd: args.cwd.as_deref(),
        mask_output: !args.no_masking,
        max_output: kagisecure_core::inject::DEFAULT_MAX_OUTPUT,
        // No deadline: this is the user's own terminal and their own command. `run_with_env`
        // over MCP is the one that gets a timeout, because nobody is watching it.
        timeout: None,
        // The terminal's own process group, so Ctrl-C and a closed window reach the child as they
        // would a command typed at the prompt — see `RunRequest::new_process_group`.
        new_process_group: false,
    };

    // Step 2 — act. The lock is already released.
    let outcome = match run_with_env(&request) {
        Ok(outcome) => outcome,
        Err(e) => {
            drop(injections);
            record_audit_best_effort(
                &mut vault,
                AuditDraft {
                    variables: names,
                    outcome: Outcome::Failed,
                    detail: Some(failure_detail(spawn_failure_code(&e), allowed_seq)),
                    ..cli_draft("run")
                },
            );
            return Err(e.into());
        }
    };
    drop(injections);

    std::io::stdout().write_all(&outcome.stdout)?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(&outcome.stderr)?;
    std::io::stderr().flush()?;

    if outcome.stdout_truncated || outcome.stderr_truncated {
        eprintln!("kagisecure: the child's output was truncated at 64 KiB per stream.");
    }

    // A signal death, unlike a plain nonzero exit, is the "abnormal end" the audit-first design
    // means: the child never got to finish and report its own status.
    if outcome.exit_code.is_none() {
        record_audit_best_effort(
            &mut vault,
            AuditDraft {
                variables: names,
                outcome: Outcome::Failed,
                detail: Some(failure_detail("KILLED_BY_SIGNAL", allowed_seq)),
                ..cli_draft("run")
            },
        );
    }
    drop(vault);

    // 128 + SIGKILL is the shell convention for "died on a signal"; we do not know which signal
    // here, so report a generic non-zero status rather than pretending it succeeded.
    Ok(u8::try_from(outcome.exit_code.unwrap_or(137)).unwrap_or(1))
}

/// A short machine-readable code for why the child could not be started at all, for the
/// best-effort `Failed` follow-up entry.
fn spawn_failure_code(e: &kagisecure_core::Error) -> &'static str {
    match e {
        kagisecure_core::Error::Spawn { .. } => "SPAWN_FAILED",
        kagisecure_core::Error::NonUtf8EnvValue(_) => "INVALID_ENV_VALUE",
        _ => "RUN_FAILED",
    }
}

#[cfg(test)]
mod tests {
    use super::parse_env_spec;

    #[test]
    fn parses_the_documented_shape() {
        assert_eq!(
            parse_env_spec("TOKEN=Acme/password").unwrap(),
            ("TOKEN", "Acme", "password")
        );
    }

    #[test]
    fn the_last_slash_separates_item_from_field() {
        assert_eq!(
            parse_env_spec("URL=team/prod/db/url").unwrap(),
            ("URL", "team/prod/db", "url")
        );
    }

    #[test]
    fn malformed_specifications_are_refused() {
        for bad in [
            "TOKEN",
            "TOKEN=nofield",
            "=Acme/password",
            "TOKEN=/password",
            "TOKEN=Acme/",
            "BAD-NAME=Acme/password",
            "A\nB=Acme/password",
        ] {
            assert!(parse_env_spec(bad).is_err(), "{bad:?} should be refused");
        }
    }
}

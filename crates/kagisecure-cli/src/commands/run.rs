//! `kagisecure run` — the one place a secret value legitimately reaches a process the user asked
//! for.

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use kagisecure_core::Vault;
use kagisecure_core::inject::{EnvInjection, RunRequest, run_with_env};
use kagisecure_core::model::{FieldValue, Secret};

use crate::cli::RunArgs;
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
/// Returns the exit status to hand back to the shell.
///
/// # Errors
///
/// If the vault cannot be opened, a reference does not resolve, or the child cannot be started.
pub fn run(path: &Path, args: &RunArgs, input: &mut SecretInput) -> Result<u8> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let vault = Vault::open_with_password(path, password.as_bytes())?;
    drop(password);

    let mut injections: Vec<EnvInjection> = Vec::with_capacity(args.env.len());
    for spec in &args.env {
        let (name, item_ref, field_ref) = parse_env_spec(spec)?;
        let field = crate::commands::item::resolve_field(&vault, item_ref, field_ref)?;
        let value = match &field.value {
            FieldValue::Secret(s) => Secret::new(s.expose().to_vec()),
            // A public field is a perfectly reasonable thing to inject (a username, a host). It
            // still goes through the masking path, which costs nothing and cannot hurt.
            FieldValue::Public(v) => Secret::from_string(v.clone()),
        };
        injections.push(EnvInjection {
            name: name.to_owned(),
            value,
        });
    }

    let (program, rest) = args
        .command
        .split_first()
        .expect("clap requires at least one word after --");

    let request = RunRequest {
        program,
        args: rest,
        env: &injections,
        cwd: args.cwd.as_deref(),
        mask_output: !args.no_masking,
        max_output: kagisecure_core::inject::DEFAULT_MAX_OUTPUT,
        // No deadline: this is the user's own terminal and their own command. `run_with_env`
        // over MCP is the one that gets a timeout, because nobody is watching it.
        timeout: None,
    };
    let outcome = run_with_env(&request)?;
    drop(injections);
    drop(vault);

    std::io::stdout().write_all(&outcome.stdout)?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(&outcome.stderr)?;
    std::io::stderr().flush()?;

    if outcome.stdout_truncated || outcome.stderr_truncated {
        eprintln!("kagisecure: the child's output was truncated at 64 KiB per stream.");
    }

    // 128 + SIGKILL is the shell convention for "died on a signal"; we do not know which signal
    // here, so report a generic non-zero status rather than pretending it succeeded.
    Ok(u8::try_from(outcome.exit_code.unwrap_or(137)).unwrap_or(1))
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
        ] {
            assert!(parse_env_spec(bad).is_err(), "{bad:?} should be refused");
        }
    }
}

//! Tests for the injector: real child processes, a real environment, real masking.

use kagisecure_core::inject::{EnvInjection, RunRequest, run_with_env};
use kagisecure_core::model::Secret;
use std::ffi::{OsStr, OsString};

const VALUE: &str = "sk_live_injected_value_123";

fn injections() -> Vec<EnvInjection> {
    vec![EnvInjection {
        name: "KAGISECURE_TEST_VAR".to_owned(),
        value: Secret::from_string(VALUE.to_owned()),
    }]
}

/// A tiny cross-platform "print an environment variable" child.
fn printenv(var: &str) -> (OsString, Vec<OsString>) {
    if cfg!(windows) {
        (
            OsString::from("cmd"),
            vec![
                OsString::from("/C"),
                OsString::from(format!("echo %{var}%")),
            ],
        )
    } else {
        (OsString::from("printenv"), vec![OsString::from(var)])
    }
}

#[test]
fn injects_the_variable_into_the_child() {
    let env = injections();
    let (program, args) = printenv("KAGISECURE_TEST_VAR");
    let mut request = RunRequest::new(&program, &args, &env);
    request.mask_output = false;

    let outcome = run_with_env(&request).unwrap();
    assert_eq!(outcome.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&outcome.stdout).contains(VALUE));
    assert_eq!(outcome.masked, 0);
}

#[test]
fn masks_the_value_out_of_the_child_output_by_default() {
    let env = injections();
    let (program, args) = printenv("KAGISECURE_TEST_VAR");
    let request = RunRequest::new(&program, &args, &env);

    let outcome = run_with_env(&request).unwrap();
    assert_eq!(outcome.exit_code, Some(0));
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(!stdout.contains(VALUE), "masking let the value through");
    assert!(stdout.contains("[kagisecure:redacted:KAGISECURE_TEST_VAR]"));
    assert_eq!(outcome.masked, 1);
}

#[test]
fn masks_stderr_as_well_as_stdout() {
    if cfg!(windows) {
        return;
    }
    let env = injections();
    let program = OsString::from("sh");
    let args = vec![
        OsString::from("-c"),
        OsString::from("echo \"$KAGISECURE_TEST_VAR\" >&2"),
    ];
    let request = RunRequest::new(&program, &args, &env);

    let outcome = run_with_env(&request).unwrap();
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert!(!stderr.contains(VALUE));
    assert!(stderr.contains("[kagisecure:redacted:KAGISECURE_TEST_VAR]"));
}

/// mcp-server.md §2.8: `command` + `args` go to the OS directly. **No shell.** An argument that
/// looks like shell metacharacters is just an argument.
#[test]
fn arguments_are_never_interpreted_by_a_shell() {
    if cfg!(windows) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("pwned");
    let env: Vec<EnvInjection> = Vec::new();
    let program = OsString::from("echo");
    let args = vec![OsString::from(format!(
        "hello; touch {}",
        marker.to_string_lossy()
    ))];
    let request = RunRequest::new(&program, &args, &env);

    let outcome = run_with_env(&request).unwrap();
    assert_eq!(outcome.exit_code, Some(0));
    assert!(
        !marker.exists(),
        "the argument was handed to a shell, which would be a command injection"
    );
    assert!(String::from_utf8_lossy(&outcome.stdout).contains("; touch "));
}

#[test]
fn a_nonzero_exit_code_is_reported_not_swallowed() {
    let env: Vec<EnvInjection> = Vec::new();
    let (program, args) = if cfg!(windows) {
        (
            OsString::from("cmd"),
            vec![OsString::from("/C"), OsString::from("exit 3")],
        )
    } else {
        (
            OsString::from("sh"),
            vec![OsString::from("-c"), OsString::from("exit 3")],
        )
    };
    let outcome = run_with_env(&RunRequest::new(&program, &args, &env)).unwrap();
    assert_eq!(outcome.exit_code, Some(3));
}

#[test]
fn a_missing_program_is_an_error_that_names_the_program_and_nothing_else() {
    let env = injections();
    let program = OsString::from("kagisecure-no-such-program-here");
    let args: Vec<OsString> = Vec::new();
    let err = run_with_env(&RunRequest::new(&program, &args, &env)).unwrap_err();
    let rendered = err.to_string();
    assert!(rendered.contains("kagisecure-no-such-program-here"));
    assert!(
        !rendered.contains(VALUE),
        "error text leaked a secret value"
    );
}

#[test]
fn output_is_capped_and_the_truncation_is_reported() {
    if cfg!(windows) {
        return;
    }
    let env: Vec<EnvInjection> = Vec::new();
    let program = OsString::from("sh");
    let args = vec![
        OsString::from("-c"),
        OsString::from("head -c 100000 /dev/zero | tr '\\0' 'x'"),
    ];
    let mut request = RunRequest::new(&program, &args, &env);
    request.max_output = 1024;

    let outcome = run_with_env(&request).unwrap();
    assert_eq!(outcome.stdout.len(), 1024);
    assert!(outcome.stdout_truncated);
    assert!(!outcome.stderr_truncated);
}

#[test]
fn the_working_directory_is_honoured() {
    if cfg!(windows) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let canonical = dir.path().canonicalize().unwrap();
    let env: Vec<EnvInjection> = Vec::new();
    let program = OsString::from("pwd");
    let args: Vec<OsString> = Vec::new();
    let mut request = RunRequest::new(&program, &args, &env);
    request.cwd = Some(&canonical);

    let outcome = run_with_env(&request).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&outcome.stdout).trim(),
        canonical.to_string_lossy()
    );
}

#[test]
fn the_child_inherits_the_parent_environment_too() {
    // SAFETY-adjacent note: this mutates the test process's environment, which is why the value is
    // namespaced. Injection adds to the inherited environment rather than replacing it.
    unsafe { std::env::set_var("KAGISECURE_TEST_INHERITED", "yes") };
    let env = injections();
    let (program, args) = printenv("KAGISECURE_TEST_INHERITED");
    let request = RunRequest::new(&program, &args, &env);
    let outcome = run_with_env(&request).unwrap();
    assert!(String::from_utf8_lossy(&outcome.stdout).contains("yes"));
}

#[test]
fn a_value_with_an_embedded_nul_is_refused_rather_than_truncated() {
    let env = vec![EnvInjection {
        name: "BAD".to_owned(),
        value: Secret::new(b"before\0after".to_vec()),
    }];
    let program = OsString::from("true");
    let args: Vec<OsString> = Vec::new();
    let program: &OsStr = &program;
    let err = run_with_env(&RunRequest::new(program, &args, &env)).unwrap_err();
    assert!(err.to_string().contains("BAD"));
    assert!(!err.to_string().contains("before"));
}

#[test]
fn a_child_that_outlives_its_deadline_is_killed_and_reported() {
    let args = [OsString::from("30")];
    let mut request = RunRequest::new(OsStr::new("/bin/sleep"), &args, &[]);
    request.timeout = Some(std::time::Duration::from_millis(200));

    let started = std::time::Instant::now();
    let outcome = run_with_env(&request).unwrap();

    assert!(outcome.timed_out, "the child should have been killed");
    assert_eq!(outcome.exit_code, None);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the deadline was not enforced; took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_child_that_finishes_in_time_is_not_reported_as_timed_out() {
    let args = [OsString::from("ok")];
    let mut request = RunRequest::new(OsStr::new("/bin/echo"), &args, &[]);
    request.timeout = Some(std::time::Duration::from_secs(30));

    let outcome = run_with_env(&request).unwrap();
    assert!(!outcome.timed_out);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&outcome.stdout).trim(), "ok");
}

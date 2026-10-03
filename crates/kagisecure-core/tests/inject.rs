//! Tests for the injector: real child processes, a real environment, real masking.

use kagisecure_core::inject::{EnvInjection, RunRequest, run_with_env};
use kagisecure_core::model::Secret;
use std::ffi::{OsStr, OsString};

const VALUE: &str = "sk_live_injected_value_123";

fn injections() -> Vec<EnvInjection> {
    vec![EnvInjection {
        name: kagisecure_core::proto::VarName::new("KAGISECURE_TEST_VAR").expect("a valid name"),
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

/// A tiny cross-platform "sleep for N seconds" child, killable like any other process.
///
/// `cmd /C timeout` refuses to run at all when stdin is redirected (as `run_with_env` always
/// does), so this reaches for PowerShell's `Start-Sleep`, which has no such restriction.
fn sleep_for(seconds: u32) -> (OsString, Vec<OsString>) {
    if cfg!(windows) {
        (
            OsString::from("powershell"),
            vec![
                OsString::from("-NoProfile"),
                OsString::from("-Command"),
                OsString::from(format!("Start-Sleep -Seconds {seconds}")),
            ],
        )
    } else {
        (
            OsString::from("sleep"),
            vec![OsString::from(seconds.to_string())],
        )
    }
}

/// A tiny cross-platform "echo one argument back to stdout" child.
fn echo_arg(text: &str) -> (OsString, Vec<OsString>) {
    if cfg!(windows) {
        (
            OsString::from("cmd"),
            vec![OsString::from("/C"), OsString::from(format!("echo {text}"))],
        )
    } else {
        (OsString::from("echo"), vec![OsString::from(text)])
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
        name: kagisecure_core::proto::VarName::new("BAD").expect("a valid name"),
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
    let (program, args) = sleep_for(30);
    let mut request = RunRequest::new(&program, &args, &[]);
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

/// `kagisecure run` calls `run_with_env`, which keeps no kill handle of its own. On Windows the
/// child's job object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) used to belong to that handle alone,
/// so it closed — killing the child — right after the spawn: a command that did anything after its
/// first instant never got to. The job now belongs to the spawned child until it has been waited
/// for. On Unix this passed before the fix too; the ownership rule itself is unit-tested in
/// `kagisecure-childproc` on every platform.
#[test]
fn a_child_run_without_a_kill_handle_is_not_killed_at_spawn() {
    let (program, args) = if cfg!(windows) {
        (
            OsString::from("powershell"),
            vec![
                OsString::from("-NoProfile"),
                OsString::from("-Command"),
                OsString::from("Start-Sleep -Milliseconds 300; Write-Output done"),
            ],
        )
    } else {
        (
            OsString::from("sh"),
            vec![OsString::from("-c"), OsString::from("sleep 0.3; echo done")],
        )
    };
    let outcome = run_with_env(&RunRequest::new(&program, &args, &[])).unwrap();
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&outcome.stdout).trim(), "done");
}

/// Whether a pid is still alive (`kill -0`).
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(unix)]
fn read_pid(path: &std::path::Path) -> u32 {
    std::fs::read_to_string(path)
        .expect("the pid file was written")
        .trim()
        .parse()
        .expect("a pid")
}

#[cfg(unix)]
fn wait_for_death(pid: u32) {
    let started = std::time::Instant::now();
    while pid_is_alive(pid) {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "pid {pid} outlived the call that started it"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// A timed-out command's *group* is ended, not just the one pid `run_with_env` spawned — and the
/// call returns within its limit plus the grace periods even though a grandchild was holding the
/// output pipes open. Killing only the direct child used to leave the grandchild running with the
/// injected value, and the pipe readers blocked on it, so the call did not return until the
/// grandchild chose to exit.
#[cfg(unix)]
#[test]
fn a_timed_out_child_takes_its_grandchildren_with_it_and_the_call_returns() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("grandchild.pid");
    let program = OsString::from("sh");
    let args = vec![
        OsString::from("-c"),
        OsString::from(format!(
            "sleep 20 & echo $! > {}; sleep 20",
            pid_file.display()
        )),
    ];
    let mut request = RunRequest::new(&program, &args, &[]);
    request.timeout = Some(std::time::Duration::from_millis(500));
    request.new_process_group = true;

    let started = std::time::Instant::now();
    let outcome = run_with_env(&request).unwrap();
    let took = started.elapsed();

    assert!(outcome.timed_out);
    assert!(
        took < std::time::Duration::from_secs(8),
        "the call must return within its limit plus the grace periods; took {took:?}"
    );
    wait_for_death(read_pid(&pid_file));
}

/// A command that exits on its own but leaves a background process in its group: the call
/// returns with the command's own output, and the straggler — which still holds the injected
/// value, and the output pipe — does not outlive it.
#[cfg(unix)]
#[test]
fn a_straggler_left_in_the_group_does_not_outlive_the_call_or_hold_it_open() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("straggler.pid");
    let program = OsString::from("sh");
    let args = vec![
        OsString::from("-c"),
        OsString::from(format!(
            "sleep 20 & echo $! > {}; echo done",
            pid_file.display()
        )),
    ];
    let mut request = RunRequest::new(&program, &args, &[]);
    request.timeout = Some(std::time::Duration::from_secs(60));
    request.new_process_group = true;

    let started = std::time::Instant::now();
    let outcome = run_with_env(&request).unwrap();
    let took = started.elapsed();

    assert!(!outcome.timed_out);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&outcome.stdout).trim(), "done");
    assert!(
        took < std::time::Duration::from_secs(8),
        "a background process holding the pipe must not hold the call open; took {took:?}"
    );
    wait_for_death(read_pid(&pid_file));
}

#[test]
fn a_child_that_finishes_in_time_is_not_reported_as_timed_out() {
    let (program, args) = echo_arg("ok");
    let mut request = RunRequest::new(&program, &args, &[]);
    request.timeout = Some(std::time::Duration::from_secs(30));

    let outcome = run_with_env(&request).unwrap();
    assert!(!outcome.timed_out);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&outcome.stdout).trim(), "ok");
}

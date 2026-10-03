//! `kagisecure daemon` — the headless approval channel.
//!
//! # What this is, and what it is not
//!
//! Since M4 the real answer to architecture.md §2.5 is the macOS app: it owns the unlocked vault,
//! runs the IPC listener, shows a Touch ID approval sheet and performs the injection. This
//! subcommand is what remains for the cases the app cannot serve — an SSH session, CI, a Linux
//! box with no GUI — and it is retained rather than removed because those cases are real.
//!
//! **The approval channel is strictly weaker than the app's** and says so on startup. A terminal
//! prompt can be answered by anything that can write to this terminal; a Touch ID sheet cannot.
//!
//! # There is no second implementation here
//!
//! Everything that decides anything — the IPC listener, caller verification, the lease rules, the
//! audit chain, the `.env` writer, the process spawner — lives in `kagisecure-agent` and is the
//! same code the app runs. What is left in this file is a vault unlock, a `y`/`N` read, and a
//! banner. That is the whole point of the M4 split: if the daemon and the app could disagree
//! about a lease rule, one of them would be wrong.
//!
//! # `--auto-approve`
//!
//! The integration tests need a daemon that approves without a human. Rather than a cargo
//! feature (which `cargo test --workspace` would not enable, quietly skipping the test that
//! matters most), the flag is refused outright in a release build:
//!
//! ```text
//! check_auto_approve(args.auto_approve, cfg!(debug_assertions)) -> exit 2 with an explanation
//! ```
//!
//! Exit 2 is "usage error", which is what this is: the invocation asked for something this binary
//! will not do. `check_auto_approve` takes the build flavour as an argument so that the release
//! branch — the one no test process can ever be compiled into — is still reachable from a test.
//!
//! A shipped binary therefore cannot be talked into it by any argument or environment variable,
//! and `cargo test` gets it for free. See ADR-0007.

use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use kagisecure_agent::approval::{ApprovalKind, ApprovalRequest, ClientVerification, Decision};
use kagisecure_agent::{Agent, AgentConfig, ReplicaSource, SharedSource, VaultHandle};
use kagisecure_core::Vault;

use crate::cli::{DaemonArgs, UsageError};
use crate::prompt::SecretInput;

/// How long an unanswered approval prompt waits before the queue counts it as a refusal.
///
/// Two seconds under the queue's own 60 s so the terminal gives up first and prints something,
/// rather than the prompt silently becoming void while the user is still typing.
const ANSWER_WINDOW: Duration = Duration::from_secs(kagisecure_agent::APPROVAL_TIMEOUT_SECONDS - 2);

/// How the daemon decides whether a request is approved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApprovalMode {
    /// Ask on the terminal.
    Ask,
    /// Refuse everything that is not already covered by a lease.
    RefuseAll,
    /// Approve everything. Debug builds only; used by the integration tests.
    AutoApprove,
}

/// Run the daemon until the socket is closed or the process is interrupted.
///
/// # Errors
///
/// If the vault cannot be opened, the socket cannot be bound (including because the kagisecure
/// app already holds it), or `--auto-approve` is used in a release build.
/// Whether `--auto-approve` may be honoured on this build.
///
/// Split out of [`run`] and given `debug_build` as a parameter rather than reading
/// `cfg!(debug_assertions)` inline, because the branch that matters is the one a test process can
/// never be in: `cargo test` builds with debug assertions on, so an inline `cfg!` makes the
/// release rule unreachable from any test and the promise in this module's header unverifiable.
///
/// # Errors
///
/// [`UsageError`] when `auto_approve` is set on a release build — a usage error, hence exit 2
/// (`kagisecure --help`), not the generic exit 1 this used to produce.
fn check_auto_approve(auto_approve: bool, debug_build: bool) -> Result<()> {
    if auto_approve && !debug_build {
        return Err(UsageError(
            "--auto-approve is only honoured in debug builds. This is a release build, so there \
             is no way to make it approve an injection without a human. See ADR-0007."
                .to_owned(),
        )
        .into());
    }
    Ok(())
}

/// What `--socket` (or `KAGISECURE_SOCKET`) names, or a usage error saying why it cannot.
///
/// The value is a socket path on Unix and a named pipe name on Windows — the platform's own
/// answer to "where does a local socket live", decided in one place,
/// [`Endpoint::parse`](kagisecure_ipc::endpoint::Endpoint::parse), which the sidecar's
/// `Endpoint::discover` also goes through for the same variable.
///
/// A [`UsageError`] rather than a plain failure: the user named something this platform cannot
/// listen on, which is a wrong invocation (exit 2), and the message has to say what to write
/// instead. Before this, such a value was carried all the way to `bind` and surfaced as
/// `Unsupported: "not a named pipe path"` — an opaque I/O error out of a flag the user set
/// deliberately.
///
/// # Errors
///
/// [`UsageError`] when the value is not usable as an endpoint on this platform.
fn socket_endpoint(
    socket: Option<&std::ffi::OsStr>,
) -> Result<Option<kagisecure_ipc::endpoint::Endpoint>> {
    let Some(socket) = socket else {
        return Ok(None);
    };
    match kagisecure_ipc::endpoint::Endpoint::parse(socket) {
        Ok(endpoint) => Ok(Some(endpoint)),
        Err(e) => Err(UsageError(format!("--socket (or KAGISECURE_SOCKET): {e}")).into()),
    }
}

pub fn run(path: &Path, args: &DaemonArgs, input: &mut SecretInput) -> Result<()> {
    check_auto_approve(args.auto_approve, cfg!(debug_assertions))?;
    // Both usage errors are settled before the master password is asked for: being told that a
    // flag is wrong *after* typing it is a worse experience than being told before.
    let endpoint = socket_endpoint(args.socket.as_deref())?;

    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let vault = Vault::open_with_password(path, password.as_bytes())?;
    drop(password);

    let banner_vaults = vault.vault_summaries();
    // Every shared vault beside this one that a device key here opens is served too, read-only,
    // until the vault locks (ADR-0035 §14). The attachments are the only thing that keeps them
    // attached; the lock detaches and drops them, and their keys with them.
    let shared = ReplicaSource::open_all(path, &vault);
    let handle = VaultHandle::new(vault);
    let banner_shared: Vec<String> = shared
        .iter()
        .filter_map(|source| source.snapshot())
        .map(|snapshot| {
            let items = snapshot.items().iter().filter(|i| i.agent_visible).count();
            let envs = snapshot
                .environments()
                .iter()
                .filter(|e| e.agent_visible)
                .count();
            format!(
                "{:<20} shared: {items} item(s) and {envs} environment(s) visible to agents",
                snapshot.name()
            )
        })
        .collect();
    let _attachments: Vec<_> = shared
        .into_iter()
        .map(|source| handle.attach_shared(source))
        .collect();
    let config = AgentConfig {
        // The headless daemon serves no browsers, so it keeps a queue of its own rather than
        // taking the app's shared one (M6).
        queue: None,
        endpoint,
        // Nor does it serve agent fills: with no broker, every `request_fill` is
        // `FILL_UNAVAILABLE` before anything is looked up (ADR-0036 §3.1).
        agent_fill: None,
    };
    let agent = Agent::start(Arc::clone(&handle), &config)
        .context("could not start the kagisecure agent")?;

    let mode = if args.auto_approve {
        ApprovalMode::AutoApprove
    } else if args.non_interactive {
        ApprovalMode::RefuseAll
    } else {
        ApprovalMode::Ask
    };
    let answers = (mode == ApprovalMode::Ask).then(stdin_lines);

    println!("kagisecure daemon — the headless approval channel.");
    println!();
    println!("  vault    {}", path.display());
    println!("  socket   {}", agent.endpoint());
    println!(
        "  approval {}",
        match mode {
            ApprovalMode::Ask => "this terminal (y/N), 60 s timeout",
            ApprovalMode::RefuseAll => "refuse everything (--non-interactive)",
            ApprovalMode::AutoApprove => "APPROVE EVERYTHING (--auto-approve, debug build)",
        }
    );
    for v in &banner_vaults {
        println!(
            "  vault    {:<20} {} item(s), {} environment(s){}",
            v.name,
            v.item_count,
            v.environment_count,
            if v.agent_visible {
                "  [visible to agents]"
            } else {
                "  [not visible to agents]"
            }
        );
    }
    for line in &banner_shared {
        println!("  vault    {line}");
    }
    println!();
    println!("The kagisecure app is the real approval channel from M4 on. A terminal prompt is");
    println!("weaker: anything that can write to this terminal can answer it. Everything else —");
    println!("leases, the audit chain, and the rule that no secret value crosses the IPC");
    println!("boundary — is `kagisecure-agent`, the same library the app runs.");
    println!();
    println!("Press Ctrl-C to stop. Locking on exit drops every lease.");
    println!();
    let _ = std::io::stdout().flush();

    loop {
        if agent.take_lock_request() {
            drop(handle.take());
            println!("kagisecure daemon: vault locked; every lease dropped.");
            let _ = std::io::stdout().flush();
        }
        let Some(request) = agent.next_request(Duration::from_millis(250)) else {
            continue;
        };
        let decision = decide(mode, answers.as_ref(), &request);
        agent.resolve(&request.id, &decision, ClientVerification::unchecked());
    }
}

/// Decide one request, the way this terminal decides things.
fn decide(
    mode: ApprovalMode,
    answers: Option<&Arc<Mutex<Receiver<String>>>>,
    request: &ApprovalRequest,
) -> Decision {
    let session = Decision::AllowSession {
        ttl_seconds: request.requested_ttl_seconds,
        uses: request.requested_uses,
    };
    match mode {
        ApprovalMode::AutoApprove => {
            println!(
                "kagisecure daemon: auto-approving {} (debug build, --auto-approve)",
                request.kind.tool()
            );
            let _ = std::io::stdout().flush();
            return session;
        }
        ApprovalMode::RefuseAll => {
            println!(
                "kagisecure daemon: refusing {} (--non-interactive)",
                request.kind.tool()
            );
            let _ = std::io::stdout().flush();
            return Decision::Deny;
        }
        ApprovalMode::Ask => {}
    }

    print_prompt(request);
    let Some(answers) = answers else {
        return Decision::Deny;
    };
    let rx = answers.lock().unwrap_or_else(|e| e.into_inner());
    match rx.recv_timeout(ANSWER_WINDOW) {
        Ok(answer) => {
            let yes = matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes");
            let once = matches!(answer.to_ascii_lowercase().as_str(), "o" | "once");
            println!(
                "kagisecure daemon: {}",
                if yes {
                    "approved"
                } else if once {
                    "approved once"
                } else {
                    "denied"
                }
            );
            let _ = std::io::stdout().flush();
            if once {
                Decision::AllowOnce
            } else if yes {
                session
            } else {
                Decision::Deny
            }
        }
        Err(RecvTimeoutError::Timeout) => {
            println!("kagisecure daemon: no answer in time — the request times out.");
            let _ = std::io::stdout().flush();
            Decision::Deny
        }
        Err(RecvTimeoutError::Disconnected) => Decision::Deny,
    }
}

/// Drain stdin on a dedicated thread so an approval prompt can time out.
fn stdin_lines() -> Arc<Mutex<Receiver<String>>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::BufRead::read_line(&mut stdin.lock(), &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.trim().to_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    Arc::new(Mutex::new(rx))
}

/// Print the facts the app's approval sheet shows (ui-spec.md §10.2).
///
/// Nothing here is supplied by the model except values it is *allowed* to influence, and every
/// one of them is printed as data, on its own line, never interpolated into an instruction.
fn print_prompt(request: &ApprovalRequest) {
    println!();
    println!("  ┌─ kagisecure approval ─────────────────────────────────────────");
    println!("  │ A caller wants to {}.", what(request.kind));
    println!("  │");
    println!("  │ caller      {}", caller_line(request));
    if let Some(cwd) = request.client_cwd.as_deref() {
        println!("  │ started in  {cwd}");
    }
    for fact in facts(request) {
        println!("  │ {fact}");
    }
    println!("  │");
    println!("  │ No secret value is shown to the caller either way.");
    println!("  └───────────────────────────────────────────────────────────────");
    print!("  Allow? [y = this session / o = once / N = deny] ");
    let _ = std::io::stdout().flush();
}

fn what(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::CreateEnvironment => "create an environment",
        ApprovalKind::AddVariables => "add variables to an environment",
        ApprovalKind::WriteEnvFile => "write a .env file",
        ApprovalKind::RunWithEnv => "run a command with secrets in its environment",
        // The headless daemon serves the MCP socket only — it never starts the browser-extension
        // listener, so these two arms are unreachable in practice: a fill needs a browser, and
        // `request_fill` on this daemon answers FILL_UNAVAILABLE before anything is asked. They
        // are written out rather than left to a wildcard so that adding a kind is a compile
        // error here too.
        ApprovalKind::FillCredential => "fill a credential into a web page",
        ApprovalKind::AgentFill => "have a login typed into a browser tab",
    }
}

/// The caller, rendered the way `PeerIdentity::describe` does: the self-reported name in quotes,
/// the kernel's facts bare, so a caller cannot pass its own name off as our label.
fn caller_line(request: &ApprovalRequest) -> String {
    let trust = if request.client_pid_from_kernel && request.client_executable.is_some() {
        "kernel pid"
    } else {
        "UNVERIFIED"
    };
    format!(
        "{:?} [{trust}] pid {} {}",
        request.client_name,
        request
            .client_pid
            .map_or_else(|| "?".to_owned(), |p| p.to_string()),
        request
            .client_executable
            .as_deref()
            .unwrap_or("unknown executable"),
    )
}

fn facts(request: &ApprovalRequest) -> Vec<String> {
    let mut facts = Vec::new();
    if let Some(source) = request.shared_source.as_deref() {
        facts.push(format!("from        {source}"));
    }
    for change in &request.changed_since_approval {
        facts.push(format!("changed     {change}"));
    }
    if let Some(name) = request.environment_name.as_deref() {
        facts.push(format!("environment {name}"));
    }
    if let Some(id) = request.environment_id.as_deref() {
        facts.push(format!("env id      {id}"));
    }
    if let Some(origin) = request.origin.as_deref() {
        facts.push(format!("origin      {origin}"));
    }
    if let Some(top) = request.top_origin.as_deref() {
        facts.push(format!("in a frame on {top}"));
    }
    if let Some(title) = request.item_title.as_deref() {
        facts.push(format!("item        {title}"));
    }
    if !request.fill_fields.is_empty() {
        facts.push(format!("fields      {}", request.fill_fields.join(", ")));
    }
    if !request.command.is_empty() {
        facts.push(format!("command     {}", request.command.join(" ")));
        facts.push("note        no shell: ; | $() in an argument are just characters".to_owned());
    }
    if let Some(path) = request.target_path.as_deref() {
        facts.push(format!("file        {path}"));
    } else if let Some(dir) = request.directory.as_deref() {
        facts.push(format!("cwd         {dir}"));
    }
    if !request.variables.is_empty() {
        facts.push(format!("variables   {}", request.variables.join(", ")));
    }
    if request.kind.mints_lease() {
        facts.push(format!(
            "for         {} s, up to {} uses",
            request.requested_ttl_seconds, request.requested_uses
        ));
    }
    match request.gitignored {
        Some(true) => facts.push("gitignore   covered by .gitignore".to_owned()),
        Some(false) => {
            facts.push("gitignore   *** INSIDE A GIT WORK TREE AND NOT IGNORED ***".to_owned())
        }
        None => {
            if request.target_path.is_some() {
                facts.push("gitignore   not inside a git work tree".to_owned());
            }
        }
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_request() -> ApprovalRequest {
        ApprovalRequest {
            id: "req-1".to_owned(),
            kind: ApprovalKind::WriteEnvFile,
            client_name: "claude-code".to_owned(),
            client_pid: Some(4242),
            client_pid_from_kernel: true,
            // A plausible absolute path for the fact list to render — not asserted on verbatim.
            // The bundled location (ADR-0026) rather than a Homebrew-style one, since that is
            // where this executable actually lives today.
            client_executable: Some(
                "/Applications/Kagisecure.app/Contents/Helpers/kagisecure-mcp".to_owned(),
            ),
            environment_name: Some("acme / staging".to_owned()),
            target_path: Some("/Users/x/code/acme/.env".to_owned()),
            variables: vec!["TOKEN".to_owned()],
            gitignored: Some(false),
            requested_ttl_seconds: 900,
            requested_uses: 10,
            ..ApprovalRequest::default()
        }
    }

    #[test]
    fn a_shared_release_names_its_vault_and_what_changed() {
        let request = ApprovalRequest {
            shared_source: Some("Shared vault “Ops” — 3 members".to_owned()),
            changed_since_approval: vec!["TOKEN changed by another member, 2 days ago".to_owned()],
            ..write_request()
        };
        let facts = facts(&request).join("\n");
        assert!(facts.contains("from        Shared vault “Ops” — 3 members"));
        assert!(facts.contains("changed     TOKEN changed by another member, 2 days ago"));
        // The personal vault's prompt is unchanged.
        let personal = facts_of_personal();
        assert!(!personal.contains("from "));
        assert!(!personal.contains("changed "));
    }

    fn facts_of_personal() -> String {
        facts(&write_request()).join("\n")
    }

    #[test]
    fn the_prompt_states_every_fact_the_sheet_states() {
        let facts = facts(&write_request()).join("\n");
        assert!(facts.contains("acme / staging"));
        assert!(facts.contains("/Users/x/code/acme/.env"));
        assert!(facts.contains("TOKEN"));
        assert!(facts.contains("900 s, up to 10 uses"));
        assert!(
            facts.contains("INSIDE A GIT WORK TREE AND NOT IGNORED"),
            "an unignored .env has to be loud: {facts}"
        );
    }

    #[test]
    fn a_run_request_shows_the_argv_and_the_no_shell_note() {
        let request = ApprovalRequest {
            kind: ApprovalKind::RunWithEnv,
            command: vec!["npm".to_owned(), "run".to_owned(), "migrate".to_owned()],
            directory: Some("/Users/x/code/acme".to_owned()),
            ..write_request()
        };
        let facts = facts(&ApprovalRequest {
            target_path: None,
            ..request
        })
        .join("\n");
        assert!(facts.contains("npm run migrate"));
        assert!(facts.contains("no shell"));
        assert!(facts.contains("cwd         /Users/x/code/acme"));
    }

    #[test]
    fn a_self_reported_name_is_quoted_so_it_cannot_borrow_our_label() {
        let request = ApprovalRequest {
            client_name: "Claude Code (verified)".to_owned(),
            ..write_request()
        };
        let line = caller_line(&request);
        assert!(line.contains("\"Claude Code (verified)\""), "{line}");
        assert!(line.contains("kernel pid"), "{line}");
    }

    #[test]
    fn a_caller_the_kernel_could_not_place_is_marked_unverified() {
        let request = ApprovalRequest {
            client_pid_from_kernel: false,
            ..write_request()
        };
        assert!(caller_line(&request).contains("UNVERIFIED"));
    }

    #[test]
    fn auto_approve_grants_exactly_what_was_asked_for() {
        let decision = decide(ApprovalMode::AutoApprove, None, &write_request());
        assert_eq!(
            decision,
            Decision::AllowSession {
                ttl_seconds: 900,
                uses: 10
            }
        );
    }

    #[test]
    fn non_interactive_refuses() {
        assert_eq!(
            decide(ApprovalMode::RefuseAll, None, &write_request()),
            Decision::Deny
        );
    }

    #[test]
    fn asking_with_no_terminal_to_ask_refuses() {
        assert_eq!(
            decide(ApprovalMode::Ask, None, &write_request()),
            Decision::Deny
        );
    }

    #[test]
    fn auto_approve_is_allowed_in_a_debug_build() {
        assert!(check_auto_approve(true, true).is_ok());
    }

    #[test]
    fn auto_approve_is_a_usage_error_in_a_release_build() {
        let error = check_auto_approve(true, false).expect_err("a release build must refuse it");
        let usage = error
            .downcast_ref::<UsageError>()
            .expect("it has to be a UsageError, or main maps it to exit 1");
        assert!(
            usage.to_string().contains("ADR-0007"),
            "the refusal should say where the rule is written down: {usage}"
        );
        assert_eq!(
            crate::exit_code_for(&error),
            crate::cli::EXIT_USAGE,
            "the module header promises exit 2 and `kagisecure --help` documents 2 as the usage \
             error; exit 1 reads as \"an unexpected error, report it\""
        );
    }

    #[test]
    fn a_daemon_without_the_flag_is_unaffected_either_way() {
        assert!(check_auto_approve(false, true).is_ok());
        assert!(check_auto_approve(false, false).is_ok());
    }

    #[test]
    fn no_socket_flag_leaves_the_endpoint_to_the_per_user_default() {
        assert!(
            socket_endpoint(None)
                .expect("no flag is not an error")
                .is_none()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_socket_flag_is_a_path_taken_verbatim() {
        let endpoint = socket_endpoint(Some(std::ffi::OsStr::new("/tmp/two-vaults/daemon.sock")))
            .expect("a path is what Unix listens on")
            .expect("some endpoint");
        assert_eq!(
            endpoint.path(),
            Some(std::path::Path::new("/tmp/two-vaults/daemon.sock"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_socket_flag_is_a_pipe_name_on_windows() {
        let endpoint = socket_endpoint(Some(std::ffi::OsStr::new("kagisecure-second-vault.sock")))
            .expect("a pipe name is what Windows listens on")
            .expect("some endpoint");
        assert_eq!(endpoint.to_string(), "kagisecure-second-vault.sock");
        assert!(endpoint.path().is_none(), "a pipe is not a file");
    }

    #[cfg(windows)]
    #[test]
    fn a_socket_path_on_windows_is_a_usage_error_that_says_what_to_pass() {
        let error = socket_endpoint(Some(std::ffi::OsStr::new(r"C:\Users\ada\run\daemon.sock")))
            .expect_err("Windows cannot listen on a filesystem path");
        let usage = error
            .downcast_ref::<UsageError>()
            .expect("a wrong invocation, not an unexpected error");
        let text = usage.to_string();
        assert!(text.contains("--socket"), "{text}");
        assert!(text.contains(r"C:\Users\ada\run\daemon.sock"), "{text}");
        assert!(
            text.contains("named pipe"),
            "the refusal has to say what Windows accepts: {text}"
        );
        assert_eq!(crate::exit_code_for(&error), crate::cli::EXIT_USAGE);
    }
}

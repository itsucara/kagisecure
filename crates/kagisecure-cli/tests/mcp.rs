//! End-to-end tests across all three processes: `kagisecure daemon`, `kagisecure-mcp`, and an
//! MCP client.
//!
//! They live in the CLI's test target rather than the sidecar's on purpose. The sidecar's
//! dependency graph is asserted locally (`cargo tree -e features`, run in CI until CI was removed
//! on 2026-09-19) to exclude the `secret-material` feature, and a
//! dev-dependency on `kagisecure-core` — which seeding a vault needs — would put it right back
//! in. The CLI already has that dependency and owns the `kagisecure` binary, so the tests belong
//! here. See ADR-0007.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;

/// A 32-byte marker, seeded as a secret value. If these bytes ever reach the model, the product
/// has failed at the one thing it exists to do.
const MARKER: &str = "K4G1-C4N4RY-8f3a91c2e7d045b6a1f8";

/// The master password for a throwaway test vault.
const PASSWORD: &str = "test-master-password";

/// A TOTP seed, seeded into an **agent-visible** item.
///
/// Agent-visible on purpose: "the sidecar never returns a code" is only worth asserting on an
/// item the agent is allowed to see at all. Both this Base32 seed and every code derived from it
/// are canaries in their own right (vault-format.md §5.3, mcp-server.md §2.7).
const TOTP_SECRET_B32: &str = "MZXW6YTBOI3XG5DBOJUW4Y3PNZ2GK3TU";
/// The URI as a service would hand it over. Contains the seed, so it is itself a canary.
const TOTP_URI: &str = "otpauth://totp/Canary:ada@example.com\
     ?secret=MZXW6YTBOI3XG5DBOJUW4Y3PNZ2GK3TU&issuer=Canary&algorithm=SHA1&digits=8&period=30";

// ---------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------

struct Fixture {
    _dir: tempfile::TempDir,
    vault: PathBuf,
    socket: PathBuf,
    project: PathBuf,
    daemon: Child,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn kagisecure() -> PathBuf {
    cargo_bin("kagisecure")
}

/// The sidecar binary, built on demand.
///
/// `cargo test --workspace` has already built it; `cargo test -p kagisecure-cli` has not, and a
/// test that silently skipped in that case would be worse than a slow one.
fn sidecar() -> PathBuf {
    let path = cargo_bin("kagisecure-mcp");
    if path.is_file() {
        return path;
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "-p", "kagisecure-mcp"])
        .status()
        .expect("could not run cargo to build the sidecar");
    assert!(status.success(), "building kagisecure-mcp failed");
    assert!(path.is_file(), "kagisecure-mcp still missing at {path:?}");
    path
}

/// Run one `kagisecure` subcommand against the fixture vault, feeding it `stdin_lines`.
fn cli(vault: &Path, stdin_lines: &[&str], args: &[&str]) -> String {
    let mut child = Command::new(kagisecure())
        .arg("--vault")
        .arg(vault)
        .arg("--password-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning kagisecure");
    {
        let stdin = child.stdin.as_mut().expect("piped");
        for line in stdin_lines {
            writeln!(stdin, "{line}").expect("writing to kagisecure stdin");
        }
    }
    let out = child.wait_with_output().expect("waiting for kagisecure");
    assert!(
        out.status.success(),
        "`kagisecure {}` failed:\n{}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A vault holding one item with the marker as its concealed value, one environment bound to it,
/// and a daemon serving it.
fn fixture(extra_daemon_args: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("test.kagivault");
    let socket = dir.path().join("d.sock");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project dir");

    // Deliberately cheap KDF parameters: this vault exists for 200 ms and protects nothing.
    cli(
        &vault,
        &[PASSWORD],
        &[
            "vault",
            "init",
            "--kdf-m-kib",
            "8",
            "--kdf-t",
            "1",
            "--name",
            "Personal",
        ],
    );
    cli(
        &vault,
        &[PASSWORD, MARKER],
        &[
            "item",
            "add",
            "--title",
            "Acme staging",
            "--category",
            "api-credential",
            "--field",
            "username=deploy",
            "--secret",
            "token",
            "--value-stdin",
        ],
    );
    cli(
        &vault,
        &[PASSWORD],
        &["env", "create", "acme / staging", "--agent-visible"],
    );
    cli(
        &vault,
        &[PASSWORD],
        &[
            "env",
            "add-var",
            "--environment",
            "acme / staging",
            "--name",
            "TOKEN",
            "--bind",
            "Acme staging/token",
        ],
    );
    cli(
        &vault,
        &[PASSWORD],
        &[
            "env",
            "agent-access",
            "--allow",
            "--logical-vault",
            "Personal",
        ],
    );
    cli(
        &vault,
        &[PASSWORD],
        &["env", "agent-access", "--allow", "--item", "Acme staging"],
    );
    // An agent-visible item carrying a one-time password. Added after "Acme staging", so the
    // tests that index `items[0]` still get that one.
    cli(
        &vault,
        &[PASSWORD, TOTP_URI],
        &[
            "item",
            "add",
            "--title",
            "GitHub",
            "--totp",
            "one-time password",
            "--value-stdin",
        ],
    );
    cli(
        &vault,
        &[PASSWORD],
        &["env", "agent-access", "--allow", "--item", "GitHub"],
    );
    // Default-deny has to be observable, so the fixture also holds one environment the user has
    // never shared. It is created before the daemon opens the vault, so the daemon's own saves
    // cannot be what hides it.
    cli(&vault, &[PASSWORD], &["env", "create", "private-env"]);

    let mut daemon = Command::new(kagisecure())
        .arg("--vault")
        .arg(&vault)
        .arg("--password-stdin")
        .arg("daemon")
        .arg("--socket")
        .arg(&socket)
        .args(extra_daemon_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the daemon");
    {
        // `--password-stdin` drains standard input to EOF, so the handle has to be dropped.
        let mut stdin = daemon.stdin.take().expect("piped");
        writeln!(stdin, "{PASSWORD}").expect("writing the master password");
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "the daemon never created its socket"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    Fixture {
        _dir: dir,
        vault,
        socket,
        project,
        daemon,
    }
}

// ---------------------------------------------------------------------------------------------
// A minimal JSON-RPC driver that keeps every byte the sidecar wrote
// ---------------------------------------------------------------------------------------------

/// Speaks MCP to the sidecar over pipes, retaining the raw bytes of both output streams.
///
/// The canary needs a byte-level assertion about **stdout**, so it cannot use an MCP client
/// library: the library consumes the stream. This is small enough to be obviously correct.
struct RawSidecar {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    seen_stdout: Vec<u8>,
    next_id: u64,
}

impl RawSidecar {
    fn start(socket: &Path) -> Self {
        let mut child = Command::new(sidecar())
            .env("KAGISECURE_SOCKET", socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawning kagisecure-mcp");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut this = Self {
            child,
            stdout,
            seen_stdout: Vec::new(),
            next_id: 0,
        };
        this.initialize();
        this
    }

    fn send(&mut self, message: &serde_json::Value) {
        let stdin = self.child.stdin.as_mut().expect("piped");
        let line = format!("{message}\n");
        stdin
            .write_all(line.as_bytes())
            .expect("writing to sidecar");
        stdin.flush().expect("flushing sidecar stdin");
    }

    fn recv(&mut self) -> serde_json::Value {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line).expect("reading sidecar");
        assert!(read > 0, "the sidecar closed stdout unexpectedly");
        self.seen_stdout.extend_from_slice(line.as_bytes());
        serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("sidecar wrote non-JSON: {e}: {line}"))
    }

    fn initialize(&mut self) {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "kagisecure-canary", "version": "0.0.0" }
            }
        }));
        let reply = self.recv();
        assert!(
            reply["result"]["serverInfo"]["name"] == "kagisecure-mcp",
            "{reply}"
        );
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
    }

    fn tool_names(&mut self) -> Vec<String> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}
        }));
        let reply = self.recv();
        let mut names: Vec<String> = reply["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().expect("tool name").to_owned())
            .collect();
        names.sort();
        names
    }

    /// The whole `tools/list` reply, as JSON text. Used for a schema-level negative assertion.
    fn tool_schemas(&mut self) -> String {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}
        }));
        let reply = self.recv();
        serde_json::to_string_pretty(&reply["result"]["tools"]).expect("tools re-encode")
    }

    fn call(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }));
        self.recv()
    }

    /// Shut down and return everything the sidecar wrote to stdout and stderr.
    fn finish(mut self) -> (Vec<u8>, Vec<u8>) {
        drop(self.child.stdin.take());
        // Drain whatever is left on stdout before the process goes away.
        let mut rest = Vec::new();
        let _ = self.stdout.read_to_end(&mut rest);
        self.seen_stdout.extend_from_slice(&rest);
        let mut stderr = Vec::new();
        if let Some(mut handle) = self.child.stderr.take() {
            let _ = handle.read_to_end(&mut stderr);
        }
        let _ = self.child.wait();
        (self.seen_stdout, stderr)
    }
}

fn structured(reply: &serde_json::Value) -> &serde_json::Value {
    &reply["result"]["structuredContent"]
}

fn is_error(reply: &serde_json::Value) -> bool {
    reply["result"]["isError"].as_bool().unwrap_or(false)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[test]
fn every_tool_works_end_to_end_and_the_marker_never_reaches_stdout() {
    let fixture = fixture(&["--auto-approve"]);
    let mut mcp = RawSidecar::start(&fixture.socket);

    assert_eq!(
        mcp.tool_names(),
        [
            "add_variables",
            "create_environment",
            "describe_item",
            "list_environments",
            "list_items",
            "list_vaults",
            "revoke_env_file",
            "run_with_env",
            "write_env_file",
        ]
    );

    // --- metadata -----------------------------------------------------------------------
    let vaults = mcp.call("list_vaults", serde_json::json!({}));
    assert!(!is_error(&vaults), "{vaults}");
    assert_eq!(structured(&vaults)["vaults"][0]["name"], "Personal");

    let items = mcp.call("list_items", serde_json::json!({}));
    let item_id = structured(&items)["items"][0]["id"]
        .as_str()
        .expect("an item")
        .to_owned();

    let described = mcp.call("describe_item", serde_json::json!({ "item_id": item_id }));
    let fields = structured(&described)["fields"]
        .as_array()
        .expect("fields")
        .clone();
    let token = fields
        .iter()
        .find(|f| f["label"] == "token")
        .expect("the concealed field");
    assert_eq!(token["concealed"], true);
    assert_eq!(
        token["has_value"], true,
        "has_value is a boolean, and it is the only thing said about the value"
    );

    let envs = mcp.call("list_environments", serde_json::json!({}));
    let env = &structured(&envs)["environments"][0];
    assert_eq!(env["name"], "acme / staging");
    assert_eq!(env["variables"][0]["name"], "TOKEN");
    let env_id = env["id"].as_str().expect("an environment").to_owned();

    // --- structure ----------------------------------------------------------------------
    let created = mcp.call(
        "create_environment",
        serde_json::json!({ "name": "made-by-agent", "description": "from a test" }),
    );
    assert!(!is_error(&created), "{created}");
    let new_env = structured(&created)["id"]
        .as_str()
        .expect("new env id")
        .to_owned();

    let added = mcp.call(
        "add_variables",
        serde_json::json!({
            "environment_id": new_env,
            "variables": [{ "name": "NEW_KEY", "hint": "paste the staging key" }]
        }),
    );
    assert_eq!(structured(&added)["status"], "pending_user_input");
    assert_eq!(structured(&added)["pending"][0], "NEW_KEY");
    assert!(
        structured(&added)["deep_link"]
            .as_str()
            .unwrap_or_default()
            .starts_with("kagisecure://environments/"),
        "{added}"
    );

    // --- injection ----------------------------------------------------------------------
    let project = fixture.project.display().to_string();
    let wrote = mcp.call(
        "write_env_file",
        serde_json::json!({ "environment_id": env_id, "directory": project }),
    );
    assert!(!is_error(&wrote), "{wrote}");
    let written_path = structured(&wrote)["path"]
        .as_str()
        .expect("a path")
        .to_owned();
    assert_eq!(structured(&wrote)["variables_written"][0], "TOKEN");
    let lease = structured(&wrote)["lease_id"]
        .as_str()
        .expect("a lease")
        .to_owned();

    // The file really does contain the value; the *tool result* does not.
    let on_disk = std::fs::read_to_string(&written_path).expect("the .env exists");
    assert!(on_disk.contains(MARKER), "the .env should hold the value");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&written_path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    let ran = mcp.call(
        "run_with_env",
        serde_json::json!({
            "environment_id": env_id,
            "command": "/usr/bin/printenv",
            "args": ["TOKEN"],
            "cwd": project,
        }),
    );
    assert!(!is_error(&ran), "{ran}");
    assert_eq!(structured(&ran)["exit_code"], 0);
    let stdout = structured(&ran)["stdout"]
        .as_str()
        .expect("stdout")
        .to_owned();
    assert_eq!(stdout.trim(), "[kagisecure:redacted:TOKEN]");
    assert_eq!(structured(&ran)["scrubbed"], 1);

    let quiet = mcp.call(
        "run_with_env",
        serde_json::json!({
            "environment_id": env_id,
            "command": "/usr/bin/printenv",
            "args": ["TOKEN"],
            "cwd": project,
            "output": "none",
        }),
    );
    assert_eq!(structured(&quiet)["exit_code"], 0);
    assert!(
        structured(&quiet)["stdout"].is_null(),
        "output:none must omit stdout entirely: {quiet}"
    );

    // --- cleanup ------------------------------------------------------------------------
    let revoked = mcp.call("revoke_env_file", serde_json::json!({ "lease_id": lease }));
    assert_eq!(structured(&revoked)["shredded"][0], written_path.as_str());
    assert!(
        !Path::new(&written_path).exists(),
        "revoke must delete the file"
    );

    // --- the canary ---------------------------------------------------------------------
    let (out, err) = mcp.finish();
    let marker = MARKER.as_bytes();
    assert!(
        !out.windows(marker.len()).any(|w| w == marker),
        "the marker appeared in the sidecar's stdout"
    );
    assert!(
        !err.windows(marker.len()).any(|w| w == marker),
        "the marker appeared in the sidecar's stderr"
    );
    assert!(!out.is_empty(), "the driver should have captured traffic");

    // And it is not in the audit log either (vault-format §8: names, never values).
    let log = cli(
        &fixture.vault,
        &[PASSWORD],
        &["audit", "--json", "--limit", "500"],
    );
    assert!(
        !log.contains(MARKER),
        "the marker appeared in the audit log"
    );
    assert!(log.contains("write_env_file"), "the log records the write");
    assert!(
        log.contains("revoke_env_file"),
        "the log records the revoke"
    );
}

#[test]
fn run_with_env_does_not_invoke_a_shell() {
    let fixture = fixture(&["--auto-approve"]);
    let mut mcp = RawSidecar::start(&fixture.socket);

    let env_id = structured(&mcp.call("list_environments", serde_json::json!({})))["environments"]
        [0]["id"]
        .as_str()
        .expect("an environment")
        .to_owned();

    let pwned = fixture.project.join("pwned");
    let project = fixture.project.display().to_string();
    let injection = format!("; touch {}", pwned.display());

    let ran = mcp.call(
        "run_with_env",
        serde_json::json!({
            "environment_id": env_id,
            "command": "/bin/echo",
            "args": [injection],
            "cwd": project,
        }),
    );
    assert!(!is_error(&ran), "{ran}");
    assert!(
        !pwned.exists(),
        "an argument containing `; touch ...` created a file, so something ran a shell"
    );
    let stdout = structured(&ran)["stdout"].as_str().unwrap_or_default();
    assert!(
        stdout.contains("; touch"),
        "the argument should have been passed through as ordinary text: {stdout:?}"
    );
    let _ = mcp.finish();
}

#[test]
fn a_second_identical_request_reuses_the_lease_and_a_broader_one_does_not() {
    let fixture = fixture(&["--auto-approve"]);
    let mut mcp = RawSidecar::start(&fixture.socket);

    let env_id = structured(&mcp.call("list_environments", serde_json::json!({})))["environments"]
        [0]["id"]
        .as_str()
        .expect("an environment")
        .to_owned();
    let project = fixture.project.display().to_string();

    let first = mcp.call(
        "write_env_file",
        serde_json::json!({ "environment_id": env_id, "directory": project }),
    );
    let lease_one = structured(&first)["lease_id"].as_str().unwrap().to_owned();

    let second = mcp.call(
        "write_env_file",
        serde_json::json!({ "environment_id": env_id, "directory": project, "overwrite": true }),
    );
    let lease_two = structured(&second)["lease_id"].as_str().unwrap().to_owned();
    assert_eq!(
        lease_one, lease_two,
        "the same request in the same directory should ride the existing lease"
    );

    // A different directory is a different lease: the match is exact, never a prefix.
    let other = fixture.project.join("nested");
    std::fs::create_dir_all(&other).expect("nested dir");
    let third = mcp.call(
        "write_env_file",
        serde_json::json!({
            "environment_id": env_id,
            "directory": other.display().to_string(),
        }),
    );
    let lease_three = structured(&third)["lease_id"].as_str().unwrap().to_owned();
    assert_ne!(
        lease_one, lease_three,
        "a different directory must not be covered by the first lease"
    );
    let _ = mcp.finish();
}

#[test]
fn a_refused_approval_returns_user_denied_and_writes_nothing() {
    let fixture = fixture(&["--non-interactive"]);
    let mut mcp = RawSidecar::start(&fixture.socket);

    let env_id = structured(&mcp.call("list_environments", serde_json::json!({})))["environments"]
        [0]["id"]
        .as_str()
        .expect("an environment")
        .to_owned();
    let project = fixture.project.display().to_string();

    let refused = mcp.call(
        "write_env_file",
        serde_json::json!({ "environment_id": env_id, "directory": project }),
    );
    assert!(is_error(&refused), "{refused}");
    assert_eq!(structured(&refused)["code"], "USER_DENIED");
    assert!(
        !fixture.project.join(".env").exists(),
        "a denial must not leave a partial write behind"
    );

    let (out, _) = mcp.finish();
    assert!(
        !out.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
        "the marker appeared in the sidecar's stdout"
    );

    // The denial is recorded, which is the whole point of keeping denials.
    let log = cli(
        &fixture.vault,
        &[PASSWORD],
        &["audit", "--json", "--limit", "500"],
    );
    assert!(
        log.contains("USER_DENIED"),
        "denials must be audited:\n{log}"
    );
    assert!(log.contains("Denied"), "denials must be audited:\n{log}");
}

#[test]
fn a_read_only_call_leaves_an_audit_entry_on_disk() {
    // Read-only tools change nothing, so nothing else in their path would ever write the vault
    // back out. If their audit entry is not persisted at the point it is appended, it lives in
    // the daemon's memory only and dies with it — an agent that merely browses leaves no trace.
    let fixture = fixture(&["--non-interactive"]);
    let mut mcp = RawSidecar::start(&fixture.socket);

    let reply = mcp.call("list_environments", serde_json::json!({}));
    assert!(!is_error(&reply), "{reply}");

    // The daemon is still running and has been asked to do nothing that mutates the vault. The
    // entry must already be in the file.
    let log = cli(
        &fixture.vault,
        &[PASSWORD],
        &["audit", "--json", "--limit", "500"],
    );
    assert!(
        log.contains("list_environments"),
        "a read-only call must be audited on disk, not only in memory:\n{log}"
    );
    let _ = mcp.finish();
}

#[test]
fn with_no_daemon_the_tools_fail_promptly_with_app_not_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("nobody-home.sock");
    let mut mcp = RawSidecar::start(&socket);

    let started = Instant::now();
    let reply = mcp.call("list_vaults", serde_json::json!({}));
    let elapsed = started.elapsed();

    assert!(is_error(&reply), "{reply}");
    assert_eq!(structured(&reply)["code"], "APP_NOT_RUNNING");
    assert!(
        structured(&reply)["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not running"),
        "{reply}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "APP_NOT_RUNNING took {elapsed:?}; it must be prompt so the client does not hang"
    );
    let _ = mcp.finish();
}

#[test]
fn an_environment_the_user_has_not_shared_is_invisible_to_agents() {
    let fixture = fixture(&["--auto-approve"]);
    let mut mcp = RawSidecar::start(&fixture.socket);
    let envs = mcp.call("list_environments", serde_json::json!({}));
    let names: Vec<String> = structured(&envs)["environments"]
        .as_array()
        .expect("array")
        .iter()
        .map(|e| e["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        !names.iter().any(|n| n == "private-env"),
        "default-deny means a fresh environment is invisible: {names:?}"
    );
    let _ = mcp.finish();
}

// ---------------------------------------------------------------------------------------------
// The same sweep, through the real MCP client API
// ---------------------------------------------------------------------------------------------

/// Everything above drives the sidecar through a hand-rolled JSON-RPC driver, because the canary
/// needs to keep the raw stdout bytes. This test does the same sweep through `rmcp`'s client, so
/// that what an actual MCP client sees — schemas, structured content, error results — is what is
/// under test, and asserts the marker is absent from every tool result.
#[tokio::test]
async fn every_tool_through_the_rmcp_client_api() {
    use rmcp::ServiceExt;
    use rmcp::model::CallToolRequestParams;
    use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};

    let fixture = fixture(&["--auto-approve"]);
    let socket = fixture.socket.clone();
    let project = fixture.project.display().to_string();

    let transport =
        TokioChildProcess::new(tokio::process::Command::new(sidecar()).configure(|cmd| {
            cmd.env("KAGISECURE_SOCKET", &socket);
        }))
        .expect("spawning the sidecar under the rmcp client");
    let client = ().serve(transport).await.expect("MCP handshake");

    let info = client.peer_info().expect("server info");
    let server = info.server_info.clone().expect("the server names itself");
    assert_eq!(server.name, "kagisecure-mcp");
    let instructions = info.instructions.clone().unwrap_or_default();
    assert!(
        instructions.contains("cannot read a value"),
        "the server must tell the model the invariant up front: {instructions}"
    );

    let mut names: Vec<String> = client
        .list_all_tools()
        .await
        .expect("tools/list")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    assert_eq!(names.len(), 9, "{names:?}");

    // Everything the client is handed, concatenated, so one assertion covers the lot.
    let mut seen = String::new();
    let call = async |name: &str, args: serde_json::Value| {
        let mut params = CallToolRequestParams::new(name.to_owned());
        if let Some(arguments) = args.as_object().cloned() {
            params = params.with_arguments(arguments);
        }
        let result = client
            .call_tool(params)
            .await
            .unwrap_or_else(|e| panic!("calling {name}: {e}"));
        serde_json::to_value(&result).expect("a tool result is JSON")
    };

    let vaults = call("list_vaults", serde_json::json!({})).await;
    seen.push_str(&vaults.to_string());

    let envs = call("list_environments", serde_json::json!({})).await;
    seen.push_str(&envs.to_string());
    let env_id = envs["structuredContent"]["environments"][0]["id"]
        .as_str()
        .expect("an environment")
        .to_owned();

    let items = call("list_items", serde_json::json!({})).await;
    seen.push_str(&items.to_string());
    let item_id = items["structuredContent"]["items"][0]["id"]
        .as_str()
        .expect("an item")
        .to_owned();

    seen.push_str(
        &call("describe_item", serde_json::json!({ "item_id": item_id }))
            .await
            .to_string(),
    );

    let created = call(
        "create_environment",
        serde_json::json!({ "name": "made-by-rmcp-client" }),
    )
    .await;
    seen.push_str(&created.to_string());
    let new_env = created["structuredContent"]["id"]
        .as_str()
        .expect("new env")
        .to_owned();

    seen.push_str(
        &call(
            "add_variables",
            serde_json::json!({
                "environment_id": new_env,
                "variables": [{ "name": "ANOTHER_KEY", "hint": "paste it" }]
            }),
        )
        .await
        .to_string(),
    );

    let wrote = call(
        "write_env_file",
        serde_json::json!({ "environment_id": env_id, "directory": project }),
    )
    .await;
    seen.push_str(&wrote.to_string());
    let lease = wrote["structuredContent"]["lease_id"]
        .as_str()
        .expect("a lease")
        .to_owned();

    seen.push_str(
        &call(
            "run_with_env",
            serde_json::json!({
                "environment_id": env_id,
                "command": "/usr/bin/printenv",
                "args": ["TOKEN"],
                "cwd": project,
            }),
        )
        .await
        .to_string(),
    );

    seen.push_str(
        &call("revoke_env_file", serde_json::json!({ "lease_id": lease }))
            .await
            .to_string(),
    );

    assert!(
        !seen.contains(MARKER),
        "the marker reached an MCP client through a tool result"
    );
    assert!(
        seen.contains("kagisecure:redacted:TOKEN"),
        "run_with_env should have masked the value it injected"
    );

    client.cancel().await.expect("clean shutdown");
}

/// The M5 canary: a one-time-password code, and the seed it comes from, never cross MCP.
///
/// The structural guarantee is that they *cannot*: `kagisecure_core::totp` is behind the
/// `secret-material` feature, and both `kagisecure-mcp` and `kagisecure-ipc` depend on the core
/// with `default-features = false`, so neither crate can name `Totp`, call `code_at`, or declare
/// a field to put a code in. This test is the assertion that goes with the argument — it drives
/// every tool against a vault whose agent-visible item *has* a TOTP field, and then reads every
/// byte the sidecar wrote.
///
/// Codes are checked for the whole window the test could possibly span, not just "now": a code
/// captured at the start of the run and printed at the end would otherwise slip past.
#[test]
fn a_totp_code_never_reaches_the_model() {
    use kagisecure_core::totp::{Totp, TotpParams};

    let started = kagisecure_core::unix_now();
    let fixture = fixture(&["--auto-approve"]);
    let mut mcp = RawSidecar::start(&fixture.socket);

    // The TOTP item is visible, and the sidecar says so — the *existence* of the field is
    // metadata the user opted into (mcp-server.md §2.4), which is what makes the rest of this
    // test meaningful rather than vacuous.
    let items = mcp.call("list_items", serde_json::json!({}));
    let github = structured(&items)["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|i| i["title"] == "GitHub")
        .expect("the TOTP item is agent-visible")
        .clone();
    let described = mcp.call(
        "describe_item",
        serde_json::json!({ "item_id": github["id"] }),
    );
    let field = structured(&described)["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .find(|f| f["label"] == "one-time password")
        .expect("the TOTP field is described")
        .clone();
    assert_eq!(field["concealed"], true, "{field}");
    assert_eq!(field["has_value"], true, "{field}");
    // Nothing else. In particular no code, no seed, no issuer, no period.
    for forbidden in ["code", "value", "secret", "otpauth", "period", "digits"] {
        assert!(
            field.get(forbidden).is_none(),
            "describe_item exposed {forbidden:?}: {field}"
        );
    }

    // Drive the rest of the surface, so the canary covers every tool rather than one.
    let env_id = structured(&mcp.call("list_environments", serde_json::json!({})))["environments"]
        [0]["id"]
        .as_str()
        .expect("an environment")
        .to_owned();
    let project = fixture.project.display().to_string();
    let _ = mcp.call("list_vaults", serde_json::json!({}));
    let wrote = mcp.call(
        "write_env_file",
        serde_json::json!({ "environment_id": env_id, "directory": project }),
    );
    let lease = structured(&wrote)["lease_id"]
        .as_str()
        .expect("a lease")
        .to_owned();
    let _ = mcp.call(
        "run_with_env",
        serde_json::json!({
            "environment_id": env_id,
            "command": "/usr/bin/printenv",
            "args": ["TOKEN"],
            "cwd": project,
        }),
    );
    let created = mcp.call(
        "create_environment",
        serde_json::json!({ "name": "agent-made", "description": "canary run" }),
    );
    let _ = mcp.call(
        "add_variables",
        serde_json::json!({
            "environment_id": structured(&created)["id"],
            "variables": [{ "name": "OTP", "hint": "a name is not a value" }]
        }),
    );
    let _ = mcp.call("revoke_env_file", serde_json::json!({ "lease_id": lease }));

    let (out, err) = mcp.finish();
    let finished = kagisecure_core::unix_now();

    let audit = cli(
        &fixture.vault,
        &[PASSWORD],
        &["audit", "--json", "--limit", "500"],
    );

    // The seed and the URI it travels in.
    for canary in [TOTP_SECRET_B32, "otpauth://"] {
        let needle = canary.as_bytes();
        assert!(
            !out.windows(needle.len()).any(|w| w == needle),
            "{canary:?} appeared in the sidecar's stdout"
        );
        assert!(
            !err.windows(needle.len()).any(|w| w == needle),
            "{canary:?} appeared in the sidecar's stderr"
        );
        assert!(
            !audit.contains(canary),
            "{canary:?} appeared in the audit log"
        );
    }

    // Every code that existed while the test was running.
    let totp = Totp::from_base32(
        TOTP_SECRET_B32,
        TotpParams {
            digits: 8,
            ..TotpParams::default()
        },
    )
    .expect("the canary seed parses");
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let stderr = String::from_utf8_lossy(&err).into_owned();
    let mut checked = 0;
    for at in (started.saturating_sub(30)..=finished + 30).step_by(15) {
        let code = totp.code_at(at).expect("a code");
        let code = code.expose_str().expect("digits");
        checked += 1;
        assert!(!stdout.contains(code), "the code {code} appeared in stdout");
        assert!(!stderr.contains(code), "the code {code} appeared in stderr");
        assert!(
            !audit.contains(code),
            "the code {code} appeared in the audit log"
        );
    }
    assert!(
        checked >= 4,
        "the window sweep covered only {checked} codes"
    );
    assert!(!out.is_empty(), "the driver should have captured traffic");

    // The `run_with_env` masking path is about environment values, not codes; assert the audit
    // log did record the *activity*, so a canary that passed because nothing happened would fail.
    assert!(audit.contains("write_env_file"), "{audit}");
}

/// No MCP tool declares a place to put a one-time-password code.
///
/// A schema-level assertion, so an added tool whose output record grows a `code` field fails here
/// before anyone has to think about whether it happened to be populated during a test run.
#[test]
fn no_tool_schema_offers_a_one_time_password() {
    let fixture = fixture(&["--auto-approve"]);
    let mut mcp = RawSidecar::start(&fixture.socket);
    let schemas = mcp.tool_schemas();
    let (out, err) = mcp.finish();
    let _ = (out, err);

    let rendered = schemas.to_lowercase();
    for forbidden in ["totp", "otpauth", "one-time password", "one_time_password"] {
        assert!(
            !rendered.contains(forbidden),
            "a tool schema mentions {forbidden:?}:\n{schemas}"
        );
    }
}

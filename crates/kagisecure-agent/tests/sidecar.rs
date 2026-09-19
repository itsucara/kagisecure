//! Cross-process: a library-hosted agent, the real `kagisecure-mcp` binary, and a raw MCP client.
//!
//! The M2 suite (`crates/kagisecure-cli/tests/mcp.rs`) proves the same path with `kagisecure
//! daemon` as the host. This one proves it with the host the *app* uses — the library, embedded in
//! the test process, approving through the queue instead of through a terminal — so that the M4
//! claim "the app serves a real sidecar" is asserted by a test and not only by a screenshot.
//!
//! The approval is answered from a worker thread that plays the part of the app's UI: it polls
//! `next_request` and calls `resolve`. There is no `--auto-approve` here and no way to add one:
//! the queue has no mode in which it answers itself.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kagisecure_agent::approval::{ApprovalRequest, ClientVerification, Decision};
use kagisecure_agent::{Agent, AgentConfig, VaultHandle};
use kagisecure_core::model::{EnvVar, Environment, Field, Item, Secret, VarSource};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};

/// A 32-byte marker, seeded as a secret value. If these bytes reach an approval request, an audit
/// entry or the sidecar's stdout, the product has failed at the one thing it exists to do.
const MARKER: &str = "K4G1-C4N4RY-af41c07b93e2d685f0a1";

struct Fixture {
    dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    agent: Agent,
    socket: PathBuf,
    project: PathBuf,
    env_id: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project dir");

    // Deliberately cheap KDF parameters: this vault exists for a second and protects nothing.
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(8, 1, 1).expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");

    let vault_id = vault.default_vault_id().expect("default vault");
    vault.set_vault_agent_visible(vault_id, true);

    let mut item = Item::new(vault_id, Category::ApiCredential, "Acme staging");
    let mut field = Field::concealed("token", Secret::from_string(MARKER.to_owned()));
    field.agent_visible = true;
    let field_id = field.id;
    let item_id = item.id;
    item.fields.push(field);
    item.agent_visible = true;
    vault.add_item(item);

    let mut env = Environment::new(vault_id, "acme / staging");
    env.agent_visible = true;
    env.set_var(EnvVar {
        name: "TOKEN".to_owned(),
        source: VarSource::ItemField {
            item: item_id,
            field: field_id,
        },
    });
    let env_id = env.id.to_string();
    vault.add_environment(env);
    vault.save().expect("save");

    let socket = dir.path().join("agent.sock");
    let handle = VaultHandle::new(vault);
    let agent = Agent::start(
        Arc::clone(&handle),
        &AgentConfig {
            socket_path: Some(socket.clone()),
            queue: None,
        },
    )
    .expect("the agent should bind a fresh socket");

    Fixture {
        dir,
        handle,
        agent,
        socket,
        project,
        env_id,
    }
}

/// The sidecar binary, built on demand.
///
/// `cargo test --workspace` has already built it; `cargo test -p kagisecure-agent` has not, and a
/// test that silently skipped in that case would be worse than a slow one.
fn sidecar() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    let candidate = dir.join("target").join("debug").join("kagisecure-mcp");
    if candidate.is_file() {
        return candidate;
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(&dir)
        .args(["build", "-p", "kagisecure-mcp"])
        .status()
        .expect("could not run cargo to build the sidecar");
    assert!(status.success(), "building kagisecure-mcp failed");
    assert!(candidate.is_file(), "kagisecure-mcp still missing");
    candidate
}

/// A minimal JSON-RPC driver over the sidecar's stdio, keeping every byte of stdout.
struct RawSidecar {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    seen_stdout: Vec<u8>,
    next_id: u64,
}

impl RawSidecar {
    fn start(socket: &Path, cwd: &Path) -> Self {
        let mut child = Command::new(sidecar())
            .current_dir(cwd)
            .env("KAGISECURE_SOCKET", socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawning kagisecure-mcp");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut me = Self {
            child,
            stdout,
            seen_stdout: Vec::new(),
            next_id: 0,
        };
        me.call(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "kagisecure-agent-test", "version": "0"}
            }),
        );
        me.notify("notifications/initialized");
        me
    }

    fn send(&mut self, value: &serde_json::Value) {
        let stdin = self.child.stdin.as_mut().expect("piped");
        writeln!(stdin, "{value}").expect("writing to the sidecar");
        stdin.flush().expect("flush");
    }

    fn notify(&mut self, method: &str) {
        let body = serde_json::json!({"jsonrpc": "2.0", "method": method});
        self.send(&body);
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = self.next_id;
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        });
        self.send(&body);
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .expect("reading the sidecar");
            assert!(read > 0, "the sidecar closed its stdout");
            self.seen_stdout.extend_from_slice(line.as_bytes());
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if value.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                return value;
            }
        }
    }

    fn tool(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.call(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }
}

impl Drop for RawSidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Drive the queue until `f` finishes, answering everything with `decision`.
///
/// `Agent` is used from the test thread, so the "UI" runs as a scoped thread borrowing it — the
/// same shape the app has, where the polling task and the main actor both hold the one agent.
fn with_ui<T>(agent: &Agent, decision: Decision, f: impl FnOnce() -> T) -> (T, Vec<ApprovalRequest>)
where
    T: Send,
{
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        let ui_stop = Arc::clone(&stop);
        let ui_seen = Arc::clone(&seen);
        let ui_decision = decision.clone();
        scope.spawn(move || {
            while !ui_stop.load(Ordering::SeqCst) {
                if let Some(request) = agent.next_request(Duration::from_millis(100)) {
                    ui_seen
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(request.clone());
                    agent.resolve(
                        &request.id,
                        &ui_decision,
                        ClientVerification {
                            verified: true,
                            evidence: "test double".to_owned(),
                        },
                    );
                }
            }
        });
        let out = f();
        stop.store(true, Ordering::SeqCst);
        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        (out, requests)
    })
}

fn structured(reply: &serde_json::Value) -> &serde_json::Value {
    &reply["result"]["structuredContent"]
}

#[test]
fn the_app_hosted_agent_serves_a_real_sidecar_end_to_end() {
    let fx = fixture();
    let mut mcp = RawSidecar::start(&fx.socket, &fx.project);

    let (written, seen) = with_ui(
        &fx.agent,
        Decision::AllowSession {
            ttl_seconds: 900,
            uses: 10,
        },
        || {
            let listed = mcp.tool("list_environments", serde_json::json!({}));
            let names = structured(&listed)["environments"][0]["variables"][0]["name"].clone();
            assert_eq!(names, "TOKEN", "reply was {listed}");

            mcp.tool(
                "write_env_file",
                serde_json::json!({
                    "environment_id": fx.env_id,
                    "directory": fx.project.canonicalize().expect("canonical").to_str(),
                    "ttl_seconds": 900
                }),
            )
        },
    );

    let result = structured(&written);
    assert_eq!(
        result["variables_written"][0], "TOKEN",
        "reply was {written}"
    );
    let env_file = fx.project.join(".env");
    assert!(
        env_file.is_file(),
        "the agent should have written {env_file:?}"
    );
    let contents = std::fs::read_to_string(&env_file).expect("read .env");
    assert!(
        contents.contains(MARKER),
        "the file the user approved does hold the value"
    );

    // One approval, and everything on it is metadata.
    assert_eq!(seen.len(), 1, "exactly one question was asked");
    let request = &seen[0];
    assert_eq!(request.variables, vec!["TOKEN".to_owned()]);
    assert_eq!(request.environment_name.as_deref(), Some("acme / staging"));
    assert!(
        request
            .target_path
            .as_deref()
            .is_some_and(|p| p.ends_with("/.env"))
    );
    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains(MARKER),
        "an approval request must never carry a value: {rendered}"
    );

    // A lease exists, names the caller, and is scoped to the exact directory.
    let leases = fx.agent.leases();
    assert_eq!(leases.len(), 1);
    assert!(leases[0].client_identity.contains("signature verified"));
    assert_eq!(
        leases[0].directory,
        fx.project
            .canonicalize()
            .expect("canonical")
            .display()
            .to_string()
    );

    // Not one byte of the marker reached the sidecar's stdout.
    let stdout = String::from_utf8_lossy(&mcp.seen_stdout).into_owned();
    assert!(
        !stdout.contains(MARKER),
        "the marker reached the MCP client's stream"
    );

    // Nor the audit log, which does record the call.
    let audited = fx
        .handle
        .with(|v| {
            v.audit_entries()
                .iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .expect("unlocked");
    assert!(audited.contains("write_env_file"));
    assert!(!audited.contains(MARKER), "audit entries record names only");

    drop(mcp);
    drop(fx.dir);
}

#[test]
fn a_denied_request_returns_user_denied_and_writes_nothing() {
    let fx = fixture();
    let mut mcp = RawSidecar::start(&fx.socket, &fx.project);

    let (reply, seen) = with_ui(&fx.agent, Decision::Deny, || {
        mcp.tool(
            "write_env_file",
            serde_json::json!({
                "environment_id": fx.env_id,
                "directory": fx.project.canonicalize().expect("canonical").to_str(),
            }),
        )
    });

    assert_eq!(seen.len(), 1);
    let text = reply.to_string();
    assert!(text.contains("USER_DENIED"), "reply was {reply}");
    assert!(
        !fx.project.join(".env").exists(),
        "a denial must not leave a partial write behind"
    );
    assert!(fx.agent.leases().is_empty(), "a denial mints no lease");

    drop(mcp);
    drop(fx.dir);
}

#[test]
fn allow_once_does_not_cover_the_next_identical_request() {
    let fx = fixture();
    let mut mcp = RawSidecar::start(&fx.socket, &fx.project);
    let dir = fx.project.canonicalize().expect("canonical");

    let (_, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        for _ in 0..2 {
            let reply = mcp.tool(
                "write_env_file",
                serde_json::json!({
                    "environment_id": fx.env_id,
                    "directory": dir.to_str(),
                    "overwrite": true,
                }),
            );
            assert!(
                !reply.to_string().contains("USER_DENIED"),
                "reply was {reply}"
            );
        }
    });

    assert_eq!(
        seen.len(),
        2,
        "\"Allow once\" is one use, so the second identical request re-prompts (ui-spec.md §10.3)"
    );

    drop(mcp);
    drop(fx.dir);
}

#[test]
fn locking_the_vault_stops_the_agent_serving() {
    let fx = fixture();
    let mut mcp = RawSidecar::start(&fx.socket, &fx.project);
    let dir = fx.project.canonicalize().expect("canonical");

    // One approved write, so there is a live lease to kill.
    let _ = with_ui(
        &fx.agent,
        Decision::AllowSession {
            ttl_seconds: 900,
            uses: 10,
        },
        || {
            mcp.tool(
                "write_env_file",
                serde_json::json!({
                    "environment_id": fx.env_id,
                    "directory": dir.to_str(),
                }),
            )
        },
    );
    assert_eq!(fx.agent.leases().len(), 1);
    assert!(fx.project.join(".env").is_file());

    // The user locks.
    drop(fx.handle.take());

    assert!(fx.agent.leases().is_empty(), "locking kills every lease");
    assert!(
        !fx.project.join(".env").exists(),
        "and shreds what those leases wrote"
    );

    let reply = mcp.tool("list_environments", serde_json::json!({}));
    assert!(
        reply.to_string().contains("VAULT_LOCKED"),
        "a locked vault serves nothing, not even metadata: {reply}"
    );

    drop(mcp);
    drop(fx.dir);
}

/// Every audit entry records the pid of the process that made the call.
///
/// The pid comes from the kernel — `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` in `kagisecure-ipc`'s
/// one `unsafe` module — not from anything the caller said about itself, which is the only reason
/// it is worth writing down. `docs/mcp-server.md` §6 lists it as part of every entry.
///
/// This is a regression test: `Service::draft` had no `self` and therefore no connection to read
/// the identity from, so the MCP path wrote `client_pid: None` on every entry while the browser
/// path in `extension.rs` wrote it correctly. An audit log kept so that "a burst of denials is the
/// signal that something is trying things" has to name the process doing the trying.
#[test]
fn every_audit_entry_names_the_process_that_made_the_call() {
    let fx = fixture();
    let mut mcp = RawSidecar::start(&fx.socket, &fx.project);

    // A read-only tool, a structural one, and an injection: three different code paths to the
    // audit log, and the pid has to be on all of them.
    mcp.tool("list_vaults", serde_json::json!({}));
    let (_, _seen) = with_ui(
        &fx.agent,
        Decision::AllowSession {
            ttl_seconds: 900,
            uses: 10,
        },
        || {
            mcp.tool(
                "write_env_file",
                serde_json::json!({
                    "environment_id": fx.env_id,
                    "directory": fx.project.to_string_lossy(),
                }),
            )
        },
    );

    let sidecar_pid = mcp.child.id();

    let entries = fx
        .handle
        .with(|v| v.audit_entries().to_vec())
        .expect("unlocked");

    let from_mcp: Vec<_> = entries.iter().filter(|e| e.actor == "mcp").collect();
    assert!(
        from_mcp.len() >= 2,
        "both calls should be audited, got {from_mcp:?}"
    );
    for entry in &from_mcp {
        assert_eq!(
            entry.client_pid,
            Some(sidecar_pid),
            "audit entry for {} should name the sidecar's pid ({sidecar_pid}), got {:?}",
            entry.tool,
            entry.client_pid
        );
    }

    drop(mcp);
    drop(fx.dir);
}

/// `lock` stops the socket serving *before* it answers, not when the host next polls.
///
/// `Service::lock` shreds the leases, closes the approval queue and sets `lock_requested`, then
/// replies `Locked`. The host — `kagisecure daemon`'s main loop, or the app — drops the vault key
/// when it next polls `Agent::take_lock_request`, which in the daemon is up to 250 ms later.
///
/// This test is the regression for that interval. It never calls `take_lock_request`, so it holds
/// the agent in exactly the state the host would be in mid-poll: the key is still in memory, and
/// nothing may be served with it. Before the fix, `list_items` answered normally here and a
/// `write_env_file` could still be approved — after `kagisecure lock` had printed "the vault key
/// and every lease are gone".
#[test]
fn the_socket_stops_serving_the_moment_a_lock_is_acknowledged() {
    let fx = fixture();
    let mut mcp = RawSidecar::start(&fx.socket, &fx.project);

    // A lease first, so there is something for the lock to kill.
    let (written, _) = with_ui(
        &fx.agent,
        Decision::AllowSession {
            ttl_seconds: 900,
            uses: 10,
        },
        || {
            mcp.tool(
                "write_env_file",
                serde_json::json!({
                    "environment_id": fx.env_id,
                    "directory": fx.project.to_string_lossy(),
                }),
            )
        },
    );
    let env_path = fx.project.join(".env");
    assert!(env_path.exists(), "the injection should have written it");
    assert_eq!(written["result"]["isError"], serde_json::Value::Bool(false));

    // Lock over IPC, the way `kagisecure lock` and the app's menu bar do.
    let mut client = kagisecure_ipc::client::Client::connect(
        &kagisecure_ipc::Endpoint::Path(fx.socket.clone()),
        kagisecure_ipc::protocol::ClientInfo {
            name: "lock-window-test".to_owned(),
            version: "0".to_owned(),
            pid: std::process::id(),
            parent_pid: None,
            argv0: "lock-window-test".to_owned(),
            cwd: None,
        },
    )
    .expect("connect");
    let reply = client
        .call(&kagisecure_ipc::protocol::Request::Lock)
        .expect("lock");
    assert!(
        matches!(reply, kagisecure_ipc::protocol::Response::Locked),
        "the lock is acknowledged: {reply:?}"
    );

    // The host has NOT taken the vault yet — deliberately, that is the window under test.
    assert!(
        fx.handle.is_unlocked(),
        "this test is only meaningful while the key is still in memory"
    );
    assert!(!env_path.exists(), "the lock shredded what the lease wrote");

    // Metadata is refused.
    for tool in ["list_vaults", "list_items", "describe_item"] {
        let arguments = if tool == "describe_item" {
            serde_json::json!({ "item_id": "00000000-0000-4000-8000-000000000000" })
        } else {
            serde_json::json!({})
        };
        let reply = mcp.tool(tool, arguments);
        assert_eq!(
            reply["result"]["structuredContent"]["code"], "VAULT_LOCKED",
            "{tool} was served after the lock was acknowledged: {reply}"
        );
    }

    // And so is an injection, without ever reaching a human. `with_ui` would answer "allow" if
    // anything asked — nothing does, because the queue closed with the lock.
    let (refused, seen) = with_ui(
        &fx.agent,
        Decision::AllowSession {
            ttl_seconds: 900,
            uses: 10,
        },
        || {
            mcp.tool(
                "write_env_file",
                serde_json::json!({
                    "environment_id": fx.env_id,
                    "directory": fx.project.to_string_lossy(),
                    "overwrite": true,
                }),
            )
        },
    );
    assert_eq!(
        refused["result"]["structuredContent"]["code"], "VAULT_LOCKED",
        "an injection after a lock: {refused}"
    );
    assert!(
        seen.is_empty(),
        "nobody should have been asked to approve anything: {seen:?}"
    );
    assert!(!env_path.exists(), "and nothing was written");

    drop(mcp);
    drop(fx.dir);
}

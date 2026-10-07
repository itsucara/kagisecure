//! Shared fixtures for the adversarial suite.
//!
//! Everything here builds the *real* thing: a real vault on disk, a real `Agent` bound to a real
//! local socket — a unix socket on Unix, a named pipe on Windows, whichever
//! `Endpoint::for_instance` gives this platform — and real `kagisecure-ipc` clients speaking the
//! real frame protocol over it. There
//! are no mocks and no test-only code paths in the product — the only test double is the thread
//! that plays the part of the app's approval UI, which is exactly what `tests/sidecar.rs` does.
//!
//! The adversarial tests deliberately talk to the socket **directly** rather than through
//! `kagisecure-mcp`. The sidecar is a convenience for models, not a trust boundary: it clamps
//! `ttl_seconds` and defaults `filename`, and anything that relies on those clamps for safety is
//! relying on a process a hostile caller simply would not run. The agent has to hold on its own.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kagisecure_agent::approval::{ApprovalRequest, ClientVerification, Decision};
use kagisecure_agent::{Agent, AgentConfig, VaultHandle};
use kagisecure_core::model::{Environment, Field, Item, Secret, VarSource};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_ipc::client::Client;
use kagisecure_ipc::protocol::{ClientInfo, Request, Response};

/// A 32-byte marker seeded as the one secret value in the fixture vault. If these bytes appear in
/// an approval request, an audit entry, an error message or a tool reply, the product has failed.
pub const MARKER: &str = "K4G1-C4N4RY-af41c07b93e2d685f0a1";

/// The canary filename an attacker would like to overwrite: the one a toolchain actually reads.
pub const REAL_DOTENV: &str = ".env";

/// The innocuous filename an attacker would show a human on the approval sheet.
pub const DECOY_DOTENV: &str = ".env.example";

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub handle: Arc<VaultHandle>,
    pub agent: Agent,
    /// Where the agent is listening, in this platform's own form.
    pub endpoint: kagisecure_ipc::Endpoint,
    pub project: PathBuf,
    pub env_id: String,
    pub item_id: String,
    pub vault_id: String,
}

/// A vault with one agent-visible environment holding one agent-visible secret.
pub fn fixture() -> Fixture {
    build_fixture(true)
}

/// The same vault with `agent_visible` turned off everywhere — the "the user said no" state.
pub fn invisible_fixture() -> Fixture {
    build_fixture(false)
}

fn build_fixture(visible: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project dir");

    // Deliberately cheap KDF parameters: this vault exists for a second and protects nothing.
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");

    let vault_id = vault.default_vault_id().expect("default vault");

    let mut item = Item::new(vault_id, Category::ApiCredential, "Acme staging");
    let mut field = Field::concealed("token", Secret::from_string(MARKER.to_owned()));
    field.agent_visible = visible;
    let field_id = field.id;
    let item_id = item.id;
    item.fields.push(field);
    item.agent_visible = visible;

    let mut env = Environment::new(vault_id, "acme / staging");
    env.agent_visible = visible;
    env.set_var(
        kagisecure_core::proto::VarName::new("TOKEN".to_owned()).expect("a valid name"),
        VarSource::ItemField {
            item: item_id,
            field: field_id,
        },
    );
    let env_id = env.id.to_string();

    vault
        .transact(|tx| {
            tx.set_vault_agent_visible(vault_id, visible);
            tx.add_item(item);
            tx.add_environment(env);
            Ok(())
        })
        .expect("save");

    // One endpoint per fixture, in whatever form this platform can listen on: a socket in the
    // fixture's own temporary directory on Unix, a pipe name of its own on Windows. Distinct per
    // fixture so two of them never collide — which is a statement about our own instances and
    // not about who else on the machine could connect.
    let endpoint = kagisecure_ipc::Endpoint::for_instance(dir.path(), "agent.sock");
    let handle = VaultHandle::new(vault);
    let agent = Agent::start(
        Arc::clone(&handle),
        &AgentConfig {
            endpoint: Some(endpoint.clone()),
            queue: None,
            agent_fill: None,
            test_logins: None,
        },
    )
    .expect("the agent should bind a fresh socket");

    Fixture {
        dir,
        handle,
        agent,
        endpoint,
        project,
        env_id,
        item_id: item_id.to_string(),
        vault_id: vault_id.to_string(),
    }
}

impl Fixture {
    /// The project directory as the agent will canonicalize it.
    pub fn canonical_project(&self) -> PathBuf {
        self.project.canonicalize().expect("canonical project")
    }

    /// A raw IPC client on the agent's socket, already past `Hello`.
    pub fn client(&self, name: &str) -> Client {
        Client::connect(&self.endpoint, client_info(name)).expect("connect to the agent socket")
    }
}

/// A `ClientInfo` naming this test process. `name` is the **self-reported** field an attacker
/// controls, which is the point of letting each test choose it.
pub fn client_info(name: &str) -> ClientInfo {
    ClientInfo {
        name: name.to_owned(),
        version: "0".to_owned(),
        pid: std::process::id(),
        parent_pid: None,
        argv0: "adversarial-test".to_owned(),
        cwd: None,
    }
}

/// A `write_env_file` request with every knob exposed, so a test can set the ones a well-behaved
/// sidecar would never set.
#[must_use]
pub fn write_env_file(
    fx: &Fixture,
    directory: &str,
    filename: &str,
    overwrite: bool,
    ttl_seconds: u64,
) -> Request {
    Request::WriteEnvFile {
        environment_id: fx.env_id.parse().expect("env id"),
        directory: directory.to_owned(),
        filename: filename.to_owned(),
        variables: None,
        overwrite,
        ttl_seconds,
    }
}

/// Run `f` with a thread playing the app's approval UI, answering everything with `decision`.
///
/// Returns whatever `f` produced plus every request the "UI" was shown, so a test can assert on
/// what a human would actually have seen on the sheet.
pub fn with_ui<T>(
    agent: &Agent,
    decision: Decision,
    f: impl FnOnce() -> T,
) -> (T, Vec<ApprovalRequest>)
where
    T: Send,
{
    with_ui_answering(agent, move |_| Some(decision.clone()), f)
}

/// The general form: a per-request policy. Returning `None` leaves the request unanswered, which
/// is how a test exercises the timeout and the lock paths.
pub fn with_ui_answering<T, P>(
    agent: &Agent,
    policy: P,
    f: impl FnOnce() -> T,
) -> (T, Vec<ApprovalRequest>)
where
    T: Send,
    P: Fn(&ApprovalRequest) -> Option<Decision> + Send + Sync,
{
    /// Stops the UI thread even when `f` panics, so a failing assertion is a failure and not a
    /// hang inside `thread::scope`.
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        let ui_stop = Arc::clone(&stop);
        let ui_seen = Arc::clone(&seen);
        let policy = &policy;
        scope.spawn(move || {
            while !ui_stop.load(Ordering::SeqCst) {
                if let Some(request) = agent.next_request(Duration::from_millis(50)) {
                    ui_seen
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(request.clone());
                    if let Some(decision) = policy(&request) {
                        agent.resolve(&request.id, &decision, verified());
                    }
                }
            }
        });
        let guard = StopOnDrop(Arc::clone(&stop));
        let out = f();
        drop(guard);
        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        (out, requests)
    })
}

/// The verdict the app would report after a successful code-signature check.
#[must_use]
pub fn verified() -> ClientVerification {
    ClientVerification {
        verified: true,
        evidence: "adversarial test double".to_owned(),
    }
}

/// The error code on a response, or `None` if it succeeded.
#[must_use]
pub fn error_code(response: &Response) -> Option<String> {
    match response {
        Response::Error { code, .. } => Some(code.as_str().to_owned()),
        _ => None,
    }
}

/// The human-facing message on an error response.
#[must_use]
pub fn error_message(response: &Response) -> Option<String> {
    match response {
        Response::Error { message, .. } => Some(message.clone()),
        _ => None,
    }
}

/// A session decision that grants everything the request asked for.
#[must_use]
pub fn allow_session(ttl_seconds: u64, uses: u32) -> Decision {
    Decision::AllowSession { ttl_seconds, uses }
}

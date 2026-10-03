//! Shared fixtures for the agent-fill suites (ADR-0036): a real vault on disk, a real MCP
//! [`Agent`] and a real [`ExtensionAgent`] sharing one approval queue and one agent-fill broker,
//! a stand-in for the app's approval UI, and a stand-in for the extension's service worker.
//!
//! The service worker is a fake only in that it is not JavaScript: it connects to the real
//! extension socket, says the real `Hello`, receives the real pushes over the duplex client and
//! answers them with the requests `extensions/shared/background.js` sends — a `TargetReport`
//! stamped with the facts a test chooses, then an `AgentFill` and an `AgentFillOutcome`. That is
//! what lets a test change exactly one of those facts between the report and the redemption.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kagisecure_agent::approval::{
    ApprovalKind, ApprovalQueue, ApprovalRequest, ClientVerification, Decision,
};
use kagisecure_agent::{
    Agent, AgentConfig, AgentFillBroker, AgentFillClock, AgentFillTimings, Endpoint,
    ExtensionAgent, ExtensionConfig, VaultHandle,
};
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::model::{Field, Item, Secret, VaultMeta};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::protocol::{
    AgentFillFailure, AgentFillField as PageField, Capability, FoundFields, PageContext, Push,
    Request as ExtRequest, Response as ExtResponse, TabFacts,
};
use kagisecure_extension_ipc::{Client as ExtClient, DuplexClient, PINNED_EXTENSION_IDS};
use kagisecure_ipc::protocol::{AgentFillField, ClientInfo, Request, Response};

/// A 32-byte marker seeded as the login's password. If these bytes reach anything the sidecar
/// is sent, the product has failed at the one thing it exists to do.
pub const MARKER: &str = "K4G1-AG3NT-F1LL-7c2e90d4b51a83f6";

/// The site the login is saved for.
pub const SAVED: &str = "https://example.com";

/// The page the fills happen on: a subdomain of the saved site, which the one rule covers.
pub const PAGE: &str = "https://login.example.com";

/// A look-alike of the saved site.
pub const LOOK_ALIKE: &str = "https://examp1e.com";

/// The one-time-password seed of [`Fixture::with_code`], in Base32. Distinctive, so finding it
/// anywhere is unambiguous; like the password, it must reach nothing the sidecar writes.
pub const CODE_SEED_B32: &str = "KRUGKIDTMVSWIIDPMYQGC3RAMFTWK3TUEBTGS3DM";

/// [`Fixture::with_code`]'s one-time-password setup: eight digits, so a code is long enough to
/// look for in a sidecar's output without matching by chance.
pub fn code_uri() -> String {
    format!("otpauth://totp/Example:alice?secret={CODE_SEED_B32}&issuer=Example&digits=8")
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub handle: Arc<VaultHandle>,
    pub queue: Arc<ApprovalQueue>,
    pub broker: Arc<AgentFillBroker>,
    /// The clock the broker's limits read: moves only when a test advances it.
    pub clock: AgentFillClock,
    pub agent: Agent,
    /// Behind a mutex so a test can stop it while a request is in flight.
    pub extension: Mutex<ExtensionAgent>,
    pub agent_endpoint: Endpoint,
    pub extension_endpoint: Endpoint,
    /// An agent-visible login at [`SAVED`], password [`MARKER`].
    pub item: String,
    /// The same login, not visible to agents.
    pub hidden: String,
    /// The same login, visible itself but in a logical vault agents may not see.
    pub in_hidden_vault: String,
    /// The same login, in the trash.
    pub trashed: String,
    /// The same login, archived.
    pub archived: String,
    /// An agent-visible login with a username and no password.
    pub no_password: String,
    /// An agent-visible login at [`SAVED`], password [`MARKER`], with a one-time password
    /// ([`code_uri`]).
    pub with_code: String,
}

/// A fixture with agent fills switched **on** and the production timings.
pub fn fixture() -> Fixture {
    fixture_with(AgentFillTimings::default())
}

/// A fixture with agent fills switched on and `timings`.
pub fn fixture_with(timings: AgentFillTimings) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) =
        Vault::create(dir.path().join("test.kagivault"), b"pw", &options).expect("create");
    let vault_id = vault.default_vault_id().expect("default vault");
    let hidden_vault = VaultMeta::new("Hidden");
    let hidden_vault_id = hidden_vault.id;

    let login = |title: &str, vault| {
        let mut item = Item::new(vault, Category::Login, title);
        item.urls = vec![SAVED.to_owned()];
        item.fields.push(Field::public("username", "alice"));
        item.fields.push(Field::concealed(
            "password",
            Secret::from_string(MARKER.to_owned()),
        ));
        item.agent_visible = true;
        item
    };
    let item = login("Example (work)", vault_id);
    let mut hidden = login("Example (hidden)", vault_id);
    hidden.agent_visible = false;
    let in_hidden_vault = login("Example (hidden vault)", hidden_vault_id);
    let mut trashed = login("Example (trashed)", vault_id);
    trashed.trashed_at = Some(kagisecure_core::unix_now());
    let mut archived = login("Example (archived)", vault_id);
    archived.archived = true;
    let mut no_password = Item::new(vault_id, Category::Login, "Example (no password)");
    no_password.urls = vec![SAVED.to_owned()];
    no_password.fields.push(Field::public("username", "bob"));
    no_password.agent_visible = true;
    let mut with_code = login("Example (with a code)", vault_id);
    with_code.fields.push(Field::totp(
        "one-time password",
        Secret::from_string(code_uri()),
    ));

    let ids = [
        &item,
        &hidden,
        &in_hidden_vault,
        &trashed,
        &archived,
        &no_password,
        &with_code,
    ]
    .map(|i| i.id.to_string());
    vault
        .transact(|tx| {
            tx.set_vault_agent_visible(vault_id, true);
            tx.add_logical_vault(hidden_vault);
            for i in [
                item,
                hidden,
                in_hidden_vault,
                trashed,
                archived,
                no_password,
                with_code,
            ] {
                tx.add_item(i);
            }
            Ok(())
        })
        .expect("save");

    let handle = VaultHandle::new(vault);
    let queue = Arc::new(ApprovalQueue::new());
    let clock = AgentFillClock::manual_for_test();
    let broker = Arc::new(AgentFillBroker::with_clock_for_test(timings, clock.clone()));
    broker.set_enabled(true);
    let Listeners {
        agent,
        extension,
        agent_endpoint,
        extension_endpoint,
    } = listen(dir.path(), "", &handle, &queue, &broker);

    let [
        item,
        hidden,
        in_hidden_vault,
        trashed,
        archived,
        no_password,
        with_code,
    ] = ids;
    Fixture {
        dir,
        handle,
        queue,
        broker,
        clock,
        agent,
        extension: Mutex::new(extension),
        agent_endpoint,
        extension_endpoint,
        item,
        hidden,
        in_hidden_vault,
        trashed,
        archived,
        no_password,
        with_code,
    }
}

/// The MCP and extension listeners of one unlock session.
pub struct Listeners {
    pub agent: Agent,
    pub extension: ExtensionAgent,
    pub agent_endpoint: Endpoint,
    pub extension_endpoint: Endpoint,
}

/// Start both listeners over `handle`, sharing `queue` and `broker`, as the app does on unlock.
fn listen(
    dir: &std::path::Path,
    suffix: &str,
    handle: &Arc<VaultHandle>,
    queue: &Arc<ApprovalQueue>,
    broker: &Arc<AgentFillBroker>,
) -> Listeners {
    let agent_endpoint = Endpoint::for_instance(dir, &format!("agent{suffix}.sock"));
    let extension_endpoint = Endpoint::for_instance(dir, &format!("extension{suffix}.sock"));
    let agent = Agent::start(
        Arc::clone(handle),
        &AgentConfig {
            endpoint: Some(agent_endpoint.clone()),
            queue: Some(Arc::clone(queue)),
            agent_fill: Some(Arc::clone(broker)),
        },
    )
    .expect("agent");
    let extension = ExtensionAgent::start(
        Arc::clone(handle),
        ExtensionConfig {
            endpoint: Some(extension_endpoint.clone()),
            allow_unlaunched_host: true,
            agent_fill: Some(Arc::clone(broker)),
            ..ExtensionConfig::new(Arc::clone(queue))
        },
    )
    .expect("extension agent");
    Listeners {
        agent,
        extension,
        agent_endpoint,
        extension_endpoint,
    }
}

impl Fixture {
    pub fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("test.kagivault")
    }

    /// A `request_fill` over a raw IPC client on the agent socket, from this test process — the
    /// sidecar, as far as the kernel is concerned.
    pub fn request_fill(&self, item_id: &str, origin: &str, fields: &[AgentFillField]) -> Response {
        request_fill_at(
            &self.agent_endpoint,
            "example-agent",
            item_id,
            origin,
            fields,
        )
    }

    /// Lock the vault, then unlock it again the way the app does: a fresh handle on the same
    /// file, and fresh listeners on it that share this fixture's queue and — process-wide, like
    /// the FFI's — its broker.
    pub fn lock_and_unlock_again(&self) -> (Arc<VaultHandle>, Listeners) {
        drop(self.handle.take());
        self.extension.lock().expect("listener").stop();
        let vault = Vault::open_with_password(self.path(), b"pw").expect("unlock again");
        let handle = VaultHandle::new(vault);
        let listeners = listen(
            self.dir.path(),
            "-again",
            &handle,
            &self.queue,
            &self.broker,
        );
        (handle, listeners)
    }

    /// The audit log as the file on disk holds it, read by a third party.
    pub fn on_disk(&self) -> Vec<AuditEntry> {
        let vault = Vault::open_with_password(self.path(), b"pw").expect("open the vault file");
        vault.verify_audit().expect("the chain verifies");
        vault.audit_entries().to_vec()
    }

    /// Every `request_fill` entry on disk, as (outcome, detail).
    pub fn fill_entries(&self) -> Vec<(kagisecure_core::proto::Outcome, String)> {
        self.on_disk()
            .into_iter()
            .filter(|e| e.tool == "request_fill")
            .map(|e| (e.outcome, e.detail.unwrap_or_default()))
            .collect()
    }
}

/// Any request on the agent socket from this test process — `lock`, for one.
pub fn agent_call(endpoint: &Endpoint, request: &Request) -> Response {
    let mut client = kagisecure_ipc::client::Client::connect(
        endpoint,
        ClientInfo {
            name: "example-agent".to_owned(),
            version: "0".to_owned(),
            pid: std::process::id(),
            parent_pid: None,
            argv0: "agent-fill-test".to_owned(),
            cwd: None,
        },
    )
    .expect("connect to the agent socket");
    client.call(request).expect("a reply")
}

/// A `request_fill` on `endpoint` from this test process, reporting itself as `name`, and with a
/// made-up parent it would like to be taken for.
pub fn request_fill_at(
    endpoint: &Endpoint,
    name: &str,
    item_id: &str,
    origin: &str,
    fields: &[AgentFillField],
) -> Response {
    let mut client = kagisecure_ipc::client::Client::connect(
        endpoint,
        ClientInfo {
            name: name.to_owned(),
            version: "0".to_owned(),
            pid: std::process::id(),
            parent_pid: Some(1),
            argv0: "agent-fill-test".to_owned(),
            cwd: None,
        },
    )
    .expect("connect to the agent socket");
    client
        .call(&Request::RequestFill {
            item_id: item_id.parse().expect("an item id"),
            origin: origin.to_owned(),
            fields: fields.to_vec(),
        })
        .expect("a reply")
}

/// A real `kagisecure-mcp` sidecar, spawned by this test process — so its parent executable, the
/// key every agent-fill limit is kept under, is this test binary rather than whatever started it.
pub struct SidecarChild {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl SidecarChild {
    /// Spawn the sidecar against `endpoint` and initialize it as an MCP client called `name`.
    pub fn spawn(endpoint: &Endpoint, name: &str) -> Self {
        use std::process::{Command, Stdio};
        let binary =
            kagisecure_test_support::binary("kagisecure-mcp", kagisecure_agent::bundle::SIDECAR);
        let mut child = Command::new(binary)
            .env("KAGISECURE_SOCKET", endpoint.as_override())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn kagisecure-mcp");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut sidecar = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        };
        sidecar.call(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": name, "version": "0"}}),
        );
        sidecar.send(&serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        sidecar
    }

    fn send(&mut self, value: &serde_json::Value) {
        use std::io::Write;
        writeln!(self.stdin, "{value}").expect("write");
        self.stdin.flush().expect("flush");
    }

    /// One JSON-RPC call; returns its `result`.
    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        use std::io::BufRead;
        self.next_id += 1;
        let id = self.next_id;
        self.send(
            &serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        );
        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("read");
            assert!(read > 0, "the sidecar closed its output");
            let value: serde_json::Value = serde_json::from_str(&line).expect("json");
            if value["id"] == id {
                return value["result"].clone();
            }
        }
    }

    /// `request_fill` through the sidecar; returns the tool result's structured content.
    pub fn request_fill(&mut self, item_id: &str, origin: &str) -> serde_json::Value {
        self.call(
            "tools/call",
            serde_json::json!({"name": "request_fill",
                "arguments": {"item_id": item_id, "origin": origin}}),
        )["structuredContent"]
            .clone()
    }

    /// `request_fill` for `fields` through the sidecar; returns the structured content.
    pub fn request_fill_fields(
        &mut self,
        item_id: &str,
        origin: &str,
        fields: &[&str],
    ) -> serde_json::Value {
        self.call(
            "tools/call",
            serde_json::json!({"name": "request_fill",
                "arguments": {"item_id": item_id, "origin": origin, "fields": fields}}),
        )["structuredContent"]
            .clone()
    }
}

impl Drop for SidecarChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Both login fields.
pub fn both() -> Vec<AgentFillField> {
    vec![AgentFillField::Username, AgentFillField::Password]
}

/// The error code of a reply, or `None` for a success.
pub fn code(response: &Response) -> Option<&'static str> {
    match response {
        Response::Error { code, .. } => Some(code.as_str()),
        _ => None,
    }
}

// -------------------------------------------------------------------------------------------------
// The app's approval UI
// -------------------------------------------------------------------------------------------------

/// The app's side of the queue: records every request, then answers it as `decide` says.
pub struct Human {
    seen: Arc<Mutex<Vec<ApprovalRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Human {
    pub fn new(
        queue: &Arc<ApprovalQueue>,
        decide: impl Fn(&ApprovalRequest) -> Option<Decision> + Send + 'static,
    ) -> Self {
        let seen: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::clone(queue);
        let thread_seen = Arc::clone(&seen);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let Some(request) = queue.next(Duration::from_millis(20)) else {
                    continue;
                };
                thread_seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(request.clone());
                if let Some(decision) = decide(&request) {
                    queue.resolve(
                        &request.id,
                        &decision,
                        ClientVerification {
                            verified: false,
                            evidence: "answered by the test's stand-in human".to_owned(),
                        },
                    );
                }
            }
        });
        Self {
            seen,
            stop,
            thread: Some(thread),
        }
    }

    /// Approves every sheet, the way the app does after a biometric.
    pub fn approving(queue: &Arc<ApprovalQueue>) -> Self {
        Self::new(queue, |_| Some(Decision::AllowOnce))
    }

    /// Denies every sheet.
    pub fn denying(queue: &Arc<ApprovalQueue>) -> Self {
        Self::new(queue, |_| Some(Decision::Deny))
    }

    pub fn seen(&self) -> Vec<ApprovalRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// How many agent-fill sheets were raised.
    pub fn sheets(&self) -> usize {
        self.seen()
            .iter()
            .filter(|r| r.kind == ApprovalKind::AgentFill)
            .count()
    }
}

impl Drop for Human {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// -------------------------------------------------------------------------------------------------
// The extension's service worker
// -------------------------------------------------------------------------------------------------

/// The tab a service worker reports for a `Locate`.
#[derive(Clone, Debug)]
pub struct Tab {
    pub page: PageContext,
    pub tab: TabFacts,
    pub found: FoundFields,
}

impl Tab {
    /// The active, visible top frame of `origin`, with a login form.
    pub fn front(origin: &str) -> Self {
        Self {
            page: PageContext::top(origin),
            tab: TabFacts {
                tab_id: 41,
                document_id: Some("doc-a".to_owned()),
                tab_active: true,
                visible: true,
            },
            found: FoundFields {
                username: true,
                password: true,
                one_time_code: false,
            },
        }
    }

    /// Page one of an identifier-first sign-in at `origin`: a username box and no password.
    pub fn identifier_only(origin: &str) -> Self {
        let mut tab = Self::front(origin);
        tab.found = FoundFields {
            username: true,
            password: false,
            one_time_code: false,
        };
        tab
    }

    /// Page two, in the same tab: a new document with a password field.
    pub fn next_page(origin: &str) -> Self {
        let mut tab = Self::front(origin);
        tab.tab.document_id = Some("doc-b".to_owned());
        tab
    }

    /// A page at `origin` that asks for a one-time code and nothing else.
    pub fn code(origin: &str) -> Self {
        let mut tab = Self::front(origin);
        tab.found = FoundFields {
            username: false,
            password: false,
            one_time_code: true,
        };
        tab
    }

    /// What the extension reports when it has nothing to report on.
    pub fn nothing() -> Self {
        Self {
            page: PageContext {
                top_origin: "null".to_owned(),
                frame_origin: None,
                top_origin_established: false,
            },
            tab: TabFacts::default(),
            found: FoundFields::default(),
        }
    }
}

/// What a service worker does when a `Deliver` arrives.
pub enum OnDeliver {
    /// Redeem it from the reported tab, then report what was written.
    Redeem,
    /// Redeem it from the reported tab, changed by the closure first, then report what was
    /// written if anything came back.
    RedeemChanged(Box<dyn Fn(&mut Tab) + Send + Sync>),
    /// Redeem it, and never say what became of it.
    RedeemSilently,
    /// Redeem it, and report that nothing could be written.
    RedeemButFail(AgentFillFailure),
    /// Report that the delivery never reached a document.
    Undeliverable(AgentFillFailure),
    /// Wait `Duration`, then redeem as [`Self::Redeem`] does.
    RedeemAfter(Duration),
    /// Do nothing; the test redeems by hand.
    Hold,
}

/// What a service worker saw and got.
#[derive(Clone, Debug)]
pub enum Seen {
    Locate {
        probe_id: String,
    },
    Deliver {
        probe_id: String,
        grant_id: String,
    },
    /// The reply to an `AgentFill` it sent.
    Filled(ExtResponse),
}

/// What a service worker does: the tab it reports, and what it does with a delivery.
type Script = Arc<Mutex<(Tab, OnDeliver)>>;

/// A connected extension session that declared `agent_fill`, answering pushes on a thread.
pub struct ServiceWorker {
    pub client: Arc<DuplexClient>,
    script: Script,
    seen: Arc<Mutex<Vec<Seen>>>,
    next_id: Arc<Mutex<u64>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServiceWorker {
    /// Connect, say hello with `agent_fill`, and answer every `Locate` with `report` and every
    /// `Deliver` as `on_deliver` says.
    pub fn start(fx: &Fixture, report: Tab, on_deliver: OnDeliver) -> Self {
        Self::connect(&fx.extension_endpoint, report, on_deliver)
    }

    /// [`Self::start`], on the extension listener at `endpoint`.
    pub fn connect(endpoint: &Endpoint, report: Tab, on_deliver: OnDeliver) -> Self {
        let (client, pushes) = hello(endpoint);
        let client = Arc::new(client);
        let script: Script = Arc::new(Mutex::new((report, on_deliver)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let next_id = Arc::new(Mutex::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let client = Arc::clone(&client);
            let script = Arc::clone(&script);
            let seen = Arc::clone(&seen);
            let next_id = Arc::clone(&next_id);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                answer_pushes(&client, &pushes, &seen, &next_id, &stop, &script);
            })
        };
        // The session is registered before `Welcome` is written, so nothing here races it.
        Self {
            client,
            script,
            seen,
            next_id,
            stop,
            thread: Some(thread),
        }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Change what this session reports and does from now on, and forget what it saw.
    pub fn set(&self, report: Tab, on_deliver: OnDeliver) {
        *self.script.lock().unwrap_or_else(|e| e.into_inner()) = (report, on_deliver);
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn locates(&self) -> usize {
        self.seen()
            .iter()
            .filter(|s| matches!(s, Seen::Locate { .. }))
            .count()
    }

    /// The grant id of the first `Deliver`, waiting up to five seconds for one.
    pub fn delivered_grant(&self) -> Option<String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(grant) = self.seen().iter().find_map(|s| match s {
                Seen::Deliver { grant_id, .. } => Some(grant_id.clone()),
                _ => None,
            }) {
                return Some(grant);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Every `AgentFill` reply this session got, once there are at least `n` of them or five
    /// seconds have passed. The agent can be answered a moment before the extension has read its
    /// own reply: the broker settles a redemption before the reply frame is written.
    pub fn fills_at_least(&self, n: usize) -> Vec<ExtResponse> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let fills = self.fills();
            if fills.len() >= n || std::time::Instant::now() >= deadline {
                return fills;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Every `(probe_id, grant_id)` of the `Deliver`s this session saw.
    pub fn deliveries(&self) -> Vec<(String, String)> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Deliver { probe_id, grant_id } => Some((probe_id, grant_id)),
                _ => None,
            })
            .collect()
    }

    /// Every `AgentFill` reply this session got.
    pub fn fills(&self) -> Vec<ExtResponse> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Filled(r) => Some(r),
                _ => None,
            })
            .collect()
    }

    /// Send an `AgentFill` by hand.
    pub fn redeem(&self, grant_id: &str, tab: &Tab) -> ExtResponse {
        call(
            &self.client,
            &self.next_id,
            &ExtRequest::AgentFill {
                grant_id: grant_id.to_owned(),
                page: tab.page.clone(),
                tab: tab.tab.clone(),
                found: tab.found,
            },
        )
    }

    /// Send an `AgentFillOutcome` by hand.
    pub fn report_outcome(
        &self,
        grant_id: &str,
        written: Vec<PageField>,
        failure: Option<AgentFillFailure>,
    ) -> ExtResponse {
        call(
            &self.client,
            &self.next_id,
            &ExtRequest::AgentFillOutcome {
                grant_id: grant_id.to_owned(),
                written,
                failure,
            },
        )
    }
}

impl Drop for ServiceWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Connect to the extension listener at `endpoint` and say `Hello` with `agent_fill`.
fn hello(endpoint: &Endpoint) -> (DuplexClient, Receiver<Push>) {
    let mut client = ExtClient::connect(endpoint).expect("connect");
    let welcome = client
        .call(
            "hello",
            &ExtRequest::Hello {
                extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
                browser: "chrome".to_owned(),
                extension_version: "0.2.0".to_owned(),
                protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
                capabilities: vec![Capability::AgentFill],
            },
        )
        .expect("hello");
    assert!(
        matches!(welcome, ExtResponse::Welcome { .. }),
        "{welcome:?}"
    );
    client.into_duplex().expect("duplex")
}

/// A connected session that declared `agent_fill` and never answers a push, so every probe waits
/// out its whole window for it — which gives a test that window to act in.
pub struct MuteSession {
    _client: DuplexClient,
    pushes: Receiver<Push>,
}

impl MuteSession {
    pub fn start(fx: &Fixture) -> Self {
        let (client, pushes) = hello(&fx.extension_endpoint);
        Self {
            _client: client,
            pushes,
        }
    }

    /// Wait up to five seconds for a `Locate`: the probe has begun.
    pub fn located(&self) -> bool {
        matches!(
            self.pushes.recv_timeout(Duration::from_secs(5)),
            Ok(Push::Locate { .. })
        )
    }
}

fn call(client: &DuplexClient, next_id: &Mutex<u64>, request: &ExtRequest) -> ExtResponse {
    let id = {
        let mut next = next_id.lock().unwrap_or_else(|e| e.into_inner());
        *next += 1;
        format!("sw-{next}")
    };
    client.call(&id, request).expect("a reply from the app")
}

fn answer_pushes(
    client: &DuplexClient,
    pushes: &Receiver<Push>,
    seen: &Mutex<Vec<Seen>>,
    next_id: &Mutex<u64>,
    stop: &AtomicBool,
    script: &Script,
) {
    let record = |s: Seen| seen.lock().unwrap_or_else(|e| e.into_inner()).push(s);
    while !stop.load(Ordering::SeqCst) {
        let Ok(push) = pushes.recv_timeout(Duration::from_millis(20)) else {
            continue;
        };
        let script = script.lock().unwrap_or_else(|e| e.into_inner());
        let (report, on_deliver) = (&script.0, &script.1);
        match push {
            Push::Locate { probe_id, .. } => {
                record(Seen::Locate {
                    probe_id: probe_id.clone(),
                });
                let reply = call(
                    client,
                    next_id,
                    &ExtRequest::TargetReport {
                        probe_id,
                        page: report.page.clone(),
                        tab: report.tab.clone(),
                        found: report.found,
                    },
                );
                assert_eq!(reply, ExtResponse::Noted, "a report is only ever noted");
            }
            Push::Deliver { probe_id, grant_id } => {
                record(Seen::Deliver {
                    probe_id,
                    grant_id: grant_id.clone(),
                });
                let mut tab = report.clone();
                let (redeem, outcome) = match on_deliver {
                    OnDeliver::Hold => (false, None),
                    OnDeliver::Undeliverable(failure) => (false, Some(Some(*failure))),
                    OnDeliver::Redeem => (true, Some(None)),
                    OnDeliver::RedeemChanged(change) => {
                        change(&mut tab);
                        (true, Some(None))
                    }
                    OnDeliver::RedeemSilently => (true, None),
                    OnDeliver::RedeemButFail(failure) => (true, Some(Some(*failure))),
                    OnDeliver::RedeemAfter(wait) => {
                        std::thread::sleep(*wait);
                        (true, Some(None))
                    }
                };
                let mut filled = None;
                if redeem {
                    let reply = call(
                        client,
                        next_id,
                        &ExtRequest::AgentFill {
                            grant_id: grant_id.clone(),
                            page: tab.page.clone(),
                            tab: tab.tab.clone(),
                            found: tab.found,
                        },
                    );
                    filled = Some(written_by(&reply));
                    record(Seen::Filled(reply));
                }
                // The extension sends no outcome after an error reply (the app finishes that
                // request itself), and always one after a delivery it could not redeem.
                let written = |r: &Option<Vec<PageField>>| r.clone().unwrap_or_default();
                let wrote = filled.as_ref().map(|w| !w.is_empty());
                match (outcome, wrote) {
                    (Some(None), Some(true)) => {
                        call(
                            client,
                            next_id,
                            &ExtRequest::AgentFillOutcome {
                                grant_id,
                                written: written(&filled),
                                failure: None,
                            },
                        );
                    }
                    (Some(Some(failure)), Some(true) | None) => {
                        call(
                            client,
                            next_id,
                            &ExtRequest::AgentFillOutcome {
                                grant_id,
                                written: Vec::new(),
                                failure: Some(failure),
                            },
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The fields a reply to `AgentFill` would have the content script write — what it reports as
/// written once it has: the fields a `filled` carries, the code of a `totp_code`, or nothing.
fn written_by(reply: &ExtResponse) -> Vec<PageField> {
    match reply {
        ExtResponse::Filled {
            username, password, ..
        } => {
            let mut written = Vec::new();
            if username.is_some() {
                written.push(PageField::Username);
            }
            if password.is_some() {
                written.push(PageField::Password);
            }
            written
        }
        ExtResponse::TotpCode { .. } => vec![PageField::OneTimeCode],
        _ => Vec::new(),
    }
}

/// Anything a test serializes to look for the marker in.
pub trait Json {
    fn json(&self) -> String;
}

macro_rules! json {
    ($($t:ty),*) => {$(
        impl Json for $t {
            fn json(&self) -> String {
                serde_json::to_string(self).expect("serializes")
            }
        }
    )*};
}
json!(Response, ExtResponse, AuditEntry, String);

/// Whether `value`, serialized, contains the marker anywhere.
pub fn carries_marker(value: &impl Json) -> bool {
    value.json().contains(MARKER)
}

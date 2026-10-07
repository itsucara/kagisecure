//! The unattended engine (ADR-0042 Phase 2), end to end on real processes: arming and resuming,
//! the unattended socket's refusal of anything outside a run, a real run releasing a granted
//! command through the real sidecar with the ADR-0002 canary, every protocol message sent from
//! inside a run creating nothing, the scheduler, and the ordinary socket's reads of the machine
//! vault.
//!
//! Unix only: runs are process groups, and binding walks the kernel's parent links.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kagisecure_agent::approval::{ClientVerification, Decision};
use kagisecure_agent::unattended::schedule::ManualClock;
use kagisecure_agent::{
    Agent, AgentConfig, RunBrowserSetup, UnattendedConfig, UnattendedEngine, VaultHandle,
};
use kagisecure_core::model::{Environment, Field, Item, Secret, VarSource};
use kagisecure_core::proto::{
    Category, EnvId, FieldId, ItemId, LeaseId, Outcome, VarName, VaultId,
};
use kagisecure_core::vault::machine::{
    CommandGrant, ExecutablePin, GrantId, GrantLimits, Job, JobId, MachineSection,
    PinnedExecutable, PresencePath, ScheduleTime, file_sha256, machine_vault_path,
};
use kagisecure_core::vault::{CreateOptions, MachineVaultKey, Vault};
use kagisecure_ipc::client::self_info;
use kagisecure_ipc::protocol::{
    AgentFillField, ErrorCode, FieldRef, OutputMode, Request, Response, VariableRequest,
};
use kagisecure_ipc::{Client, Endpoint};

/// Seeded as the machine credential. It must reach the granted command and nothing else.
const MARKER: &str = "K4G1-UN4TT3ND3D-7d2e91c4b0a35f86";

/// The file, beside the unattended socket, the in-run child writes its replies to.
const CHILD_REPLIES: &str = "child-replies.jsonl";

struct Fixture {
    dir: tempfile::TempDir,
    personal: Arc<VaultHandle>,
    personal_path: PathBuf,
    machine_path: PathBuf,
    key: Vec<u8>,
    engine: UnattendedEngine,
    endpoint: Endpoint,
    project: PathBuf,
    env_id: EnvId,
    clock: Arc<ManualClock>,
}

fn cheap_options() -> CreateOptions {
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options
}

fn sha_pin(path: &str) -> PinnedExecutable {
    PinnedExecutable {
        path: path.to_owned(),
        pin: ExecutablePin::Sha256(file_sha256(Path::new(path)).expect("hash").to_vec()),
    }
}

fn job(name: &str, root: PinnedExecutable, args: Vec<String>, dir: &Path) -> Job {
    Job {
        id: JobId::new(),
        name: name.to_owned(),
        root,
        args,
        working_dir: dir.to_string_lossy().into_owned(),
        schedule: vec![ScheduleTime::Daily { hour: 3, minute: 0 }],
        run_deadline_secs: 120,
        catch_up_secs: 0,
        run_browser: None,
        created_at: kagisecure_core::unix_now(),
        presence: PresencePath::Confirmed,
        unknown: BTreeMap::new(),
    }
}

/// The command the canary job's grant lets it run: writes the injected value to a file in the
/// project, so the test can see the release happened.
fn granted_args() -> Vec<String> {
    vec![
        "-c".to_owned(),
        "printf %s \"$TOKEN\" > released.txt".to_owned(),
    ]
}

fn fixture() -> Fixture {
    fixture_with(|_| None)
}

/// A fixture whose engine starts run browsers as `run_browser` says, given the fixture's root.
fn fixture_with(run_browser: impl FnOnce(&Path) -> Option<RunBrowserSetup>) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    let project = root.join("project");
    std::fs::create_dir_all(&project).expect("project");
    let personal_path = root.join("personal.kagivault");
    let machine_path = machine_vault_path(&personal_path);

    let (mut personal, _code) =
        Vault::create(&personal_path, b"pw", &cheap_options()).expect("create personal");
    let key = MachineVaultKey::generate().expect("key");
    let key_bytes = key.to_keychain_bytes().to_vec();
    let mut machine = Vault::create_machine(&machine_path, &key, "Machine").expect("machine");
    personal
        .transact(|tx| tx.set_machine_vault_key(key, "test"))
        .expect("store key");

    let env_id = machine
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            tx.set_vault_agent_visible(vault_id, true);
            let mut item = Item::new(vault_id, Category::ApiCredential, "Deploy token");
            item.fields.push(Field::concealed(
                "token",
                Secret::from_string(MARKER.to_owned()),
            ));
            item.agent_visible = true;
            let field = item.fields[0].id;
            let mut env = Environment::new(vault_id, "deploy");
            env.agent_visible = true;
            env.set_var(
                VarName::new("TOKEN".to_owned()).expect("name"),
                VarSource::ItemField {
                    item: item.id,
                    field,
                },
            );
            let env_id = env.id;
            tx.add_item(item);
            tx.add_environment(env);
            Ok(env_id)
        })
        .expect("seed machine vault");
    drop(machine);

    let endpoint = Endpoint::for_instance(&root, "unattended.sock");
    let clock = Arc::new(ManualClock::new(1_790_510_400, 0));
    let engine = UnattendedEngine::start(&UnattendedConfig {
        endpoint: Some(endpoint.clone()),
        machine_path: machine_path.clone(),
        tick: Duration::from_secs(3600),
        clock: Some(Arc::clone(&clock) as Arc<dyn kagisecure_agent::unattended::schedule::Clock>),
        run_browser: run_browser(&root),
    })
    .expect("engine");
    Fixture {
        dir,
        personal: VaultHandle::new(personal),
        personal_path,
        machine_path,
        key: key_bytes,
        engine,
        endpoint,
        project,
        env_id,
        clock,
    }
}

impl Fixture {
    fn arm(&self) {
        let bytes = self
            .engine
            .arm(&self.personal, PresencePath::Confirmed, "app")
            .expect("arm");
        assert_eq!(bytes.as_slice(), self.key.as_slice());
    }

    /// A fresh read of the machine vault file.
    fn machine(&self) -> Vault {
        let key = MachineVaultKey::from_keychain_bytes(&self.key).expect("key");
        Vault::open_machine(&self.machine_path, &key).expect("open machine")
    }

    fn section(&self) -> MachineSection {
        self.machine().machine().expect("a machine vault").clone()
    }

    /// Add `job` and a command grant for it over the `deploy` environment, approved now.
    fn add_job(&self, job: &Job, grant_args: Vec<String>) -> GrantId {
        let grant_id = GrantId::new();
        let now = kagisecure_core::unix_now();
        let grant = CommandGrant {
            id: grant_id,
            job: job.id,
            env: self.env_id,
            variables: vec!["TOKEN".to_owned()],
            executable: sha_pin("/bin/sh"),
            args: grant_args,
            working_dir: self.project.to_string_lossy().into_owned(),
            pinned_inputs: Vec::new(),
            timeout_secs: 30,
            limits: GrantLimits::defaults(now),
            uses: 0,
            created_at: now,
            approved_at: now + 1,
            presence: PresencePath::Confirmed,
            suspended: None,
            unknown: BTreeMap::new(),
        };
        let key = MachineVaultKey::from_keychain_bytes(&self.key).expect("key");
        let mut machine = Vault::open_machine(&self.machine_path, &key).expect("open");
        let job = job.clone();
        machine
            .transact(|tx| {
                let section = tx.machine_mut()?;
                section.jobs.push(job);
                section.command_grants.push(grant);
                Ok(())
            })
            .expect("add job");
        grant_id
    }

    fn client(&self) -> Client {
        Client::connect(&self.endpoint, self_info("unattended-test", "0")).expect("connect")
    }

    fn wait_for_runs_to_end(&self) {
        let started = Instant::now();
        while !self.engine.status().runs.is_empty() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the run did not end: {:?}",
                self.engine.status()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The monitor records the end just before it removes the run.
        std::thread::sleep(Duration::from_millis(100));
    }

    fn details(&self) -> Vec<String> {
        self.machine()
            .audit_entries()
            .iter()
            .filter_map(|e| e.detail.clone())
            .collect()
    }
}

fn run_request(env: EnvId, cwd: &Path) -> Request {
    Request::RunWithEnv {
        environment_id: env,
        command: "/bin/sh".to_owned(),
        args: granted_args(),
        cwd: cwd.to_string_lossy().into_owned(),
        variables: Some(vec!["TOKEN".to_owned()]),
        timeout_seconds: 30,
        output: OutputMode::Scrubbed,
        delivery: kagisecure_ipc::protocol::Delivery::Environment,
    }
}

fn code(response: &Response) -> Option<ErrorCode> {
    match response {
        Response::Error { code, .. } => Some(*code),
        _ => None,
    }
}

// -------------------------------------------------------------------------------------------------
// Arming
// -------------------------------------------------------------------------------------------------

#[test]
fn arming_persists_until_a_person_disarms() {
    let mut fx = fixture();
    assert!(!fx.engine.is_armed());
    fx.arm();
    assert!(fx.engine.is_armed());
    assert!(
        fx.section().arm.is_some(),
        "the arm is recorded in the body"
    );
    let personal_log: Vec<String> = fx
        .personal
        .with(|v| {
            v.audit_entries()
                .iter()
                .filter_map(|e| e.detail.clone())
                .collect()
        })
        .expect("unlocked");
    assert!(
        personal_log
            .iter()
            .any(|d| d == "ARMED (PRESENCE_CONFIRMED)"),
        "{personal_log:?}"
    );

    // The app quits: the arm stays, and a new engine resumes from the Keychain's bytes alone.
    fx.engine.stop();
    let engine = UnattendedEngine::start(&UnattendedConfig {
        endpoint: Some(Endpoint::for_instance(fx.dir.path(), "second.sock")),
        ..UnattendedConfig::new(fx.machine_path.clone())
    })
    .expect("second engine");
    assert!(engine.resume(&fx.key).expect("resume"), "resumed armed");
    assert!(engine.is_armed());

    // A person pauses: the arm record goes, and the next resume refuses.
    assert!(engine.disarm(Some(&fx.personal), "app"));
    assert!(!engine.is_armed());
    assert!(fx.section().arm.is_none());
    assert!(
        !engine.resume(&fx.key).expect("resume"),
        "disarmed stays disarmed"
    );
    assert!(
        engine
            .take_notices()
            .iter()
            .any(|n| n.kind == "DISARMED" && n.reason == "PAUSED")
    );
    let _ = fx.personal_path;
}

#[test]
fn arming_needs_the_personal_vault_unlocked() {
    let fx = fixture();
    drop(fx.personal.take());
    assert!(matches!(
        fx.engine.arm(&fx.personal, PresencePath::Confirmed, "app"),
        Err(kagisecure_agent::UnattendedError::Locked)
    ));
}

// -------------------------------------------------------------------------------------------------
// The unattended socket, from outside any run
// -------------------------------------------------------------------------------------------------

#[test]
fn a_request_from_outside_a_run_is_refused() {
    let fx = fixture();
    let job = job("deploy", sha_pin("/bin/sh"), Vec::new(), &fx.project);
    fx.add_job(&job, granted_args());

    // Disarmed: paused, before anything is looked at.
    let mut client = fx.client();
    let reply = client
        .call(&run_request(fx.env_id, &fx.project))
        .expect("call");
    assert_eq!(code(&reply), Some(ErrorCode::UnattendedPaused), "{reply:?}");

    // Armed, with a grant that covers this exact request: still refused, because the test process
    // is in no run kagisecure started.
    fx.arm();
    let reply = client
        .call(&run_request(fx.env_id, &fx.project))
        .expect("call");
    assert_eq!(code(&reply), Some(ErrorCode::NotGranted), "{reply:?}");
    assert!(!fx.project.join("released.txt").exists(), "nothing ran");
    assert!(
        fx.details()
            .iter()
            .any(|d| d == "NOT_GRANTED (OUTSIDE_RUN)"),
        "{:?}",
        fx.details()
    );
    // Not a strike: nobody's grants are suspended by a stranger knocking.
    assert!(
        fx.section()
            .command_grants
            .iter()
            .all(|g| g.suspended.is_none())
    );

    // `request_fill` from outside a run is refused like everything else, and is no strike.
    let reply = client
        .call(&Request::RequestFill {
            item_id: ItemId::new(),
            origin: "https://example.com".to_owned(),
            fields: vec![AgentFillField::Password],
        })
        .expect("call");
    assert_eq!(code(&reply), Some(ErrorCode::NotGranted), "{reply:?}");
}

/// Every message the protocol has, with plausible arguments. The `match` in [`covers`] has no
/// wildcard: a new `Request` variant does not compile until it is added here.
fn every_request(env: EnvId, cwd: &Path) -> Vec<Request> {
    let requests = vec![
        Request::ListVaults,
        Request::ListItems {
            vault_id: None,
            query: None,
            category: None,
            limit: 10,
            cursor: None,
        },
        Request::ListEnvironments { vault_id: None },
        Request::DescribeItem {
            item_id: ItemId::new(),
        },
        Request::CreateEnvironment {
            vault_id: Some(VaultId::new()),
            name: "made by an agent".to_owned(),
            description: None,
        },
        Request::AddVariables {
            environment_id: env,
            variables: vec![VariableRequest {
                name: "NEW".to_owned(),
                bind_to: Some(FieldRef {
                    item_id: ItemId::new(),
                    field_id: FieldId::new(),
                }),
                hint: None,
            }],
        },
        Request::RequestFill {
            item_id: ItemId::new(),
            origin: "https://example.com".to_owned(),
            fields: vec![AgentFillField::Password],
        },
        Request::RevokeEnvFile {
            lease_id: Some(LeaseId::new()),
            path: None,
        },
        Request::CreateTestLogin {
            app: "shop".to_owned(),
            purpose: "buyer".to_owned(),
            username: "buyer1@example.test".to_owned(),
            websites: vec!["http://localhost:47800".to_owned()],
            generator: None,
            tags: Vec::new(),
            reason: None,
            bind: None,
        },
        Request::TrashTestLogins {
            website: Some("http://localhost:47800".to_owned()),
            tag: None,
            reason: "rebuild".to_owned(),
        },
        Request::ListTestLogins {
            website: None,
            tag: None,
            query: None,
            limit: 10,
            cursor: None,
        },
        Request::Audit {
            limit: 5,
            verify: false,
        },
        Request::ListLeases,
        Request::WriteEnvFile {
            environment_id: env,
            directory: cwd.to_string_lossy().into_owned(),
            filename: ".env".to_owned(),
            variables: None,
            overwrite: false,
            ttl_seconds: 60,
        },
        Request::RunWithEnv {
            environment_id: env,
            command: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "true".to_owned()],
            cwd: cwd.to_string_lossy().into_owned(),
            variables: None,
            timeout_seconds: 5,
            output: OutputMode::None,
            delivery: kagisecure_ipc::protocol::Delivery::Environment,
        },
        // Stdin delivery is one approval per run (ADR-0047): no standing grant covers it.
        Request::RunWithEnv {
            environment_id: env,
            command: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "cat > /dev/null".to_owned()],
            cwd: cwd.to_string_lossy().into_owned(),
            variables: None,
            timeout_seconds: 5,
            output: OutputMode::None,
            delivery: kagisecure_ipc::protocol::Delivery::Stdin,
        },
        Request::Hello {
            protocol: kagisecure_ipc::protocol::PROTOCOL_VERSION,
            client: self_info("x", "0"),
        },
        Request::Lock,
    ];
    for r in &requests {
        covers(r);
    }
    requests
}

fn covers(request: &Request) {
    match request {
        Request::Hello { .. }
        | Request::ListVaults
        | Request::ListItems { .. }
        | Request::ListEnvironments { .. }
        | Request::DescribeItem { .. }
        | Request::CreateEnvironment { .. }
        | Request::AddVariables { .. }
        | Request::WriteEnvFile { .. }
        | Request::RunWithEnv { .. }
        | Request::RevokeEnvFile { .. }
        | Request::RequestFill { .. }
        | Request::CreateTestLogin { .. }
        | Request::ListTestLogins { .. }
        | Request::TrashTestLogins { .. }
        | Request::Audit { .. }
        | Request::ListLeases
        | Request::Lock => {}
    }
}

/// The jobs and grants, with the fields a release or a strike may legitimately change — use
/// counts and suspensions — cleared, so what is left is what no request may change.
fn definitions(section: &MachineSection) -> (Vec<Job>, Vec<CommandGrant>) {
    let grants = section
        .command_grants
        .iter()
        .cloned()
        .map(|mut g| {
            g.uses = 0;
            g.suspended = None;
            g
        })
        .collect();
    (section.jobs.clone(), grants)
}

#[test]
fn no_protocol_message_creates_or_changes_a_job_or_a_grant() {
    let fx = fixture();
    let job = job("deploy", sha_pin("/bin/sh"), Vec::new(), &fx.project);
    fx.add_job(&job, granted_args());
    fx.arm();
    let before = definitions(&fx.section());

    // From outside any run, on the unattended socket: every message.
    for request in every_request(fx.env_id, &fx.project) {
        let mut client = fx.client();
        let _ = client.call(&request).expect("call");
        if matches!(request, Request::Lock) {
            // Pausing is allowed to anyone; arm again for the rest.
            fx.arm();
        }
    }
    assert_eq!(definitions(&fx.section()), before);

    // And from inside a run: the child below sends them all from a real run's process tree.
    let exe = std::env::current_exe().expect("test binary");
    let exe = exe.to_string_lossy().into_owned();
    let child = self::job(
        "enumerate",
        sha_pin(&exe),
        vec![
            "unattended_child_entry_point".to_owned(),
            "--exact".to_owned(),
            "--ignored".to_owned(),
            "--test-threads=1".to_owned(),
        ],
        &fx.project,
    );
    fx.add_job(&child, vec!["-c".to_owned(), "true".to_owned()]);
    let before = definitions(&fx.section());
    fx.engine.run_now(child.id).expect("run");
    fx.wait_for_runs_to_end();

    let replies =
        std::fs::read_to_string(fx.dir.path().canonicalize().unwrap().join(CHILD_REPLIES))
            .expect("the child wrote its replies");
    assert!(replies.contains("NOT_GRANTED"), "{replies}");
    // Agent test logins are personal and interactive only (ADR-0048 §12): a create or a trash is refused
    // inside a run, and the list is empty.
    let line = |tool: &str| {
        replies
            .lines()
            .find(|l| l.starts_with(&format!("{tool} ")))
            .unwrap_or_else(|| panic!("no reply for {tool}: {replies}"))
            .to_owned()
    };
    assert!(
        line("create_test_login").contains("NOT_GRANTED"),
        "{replies}"
    );
    assert!(
        line("list_test_logins").contains(r#""items":[]"#),
        "{replies}"
    );
    assert!(
        line("trash_test_logins").contains("NOT_GRANTED"),
        "{replies}"
    );
    assert_eq!(
        definitions(&fx.section()),
        before,
        "nothing was created or changed"
    );
    // `write_env_file` from inside a run is a strike: every grant of that job is suspended and
    // the run ended.
    let section = fx.section();
    let grant = section
        .command_grants
        .iter()
        .find(|g| g.job == child.id)
        .expect("grant");
    assert_eq!(
        grant.suspended.as_ref().map(|s| s.reason.as_str()),
        Some("NO_GRANT")
    );
    let details = fx.details();
    assert!(
        details
            .iter()
            .any(|d| d.starts_with("GRANT_SUSPENDED (NO_GRANT)")),
        "{details:?}"
    );
    assert!(details.iter().any(|d| d.contains("STRIKE")), "{details:?}");
}

/// Not a test on its own: the root of the enumeration job above. It runs in a run's process
/// tree, sends every message but `lock` in order — `write_env_file` last, since it ends the run —
/// and appends each reply to [`CHILD_REPLIES`] beside the socket.
#[test]
#[ignore = "entry point of a job the unattended tests start, not a test of its own"]
fn unattended_child_entry_point() {
    use std::io::Write;

    let Some(socket) = std::env::var_os("KAGISECURE_SOCKET") else {
        return;
    };
    let socket = PathBuf::from(socket);
    let dir = socket.parent().expect("socket dir").to_path_buf();
    let cwd = dir.join("project");
    let endpoint = Endpoint::discover().expect("endpoint");
    let mut client = Client::connect(&endpoint, self_info("child", "0")).expect("connect");
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(CHILD_REPLIES))
        .expect("replies file");
    let mut requests: Vec<Request> = every_request(EnvId::new(), &cwd)
        .into_iter()
        .filter(|r| !matches!(r, Request::Lock | Request::Hello { .. }))
        .collect();
    // The strikes last: `request_fill` with no login grant, then `write_env_file`.
    requests.sort_by_key(|r| match r {
        Request::RequestFill { .. } => 1,
        Request::WriteEnvFile { .. } | Request::RunWithEnv { .. } => 2,
        _ => 0,
    });
    requests.retain(|r| !matches!(r, Request::RunWithEnv { .. }));
    for request in requests {
        let reply = client.call(&request);
        let line = match reply {
            Ok(reply) => serde_json::to_string(&reply).expect("json"),
            Err(e) => format!("\"{e}\""),
        };
        writeln!(out, "{} {line}", request.tool_name()).expect("write");
        out.flush().expect("flush");
    }
}

// -------------------------------------------------------------------------------------------------
// A real run, a real sidecar, and the canary
// -------------------------------------------------------------------------------------------------

fn sidecar() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-mcp", kagisecure_agent::bundle::SIDECAR)
}

#[test]
fn a_granted_command_runs_unattended_and_the_value_reaches_no_byte_the_sidecar_writes() {
    let fx = fixture();
    let project = fx.project.to_string_lossy().into_owned();
    let calls = [
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "unattended-job", "version": "0"}}}),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "run_with_env", "arguments": {
            "environment_id": fx.env_id.to_string(),
            "command": "/bin/sh",
            "args": granted_args(),
            "cwd": project,
            "variables": ["TOKEN"]
        }}}),
    ];
    let input: String = calls.iter().map(|c| format!("{c}\n")).collect();
    std::fs::write(fx.project.join("in.jsonl"), input).expect("input");
    // Keep the sidecar's stdin open until its answer to the call is out, then let it finish.
    let script = format!(
        "( cat in.jsonl; i=0; while [ $i -lt 300 ] && ! grep -q '\"id\":2' out.jsonl \
         2>/dev/null; do sleep 0.1; i=$((i+1)); done ) | '{}' > out.jsonl 2> err.txt",
        sidecar().display()
    );
    let job = job(
        "canary",
        sha_pin("/bin/sh"),
        vec!["-c".to_owned(), script],
        &fx.project,
    );
    let grant = fx.add_job(&job, granted_args());
    fx.arm();

    fx.engine.run_now(job.id).expect("run");
    fx.wait_for_runs_to_end();

    let released =
        std::fs::read_to_string(fx.project.join("released.txt")).expect("the granted command ran");
    assert_eq!(released, MARKER, "the value reached the granted command");

    let out = std::fs::read(fx.project.join("out.jsonl")).expect("sidecar output");
    let err = std::fs::read(fx.project.join("err.txt")).unwrap_or_default();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("\"exit_code\":0"), "{text}");
    for bytes in [&out, &err] {
        assert!(
            !bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
            "the canary reached the sidecar's output"
        );
    }

    let section = fx.section();
    let used = section
        .command_grants
        .iter()
        .find(|g| g.id == grant)
        .expect("grant");
    assert_eq!(used.uses, 1);
    assert!(used.suspended.is_none());
    let machine = fx.machine();
    let entries = machine.audit_entries();
    let allowed = entries
        .iter()
        .find(|e| {
            e.tool == "run_with_env"
                && e.outcome == Outcome::Allowed
                && e.detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with(&format!("UNATTENDED_GRANT {grant} RUN")))
        })
        .expect("the release was recorded before it happened");
    assert!(
        allowed
            .actor
            .starts_with("mcp unattended \"canary\" run 1 pid "),
        "{}",
        allowed.actor
    );
    let details = fx.details();
    assert!(
        details.iter().any(|d| d.starts_with("JOB_STARTED (run 1")),
        "{details:?}"
    );
    assert!(
        details.iter().any(|d| d.starts_with("JOB_ENDED (run 1")),
        "{details:?}"
    );
    // Nothing in the machine log carries the value either.
    let log = format!("{:?}", entries);
    assert!(!log.contains(MARKER));
}

// -------------------------------------------------------------------------------------------------
// The scheduler
// -------------------------------------------------------------------------------------------------

#[test]
fn the_scheduler_starts_a_job_at_its_time_once_and_records_one_it_missed() {
    let fx = fixture();
    let mut job = job("nightly", sha_pin("/usr/bin/true"), Vec::new(), &fx.project);
    // 12:01 UTC; the clock starts at 12:00 UTC on a Sunday, with offset 0.
    job.schedule = vec![ScheduleTime::Daily {
        hour: 12,
        minute: 1,
    }];
    fx.add_job(&job, granted_args());
    fx.arm();

    fx.engine.tick();
    assert!(fx.engine.status().runs.is_empty(), "not yet");

    fx.clock.set(1_790_510_400 + 90);
    fx.engine.tick();
    fx.wait_for_runs_to_end();
    fx.engine.tick();
    fx.wait_for_runs_to_end();
    let started = fx
        .details()
        .iter()
        .filter(|d| d.starts_with("JOB_STARTED"))
        .count();
    assert_eq!(started, 1, "started once: {:?}", fx.details());

    // The next day's time passes while the Mac sleeps; waking ten minutes late misses it.
    fx.clock.set(1_790_510_400 + 86_400 + 60 + 600);
    fx.engine.tick();
    assert!(
        fx.details()
            .iter()
            .any(|d| d == "JOB_MISSED (job \"nightly\", TOO_LATE)"),
        "{:?}",
        fx.details()
    );
    assert!(fx.engine.status().runs.is_empty());
}

// -------------------------------------------------------------------------------------------------
// The ordinary socket reads the machine vault, with the ordinary sheet
// -------------------------------------------------------------------------------------------------

fn with_ui<T: Send>(agent: &Agent, f: impl FnOnce() -> T + Send) -> T {
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let ui_stop = Arc::clone(&stop);
        scope.spawn(move || {
            while !ui_stop.load(Ordering::SeqCst) {
                if let Some(request) = agent.next_request(Duration::from_millis(50)) {
                    agent.resolve(
                        &request.id,
                        &Decision::AllowOnce,
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
        out
    })
}

#[test]
fn the_ordinary_socket_serves_machine_environments_with_a_sheet_and_only_while_unlocked() {
    let fx = fixture();
    let ordinary = Endpoint::for_instance(fx.dir.path(), "daemon.sock");
    let agent = Agent::start(
        Arc::clone(&fx.personal),
        &AgentConfig {
            endpoint: Some(ordinary.clone()),
            queue: None,
            agent_fill: None,
            test_logins: None,
        },
    )
    .expect("agent");
    let key = MachineVaultKey::from_keychain_bytes(&fx.key).expect("key");
    agent.attach_machine_vault(Some(VaultHandle::new(
        Vault::open_machine(&fx.machine_path, &key).expect("open"),
    )));

    let mut client = Client::connect(&ordinary, self_info("interactive", "0")).expect("connect");
    let listed = client
        .call(&Request::ListEnvironments { vault_id: None })
        .expect("call");
    let Response::Environments { environments } = listed else {
        panic!("{listed:?}");
    };
    assert!(
        environments.iter().any(|e| e.id == fx.env_id),
        "{environments:?}"
    );

    let reply = with_ui(&agent, || {
        client
            .call(&run_request(fx.env_id, &fx.project))
            .expect("call")
    });
    assert!(
        matches!(
            reply,
            Response::Ran {
                exit_code: Some(0),
                ..
            }
        ),
        "{reply:?}"
    );
    assert_eq!(
        std::fs::read_to_string(fx.project.join("released.txt")).expect("ran"),
        MARKER
    );
    let machine = fx.machine();
    assert!(
        machine
            .audit_entries()
            .iter()
            .any(|e| e.tool == "run_with_env" && e.outcome == Outcome::Allowed && e.actor == "mcp"),
        "recorded in the machine vault's log under the ordinary actor"
    );
    // No standing grant was used or created by an interactive release.
    assert!(fx.section().command_grants.is_empty());

    // The personal vault locks: the machine vault goes with it, armed or not.
    fx.arm();
    drop(fx.personal.take());
    let reply = client
        .call(&run_request(fx.env_id, &fx.project))
        .expect("call");
    assert_eq!(code(&reply), Some(ErrorCode::VaultLocked), "{reply:?}");
}

// -------------------------------------------------------------------------------------------------
// The run browser's extension endpoint admits only that browser's own native host
// -------------------------------------------------------------------------------------------------

/// The file the stand-in browser's native host writes its `hello` reply to.
const HOST_REPLY: &str = "run-browser-host.json";

/// A stand-in for a browser: it writes the control endpoint file a Chromium writes into its
/// profile, starts a child as a browser starts its native host — this test binary, at
/// [`run_browser_host_entry_point`] — and stays up until the run ends it.
fn fake_browser(dir: &Path) -> PathBuf {
    let exe = std::env::current_exe().expect("test binary");
    let script = dir.join("fake-browser");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do case \"$a\" in --user-data-dir=*) d=\"${{a#--user-data-dir=}}\";; esac; done\n\
             printf '9\\n/devtools/browser/test\\n' > \"$d/DevToolsActivePort\"\n\
             '{}' run_browser_host_entry_point --exact --ignored --test-threads=1 >/dev/null 2>&1 &\n\
             exec sleep 60\n",
            exe.display()
        ),
    )
    .expect("script");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    script
}

fn hello(socket: &Path) -> serde_json::Value {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    kagisecure_extension_ipc::frame::write(
        &mut stream,
        &serde_json::json!({ "ksx": 1, "id": "h-1", "body": {
            "ask": "hello",
            "extension_id": kagisecure_extension_ipc::PINNED_EXTENSION_IDS[0],
            "browser": "chrome",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }}),
    )
    .expect("write");
    let reply: serde_json::Value =
        kagisecure_extension_ipc::frame::read(&mut stream).expect("read");
    reply["body"].clone()
}

/// Not a test on its own: the stand-in browser's native host. It says `hello` on the socket the
/// engine named in the browser's environment and writes the reply beside it.
#[test]
#[ignore = "native host of the stand-in run browser, not a test of its own"]
fn run_browser_host_entry_point() {
    let Some(socket) = std::env::var_os("KAGISECURE_EXTENSION_SOCKET") else {
        return;
    };
    let socket = PathBuf::from(socket);
    let reply = hello(&socket);
    let out = socket.parent().expect("dir").join(HOST_REPLY);
    std::fs::write(out, serde_json::to_string(&reply).expect("json")).expect("reply");
}

fn wait_for(path: &Path) -> String {
    let started = Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && !text.is_empty()
        {
            return text;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_session_from_a_browser_other_than_the_runs_is_refused() {
    let fx = fixture_with(|root| {
        Some(RunBrowserSetup {
            nmhost: PathBuf::from("/usr/bin/false"),
            extension_dir: root.to_path_buf(),
            runs_dir: Some(root.join("runs")),
            extra_args: Vec::new(),
        })
    });
    let root = fx.dir.path().canonicalize().expect("root");
    let mut job = job(
        "sign in",
        sha_pin("/bin/sh"),
        vec![
            "-c".to_owned(),
            "printf %s \"$KAGISECURE_RUN_BROWSER_CDP\" > cdp.txt; sleep 30".to_owned(),
        ],
        &fx.project,
    );
    job.run_browser = Some(sha_pin(&fake_browser(&root).to_string_lossy()));
    fx.add_job(&job, granted_args());
    fx.arm();
    fx.engine.run_now(job.id).expect("run");

    // The job was handed the run browser's control endpoint.
    assert_eq!(wait_for(&fx.project.join("cdp.txt")), "http://127.0.0.1:9");

    // The run browser's own native host is served.
    let own = wait_for(&root.join(HOST_REPLY));
    assert!(
        !own.contains("\"error\""),
        "the run's browser was refused: {own}"
    );

    // Anything else — here, this test process, which no run browser started — is refused on the
    // same endpoint before it can say anything.
    let socket = std::fs::read_dir(&root)
        .expect("dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("ux-"))
        })
        .expect("the run's extension endpoint");
    let other = hello(&socket);
    assert_eq!(other["reply"], "error", "{other}");
    assert_eq!(other["code"], "UNTRUSTED_HOST", "{other}");
    assert!(
        fx.details().iter().any(|d| d == "HOST_REFUSED"),
        "{:?}",
        fx.details()
    );

    // The run's end ends the browser, its endpoint and its profile.
    assert!(fx.engine.disarm(None, "test"));
    fx.wait_for_runs_to_end();
    assert!(!socket.exists(), "the endpoint is gone");
    let left: Vec<_> = std::fs::read_dir(root.join("runs"))
        .expect("runs dir")
        .filter_map(Result::ok)
        .collect();
    assert!(left.is_empty(), "the profile is deleted: {left:?}");
}

// -------------------------------------------------------------------------------------------------
// A job's own program is started with its environment (implementation decision 51)
// -------------------------------------------------------------------------------------------------

#[test]
fn a_plain_script_whose_grant_names_it_gets_its_variables_at_start_with_no_socket_call() {
    let fx = fixture();
    // `/bin/sh -c 'test -n "$TOKEN" && …'`: it never speaks to kagisecure.
    let args = vec![
        "-c".to_owned(),
        "test -n \"$TOKEN\" && printf %s \"$TOKEN\" > started.txt".to_owned(),
    ];
    let job = job("plain", sha_pin("/bin/sh"), args.clone(), &fx.project);
    // The grant names the job's own program: the same executable, arguments and folder.
    let grant = fx.add_job(&job, args);
    fx.arm();
    fx.engine.run_now(job.id).expect("run");
    fx.wait_for_runs_to_end();

    assert_eq!(
        std::fs::read_to_string(fx.project.join("started.txt")).expect("the script ran with it"),
        MARKER
    );
    // Counted as a use, and audited like `run_with_env`: `Allowed` before the job started.
    let section = fx.section();
    let held = section.command_grant(grant).expect("grant");
    assert_eq!(held.uses, 1);
    assert!(held.suspended.is_none());
    let entries = fx.machine().audit_entries().to_vec();
    let released = entries
        .iter()
        .position(|e| {
            e.tool == "run_with_env"
                && e.outcome == Outcome::Allowed
                && e.detail.as_deref()
                    == Some(&*format!("UNATTENDED_GRANT {grant} RUN 1 (JOB_START)"))
        })
        .expect("the release's Allowed entry");
    let started = entries
        .iter()
        .position(|e| {
            e.detail
                .as_deref()
                .is_some_and(|d| d.starts_with("JOB_STARTED (run 1"))
        })
        .expect("started");
    assert!(
        released < started,
        "the release is recorded before the job starts"
    );
    assert_eq!(entries[released].variables, ["TOKEN"]);
    assert!(!format!("{entries:?}").contains(MARKER));
}

#[test]
fn a_job_whose_grant_names_another_command_starts_without_the_variables() {
    let fx = fixture();
    let args = vec![
        "-c".to_owned(),
        "printf %s \"${TOKEN:-unset}\" > started.txt".to_owned(),
    ];
    let job = job("other", sha_pin("/bin/sh"), args, &fx.project);
    // The grant is for a different argument list: nothing is released at the start.
    let grant = fx.add_job(&job, granted_args());
    fx.arm();
    fx.engine.run_now(job.id).expect("run");
    fx.wait_for_runs_to_end();
    assert_eq!(
        std::fs::read_to_string(fx.project.join("started.txt")).expect("ran"),
        "unset"
    );
    assert_eq!(fx.section().command_grant(grant).expect("grant").uses, 0);
}

//! A stand-in for the macOS app's unattended half, for the browser end-to-end test of unattended
//! sign-ins (ADR-0042 §12, Phase 5).
//!
//! It does what the app does with nobody present: it holds a personal vault with a machine vault
//! key, a machine vault with one Login item, one job and one login grant for it, starts the
//! unattended engine, arms it, and starts the job once. Everything after that is production code:
//! the engine starts the run browser (headless, a fresh profile, the real extension, the real
//! `kagisecure-nmhost`), the job's own `kagisecure-mcp` asks for the fill on the unattended socket,
//! and the run browser's extension endpoint delivers it. When the run ends it writes the machine
//! vault's audit log and the grant's state to `<dir>/outcome.json` and exits.
//!
//! An example rather than a subcommand for the reason `extension_harness` gives: no release
//! artifact contains it.
//!
//! # Usage
//!
//! ```text
//! unattended_harness --dir <dir> --browser <exe> --origin <https origin>
//!                    --username U --password P --nmhost <path> --extension <dir>
//!                    --job <exe> [--job-arg A]... [--browser-arg A]...
//! ```
//!
//! The job is started with its arguments followed by the item's id. It prints
//! `ready <unattended socket>` once the run has started.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kagisecure_agent::unattended::pins::pin_executable;
use kagisecure_agent::{
    Endpoint, RunBrowserSetup, UnattendedConfig, UnattendedEngine, VaultHandle,
};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::machine::{
    GrantId, GrantLimits, Job, JobId, LoginField, LoginGrant, PresencePath, ScheduleTime,
    machine_vault_path,
};
use kagisecure_core::vault::{CreateOptions, MachineVaultKey, Vault};

struct Args {
    dir: PathBuf,
    browser: String,
    origin: String,
    username: String,
    password: String,
    nmhost: PathBuf,
    extension: PathBuf,
    job: String,
    job_args: Vec<String>,
    browser_args: Vec<String>,
}

fn args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        map.entry(flag).or_default().push(value);
    }
    let one = |flag: &str| {
        map.get(flag)
            .and_then(|v| v.first().cloned())
            .unwrap_or_else(|| panic!("{flag} is required"))
    };
    Args {
        dir: PathBuf::from(one("--dir")),
        browser: one("--browser"),
        origin: one("--origin"),
        username: one("--username"),
        password: one("--password"),
        nmhost: PathBuf::from(one("--nmhost")),
        extension: PathBuf::from(one("--extension")),
        job: one("--job"),
        job_args: map.get("--job-arg").cloned().unwrap_or_default(),
        browser_args: map.get("--browser-arg").cloned().unwrap_or_default(),
    }
}

fn main() {
    let args = args();
    std::fs::create_dir_all(&args.dir).expect("dir");
    let dir = args.dir.canonicalize().expect("canonical dir");
    let personal_path = dir.join("personal.kagivault");
    let machine_path = machine_vault_path(&personal_path);

    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    let (mut personal, _code) = Vault::create(&personal_path, b"pw", &options).expect("personal");
    let key = MachineVaultKey::generate().expect("key");
    let mut machine = Vault::create_machine(&machine_path, &key, "Machine").expect("machine");
    personal
        .transact(|tx| tx.set_machine_vault_key(key, "harness"))
        .expect("store key");

    let now = kagisecure_core::unix_now();
    let origin = kagisecure_core::vault::machine::canonical_https_origin(&args.origin)
        .expect("an exact https origin");
    let (item_id, job_id) = machine
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            tx.set_vault_agent_visible(vault_id, true);
            let mut item = Item::new(vault_id, Category::Login, "Service account");
            item.urls = vec![origin.clone()];
            item.fields.push(Field::public("username", &args.username));
            item.fields.push(Field::concealed(
                "password",
                Secret::from_string(args.password.clone()),
            ));
            item.agent_visible = true;
            let item_id = item.id;
            tx.add_item(item);

            let mut job_args = args.job_args.clone();
            job_args.push(item_id.to_string());
            let job = Job {
                id: JobId::new(),
                name: "sign in".to_owned(),
                root: pin_executable(&args.job).expect("pin the job"),
                args: job_args,
                working_dir: dir.to_string_lossy().into_owned(),
                schedule: vec![ScheduleTime::Daily { hour: 3, minute: 0 }],
                run_deadline_secs: 300,
                catch_up_secs: 0,
                run_browser: Some(pin_executable(&args.browser).expect("pin the browser")),
                created_at: now,
                presence: PresencePath::Confirmed,
                unknown: BTreeMap::new(),
            };
            let job_id = job.id;
            let section = tx.machine_mut()?;
            section.jobs.push(job);
            section.login_grants.push(LoginGrant {
                id: GrantId::new(),
                job: job_id,
                item: item_id,
                fields: vec![LoginField::Username, LoginField::Password],
                origin: origin.clone(),
                follow_on_origins: Vec::new(),
                one_time_codes: false,
                limits: GrantLimits::defaults(now),
                uses: 0,
                created_at: now,
                approved_at: now + 1,
                presence: PresencePath::Confirmed,
                suspended: None,
                unknown: BTreeMap::new(),
            });
            Ok((item_id, job_id))
        })
        .expect("seed the machine vault");
    drop(machine);

    let endpoint = Endpoint::for_instance(&dir, "unattended.sock");
    let engine = UnattendedEngine::start(&UnattendedConfig {
        endpoint: Some(endpoint.clone()),
        run_browser: Some(RunBrowserSetup {
            nmhost: args.nmhost.clone(),
            extension_dir: args.extension.clone(),
            runs_dir: Some(dir.join("runs")),
            extra_args: args.browser_args.clone(),
        }),
        ..UnattendedConfig::new(machine_path.clone())
    })
    .expect("engine");
    let personal = VaultHandle::new(personal);
    let keychain = engine
        .arm(&personal, PresencePath::Confirmed, "harness")
        .expect("arm");
    let run = engine.run_now(job_id).expect("start the job");
    println!(
        "ready {} run {run} item {item_id}",
        endpoint.as_override().to_string_lossy()
    );

    let started = Instant::now();
    while !engine.status().runs.is_empty() && started.elapsed() < Duration::from_secs(330) {
        std::thread::sleep(Duration::from_millis(100));
    }
    // The monitor records the end just before it removes the run.
    std::thread::sleep(Duration::from_millis(300));
    let notices = engine.take_notices();

    let key = MachineVaultKey::from_keychain_bytes(&keychain).expect("key");
    let machine = Vault::open_machine(&machine_path, &key).expect("reopen");
    let entries: Vec<serde_json::Value> = machine
        .audit_entries()
        .iter()
        .map(|e| {
            serde_json::json!({
                "tool": e.tool,
                "actor": e.actor,
                "outcome": format!("{:?}", e.outcome),
                "detail": e.detail,
                "target": e.target_path,
                "variables": e.variables,
            })
        })
        .collect();
    let grants: Vec<serde_json::Value> = machine
        .machine()
        .map(|m| {
            m.login_grants
                .iter()
                .map(|g| {
                    serde_json::json!({
                        "uses": g.uses,
                        "suspended": g.suspended.as_ref().map(|s| s.reason.clone()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let runs_left = std::fs::read_dir(dir.join("runs"))
        .map(|d| d.count())
        .unwrap_or(0);
    let outcome = serde_json::json!({
        "entries": entries,
        "login_grants": grants,
        "notices": notices.iter().map(|n| format!("{} {}", n.kind, n.reason)).collect::<Vec<_>>(),
        "profiles_left": runs_left,
    });
    std::fs::write(
        dir.join("outcome.json"),
        serde_json::to_string_pretty(&outcome).expect("json"),
    )
    .expect("outcome");
    drop(engine);
    println!("done");
}

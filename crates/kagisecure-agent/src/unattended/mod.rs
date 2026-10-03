//! The unattended engine (ADR-0042 §2–§9, Phase 2): the armed machine vault, jobs kagisecure
//! starts on a schedule, and the unattended socket where a run's process tree may use the
//! standing command grants of its own job.
//!
//! # Shape
//!
//! One [`Engine`], hosted by the app. It owns:
//!
//! * **the armed state** — the machine vault open in this process, or nothing. Arming is a person's
//!   act in the app ([`Engine::arm`], after a presence proof the app has made); it returns the
//!   bytes the app keeps in the login Keychain, and after a restart the app hands them back
//!   ([`Engine::resume`]) to arm again with nobody present. Arming has no expiry: it ends only
//!   when a person disarms ([`Engine::disarm`]), a `lock` request arrives on the unattended
//!   socket, or the machine vault file stops being one this session can build on
//!   (implementation decision 1);
//! * **the scheduler** — a thread that starts each job at its calendar times ([`schedule`]);
//! * **runs** — each job's root in a process group of its own, with `KAGISECURE_SOCKET` naming
//!   the unattended socket, ended at its deadline ([`runs`]);
//! * **the unattended socket** — a second endpoint beside `daemon.sock`, same-user only, where a
//!   request is served only from a live run's process tree and only under a grant of that run's
//!   job ([`service`]);
//! * **run browsers** — for a job that declares one, a headless browser started for each run with
//!   the extension loaded, in a fresh profile, served by an extension endpoint of that run alone,
//!   where `request_fill` under a login grant is delivered ([`browser`], [`login`]).
//!
//! # What it never does
//!
//! Nothing here reads the personal vault except to take the machine vault's key when a person
//! arms, and to record that person's decisions in the personal log. No request on the unattended
//! socket creates, widens, extends or re-enables a grant or a job: the only writes it makes to the
//! machine vault's records are a grant's use count and a suspension.

pub mod browser;
pub mod login;
pub mod pins;
pub mod runs;
pub mod schedule;
pub mod service;
mod start;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::Spawned;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::MachineVaultKey;
use kagisecure_core::vault::machine::{Arm, JobId, KeychainBytes, PresencePath};
use kagisecure_core::{Vault, unix_now};
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};
use kagisecure_ipc::server::Server;
use kagisecure_ipc::sever::LiveConnections;

use crate::agent::AgentError;
use crate::vault::{REQUEST_LOCK_TIMEOUT, VaultHandle};
use browser::{RUN_BROWSER_CDP_ENV, RunBrowser, RunBrowserSetup};
use runs::{Run, RunRegistry};
use schedule::{Clock, SystemClock, latest_occurrence};

/// The file name of the unattended socket, beside `daemon.sock`.
pub const SOCKET_NAME: &str = "unattended.sock";

/// The actor of every entry the engine writes on its own behalf (ADR-0042 §8).
pub const ENGINE_ACTOR: &str = "unattended";

/// The `tool` of arm and disarm entries, in both logs.
pub const TOOL_ARM: &str = "unattended_arm";
/// The `tool` of run entries: `JOB_STARTED`, `JOB_ENDED`, `JOB_MISSED`, `JOB_NOT_STARTED`.
pub const TOOL_JOB: &str = "unattended_job";
/// The `tool` of suspension entries: `GRANT_SUSPENDED`.
pub const TOOL_GRANT: &str = "unattended_grant";

/// The shortest lateness a scheduled time is still started with, whatever the job's catch-up
/// window: a tick can only notice a time after it has passed.
const MIN_SLACK_SECS: i64 = 120;

/// How often the scheduler looks, unless configured otherwise.
pub const DEFAULT_TICK: Duration = Duration::from_secs(15);

/// How the accept loop polls.
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// How long a stop waits for severed connections.
const STOP_DRAIN: Duration = Duration::from_secs(2);

/// What the engine could not do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnattendedError {
    /// The personal vault is locked: arming needs it unlocked.
    #[error("the personal vault is locked")]
    Locked,
    /// The personal vault holds no machine vault key.
    #[error("this vault has no machine vault")]
    NoMachineVault,
    /// The machine vault is not armed.
    #[error("unattended jobs are not armed")]
    NotArmed,
    /// No job with that id.
    #[error("no such job")]
    NoSuchJob,
    /// The job is already running.
    #[error("the job is already running")]
    AlreadyRunning,
    /// The job's root executable is no longer what was pinned.
    #[error("the job's program changed since the job was defined; define it again")]
    RootPinChanged,
    /// The job's root could not be started.
    #[error("could not start the job: {0}")]
    Spawn(String),
    /// The vault refused.
    #[error("{0}")]
    Core(#[from] kagisecure_core::Error),
}

/// Something the owner should be told as it happens (ADR-0042 §9): a local notification, never
/// carrying a value or a command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnattendedNotice {
    /// `SUSPENDED`, `DISARMED`, `JOB_MISSED` or `JOB_NOT_STARTED`.
    pub kind: String,
    /// The job's name, when it is about one.
    pub job: Option<String>,
    /// Why, from the audit vocabulary.
    pub reason: String,
}

/// One live run, for the menu bar and Agent access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunStatus {
    /// The run's number.
    pub id: u64,
    /// The job's name.
    pub job: String,
    /// The root's pid.
    pub root_pid: u32,
    /// Unix seconds.
    pub started_at: u64,
}

/// The engine's state, for the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnattendedStatus {
    /// Whether the machine vault is armed.
    pub armed: bool,
    /// When it was armed, Unix seconds.
    pub armed_at: Option<u64>,
    /// Where the unattended socket is.
    pub endpoint: String,
    /// Live runs.
    pub runs: Vec<RunStatus>,
}

/// Knobs the host sets at start.
#[derive(Clone)]
pub struct UnattendedConfig {
    /// Where the unattended socket goes; beside the default `daemon.sock` when `None`.
    pub endpoint: Option<Endpoint>,
    /// The machine vault file (`kagisecure_core::vault::machine::machine_vault_path`).
    pub machine_path: PathBuf,
    /// How often the scheduler looks.
    pub tick: Duration,
    /// The clock; the system's when `None`.
    pub clock: Option<Arc<dyn Clock>>,
    /// What a run browser needs (ADR-0042 §12.3); a job that declares one does not start without
    /// it.
    pub run_browser: Option<RunBrowserSetup>,
}

impl std::fmt::Debug for UnattendedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnattendedConfig")
            .field("endpoint", &self.endpoint.as_ref().map(ToString::to_string))
            .field("machine_path", &self.machine_path)
            .field("tick", &self.tick)
            .field("run_browser", &self.run_browser)
            .finish_non_exhaustive()
    }
}

impl UnattendedConfig {
    /// The defaults for the machine vault at `machine_path`.
    #[must_use]
    pub fn new(machine_path: PathBuf) -> Self {
        Self {
            endpoint: None,
            machine_path,
            tick: DEFAULT_TICK,
            clock: None,
            run_browser: RunBrowserSetup::discover(),
        }
    }
}

/// State the socket threads, the scheduler and the run monitors share.
pub(crate) struct Core {
    machine_path: PathBuf,
    endpoint: Endpoint,
    clock: Arc<dyn Clock>,
    /// The machine vault while armed.
    machine: Mutex<Option<Arc<VaultHandle>>>,
    pub(crate) runs: RunRegistry,
    notices: Mutex<Vec<UnattendedNotice>>,
    next_run: AtomicU64,
    stopping: AtomicBool,
    /// Per job, the scheduled time (local seconds) already acted on.
    handled: Mutex<HashMap<JobId, i64>>,
    /// Local seconds the scheduler counts from: a time at or before it is not started, except
    /// within a job's catch-up window.
    since: AtomicI64,
    connections: LiveConnections,
    run_browser: Option<RunBrowserSetup>,
}

impl Core {
    /// The machine vault, if armed.
    pub(crate) fn armed(&self) -> Option<Arc<VaultHandle>> {
        self.machine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn notice(&self, kind: &str, job: Option<&str>, reason: &str) {
        self.notices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(UnattendedNotice {
                kind: kind.to_owned(),
                job: job.map(str::to_owned),
                reason: reason.to_owned(),
            });
    }

    /// Record an entry in the machine log, best-effort, if armed.
    pub(crate) fn record(&self, draft: AuditDraft) {
        if let Some(handle) = self.armed() {
            let _ = handle.record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
        }
    }

    fn now_local(&self) -> i64 {
        i64::try_from(self.clock.now_unix()).unwrap_or(i64::MAX) + self.clock.utc_offset()
    }

    /// Install `handle` as the armed machine vault, dropping any earlier one.
    fn install(&self, handle: Arc<VaultHandle>) {
        let previous = self
            .machine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(handle);
        if let Some(previous) = previous {
            drop(previous.take());
        }
        self.since.store(self.now_local(), Ordering::SeqCst);
        self.handled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Disarm: end every run, clear the arm record, record why, and drop the key. `false` if it
    /// was not armed.
    pub(crate) fn disarm(&self, reason: &str) -> bool {
        let Some(handle) = self
            .machine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return false;
        };
        for run in self.runs.live() {
            run.end("DISARMED");
            for draft in run
                .children
                .kill_all_for_stop(crate::children::CHILD_KILL_GRACE)
            {
                let _ = handle.record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
            }
            let _ = handle.record_best_effort(
                REQUEST_LOCK_TIMEOUT,
                engine_entry(
                    TOOL_JOB,
                    Outcome::Failed,
                    format!("JOB_ENDED (run {}, DISARMED)", run.id),
                ),
            );
        }
        let detail = format!("DISARMED ({reason})");
        let cleared = handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            if let Ok(machine) = tx.machine_mut() {
                machine.arm = None;
            }
            tx.append_audit(engine_entry(TOOL_ARM, Outcome::Allowed, detail.clone()));
            Ok(())
        });
        if !matches!(cleared, Some(Ok(()))) {
            // The file could not take the change (a conflict, a full disk): the key goes anyway,
            // and a resume from the Keychain would find the arm record still set — the app deletes
            // the Keychain item on this notice, which is what actually keeps it disarmed.
            let _ = handle.record_best_effort(
                REQUEST_LOCK_TIMEOUT,
                engine_entry(TOOL_ARM, Outcome::Allowed, detail),
            );
        }
        drop(handle.take());
        self.notice("DISARMED", None, reason);
        true
    }

    /// Start a run of `job` now.
    fn launch(self: &Arc<Self>, job: JobId) -> Result<u64, UnattendedError> {
        let handle = self.armed().ok_or(UnattendedError::NotArmed)?;
        // The person may have changed jobs in the app since the last look.
        if let Some(Err(e)) = handle.sync()
            && !crate::vault::sync_could_not_read(&e)
        {
            self.disarm("VAULT_CONFLICT");
            return Err(UnattendedError::NotArmed);
        }
        let job = handle
            .with(|v| v.machine().and_then(|m| m.job(job)).cloned())
            .flatten()
            .ok_or(UnattendedError::NoSuchJob)?;
        if self.runs.job_is_running(job.id) {
            return Err(UnattendedError::AlreadyRunning);
        }
        if !pins::executable_holds(&job.root) {
            self.record(engine_entry(
                TOOL_JOB,
                Outcome::Denied,
                "JOB_NOT_STARTED (ROOT_PIN_CHANGED)".to_owned(),
            ));
            self.notice("JOB_NOT_STARTED", Some(&job.name), "ROOT_PIN_CHANGED");
            return Err(UnattendedError::RootPinChanged);
        }
        let id = self.next_run.fetch_add(1, Ordering::SeqCst) + 1;
        let browser = match &job.run_browser {
            None => None,
            Some(pinned) => match self.start_browser(pinned, id, &handle) {
                Ok(browser) => Some(browser),
                Err(reason) => {
                    self.record(engine_entry(
                        TOOL_JOB,
                        Outcome::Denied,
                        format!("JOB_NOT_STARTED ({reason})"),
                    ));
                    self.notice("JOB_NOT_STARTED", Some(&job.name), reason);
                    return Err(UnattendedError::Spawn(reason.to_owned()));
                }
            },
        };
        let make_command = {
            let program = job.root.path.clone();
            let args = job.args.clone();
            let dir = job.working_dir.clone();
            let socket = self.endpoint.as_override();
            let cdp = browser.as_ref().map(|b| b.cdp.clone());
            move || {
                let mut command = Command::new(&program);
                if let Some(cdp) = &cdp {
                    command.env(RUN_BROWSER_CDP_ENV, cdp);
                }
                command
                    .args(&args)
                    .current_dir(&dir)
                    .env(kagisecure_ipc::endpoint::SOCKET_ENV, &socket)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                command
            }
        };
        let not_started = |reason: &'static str, error: String| {
            self.record(engine_entry(
                TOOL_JOB,
                Outcome::Failed,
                format!("JOB_NOT_STARTED ({reason})"),
            ));
            self.notice("JOB_NOT_STARTED", Some(&job.name), reason);
            UnattendedError::Spawn(error)
        };
        let plain = |make: &dyn Fn() -> Command| {
            Spawned::spawn(&mut make(), true)
                .map_err(|e| not_started("SPAWN_FAILED", e.to_string()))
        };
        // The job's own program, with its environment when a grant names it (implementation
        // decision 51).
        let at_start = handle
            .with(|v| start::decide(v, &job))
            .unwrap_or(start::AtStart::None);
        let (spawned, granted) = match at_start {
            start::AtStart::None => (plain(&make_command)?, None),
            start::AtStart::Refuse(reason) => {
                start::record_refusal(self, &job, id, reason);
                (plain(&make_command)?, None)
            }
            start::AtStart::Suspend(grant, reason) => {
                start::suspend(self, &handle, &job, grant, reason);
                (plain(&make_command)?, None)
            }
            start::AtStart::Release(grant, names) => {
                let fallback = make_command.clone();
                match start::start_with_grant(&handle, &job, id, &grant, names, make_command) {
                    start::Started::WithGrant(spawned, grant) => (spawned, Some(grant)),
                    start::Started::Refused(reason) => {
                        start::record_refusal(self, &job, id, reason);
                        (plain(&fallback)?, None)
                    }
                    start::Started::Failed(reason) => {
                        return Err(not_started(reason, reason.to_owned()));
                    }
                }
            }
        };
        let pid = spawned.id();
        let run = Arc::new(Run::new(
            id,
            job.id,
            job.name.clone(),
            pid,
            kagisecure_ipc::server::process_start_time(pid),
            job.root.path.clone(),
            Instant::now() + Duration::from_secs(u64::from(job.run_deadline_secs)),
            spawned.kill_handle(),
        ));
        *run.browser.lock().unwrap_or_else(|e| e.into_inner()) = browser.map(Arc::new);
        if let Some(grant) = granted {
            // The release at the start is one of this run's releases of the grant.
            let per_run = handle
                .with(|v| {
                    v.machine()
                        .and_then(|m| m.command_grant(grant))
                        .map(|g| g.limits.per_run)
                })
                .flatten()
                .unwrap_or(1);
            let _ = run.reserve(grant, per_run);
        }
        self.runs.add(Arc::clone(&run));
        self.record(AuditDraft {
            client_pid: Some(pid),
            ..engine_entry(
                TOOL_JOB,
                Outcome::Allowed,
                format!("JOB_STARTED (run {id}, job {:?})", job.name),
            )
        });
        let core = Arc::clone(self);
        let monitor = std::thread::Builder::new()
            .name("kagisecure-unattended-run".to_owned())
            .spawn(move || core.monitor(&run, spawned));
        if monitor.is_err() {
            return Err(UnattendedError::Spawn("no thread for the run".to_owned()));
        }
        Ok(id)
    }

    /// Wait for a run's root, end it at its deadline, and record how it ended.
    fn monitor(&self, run: &Arc<Run>, mut spawned: Spawned) {
        let mut timed_out = false;
        let status = loop {
            match spawned.try_reap() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(_) => break None,
            }
            if !timed_out && Instant::now() >= run.deadline {
                timed_out = true;
                run.end("TIMED_OUT");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        run.mark_finished();
        if let Some(browser) = run.take_browser() {
            if let Some(handle) = self.armed() {
                login::settle_notices(self, &handle, run, &browser.broker.take_notices());
            }
            browser.teardown();
        }
        for draft in run
            .children
            .kill_all_for_stop(crate::children::CHILD_KILL_GRACE)
        {
            self.record(draft);
        }
        let how = match (run.ended_reason(), status.and_then(|s| s.code())) {
            (Some(reason), _) => reason.to_owned(),
            (None, Some(code)) => format!("exit {code}"),
            (None, None) => "killed".to_owned(),
        };
        self.record(engine_entry(
            TOOL_JOB,
            Outcome::Allowed,
            format!("JOB_ENDED (run {}, {how})", run.id),
        ));
        self.runs.remove(run.id);
    }

    /// Start the run browser `pinned` for run `id`, or say why not.
    fn start_browser(
        &self,
        pinned: &kagisecure_core::vault::machine::PinnedExecutable,
        id: u64,
        handle: &Arc<VaultHandle>,
    ) -> Result<RunBrowser, &'static str> {
        let setup = self.run_browser.as_ref().ok_or("RUN_BROWSER_UNAVAILABLE")?;
        if !pins::executable_holds(pinned) {
            return Err("RUN_BROWSER_PIN_CHANGED");
        }
        let runs_dir = setup.runs_dir.clone().unwrap_or_else(|| {
            self.machine_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("unattended-runs")
        });
        let socket_dir = self
            .endpoint
            .path()
            .and_then(std::path::Path::parent)
            .map_or_else(|| runs_dir.clone(), std::path::Path::to_path_buf);
        RunBrowser::launch(
            setup,
            std::path::Path::new(&pinned.path),
            &runs_dir,
            &socket_dir,
            id,
            handle,
        )
    }

    /// One scheduler pass: start every job whose time has come.
    pub(crate) fn tick(self: &Arc<Self>) {
        let Some(handle) = self.armed() else {
            return;
        };
        if let Some(Err(e)) = handle.sync()
            && !crate::vault::sync_could_not_read(&e)
        {
            self.disarm("VAULT_CONFLICT");
            return;
        }
        let jobs = handle
            .with(|v| v.machine().map(|m| m.jobs.clone()).unwrap_or_default())
            .unwrap_or_default();
        let now_local = self.now_local();
        let since = self.since.load(Ordering::SeqCst);
        for job in jobs {
            let Some(at) = latest_occurrence(&job.schedule, now_local) else {
                continue;
            };
            let catch_up = i64::from(job.catch_up_secs);
            {
                let mut handled = self.handled.lock().unwrap_or_else(|e| e.into_inner());
                let baseline = handled
                    .get(&job.id)
                    .copied()
                    .unwrap_or(i64::MIN)
                    .max(since - catch_up);
                if at <= baseline {
                    continue;
                }
                handled.insert(job.id, at);
            }
            let late = now_local - at;
            if late > catch_up.max(MIN_SLACK_SECS) {
                self.record(engine_entry(
                    TOOL_JOB,
                    Outcome::Denied,
                    format!("JOB_MISSED (job {:?}, TOO_LATE)", job.name),
                ));
                self.notice("JOB_MISSED", Some(&job.name), "TOO_LATE");
            } else if self.runs.job_is_running(job.id) {
                self.record(engine_entry(
                    TOOL_JOB,
                    Outcome::Denied,
                    format!("JOB_MISSED (job {:?}, STILL_RUNNING)", job.name),
                ));
            } else {
                let _ = self.launch(job.id);
            }
        }
    }
}

/// An entry the engine writes on its own behalf.
pub(crate) fn engine_entry(tool: &str, outcome: Outcome, detail: String) -> AuditDraft {
    AuditDraft {
        actor: ENGINE_ACTOR.to_owned(),
        tool: tool.to_owned(),
        outcome,
        detail: Some(detail),
        ..AuditDraft::default()
    }
}

fn presence_detail(presence: PresencePath) -> &'static str {
    match presence {
        PresencePath::Confirmed => "PRESENCE_CONFIRMED",
        PresencePath::ConfirmedMasterPassword => "PRESENCE_CONFIRMED_MASTER_PASSWORD",
    }
}

/// The unattended engine. See the module documentation.
pub struct Engine {
    core: Arc<Core>,
    accept: Option<std::thread::JoinHandle<()>>,
    scheduler: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("endpoint", &self.core.endpoint.to_string())
            .field("armed", &self.is_armed())
            .finish()
    }
}

impl Engine {
    /// Bind the unattended socket and start the scheduler, disarmed.
    ///
    /// # Errors
    ///
    /// [`AgentError::AlreadyBound`] when something already listens there, or
    /// [`AgentError::Endpoint`].
    pub fn start(config: &UnattendedConfig) -> Result<Self, AgentError> {
        let endpoint = match &config.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => default_endpoint()?,
        };
        let server = match Server::bind(&endpoint) {
            Ok(s) => s,
            Err(EndpointError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse =>
            {
                return Err(AgentError::AlreadyBound {
                    endpoint: endpoint.to_string(),
                });
            }
            Err(e) => return Err(AgentError::from(e)),
        };
        let io = |source| {
            AgentError::Endpoint(EndpointError::Io {
                path: PathBuf::from(endpoint.to_string()),
                source,
            })
        };
        server.set_accept_nonblocking(true).map_err(io)?;

        let core = Arc::new(Core {
            machine_path: config.machine_path.clone(),
            endpoint: endpoint.clone(),
            clock: config
                .clock
                .clone()
                .unwrap_or_else(|| Arc::new(SystemClock)),
            machine: Mutex::new(None),
            runs: RunRegistry::default(),
            notices: Mutex::new(Vec::new()),
            next_run: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            handled: Mutex::new(HashMap::new()),
            since: AtomicI64::new(0),
            connections: LiveConnections::new(),
            run_browser: config.run_browser.clone(),
        });

        let accept_core = Arc::clone(&core);
        let accept = std::thread::Builder::new()
            .name("kagisecure-unattended-accept".to_owned())
            .spawn(move || accept_loop(&server, &accept_core))
            .map_err(io)?;
        let tick = config.tick;
        let scheduler_core = Arc::clone(&core);
        let scheduler = std::thread::Builder::new()
            .name("kagisecure-unattended-scheduler".to_owned())
            .spawn(move || {
                while !scheduler_core.stopping.load(Ordering::SeqCst) {
                    scheduler_core.tick();
                    sleep_unless_stopping(&scheduler_core.stopping, tick);
                }
            })
            .map_err(io)?;
        Ok(Self {
            core,
            accept: Some(accept),
            scheduler: Some(scheduler),
        })
    }

    /// Where the unattended socket is.
    #[must_use]
    pub fn endpoint(&self) -> String {
        self.core.endpoint.to_string()
    }

    /// Whether the machine vault is armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.core.armed().is_some()
    }

    /// Arm, as a person in the app after a presence proof `presence` (ADR-0042 §3): take the
    /// machine vault's key from the unlocked personal vault, open the machine vault, record the arm
    /// in both logs, and return the bytes the app keeps in the Keychain so that a restart re-arms
    /// ([`Engine::resume`]).
    ///
    /// # Errors
    ///
    /// [`UnattendedError::Locked`], [`UnattendedError::NoMachineVault`], or the vault's own error
    /// opening or writing the machine vault.
    pub fn arm(
        &self,
        personal: &VaultHandle,
        presence: PresencePath,
        actor: &str,
    ) -> Result<KeychainBytes, UnattendedError> {
        let bytes = personal
            .with(|v| {
                v.machine_vault_key()
                    .map(MachineVaultKey::to_keychain_bytes)
            })
            .ok_or(UnattendedError::Locked)?
            .ok_or(UnattendedError::NoMachineVault)?;
        let key = MachineVaultKey::from_keychain_bytes(&bytes)?;
        let handle = VaultHandle::new(Vault::open_machine(&self.core.machine_path, &key)?);
        let detail = format!("ARMED ({})", presence_detail(presence));
        handle
            .transact(REQUEST_LOCK_TIMEOUT, |tx| {
                tx.machine_mut()?.arm = Some(Arm {
                    armed_at: unix_now(),
                    presence,
                    unknown: std::collections::BTreeMap::new(),
                });
                tx.append_audit(engine_entry(TOOL_ARM, Outcome::Allowed, detail.clone()));
                Ok(())
            })
            .ok_or(UnattendedError::NotArmed)??;
        let _ = personal.record_best_effort(
            REQUEST_LOCK_TIMEOUT,
            AuditDraft {
                actor: actor.to_owned(),
                ..engine_entry(TOOL_ARM, Outcome::Allowed, detail)
            },
        );
        self.core.install(handle);
        Ok(bytes)
    }

    /// Arm again from the Keychain's bytes, with nobody present — at app launch, after a
    /// restart. `Ok(false)` when the machine vault is not armed any more (a person or a `lock`
    /// request disarmed it): the app then deletes the Keychain item.
    ///
    /// # Errors
    ///
    /// The vault's own error when the bytes do not open the machine vault.
    pub fn resume(&self, keychain: &[u8]) -> Result<bool, UnattendedError> {
        let key = MachineVaultKey::from_keychain_bytes(keychain)?;
        let vault = Vault::open_machine(&self.core.machine_path, &key)?;
        if vault.machine().is_none_or(|m| m.arm.is_none()) {
            return Ok(false);
        }
        let handle = VaultHandle::new(vault);
        let _ = handle.record_best_effort(
            REQUEST_LOCK_TIMEOUT,
            engine_entry(TOOL_ARM, Outcome::Allowed, "ARMED (RESUMED)".to_owned()),
        );
        self.core.install(handle);
        Ok(true)
    }

    /// Disarm, as a person (Pause): end every run, clear the arm record, drop the key, and record
    /// it in the machine log and — when `personal` is unlocked — the personal log. Needs no
    /// presence proof: refusing is always allowed. `false` if it was not armed. The app deletes
    /// the Keychain item either way.
    pub fn disarm(&self, personal: Option<&VaultHandle>, actor: &str) -> bool {
        let was = self.core.disarm("PAUSED");
        if was && let Some(personal) = personal {
            let _ = personal.record_best_effort(
                REQUEST_LOCK_TIMEOUT,
                AuditDraft {
                    actor: actor.to_owned(),
                    ..engine_entry(TOOL_ARM, Outcome::Allowed, "DISARMED (PAUSED)".to_owned())
                },
            );
        }
        was
    }

    /// Start a run of `job` now, as a person in the app would ("Run now"). Its grants apply to it
    /// as to a scheduled run.
    ///
    /// # Errors
    ///
    /// [`UnattendedError::NotArmed`], [`UnattendedError::NoSuchJob`],
    /// [`UnattendedError::AlreadyRunning`], [`UnattendedError::RootPinChanged`] or
    /// [`UnattendedError::Spawn`].
    pub fn run_now(&self, job: JobId) -> Result<u64, UnattendedError> {
        self.core.launch(job)
    }

    /// Run one scheduler pass now, as the scheduler thread does every tick.
    pub fn tick(&self) {
        self.core.tick();
    }

    /// The engine's state.
    #[must_use]
    pub fn status(&self) -> UnattendedStatus {
        let handle = self.core.armed();
        let armed_at = handle
            .as_ref()
            .and_then(|h| h.with(|v| v.machine().and_then(|m| m.arm.as_ref().map(|a| a.armed_at))))
            .flatten();
        UnattendedStatus {
            armed: handle.is_some(),
            armed_at,
            endpoint: self.endpoint(),
            runs: self
                .core
                .runs
                .live()
                .iter()
                .map(|r| RunStatus {
                    id: r.id,
                    job: r.job_name.clone(),
                    root_pid: r.root_pid,
                    started_at: r.started_at,
                })
                .collect(),
        }
    }

    /// What happened since the host last asked, for notifications.
    pub fn take_notices(&self) -> Vec<UnattendedNotice> {
        std::mem::take(&mut *self.core.notices.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Stop: end every run, stop the scheduler and the socket. The arm record is left as it is —
    /// an app quitting is not a person disarming — so the next launch resumes.
    pub fn stop(&mut self) {
        if self.core.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.core.runs.end_all("APP_STOPPED");
        // Run browsers are in process groups of their own: ended here, not left to monitors that
        // may not get to run before the app exits.
        for run in self.core.runs.all() {
            if let Some(browser) = run.take_browser() {
                browser.teardown();
            }
        }
        if let Some(thread) = self.scheduler.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.accept.take() {
            let _ = thread.join();
        }
        let _ = self.core.connections.sever_all(STOP_DRAIN);
        if let Some(path) = self.core.endpoint.path() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(handle) = self
            .core
            .machine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            drop(handle.take());
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The unattended socket's default place: beside the default `daemon.sock`.
fn default_endpoint() -> Result<Endpoint, EndpointError> {
    let ordinary = Endpoint::discover()?;
    Ok(match ordinary.path().and_then(std::path::Path::parent) {
        Some(dir) => Endpoint::for_instance(dir, SOCKET_NAME),
        None => Endpoint::for_instance(std::path::Path::new("."), SOCKET_NAME),
    })
}

fn sleep_unless_stopping(stopping: &AtomicBool, total: Duration) {
    let step = Duration::from_millis(20);
    let until = Instant::now() + total;
    while !stopping.load(Ordering::SeqCst) && Instant::now() < until {
        std::thread::sleep(step.min(until.saturating_duration_since(Instant::now())));
    }
}

fn accept_loop(server: &Server, core: &Arc<Core>) {
    loop {
        if core.stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut connection = match server.accept() {
            Ok(c) => c,
            Err(_) => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        if core.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Ok(severer) = connection.severer() else {
            continue;
        };
        let ticket = core.connections.arrived(severer);
        let serving = Arc::clone(core);
        let spawned = std::thread::Builder::new()
            .name("kagisecure-unattended-conn".to_owned())
            .spawn(move || {
                service::serve_connection(&serving, &mut connection);
                drop(connection);
                serving.connections.gone(ticket);
            });
        if spawned.is_err() {
            core.connections.gone(ticket);
        }
    }
}

//! The run's own browser (ADR-0042 §12.3): a Chromium-family browser kagisecure starts for one
//! run, in a fresh profile, with the kagisecure extension loaded and the native messaging manifest
//! written into that profile, pointed at an extension endpoint of this run alone; torn down, and
//! its profile deleted, when the run ends.
//!
//! # Headless, not headful
//!
//! The ADR said headful, because the old headless shell does not load an MV3 extension. The
//! Phase 5 measurement (implementation decision 40) found that the new headless mode
//! (`--headless=new`) loads the unpacked extension and launches the native host named by a
//! manifest inside `--user-data-dir`, in Microsoft Edge and in Chromium; Google Chrome ignores
//! `--load-extension` and Brave does not read a profile's manifest. A run browser therefore opens
//! no window and never takes focus.
//!
//! # One endpoint per run
//!
//! Each run browser gets an [`ExtensionAgent`] of its own over the machine vault, bound to a
//! socket named for the run, and gated to native hosts that descend from this browser's pid and
//! start time ([`super::runs::descends_from`]). Its agent-fill broker therefore sees only this
//! browser's sessions: no run's fill can reach another run's browser, and nothing else can reach
//! any (implementation decision 41).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use kagisecure_core::inject::Spawned;
use kagisecure_ipc::endpoint::Endpoint;

use crate::approval::ApprovalQueue;
use crate::extension::agent_fill::AgentFillBroker;
use crate::extension::{ExtensionAgent, ExtensionConfig, HostGate};
use crate::vault::VaultHandle;

/// The variable naming the run browser's control endpoint in the job's environment: a loopback
/// `http://127.0.0.1:<port>` a CDP client (Playwright's `connectOverCDP`, Puppeteer's `connect`)
/// attaches to.
pub const RUN_BROWSER_CDP_ENV: &str = "KAGISECURE_RUN_BROWSER_CDP";

/// Where the extension directory is named when it is not found beside the app.
pub const RUN_BROWSER_EXTENSION_ENV: &str = "KAGISECURE_RUN_BROWSER_EXTENSION";

/// How long the browser has to write its control endpoint.
const CDP_WAIT: Duration = Duration::from_secs(20);

/// How long the browser has to exit after `SIGTERM`, before the group is killed.
const EXIT_GRACE: Duration = Duration::from_secs(3);

/// What the engine needs to start a run browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunBrowserSetup {
    /// `kagisecure-nmhost`, which the manifest names.
    pub nmhost: PathBuf,
    /// The unpacked Chromium extension (`extensions/shared`).
    pub extension_dir: PathBuf,
    /// Where each run's profile directory goes; `unattended-runs` beside the machine vault when
    /// `None`.
    pub runs_dir: Option<PathBuf>,
    /// Arguments added to every run browser's command line — for a test's self-signed server
    /// (`--ignore-certificate-errors`), never set by the app.
    pub extra_args: Vec<String>,
}

impl RunBrowserSetup {
    /// Find the native host and the extension: beside the running app (its `Contents/Helpers`
    /// and `Contents/Resources/ChromiumExtension`), where the environment says, or — for a
    /// development build — in the source tree. `None` when either is missing; a job with a run
    /// browser then does not start (`RUN_BROWSER_UNAVAILABLE`).
    #[must_use]
    pub fn discover() -> Option<Self> {
        let contents = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().and_then(Path::parent).map(Path::to_path_buf));
        let helpers = contents.as_ref().map(|c| c.join("Helpers"));
        let nmhost = crate::browser_setup::nmhost_path(helpers.as_deref())?;
        let bundled = contents.map(|c| c.join("Resources").join("ChromiumExtension"));
        let explicit = std::env::var_os(RUN_BROWSER_EXTENSION_ENV).map(PathBuf::from);
        // The source tree only in a development build: a release binary must not carry this
        // machine's build paths (`cargo xtask dist` refuses one that does).
        #[cfg(debug_assertions)]
        let source = Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extensions/shared"));
        #[cfg(not(debug_assertions))]
        let source: Option<PathBuf> = None;
        let extension_dir = [explicit, bundled, source]
            .into_iter()
            .flatten()
            .find(|dir| dir.join("manifest.json").is_file())?;
        Some(Self {
            nmhost,
            extension_dir,
            runs_dir: None,
            extra_args: Vec::new(),
        })
    }
}

/// A run's browser: the process, its profile, and the extension endpoint that serves it.
pub(crate) struct RunBrowser {
    /// The run's directory: the profile, and nothing else of value.
    dir: PathBuf,
    process: Mutex<Option<Spawned>>,
    agent: Mutex<Option<ExtensionAgent>>,
    /// The broker the endpoint registers this browser's sessions with.
    pub(crate) broker: Arc<AgentFillBroker>,
    /// A queue that is closed: nothing on this endpoint ever asks a person.
    pub(crate) queue: Arc<ApprovalQueue>,
    /// The browser's pid.
    pub(crate) pid: u32,
    /// The control endpoint, for the job's environment.
    pub(crate) cdp: String,
}

impl std::fmt::Debug for RunBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunBrowser")
            .field("pid", &self.pid)
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl RunBrowser {
    /// Start `browser` for run `run`, its profile under `runs_dir` and its endpoint in
    /// `socket_dir`, over the machine vault `handle`. The error is the audit reason the job did
    /// not start with.
    pub(crate) fn launch(
        setup: &RunBrowserSetup,
        browser: &Path,
        runs_dir: &Path,
        socket_dir: &Path,
        run: u64,
        handle: &Arc<VaultHandle>,
    ) -> Result<Self, &'static str> {
        if !cfg!(unix) {
            // No run browser outside macOS (ADR-0042 §14).
            return Err("RUN_BROWSER_UNSUPPORTED");
        }
        let tag = format!("{}-{run}", std::process::id());
        let dir = runs_dir.join(format!("run-{tag}"));
        create_private_dir(runs_dir).map_err(|_| "RUN_BROWSER_UNAVAILABLE")?;
        let _ = std::fs::remove_dir_all(&dir);
        create_private_dir(&dir).map_err(|_| "RUN_BROWSER_UNAVAILABLE")?;
        match Self::start_in(setup, browser, &dir, socket_dir, &tag, handle) {
            Ok(started) => Ok(started),
            Err(reason) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(reason)
            }
        }
    }

    fn start_in(
        setup: &RunBrowserSetup,
        browser: &Path,
        dir: &Path,
        socket_dir: &Path,
        tag: &str,
        handle: &Arc<VaultHandle>,
    ) -> Result<Self, &'static str> {
        let profile = dir.join("profile");
        let hosts = profile.join("NativeMessagingHosts");
        std::fs::create_dir_all(&hosts).map_err(|_| "RUN_BROWSER_UNAVAILABLE")?;
        std::fs::write(
            hosts.join(format!(
                "{}.json",
                kagisecure_extension_ipc::NATIVE_HOST_NAME
            )),
            crate::browser_setup::manifest_body(&setup.nmhost),
        )
        .map_err(|_| "RUN_BROWSER_UNAVAILABLE")?;

        // The endpoint first, so it is there when the extension first asks; its gate learns the
        // browser's pid once there is one, and admits nothing before.
        let endpoint = Endpoint::for_instance(socket_dir, &format!("ux-{tag}.sock"));
        let broker = Arc::new(AgentFillBroker::for_run_browsers());
        let queue = Arc::new(ApprovalQueue::new());
        queue.deny_all();
        let admitted: Arc<OnceLock<(u32, u64)>> = Arc::new(OnceLock::new());
        let gate: HostGate = {
            let admitted = Arc::clone(&admitted);
            Arc::new(move |identity| match (identity.pid, admitted.get()) {
                (Some(pid), Some(&(browser, start))) => {
                    super::runs::descends_from(pid, browser, start)
                }
                _ => false,
            })
        };
        let config = ExtensionConfig {
            endpoint: Some(endpoint.clone()),
            agent_fill: Some(Arc::clone(&broker)),
            ..ExtensionConfig::new(Arc::clone(&queue))
        };
        let mut agent = ExtensionAgent::start_gated(Arc::clone(handle), config, gate)
            .map_err(|_| "RUN_BROWSER_UNAVAILABLE")?;

        let extension = setup.extension_dir.display().to_string();
        let mut command = Command::new(browser);
        command
            .arg("--headless=new")
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg(format!("--disable-extensions-except={extension}"))
            .arg(format!("--load-extension={extension}"))
            .arg("--remote-debugging-port=0")
            .arg("--remote-debugging-address=127.0.0.1")
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-sync",
                "--password-store=basic",
                "--use-mock-keychain",
            ])
            .args(&setup.extra_args)
            .arg("about:blank")
            .env(
                kagisecure_extension_ipc::endpoint::EXTENSION_SOCKET_ENV,
                endpoint.as_override(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let Ok(spawned) = Spawned::spawn(&mut command, true) else {
            agent.stop();
            return Err("RUN_BROWSER_NOT_STARTED");
        };
        let pid = spawned.id();
        let Some(start) = kagisecure_ipc::server::process_start_time(pid) else {
            // Without a start time the gate could not tell this browser from a later process
            // handed its pid: no run browser at all.
            stop_process(spawned);
            agent.stop();
            return Err("RUN_BROWSER_NOT_STARTED");
        };
        let _ = admitted.set((pid, start));

        let Some(port) = wait_for_cdp_port(&profile) else {
            stop_process(spawned);
            agent.stop();
            return Err("RUN_BROWSER_NOT_STARTED");
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            process: Mutex::new(Some(spawned)),
            agent: Mutex::new(Some(agent)),
            broker,
            queue,
            pid,
            cdp: format!("http://127.0.0.1:{port}"),
        })
    }

    /// End the browser and its endpoint, and delete the profile. Idempotent.
    pub(crate) fn teardown(&self) {
        if let Some(mut agent) = self.agent.lock().unwrap_or_else(|e| e.into_inner()).take() {
            agent.stop();
        }
        if let Some(process) = self
            .process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            stop_process(process);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for RunBrowser {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// `SIGTERM` the browser's group, give it [`EXIT_GRACE`], then kill and reap it.
fn stop_process(mut process: Spawned) {
    process.terminate();
    let until = Instant::now() + EXIT_GRACE;
    while Instant::now() < until {
        if !matches!(process.has_exited(), Ok(false)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    process.kill();
    let _ = process.reap();
}

/// The port the browser wrote to `DevToolsActivePort` in its profile, once it has.
fn wait_for_cdp_port(profile: &Path) -> Option<u16> {
    let file = profile.join("DevToolsActivePort");
    let until = Instant::now() + CDP_WAIT;
    while Instant::now() < until {
        if let Ok(text) = std::fs::read_to_string(&file)
            && let Some(port) = text.lines().next().and_then(|l| l.trim().parse().ok())
        {
            return Some(port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

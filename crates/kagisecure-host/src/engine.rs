//! The decision and the release (ADR-0043, accepted scope §A3–§A5).
//!
//! For each request, in order, under one lock: the bundle verifies again; the named grant exists,
//! is not suspended, expired or used up; the request is exactly the grant's command (otherwise a
//! strike suspends the grant); the executable still has its pinned hash (otherwise the grant is
//! suspended); the use is counted and the release is written to the audit log and synced. Only
//! then, outside the lock, the host starts the command itself with the values written once to its
//! standard input, and returns its masked output.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use kagisecure_core::inject::{Delivery, EnvInjection, RunAs, RunRequest, run_with_env};
use kagisecure_core::model::Secret;
use kagisecure_core::proto::VarName;

use crate::bundle::{self, Opened};
use crate::grant::HostGrant;
use crate::identity;
use crate::protocol::{MAX_OUTPUT, Request, Response};
use crate::store::{Store, Suspended};
use crate::{HostError, Result};

/// The host's engine over one state directory.
#[derive(Debug)]
pub struct Engine {
    store: Store,
    passwd: PathBuf,
    lock: Mutex<()>,
}

/// What a release needs once the lock is let go.
struct Release {
    grant: HostGrant,
    injections: Vec<EnvInjection>,
    run_as: Option<RunAs>,
}

fn refused(reason: &str, message: impl Into<String>) -> Response {
    Response::Refused {
        reason: reason.to_owned(),
        message: message.into(),
    }
}

impl Engine {
    /// The engine over `store`, looking accounts up in `/etc/passwd`.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self::with_passwd(store, crate::passwd::PASSWD)
    }

    /// As [`Engine::new`], with another account database (tests).
    #[must_use]
    pub fn with_passwd(store: Store, passwd: impl Into<PathBuf>) -> Self {
        Self {
            store,
            passwd: passwd.into(),
            lock: Mutex::new(()),
        }
    }

    /// Its store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Verify `bytes` as a bundle for this host from its owner, newer than the one it holds, and
    /// make it the host's: every environment and grant replaced, every use and suspension reset.
    ///
    /// # Errors
    ///
    /// Any refusal of the bundle; nothing is changed then.
    pub fn import(&self, bytes: &[u8]) -> Result<Opened> {
        let _held = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (host, _) = identity::load(self.store.dir())?;
        let owner = identity::owner(self.store.dir())?;
        let state = self.store.state()?;
        let opened = match bundle::open(bytes, &owner, &host, state.sequence) {
            Ok(o) => o,
            Err(e) => {
                let _ = self.store.audit("", "IMPORT_REFUSED", &e.to_string());
                return Err(e);
            }
        };
        self.store.replace_bundle(bytes, opened.sequence)?;
        let names: Vec<&str> = opened
            .contents
            .grants
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        self.store.audit(
            "",
            "IMPORTED",
            &format!(
                "sequence {} for host {:?}, presence {:?}, grants [{}]",
                opened.sequence,
                opened.contents.host_name,
                opened.contents.presence,
                names.join(", ")
            ),
        )?;
        Ok(opened)
    }

    /// The bundle the host holds, verified again.
    ///
    /// # Errors
    ///
    /// If there is none, or it no longer verifies.
    pub fn current(&self) -> Result<Opened> {
        let (host, _) = identity::load(self.store.dir())?;
        let owner = identity::owner(self.store.dir())?;
        let bytes = self
            .store
            .bundle()?
            .ok_or_else(|| HostError::Invalid("no bundle has been imported".to_owned()))?;
        let opened = bundle::open(&bytes, &owner, &host, None)?;
        if self.store.state()?.sequence != Some(opened.sequence) {
            return Err(HostError::Invalid(
                "the bundle on disk is not the one that was imported".to_owned(),
            ));
        }
        Ok(opened)
    }

    /// Answer one request.
    #[must_use]
    pub fn handle(&self, request: &Request) -> Response {
        let release = {
            let _held = self
                .lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match self.decide(request) {
                Ok(r) => r,
                Err(response) => return response,
            }
        };
        self.release(request, release)
    }

    fn refuse(&self, grant: &str, reason: &str, message: impl Into<String>) -> Response {
        let message = message.into();
        let _ = self.store.audit(grant, reason, &message);
        refused(reason, message)
    }

    fn suspend(&self, grant: &str, reason: &str, message: &str) -> Response {
        let suspended = self.store.state().and_then(|mut state| {
            state.grants.entry(grant.to_owned()).or_default().suspended = Some(Suspended {
                at: kagisecure_core::unix_now(),
                reason: reason.to_owned(),
            });
            self.store.save_state(&state)
        });
        let message = match suspended {
            Ok(()) => format!(
                "{message} The grant is suspended until a new bundle is imported from the Mac."
            ),
            Err(e) => format!("{message} The suspension could not be saved: {e}."),
        };
        self.refuse(grant, reason, message)
    }

    fn decide(&self, request: &Request) -> std::result::Result<Release, Response> {
        let name = request.grant.as_str();
        let opened = self
            .current()
            .map_err(|e| self.refuse(name, "NO_BUNDLE", format!("No usable bundle: {e}")))?;
        let Some(grant) = opened.contents.grant(name) else {
            return Err(self.refuse(
                name,
                "NO_SUCH_GRANT",
                format!("This host holds no grant called {name:?}."),
            ));
        };
        let mut state = self
            .store
            .state()
            .map_err(|e| self.refuse(name, "STATE_UNAVAILABLE", e.to_string()))?;
        let gs = state.grants.entry(name.to_owned()).or_default();
        if let Some(s) = &gs.suspended {
            return Err(self.refuse(
                name,
                "SUSPENDED",
                format!(
                    "The grant was suspended ({}); import a new bundle from the Mac.",
                    s.reason
                ),
            ));
        }
        if kagisecure_core::unix_now() >= grant.limits.expires_at {
            return Err(self.refuse(name, "EXPIRED", "The grant has expired."));
        }
        if gs.uses >= grant.limits.total_uses {
            return Err(self.refuse(name, "USED_UP", "The grant has no uses left."));
        }
        if let Err(m) = grant.matches(&request.argv, &request.cwd) {
            return Err(self.suspend(
                name,
                m.as_str(),
                &format!(
                    "The request is not the command the grant names ({}, in {}).",
                    grant.command_line(),
                    grant.working_dir
                ),
            ));
        }
        if !grant.pin_holds() {
            return Err(self.suspend(
                name,
                "PIN_CHANGED",
                &format!(
                    "{} is not the file the grant pinned.",
                    grant.executable.path
                ),
            ));
        }
        let run_as = match &grant.run_as {
            None => None,
            Some(user) => Some(
                crate::passwd::lookup(&self.passwd, user)
                    .map_err(|e| self.refuse(name, "RUN_AS_UNKNOWN", e.to_string()))?,
            ),
        };
        let env = opened
            .contents
            .environment(&grant.environment)
            .ok_or_else(|| {
                self.refuse(name, "NO_ENVIRONMENT", "The grant's environment is gone.")
            })?;
        let mut injections = Vec::with_capacity(grant.variables.len());
        for var in &grant.variables {
            let value = env
                .variables
                .iter()
                .find(|v| &v.name == var)
                .ok_or_else(|| self.refuse(name, "NO_VARIABLE", format!("{var} is gone.")))?;
            injections.push(EnvInjection {
                name: VarName::new(var.clone())
                    .map_err(|e| self.refuse(name, "NO_VARIABLE", e.to_string()))?,
                value: Secret::new(value.value.expose().to_vec()),
            });
        }
        // Counted and audited before anything is released (ADR-0040).
        gs.uses += 1;
        let uses = gs.uses;
        self.store
            .save_state(&state)
            .map_err(|e| refused("STATE_UNAVAILABLE", e.to_string()))?;
        self.store
            .audit(
                name,
                "RELEASED",
                &format!(
                    "STDIN {:?} to {:?} in {} as {}, use {uses}/{}",
                    grant.variables,
                    request.argv,
                    request.cwd,
                    grant.run_as.as_deref().unwrap_or("(host account)"),
                    grant.limits.total_uses
                ),
            )
            .map_err(|e| {
                refused(
                    "AUDIT_UNAVAILABLE",
                    format!("Nothing was released: the audit log cannot be written ({e})."),
                )
            })?;
        Ok(Release {
            grant: grant.clone(),
            injections,
            run_as,
        })
    }

    fn release(&self, request: &Request, release: Release) -> Response {
        let program = OsString::from(&request.argv[0]);
        let args: Vec<OsString> = request.argv[1..].iter().map(OsString::from).collect();
        let outcome = run_with_env(&RunRequest {
            program: &program,
            args: &args,
            env: &release.injections,
            delivery: Delivery::Stdin,
            cwd: Some(Path::new(&release.grant.working_dir)),
            mask_output: true,
            max_output: MAX_OUTPUT,
            timeout: Some(Duration::from_secs(u64::from(release.grant.timeout_secs))),
            new_process_group: true,
            run_as: release.run_as.as_ref(),
        });
        drop(release.injections);
        let name = release.grant.name.as_str();
        match outcome {
            Ok(o) => {
                let _ = self.store.audit(
                    name,
                    if o.timed_out { "TIMED_OUT" } else { "FINISHED" },
                    &format!("exit {:?}, {} masked", o.exit_code, o.masked),
                );
                Response::Ran {
                    exit_code: o.exit_code,
                    timed_out: o.timed_out,
                    stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
                }
            }
            Err(e) => self.refuse(name, "SPAWN_FAILED", e.to_string()),
        }
    }
}

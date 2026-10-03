//! Runs: a job's root started by kagisecure in a process group of its own, and the binding of a
//! request to one (ADR-0042 §4).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kagisecure_core::inject::ChildKillHandle;
use kagisecure_core::vault::machine::{GrantId, JobId};

use crate::children::ChildRegistry;

/// How many parents the binding walks up from the requester before giving up (ADR-0042 §4).
pub const MAX_ANCESTRY_HOPS: usize = 16;

/// A live run of a job.
pub struct Run {
    /// This run's number, unique for the life of the engine.
    pub id: u64,
    /// The job.
    pub job: JobId,
    /// The job's name, for the audit actor and the status.
    pub job_name: String,
    /// The root's kernel pid.
    pub root_pid: u32,
    /// The root's kernel-recorded start time, if the kernel reported one. A run with none cannot
    /// be bound to, since pid reuse could not be told apart.
    pub root_start: Option<u64>,
    /// The root executable's path.
    pub root_exe: String,
    /// Unix seconds when it started.
    pub started_at: u64,
    /// When it must end.
    pub deadline: Instant,
    kill: ChildKillHandle,
    /// Commands released during this run: ended with it.
    pub(crate) children: ChildRegistry,
    /// Releases per grant during this run, for the per-run limit.
    per_grant: Mutex<HashMap<GrantId, u32>>,
    /// One-time codes per login grant during this run: at most one per sign-in (§12.5).
    codes: Mutex<HashMap<GrantId, u32>>,
    /// Why the run was ended from outside, once it was.
    ended: Mutex<Option<&'static str>>,
    finished: AtomicBool,
    /// The run's own browser, for a job that declares one (ADR-0042 §12.3). Taken and torn down
    /// when the run ends.
    pub(crate) browser: Mutex<Option<Arc<super::browser::RunBrowser>>>,
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Run")
            .field("id", &self.id)
            .field("job", &self.job_name)
            .field("root_pid", &self.root_pid)
            .finish_non_exhaustive()
    }
}

impl Run {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: u64,
        job: JobId,
        job_name: String,
        root_pid: u32,
        root_start: Option<u64>,
        root_exe: String,
        deadline: Instant,
        kill: ChildKillHandle,
    ) -> Self {
        Self {
            id,
            job,
            job_name,
            root_pid,
            root_start,
            root_exe,
            started_at: kagisecure_core::unix_now(),
            deadline,
            kill,
            children: ChildRegistry::new(),
            per_grant: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            ended: Mutex::new(None),
            finished: AtomicBool::new(false),
            browser: Mutex::new(None),
        }
    }

    /// Seconds left before the deadline, at least 1.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(1))
    }

    /// Whether the run is still going: not ended from outside, root not yet reaped.
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.finished.load(Ordering::SeqCst) && self.ended_reason().is_none()
    }

    pub(crate) fn ended_reason(&self) -> Option<&'static str> {
        *self.ended.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// End the run from outside: its root's process group, and every command released in it. The
    /// monitor reaps the root and records the end.
    pub fn end(&self, reason: &'static str) {
        {
            let mut ended = self.ended.lock().unwrap_or_else(|e| e.into_inner());
            if ended.is_none() {
                *ended = Some(reason);
            }
        }
        self.kill.kill(crate::children::CHILD_KILL_GRACE);
    }

    pub(crate) fn mark_finished(&self) {
        self.finished.store(true, Ordering::SeqCst);
    }

    /// Take one release of `grant` against its per-run limit; `false` if the limit is reached.
    pub(crate) fn reserve(&self, grant: GrantId, per_run: u32) -> bool {
        let mut counts = self.per_grant.lock().unwrap_or_else(|e| e.into_inner());
        let used = counts.entry(grant).or_insert(0);
        if *used >= per_run {
            return false;
        }
        *used += 1;
        true
    }

    /// The run's browser, while it has one.
    pub(crate) fn browser(&self) -> Option<Arc<super::browser::RunBrowser>> {
        self.browser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Take the run's browser out, to tear it down.
    pub(crate) fn take_browser(&self) -> Option<Arc<super::browser::RunBrowser>> {
        self.browser
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// How many uses of `grant` this run has taken: for a login grant, its sign-ins.
    pub(crate) fn sign_ins(&self, grant: GrantId) -> u32 {
        self.per_grant
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&grant)
            .copied()
            .unwrap_or(0)
    }

    /// Take one one-time code of `grant`, at most `limit` in this run.
    pub(crate) fn reserve_code(&self, grant: GrantId, limit: u32) -> bool {
        let mut counts = self.codes.lock().unwrap_or_else(|e| e.into_inner());
        let used = counts.entry(grant).or_insert(0);
        if *used >= limit {
            return false;
        }
        *used += 1;
        true
    }

    /// Give back a code [`Run::reserve_code`] took.
    pub(crate) fn unreserve_code(&self, grant: GrantId) {
        let mut counts = self.codes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(used) = counts.get_mut(&grant) {
            *used = used.saturating_sub(1);
        }
    }

    /// Give back a use [`Run::reserve`] took, for a release that did not happen.
    pub(crate) fn unreserve(&self, grant: GrantId) {
        let mut counts = self.per_grant.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(used) = counts.get_mut(&grant) {
            *used = used.saturating_sub(1);
        }
    }
}

/// Every live run.
#[derive(Default)]
pub struct RunRegistry {
    runs: Mutex<Vec<Arc<Run>>>,
}

impl RunRegistry {
    fn runs(&self) -> std::sync::MutexGuard<'_, Vec<Arc<Run>>> {
        self.runs.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn add(&self, run: Arc<Run>) {
        self.runs().push(run);
    }

    pub(crate) fn remove(&self, id: u64) {
        self.runs().retain(|r| r.id != id);
    }

    /// Every live run, newest last.
    #[must_use]
    pub fn live(&self) -> Vec<Arc<Run>> {
        self.runs()
            .iter()
            .filter(|r| r.is_live())
            .cloned()
            .collect()
    }

    /// Every run not yet removed, live or ending.
    pub(crate) fn all(&self) -> Vec<Arc<Run>> {
        self.runs().clone()
    }

    /// Whether `job` has a live run.
    #[must_use]
    pub fn job_is_running(&self, job: JobId) -> bool {
        self.runs().iter().any(|r| r.job == job && r.is_live())
    }

    /// End every run (a disarm, a stop).
    pub fn end_all(&self, reason: &'static str) {
        for run in self.runs().iter() {
            run.end(reason);
        }
    }

    /// The live run whose process tree `peer_pid` is in, if any (ADR-0042 §4): walk the kernel's
    /// parent links from the peer, at most [`MAX_ANCESTRY_HOPS`] of them, to a live run's root
    /// with the recorded pid **and** start time. A chain that breaks, reaches `launchd`, or runs
    /// out of hops is in no run.
    #[must_use]
    pub fn bind(&self, peer_pid: Option<u32>) -> Option<Arc<Run>> {
        let mut pid = peer_pid?;
        let live = self.live();
        for _ in 0..=MAX_ANCESTRY_HOPS {
            if let Some(run) = live.iter().find(|r| r.root_pid == pid) {
                let start = kagisecure_ipc::server::process_start_time(pid);
                return (run.root_start.is_some() && start == run.root_start)
                    .then(|| Arc::clone(run));
            }
            pid = kagisecure_extension_ipc::peer::parent_pid(pid)?;
            if pid <= 1 {
                return None;
            }
        }
        None
    }
}

/// Whether `pid` is `ancestor` (started at `ancestor_start`) or descends from it, walking the
/// kernel's parent links at most [`MAX_ANCESTRY_HOPS`] times — the unattended extension endpoint's
/// gate (ADR-0042 §12.4). The start time is compared where the chain reaches `ancestor`'s pid, so
/// a later process handed that pid is not it.
#[must_use]
pub fn descends_from(pid: u32, ancestor: u32, ancestor_start: u64) -> bool {
    let mut pid = pid;
    for _ in 0..=MAX_ANCESTRY_HOPS {
        if pid == ancestor {
            return kagisecure_ipc::server::process_start_time(pid) == Some(ancestor_start);
        }
        let Some(parent) = kagisecure_extension_ipc::peer::parent_pid(pid) else {
            return false;
        };
        if parent <= 1 {
            return false;
        }
        pid = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_descends_from_this_process_and_this_process_from_no_child() {
        let me = std::process::id();
        let Some(start) = kagisecure_ipc::server::process_start_time(me) else {
            return;
        };
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn");
        let pid = child.id();
        assert!(descends_from(pid, me, start));
        assert!(descends_from(me, me, start));
        // The wrong start time: a later process handed this pid is not it.
        assert!(!descends_from(pid, me, start.wrapping_add(1)));
        // Not the other way round, and not a stranger.
        let child_start = kagisecure_ipc::server::process_start_time(pid).unwrap_or(0);
        assert!(!descends_from(me, pid, child_start));
        let _ = child.kill();
        let _ = child.wait();
    }
}

//! Tracking `run_with_env` children so a vault lock — or the agent simply stopping — can end what
//! an approval started.
//!
//! `docs/mcp-server.md`'s "lock ends what an approval started" covers files a lease wrote
//! ([`crate::vault`]'s lock hook, via `kagisecure_core::lease::LeaseStore::revoke_all`) and it
//! covers a child process the same way: a `run_with_env` command keeps running, with the injected
//! value still in its environment, on a connection thread that is blocked inside
//! `kagisecure_core::inject::run_with_env`'s own wait loop — a thread the lock has no other way to
//! reach. `crate::agent::Agent::stop()` (app quit, agent toggled off) has the identical problem
//! even when nothing locks the vault: the connection thread and its child do not know the socket
//! just went away, so [`ChildRegistry::kill_all_for_stop`] is the same cure for that case.
//!
//! This registry is that other way. [`Service::run_with_env`](crate::service::Service) registers
//! a child the instant it exists (via `run_with_env_tracked`'s `on_spawn`) and deregisters it the
//! moment its own `wait()` returns, on every exit path — so an entry here always describes a child
//! that is still actually running, and [`ChildRegistry::kill_all_for_lock`] (or
//! [`ChildRegistry::kill_all_for_stop`]) never leaks one whose process the OS has long since
//! reaped and whose pid it may have reused for something else.
//!
//! # Where the audit entry comes from
//!
//! A killed child needs a `Failed`/`KILLED_ON_LOCK` entry recorded (ADR pattern: same tool, lease,
//! target and variables as the `Allowed` entry it follows, `detail` naming that entry's `seq`).
//! The ordinary way an abnormal `run_with_env` outcome gets that — [`crate::release::Acted`]'s
//! `abnormal` arm, written by [`crate::release::audited_release`]'s own follow-up call — does not
//! work here: that call goes through [`crate::vault::VaultHandle::record_best_effort`], which
//! needs the vault still in the handle, and by the time a lock's ordinary hooks run
//! ([`crate::vault::VaultHandle::take`]) the handle has already given it up. So this registry
//! builds the `Failed` draft itself, from the template and `seq` it was registered with, and hands
//! it back to the caller — `crate::agent::Agent::start`'s vault-lock hook — to queue directly on
//! the vault that is *about* to be taken away, while it is still there to queue onto
//! ([`crate::vault::VaultHandle::add_vault_lock_hook`]).
//!
//! `Agent::stop()` does not take the vault away — it may still be unlocked once the agent has
//! stopped — so its `KILLED_ON_STOP` drafts need none of that: `record_best_effort` is called the
//! ordinary way, exactly as `Service::kill_running_children` already does for the MCP channel's own
//! early-cleanup `lock` tool.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::ChildKillHandle;
use kagisecure_core::proto::Outcome;

/// How long a `run_with_env` child gets between `SIGTERM` and `SIGKILL` when the vault locks out
/// from under it (Unix only — see [`ChildKillHandle::kill`]).
///
/// Short on purpose: "lock ends what an approval started" means the injected value should stop
/// being reachable promptly, not that a slow child gets to linger. Long enough that a well-behaved
/// program's own `SIGTERM` handler (flushing a log, closing a socket) has a real chance to run
/// before the hard kill.
pub const CHILD_KILL_GRACE: Duration = Duration::from_secs(2);

/// A registration handle, so a caller can deregister exactly the entry it registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildId(u64);

struct Tracked {
    kill: ChildKillHandle,
    /// The release's own `AuditDraft` (tool, actor, lease, environment, variables, target — its
    /// `outcome` and `detail` are ignored and overwritten on use), captured at registration so
    /// this registry never needs to reach back into whatever registered it.
    template: AuditDraft,
    /// The `seq` of the `Allowed` entry a `KILLED_ON_LOCK` follow-up for this child should name.
    entry_seq: u64,
}

/// A lock or a stop has drained the registry: nothing registers any more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryClosed;

#[derive(Default)]
struct State {
    children: BTreeMap<u64, Tracked>,
    /// Set by the first [`ChildRegistry::kill_all_for_lock`] or
    /// [`ChildRegistry::kill_all_for_stop`], and never cleared: an agent does not serve again
    /// after either — a locked vault never comes back into the same handle (a new unlock is a new
    /// handle and a new agent), and a stopped agent is rebuilt to start again.
    closed: bool,
}

/// Every child, in this process, currently running under an environment `run_with_env` injected.
#[derive(Default)]
pub struct ChildRegistry {
    next: AtomicU64,
    state: Mutex<State>,
}

impl ChildRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start tracking a spawned child. Call this the moment it exists — see
    /// `kagisecure_core::inject::run_with_env_tracked`'s own doc comment for why the timing
    /// matters: a lock arriving in the window before registration would see nothing to kill.
    ///
    /// # Errors
    ///
    /// [`RegistryClosed`] when a lock or a stop has already drained this registry. The child
    /// spawned *after* the release was prepared, and the lock landed in between: it found nothing
    /// to kill then, so it is killed now, at once, before this returns — the one outcome "lock
    /// ends what an approval started" allows. Checked under the same mutex the drain takes, so a
    /// registration is either drained by the lock or refused by it; there is no third order.
    pub fn register(
        &self,
        kill: ChildKillHandle,
        template: AuditDraft,
        entry_seq: u64,
    ) -> Result<ChildId, RegistryClosed> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state();
        if state.closed {
            drop(state);
            kill.kill_now();
            return Err(RegistryClosed);
        }
        state.children.insert(
            id,
            Tracked {
                kill,
                template,
                entry_seq,
            },
        );
        Ok(ChildId(id))
    }

    /// Stop tracking a child once its own `wait()` has returned — successfully, with an error, or
    /// because it was killed. This must run on every exit path: an entry left behind here outlives
    /// the process it describes, and a later lock would try to kill a pid the OS may have long
    /// since reused for something unrelated.
    pub fn deregister(&self, id: ChildId) {
        self.state().children.remove(&id.0);
    }

    /// On lock: ask every still-tracked child (and, so far as the OS allows, anything it spawned)
    /// to stop, and return one `Failed`/`KILLED_ON_LOCK` audit draft per child for the caller to
    /// queue directly on the vault before it is gone (see the module documentation for why it must
    /// be this caller and not this registry that writes it).
    ///
    /// Empties the registry and closes it: every child that was tracked a moment ago is either
    /// already being killed or has already exited (and was deregistered before this ran), and one
    /// that registers from now on — spawned after its release was prepared but after this lock —
    /// is killed at once by [`Self::register`] instead.
    ///
    /// Returns promptly regardless of `grace` or how many children there are:
    /// [`ChildKillHandle::kill`] itself returns immediately and finishes any hard kill it still
    /// owes on a thread of its own, so this call — made from the same thread that is taking the
    /// vault away — never makes a lock wait out a grace period.
    pub fn kill_all_for_lock(&self, grace: Duration) -> Vec<AuditDraft> {
        self.kill_all("KILLED_ON_LOCK", grace)
    }

    /// The other caller of [`Self::kill_all`]: `crate::agent::Agent::stop()`, for the app quitting
    /// or the agent being toggled off — not a vault lock, and possibly with the vault still
    /// unlocked afterwards. Same kill, same drained registry, same promptness; the only
    /// difference is the word an audit entry names, `KILLED_ON_STOP`, so the two are
    /// distinguishable in the log.
    pub fn kill_all_for_stop(&self, grace: Duration) -> Vec<AuditDraft> {
        self.kill_all("KILLED_ON_STOP", grace)
    }

    /// The shared body of [`Self::kill_all_for_lock`] and [`Self::kill_all_for_stop`]: drain the
    /// registry, kill everything in it, and hand back one `Failed` draft per child, its `detail`
    /// naming `reason` and the `Allowed` entry's `seq`.
    fn kill_all(&self, reason: &str, grace: Duration) -> Vec<AuditDraft> {
        let tracked: Vec<Tracked> = {
            let mut state = self.state();
            state.closed = true;
            std::mem::take(&mut state.children).into_values().collect()
        };
        tracked
            .into_iter()
            .map(|t| {
                t.kill.kill(grace);
                AuditDraft {
                    outcome: Outcome::Failed,
                    detail: Some(format!("{reason} (entry {})", t.entry_seq)),
                    ..t.template
                }
            })
            .collect()
    }

    /// How many children are tracked right now. Test and status-reporting use only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state().children.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// The registry's bookkeeping is platform-independent, but exercising it end to end needs a real
// child to register and kill — these tests shell out to `sleep`, exactly as
// `kagisecure-childproc`'s own tests do, so the whole module is Unix-only rather than needing a
// second, Windows-flavoured fixture that would test nothing this crate does differently.
#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;

    use kagisecure_core::inject::Spawned;

    use super::*;

    fn draft() -> AuditDraft {
        AuditDraft {
            tool: "run_with_env".to_owned(),
            ..AuditDraft::default()
        }
    }

    /// A real, short-lived child plus the handle this registry tracks it with. Kept alive for the
    /// whole test so it can be reaped, whichever way the test ends it.
    fn sleeping_child() -> (Spawned, ChildKillHandle) {
        let mut command = Command::new("sleep");
        command.arg("30");
        let child = Spawned::spawn(&mut command, true).expect("spawn sleep");
        let handle = child.kill_handle();
        (child, handle)
    }

    #[test]
    fn a_registered_child_is_deregistered_and_no_longer_killed_on_lock() {
        let (child, kill) = sleeping_child();
        let registry = ChildRegistry::new();
        let id = registry.register(kill, draft(), 7).expect("open");
        assert_eq!(registry.len(), 1);
        registry.deregister(id);
        assert!(registry.is_empty());
        assert!(
            registry
                .kill_all_for_lock(Duration::from_millis(1))
                .is_empty()
        );
        child.kill();
        let _ = child.reap();
    }

    #[test]
    fn locking_kills_every_tracked_child_and_names_its_allowed_entry() {
        let (mut first, first_kill) = sleeping_child();
        let (mut second, second_kill) = sleeping_child();
        let registry = ChildRegistry::new();
        let _ = registry.register(first_kill, draft(), 41);
        let _ = registry.register(second_kill, draft(), 42);
        assert_eq!(registry.len(), 2);

        let mut drafts = registry.kill_all_for_lock(Duration::from_millis(50));
        drafts.sort_by_key(|d| d.detail.clone());

        assert!(registry.is_empty(), "the registry itself is drained");
        assert_eq!(drafts.len(), 2);
        for (draft, seq) in drafts.iter().zip([41, 42]) {
            assert_eq!(draft.outcome, Outcome::Failed);
            assert_eq!(
                draft.detail.as_deref(),
                Some(format!("KILLED_ON_LOCK (entry {seq})").as_str())
            );
            assert_eq!(draft.tool, "run_with_env");
        }

        // The kill was sent; wait it out (well inside the 30s the child would otherwise sleep)
        // so this test does not leave a process behind.
        for child in [&mut first, &mut second] {
            let started = std::time::Instant::now();
            loop {
                if child.try_reap().expect("try_reap").is_some() {
                    break;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "should have died by now"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[test]
    fn stopping_kills_every_tracked_child_and_names_it_killed_on_stop() {
        // Same mechanics as a lock, different word: `Agent::stop()` (app quit, agent toggled off)
        // uses this instead of `kill_all_for_lock` so the two are told apart in the audit log.
        let (mut child, kill) = sleeping_child();
        let registry = ChildRegistry::new();
        let _ = registry.register(kill, draft(), 9);
        assert_eq!(registry.len(), 1);

        let drafts = registry.kill_all_for_stop(Duration::from_millis(50));

        assert!(registry.is_empty(), "the registry itself is drained");
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].outcome, Outcome::Failed);
        assert_eq!(
            drafts[0].detail.as_deref(),
            Some("KILLED_ON_STOP (entry 9)")
        );
        assert_eq!(drafts[0].tool, "run_with_env");

        let started = std::time::Instant::now();
        loop {
            if child.try_reap().expect("try_reap").is_some() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "should have died by now"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The lock race: `run_with_env` spawns its child *after* the release was prepared, so a
    /// lock can land between the two. The lock drains the registry — which is empty — and the
    /// child that registers a moment later was never killed. A registry the lock has drained is
    /// now closed: a late registration is refused, and the child killed at once.
    #[test]
    fn a_child_that_registers_after_the_lock_is_killed_at_once() {
        let registry = ChildRegistry::new();
        assert!(
            registry
                .kill_all_for_lock(Duration::from_millis(50))
                .is_empty()
        );

        let (mut child, kill) = sleeping_child();
        assert_eq!(
            registry.register(kill, draft(), 5),
            Err(RegistryClosed),
            "a registration after the lock is refused"
        );
        assert!(registry.is_empty(), "nothing is tracked past a lock");

        let started = std::time::Instant::now();
        loop {
            if child.try_reap().expect("try_reap").is_some() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "a child registered after the lock must not keep running"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The same for a plain stop: a registry `Agent::stop()` drained is closed too.
    #[test]
    fn a_child_that_registers_after_a_stop_is_killed_at_once() {
        let registry = ChildRegistry::new();
        let _ = registry.kill_all_for_stop(Duration::from_millis(50));
        let (mut child, kill) = sleeping_child();
        let _ = registry.register(kill, draft(), 6);
        let started = std::time::Instant::now();
        while child.try_reap().expect("try_reap").is_none() {
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

//! The auto-type broker: how an approved `request_type` reaches the app that types it
//! ([ADR-0050](../../../docs/decisions/0050-auto-type-into-native-apps.md)).
//!
//! # The contract
//!
//! Like the approval queue, nothing here calls into the foreign language:
//!
//! * The IPC thread that served `request_type` — after the sheet (or the grace window), and after
//!   the `Allowed` entry is on disk — calls [`AutoTypeBroker::deliver`] with an [`AutoTypeJob`]
//!   and blocks until the app reports how typing went, or [`JOB_TIMEOUT`] passes.
//! * The app polls [`AutoTypeBroker::next_job`] from a background task, verifies the frontmost
//!   app and the focused field, types, and answers with [`AutoTypeBroker::finish`].
//! * The app says whether it can type at all — it holds the Accessibility permission — with
//!   [`AutoTypeBroker::set_ready`]. A host with no app (`kagisecure daemon`) has no broker, and a
//!   broker that is not ready answers `TYPE_UNAVAILABLE` before any sheet.
//!
//! # Limits
//!
//! The same shape as agent fills after 2026-10-03 (ADR-0036 §9 as amended): one auto-type at a
//! time, **Deny and block this agent** for thirty minutes, and — because a keystroke stream is
//! cheaper to repeat than a browser flow — at most [`MAX_PER_WINDOW`] requests per agent in
//! [`RATE_WINDOW`]. Keyed by the sidecar's parent executable, never a self-reported name.
//!
//! # Values
//!
//! An [`AutoTypeJob`] carries values: it is the one thing in this crate, besides a browser fill,
//! that does. It is built only by `extension::crossing::auto_type_values` from a
//! [`Grant`](crate::approval::Grant), held in [`SecretText`] buffers that zeroize on drop, and
//! handed only to the app in this process. It is never serialized and never reaches the socket.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kagisecure_core::model::SecretText;
use kagisecure_ipc::protocol::{TypeField, TypeTarget};

/// How long a delivered job waits for the app to take it and report back. Typing a password is
/// well under a second; this covers a busy main thread, not a person.
pub const JOB_TIMEOUT: Duration = Duration::from_secs(20);

/// How long **Deny and block this agent** blocks auto-type for it.
pub const DENY_AND_BLOCK: Duration = Duration::from_secs(30 * 60);

/// The rate window.
pub const RATE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Most `request_type` calls one agent may make in [`RATE_WINDOW`].
pub const MAX_PER_WINDOW: usize = 30;

/// One value to type, named.
pub struct TypedValue {
    /// Which field it is.
    pub field: TypeField,
    /// The value, zeroized on drop.
    pub value: SecretText,
}

impl std::fmt::Debug for TypedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedValue")
            .field("field", &self.field)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// One approved auto-type, for the app to verify and type.
#[derive(Debug)]
pub struct AutoTypeJob {
    /// Opaque id, quoted back to [`AutoTypeBroker::finish`].
    pub id: String,
    /// The item's title, for a notice.
    pub item_title: String,
    /// The app that must be in front, and what else must match.
    pub target: TypeTarget,
    /// What to type, in order. Tab separates consecutive values.
    pub values: Vec<TypedValue>,
}

/// How typing went, as the app reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeOutcome {
    /// Every value was typed.
    Typed,
    /// Before anything was typed: the frontmost app, its team, its window title or the focused
    /// field did not match.
    TargetMismatch,
    /// Focus moved while typing; `typed_any` says whether some keystrokes were already sent.
    FocusChanged {
        /// Whether some keystrokes reached the app before typing stopped.
        typed_any: bool,
    },
    /// Another app holds secure keyboard input, so keystrokes would not arrive. Nothing typed.
    SecureInput,
    /// kagisecure lacks the Accessibility permission. Nothing typed.
    AccessibilityDenied,
    /// The app never took the job, or never reported back in time.
    TimedOut,
    /// The vault locked before the job was typed. Nothing typed.
    Locked,
}

impl TypeOutcome {
    /// The audit token for an outcome that is not [`Self::Typed`].
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Typed => "TYPED",
            Self::TargetMismatch => "NO_MATCHING_TARGET",
            Self::FocusChanged { typed_any: false } => "FOCUS_CHANGED",
            Self::FocusChanged { typed_any: true } => "FOCUS_CHANGED_PARTWAY",
            Self::SecureInput => "SECURE_INPUT",
            Self::AccessibilityDenied => "ACCESSIBILITY_DENIED",
            Self::TimedOut => "NOT_TYPED_IN_TIME",
            Self::Locked => "LOCKED_BEFORE_TYPING",
        }
    }
}

/// Why a request was refused before anyone was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitRefusal {
    /// The person pressed **Deny and block this agent** less than thirty minutes ago.
    Blocked,
    /// Another auto-type is in progress.
    Busy,
    /// This agent made [`MAX_PER_WINDOW`] requests in the last [`RATE_WINDOW`].
    RateLimited,
}

#[derive(Default)]
struct State {
    ready: bool,
    in_flight: bool,
    next_id: u64,
    queue: VecDeque<AutoTypeJob>,
    /// Jobs delivered and not yet settled: `None` while waiting, `Some` once reported.
    outcomes: HashMap<String, Option<TypeOutcome>>,
    blocks: BTreeMap<String, Instant>,
    recent: BTreeMap<String, VecDeque<Instant>>,
}

/// The process-wide auto-type broker. One per app; see the module documentation.
pub struct AutoTypeBroker {
    state: Mutex<State>,
    signal: Condvar,
    job_timeout: Duration,
}

impl Default for AutoTypeBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AutoTypeBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoTypeBroker")
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

/// The one-at-a-time slot. Dropping it frees the slot.
#[derive(Debug)]
pub struct AutoTypeSlot<'a> {
    broker: &'a AutoTypeBroker,
}

impl Drop for AutoTypeSlot<'_> {
    fn drop(&mut self) {
        self.broker.state().in_flight = false;
    }
}

impl AutoTypeBroker {
    /// A broker that is not ready until the app says so.
    #[must_use]
    pub fn new() -> Self {
        Self::with_job_timeout(JOB_TIMEOUT)
    }

    /// A broker whose jobs wait `job_timeout` — for tests.
    #[must_use]
    pub fn with_job_timeout(job_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(State::default()),
            signal: Condvar::new(),
            job_timeout,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the app can type: it is running, it holds the Accessibility permission and the
    /// person has not turned agent auto-type off.
    pub fn set_ready(&self, ready: bool) {
        self.state().ready = ready;
    }

    /// See [`Self::set_ready`].
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state().ready
    }

    /// Take the one-at-a-time slot for the agent `key`, at `now`, or say why not.
    ///
    /// # Errors
    ///
    /// [`AdmitRefusal`] when the agent is blocked, another auto-type is running, or the agent is
    /// over its rate.
    pub fn admit(&self, key: &str, now: Instant) -> Result<AutoTypeSlot<'_>, AdmitRefusal> {
        let mut state = self.state();
        state.blocks.retain(|_, until| *until > now);
        if state.blocks.contains_key(key) {
            return Err(AdmitRefusal::Blocked);
        }
        if state.in_flight {
            return Err(AdmitRefusal::Busy);
        }
        let recent = state.recent.entry(key.to_owned()).or_default();
        while recent
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= RATE_WINDOW)
        {
            recent.pop_front();
        }
        if recent.len() >= MAX_PER_WINDOW {
            return Err(AdmitRefusal::RateLimited);
        }
        recent.push_back(now);
        state.in_flight = true;
        Ok(AutoTypeSlot { broker: self })
    }

    /// Block the agent `key` for [`DENY_AND_BLOCK`] from `now`. Never shortens a block.
    pub fn block(&self, key: &str, now: Instant) {
        let until = now + DENY_AND_BLOCK;
        let mut state = self.state();
        let entry = state.blocks.entry(key.to_owned()).or_insert(until);
        *entry = (*entry).max(until);
    }

    /// A fresh job id nobody can guess.
    #[must_use]
    pub fn fresh_id(&self) -> String {
        let mut state = self.state();
        state.next_id = state.next_id.wrapping_add(1);
        format!(
            "type-{}-{}",
            state.next_id,
            kagisecure_core::proto::LeaseId::new()
        )
    }

    /// Hand `job` to the app and wait until it reports, or [`JOB_TIMEOUT`] passes.
    pub fn deliver(&self, job: AutoTypeJob) -> TypeOutcome {
        let id = job.id.clone();
        let deadline = Instant::now() + self.job_timeout;
        let mut state = self.state();
        if !state.ready {
            return TypeOutcome::AccessibilityDenied;
        }
        state.outcomes.insert(id.clone(), None);
        state.queue.push_back(job);
        self.signal.notify_all();
        loop {
            match state.outcomes.get(&id) {
                Some(Some(outcome)) => {
                    let outcome = *outcome;
                    state.outcomes.remove(&id);
                    return outcome;
                }
                Some(None) => {}
                // Swept by `revoke_all`.
                None => return TypeOutcome::Locked,
            }
            let now = Instant::now();
            if now >= deadline {
                // Untaken jobs are withdrawn, values and all.
                state.queue.retain(|j| j.id != id);
                state.outcomes.remove(&id);
                return TypeOutcome::TimedOut;
            }
            state = self
                .signal
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The app: wait up to `timeout` for a job, and take it.
    #[must_use]
    pub fn next_job(&self, timeout: Duration) -> Option<AutoTypeJob> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        loop {
            if let Some(job) = state.queue.pop_front() {
                return Some(job);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            state = self
                .signal
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The app: report how job `id` went. `false` when the id is unknown — it timed out, or a lock
    /// swept it.
    pub fn finish(&self, id: &str, outcome: TypeOutcome) -> bool {
        let mut state = self.state();
        match state.outcomes.get_mut(id) {
            Some(slot @ None) => {
                *slot = Some(outcome);
                self.signal.notify_all();
                true
            }
            _ => false,
        }
    }

    /// A lock: withdraw every job not yet taken and answer every waiting caller `Locked`.
    pub fn revoke_all(&self) {
        let mut state = self.state();
        state.queue.clear();
        state.outcomes.clear();
        self.signal.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn job(broker: &AutoTypeBroker) -> AutoTypeJob {
        AutoTypeJob {
            id: broker.fresh_id(),
            item_title: "Example".to_owned(),
            target: TypeTarget {
                bundle_id: "com.example.app".to_owned(),
                team_id: None,
                window_title: None,
            },
            values: vec![TypedValue {
                field: TypeField::Password,
                value: SecretText::new("hunter2".to_owned()),
            }],
        }
    }

    #[test]
    fn a_job_reaches_the_app_and_its_outcome_comes_back() {
        let broker = Arc::new(AutoTypeBroker::new());
        broker.set_ready(true);
        let app = Arc::clone(&broker);
        let typist = std::thread::spawn(move || {
            let job = app.next_job(Duration::from_secs(5)).expect("a job");
            assert_eq!(job.values[0].value.expose(), "hunter2");
            assert!(app.finish(&job.id, TypeOutcome::Typed));
            assert!(!app.finish(&job.id, TypeOutcome::Typed), "settled once");
        });
        assert_eq!(broker.deliver(job(&broker)), TypeOutcome::Typed);
        typist.join().unwrap();
    }

    #[test]
    fn an_untaken_job_times_out_and_is_withdrawn() {
        let broker = AutoTypeBroker::with_job_timeout(Duration::from_millis(50));
        broker.set_ready(true);
        assert_eq!(broker.deliver(job(&broker)), TypeOutcome::TimedOut);
        assert!(broker.next_job(Duration::from_millis(1)).is_none());
    }

    #[test]
    fn a_broker_that_is_not_ready_types_nothing() {
        let broker = AutoTypeBroker::new();
        assert_eq!(
            broker.deliver(job(&broker)),
            TypeOutcome::AccessibilityDenied
        );
        assert!(broker.next_job(Duration::from_millis(1)).is_none());
    }

    #[test]
    fn one_at_a_time_a_block_and_a_rate() {
        let broker = AutoTypeBroker::new();
        let now = Instant::now();
        let slot = broker.admit("agent", now).expect("admitted");
        assert_eq!(broker.admit("other", now).unwrap_err(), AdmitRefusal::Busy);
        drop(slot);
        broker.block("agent", now);
        assert_eq!(
            broker.admit("agent", now).unwrap_err(),
            AdmitRefusal::Blocked
        );
        assert!(broker.admit("agent", now + DENY_AND_BLOCK).is_ok());
        for _ in 1..MAX_PER_WINDOW {
            drop(broker.admit("busy", now).expect("under the rate"));
        }
        drop(broker.admit("busy", now).expect("the last one"));
        assert_eq!(
            broker.admit("busy", now).unwrap_err(),
            AdmitRefusal::RateLimited
        );
        assert!(broker.admit("busy", now + RATE_WINDOW).is_ok());
    }

    #[test]
    fn a_lock_answers_a_waiting_caller() {
        let broker = Arc::new(AutoTypeBroker::new());
        broker.set_ready(true);
        let locker = Arc::clone(&broker);
        let waiter = {
            let broker = Arc::clone(&broker);
            std::thread::spawn(move || broker.deliver(job(&broker)))
        };
        while locker.state().outcomes.is_empty() {
            std::thread::yield_now();
        }
        locker.revoke_all();
        assert_eq!(waiter.join().unwrap(), TypeOutcome::Locked);
    }

    #[test]
    fn a_job_debug_never_shows_a_value() {
        let broker = AutoTypeBroker::new();
        assert!(!format!("{:?}", job(&broker)).contains("hunter2"));
    }
}

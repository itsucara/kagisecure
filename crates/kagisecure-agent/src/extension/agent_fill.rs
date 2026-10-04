//! The agent-fill broker: how an agent's `request_fill` finds a browser tab, a human and a value
//! ([ADR-0036](../../../../docs/decisions/0036-agent-requested-browser-fill.md), Phases 1–3).
//!
//! # Where this sits
//!
//! An agent's request arrives on the MCP socket, on a thread of [`crate::service`]. The tab it is
//! about is on the *other* socket, the extension's, behind a native host. Neither channel can
//! reach into the other, so this broker is the rendezvous both sides hold an `Arc` to:
//!
//! ```text
//!   MCP thread (service.rs)                 AgentFillBroker                extension thread
//!   gates 1–4 ─▶ admit() ─▶ FlowSlot::serve                                (extension.rs)
//!                gate 7: audit pre-flight, before any tab is looked at
//!                gate 5: sessions? ────────── registry ◀── register() ◀── Hello{agent_fill}
//!                gate 6: push Locate ────────────────────────────────────▶ (browser)
//!                        wait ≤ 2 s ◀─────── reports ◀──── report() ◀──── TargetReport
//!                        locked meanwhile? then choose one tab
//!                gate 8: the sheet (no lock held)
//!                gate 9: issue grant, push Deliver ──────────────────────▶ (browser)
//!                        wait ≤ 30 s ◀────── redeem() ◀── AgentFill: re-check, release via
//!                                                           crossing inside audited_release
//!                        wait ≤ 10 s ◀────── outcome() ◀─ AgentFillOutcome
//!   FillResult / error ◀─
//! ```
//!
//! The value leaves the app in exactly one place: the `Filled` reply to the extension's own
//! `AgentFill` request, built by [`crossing::filled`] from an [`Approved`] this broker holds but
//! never opens. Nothing here reads a secret — `crossing`'s scan test covers this file too — and
//! the MCP thread gets back field **names** only.
//!
//! # What a grant is bound to
//!
//! One approval produces one [`AgentFillGrant`], never a lease (§6). It names the sidecar process
//! (its kernel pid, executable and start time, never what the sidecar says about itself), the
//! item, the exact fields, the browser-established origin, the extension session, the tab id,
//! frame 0 and the document id. It lives in this broker, not in any lease store, so a fill lease
//! cannot excuse it and it cannot mint one. It dies on first use, [`GRANT_LIFE`] after it was
//! issued, on a vault lock ([`AgentFillBroker::revoke_all`]), when its extension session
//! disconnects, and on any failed re-check — a request that gets one binding wrong spends the
//! grant.
//!
//! # Identifier-first sign-ins: one approval, two pages (§7.3)
//!
//! A request for username and password whose tab in front has only an identifier box is served
//! as a **two-step grant**, and the sheet says so. Step one's grant writes only the username —
//! built by [`crossing::username_only`], which borrows the [`Approved`] instead of spending it,
//! since a username is metadata (implementation decision 4). The agent is answered
//! `fields_written: ["username"]`, `fields_pending: ["password"]`, and the unspent approval waits
//! here as a [`PendingStep`] for at most [`FLOW_WINDOW`] from the approval.
//!
//! The agent presses the page's own Next button and calls `request_fill` again for
//! `["password"]`. That call — the same sidecar process, the same item, inside the window — is
//! a *continuation*: gate 1 takes the pending step out (spending it, whatever happens next),
//! the browser that served step one is asked afresh, and a report from the **same session and
//! tab**, in front, at the claimed origin, which [`continues_same_site`] with step one's origin,
//! is covered by the item and has a password field gets a fresh `Deliver` — a new probe id and a
//! new grant id — whose redemption spends the approval on the password. No second sheet. The
//! same document is allowed as well as a later one: a site that swaps the form in place without
//! navigating keeps its document id (implementation decision 38). A continuation that finds
//! anything else is `NO_MATCHING_TAB`, and the agent's retry is a new request with a sheet of its
//! own. Another item, another sidecar, another field set, a call after the window or after a
//! lock is never a continuation at all.
//!
//! # One-time codes (§7.4)
//!
//! `["one_time_code"]` is always its own request with its own sheet: no approval, pending or
//! not, ever covers a code it did not name. Its target must report a one-time-code field, and
//! its grant is spent by [`crossing::totp_code`] into the extension's `totp_code` reply — no
//! clipboard, on this path. Every entry for it is written under the tool name the extension
//! channel already uses for codes, `totp_code`.
//!
//! # Gate 1: one flow at a time, and the human's attention budgeted
//!
//! [`AgentFillBroker::admit`] is gate 1, and everything it decides is decided before the item is
//! looked up (§11.1), keyed on the sidecar's kernel-resolved parent executable — never on the
//! name the agent reports ([`limits`], §9):
//!
//! 1. a **blocked** agent — *Deny and block* for thirty minutes, or a second origin mismatch until
//!    the human unblocks it — is `USER_DENIED` without a sheet, audited `AGENT_FILL_BLOCKED`;
//! 2. a request the human **denied or let time out** in the last ten minutes, for the same agent,
//!    item and origin, is `USER_DENIED` without a sheet, audited `AGENT_FILL_BLOCKED`;
//! 3. an agent that has had **three sheets in ten minutes** is `RATE_LIMITED` without a sheet for
//!    the next ten, audited `AGENT_FILL_RATE_LIMITED`, and the human hears about it once;
//! 4. while **another agent fill is in progress**, anywhere in the process, the request is
//!    `RATE_LIMITED` at once rather than queued, audited `AGENT_FILL_BUSY`. §9.1 asks for one
//!    *sheet* on screen at a time; the slot is held for the whole *flow*, gate 1 to the answer,
//!    which is the stricter form of the same rule since a flow raises at most one sheet
//!    (ADR-0036, implementation decision 18).
//!
//! The limits live here, in the process-wide broker, so they survive a vault lock; only the
//! origin-mismatch count starts again with each unlock session.
//!
//! # Blocking, and what is never held across a wait
//!
//! `request_fill` is one IPC call that returns when the flow is over, so the MCP thread blocks:
//! at most the probe window, the approval's 60 seconds, the grant's 30 and the outcome wait. The
//! broker's own mutex is taken only for bookkeeping and released before every wait, every push
//! and every vault access; no vault lock is held anywhere in this file except inside the release
//! transaction that `audited_release` runs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Item, ItemId};
use kagisecure_core::proto::Outcome as AuditOutcome;
use kagisecure_extension_ipc::listener::PushSender;
use kagisecure_extension_ipc::origin::{
    AgentOriginRendering, Origin, continues_same_site, covering_website,
};
use kagisecure_extension_ipc::peer::HostIdentity;
use kagisecure_extension_ipc::protocol::{
    AgentFillFailure, AgentFillField as PageField, ErrorCode as ExtCode, FillField, FoundFields,
    PageContext, Push, Response as ExtResponse, TabFacts,
};
use kagisecure_ipc::protocol::{AgentFillField, ErrorCode, Response};
use kagisecure_ipc::server::{PeerIdentity, executable_for_pid, process_start_time};

pub mod limits;

pub use limits::{AgentFillBlock, AgentFillBlockReason, DENY_AND_BLOCK};
use limits::{Limits, Refusal};

use super::crossing::{self, Approved};
use crate::approval::{AgentFillFacts, ApprovalKind, ApprovalQueue, ApprovalRequest};
use crate::catalog::Catalog;
use crate::release::{self, Acted, NotReleased, Released, audited_release};
use crate::shared::SheetFacts;
use crate::vault::{REQUEST_LOCK_TIMEOUT, VaultHandle};

/// How long the broker waits for the connected browsers to report the tab in front (§3.2).
///
/// The wait ends early once every session that was asked has answered — the extension answers
/// every `Locate`, with an ineligible report when it has nothing to report on — so this bounds a
/// browser that does not answer at all.
pub const PROBE_WINDOW: Duration = Duration::from_secs(2);

/// How long an approved grant waits to be redeemed by the extension (§6): thirty seconds after it
/// was issued, which is the time between the human's fingerprint and the extension's `AgentFill`
/// arriving — in practice well under one.
pub const GRANT_LIFE: Duration = Duration::from_secs(30);

/// How long, after a value was released, the broker waits for the extension to say whether it was
/// written.
pub const OUTCOME_WAIT: Duration = Duration::from_secs(10);

/// How long a redemption may run before the flow stops waiting for it: the release transaction's
/// own bound on waiting for the vault file ([`REQUEST_LOCK_TIMEOUT`]) and ten seconds for the
/// write itself.
///
/// A redemption that is still running when this passes did not end the way redemptions end — its
/// thread panicked, say — and the one flow slot must not wait for it forever. One that does finish
/// afterwards finds the flow gone and hands nothing out ([`AgentFillBroker::redeem`]).
pub const REDEEM_DEADLINE: Duration = REQUEST_LOCK_TIMEOUT.saturating_add(Duration::from_secs(10));

/// How long the whole identifier-first flow may take (§6, §7.3): from the approval to the
/// password's redemption on the next page. A step two asked for later is a new request.
pub const FLOW_WINDOW: Duration = Duration::from_secs(60);

/// How long a released fill is remembered for a late follow-up (the §8.3 tripwire reports up to
/// ten seconds after the write).
const FOLLOW_UP_MEMORY: Duration = Duration::from_secs(60);

/// How long after the extension reported writing a password it may still report the tripwire
/// (§8.3): the content script watches for ten seconds, and the report takes a moment to arrive.
/// An `UNMASKED` outcome later than this, or for a fill that wrote no password, is ignored.
pub const TRIPWIRE_WINDOW: Duration = Duration::from_secs(15);

/// How many released fills are remembered for a late follow-up.
const FOLLOW_UP_SLOTS: usize = 16;

/// How many notices wait for the app before the oldest is dropped.
const NOTICE_SLOTS: usize = 32;

/// The tool name every agent-fill audit entry for a login is written under.
pub const TOOL: &str = "request_fill";

/// The tool name every audit entry for an agent's one-time-code request is written under: the
/// one the extension channel already uses for codes (ADR-0036 §7.4, §10).
pub const CODE_TOOL: &str = "totp_code";

/// The tool an entry about `fields` is written under: [`CODE_TOOL`] for a valid one-time-code
/// request, [`TOOL`] for everything else.
fn tool_for(fields: &[AgentFillField]) -> &'static str {
    if fields == [AgentFillField::OneTimeCode] {
        CODE_TOOL
    } else {
        TOOL
    }
}

/// Audit `detail` tokens for agent fills (ADR-0036 §10). A fixed vocabulary, like every other
/// `detail` this project writes.
pub mod audit_detail {
    /// The fill was approved by the human and its value released to the extension. Written
    /// `Allowed`, inside the release transaction, before the value leaves the app.
    pub const AGENT_FILL_APPROVED: &str = "AGENT_FILL_APPROVED";
    /// [`AGENT_FILL_APPROVED`], for a grant bound without a document id because the browser did
    /// not report one: the binding degraded to tab id, frame 0 and the exact origin (§4, §12),
    /// and the log says so rather than leaving it silent.
    pub const AGENT_FILL_APPROVED_WITHOUT_DOCUMENT_ID: &str =
        "AGENT_FILL_APPROVED (no document id)";
    /// [`AGENT_FILL_APPROVED`] for step one of an identifier-first grant: the username only.
    /// Step two's entry reads `"AGENT_FILL_APPROVED (step 2 of 2, entry N)"`, naming this one.
    /// Either gains `", no document id"` inside the parentheses when the binding degraded.
    pub const AGENT_FILL_APPROVED_STEP_ONE: &str = "AGENT_FILL_APPROVED (step 1 of 2)";
    /// Step one wrote the username, and the password step never came: the flow window closed,
    /// or the browser session that served step one went away, first. A follow-up of step one's
    /// entry, `"AGENT_FILL_PENDING_EXPIRED (entry N)"`.
    pub const AGENT_FILL_PENDING_EXPIRED: &str = "AGENT_FILL_PENDING_EXPIRED";
    /// Step one wrote the username, and the agent's call for the password was refused: its tab
    /// was not the same sign-in on the same tab, or it could not be served. The pending step is
    /// spent. A follow-up of step one's entry, `"AGENT_FILL_PENDING_REFUSED (entry N)"`.
    pub const AGENT_FILL_PENDING_REFUSED: &str = "AGENT_FILL_PENDING_REFUSED";
    /// The human denied, or the sheet timed out.
    pub const AGENT_FILL_DENIED: &str = "AGENT_FILL_DENIED";
    /// No eligible tab, more than one, or a tab on a saved site but not at the claimed origin.
    pub const AGENT_FILL_NO_TARGET: &str = "AGENT_FILL_NO_TARGET";
    /// The tab in front is on an origin the item is not saved for (§9.4).
    pub const AGENT_FILL_ORIGIN_MISMATCH: &str = "AGENT_FILL_ORIGIN_MISMATCH";
    /// Approved, but nothing was released: the grant expired, a re-check refused it, the
    /// extension reported it could not deliver, or its session went away. There is no
    /// `(entry N)`: the `Allowed` entry is written only at release, and there was none — except
    /// for a release that committed after the flow stopped waiting for it ([`REDEEM_DEADLINE`]),
    /// whose value was then not handed out: that one is a follow-up,
    /// `"AGENT_FILL_NOT_DELIVERED (entry N)"`.
    pub const AGENT_FILL_NOT_DELIVERED: &str = "AGENT_FILL_NOT_DELIVERED";
    /// Released, but the content script reported it could not write. A follow-up,
    /// `"AGENT_FILL_NOT_WRITTEN (entry N)"`.
    pub const AGENT_FILL_NOT_WRITTEN: &str = "AGENT_FILL_NOT_WRITTEN";
    /// Released, but the extension never said whether it wrote: its outcome did not arrive in
    /// time, or its connection closed first. A follow-up, `"AGENT_FILL_NOT_CONFIRMED (entry N)"`.
    pub const AGENT_FILL_NOT_CONFIRMED: &str = "AGENT_FILL_NOT_CONFIRMED";
    /// The tripwire of §8.3 fired after the write. A follow-up, `"AGENT_FILL_UNMASKED (entry N)"`.
    pub const AGENT_FILL_UNMASKED: &str = "AGENT_FILL_UNMASKED";
    /// [`AGENT_FILL_DENIED`], when the human pressed **Deny and block this agent**: the agent is
    /// blocked for thirty minutes from then (§9.3).
    pub const AGENT_FILL_DENIED_AND_BLOCKED: &str = "AGENT_FILL_DENIED (agent blocked)";
    /// [`AGENT_FILL_ORIGIN_MISMATCH`], for the mismatch that blocked the agent until the human
    /// unblocks it (§9.4).
    pub const AGENT_FILL_ORIGIN_MISMATCH_AND_BLOCKED: &str =
        "AGENT_FILL_ORIGIN_MISMATCH (agent blocked)";
    /// Answered `USER_DENIED` without a sheet: the agent is blocked, or the human denied (or let
    /// time out) the identical request within ten minutes (§9.1, §9.3).
    pub const AGENT_FILL_BLOCKED: &str = "AGENT_FILL_BLOCKED";
    /// Answered `RATE_LIMITED` without a sheet: the agent has had three sheets in ten minutes
    /// (§9.1).
    pub const AGENT_FILL_RATE_LIMITED: &str = "AGENT_FILL_RATE_LIMITED";
    /// Answered `RATE_LIMITED` at once: another agent fill was already in progress, and they are
    /// served one at a time (§9.1).
    pub const AGENT_FILL_BUSY: &str = "AGENT_FILL_BUSY";
}

/// The one answer for every reason there is no tab to fill (ADR-0036 §11.2): one code, one
/// sentence, so the agent cannot tell "not at that origin" from "not a site saved for the item".
pub(crate) const NO_MATCHING_TAB: &str = "kagisecure found no tab it can fill: the tab in front \
     is not at that origin, is not a sign-in page kagisecure recognizes, is not visible, is not a \
     site saved for this item, or changed before the fill. Nothing was filled. Bring the right tab \
     to the front and retry at most once.";

/// The answer when the item has no value for a requested field (gate 4).
pub(crate) const NOTHING_TO_FILL: &str = "That item has no value for a field you asked to fill. \
     Nothing was filled. Check describe_item.";

/// The answer for an archived item (gate 4, implementation decision 13): found, but not a
/// candidate for a fresh sign-in.
pub(crate) const ARCHIVED: &str = "That item is archived, so kagisecure does not fill it into a \
     sign-in page. Nothing was filled. Ask the user to restore it in kagisecure if it is still in \
     use.";

/// The answer when another agent fill is already in progress (gate 1).
pub(crate) const BUSY: &str = "kagisecure is already asking the user about another agent fill, and \
     asks about one at a time. Nothing was filled. Wait for that one to finish, then retry once.";

/// The answer for an agent over its budget of sheets (gate 1).
pub(crate) const RATE_LIMITED: &str = "This agent has asked kagisecure to fill logins too often, \
     and the user has been told. Nothing was filled. Stop; do not retry.";

/// The answer for a blocked agent (gate 1).
pub(crate) const BLOCKED: &str = "The user has blocked this agent from asking kagisecure to fill \
     logins for now. Nothing was filled. Stop; do not request a fill again.";

/// The answer for a request the user already declined (gate 1).
pub(crate) const DENIED_EARLIER: &str = "The user already declined this fill. Nothing was filled. \
     Stop; do not request the same thing again.";

/// The extension's answer to an `AgentFill` that no grant covers, whatever the reason.
const NO_FILL_WAITING: &str = "No fill is waiting for this page.";

/// The broker's timings: [`PROBE_WINDOW`], [`GRANT_LIFE`], [`OUTCOME_WAIT`],
/// [`REDEEM_DEADLINE`] and [`FLOW_WINDOW`] in production.
///
/// A struct so a test can shorten them ([`AgentFillBroker::with_timings_for_test`]) rather than
/// wait out thirty real seconds to see a grant expire. There is no other way to change them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentFillTimings {
    /// See [`PROBE_WINDOW`].
    pub probe_window: Duration,
    /// See [`GRANT_LIFE`].
    pub grant_life: Duration,
    /// See [`OUTCOME_WAIT`].
    pub outcome_wait: Duration,
    /// See [`REDEEM_DEADLINE`].
    pub redeem_deadline: Duration,
    /// See [`FLOW_WINDOW`].
    pub flow_window: Duration,
}

impl Default for AgentFillTimings {
    fn default() -> Self {
        Self {
            probe_window: PROBE_WINDOW,
            grant_life: GRANT_LIFE,
            outcome_wait: OUTCOME_WAIT,
            redeem_deadline: REDEEM_DEADLINE,
            flow_window: FLOW_WINDOW,
        }
    }
}

/// Something the human should hear about even though no sheet was raised (ADR-0036 §9.1, §9.4).
///
/// Queued here and drained by the app with [`AgentFillBroker::take_notices`]. Metadata only.
/// Nothing is noticed that the human did themselves — *Deny and block*, an unblock — or that
/// would repeat per request: a blocked or rate-limited agent asking again is audited, not
/// noticed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentFillNotice {
    /// An agent asked to fill an item into a tab whose origin the item is not saved for.
    OriginMismatch {
        /// The agent, as the audit log names it: self-reported name quoted, kernel facts bare.
        agent: String,
        /// The item's title.
        item_title: String,
        /// The origin the browser reported, rendered so a look-alike is obvious.
        origin: AgentOriginRendering,
    },
    /// An agent went over its budget of sheets and is refused for the next ten minutes (§9.1).
    /// One per cool-down, however many requests it refuses.
    RateLimited {
        /// The agent, as the audit log names it.
        agent: String,
        /// The key its budget is kept under: the sidecar's parent executable.
        key: String,
        /// How many times it asked inside the window, this refusal included.
        requests: u32,
        /// The window, and the cool-down, in minutes.
        window_minutes: u32,
    },
    /// An agent was blocked without the human pressing anything: its second origin mismatch in
    /// this unlock session (§9.4). It stays blocked until the human unblocks it.
    Blocked {
        /// The agent, as the audit log names it.
        agent: String,
        /// The key it is blocked under — what `unblock` takes.
        key: String,
        /// Why.
        reason: AgentFillBlockReason,
    },
    /// The tripwire of §8.3 fired: within seconds of an agent fill writing a password, the
    /// password input stopped being `type=password` — the site's own "show password" control —
    /// and the extension cleared it. The fill did happen; what the agent could read, it may
    /// have read. One per fill.
    Unmasked {
        /// The agent, as the audit log names it.
        agent: String,
        /// The item's title.
        item_title: String,
        /// The origin the password was written at, rendered as the sheet rendered it.
        origin: AgentOriginRendering,
    },
}

/// Where the approval-fatigue limits read the time: the monotonic clock, or — for a test that has
/// to see ten or thirty minutes pass — a clock that only moves when told to.
///
/// Only the limits read it. The broker's short waits (the probe window, a grant's life, the
/// outcome wait) are real waits on a condition variable and keep the real clock.
#[derive(Clone, Debug, Default)]
pub struct AgentFillClock {
    /// `None` for the real clock; the manual clock's accumulated advance otherwise.
    advanced: Option<Arc<Mutex<Duration>>>,
}

impl AgentFillClock {
    /// A clock that starts at the real time and then moves only by [`Self::advance`].
    #[must_use]
    pub fn manual_for_test() -> Self {
        Self {
            advanced: Some(Arc::new(Mutex::new(Duration::ZERO))),
        }
    }

    /// Move a manual clock forward. Does nothing to the real clock.
    pub fn advance(&self, by: Duration) {
        if let Some(advanced) = &self.advanced {
            let mut advanced = advanced.lock().unwrap_or_else(|e| e.into_inner());
            *advanced = advanced.saturating_add(by);
        }
    }

    fn now(&self) -> Instant {
        let now = Instant::now();
        match &self.advanced {
            None => now,
            Some(advanced) => now + *advanced.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}

/// The sidecar process an agent fill is bound to, from the kernel (implementation decision 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sidecar {
    /// The sidecar's pid, from the kernel.
    pid: u32,
    /// Its executable, resolved from that pid when the request arrived.
    executable: String,
    /// When that process started, asked of the kernel when the request arrived — what tells it
    /// apart from a later process that was handed its pid, since every sidecar runs the same
    /// executable. `None` where the platform cannot say ([`process_start_time`]); the binding is
    /// then the pid and executable alone.
    started: Option<u64>,
    /// Its self-reported client name, for the sheet. Display-only.
    name: String,
    /// How the audit log names it: `mcp "<name>" [...] pid N <exe>`.
    actor: String,
    /// Its parent's pid, from the kernel — never the `parent_pid` the sidecar reports.
    parent_pid: u32,
    /// That parent's executable: what "this agent" means on the sheet, and the key every limit
    /// and block is kept under (§5, §9.3).
    parent_executable: String,
    /// Its kernel audit token (macOS), for the app's code-signature check: unlike the pid it
    /// cannot come to name a later process.
    audit_token: Option<String>,
}

impl Sidecar {
    /// The sidecar behind `identity`, if the kernel said who it is. `None` when the pid did not
    /// come from the kernel, or its executable or its parent's could not be resolved: a grant
    /// bound to a process that cannot be recognized again at delivery is not issued at all, and a
    /// request that no limit can be keyed on is not served either.
    pub(crate) fn of(identity: &PeerIdentity) -> Option<Self> {
        let pid = identity.kernel_pid()?;
        let executable = identity.executable.clone()?;
        let parent_pid = kagisecure_extension_ipc::peer::parent_pid(pid)?;
        let parent_executable = executable_for_pid(parent_pid)?;
        Some(Self {
            pid,
            executable,
            started: process_start_time(pid),
            name: identity
                .reported
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |c| c.name.clone()),
            actor: actor_for(identity),
            parent_pid,
            parent_executable,
            audit_token: identity.audit_token.clone(),
        })
    }

    /// The same sidecar under another audit actor: the unattended engine's, which names the job
    /// and the run (ADR-0042 §12.8).
    pub(crate) fn with_actor(mut self, actor: String) -> Self {
        self.actor = actor;
        self
    }

    /// The key its limits and blocks are kept under: its parent's executable.
    fn key(&self) -> &str {
        &self.parent_executable
    }

    /// Whether the process that asked is still alive and still the same process: the same
    /// executable and, where the kernel can say, the same start time. A pid handed to another
    /// sidecar after this one exited has the executable — every sidecar is the same binary — but
    /// not the start time.
    fn still_running(&self) -> bool {
        self.is_alive()
    }

    /// Whether `other` is this very process: the same kernel pid, executable and start time —
    /// never what either says about itself. What makes a second call the same agent's (§7.3).
    fn same_process(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.executable == other.executable
            && self.started == other.started
    }

    fn is_alive(&self) -> bool {
        executable_for_pid(self.pid).as_deref() == Some(self.executable.as_str())
            && self
                .started
                .is_none_or(|started| process_start_time(self.pid) == Some(started))
    }
}

/// How the audit log names the sidecar that asked (implementation decision 7): the `mcp` prefix
/// every agent actor starts with, then the peer as `PeerIdentity::describe` renders it —
/// self-reported name quoted, kernel facts bare.
#[must_use]
pub(crate) fn actor_for(identity: &PeerIdentity) -> String {
    format!("mcp {}", identity.describe())
}

/// The actor, with the browser that carried the value appended.
fn actor_via(sidecar: &Sidecar, session: &SessionFacts) -> String {
    format!(
        "{} via {} (extension {:?})",
        sidecar.actor,
        session
            .identity
            .browser
            .map_or("unknown browser", |b| b.display_name()),
        session.extension_id
    )
}

/// Which gate-4 answer `item` gets for `fields`, if any: the archived sentence, or the one for a
/// field it has no value for. Reads no value — `crossing`'s predicates say whether one is there.
pub(crate) fn nothing_to_fill(item: &Item, fields: &[AgentFillField]) -> Option<&'static str> {
    if item.archived {
        Some(ARCHIVED)
    } else if has_fields(item, fields) {
        None
    } else {
        Some(NOTHING_TO_FILL)
    }
}

fn has_fields(item: &Item, fields: &[AgentFillField]) -> bool {
    fields.iter().all(|field| match field {
        AgentFillField::Username => item.username().is_some(),
        AgentFillField::Password => crossing::has_password(item),
        AgentFillField::OneTimeCode => crossing::has_working_totp(item),
    })
}

/// The page's name for a field.
fn page_field(field: AgentFillField) -> PageField {
    match field {
        AgentFillField::Username => PageField::Username,
        AgentFillField::Password => PageField::Password,
        AgentFillField::OneTimeCode => PageField::OneTimeCode,
    }
}

fn field_names(fields: &[AgentFillField]) -> Vec<String> {
    fields.iter().map(|f| f.as_str().to_owned()).collect()
}

/// What gate 1 answers, and records, for a request [`AgentFillBroker::admit`] refused.
///
/// The entry names the agent, the fields and — for a repeat of a request the human already
/// denied, which went through gate 3 the first time — the item and the claimed origin. A block,
/// a budget and a busy slot are decided without either, and the entry does not name them: an item
/// id nobody has looked up would say nothing true.
pub(crate) fn refused_at_gate_one(
    refusal: Refusal,
    sidecar: &Sidecar,
    item_id: &str,
    origin: Option<&str>,
    fields: &[AgentFillField],
) -> (AuditDraft, Response) {
    let (detail, code, message) = match refusal {
        Refusal::Blocked => (
            audit_detail::AGENT_FILL_BLOCKED,
            ErrorCode::UserDenied,
            BLOCKED,
        ),
        Refusal::DeniedEarlier => (
            audit_detail::AGENT_FILL_BLOCKED,
            ErrorCode::UserDenied,
            DENIED_EARLIER,
        ),
        Refusal::RateLimited { .. } => (
            audit_detail::AGENT_FILL_RATE_LIMITED,
            ErrorCode::RateLimited,
            RATE_LIMITED,
        ),
        Refusal::Busy => (audit_detail::AGENT_FILL_BUSY, ErrorCode::RateLimited, BUSY),
    };
    let repeat = refusal == Refusal::DeniedEarlier;
    let entry = AuditDraft {
        actor: sidecar.actor.clone(),
        client_pid: Some(sidecar.pid),
        tool: tool_for(fields).to_owned(),
        item_id: if repeat {
            ItemId::parse_canonical(item_id)
        } else {
            None
        },
        variables: field_names(fields),
        target_path: origin.filter(|_| repeat).map(str::to_owned),
        outcome: AuditOutcome::Denied,
        detail: Some(detail.to_owned()),
        ..AuditDraft::default()
    };
    (entry, Response::error(code, message))
}

/// The audit entry for a request refused after gate 1 and before its item was looked up — its
/// arguments, or gate 2 — recording `reply`'s code (ADR-0036 §10: every request leaves one).
///
/// Like every entry written before gate 3, it names no item: it reads the same for an item that
/// exists, one that is hidden and one that never did. The field names are recorded only when
/// they are a valid set, so nothing unchecked goes into the log. `None` for a reply that is not
/// an error.
pub(crate) fn refused_before_the_item(
    sidecar: &Sidecar,
    fields: &[AgentFillField],
    reply: &Response,
) -> Option<AuditDraft> {
    let Response::Error { code, .. } = reply else {
        return None;
    };
    let valid = kagisecure_ipc::protocol::agent_fill_fields_ok(fields);
    Some(AuditDraft {
        actor: sidecar.actor.clone(),
        client_pid: Some(sidecar.pid),
        tool: if valid { tool_for(fields) } else { TOOL }.to_owned(),
        variables: if valid {
            field_names(fields)
        } else {
            Vec::new()
        },
        outcome: refusal_outcome(*code),
        detail: Some(code.as_str().to_owned()),
        ..AuditDraft::default()
    })
}

/// `Failed` for a refusal that means something went wrong — the vault file in dispute — and
/// `Denied` for every other refusal.
fn refusal_outcome(code: ErrorCode) -> AuditOutcome {
    match code {
        ErrorCode::VaultConflict | ErrorCode::Internal => AuditOutcome::Failed,
        _ => AuditOutcome::Denied,
    }
}

// -------------------------------------------------------------------------------------------------
// The broker
// -------------------------------------------------------------------------------------------------

/// The process-wide rendezvous between `request_fill` and the browsers that can serve it.
///
/// One per process, held by both listeners, and outliving both: the app restarts the extension
/// listener on every unlock, and the limits' blocks must survive that. Holds no vault reference —
/// each caller brings its own — so a lock empties it ([`Self::revoke_all`]) without it keeping a
/// locked vault alive.
pub struct AgentFillBroker {
    /// The feature switch (§2, implementation decision 12). In memory only, default off.
    enabled: AtomicBool,
    /// Serving run browsers (ADR-0042 §12.4): a report's document counts as visible whatever it
    /// says, since nobody looks at a run browser and a locked screen may call it hidden.
    run_browsers: AtomicBool,
    timings: AgentFillTimings,
    clock: AgentFillClock,
    state: Mutex<State>,
    /// Signalled whenever a report, a redemption, an outcome, a revocation or a disconnect
    /// changes what the MCP thread is waiting for.
    signal: Condvar,
}

impl Default for AgentFillBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AgentFillBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state();
        f.debug_struct("AgentFillBroker")
            .field("enabled", &self.is_enabled())
            .field("sessions", &state.sessions.len())
            .field("in_progress", &state.flow.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct State {
    /// Extension sessions that declared `agent_fill`, by the broker's own id for them.
    sessions: BTreeMap<u64, SessionFacts>,
    next_session: u64,
    /// The one flow in progress, if any.
    flow: Option<Flow>,
    /// Bumped by every [`AgentFillBroker::revoke_all`], so a flow can tell that a lock happened
    /// while it was not looking — at the sheet, say.
    lock_epoch: u64,
    /// Released fills, remembered briefly for a late follow-up.
    recent: VecDeque<RecentRelease>,
    /// Identifier-first grants whose username is written and whose password is still to come
    /// (§7.3). Each is removed by the continuation that takes it, by its watcher when its window
    /// closes or its session is gone, or by a lock.
    pending: Vec<PendingStep>,
    next_pending: u64,
    notices: VecDeque<AgentFillNotice>,
    /// Approval fatigue (§9): budgets, sticky denials, blocks. Survives [`AgentFillBroker::revoke_all`].
    limits: Limits,
}

/// What the broker knows about one extension session.
#[derive(Clone)]
struct SessionFacts {
    push: PushSender,
    identity: HostIdentity,
    extension_id: String,
}

/// The flow in progress.
struct Flow {
    /// [`State::lock_epoch`] when the flow began.
    epoch: u64,
    probe: Option<Probe>,
    /// The grant, while it is in the store: from issue until redeemed, revoked or expired.
    grant: Option<AgentFillGrant>,
    /// The grant's id and session, kept after it leaves the store so its outcome can be matched.
    issued: Option<(String, u64)>,
    delivery: Delivery,
    /// The pending step this flow continues, taken out at gate 1: this flow is step two of an
    /// identifier-first grant, and is served without a sheet or not at all.
    continuation: Option<PendingStep>,
}

/// Step one of an identifier-first grant is done — the username is written — and the approval
/// waits, unspent, for step two (ADR-0036 §7.3).
///
/// Everything step two must match is here: the sidecar process, the item, the extension session,
/// the tab, step one's origin and the flow window. The [`Approved`] leaves only to the
/// continuation that takes this step out, which spends it on the password or drops it.
struct PendingStep {
    id: u64,
    sidecar: Sidecar,
    item_id: String,
    /// Step one's origin, ASCII-serialized: step two's must continue it ([`continues_same_site`]).
    first_origin: String,
    session: u64,
    tab_id: u64,
    /// The end of the flow window, counted from the approval.
    until: Instant,
    /// [`State::lock_epoch`] when the flow began: a lock since then ends it.
    epoch: u64,
    /// Step one's `Allowed` entry and its `seq`, for the follow-up if step two never happens.
    entry: AuditDraft,
    entry_seq: u64,
    approved: Approved,
    /// Where that follow-up is written. Weak: the broker must not keep a vault alive.
    handle: Weak<VaultHandle>,
    /// The session that served step one went away; step two cannot come.
    session_gone: bool,
}

impl PendingStep {
    /// Whether a request by `sidecar` for `fields` of `item_id` continues this step, at `now`, in
    /// lock epoch `epoch`. Nothing else about the request is looked at here; the tab is judged
    /// once it has been located.
    fn continued_by(
        &self,
        sidecar: &Sidecar,
        item_id: &str,
        fields: &[AgentFillField],
        now: Instant,
        epoch: u64,
    ) -> bool {
        fields == [AgentFillField::Password]
            && self.item_id == item_id
            && self.sidecar.same_process(sidecar)
            && now < self.until
            && self.epoch == epoch
            && !self.session_gone
    }
}

/// A `Locate` in flight.
struct Probe {
    id: String,
    /// Sessions that were pushed to and have not answered.
    waiting: BTreeSet<u64>,
    reports: Vec<Report>,
}

/// One `TargetReport`, with the session it arrived on.
struct Report {
    session: u64,
    page: PageContext,
    tab: TabFacts,
    found: FoundFields,
}

/// An approved agent fill, waiting to be redeemed (ADR-0036 §6).
///
/// Every binding the human approved, and the [`Approved`] that lets `crossing` build the one reply
/// that carries the value. Never cloned, never handed to either caller, and gone from the store
/// the moment anybody tries to redeem it.
#[derive(Debug)]
pub struct AgentFillGrant {
    id: String,
    session: u64,
    sidecar: Sidecar,
    item_id: String,
    /// The item's title, for a notice about this fill.
    item_title: String,
    /// The fields this redemption writes — for step one of a two-step grant, the username only.
    fields: Vec<AgentFillField>,
    /// The browser-established origin, ASCII-serialized.
    origin: String,
    tab_id: u64,
    document_id: Option<String>,
    expires_at: Instant,
    /// The audit entry the release is recorded under.
    entry: AuditDraft,
    step: Step,
    approved: Approved,
}

/// What a grant's redemption releases, and whether it spends the approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// A login on one page: the approval is spent on the granted fields.
    Whole,
    /// Page one of an identifier-first sign-in: the username only, and the approval is kept for
    /// page two, until `until`.
    One { until: Instant },
    /// Page two: the password, spending the approval step one kept.
    Two,
    /// A one-time code, spent into the `totp_code` reply.
    Code,
}

/// Where delivery stands, as the MCP thread sees it.
enum Delivery {
    /// No grant yet.
    NotYet,
    /// The grant is in the store, waiting for the extension.
    Waiting,
    /// The extension is redeeming it: the release transaction is running. Given up on at
    /// `until` ([`REDEEM_DEADLINE`]), or as soon as the session redeeming it goes away.
    Redeeming { until: Instant },
    /// A redemption was refused, or its release did not happen.
    Refused(Refused),
    /// Nothing was released, and nothing will be: expired, reported undeliverable, or its
    /// session went away.
    Undelivered,
    /// A lock revoked the grant.
    Locked,
    /// The value left the app.
    Released(Box<ReleasedFill>),
}

/// Why a redemption released nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    /// A re-check refused it: another session, tab, document, origin, frame, visibility, form or
    /// sidecar, or an item that no longer covers the origin or has the fields.
    Recheck,
    /// Its audit entry could not be written ([`NotReleased::AuditUnavailable`]); the `Failed`
    /// entry is already queued.
    AuditUnavailable,
    /// The vault locked before the release.
    Locked,
    /// The approval did not cover what was about to be built. Unreachable; refused rather than
    /// trusted.
    Internal,
}

/// A value that left the app, and what has been heard about it since.
struct ReleasedFill {
    entry: AuditDraft,
    entry_seq: u64,
    fields: Vec<AgentFillField>,
    at: Instant,
    outcome: Option<(Vec<PageField>, Option<AgentFillFailure>)>,
    /// Step one of a two-step grant: the approval it kept for step two, and the end of the flow
    /// window. Taken by the flow once the extension says the username was written.
    kept: Option<(Approved, Instant)>,
    /// What a late tripwire report is matched against.
    tripwire: Tripwire,
    /// The reply frame carrying it could not be written; `REPLY_FAILED` is already recorded.
    reply_failed: bool,
    /// The session closed before an outcome arrived; none will.
    session_gone: bool,
}

/// A released fill remembered for a late follow-up.
struct RecentRelease {
    grant_id: String,
    session: u64,
    at: Instant,
    tripwire: Tripwire,
}

/// What the §8.3 tripwire needs to know about a released fill: its entry, and whether — and
/// when — the extension said it wrote a password, which is the only thing the tripwire watches.
#[derive(Clone)]
struct Tripwire {
    entry: AuditDraft,
    entry_seq: u64,
    /// The agent, as the audit log names it, for the notice.
    agent: String,
    item_title: String,
    /// The origin the value was written at, ASCII-serialized.
    origin: String,
    /// When the extension's first outcome reported the password written, if it did.
    armed_at: Option<Instant>,
    /// Whether the tripwire has already been recorded: it fires once per fill.
    fired: bool,
}

impl Tripwire {
    /// Whether an `UNMASKED` report arriving at `now` is the tripwire of this fill: the first
    /// outcome wrote the password, it has not fired yet, and it is inside [`TRIPWIRE_WINDOW`].
    fn fires_at(&self, now: Instant) -> bool {
        !self.fired
            && self
                .armed_at
                .is_some_and(|at| now.saturating_duration_since(at) <= TRIPWIRE_WINDOW)
    }
}

impl AgentFillBroker {
    /// A broker with the production timings, switched off.
    #[must_use]
    pub fn new() -> Self {
        Self::build(AgentFillTimings::default(), AgentFillClock::default())
    }

    /// A broker with shortened timings, for a test that has to see a grant expire.
    ///
    /// Test support, in the `_for_test` naming convention this crate already uses: production
    /// code builds a broker with [`Self::new`], and nothing reads timings from anywhere else.
    #[must_use]
    pub fn with_timings_for_test(timings: AgentFillTimings) -> Self {
        Self::build(timings, AgentFillClock::default())
    }

    /// A broker with shortened timings whose limits read `clock`, for a test that has to see ten
    /// or thirty minutes pass ([`AgentFillClock::manual_for_test`]).
    #[must_use]
    pub fn with_clock_for_test(timings: AgentFillTimings, clock: AgentFillClock) -> Self {
        Self::build(timings, clock)
    }

    fn build(timings: AgentFillTimings, clock: AgentFillClock) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            run_browsers: AtomicBool::new(false),
            timings,
            clock,
            state: Mutex::new(State::default()),
            signal: Condvar::new(),
        }
    }

    /// A broker for the unattended extension endpoint (ADR-0042 §12.4): switched on, and taking a
    /// run browser's tab as visible whatever the document says.
    #[must_use]
    pub fn for_run_browsers() -> Self {
        let broker = Self::new();
        broker.enabled.store(true, Ordering::SeqCst);
        broker.run_browsers.store(true, Ordering::SeqCst);
        broker
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Turn agent fills on or off (`agent_fill_set_enabled`). Off, every `request_fill` answers
    /// `FILL_UNAVAILABLE` before its item is looked up. A convenience, not a boundary: the
    /// per-fill sheet and its biometric are (implementation decision 12).
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    /// Whether agent fills are on. Always `false` on Windows, which never offers them
    /// (implementation decision 8), whatever the switch says.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !cfg!(windows) && self.enabled.load(Ordering::SeqCst)
    }

    /// How many extension sessions declared `agent_fill` and are connected now.
    #[must_use]
    pub fn connected_sessions(&self) -> usize {
        self.state()
            .sessions
            .values()
            .filter(|s| s.push.is_open())
            .count()
    }

    /// How many grants are waiting to be redeemed: zero or one.
    #[must_use]
    pub fn live_grants(&self) -> usize {
        self.state()
            .flow
            .as_ref()
            .map_or(0, |f| usize::from(f.grant.is_some()))
    }

    /// How many identifier-first grants have their username written and are waiting for the
    /// password step: open, inside their flow window, with their session still connected.
    #[must_use]
    pub fn pending_steps(&self) -> usize {
        let now = Instant::now();
        self.state()
            .pending
            .iter()
            .filter(|p| !p.session_gone && now < p.until)
            .count()
    }

    /// Every notice queued since the last call, oldest first.
    #[must_use]
    pub fn take_notices(&self) -> Vec<AgentFillNotice> {
        self.state().notices.drain(..).collect()
    }

    /// Every agent blocked from `request_fill` now, by key (§9.3, §9.4). A timed block that has
    /// run out is not listed.
    #[must_use]
    pub fn blocks(&self) -> Vec<AgentFillBlock> {
        let now = self.clock.now();
        self.state().limits.blocks(now)
    }

    /// Lift the block on `key` (the human pressed Unblock in Agent access). Returns whether there
    /// was one. Sticky denials and the agent's budget are left as they are, and so is its
    /// origin-mismatch count: a further mismatch in this unlock session blocks it again.
    pub fn unblock(&self, key: &str) -> bool {
        self.state().limits.unblock(key)
    }

    /// What a vault lock does to agent fills: the waiting grant dies, and a flow that is at its
    /// sheet finds, when the sheet returns, that it may not issue one. Blocks, sticky denials and
    /// budgets survive it — a restriction a relock reset would be a fresh start for the agent it
    /// restricts — and origin mismatches start counting again (§9.3, §9.4).
    pub fn revoke_all(&self) {
        {
            let mut state = self.state();
            state.limits.new_unlock_session();
            state.lock_epoch = state.lock_epoch.wrapping_add(1);
            if let Some(flow) = state.flow.as_mut()
                && flow.grant.take().is_some()
            {
                flow.delivery = Delivery::Locked;
            }
            state.recent.clear();
            // A pending step two dies with the key, like a grant. There is no vault to record
            // that in; the approval it held is dropped here.
            state.pending.clear();
        }
        self.signal.notify_all();
    }

    /// Whether a request from `sidecar` for `fields` of `item_id` would be step two of a pending
    /// identifier-first grant (§7.3) — one sign-in in two steps, which the unattended engine
    /// counts once (ADR-0042 §12.2). Takes nothing out: [`Self::admit`] does that.
    pub(crate) fn continues(
        &self,
        sidecar: &Sidecar,
        item_id: &str,
        fields: &[AgentFillField],
    ) -> bool {
        let state = self.state();
        let epoch = state.lock_epoch;
        let now = Instant::now();
        state
            .pending
            .iter()
            .any(|p| p.continued_by(sidecar, item_id, fields, now, epoch))
    }

    /// Gate 1's "not blocked or limited" for `sidecar` asking to fill `item_id` at `origin` (the
    /// claim, ASCII-serialized, when it parses): take the one flow slot, or say why not. The
    /// switch is the caller's to check first, so that "off" answers before anything here.
    ///
    /// In order: a block, a sticky denial, the agent's budget, then the slot (see the module
    /// documentation). Nothing here depends on the vault or the item.
    ///
    /// A request that continues a pending identifier-first grant (§7.3) — the same sidecar
    /// process, the same item, `["password"]`, inside the flow window — is admitted as step two:
    /// it raises no sheet, so the budget does not apply to it, and the pending step is taken out
    /// of the store here, so this request is its only chance.
    pub(crate) fn admit(
        self: &Arc<Self>,
        sidecar: &Sidecar,
        item_id: &str,
        origin: Option<&str>,
        fields: &[AgentFillField],
    ) -> Result<FlowSlot, Refusal> {
        let now = self.clock.now();
        let real_now = Instant::now();
        let mut state = self.state();
        let epoch = state.lock_epoch;
        let continues = state
            .pending
            .iter()
            .position(|p| p.continued_by(sidecar, item_id, fields, real_now, epoch));
        state
            .limits
            .check(sidecar.key(), item_id, origin, now, continues.is_none())?;
        if state.flow.is_some() {
            return Err(Refusal::Busy);
        }
        let continuation = continues.map(|at| state.pending.remove(at));
        state.flow = Some(Flow {
            epoch,
            probe: None,
            grant: None,
            issued: None,
            delivery: Delivery::NotYet,
            continuation,
        });
        drop(state);
        // The pending step's watcher, if any, sees it gone and stops.
        self.signal.notify_all();
        Ok(FlowSlot {
            broker: Arc::clone(self),
        })
    }

    /// A session declared `agent_fill` in its `Hello`: remember it, and how to push to it.
    pub(crate) fn register(
        self: &Arc<Self>,
        push: PushSender,
        identity: HostIdentity,
        extension_id: String,
    ) -> SessionTicket {
        let id = {
            let mut state = self.state();
            state.next_session = state.next_session.wrapping_add(1);
            let id = state.next_session;
            state.sessions.insert(
                id,
                SessionFacts {
                    push,
                    identity,
                    extension_id,
                },
            );
            id
        };
        SessionTicket {
            broker: Arc::clone(self),
            id,
        }
    }

    /// A session went away: it can no longer report, redeem, or say what became of a fill.
    fn deregister(&self, session: u64) {
        {
            let mut state = self.state();
            state.sessions.remove(&session);
            // A step two can only come from the session that served step one.
            for pending in state.pending.iter_mut().filter(|p| p.session == session) {
                pending.session_gone = true;
            }
            if let Some(flow) = state.flow.as_mut() {
                if let Some(probe) = flow.probe.as_mut() {
                    probe.waiting.remove(&session);
                }
                if flow.grant.as_ref().is_some_and(|g| g.session == session) {
                    flow.grant = None;
                    flow.delivery = Delivery::Undelivered;
                }
                if flow.issued.as_ref().is_some_and(|(_, s)| *s == session) {
                    match &mut flow.delivery {
                        Delivery::Released(released) => released.session_gone = true,
                        // A session is deregistered on the thread that redeems for it, so a
                        // redemption still marked as running here ended without saying how —
                        // it panicked. Nothing was handed out, and the flow must not wait for
                        // an answer that will never come.
                        Delivery::Redeeming { .. } => flow.delivery = Delivery::Undelivered,
                        _ => {}
                    }
                }
            }
        }
        self.signal.notify_all();
    }

    /// A `TargetReport` arrived on `session`. Kept only if it answers the probe in flight and
    /// `session` was asked; anything else is dropped. The extension is answered `Noted` either
    /// way, so it learns nothing about what was asked.
    pub(crate) fn report(
        &self,
        session: u64,
        probe_id: &str,
        page: &PageContext,
        tab: &TabFacts,
        found: FoundFields,
    ) {
        let kept = {
            let mut state = self.state();
            match state.flow.as_mut().and_then(|f| f.probe.as_mut()) {
                Some(probe) if probe.id == probe_id && probe.waiting.contains(&session) => {
                    probe.waiting.remove(&session);
                    let mut tab = tab.clone();
                    if self.run_browsers.load(Ordering::SeqCst) {
                        tab.visible = true;
                    }
                    probe.reports.push(Report {
                        session,
                        page: page.clone(),
                        tab,
                        found,
                    });
                    true
                }
                _ => false,
            }
        };
        if kept {
            self.signal.notify_all();
        }
    }

    /// The extension asks for the fill a `Deliver` announced (§4). Runs on the extension
    /// connection's thread; returns the reply for it, and — when a value was released — what the
    /// connection loop needs if the reply frame then cannot be written.
    ///
    /// The grant leaves the store before anything is checked, so it is spent whatever happens:
    /// a request that gets any binding wrong, from any session, ends it.
    pub(crate) fn redeem(
        &self,
        session: u64,
        handle: &Arc<VaultHandle>,
        grant_id: &str,
        page: &PageContext,
        tab: &TabFacts,
        found: FoundFields,
    ) -> Redemption {
        let taken = {
            let mut state = self.state();
            match state.flow.as_mut() {
                Some(flow) if flow.grant.as_ref().is_some_and(|g| g.id == grant_id) => {
                    flow.delivery = Delivery::Redeeming {
                        until: Instant::now() + self.timings.redeem_deadline,
                    };
                    flow.grant.take()
                }
                _ => None,
            }
        };
        // The flow waiting on this grant now waits on the redemption's deadline instead.
        self.signal.notify_all();
        let Some(grant) = taken else {
            return Redemption::refused(ExtResponse::error(ExtCode::NoMatch, NO_FILL_WAITING));
        };

        if !grant.still_matches(session, page, tab, found) || !grant.sidecar.still_running() {
            self.settle(grant_id, Delivery::Refused(Refused::Recheck));
            return Redemption::refused(ExtResponse::error(ExtCode::NoMatch, NO_FILL_WAITING));
        }

        let AgentFillGrant {
            id,
            item_id,
            item_title,
            fields,
            origin,
            entry,
            step,
            approved,
            sidecar,
            ..
        } = grant;
        let wanted: Vec<FillField> = fields
            .iter()
            .filter_map(|f| page_field(*f).as_fill_field())
            .collect();
        let checked = fields.clone();
        let checked_origin = origin.clone();
        // The crossing. Everything that decides the fill is checked again inside the transaction,
        // on the file as it is now: the item may have been hidden, trashed, archived, emptied or
        // moved to other websites while the sheet was up.
        let released = audited_release(
            handle,
            REQUEST_LOCK_TIMEOUT,
            entry.clone(),
            move |tx| {
                // The shared vaults' snapshots as they are now: the personal vault's handle is
                // held, a shared vault's state is second (`crate::shared`).
                let catalog = Catalog::new(tx, handle.shared_snapshots());
                let item = crate::service::agent_visible_item(&catalog, &item_id)
                    .filter(|item| !item.archived)
                    .ok_or(Refused::Recheck)?;
                let page = Origin::parse(&checked_origin).map_err(|_| Refused::Recheck)?;
                covering_website(&super::saved_websites(item), &page).ok_or(Refused::Recheck)?;
                if !has_fields(item, &checked) {
                    return Err(Refused::Recheck);
                }
                match step {
                    // Step one borrows the approval and hands it back for step two.
                    Step::One { until } => {
                        crossing::username_only(&approved, item, super::username_of(item))
                            .map(|reply| (reply, Some((approved, until))))
                    }
                    Step::Code => crossing::totp_code(approved, item, kagisecure_core::unix_now())
                        .map(|reply| (reply, None)),
                    Step::Whole | Step::Two => {
                        crossing::filled(approved, item, &wanted, super::username_of(item))
                            .map(|reply| (reply, None))
                    }
                }
                .ok_or(Refused::Internal)
            },
            |released, _entry_seq| Acted::done(released),
        );

        match released {
            Ok(Released {
                value: (value, kept),
                entry_seq,
            }) => {
                let tripwire = Tripwire {
                    entry: entry.clone(),
                    entry_seq,
                    agent: sidecar.actor.clone(),
                    item_title,
                    origin,
                    armed_at: None,
                    fired: false,
                };
                let taken = self.settle(
                    &id,
                    Delivery::Released(Box::new(ReleasedFill {
                        entry: entry.clone(),
                        entry_seq,
                        fields,
                        at: Instant::now(),
                        outcome: None,
                        kept,
                        tripwire,
                        reply_failed: false,
                        session_gone: false,
                    })),
                );
                if !taken {
                    // The flow stopped waiting while the transaction ran (`REDEEM_DEADLINE`) and
                    // has told the agent nothing was filled. The entry is committed, but the
                    // value has not left: it is dropped here, and the entry gets its follow-up.
                    drop(value);
                    let _ = handle.record_best_effort(
                        REQUEST_LOCK_TIMEOUT,
                        release::follow_up(
                            &entry,
                            audit_detail::AGENT_FILL_NOT_DELIVERED,
                            entry_seq,
                        ),
                    );
                    return Redemption::refused(ExtResponse::error(
                        ExtCode::NoMatch,
                        NO_FILL_WAITING,
                    ));
                }
                Redemption {
                    response: value,
                    released: Some((entry, entry_seq, id)),
                }
            }
            Err(NotReleased::Locked) => {
                self.settle(&id, Delivery::Refused(Refused::Locked));
                Redemption::refused(ExtResponse::error(
                    ExtCode::VaultLocked,
                    "The vault locked.",
                ))
            }
            Err(NotReleased::AuditUnavailable(_)) => {
                self.settle(&id, Delivery::Refused(Refused::AuditUnavailable));
                Redemption::refused(super::audit_unavailable())
            }
            Err(NotReleased::Refused(reason)) => {
                self.settle(&id, Delivery::Refused(reason));
                Redemption::refused(match reason {
                    Refused::Internal => ExtResponse::error(
                        ExtCode::Internal,
                        "The approval did not match the fill. Nothing was sent.",
                    ),
                    _ => ExtResponse::error(ExtCode::NoMatch, NO_FILL_WAITING),
                })
            }
        }
    }

    /// A redemption the extension listener refused before it reached [`Self::redeem`] — the vault
    /// file could not be confirmed, say. Spent like any failed re-check, so the agent is answered
    /// now rather than when the grant would have expired.
    pub(crate) fn abandon(&self, grant_id: &str) {
        let spent = {
            let mut state = self.state();
            match state.flow.as_mut() {
                Some(flow) if flow.grant.as_ref().is_some_and(|g| g.id == grant_id) => {
                    flow.grant = None;
                    true
                }
                _ => false,
            }
        };
        if spent {
            self.settle(grant_id, Delivery::Refused(Refused::Recheck));
        }
    }

    /// How the redemption of `grant_id` ended, for the flow waiting on it. Returns whether that
    /// flow was still waiting: `false` when it has moved on — the redemption ran past
    /// [`REDEEM_DEADLINE`], or the flow has ended and another may have begun — in which case
    /// nothing is changed, so a late redemption can never settle somebody else's flow.
    fn settle(&self, grant_id: &str, delivery: Delivery) -> bool {
        let taken = {
            let mut state = self.state();
            match state.flow.as_mut() {
                Some(flow)
                    if flow.issued.as_ref().is_some_and(|(id, _)| id == grant_id)
                        && matches!(
                            flow.delivery,
                            Delivery::Waiting | Delivery::Redeeming { .. }
                        ) =>
                {
                    flow.delivery = delivery;
                    true
                }
                _ => false,
            }
        };
        self.signal.notify_all();
        taken
    }

    /// The reply frame carrying a released agent fill could not be written. `REPLY_FAILED` is
    /// already recorded by the connection loop; this only stops the MCP thread waiting for an
    /// outcome that cannot come.
    pub(crate) fn reply_failed(&self, grant_id: &str) {
        {
            let mut state = self.state();
            if let Some(flow) = state.flow.as_mut()
                && flow.issued.as_ref().is_some_and(|(id, _)| id == grant_id)
                && let Delivery::Released(released) = &mut flow.delivery
            {
                released.reply_failed = true;
            }
        }
        self.signal.notify_all();
    }

    /// The extension says what became of a fill (`AgentFillOutcome`).
    ///
    /// For the flow in progress it is what the MCP thread is waiting for — and, for a grant never
    /// redeemed (the delivery did not reach the document, or the content script's own re-check
    /// failed first), the end of that grant. After that first outcome, the only one that means
    /// anything is the tripwire (§8.3): `UNMASKED`, within [`TRIPWIRE_WINDOW`] of a first outcome
    /// that reported the password written, once per fill. It is recorded as the follow-up
    /// `AGENT_FILL_UNMASKED (entry N)` and the human is told — and it is never taken for a second
    /// fill: nothing is released for it and no answer changes. From any other session, for any
    /// other grant, or for a fill that wrote no password, an outcome is ignored.
    pub(crate) fn outcome(
        &self,
        session: u64,
        handle: &VaultHandle,
        grant_id: &str,
        written: &[PageField],
        failure: Option<AgentFillFailure>,
    ) {
        let now = Instant::now();
        let fired = {
            let mut state = self.state();
            let mut fired = None;
            let current = state
                .flow
                .as_mut()
                .filter(|f| f.issued.as_ref() == Some(&(grant_id.to_owned(), session)));
            if let Some(flow) = current {
                match &mut flow.delivery {
                    Delivery::Waiting => {
                        flow.grant = None;
                        flow.delivery = Delivery::Undelivered;
                    }
                    Delivery::Released(released) if released.outcome.is_none() => {
                        if failure.is_none() && written.contains(&PageField::Password) {
                            released.tripwire.armed_at = Some(now);
                        }
                        released.outcome = Some((written.to_vec(), failure));
                    }
                    // The flow has its answer and is about to end: a tripwire this early is
                    // recorded against it, as it would be a moment later from `recent`.
                    Delivery::Released(released)
                        if failure == Some(AgentFillFailure::Unmasked)
                            && released.tripwire.fires_at(now) =>
                    {
                        released.tripwire.fired = true;
                        fired = Some(released.tripwire.clone());
                    }
                    _ => {}
                }
            } else if failure == Some(AgentFillFailure::Unmasked)
                && let Some(recent) = state.recent.iter_mut().find(|r| {
                    r.grant_id == grant_id && r.session == session && r.tripwire.fires_at(now)
                })
            {
                recent.tripwire.fired = true;
                fired = Some(recent.tripwire.clone());
            }
            fired
        };
        self.signal.notify_all();
        if let Some(tripwire) = fired {
            let _ = handle.record_best_effort(
                REQUEST_LOCK_TIMEOUT,
                release::follow_up(
                    &tripwire.entry,
                    audit_detail::AGENT_FILL_UNMASKED,
                    tripwire.entry_seq,
                ),
            );
            if let Ok(origin) = Origin::parse(&tripwire.origin) {
                self.notice(AgentFillNotice::Unmasked {
                    agent: tripwire.agent,
                    item_title: tripwire.item_title,
                    origin: AgentOriginRendering::of(&origin),
                });
            }
        }
    }

    /// Keep `pending` until its step two takes it, its flow window closes, its session goes away
    /// or a lock clears it — and, for the two that leave the username written with nobody coming
    /// for the password, record so as the follow-up of step one's entry.
    ///
    /// Runs on a thread of its own, because nobody else is waiting: the agent has already been
    /// answered `fields_pending: ["password"]`.
    fn keep_pending(self: &Arc<Self>, pending: PendingStep) {
        let id = pending.id;
        {
            let mut state = self.state();
            if pending.epoch != state.lock_epoch {
                // A lock since the flow began: the approval dies with the key, unrecorded.
                return;
            }
            state.pending.push(pending);
        }
        let broker = Arc::clone(self);
        let watched = std::thread::Builder::new()
            .name("agent-fill-pending".to_owned())
            .spawn(move || broker.watch_pending(id));
        if watched.is_err() {
            // Without a watcher nothing would record its end: end it now instead.
            let ended = {
                let mut state = self.state();
                let at = state.pending.iter().position(|p| p.id == id);
                at.map(|at| state.pending.remove(at))
            };
            if let Some(pending) = ended {
                Self::pending_ended(&pending, audit_detail::AGENT_FILL_PENDING_EXPIRED);
            }
        }
    }

    fn watch_pending(&self, id: u64) {
        let mut state = self.state();
        loop {
            let Some(at) = state.pending.iter().position(|p| p.id == id) else {
                // Taken by its step two, or cleared by a lock: not this thread's to record.
                return;
            };
            let now = Instant::now();
            let pending = &state.pending[at];
            if pending.session_gone || now >= pending.until {
                let pending = state.pending.remove(at);
                drop(state);
                Self::pending_ended(&pending, audit_detail::AGENT_FILL_PENDING_EXPIRED);
                return;
            }
            let wait = pending.until.saturating_duration_since(now);
            state = self
                .signal
                .wait_timeout(state, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Record, best-effort, that a pending step ended without its password: `code` as the
    /// follow-up of step one's entry. The approval it held is dropped with it.
    fn pending_ended(pending: &PendingStep, code: &str) {
        if let Some(handle) = pending.handle.upgrade() {
            let _ = handle.record_best_effort(
                REQUEST_LOCK_TIMEOUT,
                release::follow_up(&pending.entry, code, pending.entry_seq),
            );
        }
    }

    fn notice(&self, notice: AgentFillNotice) {
        Self::push_notice(&mut self.state(), notice);
    }

    fn push_notice(state: &mut State, notice: AgentFillNotice) {
        if state.notices.len() >= NOTICE_SLOTS {
            state.notices.pop_front();
        }
        state.notices.push_back(notice);
    }
}

/// What [`AgentFillBroker::redeem`] hands back to the extension connection.
pub(crate) struct Redemption {
    /// The reply to the `AgentFill` request.
    pub(crate) response: ExtResponse,
    /// For a release: its entry, the entry's `seq`, and the grant id — what the connection loop
    /// needs to record `REPLY_FAILED` and tell the broker if the reply frame cannot be written.
    pub(crate) released: Option<(AuditDraft, u64, String)>,
}

impl Redemption {
    fn refused(response: ExtResponse) -> Self {
        Self {
            response,
            released: None,
        }
    }
}

/// A registered extension session. Dropping it deregisters the session, so a connection that
/// ends — however it ends — takes its grant with it.
pub(crate) struct SessionTicket {
    broker: Arc<AgentFillBroker>,
    id: u64,
}

impl SessionTicket {
    /// The broker's id for this session.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// The broker this session is registered with.
    pub(crate) fn broker(&self) -> &AgentFillBroker {
        &self.broker
    }
}

impl Drop for SessionTicket {
    fn drop(&mut self) {
        self.broker.deregister(self.id);
    }
}

impl AgentFillGrant {
    /// Every binding the human approved, checked against the `AgentFill` request that is trying
    /// to redeem this grant — each of them alone is enough to refuse it (§4, §6).
    ///
    /// The page must still have a field for everything this redemption writes: for step one of a
    /// two-step grant that is the username box alone, which is exactly what page one has.
    fn still_matches(
        &self,
        session: u64,
        page: &PageContext,
        tab: &TabFacts,
        found: FoundFields,
    ) -> bool {
        let fields: Vec<PageField> = self.fields.iter().map(|f| page_field(*f)).collect();
        Instant::now() < self.expires_at
            && session == self.session
            && tab.tab_id == self.tab_id
            && tab.document_id == self.document_id
            && in_top_frame(page)
            && Origin::parse(&page.top_origin).is_ok_and(|o| o.ascii_serialization() == self.origin)
            && found.covers(&fields)
    }
}

/// Whether `page` is the top frame, as the browser itself established it.
fn in_top_frame(page: &PageContext) -> bool {
    page.top_origin_established
        && page
            .frame_origin
            .as_ref()
            .is_none_or(|frame| *frame == page.top_origin)
}

/// Whether `report` is *in front*: frame 0 as the browser established it, the active tab of its
/// window, and a visible document.
fn in_front(report: &Report) -> bool {
    in_top_frame(&report.page) && report.tab.tab_active && report.tab.visible
}

// -------------------------------------------------------------------------------------------------
// One flow, from gate 5 to the answer
// -------------------------------------------------------------------------------------------------

/// What gates 1–4 established, for gates 5–9.
pub(crate) struct AgentFillCall<'a> {
    /// The vault the request was checked against.
    pub(crate) handle: &'a Arc<VaultHandle>,
    /// The approval queue the sheet is raised on.
    pub(crate) queue: &'a ApprovalQueue,
    /// The sidecar that asked.
    pub(crate) sidecar: Sidecar,
    /// The item, by its canonical id.
    pub(crate) item_id: String,
    /// The origin the agent claims, ASCII-serialized.
    pub(crate) claimed_origin: String,
    /// The fields asked for.
    pub(crate) fields: Vec<AgentFillField>,
    /// The shared vault the item is in, once gate 3 found it in one: every entry from then on
    /// names it (ADR-0035 decision 24). `None` for the personal vault, and before gate 3.
    pub(crate) vault_id: Option<kagisecure_core::proto::VaultId>,
    /// A standing login grant's pass, for an unattended fill (ADR-0042 §12.6): gate 8 spends it
    /// instead of raising a sheet. `None` on every path a person answers.
    pub(crate) standing: Mutex<Option<crate::unattended::login::StandingPass>>,
}

impl AgentFillCall<'_> {
    /// The audit entry for this request, before a browser is involved: under `request_fill`, or
    /// `totp_code` for a one-time code.
    pub(crate) fn entry(&self, outcome: AuditOutcome, detail: &str) -> AuditDraft {
        AuditDraft {
            actor: self.sidecar.actor.clone(),
            client_pid: Some(self.sidecar.pid),
            tool: tool_for(&self.fields).to_owned(),
            vault_id: self.vault_id,
            item_id: ItemId::parse_canonical(&self.item_id),
            variables: field_names(&self.fields),
            outcome,
            detail: Some(detail.to_owned()),
            ..AuditDraft::default()
        }
    }

    /// The audit entry once a tab has been chosen: the browser that would carry the value is part
    /// of the actor, and the origin it established is the target.
    fn entry_via(
        &self,
        session: &SessionFacts,
        origin: &str,
        outcome: AuditOutcome,
        detail: &str,
    ) -> AuditDraft {
        AuditDraft {
            actor: actor_via(&self.sidecar, session),
            target_path: Some(origin.to_owned()),
            ..self.entry(outcome, detail)
        }
    }

    fn record(&self, draft: AuditDraft) {
        let _ = self.handle.record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
    }

    /// Record, best-effort, that the vault locked before anybody approved this request, and
    /// answer so. The same entry wherever the lock is found before the sheet is answered: it names
    /// no browser and no origin, so it does not say whether a tab had been chosen. A lock that
    /// already took the key leaves nothing to write it to (implementation decision 37).
    fn locked(&self) -> Response {
        self.record(self.entry(AuditOutcome::Denied, ErrorCode::VaultLocked.as_str()));
        crate::service::locked_reply()
    }
}

/// The one flow in progress. Dropping it ends the flow: a grant still in the store is revoked, and
/// a released fill is remembered for its follow-up.
pub(crate) struct FlowSlot {
    broker: Arc<AgentFillBroker>,
}

impl Drop for FlowSlot {
    fn drop(&mut self) {
        let mut state = self.broker.state();
        if let Some(flow) = state.flow.take()
            && let (Delivery::Released(released), Some((grant_id, session))) =
                (flow.delivery, flow.issued)
        {
            if state.recent.len() >= FOLLOW_UP_SLOTS {
                state.recent.pop_front();
            }
            state.recent.push_back(RecentRelease {
                grant_id,
                session,
                at: released.at,
                tripwire: released.tripwire,
            });
        }
        state.recent.retain(|r| r.at.elapsed() <= FOLLOW_UP_MEMORY);
    }
}

/// The tab chosen at gate 6.
struct Target {
    session: u64,
    origin: Origin,
    saved: Origin,
    tab: TabFacts,
    /// Page one of an identifier-first sign-in, for a username-and-password request: served as
    /// a two-step grant (§7.3).
    two_step: bool,
}

/// What gate 6 concluded.
enum Choice {
    One(Target),
    /// No eligible tab, or more than one.
    NoTarget,
    /// The tab in front is on an origin the item is not saved for.
    Mismatch(Origin),
}

/// §3.2's rule, as amended on 2026-10-03 to let agents drive background tabs.
///
/// A report on a saved site is eligible when the browser established it as frame 0, its origin is
/// byte-equal to the claim and the page has a field for every field asked — or, for a request
/// naming both username and password, is page one of an identifier-first sign-in, which makes it
/// a two-step target (§3.2 check 5, §7.3). The tab need **not** be active or visible: an agent may
/// work in a background tab or a window that is not in front. With exactly one eligible report,
/// that one; with several, the one *in front* (the active tab of its window, visible), if exactly
/// one is; otherwise nothing.
///
/// With none eligible, an in-front report whose origin no saved website covers is the phishing
/// signal of §9.4 — but only when it can be the agent's own tab: when it is the **only** report in
/// front, or its origin is **the one the agent claimed**. Another browser's tab, in front beside
/// the agent's, is the human's own browsing: it is not recorded or reported. That case is plain
/// `NoTarget`.
fn choose(reports: &[Report], claimed: &str, fields: &[PageField], websites: &[String]) -> Choice {
    let login = fields.contains(&PageField::Username) && fields.contains(&PageField::Password);
    let mut eligible: Vec<(bool, Target)> = Vec::new();
    let mut in_front_count = 0_usize;
    let mut uncovered = Vec::new();
    for report in reports {
        if !in_top_frame(&report.page) {
            continue;
        }
        let Ok(origin) = Origin::parse(&report.page.top_origin) else {
            continue;
        };
        let front = in_front(report);
        if front {
            in_front_count += 1;
        }
        let Some(saved) = covering_website(websites, &origin) else {
            if front {
                uncovered.push(origin);
            }
            continue;
        };
        let two_step = login && report.found.is_identifier_only();
        if origin.ascii_serialization() != claimed || !(report.found.covers(fields) || two_step) {
            continue;
        }
        eligible.push((
            front,
            Target {
                session: report.session,
                origin,
                saved,
                tab: report.tab.clone(),
                two_step,
            },
        ));
    }
    if eligible.len() == 1 {
        return Choice::One(eligible.remove(0).1);
    }
    if !eligible.is_empty() {
        let mut fronts: Vec<Target> = eligible
            .into_iter()
            .filter_map(|(front, target)| front.then_some(target))
            .collect();
        if fronts.len() == 1 {
            return Choice::One(fronts.remove(0));
        }
        return Choice::NoTarget;
    }
    let signal = if in_front_count == 1 {
        uncovered.pop()
    } else {
        uncovered
            .into_iter()
            .find(|origin| origin.ascii_serialization() == claimed)
    };
    signal.map_or(Choice::NoTarget, Choice::Mismatch)
}

/// §7.3's rule for step two, given the reports of the one session that served step one: the
/// report from that session **and tab**, in front, at the claimed origin, which continues step
/// one's origin by the extension's same-site rule and which the item covers, with a password
/// field. The document may be the same one or a later one (implementation decision 38).
///
/// An uncovered origin in that tab is still §9.4's signal, as at gate 6.
fn choose_step_two(
    reports: &[Report],
    pending: &PendingStep,
    claimed: &str,
    websites: &[String],
) -> Choice {
    let mut chosen = Choice::NoTarget;
    for report in reports {
        if report.session != pending.session
            || report.tab.tab_id != pending.tab_id
            || !in_top_frame(&report.page)
        {
            continue;
        }
        let Ok(origin) = Origin::parse(&report.page.top_origin) else {
            continue;
        };
        let Some(saved) = covering_website(websites, &origin) else {
            return Choice::Mismatch(origin);
        };
        let ascii = origin.ascii_serialization();
        if ascii == claimed
            && continues_same_site(&pending.first_origin, &ascii)
            && report.found.covers(&[PageField::Password])
            && matches!(chosen, Choice::NoTarget)
        {
            chosen = Choice::One(Target {
                session: report.session,
                origin,
                saved,
                tab: report.tab.clone(),
                two_step: false,
            });
        } else {
            // Two reports for the one tab, or one that does not continue step one: nothing.
            return Choice::NoTarget;
        }
    }
    chosen
}

fn no_matching_tab() -> Response {
    Response::error(ErrorCode::NoMatchingTab, NO_MATCHING_TAB)
}

/// An opaque id nobody can guess: a v4 UUID behind a prefix.
fn fresh_id(prefix: &str) -> String {
    format!("{prefix}-{}", kagisecure_core::proto::LeaseId::new())
}

/// The `detail` of a release's `Allowed` entry: [`audit_detail::AGENT_FILL_APPROVED`], with the
/// step of a two-step grant — step two naming step one's entry — and the document-id degradation
/// of §4 inside one pair of parentheses.
fn approved_detail(step: Step, first_entry: Option<u64>, document_id: bool) -> String {
    let mut notes = Vec::new();
    match (step, first_entry) {
        (Step::One { .. }, _) => notes.push("step 1 of 2".to_owned()),
        (Step::Two, Some(seq)) => notes.push(format!("step 2 of 2, entry {seq}")),
        (Step::Two, None) => notes.push("step 2 of 2".to_owned()),
        (Step::Whole | Step::Code, _) => {}
    }
    if !document_id {
        notes.push("no document id".to_owned());
    }
    if notes.is_empty() {
        audit_detail::AGENT_FILL_APPROVED.to_owned()
    } else {
        format!(
            "{} ({})",
            audit_detail::AGENT_FILL_APPROVED,
            notes.join(", ")
        )
    }
}

/// What gate 9 is to issue: the step, the approval it spends or keeps, and — for step two —
/// step one's entry and the end of the flow window, which bounds the grant's life too.
struct Issue {
    step: Step,
    approved: Approved,
    first_entry: Option<u64>,
    until: Option<Instant>,
}

/// The item as it is now, for gates 3 and 4 asked again after the probe: its saved websites, its
/// title as the agent's listing shows it and — for an item in a shared vault — what its sheet
/// states and a grant records ([`SheetFacts`]), or the answer — already recorded — the request
/// gets instead.
fn item_now(
    call: &AgentFillCall<'_>,
) -> Result<(Vec<String>, String, Option<SheetFacts>), Response> {
    let shared = call.handle.shared_snapshots();
    let looked_up = call.handle.with(|vault| {
        let catalog = Catalog::new(vault, shared);
        catalog.agent_item(&call.item_id).map(|found| {
            let item = found.value;
            let password = call
                .fields
                .iter()
                .any(|f| matches!(f, AgentFillField::Password));
            let code = call
                .fields
                .iter()
                .any(|f| matches!(f, AgentFillField::OneTimeCode));
            (
                super::saved_websites(item),
                catalog.item_title(found),
                nothing_to_fill(item, &call.fields),
                found
                    .place
                    .shared()
                    .map(|snapshot| SheetFacts::for_fill(snapshot, item, password, code)),
            )
        })
    });
    match looked_up {
        None => Err(call.locked()),
        // Hidden, trashed or gone while the browsers were being asked: gate 3's answer, and
        // gate 3's entry, which names no item.
        Some(None) => {
            call.record(AuditDraft {
                item_id: None,
                vault_id: None,
                ..call.entry(AuditOutcome::Denied, ErrorCode::NotFound.as_str())
            });
            Err(crate::service::no_such_item())
        }
        Some(Some((_, _, Some(message), _))) => {
            call.record(call.entry(AuditOutcome::Denied, ErrorCode::NothingToFill.as_str()));
            Err(Response::error(ErrorCode::NothingToFill, message))
        }
        Some(Some((websites, title, None, shared))) => Ok((websites, title, shared)),
    }
}

impl FlowSlot {
    /// Gates 5–9 (ADR-0036 §11.1). Returns the sidecar's answer; every way out is audited.
    ///
    /// # Nothing after the target is chosen may answer without a sheet or a notice
    ///
    /// Once gate 6 has found a tab in front that is at the claimed origin, covered by the item and
    /// fillable, the only answers left are the human's (a sheet) or `NO_MATCHING_TAB`. Anything
    /// else answered without a sheet would tell the agent, for free, the one bit gate 6 exists to
    /// keep from it — "this item is saved for the site I am on" — where a mismatch at least costs
    /// it a notice and, the second time, a block (§9.4, §11.2). So everything that does not
    /// depend on the target is decided before gate 6 is asked: the audit pre-flight (gate 7) runs
    /// before gate 5, and a lock that landed while the browsers were being asked is answered
    /// right after the probe, before [`choose`] looks at a single report.
    ///
    /// A continuation (step two of an identifier-first grant) takes [`Self::serve_step_two`]
    /// instead, which raises no sheet.
    pub(crate) fn serve(self, call: &AgentFillCall<'_>) -> Response {
        let continuation = self
            .broker
            .state()
            .flow
            .as_mut()
            .and_then(|flow| flow.continuation.take());
        if let Some(pending) = continuation {
            return self.serve_step_two(call, pending);
        }
        let broker = Arc::clone(&self.broker);

        // Gate 7, asked first: the audit pre-flight.
        if let Err(answer) = Self::preflight(call) {
            return answer;
        }

        // Gate 5: a browser to ask.
        let asked: Vec<(u64, PushSender)> = broker
            .state()
            .sessions
            .iter()
            .filter(|(_, s)| s.push.is_open())
            .map(|(id, s)| (*id, s.push.clone()))
            .collect();
        if asked.is_empty() {
            call.record(call.entry(AuditOutcome::Denied, ErrorCode::FillUnavailable.as_str()));
            return crate::service::fill_unavailable();
        }

        // Gate 6: the target.
        let (probe_id, reports) = self.locate(&asked, &call.claimed_origin);
        // The item as it is now: the browsers took up to the probe window to answer, and gates 3
        // and 4 are asked again rather than trusted, with the answers they would now give.
        let (websites, title, shared) = match item_now(call) {
            Ok(found) => found,
            Err(answer) => return answer,
        };
        // Gate 2 again, before the reports are read. A lock while the browsers were being asked
        // — the `lock` tool, say, which bumps the epoch and closes the approval queue while the
        // vault is still in the handle — would otherwise be found only at the sheet, and so only
        // when a target had been chosen.
        if self.locked_since(call) {
            return call.locked();
        }
        let wanted: Vec<PageField> = call.fields.iter().map(|f| page_field(*f)).collect();
        let target = match choose(&reports, &call.claimed_origin, &wanted, &websites) {
            Choice::One(target) => target,
            Choice::NoTarget => {
                call.record(call.entry(AuditOutcome::Denied, audit_detail::AGENT_FILL_NO_TARGET));
                return no_matching_tab();
            }
            Choice::Mismatch(origin) => return self.mismatch(call, &origin, title),
        };
        let origin = target.origin.ascii_serialization();
        let Some((session, facts)) = self.facts(call, &target, &title) else {
            // The chosen session disconnected in the moment since it reported.
            call.record(call.entry(AuditOutcome::Denied, audit_detail::AGENT_FILL_NO_TARGET));
            return no_matching_tab();
        };

        // Gate 8, unattended (ADR-0042 §12.6): a standing login grant's pass stands where the
        // person's grant would, and no sheet is raised.
        let standing = call
            .standing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(pass) = standing {
            let Some(approved) =
                Approved::from_standing(pass, &origin, &call.item_id, &field_names(&call.fields))
            else {
                call.record(call.entry_via(
                    &session,
                    &origin,
                    AuditOutcome::Denied,
                    ErrorCode::NotGranted.as_str(),
                ));
                return Response::error(
                    ErrorCode::NotGranted,
                    crate::unattended::service::NOT_GRANTED,
                );
            };
            let step = if target.two_step {
                Step::One {
                    until: Instant::now() + broker.timings.flow_window,
                }
            } else if call.fields == [AgentFillField::OneTimeCode] {
                Step::Code
            } else {
                Step::Whole
            };
            let issue = Issue {
                step,
                approved,
                first_entry: None,
                until: match step {
                    Step::One { until } => Some(until),
                    _ => None,
                },
            };
            return self.deliver(call, &session, &probe_id, target, &title, issue);
        }

        // Gate 8: the human. Always the full sheet (implementation decision 5); no lock of this
        // broker's, and none of the vault's, is held while it is up. The sheet counts against the
        // agent's budget from the moment it is raised (§9.1).
        let raised = broker.clock.now();
        broker
            .state()
            .limits
            .sheet_raised(call.sidecar.key(), raised);
        let mut request = ApprovalRequest::for_agent_fill(facts);
        if let Some(shared) = &shared {
            shared.state_on(&mut request);
        }
        let outcome = call.queue.ask(request);
        let block_agent = outcome.block_agent;
        let grant = match outcome.into_grant() {
            Ok(grant) => grant,
            Err(ErrorCode::VaultLocked) => return call.locked(),
            Err(code) => {
                // Denied or timed out: the human has answered this question for ten minutes, and
                // with Deny and block, every question from this agent for thirty (§9.1, §9.3).
                let now = broker.clock.now();
                {
                    let mut state = broker.state();
                    state.limits.denied(
                        call.sidecar.key(),
                        &call.item_id,
                        &call.claimed_origin,
                        now,
                    );
                    if block_agent {
                        state.limits.block(
                            call.sidecar.key(),
                            &call.sidecar.name,
                            AgentFillBlockReason::DeniedAndBlocked,
                            now,
                        );
                    }
                }
                call.record(call.entry_via(
                    &session,
                    &origin,
                    AuditOutcome::Denied,
                    if block_agent {
                        audit_detail::AGENT_FILL_DENIED_AND_BLOCKED
                    } else {
                        audit_detail::AGENT_FILL_DENIED
                    },
                ));
                return crate::service::denied_reply(code);
            }
        };
        let Some(approved) = Approved::from_grant(
            grant,
            ApprovalKind::AgentFill,
            &origin,
            &call.item_id,
            &field_names(&call.fields),
        ) else {
            // Unreachable while `ask` answers the request it was given.
            call.record(call.entry_via(
                &session,
                &origin,
                AuditOutcome::Failed,
                ErrorCode::Internal.as_str(),
            ));
            return Response::error(
                ErrorCode::Internal,
                "The approval did not match the request. Nothing was filled.",
            );
        };

        // What the human saw of a shared item is what they approved (ADR-0035 §14).
        if let Some(shared) = &shared {
            shared.record_approved(call.handle);
        }

        // Gate 9: delivery. The flow window of a two-step grant runs from the approval.
        let step = if target.two_step {
            Step::One {
                until: Instant::now() + broker.timings.flow_window,
            }
        } else if call.fields == [AgentFillField::OneTimeCode] {
            Step::Code
        } else {
            Step::Whole
        };
        let issue = Issue {
            step,
            approved,
            first_entry: None,
            until: match step {
                Step::One { until } => Some(until),
                _ => None,
            },
        };
        self.deliver(call, &session, &probe_id, target, &title, issue)
    }

    /// Step two of an identifier-first grant (§7.3): the pending step `pending`, taken out of the
    /// store at gate 1, is served for the password without a sheet — or not at all.
    ///
    /// The browser that served step one is asked where it is now; [`choose_step_two`] decides.
    /// Whatever the answer, the pending step is spent: when the password is not released, step
    /// one's entry gets its `AGENT_FILL_PENDING_REFUSED` follow-up and the agent's next request
    /// is a new one, with a sheet of its own.
    fn serve_step_two(self, call: &AgentFillCall<'_>, pending: PendingStep) -> Response {
        let entry = pending.entry.clone();
        let entry_seq = pending.entry_seq;
        let answer = self.step_two(call, pending);
        if !matches!(answer, Response::FillResult { .. }) {
            call.record(release::follow_up(
                &entry,
                audit_detail::AGENT_FILL_PENDING_REFUSED,
                entry_seq,
            ));
        }
        answer
    }

    fn step_two(self, call: &AgentFillCall<'_>, pending: PendingStep) -> Response {
        // Gate 7, as for any request.
        if let Err(answer) = Self::preflight(call) {
            return answer;
        }
        // Gate 5: only the session that served step one can serve step two.
        let asked: Option<(u64, PushSender, SessionFacts)> = {
            let state = self.broker.state();
            state
                .sessions
                .get(&pending.session)
                .filter(|s| s.push.is_open())
                .map(|s| (pending.session, s.push.clone(), s.clone()))
        };
        let Some((session_id, push, session)) = asked else {
            call.record(call.entry(AuditOutcome::Denied, audit_detail::AGENT_FILL_NO_TARGET));
            return no_matching_tab();
        };

        // Gate 6: where that tab is now.
        let (probe_id, reports) = self.locate(&[(session_id, push)], &call.claimed_origin);
        let (websites, title, _) = match item_now(call) {
            Ok(found) => found,
            Err(answer) => return answer,
        };
        if self.locked_since(call) {
            return call.locked();
        }
        let target = match choose_step_two(&reports, &pending, &call.claimed_origin, &websites) {
            Choice::One(target) => target,
            Choice::NoTarget => {
                call.record(call.entry(AuditOutcome::Denied, audit_detail::AGENT_FILL_NO_TARGET));
                return no_matching_tab();
            }
            Choice::Mismatch(origin) => return self.mismatch(call, &origin, title),
        };

        // Gate 8 was step one's sheet. Gate 9: the password, spending step one's approval, within
        // what is left of the flow window.
        let issue = Issue {
            step: Step::Two,
            approved: pending.approved,
            first_entry: Some(pending.entry_seq),
            until: Some(pending.until),
        };
        self.deliver(call, &session, &probe_id, target, &title, issue)
    }

    /// Gate 7: the audit pre-flight. Nobody is asked to approve what could not be recorded — and
    /// whether earlier entries can be written does not depend on the tab, so it is answered
    /// before any tab is looked at.
    fn preflight(call: &AgentFillCall<'_>) -> Result<(), Response> {
        match call.handle.flush(REQUEST_LOCK_TIMEOUT) {
            None => Err(call.locked()),
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => {
                eprintln!(
                    "kagisecure: not asking the user to approve an agent fill: earlier audit \
                     entries still cannot be written: {e}"
                );
                let base = call.entry(AuditOutcome::Failed, "");
                let _ = call.handle.queue_audit(release::unavailable_entry(&base));
                Err(crate::service::audit_unavailable())
            }
        }
    }

    /// Whether a lock landed since this flow began, or the vault is locked now.
    fn locked_since(&self, call: &AgentFillCall<'_>) -> bool {
        let changed = {
            let state = self.broker.state();
            state
                .flow
                .as_ref()
                .is_none_or(|flow| flow.epoch != state.lock_epoch)
        };
        changed || !call.handle.is_unlocked()
    }

    /// §9.4: the tab in front is at `origin`, which the item is not saved for. Recorded, noticed,
    /// counted — the second in this unlock session blocks the agent until somebody looks — and
    /// answered `NO_MATCHING_TAB`. A claim that is merely off on a saved site is `NoTarget`, and
    /// counts for nothing here.
    fn mismatch(&self, call: &AgentFillCall<'_>, origin: &Origin, title: String) -> Response {
        let broker = &self.broker;
        let now = broker.clock.now();
        let blocked =
            broker
                .state()
                .limits
                .origin_mismatch(call.sidecar.key(), &call.sidecar.name, now);
        call.record(AuditDraft {
            target_path: Some(origin.ascii_serialization()),
            ..call.entry(
                AuditOutcome::Denied,
                if blocked {
                    audit_detail::AGENT_FILL_ORIGIN_MISMATCH_AND_BLOCKED
                } else {
                    audit_detail::AGENT_FILL_ORIGIN_MISMATCH
                },
            )
        });
        broker.notice(AgentFillNotice::OriginMismatch {
            agent: call.sidecar.actor.clone(),
            item_title: title,
            origin: AgentOriginRendering::of(origin),
        });
        if blocked {
            broker.notice(AgentFillNotice::Blocked {
                agent: call.sidecar.actor.clone(),
                key: call.sidecar.key().to_owned(),
                reason: AgentFillBlockReason::OriginMismatch,
            });
        }
        no_matching_tab()
    }

    /// Push `Locate` to every session in `asked` and collect what comes back, until every one has
    /// answered or the probe window closes. Returns the probe's id with the reports.
    fn locate(&self, asked: &[(u64, PushSender)], claimed_origin: &str) -> (String, Vec<Report>) {
        let broker = &self.broker;
        let probe_id = fresh_id("probe");
        if let Some(flow) = broker.state().flow.as_mut() {
            flow.probe = Some(Probe {
                id: probe_id.clone(),
                waiting: asked.iter().map(|(id, _)| *id).collect(),
                reports: Vec::new(),
            });
        }
        let push = Push::Locate {
            probe_id: probe_id.clone(),
            origin: Some(claimed_origin.to_owned()),
        };
        for (id, sender) in asked {
            if sender.send(&push).is_err()
                && let Some(probe) = broker.state().flow.as_mut().and_then(|f| f.probe.as_mut())
            {
                probe.waiting.remove(id);
            }
        }

        let deadline = Instant::now() + broker.timings.probe_window;
        let mut state = broker.state();
        loop {
            let done = state
                .flow
                .as_ref()
                .and_then(|f| f.probe.as_ref())
                .is_none_or(|p| p.waiting.is_empty());
            let now = Instant::now();
            if done || now >= deadline {
                break;
            }
            state = broker
                .signal
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let reports = state
            .flow
            .as_mut()
            .and_then(|f| f.probe.take())
            .map(|p| p.reports)
            .unwrap_or_default();
        (probe_id, reports)
    }

    /// The sheet's facts for `target`, and the session they came from.
    fn facts(
        &self,
        call: &AgentFillCall<'_>,
        target: &Target,
        title: &str,
    ) -> Option<(SessionFacts, AgentFillFacts)> {
        let session = self.broker.state().sessions.get(&target.session)?.clone();
        // The sidecar's parent from the kernel, never the `parent_pid` the sidecar reports: it is
        // what "this agent" means on the sheet, and exactly what its limits and blocks are keyed
        // on — resolved once, at gate 1 (§5, §9.3).
        let facts = AgentFillFacts {
            agent_name: call.sidecar.name.clone(),
            sidecar_pid: call.sidecar.pid,
            sidecar_executable: Some(call.sidecar.executable.clone()),
            sidecar_audit_token: call.sidecar.audit_token.clone(),
            parent_pid: Some(call.sidecar.parent_pid),
            parent_executable: Some(call.sidecar.parent_executable.clone()),
            item_id: call.item_id.clone(),
            item_title: title.to_owned(),
            fields: call.fields.clone(),
            two_step: target.two_step,
            page_origin: AgentOriginRendering::of(&target.origin),
            saved_website: target.saved.ascii_serialization(),
            page_host_differs: target.saved.host() != target.origin.host(),
            browser: session
                .identity
                .browser
                .map(|b| b.display_name().to_owned()),
            browser_pid: session.identity.browser_pid,
            browser_executable: session.identity.browser_executable.clone(),
            browser_is_app_extension: session.identity.app_extension,
            host_pid: session.identity.pid,
            host_audit_token: session.identity.audit_token.clone(),
            host_executable: session.identity.executable.clone(),
            extension_id: Some(session.extension_id.clone()),
        };
        Some((session, facts))
    }

    /// Gate 9: issue the grant, ring `Deliver`, and wait for the extension to redeem it and say
    /// what it wrote.
    fn deliver(
        self,
        call: &AgentFillCall<'_>,
        session: &SessionFacts,
        probe_id: &str,
        target: Target,
        title: &str,
        issue: Issue,
    ) -> Response {
        let broker = Arc::clone(&self.broker);
        let origin = target.origin.ascii_serialization();
        let grant_id = fresh_id("grant");
        let Issue {
            step,
            approved,
            first_entry,
            until,
        } = issue;
        // What this redemption writes: step one, the username; step two, the password.
        let fields = match step {
            Step::One { .. } => vec![AgentFillField::Username],
            Step::Two => vec![AgentFillField::Password],
            Step::Whole | Step::Code => call.fields.clone(),
        };
        let detail = match approved.standing() {
            // ADR-0042 §12.8: an unattended fill names its grant and run.
            Some(label) => format!("UNATTENDED_FILL_APPROVED ({label})"),
            None => approved_detail(step, first_entry, target.tab.document_id.is_some()),
        };
        let entry = AuditDraft {
            variables: field_names(&fields),
            ..call.entry_via(session, &origin, AuditOutcome::Allowed, &detail)
        };
        let not_delivered = || {
            call.record(call.entry_via(
                session,
                &origin,
                AuditOutcome::Failed,
                audit_detail::AGENT_FILL_NOT_DELIVERED,
            ));
            no_matching_tab()
        };

        // Issued under the broker's lock, and only if no lock landed since the flow began and the
        // vault is still unlocked now. `is_unlocked` takes the vault handle's mutex, which a lock
        // releases before it runs its hooks — so a lock either happened before this check and is
        // seen, or runs `revoke_all` after it and takes the grant back.
        {
            let mut state = broker.state();
            let epoch = state.lock_epoch;
            let session_live = state.sessions.contains_key(&target.session);
            let Some(flow) = state.flow.as_mut() else {
                drop(state);
                return not_delivered();
            };
            if flow.epoch != epoch || !call.handle.is_unlocked() {
                // The human approved; a lock since then took the approval with it. Recorded, so
                // the log does not end at a sheet the human said yes to.
                drop(state);
                let _ = not_delivered();
                return crate::service::locked_reply();
            }
            if !session_live {
                drop(state);
                return not_delivered();
            }
            let life = Instant::now() + broker.timings.grant_life;
            flow.grant = Some(AgentFillGrant {
                id: grant_id.clone(),
                session: target.session,
                sidecar: call.sidecar.clone(),
                item_id: call.item_id.clone(),
                item_title: title.to_owned(),
                fields: fields.clone(),
                origin: origin.clone(),
                tab_id: target.tab.tab_id,
                document_id: target.tab.document_id.clone(),
                expires_at: until.map_or(life, |until| life.min(until)),
                entry,
                step,
                approved,
            });
            flow.issued = Some((grant_id.clone(), target.session));
            flow.delivery = Delivery::Waiting;
        }

        // The probe id is the extension's key for the tab and document it reported; the grant id
        // is what it quotes back. Neither says anything about the item, the site or the agent.
        let rung = session.push.send(&Push::Deliver {
            probe_id: probe_id.to_owned(),
            grant_id,
        });
        if rung.is_err() {
            let mut state = broker.state();
            if let Some(flow) = state.flow.as_mut()
                && matches!(flow.delivery, Delivery::Waiting)
            {
                flow.grant = None;
                flow.delivery = Delivery::Undelivered;
            }
        }
        let first = Delivered {
            session: target.session,
            tab_id: target.tab.tab_id,
            origin: &origin,
        };
        self.wait_for_delivery(call, session, &first, &not_delivered)
    }

    /// Wait until the grant is redeemed and its outcome is known, or it dies; then record and
    /// answer.
    fn wait_for_delivery(
        &self,
        call: &AgentFillCall<'_>,
        session: &SessionFacts,
        delivered: &Delivered<'_>,
        not_delivered: &dyn Fn() -> Response,
    ) -> Response {
        let broker = &self.broker;
        let origin = delivered.origin;
        let mut state = broker.state();
        loop {
            let now = Instant::now();
            let Some(flow) = state.flow.as_mut() else {
                break;
            };
            let wake = match &flow.delivery {
                Delivery::Waiting => {
                    let expires_at = flow.grant.as_ref().map_or(now, |g| g.expires_at);
                    if now >= expires_at {
                        flow.grant = None;
                        flow.delivery = Delivery::Undelivered;
                        continue;
                    }
                    expires_at
                }
                // The release transaction bounds itself, and settles the flow when it ends; the
                // deadline is for a redemption that ended without doing so.
                Delivery::Redeeming { until } => {
                    if now >= *until {
                        flow.delivery = Delivery::Undelivered;
                        continue;
                    }
                    *until
                }
                Delivery::Released(released) => {
                    let until = released.at + broker.timings.outcome_wait;
                    if released.outcome.is_some()
                        || released.reply_failed
                        || released.session_gone
                        || now >= until
                    {
                        break;
                    }
                    until
                }
                Delivery::NotYet
                | Delivery::Refused(_)
                | Delivery::Undelivered
                | Delivery::Locked => break,
            };
            state = broker
                .signal
                .wait_timeout(state, wake.saturating_duration_since(now))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }

        // What happened, read under the lock; recorded and answered after it is released. The
        // approval step one kept moves out of the state here, and only here.
        let lock_epoch = state.lock_epoch;
        let settled = match state.flow.as_mut() {
            Some(flow) => {
                let epoch = flow.epoch;
                match &mut flow.delivery {
                    Delivery::Released(released) => {
                        let kept = released.kept.take();
                        Settled::Released {
                            entry: released.entry.clone(),
                            entry_seq: released.entry_seq,
                            fields: released.fields.clone(),
                            outcome: released.outcome.clone(),
                            reply_failed: released.reply_failed,
                            step_one: kept.is_some(),
                            kept: kept.filter(|_| epoch == lock_epoch),
                        }
                    }
                    Delivery::Refused(Refused::AuditUnavailable) => Settled::AuditUnavailable,
                    Delivery::Refused(Refused::Locked) | Delivery::Locked => Settled::Locked,
                    Delivery::Refused(Refused::Internal) => Settled::Internal,
                    _ => Settled::Undelivered,
                }
            }
            None => Settled::Undelivered,
        };
        drop(state);

        match settled {
            Settled::Undelivered => not_delivered(),
            // Approved, and then a lock took the grant or beat the release to the vault.
            Settled::Locked => {
                let _ = not_delivered();
                crate::service::locked_reply()
            }
            // The `Failed` entry is already queued (`audited_release`).
            Settled::AuditUnavailable => crate::service::audit_unavailable(),
            Settled::Internal => {
                call.record(call.entry_via(
                    session,
                    origin,
                    AuditOutcome::Failed,
                    ErrorCode::Internal.as_str(),
                ));
                Response::error(
                    ErrorCode::Internal,
                    "The approval did not match the fill. Nothing was filled.",
                )
            }
            Settled::Released {
                entry,
                entry_seq,
                fields,
                outcome,
                reply_failed,
                step_one,
                kept,
            } => {
                let follow_up = |code: &str| {
                    call.record(release::follow_up(&entry, code, entry_seq));
                };
                match outcome {
                    // `REPLY_FAILED` already says what happened.
                    _ if reply_failed => no_matching_tab(),
                    None => {
                        follow_up(audit_detail::AGENT_FILL_NOT_CONFIRMED);
                        no_matching_tab()
                    }
                    Some((written, None)) if !written.is_empty() => {
                        let fields_written: Vec<AgentFillField> = fields
                            .into_iter()
                            .filter(|f| written.contains(&page_field(*f)))
                            .collect();
                        // Step one: whatever was asked for and not written is pending — the
                        // password, which the approval kept here is now waiting to pay for. Said
                        // even when a lock overtook step one: the password is not written.
                        let fields_pending: Vec<AgentFillField> = if step_one {
                            call.fields
                                .iter()
                                .copied()
                                .filter(|f| !fields_written.contains(f))
                                .collect()
                        } else {
                            Vec::new()
                        };
                        if let Some((approved, until)) = kept
                            && fields_written == [AgentFillField::Username]
                        {
                            self.keep_pending(call, delivered, entry, entry_seq, approved, until);
                        }
                        Response::FillResult {
                            fields_written,
                            fields_pending,
                        }
                    }
                    Some(_) => {
                        follow_up(audit_detail::AGENT_FILL_NOT_WRITTEN);
                        no_matching_tab()
                    }
                }
            }
        }
    }

    /// Step one wrote the username: the approval waits for step two, bound to what step one was
    /// bound to, until the flow window closes.
    fn keep_pending(
        &self,
        call: &AgentFillCall<'_>,
        delivered: &Delivered<'_>,
        entry: AuditDraft,
        entry_seq: u64,
        approved: Approved,
        until: Instant,
    ) {
        let id = {
            let mut state = self.broker.state();
            state.next_pending = state.next_pending.wrapping_add(1);
            state.next_pending
        };
        let epoch = self
            .broker
            .state()
            .flow
            .as_ref()
            .map_or(u64::MAX, |f| f.epoch);
        self.broker.keep_pending(PendingStep {
            id,
            sidecar: call.sidecar.clone(),
            item_id: call.item_id.clone(),
            first_origin: delivered.origin.to_owned(),
            session: delivered.session,
            tab_id: delivered.tab_id,
            until,
            epoch,
            entry,
            entry_seq,
            approved,
            handle: Arc::downgrade(call.handle),
            session_gone: false,
        });
    }
}

/// Where a grant was delivered: what step two of a two-step grant must continue.
struct Delivered<'a> {
    session: u64,
    tab_id: u64,
    origin: &'a str,
}

/// How a delivery ended, copied out of the broker's state.
///
/// A value on one stack frame, for the moment between reading the state and answering, so the
/// size of its one large variant costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
enum Settled {
    Undelivered,
    Locked,
    AuditUnavailable,
    Internal,
    Released {
        entry: AuditDraft,
        entry_seq: u64,
        fields: Vec<AgentFillField>,
        outcome: Option<(Vec<PageField>, Option<AgentFillFailure>)>,
        reply_failed: bool,
        /// Whether this was step one of a two-step grant.
        step_one: bool,
        /// Step one's approval, kept for step two — `None` for every other release, and for a
        /// step one a lock overtook.
        kept: Option<(Approved, Instant)>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(origin: &str, found: FoundFields) -> Report {
        Report {
            session: 1,
            page: PageContext::top(origin),
            tab: TabFacts {
                tab_id: 7,
                document_id: Some("doc".to_owned()),
                tab_active: true,
                visible: true,
            },
            found,
        }
    }

    fn login_form() -> FoundFields {
        FoundFields {
            username: true,
            password: true,
            one_time_code: false,
        }
    }

    fn both() -> Vec<PageField> {
        vec![PageField::Username, PageField::Password]
    }

    fn saved() -> Vec<String> {
        vec!["https://example.com".to_owned()]
    }

    #[test]
    fn one_eligible_report_is_chosen() {
        let reports = [report("https://login.example.com", login_form())];
        let Choice::One(target) = choose(&reports, "https://login.example.com", &both(), &saved())
        else {
            panic!("one eligible report must be chosen");
        };
        assert_eq!(target.saved.ascii_serialization(), "https://example.com");
        assert_eq!(target.tab.tab_id, 7);
    }

    #[test]
    fn a_look_alike_in_front_is_a_mismatch_whatever_the_claim() {
        for claim in ["https://examp1e.com", "https://example.com"] {
            let reports = [report("https://examp1e.com", login_form())];
            assert!(
                matches!(
                    choose(&reports, claim, &both(), &saved()),
                    Choice::Mismatch(ref o) if o.ascii_serialization() == "https://examp1e.com"
                ),
                "claim {claim}"
            );
        }
    }

    #[test]
    fn another_browsers_tab_beside_the_agents_is_not_a_mismatch() {
        // The agent's browser is on a saved site, off by a subdomain; the human's other browser
        // is somewhere the item is not saved for. Neither is eligible, and the other one is not
        // the agent's business.
        let mut other = report("https://private.test", login_form());
        other.session = 2;
        let reports = [report("https://www.example.com", login_form()), other];
        assert!(matches!(
            choose(&reports, "https://login.example.com", &both(), &saved()),
            Choice::NoTarget
        ));
    }

    #[test]
    fn beside_another_tab_a_mismatch_counts_only_at_the_claimed_origin() {
        let mut other = report("https://private.test", login_form());
        other.session = 2;
        let reports = [report("https://examp1e.com", login_form()), other];
        assert!(matches!(
            choose(&reports, "https://examp1e.com", &both(), &saved()),
            Choice::Mismatch(ref o) if o.ascii_serialization() == "https://examp1e.com"
        ));
        assert!(matches!(
            choose(&reports, "https://login.example.com", &both(), &saved()),
            Choice::NoTarget
        ));
    }

    #[test]
    fn a_saved_site_at_another_origin_than_claimed_is_no_target_not_a_mismatch() {
        let reports = [report("https://www.example.com", login_form())];
        assert!(matches!(
            choose(&reports, "https://example.com", &both(), &saved()),
            Choice::NoTarget
        ));
    }

    fn identifier_only() -> FoundFields {
        FoundFields {
            username: true,
            password: false,
            one_time_code: false,
        }
    }

    #[test]
    fn an_identifier_only_page_is_a_two_step_target_for_a_login_and_a_plain_one_for_a_username() {
        let reports = [report("https://example.com", identifier_only())];
        let Choice::One(login) = choose(&reports, "https://example.com", &both(), &saved()) else {
            panic!("page one of an identifier-first sign-in is eligible for a login");
        };
        assert!(login.two_step);
        let Choice::One(username) = choose(
            &reports,
            "https://example.com",
            &[PageField::Username],
            &saved(),
        ) else {
            panic!("a username alone fits page one");
        };
        assert!(!username.two_step);
        // The password alone has nowhere to go on page one.
        assert!(matches!(
            choose(
                &reports,
                "https://example.com",
                &[PageField::Password],
                &saved()
            ),
            Choice::NoTarget
        ));
    }

    #[test]
    fn a_one_time_code_needs_a_page_with_a_code_field() {
        let code = [PageField::OneTimeCode];
        let reports = [report("https://example.com", login_form())];
        assert!(matches!(
            choose(&reports, "https://example.com", &code, &saved()),
            Choice::NoTarget
        ));
        let with_code = FoundFields {
            one_time_code: true,
            ..FoundFields::default()
        };
        let reports = [report("https://example.com", with_code)];
        assert!(matches!(
            choose(&reports, "https://example.com", &code, &saved()),
            Choice::One(ref t) if !t.two_step
        ));
    }

    fn pending_on(session: u64, tab_id: u64, first: &str) -> PendingStep {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || {
            asker.ask(ApprovalRequest {
                kind: ApprovalKind::AgentFill,
                origin: Some("https://login.example.com".to_owned()),
                item_id: Some("item-1".to_owned()),
                fill_fields: vec!["username".to_owned(), "password".to_owned()],
                ..ApprovalRequest::default()
            })
        });
        let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
        queue.resolve(
            &delivered.id,
            &crate::approval::Decision::AllowOnce,
            crate::approval::ClientVerification::unchecked(),
        );
        let grant = thread.join().expect("asker").into_grant().expect("granted");
        let approved = Approved::from_grant(
            grant,
            ApprovalKind::AgentFill,
            "https://login.example.com",
            "item-1",
            &["username".to_owned(), "password".to_owned()],
        )
        .expect("approved");
        PendingStep {
            id: 1,
            sidecar: this_process_as_a_sidecar(None),
            item_id: "item-1".to_owned(),
            first_origin: first.to_owned(),
            session,
            tab_id,
            until: Instant::now() + FLOW_WINDOW,
            epoch: 0,
            entry: AuditDraft::default(),
            entry_seq: 1,
            approved,
            handle: Weak::new(),
            session_gone: false,
        }
    }

    #[test]
    fn step_two_must_be_the_same_tab_on_the_same_site_with_a_password_field() {
        let pending = pending_on(1, 7, "https://login.example.com");
        let page_two = |origin: &str| report(origin, login_form());
        let claim_ok = |reports: &[Report], claim: &str| {
            matches!(
                choose_step_two(reports, &pending, claim, &saved()),
                Choice::One(_)
            )
        };
        // The same document (a form swapped in place) or a later one, at the same origin or a
        // subdomain of it.
        assert!(claim_ok(
            &[page_two("https://login.example.com")],
            "https://login.example.com"
        ));
        assert!(claim_ok(
            &[page_two("https://pw.login.example.com")],
            "https://pw.login.example.com"
        ));
        // A sibling on the same registrable domain is covered by the item but is not the same
        // sign-in.
        assert!(!claim_ok(
            &[page_two("https://accounts.example.com")],
            "https://accounts.example.com"
        ));
        // Not the claimed origin.
        assert!(!claim_ok(
            &[page_two("https://login.example.com")],
            "https://pw.login.example.com"
        ));
        // Still page one.
        assert!(!claim_ok(
            &[report("https://login.example.com", identifier_only())],
            "https://login.example.com"
        ));
        // Another tab, or another session.
        let mut other_tab = page_two("https://login.example.com");
        other_tab.tab.tab_id = 8;
        assert!(!claim_ok(&[other_tab], "https://login.example.com"));
        let mut other_session = page_two("https://login.example.com");
        other_session.session = 2;
        assert!(!claim_ok(&[other_session], "https://login.example.com"));
        // The tab wandered off to a site the item is not saved for: §9.4's signal.
        assert!(matches!(
            choose_step_two(
                &[page_two("https://examp1e.com")],
                &pending,
                "https://examp1e.com",
                &saved()
            ),
            Choice::Mismatch(_)
        ));
    }

    #[test]
    fn a_continuation_is_the_same_process_item_and_password_inside_the_window() {
        let pending = pending_on(1, 7, "https://login.example.com");
        let me = this_process_as_a_sidecar(None);
        let now = Instant::now();
        let password = [AgentFillField::Password];
        assert!(pending.continued_by(&me, "item-1", &password, now, 0));
        assert!(!pending.continued_by(&me, "item-2", &password, now, 0));
        assert!(!pending.continued_by(&me, "item-1", &both_fields(), now, 0));
        assert!(!pending.continued_by(&me, "item-1", &[AgentFillField::OneTimeCode], now, 0));
        assert!(!pending.continued_by(&me, "item-1", &password, now + FLOW_WINDOW, 0));
        assert!(!pending.continued_by(&me, "item-1", &password, now, 1));
        let mut another = this_process_as_a_sidecar(None);
        another.pid = another.pid.wrapping_add(1);
        assert!(!pending.continued_by(&another, "item-1", &password, now, 0));
        // The name a process reports is not what makes it the same process.
        let mut renamed = this_process_as_a_sidecar(None);
        renamed.name = "another-name".to_owned();
        assert!(pending.continued_by(&renamed, "item-1", &password, now, 0));
    }

    fn both_fields() -> Vec<AgentFillField> {
        vec![AgentFillField::Username, AgentFillField::Password]
    }

    #[test]
    fn the_approved_detail_names_the_step_and_the_degradation() {
        let one = Step::One {
            until: Instant::now(),
        };
        assert_eq!(
            approved_detail(Step::Whole, None, true),
            audit_detail::AGENT_FILL_APPROVED
        );
        assert_eq!(
            approved_detail(Step::Whole, None, false),
            audit_detail::AGENT_FILL_APPROVED_WITHOUT_DOCUMENT_ID
        );
        assert_eq!(
            approved_detail(one, None, true),
            audit_detail::AGENT_FILL_APPROVED_STEP_ONE
        );
        assert_eq!(
            approved_detail(Step::Two, Some(12), true),
            "AGENT_FILL_APPROVED (step 2 of 2, entry 12)"
        );
        assert_eq!(
            approved_detail(Step::Two, Some(12), false),
            "AGENT_FILL_APPROVED (step 2 of 2, entry 12, no document id)"
        );
        assert_eq!(
            approved_detail(Step::Code, None, true),
            "AGENT_FILL_APPROVED"
        );
    }

    #[test]
    fn a_code_is_audited_under_totp_code_and_a_login_under_request_fill() {
        assert_eq!(tool_for(&[AgentFillField::OneTimeCode]), CODE_TOOL);
        assert_eq!(CODE_TOOL, "totp_code");
        assert_eq!(tool_for(&both_fields()), TOOL);
        assert_eq!(tool_for(&[AgentFillField::Password]), TOOL);
    }

    #[test]
    fn a_framed_or_unestablished_report_is_never_a_target() {
        let mut unestablished = report("https://example.com", login_form());
        unestablished.page.top_origin_established = false;
        let mut in_a_frame = report("https://example.com", login_form());
        in_a_frame.page.frame_origin = Some("https://other.test".to_owned());
        for (what, r) in [("unestablished", unestablished), ("a frame", in_a_frame)] {
            assert!(
                matches!(
                    choose(&[r], "https://example.com", &both(), &saved()),
                    Choice::NoTarget
                ),
                "{what}"
            );
        }
    }

    #[test]
    fn a_hidden_or_inactive_tab_is_a_target_when_it_is_the_only_match() {
        let mut hidden = report("https://example.com", login_form());
        hidden.tab.visible = false;
        let mut inactive = report("https://example.com", login_form());
        inactive.tab.tab_active = false;
        for (what, r) in [("hidden", hidden), ("inactive", inactive)] {
            assert!(
                matches!(
                    choose(&[r], "https://example.com", &both(), &saved()),
                    Choice::One(_)
                ),
                "{what}"
            );
        }
    }

    #[test]
    fn of_several_matches_the_one_in_front_is_chosen() {
        let mut background = report("https://example.com", login_form());
        background.session = 2;
        background.tab.tab_active = false;
        let reports = [background, report("https://example.com", login_form())];
        let Choice::One(target) = choose(&reports, "https://example.com", &both(), &saved()) else {
            panic!("expected the front tab");
        };
        assert_eq!(target.session, 1);
    }

    #[test]
    fn two_eligible_reports_in_front_are_no_target() {
        let mut second = report("https://example.com", login_form());
        second.session = 2;
        let reports = [report("https://example.com", login_form()), second];
        assert!(matches!(
            choose(&reports, "https://example.com", &both(), &saved()),
            Choice::NoTarget
        ));
    }

    #[test]
    fn the_empty_report_the_extension_sends_is_ineligible() {
        let empty = Report {
            session: 1,
            page: PageContext {
                top_origin: "null".to_owned(),
                frame_origin: None,
                top_origin_established: false,
            },
            tab: TabFacts::default(),
            found: FoundFields::default(),
        };
        assert!(matches!(
            choose(&[empty], "https://example.com", &both(), &saved()),
            Choice::NoTarget
        ));
    }

    #[test]
    fn every_audit_detail_token_is_screaming_snake_case() {
        for token in [
            audit_detail::AGENT_FILL_APPROVED,
            audit_detail::AGENT_FILL_DENIED,
            audit_detail::AGENT_FILL_NO_TARGET,
            audit_detail::AGENT_FILL_ORIGIN_MISMATCH,
            audit_detail::AGENT_FILL_NOT_DELIVERED,
            audit_detail::AGENT_FILL_NOT_WRITTEN,
            audit_detail::AGENT_FILL_NOT_CONFIRMED,
            audit_detail::AGENT_FILL_UNMASKED,
            audit_detail::AGENT_FILL_BUSY,
            audit_detail::AGENT_FILL_BLOCKED,
            audit_detail::AGENT_FILL_RATE_LIMITED,
            audit_detail::AGENT_FILL_PENDING_EXPIRED,
            audit_detail::AGENT_FILL_PENDING_REFUSED,
        ] {
            assert!(
                token.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{token}"
            );
        }
    }

    fn this_process_as_a_sidecar(started: Option<u64>) -> Sidecar {
        let pid = std::process::id();
        Sidecar {
            pid,
            executable: executable_for_pid(pid).expect("this process's executable"),
            started,
            name: "example-agent".to_owned(),
            actor: "mcp \"example-agent\"".to_owned(),
            parent_pid: 1,
            parent_executable: "/sbin/launchd".to_owned(),
            audit_token: None,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_sidecar_is_still_running_only_while_its_pid_keeps_its_start_time() {
        let started = process_start_time(std::process::id()).expect("a start time here");
        assert!(this_process_as_a_sidecar(Some(started)).still_running());
        // The same pid and executable, started at another moment: another process that was
        // handed the pid, which the executable alone cannot tell apart.
        assert!(!this_process_as_a_sidecar(Some(started.wrapping_add(1))).still_running());
        assert!(!this_process_as_a_sidecar(Some(started.wrapping_sub(1))).still_running());
    }

    #[test]
    fn without_a_start_time_a_sidecar_is_bound_to_its_pid_and_executable() {
        assert!(this_process_as_a_sidecar(None).still_running());
        let mut gone = this_process_as_a_sidecar(None);
        gone.executable = "/nonexistent/kagisecure-mcp".to_owned();
        assert!(!gone.still_running());
    }

    /// A broker whose one flow has issued `grant-1` to session 5 and is redeeming it.
    fn redeeming() -> Arc<AgentFillBroker> {
        let broker = Arc::new(AgentFillBroker::new());
        broker.state().flow = Some(Flow {
            epoch: 0,
            probe: None,
            grant: None,
            issued: Some(("grant-1".to_owned(), 5)),
            delivery: Delivery::Redeeming {
                until: Instant::now() + REDEEM_DEADLINE,
            },
            continuation: None,
        });
        broker
    }

    fn delivery_is_undelivered(broker: &AgentFillBroker) -> bool {
        matches!(
            broker.state().flow.as_ref().map(|f| &f.delivery),
            Some(Delivery::Undelivered)
        )
    }

    #[test]
    fn a_session_dropped_mid_redemption_does_not_wedge_the_flow() {
        let broker = redeeming();
        // Another session going away is none of this redemption's business.
        drop(SessionTicket {
            broker: Arc::clone(&broker),
            id: 6,
        });
        assert!(!delivery_is_undelivered(&broker));

        // The redeeming session's thread panics in the middle of the release: unwinding drops
        // its ticket, which is the only thing that runs.
        let ticket = SessionTicket {
            broker: Arc::clone(&broker),
            id: 5,
        };
        let unwound = std::thread::spawn(move || {
            let _ticket = ticket;
            panic!("a redemption that never settles");
        })
        .join();
        assert!(unwound.is_err());
        assert!(
            delivery_is_undelivered(&broker),
            "the waiting flow is told nothing was delivered, and gives the slot back"
        );
        assert!(
            !broker.settle("grant-1", Delivery::Refused(Refused::Recheck)),
            "a redemption that ends late settles nothing"
        );
    }

    #[test]
    fn a_late_redemption_never_settles_another_flow() {
        let broker = redeeming();
        broker.state().flow.as_mut().expect("a flow").issued = Some(("grant-2".to_owned(), 5));
        assert!(!broker.settle("grant-1", Delivery::Refused(Refused::Recheck)));
        assert!(matches!(
            broker.state().flow.as_ref().map(|f| &f.delivery),
            Some(Delivery::Redeeming { .. })
        ));
        assert!(broker.settle("grant-2", Delivery::Refused(Refused::Recheck)));
    }

    #[test]
    fn a_redemption_has_a_hard_deadline_past_the_release_transactions_own() {
        assert!(REDEEM_DEADLINE > REQUEST_LOCK_TIMEOUT);
        assert_eq!(AgentFillTimings::default().redeem_deadline, REDEEM_DEADLINE);
    }

    #[test]
    fn the_switch_is_off_by_default_and_a_grant_lives_thirty_seconds() {
        assert!(!AgentFillBroker::new().is_enabled());
        assert_eq!(GRANT_LIFE, Duration::from_secs(30));
        assert_eq!(AgentFillTimings::default().grant_life, GRANT_LIFE);
    }
}

//! The presence gate: a fresh, physical human decision in front of every value the app releases
//! ([ADR-0038](../../../docs/decisions/0038-app-release-needs-presence.md)).
//!
//! # What lives here
//!
//! * [`PresenceGate`] — the one foreign (Swift-implemented) trait this crate has, awaited from
//!   Rust. The app's implementation asks `LocalAuthentication` with a fresh `LAContext` and no
//!   reuse duration; a test's implementation answers from a script. Installed once per session
//!   with [`VaultSession::set_presence_gate`]; with none installed, every release fails closed.
//! * The prompt's wording, built here from vault facts — the item's title, the field's label, the
//!   action — and sanitised the way the app's `ApprovalSheet.safe` sanitises fill-approval text,
//!   so a title cannot reorder, hide or out-shout the sentence around it.
//! * The in-flight registry: at most one release awaits the gate at a time, a second is refused
//!   ([`FfiError::PresenceBusy`]) rather than queued, and [`VaultSession::lock`] drains it — the
//!   release it finds is recorded `VAULT_LOCKED` and can no longer hand anything out, whatever the
//!   gate answers afterwards.
//! * The master-password fallback's verifier (ADR-0038 user decision 7), rate limited here.
//!
//! The release calls themselves, and the objects they return, are in `crate::release`.
//!
//! [`VaultSession::set_presence_gate`]: crate::VaultSession::set_presence_gate
//! [`VaultSession::lock`]: crate::VaultSession::lock
//! [`FfiError::PresenceBusy`]: crate::FfiError::PresenceBusy

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Field, Item};
use kagisecure_core::proto::{FieldKind, Outcome};
use zeroize::Zeroizing;

use crate::session::VaultSession;
use crate::{FfiError, FfiResult};

/// How long a release stays live after the touch that granted it: five minutes, and use does not
/// extend it (ADR-0038 user decisions 2 and 5).
pub(crate) const RELEASE_TTL: Duration = Duration::from_secs(5 * 60);

/// The longest the master-password fallback ever makes a person wait between attempts.
pub(crate) const MAX_PASSWORD_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// Audit `detail` for a release a fresh presence check granted.
pub const DETAIL_PRESENCE_CONFIRMED: &str = "PRESENCE_CONFIRMED";
/// Audit `detail` for a release granted by the fallback (ADR-0038 user decision 7): the gate
/// could not run `LocalAuthentication`, and the person typed the vault's **master** password
/// instead, which this crate checked itself ([`VaultSession::verify_master_password`]) while the
/// release was waiting.
///
/// Its own detail, not `PRESENCE_CONFIRMED`, because the two prove different things (W-20): a
/// biometric, a watch or the Mac's login password is evidence a person was at this Mac, while the
/// master password is evidence only that whoever answered knows it — the one secret an adversary
/// who also drives the UI may already have. `MASTER_PASSWORD` rather than just `PASSWORD`,
/// because `LocalAuthentication` itself accepts the Mac's *login* password, and that answer is
/// `PRESENCE_CONFIRMED`; a reader of the log must not have to guess which password was typed.
/// The shared `PRESENCE_CONFIRMED` prefix keeps both grants together for anyone scanning by it.
///
/// Decided by Rust, not claimed by the gate: the gate still answers plain
/// [`PresenceOutcome::Confirmed`], and this detail is written only when a
/// [`MasterPasswordCheck::Verified`] happened for the release in flight.
pub const DETAIL_PRESENCE_CONFIRMED_MASTER_PASSWORD: &str = "PRESENCE_CONFIRMED_MASTER_PASSWORD";
/// Audit `detail` for a release refused because the person dismissed the prompt.
pub const DETAIL_PRESENCE_CANCELLED: &str = "PRESENCE_CANCELLED";
/// Audit `detail` for a release refused because no presence check could run.
pub const DETAIL_PRESENCE_UNAVAILABLE: &str = "PRESENCE_UNAVAILABLE";
/// Audit `detail` for a release refused because another prompt was already up.
pub const DETAIL_PRESENCE_BUSY: &str = "PRESENCE_BUSY";
/// Audit `detail` for a release that was waiting on its prompt when the vault locked.
pub const DETAIL_VAULT_LOCKED: &str = "VAULT_LOCKED";
/// Audit `detail` for a copy of a value already shown under an earlier touch — no new touch
/// happened for this entry, and the log says so (ADR-0038 user decision 1).
pub const DETAIL_SHOWN_EARLIER: &str = "SHOWN_EARLIER";
/// Audit `detail` for a release the person confirmed whose item, field or notes had been deleted
/// by the time the prompt answered — from this window, another one, or another process. Outcome
/// `failed`, not `denied`: nobody refused anything, and there was nothing left to hand out.
pub const DETAIL_GONE_DURING_PROMPT: &str = "GONE_DURING_PROMPT";

/// Audit `tool` for a wrong or throttled master password typed into the fallback — recorded
/// because a burst of them is what an automation agent guessing through the app's own UI looks
/// like, and the log is where a person would look for that.
pub const TOOL_VERIFY_MASTER_PASSWORD: &str = "verify_master_password";
/// Audit `detail` for a master password that was checked and was wrong.
pub const DETAIL_MASTER_PASSWORD_WRONG: &str = "MASTER_PASSWORD_WRONG";
/// Audit `detail` for an attempt refused unchecked by the back-off. Recorded once per back-off
/// window rather than once per attempt: an attempt that is refused costs nothing, and writing an
/// entry for each would let anything that can press Return grow the log (and rewrite the vault
/// file) as fast as it can press it.
pub const DETAIL_MASTER_PASSWORD_THROTTLED: &str = "MASTER_PASSWORD_THROTTLED";

/// How long one refusal reason (`PRESENCE_BUSY`, `PRESENCE_CANCELLED`, `PRESENCE_UNAVAILABLE`)
/// is written once and then only counted: a minute ([`Presence::throttle_refusal`]).
pub(crate) const REFUSAL_AUDIT_WINDOW: Duration = Duration::from_secs(60);

/// Suffix of the audit `detail` that closes a throttled burst of one refusal reason, followed by
/// how many refusals the window counted without writing: `PRESENCE_BUSY_REPEATED:17` is seventeen
/// more `PRESENCE_BUSY` refusals than the one entry already written for that minute.
pub const DETAIL_REPEATED_SUFFIX: &str = "_REPEATED:";

/// What a presence check answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PresenceOutcome {
    /// A person proved presence — Touch ID, an Apple Watch, the login password, or (only when
    /// none of those can run) the vault's master password. The one answer that releases anything.
    Confirmed,
    /// The person dismissed the prompt, or the check failed.
    Cancelled,
    /// No presence check can run on this Mac right now.
    Unavailable,
    /// Another prompt is already up; this one was refused rather than queued.
    Busy,
}

/// The app's presence check, implemented in Swift and awaited from Rust.
///
/// `reason` is the whole sentence to show, built and sanitised by this crate from vault facts; the
/// implementation shows it as it is (for `LocalAuthentication`, as the `localizedReason`, which
/// the system renders after "“Kagisecure” is trying to").
///
/// The contract an implementation keeps (ADR-0038 §6, the same rules ADR-0037 states for fills):
/// a fresh check every call, with no reuse window; only a real, completed check answers
/// [`PresenceOutcome::Confirmed`]; a check that is cancelled, times out or is invalidated by a
/// lock never does; and a second call while one prompt is up answers [`PresenceOutcome::Busy`]
/// rather than waiting its turn.
///
/// `#[async_trait]` because `Arc<dyn PresenceGate>` needs the trait to be dyn-compatible, which a
/// native `async fn` in a trait is not on stable Rust (ADR-0038, "Spike result").
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PresenceGate: Send + Sync {
    /// Ask a person to prove they are present and meant `reason`.
    async fn confirm(&self, reason: String) -> PresenceOutcome;
}

/// Why the app is asking for a value — which decides the prompt's wording, the audit entry, and
/// what the release may do afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ReleasePurpose {
    /// Show the value in the detail pane (ui-spec §4.2). The release can be read again until it
    /// ends, and a copy of the shown value needs no new touch (user decision 1).
    Reveal,
    /// Copy the value without showing it. One use: a second copy is a second touch.
    Copy,
    /// Copy from Quick Access (⏎, ⌥⏎). One use.
    QuickAccessCopy,
    /// Show one concealed value inside the edit sheet, which never prefills (user decision 4).
    EditReveal,
}

impl ReleasePurpose {
    /// A copy is spent by its one use; a shown value stays readable until it ends.
    pub(crate) fn is_one_use(self) -> bool {
        matches!(self, Self::Copy | Self::QuickAccessCopy)
    }

    /// Whether the value this purpose released is on screen, so copying it again is the one
    /// exemption user decision 1 grants.
    pub(crate) fn shows_value(self) -> bool {
        matches!(self, Self::Reveal | Self::EditReveal)
    }
}

/// The monotonic clock releases and the password back-off are measured on.
///
/// Not part of the FFI surface: the app always runs on [`SystemClock`]. It exists so a test can
/// step past the five-minute cap without waiting five minutes
/// (`VaultSession::set_clock_for_testing`).
#[doc(hidden)]
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> Instant;
}

/// The real clock.
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The master-password fallback's answer ([`VaultSession::verify_master_password`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MasterPasswordCheck {
    /// The password is this vault's master password.
    Verified,
    /// It is not. The next attempt is refused for `retry_after_ms`, doubling with every
    /// consecutive failure up to five minutes.
    Wrong {
        /// Milliseconds until the next attempt will be checked.
        retry_after_ms: u64,
    },
    /// Not checked at all: an earlier failure's back-off has not run out, or another check is
    /// still running. Nothing was derived and nothing was compared.
    Throttled {
        /// Milliseconds until an attempt will be checked.
        retry_after_ms: u64,
    },
}

/// The audit entry a release in flight would write, kept so a lock can record it.
pub(crate) struct InFlightRelease {
    token: u64,
    draft: AuditDraft,
    /// The master-password fallback verified a password while this release waited.
    master_password_verified: bool,
}

/// What [`Presence::settle`] found.
pub(crate) enum Settled {
    /// A lock got there first; nothing may be released.
    Gone,
    /// Still registered — now taken out. `master_password` says whether the fallback verified the
    /// master password during its prompt.
    Current {
        /// See [`DETAIL_PRESENCE_CONFIRMED_MASTER_PASSWORD`].
        master_password: bool,
    },
}

#[derive(Default)]
struct Registry {
    /// Set by [`Presence::close_for_lock`]. Once set, nothing new is registered: the vault is on
    /// its way out, and a release that started now would only be refused a moment later.
    closed: bool,
    /// The one release awaiting its prompt, if any.
    current: Option<InFlightRelease>,
}

/// Why a release could not be registered.
pub(crate) enum RegisterRefusal {
    /// Another release is already awaiting its prompt.
    Busy,
    /// The vault is locking.
    Locked,
}

#[derive(Default)]
struct Backoff {
    failures: u32,
    not_before: Option<Instant>,
    checking: bool,
    /// A throttled attempt has been audited since the last real check.
    throttle_recorded: bool,
}

/// One refusal reason's throttle window ([`Presence::throttle_refusal`]).
struct RefusalWindow {
    opened_at: Instant,
    /// Refusals counted, not written, since the window opened.
    suppressed: u32,
    /// The first counted refusal's tool, item and labels, each kept for the entry that reports
    /// the window only while every counted refusal agreed on it.
    tool: Option<String>,
    item_id: Option<kagisecure_core::model::ItemId>,
    variables: Vec<String>,
    same_tool: bool,
    same_item: bool,
    same_variables: bool,
}

impl RefusalWindow {
    fn opened(at: Instant) -> Self {
        Self {
            opened_at: at,
            suppressed: 0,
            tool: None,
            item_id: None,
            variables: Vec::new(),
            same_tool: true,
            same_item: true,
            same_variables: true,
        }
    }

    fn count(&mut self, draft: AuditDraft) {
        if self.suppressed == 0 {
            self.tool = Some(draft.tool);
            self.item_id = draft.item_id;
            self.variables = draft.variables;
        } else {
            self.same_tool &= self.tool.as_deref() == Some(draft.tool.as_str());
            self.same_item &= self.item_id == draft.item_id;
            self.same_variables &= self.variables == draft.variables;
        }
        self.suppressed = self.suppressed.saturating_add(1);
    }

    /// The entry reporting what this window counted, if it counted anything.
    fn summary(&self, detail: &str) -> Option<AuditDraft> {
        if self.suppressed == 0 {
            return None;
        }
        Some(AuditDraft {
            actor: "app".to_owned(),
            tool: self
                .tool
                .clone()
                .filter(|_| self.same_tool)
                .unwrap_or_else(|| "release".to_owned()),
            item_id: self.item_id.filter(|_| self.same_item),
            variables: if self.same_variables {
                self.variables.clone()
            } else {
                Vec::new()
            },
            outcome: Outcome::Denied,
            detail: Some(format!(
                "{detail}{DETAIL_REPEATED_SUFFIX}{}",
                self.suppressed
            )),
            ..AuditDraft::default()
        })
    }
}

/// Why a master-password attempt was not checked.
pub(crate) struct Throttle {
    /// How long until an attempt will be checked.
    wait: Duration,
    /// The first throttled attempt since the last real check — the one that gets an audit entry.
    record: bool,
}

/// Per-session presence state. Shared (`Arc`) with every release in flight, so a release future
/// the caller abandons can still take itself out of the registry from its `Drop`.
pub(crate) struct Presence {
    gate: OnceLock<Arc<dyn PresenceGate>>,
    registry: Mutex<Registry>,
    next_token: AtomicU64,
    clock: RwLock<Arc<dyn Clock>>,
    backoff: Mutex<Backoff>,
    /// Per refusal reason (the audit `detail`), its throttle window.
    refusals: Mutex<Vec<(&'static str, RefusalWindow)>>,
}

impl Presence {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: OnceLock::new(),
            registry: Mutex::new(Registry::default()),
            next_token: AtomicU64::new(1),
            clock: RwLock::new(Arc::new(SystemClock)),
            backoff: Mutex::new(Backoff::default()),
            refusals: Mutex::new(Vec::new()),
        })
    }

    /// The audit entries to write for a release refused with `detail` — `draft` itself, or
    /// nothing at all.
    ///
    /// A refusal releases nothing and costs whoever caused it nothing, but its entry costs a
    /// rewrite of the whole vault file; written every time, anything that can click Show (or call
    /// `release_field` while a prompt is up) in a loop could rewrite the vault as fast as it can
    /// click — the same reasoning [`DETAIL_MASTER_PASSWORD_THROTTLED`] applies to wrong
    /// passwords. So the first refusal of each reason in a [`REFUSAL_AUDIT_WINDOW`] is written as
    /// it always was, and the rest of that window's refusals of the same reason are only counted.
    /// The count is not lost: it is written as one `<detail>_REPEATED:<n>` entry
    /// ([`DETAIL_REPEATED_SUFFIX`]) — ahead of the next refusal of any reason once its window has
    /// passed, ahead of the next grant ([`Presence::drain_refusal_counts`]), and at the lock, riding
    /// the final flush — so a burst is still visible as evidence, as one entry rather than
    /// thousands.
    pub(crate) fn throttle_refusal(
        &self,
        detail: &'static str,
        draft: AuditDraft,
    ) -> Vec<AuditDraft> {
        let now = self.now();
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = Vec::new();
        // Close every window that has run out, reporting what it counted.
        refusals.retain(|(reason, window)| {
            let open = now < window.opened_at + REFUSAL_AUDIT_WINDOW;
            if !open {
                out.extend(window.summary(reason));
            }
            open
        });
        match refusals.iter_mut().find(|(reason, _)| *reason == detail) {
            Some((_, window)) => window.count(draft),
            None => {
                refusals.push((detail, RefusalWindow::opened(now)));
                out.push(draft);
            }
        }
        out
    }

    /// Every refusal count not yet written, as entries, and a fresh start for every reason — for
    /// a grant (so the log shows the burst before the release it ended in) and for the lock.
    pub(crate) fn drain_refusal_counts(&self) -> Vec<AuditDraft> {
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        refusals
            .drain(..)
            .filter_map(|(reason, window)| window.summary(reason))
            .collect()
    }

    /// Install the gate. `false` if one was already installed: the first one stays.
    pub(crate) fn install(&self, gate: Arc<dyn PresenceGate>) -> bool {
        self.gate.set(gate).is_ok()
    }

    pub(crate) fn gate(&self) -> Option<Arc<dyn PresenceGate>> {
        self.gate.get().cloned()
    }

    pub(crate) fn now(&self) -> Instant {
        self.clock
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .now()
    }

    pub(crate) fn set_clock(&self, clock: Arc<dyn Clock>) {
        *self.clock.write().unwrap_or_else(PoisonError::into_inner) = clock;
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register a release that is about to await the gate, and return its token.
    ///
    /// **Lock order:** the caller already holds the vault handle's mutex — always handle first,
    /// then this registry, everywhere (here, [`Presence::settle`], [`Presence::abandon`],
    /// [`Presence::close_for_lock`]) — so a lock and a release can never wait on each other.
    pub(crate) fn register(&self, draft: AuditDraft) -> Result<u64, RegisterRefusal> {
        let mut registry = self.registry();
        if registry.closed {
            return Err(RegisterRefusal::Locked);
        }
        if registry.current.is_some() {
            return Err(RegisterRefusal::Busy);
        }
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        registry.current = Some(InFlightRelease {
            token,
            draft,
            master_password_verified: false,
        });
        Ok(token)
    }

    /// Take `token` out of the registry once its prompt has answered. [`Settled::Gone`] means a
    /// lock got there first: it has already recorded this release as `VAULT_LOCKED`, and the
    /// release must hand nothing out. Called with the vault handle's mutex held (see
    /// [`Presence::register`]).
    pub(crate) fn settle(&self, token: u64) -> Settled {
        let mut registry = self.registry();
        match registry.current.take_if(|c| c.token == token) {
            Some(current) => Settled::Current {
                master_password: current.master_password_verified,
            },
            None => Settled::Gone,
        }
    }

    /// The master-password fallback just verified the password: mark the release waiting on its
    /// prompt, if there is one, so it is recorded as granted by the master password. Takes only
    /// the registry (no handle mutex is held by the caller).
    fn note_master_password_verified(&self) {
        if let Some(current) = self.registry().current.as_mut() {
            current.master_password_verified = true;
        }
    }

    /// The item and label of the release waiting on its prompt, if any — so a failed
    /// master-password attempt can say what it was for.
    fn waiting_for(&self) -> Option<(Option<kagisecure_core::model::ItemId>, Vec<String>)> {
        self.registry()
            .current
            .as_ref()
            .map(|c| (c.draft.item_id, c.draft.variables.clone()))
    }

    /// A release future was dropped before its prompt answered — the caller cancelled the task.
    /// If it is still registered, take it out and queue a denial, so the log does not claim it is
    /// still waiting and a later lock does not record it as `VAULT_LOCKED`. Called with the vault
    /// handle's mutex held; `vault` is `None` once the vault is gone, and then there is nowhere
    /// left to record anything.
    pub(crate) fn abandon(&self, token: u64, vault: Option<&mut Vault>) {
        let mut registry = self.registry();
        let Some(current) = registry.current.take_if(|c| c.token == token) else {
            return;
        };
        drop(registry);
        if let Some(vault) = vault {
            vault.queue_audit(denied(current.draft, DETAIL_PRESENCE_CANCELLED));
        }
    }

    /// The vault is about to lock: refuse new releases, and record the one in flight, if any, as
    /// `VAULT_LOCKED` — queued on `vault` while it still exists, so the lock's own final flush
    /// writes it. Called with the vault handle's mutex held.
    pub(crate) fn close_for_lock(&self, vault: Option<&mut Vault>) {
        let mut registry = self.registry();
        registry.closed = true;
        let pending = registry.current.take();
        drop(registry);
        let counts = self.drain_refusal_counts();
        if let Some(vault) = vault {
            // Refusals counted but not yet written ride the lock's final flush too.
            for summary in counts {
                vault.queue_audit(summary);
            }
            if let Some(pending) = pending {
                vault.queue_audit(denied(pending.draft, DETAIL_VAULT_LOCKED));
            }
        }
    }

    /// Start a master-password check, or say how long until one may start.
    fn begin_password_check(&self) -> Result<(), Throttle> {
        let now = self.now();
        let mut backoff = self.backoff.lock().unwrap_or_else(PoisonError::into_inner);
        let wait = if backoff.checking {
            // A second attempt racing the first would dodge the back-off entirely: every one of a
            // burst would be checked before the first failure was counted.
            Some(Duration::from_secs(1))
        } else {
            backoff
                .not_before
                .filter(|not_before| now < *not_before)
                .map(|not_before| not_before - now)
        };
        if let Some(wait) = wait {
            let record = !backoff.throttle_recorded;
            backoff.throttle_recorded = true;
            return Err(Throttle { wait, record });
        }
        backoff.checking = true;
        Ok(())
    }

    /// Finish a master-password check, returning the back-off the next attempt now faces.
    fn end_password_check(&self, verified: Option<bool>) -> Duration {
        let now = self.now();
        let mut backoff = self.backoff.lock().unwrap_or_else(PoisonError::into_inner);
        backoff.checking = false;
        backoff.throttle_recorded = false;
        match verified {
            Some(true) => {
                backoff.failures = 0;
                backoff.not_before = None;
                Duration::ZERO
            }
            Some(false) => {
                backoff.failures = backoff.failures.saturating_add(1);
                let wait = password_backoff(backoff.failures);
                backoff.not_before = Some(now + wait);
                wait
            }
            // The check could not run (the vault locked, say): it neither counts nor resets.
            None => Duration::ZERO,
        }
    }
}

/// The wait after `failures` consecutive wrong master passwords: one second after the first,
/// doubling with each one after that, never more than [`MAX_PASSWORD_BACKOFF`].
pub(crate) fn password_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let doublings = (failures - 1).min(20);
    Duration::from_secs(1u64 << doublings).min(MAX_PASSWORD_BACKOFF)
}

/// `draft` as a refusal with `detail`.
pub(crate) fn denied(draft: AuditDraft, detail: &str) -> AuditDraft {
    AuditDraft {
        outcome: Outcome::Denied,
        detail: Some(detail.to_owned()),
        ..draft
    }
}

// MARK: - The prompt

/// What a release is for, as the prompt names it.
pub(crate) enum Subject<'a> {
    /// A concealed field: what kind of value it is, its label and its item's title.
    Field {
        /// What the field *is* ([`field_noun`]) — from facts a relabel cannot change.
        noun: &'static str,
        /// The item's title.
        title: &'a str,
        /// The field's label.
        label: &'a str,
    },
    /// An item's one-time code.
    Totp {
        /// The item's title.
        title: &'a str,
    },
    /// An item's notes.
    Notes {
        /// The item's title.
        title: &'a str,
    },
}

/// What a concealed field is, in the prompt's words, decided only by facts the edit sheet cannot
/// change without a presence check: the item's primary-secret designation (by field id,
/// `Item::primary_secret`) and the field's kind (which `save_item` refuses to change on a stored
/// secret without its value).
///
/// The label and the title are in the prompt too, but they are text anyone driving the UI can
/// rewrite for free: a PIN relabelled "password" is still announced as "the concealed field
/// “password”", not as "the password", so the one word the prompt vouches for cannot be forged.
pub(crate) fn field_noun(item: &Item, field: &Field) -> &'static str {
    match field.kind {
        FieldKind::Totp => "one-time password setup",
        FieldKind::CreditCardNumber => "card number",
        _ if item
            .primary_secret_field()
            .is_some_and(|p| p.id == field.id) =>
        {
            "password"
        }
        _ => "concealed field",
    }
}

/// The sentence the presence prompt shows. The system prefixes it with "“Kagisecure” is trying
/// to", so it starts with a verb.
///
/// It names what is about to be released and where it is going, and ends by telling the person
/// when to refuse: the sentence that stops an automation agent from getting a real person to touch
/// the sensor for it is the one that says exactly what is happening (ADR-0037, ADR-0038 §1). Every
/// run of vault text in it goes through [`sanitize`] first.
pub(crate) fn reason(subject: &Subject<'_>, purpose: ReleasePurpose) -> String {
    let verb = match purpose {
        ReleasePurpose::Reveal | ReleasePurpose::EditReveal => "show",
        ReleasePurpose::Copy | ReleasePurpose::QuickAccessCopy => "copy",
    };
    let (what, it) = match subject {
        Subject::Field { noun, title, label } => (
            format!("the {noun} “{}” of “{}”", sanitize(label), sanitize(title)),
            "it",
        ),
        Subject::Totp { title } => (format!("the one-time code for “{}”", sanitize(title)), "it"),
        Subject::Notes { title } => (format!("the notes of “{}”", sanitize(title)), "them"),
    };
    let context = match purpose {
        ReleasePurpose::EditReveal => format!(" to edit {it}"),
        ReleasePurpose::QuickAccessCopy => " from Quick Access".to_owned(),
        ReleasePurpose::Reveal | ReleasePurpose::Copy => String::new(),
    };
    format!("{verb} {what}{context}. Continue only if you just asked Kagisecure to {verb} {it}")
}

/// How much of one run of vault text the prompt will carry before cutting it.
const UNTRUSTED_RUN_LIMIT: usize = 64;

/// Sanitise one run of vault text — a title, a label — for the presence prompt.
///
/// The same four rules as the app's `ApprovalSheet.safe`, for the same reason: the vault supplies
/// the string (and an import, a shared file or a careless paste supplies the vault), while this
/// crate supplies the sentence around it.
///
/// * **Quoting.** Every quote glyph becomes `'`, so a title cannot close the prompt's own “…”
///   and carry on in the app's voice.
/// * **Direction.** Format characters — the bidi embeddings, overrides, isolates and marks, the
///   zero-width joiners and spaces, the tag characters — and private-use scalars are dropped, so
///   a title cannot reorder or hide the words around it.
/// * **Shape.** Control characters, line and paragraph separators and every run of whitespace
///   collapse to one space, so the sentence stays one line.
/// * **Length.** At most [`UNTRUSTED_RUN_LIMIT`] characters, cut with a visible `…`, so the verb
///   and the warning can never be pushed out of view.
pub(crate) fn sanitize(raw: &str) -> String {
    sanitize_to(raw, UNTRUSTED_RUN_LIMIT)
}

fn sanitize_to(raw: &str, limit: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(limit * 4));
    let mut pending_space = false;
    for c in raw.chars() {
        if is_quote(c) {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push('\'');
            continue;
        }
        if is_format(c) || is_private_use(c) {
            continue;
        }
        if c.is_control() || c == '\u{2028}' || c == '\u{2029}' || c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(c);
    }
    if out.is_empty() {
        return "unnamed".to_owned();
    }
    if out.chars().count() <= limit {
        return out;
    }
    let mut cut: String = out.chars().take(limit - 1).collect();
    cut.push('…');
    cut
}

/// The quote glyphs `ApprovalSheet.safe` neutralises, the same list.
fn is_quote(c: char) -> bool {
    matches!(
        c,
        '\u{0022}'
            | '\u{00AB}'
            | '\u{00BB}'
            | '\u{2018}'
            | '\u{2019}'
            | '\u{201A}'
            | '\u{201B}'
            | '\u{201C}'
            | '\u{201D}'
            | '\u{201E}'
            | '\u{201F}'
            | '\u{2033}'
            | '\u{2036}'
            | '\u{2039}'
            | '\u{203A}'
            | '\u{301D}'
            | '\u{301E}'
            | '\u{301F}'
            | '\u{FF02}'
    )
}

/// Unicode general category `Cf` (format), which is what Swift's `.format` matches: invisible
/// characters that change how the text around them is shown. The standard library has no
/// general-category lookup, so this is the table itself (Unicode 16).
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Unicode general category `Co` (private use).
fn is_private_use(c: char) -> bool {
    matches!(
        c,
        '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}'
    )
}

// MARK: - The session's side

#[uniffi::export]
impl VaultSession {
    /// Install the app's presence check. Once per session: a second call is refused and the first
    /// gate stays, so nothing that runs later can swap in a gate that always says yes.
    ///
    /// Until a gate is installed, every `release_*` call fails closed with
    /// [`FfiError::NoPresenceGate`].
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if a gate is already installed.
    pub fn set_presence_gate(&self, gate: Arc<dyn PresenceGate>) -> FfiResult<()> {
        if self.presence().install(gate) {
            Ok(())
        } else {
            Err(FfiError::invalid(
                "a presence check is already installed on this session",
            ))
        }
    }

    /// Check the vault's master password — the presence gate's fallback when
    /// `LocalAuthentication` cannot run at all (ADR-0038 user decision 7).
    ///
    /// Argon2id runs with no lock held: the header facts it needs are copied out first, and only
    /// the constant-time comparison of the unwrapped key against this session's happens under the
    /// vault's mutex again. So a check — deliberately slow — stalls neither the agent nor the
    /// list. Call it off the main thread for the same reason.
    ///
    /// Rate limited, per session: after a wrong password the next attempt is refused for one
    /// second, then two, four, … up to five minutes; a right one resets it. Attempts are also
    /// serialised — one running check makes every other attempt [`MasterPasswordCheck::Throttled`]
    /// — so a burst of attempts cannot all be checked before the first failure is counted.
    ///
    /// A right password while a release is waiting on its prompt marks that release, so its
    /// grant is audited `DETAIL_PRESENCE_CONFIRMED_MASTER_PASSWORD` rather than as a biometric.
    /// A wrong one is audited best-effort (`verify_master_password`, `denied`,
    /// `DETAIL_MASTER_PASSWORD_WRONG`, naming the item the waiting release is for), and so is
    /// the first throttled attempt of each back-off window
    /// (`DETAIL_MASTER_PASSWORD_THROTTLED`): a burst of guesses is exactly what an automation
    /// agent working through the app's own UI would leave, and never a reason to refuse the
    /// check itself.
    ///
    /// # Errors
    ///
    /// [`FfiError::VaultLocked`]; [`FfiError::NoSuchSlot`] if the vault has no master-password
    /// slot; KDF failures.
    pub fn verify_master_password(&self, password: String) -> FfiResult<MasterPasswordCheck> {
        let password = Zeroizing::new(password);
        let presence = self.presence();
        if let Err(throttle) = presence.begin_password_check() {
            if !self.is_unlocked() {
                return Err(FfiError::VaultLocked);
            }
            if throttle.record {
                self.record_password_attempt(&presence, DETAIL_MASTER_PASSWORD_THROTTLED);
            }
            return Ok(MasterPasswordCheck::Throttled {
                retry_after_ms: millis(throttle.wait),
            });
        }
        let verified = self.check_master_password(password.as_bytes());
        drop(password);
        let wait = presence.end_password_check(verified.as_ref().ok().copied());
        if verified? {
            presence.note_master_password_verified();
            Ok(MasterPasswordCheck::Verified)
        } else {
            self.record_password_attempt(&presence, DETAIL_MASTER_PASSWORD_WRONG);
            Ok(MasterPasswordCheck::Wrong {
                retry_after_ms: millis(wait),
            })
        }
    }
}

impl VaultSession {
    /// Replace the clock releases and the password back-off are measured on. For tests only: the
    /// app never calls it, and it is not part of the FFI surface.
    #[doc(hidden)]
    pub fn set_clock_for_testing(&self, clock: Arc<dyn Clock>) {
        self.presence().set_clock(clock);
    }

    /// Audit a master-password attempt that did not verify, best-effort, naming the release it
    /// was typed for if one is waiting.
    fn record_password_attempt(&self, presence: &Presence, detail: &str) {
        let (item_id, variables) = presence.waiting_for().unwrap_or_default();
        let draft = AuditDraft {
            actor: "app".to_owned(),
            tool: TOOL_VERIFY_MASTER_PASSWORD.to_owned(),
            item_id,
            variables,
            outcome: Outcome::Denied,
            detail: Some(detail.to_owned()),
            ..AuditDraft::default()
        };
        self.handle()
            .record_best_effort(crate::session::APP_LOCK_TIMEOUT, draft);
    }

    /// `Ok(true)` if `password` opens this session's vault key, `Ok(false)` if not.
    fn check_master_password(&self, password: &[u8]) -> FfiResult<bool> {
        // 1. Under the lock: copy out the public header material the derivation needs.
        let check = self.with_vault(|vault| vault.password_check())??;
        // 2. With no lock held: Argon2id, then the AEAD unwrap that proves the password.
        let key = match check.open(password) {
            Ok(key) => key,
            Err(kagisecure_core::Error::Decrypt) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        // 3. Under the lock again, briefly: is that this session's key? Constant time.
        self.with_vault(|vault| vault.holds_vault_key(&key))
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitising_drops_bidi_and_invisible_characters() {
        let hostile = "Git\u{202E}buH\u{2066}\u{200B}x\u{FEFF}";
        assert_eq!(sanitize(hostile), "GitbuHx");
    }

    #[test]
    fn sanitising_collapses_control_and_whitespace_runs() {
        assert_eq!(sanitize("  a\n\n\tb\u{2028}c\u{0007} "), "a b c");
    }

    #[test]
    fn sanitising_neutralises_quotes() {
        assert_eq!(sanitize("x” is safe. “y"), "x' is safe. 'y");
    }

    #[test]
    fn sanitising_bounds_the_length_and_names_the_empty() {
        let long = "a".repeat(200);
        let cut = sanitize(&long);
        assert_eq!(cut.chars().count(), UNTRUSTED_RUN_LIMIT);
        assert!(cut.ends_with('…'));
        assert_eq!(sanitize("\u{202E}\u{200B}"), "unnamed");
    }

    #[test]
    fn the_reason_names_the_thing_and_says_when_to_refuse() {
        let r = reason(
            &Subject::Field {
                noun: "password",
                title: "GitHub",
                label: "password",
            },
            ReleasePurpose::Copy,
        );
        assert_eq!(
            r,
            "copy the password “password” of “GitHub”. Continue only if you just asked \
             Kagisecure to copy it"
        );
        let r = reason(
            &Subject::Notes { title: "Bank" },
            ReleasePurpose::EditReveal,
        );
        assert_eq!(
            r,
            "show the notes of “Bank” to edit them. Continue only if you just asked Kagisecure \
             to show them"
        );
        let r = reason(
            &Subject::Totp { title: "AWS" },
            ReleasePurpose::QuickAccessCopy,
        );
        assert!(r.starts_with("copy the one-time code for “AWS” from Quick Access."));
    }

    /// The noun comes from the designation and the kind, never the label: relabelling a PIN
    /// "password" (or a card's CVV "number") does not change what the prompt calls it.
    #[test]
    fn the_noun_is_the_fields_kind_and_role_not_its_label() {
        use kagisecure_core::model::{Category, Secret, VaultId};

        let mut item = Item::new(VaultId::new(), Category::Login, "Bank");
        item.fields
            .push(Field::concealed("password", Secret::new(b"pw".to_vec())));
        item.fields
            .push(Field::concealed("PIN", Secret::new(b"4321".to_vec())));
        item.fields.push(Field::totp(
            "one-time password",
            Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec()),
        ));
        item.pin_primary_secret();
        let nouns = |item: &Item| -> Vec<&'static str> {
            item.fields.iter().map(|f| field_noun(item, f)).collect()
        };
        assert_eq!(
            nouns(&item),
            ["password", "concealed field", "one-time password setup"]
        );

        item.fields[1].label = "password".to_owned();
        item.fields[0].label = "PIN".to_owned();
        item.fields.swap(0, 1);
        assert_eq!(
            nouns(&item),
            ["concealed field", "password", "one-time password setup"],
            "the relabelled PIN is still a concealed field, the real password still the password"
        );

        let card = Item::from_template(VaultId::new(), Category::CreditCard, "Visa");
        let by_label = |label: &str| card.fields.iter().find(|f| f.label == label).unwrap();
        assert_eq!(field_noun(&card, by_label("number")), "card number");
        assert_eq!(field_noun(&card, by_label("CVV")), "concealed field");
    }

    #[test]
    fn the_backoff_doubles_and_is_capped() {
        assert_eq!(password_backoff(0), Duration::ZERO);
        assert_eq!(password_backoff(1), Duration::from_secs(1));
        assert_eq!(password_backoff(2), Duration::from_secs(2));
        assert_eq!(password_backoff(5), Duration::from_secs(16));
        assert_eq!(password_backoff(9), Duration::from_secs(256));
        assert_eq!(password_backoff(10), MAX_PASSWORD_BACKOFF);
        assert_eq!(password_backoff(u32::MAX), MAX_PASSWORD_BACKOFF);
    }
}

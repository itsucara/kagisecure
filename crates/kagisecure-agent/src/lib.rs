//! `kagisecure-agent` — everything the process that owns the unlocked vault does *for agents*.
//!
//! # Why this crate exists
//!
//! [architecture.md](../../../docs/architecture.md) §2.5 lists four jobs for the native app, and
//! §2.6 lists the same four for `kagisecure daemon` minus the UI. Until M4 those two lists were
//! implemented once, in `crates/kagisecure-cli/src/commands/daemon.rs`, which meant the macOS app
//! could only get them by reimplementing them in Swift — the layering bug architecture.md §2.5
//! calls out in as many words.
//!
//! So the logic moved here: the IPC listener, caller verification, the lease store, the audit
//! append, the `.env` writer and the process spawner. The app drives it over
//! `kagisecure-ffi`; `kagisecure daemon` drives it from a terminal loop. Both get the same
//! implementation, and neither owns a copy of it.
//!
//! # The shape that makes an app-hosted approval possible
//!
//! [ADR-0001](../../../docs/decisions/0001-rust-core-native-ui.md) and architecture.md §4.1 forbid
//! Rust calling up into Swift. An approval is exactly the call that would want to: "ask the human,
//! and tell me what they said." The way out is a **queue** instead of a callback:
//!
//! ```text
//!   sidecar → IPC thread ── submit ──▶ ApprovalQueue ◀── next_request ── UI thread (Swift)
//!                    ▲                     │                                   │
//!                    └──── Decision ───────┴────────────── resolve ────────────┘
//! ```
//!
//! # The second channel (M6)
//!
//! [`extension`] is the same shape for browsers: a second socket, a second protocol that
//! *deliberately* carries one value, and the **same** approval queue — so a fill approval is one
//! more sheet in the same loop rather than a parallel mechanism with its own timeout and its own
//! chance to get the biometric gate wrong. What it does not share is the lease store: a fill is
//! scoped to an origin and an item ([`fill_lease`]), never to a directory and a variable set.
//!
//! The IPC thread blocks on the queue for at most 60 seconds
//! ([`APPROVAL_TIMEOUT_SECONDS`]); the UI thread polls [`Agent::next_request`] and answers with
//! [`Agent::resolve`]. Every call across the FFI is therefore app → Rust and returns a value,
//! which is the only UniFFI shape this project is willing to build a security-critical path on.
//!
//! # What the queue may carry
//!
//! [`ApprovalRequest`] is metadata: client identity, pid, executable path, project directory,
//! environment name, **variable names**, the requested TTL and use count. It cannot carry a value
//! — the same rule the IPC protocol has, restated one layer up, and asserted by
//! `secret_markers_never_reach_the_approval_queue`.
//!
//! # Locking
//!
//! [`VaultHandle`] is the shared owner. The app (or the daemon) takes the vault out of it to lock;
//! that zeroizes the key on drop, and the handle's lock hook immediately kills every lease,
//! shreds every file written under one, and denies every approval still waiting for an answer.
//! There is no window in which a locked vault still serves an agent.

// `deny`, not `forbid`: `browser_setup`'s Windows registry module is `#[allow(unsafe_code)]` for
// the direct Win32 registry calls (`RegCreateKeyExW` et al.) native-messaging registration needs
// there, and `forbid` cannot be downgraded by an inner `#[allow]` anywhere in the crate, even in
// one module. Every other module is exactly as unsafe-free as it was.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod agent;
pub mod approval;
pub mod browser_setup;
pub mod bundle;
pub mod catalog;
mod children;
pub mod extension;
pub mod fill_lease;
pub mod release;
pub mod service;
pub mod setup;
pub mod shared;
pub mod test_login;
pub mod unattended;
pub mod vault;

pub use agent::{Agent, AgentConfig, AgentError, AgentStatus};
pub use approval::{
    APPROVAL_TIMEOUT_SECONDS, AgentFillFacts, ApprovalKind, ApprovalQueue, ApprovalRequest,
    ClientVerification, Decision, TestLoginFacts, TestLoginWebsite,
};
pub use extension::agent_fill::{
    AgentFillBlock, AgentFillBlockReason, AgentFillBroker, AgentFillClock, AgentFillNotice,
    AgentFillTimings,
};
pub use extension::{ExtensionAgent, ExtensionConfig, ExtensionError, ExtensionStatus, HostGate};
pub use fill_lease::{FillLease, FillLeaseStore};
/// Re-exported because it is now part of this crate's own surface:
/// [`AgentConfig::endpoint`] and [`ExtensionConfig::endpoint`] take one, so a host that names a
/// socket location has to be able to build one without depending on `kagisecure-ipc` directly.
pub use kagisecure_ipc::endpoint::{Endpoint, EndpointError};
pub use shared::{ReplicaSource, SharedAttachment, SharedSource};
pub use test_login::{TestLoginBroker, TestLoginNotice};
pub use unattended::browser::RunBrowserSetup;
pub use unattended::{
    Engine as UnattendedEngine, UnattendedConfig, UnattendedError, UnattendedNotice,
    UnattendedStatus,
};
pub use vault::VaultHandle;

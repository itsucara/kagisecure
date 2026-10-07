//! `kagisecure-shared` — shared vaults: a growing set of signed, encrypted records, exchanged by
//! the people who share them as plain files (ADR-0035, `docs/decisions/0035-shared-vaults.md`).
//!
//! # What lives here, and what does not yet
//!
//! This crate is where every part of a shared vault that is not the personal vault lives: device
//! keys' public halves and fingerprints, the HPKE wrap of an epoch key to a device, Ed25519
//! signatures over records, the record and bundle encodings, the roster and epoch state machines,
//! the local replica, and the merge, built against the ADR-0035 addendum's encoding
//! contract. What exists so far:
//!
//! - [`suite`]: the one suite, `x25519-ed25519-v1`.
//! - [`device`]: [`DevicePublic`] (strictly checked public keys), [`DeviceKeyId`],
//!   [`Fingerprint`], and [`DeviceSecret`], loaded from the personal vault's device key.
//! - [`sign`]: domain-separated Ed25519 signatures, verified strictly.
//! - [`epoch_key`]: [`EpochKey`], [`EpochId`] and record keys.
//! - [`hpke_wrap`]: wrapping an epoch key to a device with HPKE (RFC 9180), with randomness drawn
//!   from `kagisecure-core`'s generator.
//! - [`record`]: the signed record [`Envelope`], parsed within bounds before anything is decoded,
//!   its [`RecordBody`] and [`RecordId`].
//! - [`merge`]: one item or environment as a person sees it, merged from its accepted versions
//!   last-writer-wins per attribute, field and variable.
//! - [`payload`]: what item and environment records carry, [`ItemVersion`] and [`EnvVersion`],
//!   with this device's local-only settings kept out of both.
//! - [`bundle`]: a bundle file's magic, version and bounded record list — one shared vault's
//!   records as a single file, in a deterministic order that does not depend on how they were
//!   handed in.
//! - [`epoch`]: the epoch operations ([`EpochOp`]) and this device's [`KeyRing`]: which epoch
//!   keys it holds, and which epoch to write under.
//! - [`exchange`]: the `records/<64 hex>.ksr` exchange directory — export and a
//!   bounded import that quietly skips anything that is not exactly what its name claims.
//! - [`replica`]: this device's local copy of one shared vault — its records and its own
//!   settings, in one file authenticated by this device's key, written under a lock as the
//!   union of what is on disk and what the writer holds.
//! - [`write`]: putting and deleting items and environments as this device's next record.
//! - [`admin`]: creating a vault, inviting and joining a device, removing, changing roles,
//!   importing, exporting and syncing records, and this device's agent-visibility settings.
//! - [`rotation`]: what a removed device could read, for a person to act on.
//! - [`unattended`]: the vault's policy on unattended copies of its values, and which devices
//!   hold one (ADR-0042 §13).
//! - [`read`]: what this device's agents may be served from a shared vault — a snapshot of its
//!   items and environments with this device's settings applied, bindings resolved inside the
//!   vault, and which values changed since this device last approved releasing them.
//! - [`view`]: which item and environment versions one device reads from a record set: signed
//!   by a writer's or an admin's device at the roster heads they name, and decrypted.
//! - [`roster_op`]: the roster operations ([`RosterOp`]) and their encoding.
//! - [`roster`]: the roster computed from them ([`RosterState`]): members, devices and roles,
//!   in one order on every replica, with trusted admins.
//!
//! Everything this crate signs or hashes is deterministic CBOR, and anything else is refused on
//! reading (ADR-0035 addendum, decision 33).
//!
//! The device keys' secret halves are not here. They live in the personal vault's encrypted body
//! (`kagisecure_core::vault::DeviceKey`, ADR-0035 §5), so they are usable exactly while the
//! personal vault is unlocked, and this crate borrows them from an open vault when it signs or
//! unwraps.
//!
//! # Why this is a separate crate
//!
//! A shared vault's records arrive from other people's computers, through a git repository, a
//! sync folder or a USB stick: parsing them is parsing untrusted input, the situation ADR-0031 §1
//! resolved for import by giving it its own crate. It also brings the workspace's only
//! public-key cryptography (`hpke`, `ed25519-dalek`, and `x25519-dalek` and `curve25519-dalek`
//! beneath them). Keeping both here keeps them out of every consumer that does not share vaults,
//! and gives `cargo deny` and the dependency guard one subtree to point at.
//!
//! ```text
//! kagisecure-shared → kagisecure-core { features = ["secret-material"] }
//! ```
//!
//! # `kagisecure-mcp` and `kagisecure-ipc` must never depend on this crate
//!
//! This crate enables `secret-material` and decrypts shared records. An edge from the MCP sidecar,
//! the IPC layer, the extension channel or the native-messaging host to here would switch that
//! feature on for them through Cargo's feature unification, and hand an agent-facing process the
//! code that decrypts other people's values — without a line of their source changing (ADR-0002,
//! ADR-0035 §14). `tests/dependency_guard.rs` asserts the absence of that edge from inside this
//! crate, beside the code that would cause the problem.
//!
//! # No network code
//!
//! Shared vaults are exchanged by the users, as files; this crate reads and writes files at paths
//! a person chose and nothing else (ADR-0035 §7, architecture §9, threat-model N-9). The
//! dependency guard also asserts that nothing reachable from here is a network client, a socket
//! library or an async runtime, and `deny.toml` bans the network crates for the whole workspace.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod admin;
pub mod bundle;
mod cbor;
pub mod device;
pub mod epoch;
pub mod epoch_key;
pub mod error;
pub mod exchange;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod host_bundle;
pub mod hpke_wrap;
pub mod merge;
pub mod payload;
pub mod read;
pub mod record;
pub mod replica;
pub mod roster;
pub mod roster_op;
pub mod rotation;
pub mod sign;
pub mod suite;
pub mod unattended;
pub mod view;
pub mod write;

#[cfg(test)]
mod golden;
#[cfg(test)]
mod test_support;

pub use device::{DeviceKeyId, DevicePublic, DeviceSecret, Fingerprint};
pub use epoch::{EpochInfo, EpochOp, KeyRing};
pub use epoch_key::{EpochId, EpochKey, RecordKey};
pub use error::{Result, SharedError};
pub use hpke_wrap::{EpochWrap, unwrap_epoch_key, wrap_epoch_key};
pub use payload::{EnvVersion, ItemVersion};
pub use record::{Envelope, NewRecord, RecordBody, RecordId, RecordKind, VerifiedRecord};
pub use roster::{
    DeviceState, Ignored, MemberId, MemberState, Refusal, RemovalReason, Role, RosterOp,
    RosterSnapshot, RosterState, RosterWarning, Verification, Waiting,
};
pub use sign::{SigDomain, Signature, Signed};
pub use suite::Suite;

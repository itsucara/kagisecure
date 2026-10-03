//! Changing who is in a shared vault and moving its records between devices: creating a vault,
//! inviting a device and joining with it, removing one, changing a role, importing and
//! exporting records (ADR-0035 §7, §10, §11; addendum, decisions 81–87, under the trusted-admin
//! amendment), and which items and environments this device's agents may see ([`visibility`]).
//!
//! Every function here runs with the personal vault unlocked, on a person's own command, never
//! through the daemon or an agent (decision 29), and each writes in one replica transaction.
//! What an agent-facing process may reach of this crate never includes this module.

pub mod create;
pub mod enroll;
pub mod exchange;
pub mod remove;
pub mod visibility;

/// The longest vault name or device label, in characters (ADR-0035 addendum, limits).
pub const MAX_LABEL_CHARS: usize = 128;

/// Refuse a name or label longer than [`MAX_LABEL_CHARS`].
pub(crate) fn check_label(label: &str) -> crate::Result<()> {
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(crate::SharedError::LimitExceeded {
            what: "label characters",
            limit: MAX_LABEL_CHARS as u64,
        });
    }
    Ok(())
}

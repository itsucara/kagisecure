//! `kagisecure-extension-ipc` — the browser-extension channel.
//!
//! # Why this is not `kagisecure-ipc`
//!
//! [`kagisecure-ipc`](../kagisecure_ipc/index.html) exists to make a promise structural: its
//! protocol has **no message whose reply can carry a value**, and it cannot acquire one because
//! the crate cannot name `Secret` (ADR-0002). Autofill is the one feature that cannot be built on
//! that promise. A browser extension that fills a password field has to be handed the password.
//!
//! So this is a second, separate protocol, on a second, separate socket, with a **different wire
//! format**, and the difference is deliberate rather than incidental: a frame written for one
//! channel does not parse on the other (ADR-0019). Nothing here imports a lease type, an
//! environment type, or `write_env_file` — the extension is not an MCP client and must not be
//! able to become one by accident.
//!
//! # What may carry a value
//!
//! Exactly one field of exactly one message: [`protocol::Response::Filled`]'s `password`, plus
//! [`protocol::Response::TotpCode`]'s `code`, both typed [`protocol::FillValue`]. That type has
//! no `Display`, redacts itself in `Debug`, and zeroizes on drop. Everything else on the wire is
//! titles, usernames, origins, item ids and error codes.
//!
//! `kagisecure-core` is depended on with `proto` only, so this crate — and therefore
//! `kagisecure-nmhost`, which links it — cannot name `Secret`, cannot open a vault, and has no
//! type a vault key could occupy.
//!
//! # Shape
//!
//! * [`protocol`] — the messages, the error codes, and `FillValue`.
//! * [`nm`] — Chrome native-messaging framing: 4-byte **native-endian** length, then JSON.
//! * [`frame`] — the app-socket framing: 4-byte **big-endian** length, then JSON.
//! * [`origin`] — origin parsing and the eTLD+1 matching rule.
//! * [`endpoint`] — where the extension socket lives, beside the agent socket.
//! * [`client`] — the native host's half.
//! * [`listener`] — the app's half, plus what can be established about the host that connected.
//!
//! # Why `deny(unsafe_code)` and not `forbid`
//!
//! There is no `unsafe` in this crate at all; `deny` is used for symmetry with `kagisecure-ipc`,
//! whose peer-identification module this one borrows rather than duplicates.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod endpoint;
pub mod frame;
pub mod listener;
pub mod nm;
pub mod origin;
pub mod peer;
pub mod protocol;

pub use client::{Client, ClientError};
pub use endpoint::{EXTENSION_SOCKET_ENV, EXTENSION_SOCKET_FILE, extension_endpoint};
pub use listener::{HostConnection, Listener};
pub use origin::{MatchFailure, Origin, OriginError, item_match};
pub use peer::{
    HostIdentity, HostKind, KnownBrowser, SAFARI_EXTENSION_BUNDLE_ID, SAFARI_EXTENSION_EXECUTABLE,
};
pub use protocol::{
    ErrorCode, FillField, FillValue, MatchItem, PROTOCOL_VERSION, PageContext, Request, Response,
};

/// The Chrome native-messaging host name.
///
/// This is the string the extension passes to `chrome.runtime.connectNative`, and the file name
/// of the manifest each Chromium-family browser looks for in its `NativeMessagingHosts`
/// directory.
pub const NATIVE_HOST_NAME: &str = "com.kagisecure.nmhost";

/// The extension ids the app will serve.
///
/// The id is pinned by committing the extension's public `key` in its `manifest.json`, which
/// fixes the id whether the extension is loaded unpacked or installed from the Web Store
/// (ADR-0021). An extension that is not on this list is refused at `Hello` — it never reaches an
/// approval sheet, because the human has nothing useful to weigh about a stranger's extension id.
pub const PINNED_EXTENSION_IDS: &[&str] = &["nlijibjnmanccalmafnfbobkcfjiibmd"];

/// Whether `id` is an extension this app serves.
#[must_use]
pub fn is_pinned_extension(id: &str) -> bool {
    PINNED_EXTENSION_IDS.contains(&id)
}

/// Whether `id` is the Safari Web Extension this app ships.
///
/// A separate function from [`is_pinned_extension`] rather than one list with both in it, because
/// they are pinned by different means and must not be able to satisfy each other: a Chromium id is
/// pinned by a committed public key, and Safari's is a bundle identifier the app extension reports
/// about itself and the app corroborates with a code-signature check on the same process. A
/// Chromium extension claiming to be `com.kagisecure.app.safari-extension` reaches
/// [`is_pinned_extension`] and is refused (ADR-0024 §4).
#[must_use]
pub fn is_pinned_safari_extension(id: &str) -> bool {
    id == SAFARI_EXTENSION_BUNDLE_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_id_is_a_chrome_extension_id() {
        for id in PINNED_EXTENSION_IDS {
            assert_eq!(id.len(), 32, "{id}");
            assert!(
                id.bytes().all(|b| (b'a'..=b'p').contains(&b)),
                "a Chrome extension id is 32 characters from a..p: {id}"
            );
        }
    }

    #[test]
    fn a_stranger_is_not_pinned() {
        assert!(is_pinned_extension(PINNED_EXTENSION_IDS[0]));
        assert!(!is_pinned_extension("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_pinned_extension(""));
    }

    #[test]
    fn the_two_pins_do_not_satisfy_each_other() {
        assert!(is_pinned_safari_extension(SAFARI_EXTENSION_BUNDLE_ID));
        assert!(
            !is_pinned_extension(SAFARI_EXTENSION_BUNDLE_ID),
            "a Chromium extension must not be able to pass as the Safari one"
        );
        assert!(
            !is_pinned_safari_extension(PINNED_EXTENSION_IDS[0]),
            "and the Chromium id must not pass on the Safari socket"
        );
        assert!(!is_pinned_safari_extension(""));
    }
}

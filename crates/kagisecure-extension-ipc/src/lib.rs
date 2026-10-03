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
//! titles, usernames, origins, item ids, tab and document ids, which fields a page has, and error
//! codes.
//!
//! That stays true of agent-requested fills (ADR-0036). The app may now speak first, with a
//! [`protocol::Push`], but a push is a doorbell carrying two opaque ids and nothing else; the value
//! an approved agent fill releases goes back in the same `Filled` or `TotpCode` reply, to a
//! request the extension made, built by the same constructor as a human fill's.
//!
//! `kagisecure-core` is depended on with `proto` only, so this crate — and therefore
//! `kagisecure-nmhost`, which links it — cannot name `Secret`, cannot open a vault, and has no
//! type a vault key could occupy.
//!
//! # Shape
//!
//! * [`protocol`] — the messages, the error codes, and `FillValue`: requests, replies, and the
//!   app's value-free pushes.
//! * [`nm`] — Chrome native-messaging framing: 4-byte **native-endian** length, then JSON.
//! * [`frame`] — the app-socket framing: 4-byte **big-endian** length, then JSON.
//! * [`origin`] — origin parsing and the eTLD+1 matching rule, plus what the agent-fill sheet
//!   needs from it: which saved website covered a page, a look-alike-revealing rendering, and the
//!   extension's same-site rule for a two-page sign-in.
//! * [`endpoint`] — where the extension socket lives, beside the agent socket.
//! * [`client`] — the native host's half, lock-step or duplex (replies and pushes interleaved).
//! * [`listener`] — the app's half, plus what can be established about the host that connected,
//!   and a handle to push through.
//! * [`sever`] — ending a connected host's session from another thread, so that a stopped
//!   listener really releases its endpoint. A re-export of `kagisecure_ipc::sever`, which both
//!   channels now share.
//!
//! # `forbid(unsafe_code)`
//!
//! This crate used to be `deny` with one exception, `sever`'s `DisconnectNamedPipe`, and the
//! client's busy-pipe wait went through `interprocess`'s safe API. Both now live in
//! `kagisecure-ipc` (`sever`, and `connect`, which also opens the client end with
//! identification-only impersonation), shared by the two channels rather than written twice, so
//! nothing here needs `unsafe` and the lint is the one that cannot be overridden.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod endpoint;
pub mod frame;
pub mod listener;
pub mod nm;
pub mod origin;
pub mod peer;
pub mod protocol;
pub mod sever;

pub use client::{Client, ClientError, DuplexClient};
pub use endpoint::{EXTENSION_SOCKET_ENV, EXTENSION_SOCKET_FILE, extension_endpoint};
pub use listener::{HostConnection, Listener, PushSender};
pub use origin::{
    AgentOriginRendering, MatchFailure, Origin, OriginError, continues_same_site, covering_website,
    item_match,
};
pub use peer::{
    HostIdentity, HostKind, KnownBrowser, SAFARI_EXTENSION_BUNDLE_ID, SAFARI_EXTENSION_EXECUTABLE,
};
pub use protocol::{
    AgentFillFailure, AgentFillField, Capability, ErrorCode, FillField, FillValue, FoundFields,
    HostBound, MatchItem, PROTOCOL_VERSION, PageContext, Push, PushEnvelope, Request, Response,
    TabFacts,
};
pub use sever::Severer;

/// The Chrome native-messaging host name.
///
/// This is the string the extension passes to `chrome.runtime.connectNative`, and the file name
/// of the manifest each Chromium-family browser looks for in its `NativeMessagingHosts`
/// directory.
pub const NATIVE_HOST_NAME: &str = "com.kagisecure.nmhost";

/// The extension ids the app will serve.
///
/// The first is the id the committed public `key` in `extensions/shared/manifest.json` pins: the
/// one every unpacked load gets, on any machine, from any directory (ADR-0021). It stays first —
/// the setup screen shows `PINNED_EXTENSION_IDS[0]`, and a test in `extensions/chrome` checks it is
/// the id the committed key derives.
///
/// A Chrome Web Store install has a **different** id: the store refuses a new item whose manifest
/// carries a `key`, so the store package has none, and the store assigns the item's id at the first
/// upload (ADR-0021, amendment of 2026-10-03). Once that id is known it is added here, as a second
/// entry — and nowhere else: the native messaging manifests the setup screen writes take their
/// `allowed_origins` from this list. `docs/chrome-web-store.md` has the steps.
///
/// An extension that is not on this list is refused at `Hello` — it never reaches an approval
/// sheet, because the human has nothing useful to weigh about a stranger's extension id.
pub const PINNED_EXTENSION_IDS: &[&str] = &[
    // Unpacked, pinned by the committed `key` (ADR-0021). Keep first.
    "nlijibjnmanccalmafnfbobkcfjiibmd",
    // The Chrome Web Store item (assigned at the first upload, 2026-10-03).
    "aacppfmljihmjacphgpkbmanhbhphjgl",
];

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

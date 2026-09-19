//! `kagisecure-ipc` — the local IPC protocol between the MCP sidecar and the process that owns
//! the unlocked vault (architecture.md §4.2/§4.3).
//!
//! # The point of this crate
//!
//! The MCP schema in [mcp-server.md](../../../docs/mcp-server.md) says no tool returns a secret
//! value. This crate is where that stops being a promise about tool descriptions and becomes a
//! property of the program: **the protocol has no message whose reply carries a value**, and it
//! cannot acquire one, because `kagisecure-ipc` depends on `kagisecure-core` with
//! `default-features = false` and therefore cannot name `Secret` at all.
//!
//! Even if the sidecar were fully compromised, the process on the other end has nothing to send.
//!
//! # Shape
//!
//! * [`protocol`] — the message types and the stable error codes.
//! * [`frame`] — `u32` little-endian length prefix, UTF-8 JSON body, 1 MiB cap.
//! * [`endpoint`] — where the socket lives, `0600` in a `0700` directory.
//! * [`client`] — the sidecar's half. Blocking, one round trip per call.
//! * [`server`] — the daemon's half, plus what can be learned about a caller.
//! * [`kernel_peer`] — the one place this crate uses FFI: the peer pid straight from the kernel
//!   (macOS `LOCAL_PEERPID`, Linux `SO_PEERCRED`). Public since M6, so that
//!   `kagisecure-extension-ipc`'s listener identifies the native host the same way this crate
//!   identifies a sidecar, rather than growing a second copy of the same two syscalls.
//!
//! # Why `deny(unsafe_code)`, not `forbid`
//!
//! Every module here is safe Rust with one exception: `kernel_peer`, which needs `getsockopt`
//! FFI to get a caller's pid from the kernel on macOS (see ADR-0007 §3). `forbid` cannot be
//! locally overridden by a nested `allow` — that is the point of `forbid` — so getting a scoped
//! exception for one small, reviewed module means the crate-wide lint has to be `deny` instead.
//! `deny` is not weaker in practice: every module except `kernel_peer` is exactly as unsafe-free
//! as it would be under `forbid`, and `kernel_peer` states its own `#![allow(unsafe_code)]`
//! plainly at the top of the file rather than sneaking past the crate's setting.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod endpoint;
pub mod frame;
pub mod kernel_peer;
pub mod protocol;
pub mod server;

pub use client::{Client, ClientError};
pub use endpoint::{Endpoint, EndpointError};
pub use frame::FrameError;
pub use protocol::{ErrorCode, Request, Response};
pub use server::{Connection, PeerIdentity, Server};

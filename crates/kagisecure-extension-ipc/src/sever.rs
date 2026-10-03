//! Ending a connected native host's session from a thread that is not serving it.
//!
//! This lived here until the MCP agent's channel turned out to have the same stop/restart defect
//! the extension channel had: a stopped listener whose accepted connections stay open keeps its
//! Windows pipe name, and the next unlock's bind on it is refused. The implementation now lives
//! in [`kagisecure_ipc::sever`], below both channels, and is documented there in full; this module
//! re-exports it so the extension channel's paths (`kagisecure_extension_ipc::Severer`,
//! `kagisecure_extension_ipc::sever::Severer`) keep working.
//!
//! What it gives this crate is unchanged: [`crate::HostConnection::severer`] hands out a
//! [`Severer`] at accept time, and every handle a `HostConnection` holds is kept in a `Closing`,
//! so that dropping it closes the pipe instance there and then rather than in `interprocess`'s
//! linger thread.

pub use kagisecure_ipc::sever::Severer;

pub(crate) use kagisecure_ipc::sever::Closing;

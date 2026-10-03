//! Regression test: stopping the MCP agent must not silence the browser extension's lock hook.
//!
//! `Agent::stop()` used to call `VaultHandle::clear_lock_hook`, which emptied *every* hook
//! registered on the shared `VaultHandle` — the MCP agent's own primary and vault-needing hooks,
//! and also whatever the browser-extension listener had registered with `add_lock_hook`. So once
//! an MCP agent that shared a vault with a running extension listener stopped (the app quitting
//! its MCP side, or the agent being toggled off in settings), the *next* vault lock no longer
//! emptied the extension's fill-lease store — the exact thing a lock exists to guarantee (a fresh
//! presence check, and never a stale approval, at the next fill).
//!
//! The fix makes every hook individually removable (`kagisecure_agent::vault::LockHookGuard`):
//! each registration method hands back a token that deregisters only the entry it was issued for,
//! and `Agent::stop` now drops only the two guards it holds.
//!
//! This test starts both listeners on one vault — exactly the app's own arrangement, where one
//! `VaultHandle` is shared between the MCP agent and the extension listener — seeds a fill lease
//! directly into the extension's store (bypassing the wire protocol, which `sidecar.rs` and
//! `extension.rs` already exercise elsewhere), stops the MCP agent, and then locks through the
//! same handle both listeners share, the way `kagisecure lock` and the app's ⌘\ both do.

use std::sync::Arc;

use kagisecure_agent::approval::ApprovalQueue;
use kagisecure_agent::{
    Agent, AgentConfig, Endpoint, ExtensionAgent, ExtensionConfig, VaultHandle,
};
use kagisecure_core::vault::{CreateOptions, Vault};

#[test]
fn stopping_the_mcp_agent_does_not_silence_the_extensions_lock_hook() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");

    // Deliberately cheap KDF parameters: this vault exists for a second and protects nothing.
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    let (vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");
    let handle = VaultHandle::new(vault);

    let mut agent = Agent::start(
        Arc::clone(&handle),
        &AgentConfig {
            endpoint: Some(Endpoint::for_instance(dir.path(), "agent.sock")),
            queue: None,
            agent_fill: None,
        },
    )
    .expect("the mcp agent starts");

    let extension = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            endpoint: Some(Endpoint::for_instance(dir.path(), "extension.sock")),
            allow_unlaunched_host: true,
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("the extension listener starts");

    extension.grant_fill_lease_for_test("https://example.com", "item-a", "Example");
    assert_eq!(
        extension.fill_leases().len(),
        1,
        "the seeded lease should be live before anything stops or locks"
    );

    // Stop the MCP agent. This used to call `VaultHandle::clear_lock_hook`, which reached past its
    // own two hooks and cleared the extension's as well.
    agent.stop();

    // Lock through the same `VaultHandle` both listeners share — what `kagisecure lock` and the
    // app's ⌘\ both eventually call.
    drop(handle.take());

    assert!(!handle.is_unlocked());
    assert!(
        extension.fill_leases().is_empty(),
        "the extension's lock hook must still run, and its lease store must still be emptied, \
         after the mcp agent has already stopped"
    );
}

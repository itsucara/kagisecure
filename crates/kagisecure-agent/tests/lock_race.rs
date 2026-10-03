//! "Locking must mean locking" in the gap between the agent being told to lock and the host
//! actually taking the vault.
//!
//! `kagisecure lock` sets a flag the host polls with `Agent::take_lock_request`, then the host
//! takes the vault. `take_lock_request` used to *clear* the flag as it reported it — so between
//! that poll and the host's `take`, the vault was still in the handle and the flag was down, and
//! the agent went back to serving requests after it had already answered `Locked`.

mod common;

use common::{error_code, fixture};
use kagisecure_ipc::protocol::{Request, Response};

#[test]
fn nothing_is_served_between_the_hosts_poll_and_its_take() {
    let fx = fixture();
    let mut client = fx.client("lock-race");

    assert!(matches!(
        client.call(&Request::Lock).expect("call"),
        Response::Locked
    ));
    // The host notices…
    assert!(fx.agent.take_lock_request());
    // …and before it gets round to taking the vault, another request arrives.
    let reply = client.call(&Request::ListVaults).expect("call");
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("VAULT_LOCKED"),
        "a lock that has been acknowledged must hold while the host catches up: {reply:?}"
    );
    // The host is told once, not on every poll.
    assert!(!fx.agent.take_lock_request());

    drop(fx.handle.take());
    let reply = client.call(&Request::ListVaults).expect("call");
    assert_eq!(error_code(&reply).as_deref(), Some("VAULT_LOCKED"));
}

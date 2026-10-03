//! A stopped agent serves nothing — not even the one request a connection was already waiting for.
//!
//! `serve_connection` checked `stopping` only before it blocked reading the next request. A
//! connection idle at the moment of `Agent::stop()` therefore served the very next request that
//! arrived — against a lease store the stop had already emptied and would never empty again, with
//! lock hooks already retired, and (in the app, whose approval queue is shared with the next agent)
//! with a sheet a fresh agent's UI would answer.

mod common;

use common::fixture;
use kagisecure_ipc::protocol::{Request, Response};

#[test]
fn a_connection_idle_across_a_stop_is_not_served_afterwards() {
    let mut fx = fixture();
    let mut client = fx.client("stop-serving");
    // The connection is live and its thread is parked reading the next request.
    assert!(matches!(
        client.call(&Request::ListVaults).expect("call"),
        Response::Vaults { .. }
    ));

    fx.agent.stop();

    // Closed without an answer, or answered with a refusal: either way nothing was served.
    let reply = client.call(&Request::ListVaults);
    assert!(
        !matches!(reply, Ok(Response::Vaults { .. })),
        "a stopped agent answered a request as though it were still running"
    );
}

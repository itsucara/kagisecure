//! The MCP agent stopping and starting again on the same endpoint with a sidecar still connected.
//!
//! The app calls `agent_stop` on every vault lock and `agent_start` on the next unlock, on the
//! same endpoint. A sidecar that connected before the lock and is idle — which is where a
//! connection spends nearly all of its life — leaves the agent's serving thread parked in a read.
//! The extension channel had exactly this shape and hung for 39 minutes on Windows
//! (`the_native_host_survives_the_app_going_away_and_coming_back` in `tests/extension.rs`): a
//! named pipe's name lives for as long as any server-side instance is open, so the parked
//! connection kept the name, the restart's bind was refused, and the bind-error classifier then
//! waited without bound to connect to a name whose only instance was busy.
//!
//! This is the same scenario on the MCP channel. It is run under a hard deadline so that a
//! regression fails the test instead of hanging the suite.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use kagisecure_agent::{Agent, AgentConfig};
use kagisecure_ipc::client::Client;
use kagisecure_ipc::protocol::{Request, Response};

/// Far beyond anything the scenario needs when it works (well under a second), and far short of
/// "the suite is hung".
const DEADLINE: Duration = Duration::from_secs(60);

/// What a restart may take. Generous against a loaded machine; the failure this guards against is
/// either an unbounded wait or a refused bind, not a slow one.
const RESTART_BOUND: Duration = Duration::from_secs(10);

/// Run `body` on its own thread and fail — rather than hang — if it has not finished by
/// [`DEADLINE`]. A thread still stuck at the deadline is left behind; the test binary exits
/// without it.
fn with_deadline(body: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        body();
        let _ = done.send(());
    });
    match finished.recv_timeout(DEADLINE) {
        Ok(()) => thread.join().expect("the body finished"),
        // The body panicked and dropped the sender: re-raise its panic, message and all.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            if let Err(panic) = thread.join() {
                std::panic::resume_unwind(panic);
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
            "stopping and restarting the agent with a sidecar connected did not finish within \
             {DEADLINE:?}: the restart is waiting on the connection the stop left open"
        ),
    }
}

#[test]
fn a_connected_sidecar_does_not_keep_a_stopped_agent_from_coming_back() {
    with_deadline(|| {
        let common::Fixture {
            dir: _dir,
            handle,
            mut agent,
            endpoint,
            ..
        } = common::fixture();

        // A sidecar connects, completes the handshake and one call, and goes idle. The agent's
        // thread for it is now parked in a read, waiting for the next request.
        let mut before =
            Client::connect(&endpoint, common::client_info("before-lock")).expect("connect");
        assert!(matches!(
            before
                .call(&Request::ListVaults)
                .expect("a call before the lock"),
            Response::Vaults { .. }
        ));

        // Lock: the app stops the agent.
        let stopping = Instant::now();
        agent.stop();
        let stopped_in = stopping.elapsed();
        drop(agent);

        // Unlock: the app starts it again on the same endpoint.
        let starting = Instant::now();
        let restarted = Agent::start(
            Arc::clone(&handle),
            &AgentConfig {
                endpoint: Some(endpoint.clone()),
                queue: None,
                agent_fill: None,
            },
        );
        let started_in = starting.elapsed();
        let restarted = restarted.unwrap_or_else(|e| {
            panic!(
                "the restart was refused after {started_in:?}, so the stop left the endpoint \
                 taken: {e}"
            )
        });
        assert!(
            started_in < RESTART_BOUND,
            "the restart took {started_in:?} against a {RESTART_BOUND:?} bound"
        );
        eprintln!("stop took {stopped_in:?}, restart took {started_in:?}");

        // The old connection belongs to the agent that stopped. It must not be served by it — a
        // stopped agent answering requests over a socket it has given up is exactly the stale
        // session this is about — so the sidecar's next call on it fails, and the sidecar does
        // what it does for every tool call anyway: connects again.
        assert!(
            before.call(&Request::ListVaults).is_err(),
            "a connection accepted before the stop must not be served after it"
        );
        drop(before);

        let mut after =
            Client::connect(&endpoint, common::client_info("after-unlock")).expect("reconnect");
        assert!(matches!(
            after
                .call(&Request::ListVaults)
                .expect("a call after the unlock"),
            Response::Vaults { .. }
        ));
        drop(after);
        drop(restarted);
    });
}

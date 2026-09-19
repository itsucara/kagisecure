//! `revoke_env_file` against a lease that is not there.
//!
//! This exists to hold a decision still. `docs/mcp-server.md` §7 used to list a `LEASE_EXPIRED`
//! code that nothing in the workspace ever constructed, and the obvious place to wire it up is
//! right here: a caller names a lease, the lease is gone, surely that is what the code is for.
//!
//! It is not. Revoking is cleanup. An agent that finishes a task, deletes the `.env` it was given,
//! and then — because a retry, a restart, or a second tool call — asks again must get the same
//! answer: the access is gone, which is what it wanted. `LEASE_EXPIRED` tells the model to
//! "request a fresh injection", and handing that instruction to an agent that has just finished
//! tidying up is the opposite of what should happen.
//!
//! So the code was removed from the table instead, and these two scenarios are why.

use std::sync::Arc;

use kagisecure_agent::{Agent, AgentConfig, VaultHandle};
use kagisecure_core::proto::LeaseId;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_ipc::client::Client;
use kagisecure_ipc::endpoint::Endpoint;
use kagisecure_ipc::protocol::{Request, Response};

struct Fixture {
    dir: tempfile::TempDir,
    _handle: Arc<VaultHandle>,
    _agent: Agent,
    endpoint: Endpoint,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");

    // Deliberately cheap KDF parameters: this vault exists for a second and protects nothing.
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(8, 1, 1).expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");

    let socket = dir.path().join("agent.sock");
    let handle = VaultHandle::new(vault);
    let agent = Agent::start(
        Arc::clone(&handle),
        &AgentConfig {
            socket_path: Some(socket.clone()),
            queue: None,
        },
    )
    .expect("the agent should bind a fresh socket");

    Fixture {
        dir,
        _handle: handle,
        _agent: agent,
        endpoint: Endpoint::Path(socket),
    }
}

fn connect(fixture: &Fixture) -> Client {
    Client::connect(
        &fixture.endpoint,
        kagisecure_ipc::client::self_info("kagisecure-revoke-test", "0.0.0"),
    )
    .expect("the client should reach the agent")
}

#[test]
fn revoking_a_lease_that_is_gone_is_a_successful_no_op() {
    let fixture = fixture();
    let mut client = connect(&fixture);

    let response = client
        .call(&Request::RevokeEnvFile {
            // A well-formed id that was never granted. Indistinguishable, from inside the lease
            // store, from one that expired ten seconds ago or was revoked a moment before — and
            // all three deserve the same answer.
            lease_id: Some(LeaseId::new()),
            path: None,
        })
        .expect("the call itself should succeed");

    match response {
        Response::Revoked { shredded } => assert!(
            shredded.is_empty(),
            "nothing was written under a lease that never existed"
        ),
        other => {
            panic!("revoking is cleanup and must not fail — see this file's header. Got {other:?}")
        }
    }
}

#[test]
fn a_stale_lease_id_alongside_a_path_still_shreds_the_path() {
    let fixture = fixture();
    let mut client = connect(&fixture);

    // The path is actionable on its own — the file is right there — so an unrecognised lease id
    // beside it must not stop the shred.
    let env_file = fixture.dir.path().join(".env");
    std::fs::write(&env_file, b"TOKEN=whatever\n").expect("write");

    let response = client
        .call(&Request::RevokeEnvFile {
            lease_id: Some(LeaseId::new()),
            path: Some(env_file.display().to_string()),
        })
        .expect("the call itself should succeed");

    match response {
        Response::Revoked { shredded } => {
            assert_eq!(
                shredded,
                vec![env_file.display().to_string()],
                "the file named by `path` should have been shredded"
            );
            assert!(!env_file.exists(), "the file should be gone");
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

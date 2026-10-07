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
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");

    let endpoint = Endpoint::for_instance(dir.path(), "agent.sock");
    let handle = VaultHandle::new(vault);
    let agent = Agent::start(
        Arc::clone(&handle),
        &AgentConfig {
            endpoint: Some(endpoint.clone()),
            queue: None,
            agent_fill: None,
            test_logins: None,
        },
    )
    .expect("the agent should bind a fresh socket");

    Fixture {
        dir,
        _handle: handle,
        _agent: agent,
        endpoint,
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

/// REPLACED: this test used to assert that a path named beside a stale lease id is shredded
/// whether or not kagisecure ever wrote it — which is the defect below, recorded as behaviour.
/// What survives of it is the part that is still true: a stale lease id does not stop anything,
/// and the call still succeeds.
///
/// The positive half — a file kagisecure *did* write is still shredded by path, even after the
/// lease that wrote it has gone — is asserted in `tests/adversarial_lease.rs`, which has the
/// approval-UI fixture this file deliberately does not.
#[test]
fn a_stale_lease_id_beside_a_path_is_still_a_successful_no_op() {
    let fixture = fixture();
    let mut client = connect(&fixture);

    let env_file = fixture.dir.path().join(".env");
    std::fs::write(&env_file, b"TOKEN=whatever\n").expect("write");

    let response = client
        .call(&Request::RevokeEnvFile {
            lease_id: Some(LeaseId::new()),
            path: Some(env_file.display().to_string()),
        })
        .expect("the call itself should succeed");

    match response {
        Response::Revoked { shredded } => assert!(
            shredded.is_empty(),
            "this agent never wrote {env_file:?}, so it may not destroy it"
        ),
        other => panic!("revoking is cleanup and must not fail. Got {other:?}"),
    }
    assert!(
        env_file.exists(),
        "a file this agent never wrote survives, whatever it is called"
    );
}

/// `revoke_env_file` must not be an unauthenticated delete-any-file primitive.
///
/// `Service::revoke` opens with "Revoking access is always allowed: there is no approval", which
/// is the right rule for giving access *back*. But the `path` arm does not restrict itself to
/// paths this process wrote:
///
/// ```text
/// targets.extend(leases.revoke_by_path(&candidate));
/// if !targets.contains(&candidate) {
///     targets.push(candidate);          // unconditional
/// }
/// ```
///
/// and `envfile::shred` then zeroes and unlinks any regular file it is handed. So any caller that
/// can reach the socket — which, on the shipped design, is any process running as the user — can
/// name an arbitrary path and have the process holding the unlocked vault destroy it, with no
/// approval sheet, no lease, and no relationship to anything kagisecure ever wrote.
///
/// The canary here is deliberately not a `.env`: it is a file with no connection to this product
/// at all, which is the whole point.
#[test]
// FIXED: `Service::revoke` now shreds only paths in `LeaseStore`'s written ledger; an unknown
// path drops any lease, leaves the file alone, and records PATH_NOT_WRITTEN_BY_KAGISECURE.
// UNVERIFIED — this machine cannot run test binaries.
fn revoking_a_path_this_agent_never_wrote_shreds_nothing() {
    let fixture = fixture();
    let mut client = connect(&fixture);

    const BYSTANDER_CONTENTS: &str = "an important file that kagisecure never touched\n";
    let bystander = fixture.dir.path().join("notes.txt");
    std::fs::write(&bystander, BYSTANDER_CONTENTS).expect("write the bystander file");

    let response = client
        .call(&Request::RevokeEnvFile {
            lease_id: None,
            path: Some(bystander.display().to_string()),
        })
        .expect("the call itself should succeed");

    match response {
        Response::Revoked { shredded } => assert!(
            shredded.is_empty(),
            "the agent shredded {shredded:?}, which no lease of its ever wrote"
        ),
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(&bystander).unwrap_or_default(),
        BYSTANDER_CONTENTS,
        "a file the agent never wrote must survive a revoke that names it"
    );
}

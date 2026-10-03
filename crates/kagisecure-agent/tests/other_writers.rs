//! The vault file has more than one writer: the process serving the agent, and the CLI beside it.
//!
//! Each test here plays the CLI with a second, independently opened [`Vault`] on the same file —
//! a second process in every respect that matters, since nothing is shared with the agent's copy
//! but the path — and checks what the agent does about a change it did not make:
//!
//! * a visibility change made elsewhere applies to the agent's **next** request, and the agent's
//!   own later writes do not undo it;
//! * the agent's writes never drop what another writer committed;
//! * a file that went backwards (an older copy restored while the vault was unlocked) is refused,
//!   never overwritten, and everything works again once it is put right.
//!
//! Everything runs over the real socket with the real IPC client, as in the adversarial suite.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{
    Fixture, REAL_DOTENV, allow_session, error_code, fixture, with_ui, with_ui_answering,
    write_env_file,
};
use kagisecure_agent::approval::Decision;
use kagisecure_agent::{ExtensionAgent, ExtensionConfig};
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::{Category, Outcome};
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{Request, Response, VariableRequest};

fn vault_path(fx: &Fixture) -> PathBuf {
    fx.dir.path().join("test.kagivault")
}

/// A second writer on the same file, opened the way the CLI opens it.
fn other_process(path: &Path) -> Vault {
    Vault::open_with_password(path, b"pw").expect("a second process opens the vault")
}

/// What `kagisecure env agent-access --environment <id> --deny` does, from another process.
fn deny_environment_elsewhere(path: &Path, env_id: &str) {
    other_process(path)
        .transact(|tx| {
            tx.find_environment_mut(env_id)?.agent_visible = false;
            tx.append_audit(AuditDraft {
                actor: "cli".to_owned(),
                tool: "env agent-access".to_owned(),
                outcome: Outcome::Allowed,
                ..AuditDraft::default()
            });
            Ok(())
        })
        .expect("the other process commits");
}

/// The environment as the file on disk holds it now, read by a third party.
fn visible_on_disk(path: &Path, env_id: &str) -> bool {
    other_process(path)
        .find_environment(env_id)
        .expect("the environment is still there")
        .agent_visible
}

fn tools_on_disk(path: &Path) -> Vec<String> {
    let vault = other_process(path);
    vault.verify_audit().expect("the chain verifies");
    vault
        .audit_entries()
        .iter()
        .map(|e| e.tool.clone())
        .collect()
}

fn list_environments(fx: &Fixture) -> Response {
    fx.client("other-writers")
        .call(&Request::ListEnvironments { vault_id: None })
        .expect("call")
}

fn environment_ids(reply: &Response) -> Vec<String> {
    match reply {
        Response::Environments { environments } => {
            environments.iter().map(|e| e.id.to_string()).collect()
        }
        other => panic!("expected environments, got {other:?}"),
    }
}

#[test]
fn agent_access_denied_from_another_process_hides_the_environment_on_the_next_request() {
    let fx = fixture();
    let path = vault_path(&fx);
    assert_eq!(
        environment_ids(&list_environments(&fx)),
        vec![fx.env_id.clone()]
    );

    deny_environment_elsewhere(&path, &fx.env_id);

    // The very next request, with nothing in between to prompt a re-read.
    assert!(
        environment_ids(&list_environments(&fx)).is_empty(),
        "the environment the user just hid must not be listed"
    );

    // The agent writes after that — this call's own audit entry was one such write — and none
    // of its writes may put its older copy of the flag back.
    let _ = fx
        .client("other-writers")
        .call(&Request::ListVaults)
        .expect("call");
    assert!(
        !visible_on_disk(&path, &fx.env_id),
        "the agent's own writes reverted a change another process made"
    );
    let tools = tools_on_disk(&path);
    assert!(tools.contains(&"env agent-access".to_owned()), "{tools:?}");
    assert_eq!(
        tools.iter().filter(|t| *t == "list_environments").count(),
        2,
        "both list calls are on disk: {tools:?}"
    );
}

#[test]
fn a_lease_granted_before_the_environment_was_hidden_does_not_outlast_it() {
    let fx = fixture();
    let path = vault_path(&fx);
    let dir = fx.canonical_project().display().to_string();

    let target = fx.canonical_project().join(REAL_DOTENV);

    // The human approves "for this session": a live, multi-use lease on this file.
    let (first, _) = with_ui(&fx.agent, allow_session(900, 5), || {
        fx.client("other-writers")
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert!(matches!(first, Response::WroteEnvFile { .. }), "{first:?}");
    std::fs::remove_file(&target).expect("the agent's first file");
    assert_eq!(
        fx.agent.leases().len(),
        1,
        "a live lease covers the next write"
    );

    deny_environment_elsewhere(&path, &fx.env_id);

    let (second, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("other-writers")
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert_eq!(
        error_code(&second).as_deref(),
        Some("NOT_FOUND"),
        "{second:?}"
    );
    assert!(
        seen.is_empty(),
        "a hidden environment is never put to the human"
    );
    assert!(
        !target.exists(),
        "the lease released a value of an environment the user has since hidden"
    );
}

#[test]
fn an_environment_hidden_while_the_sheet_is_up_is_not_released() {
    let fx = fixture();
    let path = vault_path(&fx);
    let dir = fx.canonical_project().display().to_string();
    let env_id = fx.env_id.clone();
    let hide_path = path.clone();

    // The human hides the environment from a terminal while the sheet is still up, then —
    // distracted — presses Allow anyway.
    let (reply, seen) = with_ui_answering(
        &fx.agent,
        move |_| {
            deny_environment_elsewhere(&hide_path, &env_id);
            Some(allow_session(900, 5))
        },
        || {
            fx.client("other-writers")
                .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
                .expect("call")
        },
    );
    assert_eq!(seen.len(), 1);
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("NOT_FOUND"),
        "{reply:?}"
    );
    assert!(
        !fx.canonical_project().join(REAL_DOTENV).exists(),
        "the value was released after its environment was hidden"
    );
    assert!(
        fx.agent.leases().is_empty(),
        "the lease minted by that approval must not survive the refusal"
    );
}

#[test]
fn variables_are_not_added_to_an_environment_hidden_while_the_sheet_is_up() {
    let fx = fixture();
    let path = vault_path(&fx);
    let env_id = fx.env_id.clone();
    let hide_path = path.clone();

    let (reply, seen) = with_ui_answering(
        &fx.agent,
        move |_| {
            deny_environment_elsewhere(&hide_path, &env_id);
            Some(Decision::AllowOnce)
        },
        || {
            fx.client("other-writers")
                .call(&Request::AddVariables {
                    environment_id: fx.env_id.parse().expect("env id"),
                    variables: vec![VariableRequest {
                        name: "ADDED_LATE".to_owned(),
                        hint: None,
                        bind_to: None,
                    }],
                })
                .expect("call")
        },
    );
    assert_eq!(seen.len(), 1);
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("NOT_FOUND"),
        "{reply:?}"
    );
    let on_disk = other_process(&path);
    let env = on_disk.find_environment(&fx.env_id).expect("env");
    assert!(!env.agent_visible, "the other process's change stands");
    assert!(
        env.var("ADDED_LATE").is_none(),
        "the change was applied anyway"
    );
}

#[test]
fn an_item_another_process_adds_survives_the_agents_next_write_and_is_served() {
    let fx = fixture();
    let path = vault_path(&fx);

    let mut elsewhere = other_process(&path);
    let item_id = elsewhere
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            let mut item = Item::new(vault_id, Category::ApiCredential, "Added by the CLI");
            item.fields.push(Field::concealed(
                "token",
                Secret::from_string("elsewhere".to_owned()),
            ));
            item.agent_visible = true;
            let id = item.id.to_string();
            tx.add_item(item);
            Ok(id)
        })
        .expect("the other process commits");

    // The agent's next request serves the new item — and writes its own audit entry.
    let reply = fx
        .client("other-writers")
        .call(&Request::ListItems {
            vault_id: None,
            query: None,
            category: None,
            limit: 50,
            cursor: None,
        })
        .expect("call");
    let Response::Items { items, .. } = reply else {
        panic!("expected items, got {reply:?}");
    };
    assert!(
        items.iter().any(|i| i.id.to_string() == item_id),
        "an item another process added is served on the next request"
    );

    let on_disk = other_process(&path);
    assert!(
        on_disk.find_item(&item_id).is_ok(),
        "the agent's audit write dropped an item another process committed"
    );
    assert!(tools_on_disk(&path).contains(&"list_items".to_owned()));

    // And the other way round: the agent writes, then the other process writes on top.
    let _ = fx
        .client("other-writers")
        .call(&Request::ListVaults)
        .expect("call");
    elsewhere
        .transact(|tx| {
            tx.append_audit(AuditDraft {
                actor: "cli".to_owned(),
                tool: "item show".to_owned(),
                outcome: Outcome::Allowed,
                ..AuditDraft::default()
            });
            Ok(())
        })
        .expect("the other process commits on top of the agent's write");
    let tools = tools_on_disk(&path);
    let agent_entry = tools.iter().position(|t| t == "list_vaults");
    let cli_entry = tools.iter().position(|t| t == "item show");
    assert!(
        agent_entry.is_some() && agent_entry < cli_entry,
        "both writers' entries, in order: {tools:?}"
    );
}

#[test]
fn a_vault_file_restored_from_an_older_copy_is_refused_and_never_overwritten() {
    let fx = fixture();
    let path = vault_path(&fx);
    let dir = fx.canonical_project().display().to_string();

    let older = std::fs::read(&path).expect("read the vault");
    // The agent writes, so the file on disk moves past that copy.
    let _ = fx
        .client("other-writers")
        .call(&Request::ListVaults)
        .expect("call");
    let newer = std::fs::read(&path).expect("read the vault");
    assert_ne!(older, newer);

    // Somebody restores the older copy — a backup, a sync conflict — while the vault is unlocked.
    std::fs::write(&path, &older).expect("restore the older copy");

    let mut client = fx.client("other-writers");
    let listed = client
        .call(&Request::ListEnvironments { vault_id: None })
        .expect("call");
    assert_eq!(
        error_code(&listed).as_deref(),
        Some("VAULT_CONFLICT"),
        "{listed:?}"
    );

    let (created, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let created = client
            .call(&Request::CreateEnvironment {
                vault_id: None,
                name: "while diverged".to_owned(),
                description: None,
            })
            .expect("call");
        let written = client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call");
        (created, written)
    });
    assert_eq!(error_code(&created.0).as_deref(), Some("VAULT_CONFLICT"));
    assert_eq!(error_code(&created.1).as_deref(), Some("VAULT_CONFLICT"));
    assert!(
        seen.is_empty(),
        "nothing is put to the human while the file is in dispute"
    );
    assert!(!fx.canonical_project().join(REAL_DOTENV).exists());

    // Cleanup still works: revoking is never refused.
    let revoked = client
        .call(&Request::RevokeEnvFile {
            lease_id: None,
            path: None,
        })
        .expect("call");
    assert!(matches!(revoked, Response::Revoked { .. }), "{revoked:?}");

    assert_eq!(
        std::fs::read(&path).expect("read the vault"),
        older,
        "the restored file was overwritten"
    );

    // Put the newer file back: the agent serves again, and the revoke's entry, which could not be
    // written while the file was in dispute, reaches the disk with the next write.
    std::fs::write(&path, &newer).expect("put the newer file back");
    let listed = client
        .call(&Request::ListEnvironments { vault_id: None })
        .expect("call");
    assert_eq!(environment_ids(&listed), vec![fx.env_id.clone()]);
    let tools = tools_on_disk(&path);
    assert!(tools.contains(&"revoke_env_file".to_owned()), "{tools:?}");
    assert_eq!(
        fx.handle
            .with(Vault::unsaved_audit_entries)
            .expect("unlocked"),
        0
    );
}

#[test]
fn the_browser_extension_refuses_a_restored_vault_file_too() {
    use kagisecure_extension_ipc::protocol::{
        ErrorCode, FillField, PageContext, Request as ExtRequest, Response as ExtResponse,
    };
    use kagisecure_extension_ipc::{Client, PINNED_EXTENSION_IDS};

    let fx = fixture();
    let path = vault_path(&fx);
    let endpoint = kagisecure_ipc::Endpoint::for_instance(fx.dir.path(), "extension.sock");
    let _extension = ExtensionAgent::start(
        Arc::clone(&fx.handle),
        ExtensionConfig {
            endpoint: Some(endpoint.clone()),
            allow_unlaunched_host: true,
            ..ExtensionConfig::new(fx.agent.queue())
        },
    )
    .expect("extension agent");
    let mut browser = Client::connect(&endpoint).expect("connect");
    let welcome = browser
        .call(
            "1",
            &ExtRequest::Hello {
                extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
                browser: "chrome".to_owned(),
                extension_version: "0.1.0".to_owned(),
                protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
                capabilities: vec![],
            },
        )
        .expect("hello");
    assert!(
        matches!(welcome, ExtResponse::Welcome { .. }),
        "{welcome:?}"
    );
    let page = PageContext::top("https://example.test");
    let before = browser
        .call("2", &ExtRequest::Match { page: page.clone() })
        .expect("match");
    assert!(matches!(before, ExtResponse::Matches { .. }), "{before:?}");

    let older = std::fs::read(&path).expect("read the vault");
    let _ = fx
        .client("other-writers")
        .call(&Request::ListVaults)
        .expect("call");
    std::fs::write(&path, &older).expect("restore the older copy");

    for (id, request) in [
        ("3", ExtRequest::Match { page: page.clone() }),
        (
            "4",
            ExtRequest::Fill {
                page: page.clone(),
                item_id: fx.item_id.clone(),
                fields: vec![FillField::Password],
            },
        ),
    ] {
        match browser.call(id, &request).expect("call") {
            // `VAULT_CONFLICT`, not `INTERNAL`: the extension protocol's own equivalent of the MCP
            // channel's code above, added without a version bump the same way `AUDIT_UNAVAILABLE`
            // was. Neither `match` nor `fill` carries anything beyond the bare error — no item,
            // no username, and above all no password — which is what the `Error { code, .. }` arm
            // asserts by construction: anything with a `password` field is a different variant and
            // would fail the match below.
            ExtResponse::Error { code, .. } => assert_eq!(code, ErrorCode::VaultConflict),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
    assert_eq!(
        std::fs::read(&path).expect("read"),
        older,
        "a conflicted vault file must never be written to, not even to fail more informatively"
    );
}

#[test]
fn a_change_blocked_by_another_writer_is_answered_vault_busy_and_changes_nothing() {
    let fx = fixture();
    let path = vault_path(&fx);

    // Another process takes the write lock and keeps it past the agent's wait. (A real writer
    // never holds it this long; a stuck one might.)
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        other_process(&holder_path)
            .transact(|_| {
                locked_tx.send(()).expect("signal");
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
                Ok(())
            })
            .expect("the holder commits");
    });
    locked_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the holder has the lock");

    let started = Instant::now();
    let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("other-writers")
            .call(&Request::CreateEnvironment {
                vault_id: None,
                name: "blocked".to_owned(),
                description: None,
            })
            .expect("call")
    });
    let waited = started.elapsed();
    release_tx.send(()).expect("release");
    holder.join().expect("holder");

    assert_eq!(seen.len(), 1, "the approval itself never waits on the lock");
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("VAULT_BUSY"),
        "{reply:?}"
    );
    let wait = kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT;
    assert!(
        waited >= wait && waited < wait * 2,
        "gave up after {waited:?}: once, after the full wait"
    );
    assert!(
        fx.handle
            .with(|vault| vault.find_environment("blocked").is_err())
            .expect("unlocked"),
        "a change that could not be written must not linger in memory"
    );

    // The next write carries the entry that says it failed; the environment never appears.
    let _ = fx
        .client("other-writers")
        .call(&Request::ListVaults)
        .expect("call");
    let on_disk = other_process(&path);
    assert!(on_disk.find_environment("blocked").is_err());
    assert!(on_disk.audit_entries().iter().any(|e| {
        e.tool == "create_environment"
            && e.outcome == Outcome::Failed
            && e.detail.as_deref() == Some("VAULT_BUSY")
    }));
}

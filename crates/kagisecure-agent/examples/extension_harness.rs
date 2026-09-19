//! A stand-in for the macOS app, for the browser end-to-end test.
//!
//! # What this is for
//!
//! The Playwright suite has to drive a **real** Chrome, with the **real** extension, through the
//! **real** native messaging host, into a **real** listener over a **real** socket. Every one of
//! those can be real in a test except the last hop: the thing that owns the vault and shows the
//! approval sheet is a SwiftUI app, and a SwiftUI app is not something `node --test` can start,
//! unlock and drive.
//!
//! So this binary is that app's back half — a `VaultHandle`, an [`ExtensionAgent`], and a robot in
//! the chair where the human sits. Everything below the sheet is the production code path; what is
//! replaced is the human, and only the human. The human half is verified by hand, with screenshots
//! (`docs/browser-extension.md` §7).
//!
//! # Why it is an example and not a subcommand
//!
//! `cargo build --example` produces a binary under `target/debug/examples/` that no release
//! artifact contains and no user can invoke. A `kagisecure` subcommand that auto-approves fills
//! would be a shipped program with the approval removed, which is the thing this project spends
//! most of its design effort not having.
//!
//! It also cannot be built in release: [`ExtensionConfig::auto_approve`] asserts on
//! `cfg!(debug_assertions)`.
//!
//! # Usage
//!
//! ```text
//! extension_harness --socket <path> --site <origin>... [--username U] [--password P] [--totp URI]
//!                   [--second-username U --second-password P]
//!                   [--safari-socket <path>] [--allow-unlaunched-host] [--deny]
//! ```
//!
//! `--site` is **repeatable**, and every occurrence becomes another saved website on the one test
//! item. An item with two websites is a thing users have, and the origin rule has to hold for each
//! of them independently — so the e2e suite saves one item at two unrelated registrable domains
//! and drives every match and mismatch case against it.
//!
//! `--second-username` and `--second-password` add a **second item at the same websites**, which
//! is the shape an identifier-first scenario needs: with two items matching one origin there is no
//! "the only thing it could be", so page two either remembers what the user picked on page one or
//! asks again — and which of those happened is visible in the page. Without them one item is
//! saved, which is what every other scenario wants.
//!
//! `--deny` puts a robot in the chair that says **no**. It is the mirror image of the default:
//! `auto_approve` is switched off and this binary answers the queue itself with
//! [`Decision::Deny`], which exercises the same `ask`/`resolve` round trip and the `USER_DENIED`
//! path below it. Without it there is no way to test a refusal end to end, because the thing that
//! refuses is a human.
//!
//! `--safari-socket` binds the second front end (ADR-0024) at an explicit path, so the transport
//! can be driven without an App Group — which is what a probe built to test the *sandbox
//! boundary* needs, and what a Safari extension pointed at a scratch vault would use.
//! `--allow-unlaunched-host` switches off the peer-identity gate on both sockets; it is a debug
//! affordance that `ExtensionAgent::start` refuses to compile into a release build, and the gate
//! itself is tested with it off in `tests/extension.rs` and `tests/safari.rs`.
//!
//! Prints one line of JSON when it is listening, then serves until stdin closes. On exit it prints
//! a second line summarizing the audit log, so the test can assert on what was recorded without
//! opening the vault itself.

use std::io::{BufRead, Write};
use std::sync::Arc;

use kagisecure_agent::approval::{ApprovalQueue, ClientVerification, Decision};
use kagisecure_agent::{ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};

fn arg(args: &[String], name: &str) -> Option<String> {
    all(args, name).into_iter().next()
}

/// Every value given for a repeatable flag, in the order they appeared.
fn all(args: &[String], name: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == name)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket = arg(&args, "--socket").expect("--socket is required");
    let sites = all(&args, "--site");
    assert!(!sites.is_empty(), "at least one --site is required");
    let username = arg(&args, "--username").unwrap_or_else(|| "alice".to_owned());
    let password = arg(&args, "--password").unwrap_or_else(|| "correct-horse".to_owned());
    let totp = arg(&args, "--totp");
    let second_username = arg(&args, "--second-username");
    let second_password = arg(&args, "--second-password");
    let safari_socket = arg(&args, "--safari-socket");
    let allow_unlaunched_host = args.iter().any(|a| a == "--allow-unlaunched-host");
    let deny = args.iter().any(|a| a == "--deny");

    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("e2e.kagivault");

    // Deliberately cheap KDF parameters: this vault lives for the length of one test run.
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(8, 1, 1).expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create vault");
    let vault_id = vault.default_vault_id().expect("default vault");

    let mut item = Item::new(vault_id, Category::Login, "Test login");
    item.urls = sites.clone();
    item.fields.push(Field::public("username", username));
    item.fields
        .push(Field::concealed("password", Secret::from_string(password)));
    if let Some(uri) = totp {
        item.fields
            .push(Field::totp("one-time password", Secret::from_string(uri)));
    }
    vault.add_item(item);

    // A second account at the *same* websites, when the test asks for one. Two matches at one
    // origin is the case where "which item" is a real question rather than a foregone conclusion.
    if let (Some(username), Some(password)) = (second_username, second_password) {
        let mut second = Item::new(vault_id, Category::Login, "Test login (second account)");
        second.urls = sites.clone();
        second.fields.push(Field::public("username", username));
        second
            .fields
            .push(Field::concealed("password", Secret::from_string(password)));
        vault.add_item(second);
    }

    // A second item at a different origin, so "no match" in the test means the rule refused rather
    // than the vault being empty.
    let mut elsewhere = Item::new(vault_id, Category::Login, "Never fill me");
    elsewhere.urls = vec!["https://never.example".to_owned()];
    elsewhere.fields.push(Field::public("username", "nobody"));
    elsewhere.fields.push(Field::concealed(
        "password",
        Secret::from_string("must-not-appear".to_owned()),
    ));
    vault.add_item(elsewhere);

    vault.save().expect("save");

    let handle = VaultHandle::new(vault);
    let queue = Arc::new(ApprovalQueue::new());

    // The robot that says no. `auto_approve` is the robot that says yes, and it works the same
    // way — a thread on `next`/`resolve` — so a denial here is the production `USER_DENIED` path
    // and not a shortcut around it.
    if deny {
        let denier = Arc::clone(&queue);
        std::thread::spawn(move || {
            // `next` answers `None` on *timeout* as well as on a closed queue, so this polls
            // forever rather than stopping at the first quiet moment. The thread dies with the
            // process, which is the whole lifetime this binary has.
            loop {
                if let Some(request) = denier.next(std::time::Duration::from_millis(200)) {
                    denier.resolve(
                        &request.id,
                        &Decision::Deny,
                        ClientVerification {
                            verified: false,
                            evidence: "denied by a debug build".to_owned(),
                        },
                    );
                }
            }
        });
    }

    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            socket_path: Some(std::path::PathBuf::from(&socket)),
            safari_socket_path: safari_socket.as_ref().map(std::path::PathBuf::from),
            auto_approve: !deny,
            // Defaults to **not** set: Chrome is the parent of the native host in the Playwright
            // suite, so the process-ancestry gate is exercised for real rather than switched off.
            allow_unlaunched_host,
            ..ExtensionConfig::new(Arc::clone(&queue))
        },
    )
    .expect("extension agent");

    println!(
        "{{\"event\":\"ready\",\"socket\":{socket:?},\"endpoint\":{:?},\"safari\":{:?}}}",
        agent.endpoint(),
        agent.safari_endpoint()
    );
    let _ = std::io::stdout().flush();

    // Serve until the test closes our stdin.
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(command) if command.trim() == "audit" => {
                print_audit(&handle);
            }
            Ok(command) if command.trim() == "lock" => {
                drop(handle.take());
                println!("{{\"event\":\"locked\"}}");
                let _ = std::io::stdout().flush();
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    print_audit(&handle);
}

/// Print the audit log as one JSON line: tool, outcome and detail per entry, and nothing else.
///
/// No value can appear here — `AuditEntry` has no field one could sit in — but the test asserts
/// that anyway, against its own canary.
fn print_audit(handle: &Arc<VaultHandle>) {
    let rows: Vec<String> = handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .map(|e| {
                    format!(
                        "{{\"tool\":{:?},\"outcome\":{:?},\"detail\":{:?},\"origin\":{:?},\"fields\":{:?}}}",
                        e.tool,
                        format!("{:?}", e.outcome),
                        e.detail.clone().unwrap_or_default(),
                        e.target_path.clone().unwrap_or_default(),
                        e.variables.join(",")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    println!("{{\"event\":\"audit\",\"entries\":[{}]}}", rows.join(","));
    let _ = std::io::stdout().flush();
}

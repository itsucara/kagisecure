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
//!                   [--safari-socket <path>] [--allow-unlaunched-host] [--deny | --presence]
//!                   [--agent-socket <path>] [--agent-fill] [--test-logins]
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
//! `--presence` puts a robot in the chair that **reviews and then leaves**: it answers every full
//! approval sheet with "Allow for this session", and denies every presence-only prompt
//! ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)). That is
//! the app with nobody at the keyboard after the first login — a presence prompt is a
//! LocalAuthentication sheet, and with no finger, password or watch it comes back cancelled, which
//! the app turns into a denial. It is what lets the browser suite show that a trusted click the
//! test itself synthesizes over CDP, the same kind an automation agent sends, fills nothing.
//!
//! `--safari-socket` binds the second front end (ADR-0024) at an explicit path, so the transport
//! can be driven without an App Group — which is what a probe built to test the *sandbox
//! boundary* needs, and what a Safari extension pointed at a scratch vault would use.
//! `--allow-unlaunched-host` switches off the peer-identity gate on both sockets; it is a debug
//! affordance that `ExtensionAgent::start` refuses to compile into a release build, and the gate
//! itself is tested with it off in `tests/extension.rs` and `tests/safari.rs`.
//!
//! `--agent-socket` also serves the **MCP** socket there — a library [`Agent`] on the same vault,
//! the same approval queue and the same agent-fill broker — so a real `kagisecure-mcp` can be
//! pointed at it (`KAGISECURE_SOCKET`) and drive `request_fill` into the browser the suite is
//! driving ([ADR-0036](../../../docs/decisions/0036-agent-requested-browser-fill.md)).
//! `--agent-fill` turns the broker's switch on, as the app's setting would, and makes the test
//! item and its vault visible to agents, which `request_fill` requires; without it every
//! `request_fill` is `FILL_UNAVAILABLE`. The robot in the chair answers the agent-fill sheet the
//! way it answers every other one: yes by default, no with `--deny`. With `--agent-fill` and
//! neither `--deny` nor `--presence`, every request that robot answers is first announced as a
//! line of JSON, `{"event":"sheet","kind":…}`, so the suite can count the sheets a scenario raised.
//!
//! `--test-logins` (with `--agent-socket`) turns agent test logins on (ADR-0048): it creates the
//! "Agent test logins" vault with the switch on and no extra allowed domains — loopback,
//! `localhost`, `*.localhost` and `*.test` need none — and hands the MCP side a test-login broker,
//! so `create_test_login` and the no-sheet login and sign-up fills can be driven end to end.
//!
//! Prints one line of JSON when it is listening, then serves until stdin closes. On exit it prints
//! a second line summarizing the audit log, so the test can assert on what was recorded without
//! opening the vault itself.

use std::io::{BufRead, Write};
use std::sync::Arc;

use kagisecure_agent::approval::{ApprovalQueue, ClientVerification, Decision};
use kagisecure_agent::{
    Agent, AgentConfig, AgentFillBroker, Endpoint, ExtensionAgent, ExtensionConfig,
    TestLoginBroker, VaultHandle,
};
use kagisecure_core::model::{Field, Item, Secret, TestLoginPolicy};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};

fn arg(args: &[String], name: &str) -> Option<String> {
    all(args, name).into_iter().next()
}

/// One endpoint flag, read the way the product reads `--socket`.
///
/// A panic rather than a usage error: this is a debug-only example driven by a test suite, and a
/// harness that started on the wrong endpoint would be diagnosed as a browser that never
/// connected. The message is the one `Endpoint::parse` writes, which names what to pass instead.
fn endpoint_arg(flag: &str, value: &str) -> Endpoint {
    Endpoint::parse(std::ffi::OsStr::new(value)).unwrap_or_else(|e| panic!("{flag}: {e}"))
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
    let presence = args.iter().any(|a| a == "--presence");
    let agent_socket = arg(&args, "--agent-socket");
    let agent_fill = args.iter().any(|a| a == "--agent-fill");
    let test_logins = args.iter().any(|a| a == "--test-logins");
    assert!(
        !(deny && presence),
        "--deny and --presence are two different robots; pass one"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("e2e.kagivault");

    // Deliberately cheap KDF parameters: this vault lives for the length of one test run.
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create vault");
    let vault_id = vault.default_vault_id().expect("default vault");

    let mut item = Item::new(vault_id, Category::Login, "Test login");
    item.urls = sites.clone();
    // `request_fill` serves only an item an agent may see, in a vault an agent may see.
    item.agent_visible = agent_fill;
    item.fields.push(Field::public("username", username));
    item.fields
        .push(Field::concealed("password", Secret::from_string(password)));
    if let Some(uri) = totp {
        item.fields
            .push(Field::totp("one-time password", Secret::from_string(uri)));
    }

    // A second account at the *same* websites, when the test asks for one. Two matches at one
    // origin is the case where "which item" is a real question rather than a foregone conclusion.
    let second = if let (Some(username), Some(password)) = (second_username, second_password) {
        let mut second = Item::new(vault_id, Category::Login, "Test login (second account)");
        second.urls = sites.clone();
        second.fields.push(Field::public("username", username));
        second
            .fields
            .push(Field::concealed("password", Secret::from_string(password)));
        Some(second)
    } else {
        None
    };

    // A second item at a different origin, so "no match" in the test means the rule refused rather
    // than the vault being empty.
    let mut elsewhere = Item::new(vault_id, Category::Login, "Never fill me");
    elsewhere.urls = vec!["https://never.example".to_owned()];
    elsewhere.fields.push(Field::public("username", "nobody"));
    elsewhere.fields.push(Field::concealed(
        "password",
        Secret::from_string("must-not-appear".to_owned()),
    ));

    vault
        .transact(|tx| {
            if agent_fill {
                tx.set_vault_agent_visible(vault_id, true);
            }
            tx.add_item(item);
            if let Some(second) = second {
                tx.add_item(second);
            }
            tx.add_item(elsewhere);
            Ok(())
        })
        .expect("save");
    if test_logins {
        vault
            .transact(|tx| {
                tx.ensure_agent_test_vault("extension_harness")?;
                tx.set_test_login_policy(
                    TestLoginPolicy {
                        enabled: true,
                        auto_domains: Vec::new(),
                        unknown: std::collections::BTreeMap::new(),
                    },
                    "extension_harness",
                )
            })
            .expect("test-login vault");
    }

    let handle = VaultHandle::new(vault);
    let queue = Arc::new(ApprovalQueue::new());

    // The robot that says no — to everything with `--deny`, to presence prompts only with
    // `--presence`. `auto_approve` is the robot that says yes, and it works the same way — a
    // thread on `next`/`resolve` — so a denial here is the production `USER_DENIED` path and not a
    // shortcut around it.
    if deny || presence {
        let robot = Arc::clone(&queue);
        std::thread::spawn(move || {
            // `next` answers `None` on *timeout* as well as on a closed queue, so this polls
            // forever rather than stopping at the first quiet moment. The thread dies with the
            // process, which is the whole lifetime this binary has.
            loop {
                if let Some(request) = robot.next(std::time::Duration::from_millis(200)) {
                    let decision = if deny || request.presence_only {
                        Decision::Deny
                    } else {
                        Decision::AllowSession {
                            ttl_seconds: request.requested_ttl_seconds,
                            uses: 1,
                        }
                    };
                    robot.resolve(
                        &request.id,
                        &decision,
                        ClientVerification {
                            verified: false,
                            evidence: if deny {
                                "denied by a debug build".to_owned()
                            } else {
                                "answered by a debug build with nobody present".to_owned()
                            },
                        },
                    );
                }
            }
        });
    }

    // The robot that says yes to an agent fill. `auto_approve` answers only the fills the
    // extension listener asks about itself; an agent fill's sheet is raised by the MCP side, so
    // it needs a robot of its own on the same queue. Whatever this one picks up it answers exactly
    // as `auto_approve` would, so the two never disagree about a request either takes.
    //
    // Each request it picks up is announced on stdout as a `sheet` event — the kind, and nothing
    // else — before it is answered. That is how the browser suite counts the sheets an agent fill
    // raised: "no sheet" for a look-alike, "no second sheet" for page two of a sign-in, are claims
    // about the human's attention, and an audit entry is only indirect evidence of them.
    if agent_fill && !deny && !presence {
        let robot = Arc::clone(&queue);
        std::thread::spawn(move || {
            loop {
                if let Some(request) = robot.next(std::time::Duration::from_millis(200)) {
                    println!(
                        "{{\"event\":\"sheet\",\"kind\":{:?},\"presence_only\":{}}}",
                        format!("{:?}", request.kind),
                        request.presence_only
                    );
                    let _ = std::io::stdout().flush();
                    let decision = if request.presence_only {
                        Decision::AllowOnce
                    } else {
                        Decision::AllowSession {
                            ttl_seconds: request.requested_ttl_seconds,
                            uses: 1,
                        }
                    };
                    robot.resolve(
                        &request.id,
                        &decision,
                        ClientVerification {
                            verified: false,
                            evidence: "auto-approved by a debug build".to_owned(),
                        },
                    );
                }
            }
        });
    }

    let broker = Arc::new(AgentFillBroker::new());
    broker.set_enabled(agent_fill);

    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            // `--socket` here means what `kagisecure daemon --socket` means, through the same
            // parser: a socket path on Unix, a named pipe name on Windows.
            endpoint: Some(endpoint_arg("--socket", &socket)),
            safari_endpoint: safari_socket
                .as_deref()
                .map(|value| endpoint_arg("--safari-socket", value)),
            auto_approve: !deny && !presence,
            // Defaults to **not** set: Chrome is the parent of the native host in the Playwright
            // suite, so the process-ancestry gate is exercised for real rather than switched off.
            allow_unlaunched_host,
            agent_fill: Some(Arc::clone(&broker)),
            ..ExtensionConfig::new(Arc::clone(&queue))
        },
    )
    .expect("extension agent");

    let mcp = agent_socket.as_deref().map(|value| {
        Agent::start(
            Arc::clone(&handle),
            &AgentConfig {
                endpoint: Some(endpoint_arg("--agent-socket", value)),
                queue: Some(Arc::clone(&queue)),
                agent_fill: Some(Arc::clone(&broker)),
                test_logins: test_logins.then(|| Arc::new(TestLoginBroker::new())),
            },
        )
        .expect("MCP agent")
    });

    // Built with serde_json, not a hand-written format string: `safari` and `agent` are
    // `Option<String>`, and `{:?}` on those prints Rust's `None` / `Some("...")` debug form, which
    // is not JSON at all. `json!` serializes `None` as `null`, same as every other event line here.
    println!(
        "{}",
        serde_json::json!({
            "event": "ready",
            "socket": socket,
            "endpoint": agent.endpoint(),
            "safari": agent.safari_endpoint(),
            "agent": mcp.as_ref().map(Agent::endpoint),
        })
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

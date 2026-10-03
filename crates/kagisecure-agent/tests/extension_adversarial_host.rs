//! Adversarial: who is allowed to be on the other end, and what the app claims to know about it.
//!
//! `peer.rs` is explicit that its browser test and its app-extension test are **path** tests and
//! not identities — the identity is a code-signature check the app runs in Swift, on the pids
//! this layer supplies. That design is only sound if two things hold, and both are testable here:
//!
//! 1. a program that merely *looks* like a browser, or like our own `.appex`, gets no further
//!    than the gate lets it — the pinned extension id, the origin rule and the human are all
//!    still in front of every value; and
//! 2. whatever the app *says* about such a peer is a statement of raw facts the Swift verdict can
//!    contradict, never a claim that anything was verified. If the evidence read as an
//!    endorsement, a copy of `/bin/sh` named `Google Chrome` would be laundered into one.
//!
//! So the impostors here are real processes at real paths: a copy of `/bin/sh` named
//! `Google Chrome` that launches the real `kagisecure-nmhost`, and a copy of the real host placed
//! at an `.appex` path shape that is not our bundle. Both connect to a real listener over a real
//! socket.
//!
//! The last section is about the two test affordances, `auto_approve` and `allow_unlaunched_host`,
//! which are guarded by `assert!` rather than by `#[cfg]`. A release build must abort rather than
//! serve with either of them on, and the only honest way to observe an abort is from a parent
//! process — so that test re-executes this binary and reads the child's exit status.
//!
//! Unix-only. The impostors are `/bin/sh` copied to a browser's name and a host placed at an
//! `.appex` path shape; neither has a Windows analogue, and the peer plumbing is raw
//! `UnixStream`. TODO(windows): the equivalent is a copy of any executable named `chrome.exe`
//! launching the real host, checked against `known_browser_for` — worth writing, on Windows.

#![cfg(unix)]

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use kagisecure_agent::approval::ApprovalQueue;
use kagisecure_agent::extension::audit_detail;
use kagisecure_agent::{Endpoint, ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::frame;
use kagisecure_extension_ipc::{
    PINNED_EXTENSION_IDS, SAFARI_EXTENSION_BUNDLE_ID, SAFARI_EXTENSION_EXECUTABLE, nm,
};
use serde_json::{Value, json};

/// Seeded as the login's password, so every refusal in this file can also be checked for silence.
const PASSWORD_CANARY: &str = "H0ST-PW-C4N4RY-2c8b41f7e09d63a5";

const SITE: &str = "https://host.example";

/// The name an impostor takes to satisfy `known_browser_for`, which matches on the file name.
const IMPOSTOR_BROWSER_NAME: &str = "Google Chrome";

struct Fixture {
    dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    _agent: ExtensionAgent,
    nm_socket: PathBuf,
    safari_socket: PathBuf,
    item_id: String,
}

fn fixture(allow_unlaunched_host: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");

    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");
    let vault_id = vault.default_vault_id().expect("default vault");

    let mut item = Item::new(vault_id, Category::Login, "Host test site");
    item.urls = vec![SITE.to_owned()];
    item.fields.push(Field::public("username", "alice"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(PASSWORD_CANARY.to_owned()),
    ));
    let item_id = item.id.to_string();
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .expect("save");

    let nm_socket = dir.path().join("extension.sock");
    let safari_socket = dir.path().join("safari.sock");
    let handle = VaultHandle::new(vault);
    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            // This whole file is `#![cfg(unix)]` — it speaks `UnixStream` directly — so a
            // filesystem socket is the right endpoint here by construction.
            endpoint: Some(Endpoint::Path(nm_socket.clone())),
            safari_endpoint: Some(Endpoint::Path(safari_socket.clone())),
            auto_approve: true,
            allow_unlaunched_host,
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("extension agent");

    Fixture {
        dir,
        handle,
        _agent: agent,
        nm_socket,
        safari_socket,
        item_id,
    }
}

/// The real native host binary, built on demand — see `kagisecure_test_support::binary` for the
/// shared resolution logic. A hardcoded `target/debug` would be wrong the moment the suite runs in
/// a scratch target directory.
fn nmhost_binary() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-nmhost", kagisecure_agent::bundle::NMHOST)
}

/// A raw app-socket connection, for the tests that speak to the listener directly.
struct RawExtension {
    stream: UnixStream,
    next_id: u64,
}

impl RawExtension {
    fn connect(socket: &Path) -> Self {
        let stream = UnixStream::connect(socket).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("read timeout");
        Self { stream, next_id: 0 }
    }

    fn send(&mut self, body: Value) -> Option<Value> {
        self.next_id += 1;
        let id = format!("host-{}", self.next_id);
        frame::write(
            &mut self.stream,
            &json!({ "ksx": 1, "id": id, "body": body }),
        )
        .ok()?;
        let reply: Value = frame::read(&mut self.stream).ok()?;
        Some(reply["body"].clone())
    }

    fn hello_as(&mut self, extension_id: &str) -> Option<Value> {
        self.send(json!({
            "ask": "hello",
            "extension_id": extension_id,
            "browser": "chrome",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }))
    }
}

fn host_refusals(fixture: &Fixture) -> usize {
    fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter(|e| e.detail.as_deref() == Some(audit_detail::HOST_REFUSED))
                .count()
        })
        .expect("unlocked")
}

fn audit_json(fixture: &Fixture) -> String {
    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .unwrap_or_default();
    serde_json::to_string(&entries).expect("audit json")
}

// ---------------------------------------------------------------------------
// B-16: each socket pins its own extension id, and a crossing is audited.
// ---------------------------------------------------------------------------

#[test]
fn an_extension_id_pinned_for_the_other_socket_is_refused_and_recorded_on_both() {
    let fixture = fixture(true);

    // The Safari bundle id, offered on the native-messaging socket.
    let mut on_nm = RawExtension::connect(&fixture.nm_socket);
    let reply = on_nm
        .hello_as(SAFARI_EXTENSION_BUNDLE_ID)
        .expect("an answer");
    assert_eq!(reply["reply"], "error", "{reply}");
    assert_eq!(reply["code"], "UNKNOWN_EXTENSION", "{reply}");

    // The Chromium extension id, offered on the Safari socket.
    let mut on_safari = RawExtension::connect(&fixture.safari_socket);
    let reply = on_safari
        .hello_as(PINNED_EXTENSION_IDS[0])
        .expect("an answer");
    assert_eq!(reply["reply"], "error", "{reply}");
    assert_eq!(reply["code"], "UNKNOWN_EXTENSION", "{reply}");

    assert_eq!(
        host_refusals(&fixture),
        2,
        "each refusal is a HOST_REFUSED entry, so a user can see somebody tried"
    );

    // And neither connection can go on to do anything, because no `Hello` succeeded.
    for connection in [&mut on_nm, &mut on_safari] {
        let after = connection
            .send(json!({
                "ask": "fill",
                "page": { "top_origin": SITE },
                "item_id": fixture.item_id,
                "fields": ["password"],
            }))
            .expect("an answer");
        assert_eq!(after["reply"], "error", "{after}");
        assert_eq!(after["code"], "PROTOCOL", "{after}");
    }
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

#[test]
fn an_extension_id_nobody_pinned_is_refused_on_both_sockets() {
    let fixture = fixture(true);
    for (socket, label) in [
        (&fixture.nm_socket, "native messaging"),
        (&fixture.safari_socket, "safari"),
    ] {
        for impostor in [
            "",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // The pinned id with one character changed.
            &{
                let mut id = PINNED_EXTENSION_IDS[0].to_owned();
                id.pop();
                id.push('z');
                id
            },
            // The pinned id with trailing whitespace, and with different case.
            &format!("{} ", PINNED_EXTENSION_IDS[0]),
            &PINNED_EXTENSION_IDS[0].to_uppercase(),
            &format!("{SAFARI_EXTENSION_BUNDLE_ID}.evil"),
        ] {
            let mut connection = RawExtension::connect(socket);
            let reply = connection.hello_as(impostor).expect("an answer");
            assert_eq!(
                reply["code"], "UNKNOWN_EXTENSION",
                "{impostor:?} on the {label} socket: {reply}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// B-18: a request before `Hello`.
// ---------------------------------------------------------------------------

#[test]
fn a_fill_before_hello_is_a_protocol_refusal_that_touches_no_vault() {
    let fixture = fixture(true);
    let mut extension = RawExtension::connect(&fixture.nm_socket);

    for premature in [
        json!({ "ask": "fill", "page": { "top_origin": SITE },
                "item_id": fixture.item_id, "fields": ["password"] }),
        json!({ "ask": "totp", "page": { "top_origin": SITE }, "item_id": fixture.item_id }),
        json!({ "ask": "match", "page": { "top_origin": SITE } }),
        json!({ "ask": "status" }),
    ] {
        let reply = extension.send(premature.clone()).expect("an answer");
        assert_eq!(reply["reply"], "error", "{premature}: {reply}");
        assert_eq!(
            reply["code"], "PROTOCOL",
            "everything before a hello is a protocol error: {premature}: {reply}"
        );
        assert!(
            !serde_json::to_string(&reply)
                .unwrap()
                .contains(PASSWORD_CANARY)
        );
    }

    // Nothing was read from the vault and nothing was written to the log.
    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    assert!(
        entries.iter().all(|e| e.tool != "fill_credential"),
        "a request before hello must not reach the fill path at all"
    );
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

// ---------------------------------------------------------------------------
// B-19: a refused host stays refused for the life of the connection.
// ---------------------------------------------------------------------------

#[test]
fn a_host_refused_at_connect_stays_refused_for_every_request_it_ever_sends() {
    // The affordance off, so this test binary — whose parent is `cargo`, not a browser — is
    // refused at gate 2, exactly as a native host launched by a shell script would be.
    let fixture = fixture(false);
    let mut extension = RawExtension::connect(&fixture.nm_socket);

    // The refusal is decided once, before the first request, and is re-served forever. A hundred
    // attempts, including well-formed ones with the pinned id, must all get the same answer:
    // the gate is not re-evaluated per request, so nothing an attacker does later can pass it.
    for attempt in 0..100 {
        let reply = extension.hello_as(PINNED_EXTENSION_IDS[0]).expect("answer");
        assert_eq!(reply["reply"], "error", "attempt {attempt}: {reply}");
        assert_eq!(
            reply["code"], "UNTRUSTED_HOST",
            "attempt {attempt}: {reply}"
        );
        assert!(
            !reply["message"].as_str().unwrap_or_default().is_empty(),
            "a refusal says why, rather than closing the port"
        );
    }

    let reply = extension
        .send(json!({ "ask": "fill", "page": { "top_origin": SITE },
                      "item_id": fixture.item_id, "fields": ["password"] }))
        .expect("answer");
    assert_eq!(reply["code"], "UNTRUSTED_HOST", "{reply}");
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
    assert_eq!(
        host_refusals(&fixture),
        1,
        "the refusal is decided and recorded once per connection, not once per request"
    );
}

// ---------------------------------------------------------------------------
// B-12: a copy of /bin/sh named `Google Chrome` launches the real native host.
// ---------------------------------------------------------------------------

/// The impostor launcher's source.
///
/// A copy of a system shell cannot be used for this: macOS kills a copied `/bin/sh`, `/bin/zsh`
/// or `/usr/bin/perl` with `SIGKILL` before `main`, so an impostor built that way would "pass"
/// every test by never running. This is therefore a real program, compiled at test time, whose
/// only job is to be the process that launches the native host — and whose file name is the only
/// thing `known_browser_for` ever looks at.
///
/// `wait` keeps the launcher alive as the host's parent, which is what a browser does. `orphan`
/// double-forks and exits, which reparents the host onto `launchd` and is what a launcher shim
/// trying to hide its ancestry would do.
const IMPOSTOR_LAUNCHER_SOURCE: &str = r#"
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int orphan = strcmp(argv[1], "orphan") == 0;
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        if (orphan) {
            pid_t grandchild = fork();
            if (grandchild != 0) _exit(0);
        }
        execv(argv[2], &argv[2]);
        _exit(127);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return 0;
}
"#;

/// Compile [`IMPOSTOR_LAUNCHER_SOURCE`] to `path`, whose file name is the impersonation.
///
/// `None` when there is no C compiler on this machine, which is a skip rather than a failure: the
/// property under test is about the app, and a machine with no `cc` cannot build the impostor to
/// ask it with.
fn impostor_launcher(path: &Path) -> Option<PathBuf> {
    let parent = path.parent().expect("a parent");
    std::fs::create_dir_all(parent).expect("mkdir");
    let source = parent.join("impostor.c");
    std::fs::write(&source, IMPOSTOR_LAUNCHER_SOURCE).expect("write the launcher source");
    let status = Command::new("cc")
        .arg("-O0")
        .arg("-o")
        .arg(path)
        .arg(&source)
        .status()
        .ok()?;
    status.success().then(|| path.to_path_buf())
}

#[test]
fn a_program_merely_named_like_a_browser_passes_the_path_gate_but_claims_no_verification() {
    // `launched_by_browser()` is a path test, and `peer.rs` says so in as many words: anything
    // that can write a file named `Google Chrome` satisfies it. That is not the finding. The
    // finding would be the app *claiming* something about such a peer that the Swift
    // code-signature verdict could not contradict — so what is asserted here is that the evidence
    // the app hands out names the impostor's real path and its real pid, and nothing else.
    let fixture = fixture(false);
    let Some(impostor) =
        impostor_launcher(&fixture.dir.path().join("fake").join(IMPOSTOR_BROWSER_NAME))
    else {
        eprintln!("skipping: no C compiler to build the impostor launcher with");
        return;
    };
    let host = nmhost_binary();

    // The impostor stays alive as the host's parent, which is what a browser does, so the
    // ancestry walk finds it.
    let mut child = Command::new(&impostor)
        .arg("wait")
        .arg(&host)
        .arg("chrome-extension://x/")
        .arg("com.kagisecure.nmhost")
        .env("KAGISECURE_EXTENSION_SOCKET", &fixture.nm_socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the impostor browser");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    nm::write(
        &mut stdin,
        &json!({ "ksx": 1, "id": "imp-1", "body": {
            "ask": "hello",
            "extension_id": PINNED_EXTENSION_IDS[0],
            "browser": "chrome",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }}),
    )
    .expect("write a native message");
    let reply: Value = nm::read(&mut stdout).expect("read a native message");
    let body = &reply["body"];

    assert_eq!(
        body["reply"], "welcome",
        "the path gate is documented to pass here; the interesting part is what is claimed: \
         {body}"
    );
    let evidence: Vec<String> = body["host_evidence"]
        .as_array()
        .expect("host evidence")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_owned())
        .collect();
    let joined = evidence.join("\n");
    assert!(
        joined.contains(&impostor.display().to_string()),
        "the evidence must name the impostor's real executable path, so the Swift \
         code-signature verdict has something to go red about: {joined}"
    );
    assert!(
        !joined.to_lowercase().contains("verified")
            && !joined.to_lowercase().contains("signature ok")
            && !joined.to_lowercase().contains("trusted"),
        "the evidence must not read as an endorsement of a peer nothing has checked: {joined}"
    );

    drop(stdin);
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        let _ = handle.read_to_string(&mut stderr);
    }
    let _ = child.wait();
    assert!(!stderr.contains(PASSWORD_CANARY), "{stderr}");
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

#[test]
fn the_evidence_says_in_words_that_nothing_here_checked_a_signature() {
    // `peer.rs`'s doc comment on `evidence()` states the requirement: "Deliberately says
    // *'signature not checked here'* rather than nothing: the check happens in Swift and this
    // string is written by Rust, so it must not read as if a check passed." The `"Launched by: \
    // ..."` lines now carry that caveat, since those are the ones that name a browser next to a
    // path a reader could otherwise mistake for a verified identity.
    let fixture = fixture(true);
    let mut extension = RawExtension::connect(&fixture.nm_socket);
    let welcome = extension.hello_as(PINNED_EXTENSION_IDS[0]).expect("answer");
    let joined = welcome["host_evidence"]
        .as_array()
        .expect("host evidence")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    assert!(
        joined.contains("not checked") || joined.contains("unverified"),
        "the evidence must say that no signature was checked here: {joined}"
    );
}

// ---------------------------------------------------------------------------
// B-15: a binary at an `.appex` path shape that is not our bundle.
// ---------------------------------------------------------------------------

#[test]
fn a_binary_at_a_forged_appex_path_is_served_only_as_a_path_match_and_is_named_as_itself() {
    // `is_safari_extension_executable` tests two things about the *path*: the file name, and an
    // enclosing `KagisecureSafariExtension.appex` directory. Neither is an identity, and a
    // forgery is one `mkdir` away. As with the browser impostor, the property under test is that
    // the app reports the forged path rather than laundering it into a claim.
    let fixture = fixture(false);
    let forged_dir = fixture
        .dir
        .path()
        .join("x")
        .join(format!("{SAFARI_EXTENSION_EXECUTABLE}.appex"))
        .join("Contents")
        .join("MacOS");
    std::fs::create_dir_all(&forged_dir).expect("mkdir");
    let forged = forged_dir.join(SAFARI_EXTENSION_EXECUTABLE);
    // The real native host, at a forged path: it speaks the protocol, and its executable path is
    // the thing being judged.
    std::fs::copy(nmhost_binary(), &forged).expect("copy the host to the forged path");

    let mut child = Command::new(&forged)
        .env("KAGISECURE_EXTENSION_SOCKET", &fixture.safari_socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the forged app extension");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    nm::write(
        &mut stdin,
        &json!({ "ksx": 1, "id": "forged-1", "body": {
            "ask": "hello",
            "extension_id": SAFARI_EXTENSION_BUNDLE_ID,
            "browser": "safari",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }}),
    )
    .expect("write");
    let reply: Value = nm::read(&mut stdout).expect("read");
    let body = &reply["body"];

    if body["reply"] == "welcome" {
        let joined = body["host_evidence"]
            .as_array()
            .expect("host evidence")
            .iter()
            .map(|v| v.as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains(&forged.display().to_string()),
            "a forged appex path must be reported as the path it is: {joined}"
        );
        assert!(
            !joined.to_lowercase().contains("verified"),
            "nothing here verified anything: {joined}"
        );
    } else {
        assert_eq!(body["code"], "UNTRUSTED_HOST", "{body}");
    }

    drop(stdin);
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        let _ = handle.read_to_string(&mut stderr);
    }
    let _ = child.wait();
    assert!(!stderr.contains(PASSWORD_CANARY), "{stderr}");
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

// ---------------------------------------------------------------------------
// B-13: a double-forking launcher under a program named like a browser.
// ---------------------------------------------------------------------------

#[test]
fn a_host_whose_launcher_double_forked_is_judged_on_the_ancestry_that_is_actually_there() {
    // A script that double-forks orphans the host onto `launchd`, so there is no browser above it
    // any more. With the affordance off, that must be a refusal — the gate's whole purpose is
    // that a native host with nothing recognizable above it is not served.
    let fixture = fixture(false);
    let Some(launcher) = impostor_launcher(
        &fixture
            .dir
            .path()
            .join("double")
            .join(IMPOSTOR_BROWSER_NAME),
    ) else {
        eprintln!("skipping: no C compiler to build the impostor launcher with");
        return;
    };
    let host = nmhost_binary();

    let mut child = Command::new(&launcher)
        .arg("orphan")
        .arg(&host)
        .env("KAGISECURE_EXTENSION_SOCKET", &fixture.nm_socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the double-forking launcher");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let _ = child.wait();

    // The orphaned host kept the pipes, so it can still be spoken to — but its parent is gone and
    // `launchd` is not a browser, so the gate must refuse it.
    nm::write(
        &mut stdin,
        &json!({ "ksx": 1, "id": "orphan-1", "body": {
            "ask": "hello",
            "extension_id": PINNED_EXTENSION_IDS[0],
            "browser": "chrome",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }}),
    )
    .expect("write");
    // An `Err` here is the host exiting without answering, which is also a refusal — it was
    // never served.
    if let Ok(reply) = nm::read::<_, Value>(&mut stdout) {
        let body = &reply["body"];
        assert_eq!(
            body["reply"], "error",
            "a host whose launcher forked away its own ancestry must not be served: {body}"
        );
        assert_eq!(body["code"], "UNTRUSTED_HOST", "{body}");
    }
    drop(stdin);

    std::thread::sleep(Duration::from_millis(200));
    let approved = fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter(|e| e.detail.as_deref() == Some(audit_detail::FILL_APPROVED))
                .count()
        })
        .expect("unlocked");
    assert_eq!(approved, 0, "nothing was filled for an orphaned host");
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

// ---------------------------------------------------------------------------
// B-27: the two test affordances must not be usable in a release build.
// ---------------------------------------------------------------------------

/// The environment variable the release-abort test sets on the child it re-executes.
const ABORT_PROBE: &str = "KAGISECURE_LANE3_ABORT_PROBE";

#[test]
fn a_release_build_refuses_to_start_with_either_test_affordance_switched_on() {
    if cfg!(debug_assertions) {
        // In a debug build the affordances are permitted by design — that is what every other
        // test in this file relies on — so there is nothing to observe here. The release case
        // below is the one that matters, and is reached by `cargo test --release`.
        let fixture = fixture(true);
        assert!(fixture.nm_socket.exists());
        return;
    }

    // An `assert!` under `panic = "abort"` cannot be caught, so the observation has to be made
    // from a parent process: re-execute this same test binary, pointed at the probe below.
    for affordance in ["auto_approve", "allow_unlaunched_host"] {
        let status = Command::new(std::env::current_exe().expect("current exe"))
            .args([
                "--exact",
                "the_probe_that_starts_a_listener_with_an_affordance",
                "--ignored",
                "--nocapture",
            ])
            .env(ABORT_PROBE, affordance)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("re-execute this test binary");
        assert!(
            !status.success(),
            "a release build started a listener with {affordance} switched on"
        );
    }
}

#[test]
#[ignore = "helper for a_release_build_refuses_to_start_with_either_test_affordance_switched_on: \
            aborts by design, and is only meaningful as a child process"]
fn the_probe_that_starts_a_listener_with_an_affordance() {
    let Ok(affordance) = std::env::var(ABORT_PROBE) else {
        // Run directly with `--include-ignored` rather than as the probe: do nothing, so a
        // developer sweeping the whole suite does not get a deliberate abort in their face.
        return;
    };
    let fixture = fixture(affordance == "allow_unlaunched_host");
    // Unreachable in a release build, because `ExtensionAgent::start` asserts first.
    #[cfg(not(debug_assertions))]
    panic!("a release build must have aborted before reaching this line");
    drop(fixture);
}

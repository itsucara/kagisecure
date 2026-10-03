//! The dependency-graph rules from `src/lib.rs`, asserted.
//!
//! Two rules, both about edges rather than code, because both would stop being true without a
//! line of the affected crate's source changing:
//!
//! 1. **No agent-facing crate reaches this one, or the public-key cryptography beneath it.**
//!    `kagisecure-mcp` and `kagisecure-ipc` hold the ADR-0002 property that they *cannot* name
//!    `kagisecure_core::Secret`; `kagisecure-extension-ipc` and `kagisecure-nmhost` carry the
//!    browser channel. An edge from any of them to this crate would switch `secret-material` on
//!    for them through Cargo's feature unification and put the code that decrypts shared values,
//!    and changes rosters, within reach of a process an agent or a web page talks to (ADR-0035
//!    §4, §14).
//! 2. **This crate reaches no network code.** Shared vaults are exchanged by people, as files;
//!    kagisecure adds no socket, no HTTP client, no git client and no sync service (ADR-0035 §7,
//!    architecture §9, threat-model N-9). A network client, a socket library or an async runtime
//!    anywhere beneath this crate would be the first step away from that, so its arrival fails
//!    here. `deny.toml` bans the network crates for the whole workspace as well.
//!
//! The graph is `cargo metadata`'s resolve graph for the whole workspace, with every feature and
//! every platform, and every dependency kind — normal, build and dev — because a dev-dependency
//! edge today is a one-word change from a normal one.

use std::collections::{HashMap, HashSet};
use std::process::Command;

/// The package under test.
const THIS_CRATE: &str = "kagisecure-shared";

/// The agent- and browser-facing crates that must not reach this crate, however indirectly.
const FORBIDDEN_DEPENDENTS: &[&str] = &[
    "kagisecure-mcp",
    "kagisecure-ipc",
    "kagisecure-extension-ipc",
    "kagisecure-nmhost",
];

/// What those crates must not reach besides this crate: the public-key cryptography only this
/// crate's subtree carries.
const PUBLIC_KEY_CRATES: &[&str] = &[
    "hpke",
    "ed25519",
    "ed25519-dalek",
    "x25519-dalek",
    "curve25519-dalek",
    // Not in the graph today; the likely arrivals for a later suite (ADR-0035 §4: P-256 for
    // Secure Enclave-held keys) or a careless dependency, and just as unwelcome in those crates.
    "p256",
    "ecdsa",
    "elliptic-curve",
    "rsa",
];

/// What this crate must not reach: network clients and servers, TLS, git clients, socket
/// libraries and async runtimes.
const NETWORK_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "h2",
    "rustls",
    "native-tls",
    "openssl",
    "isahc",
    "git2",
    "gix",
    "hyper-util",
    "attohttpc",
    "minreq",
    "surf",
    "tungstenite",
    "tokio-tungstenite",
    "quinn",
    "hickory-resolver",
    "trust-dns-resolver",
    "openssl-sys",
    "curl-sys",
    "ssh2",
    "libssh2-sys",
    "gix-transport",
    "gix-protocol",
    "socket2",
    "mio",
    "tokio",
    "interprocess",
];

/// `cargo metadata`'s resolve graph, as `package name → dependency names`.
fn dependency_graph() -> HashMap<String, Vec<String>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--manifest-path",
            manifest,
        ])
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON");
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve.nodes");

    // Package ids are opaque; map them to names once and then work in names.
    let mut names: HashMap<&str, String> = HashMap::new();
    for package in metadata["packages"].as_array().expect("packages") {
        names.insert(
            package["id"].as_str().expect("package id"),
            package["name"].as_str().expect("package name").to_owned(),
        );
    }

    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    for node in nodes {
        let id = node["id"].as_str().expect("node id");
        let Some(name) = names.get(id) else { continue };
        let deps = node["dependencies"]
            .as_array()
            .expect("node dependencies")
            .iter()
            .filter_map(|d| names.get(d.as_str().expect("dependency id")).cloned())
            .collect();
        graph
            .entry(name.clone())
            .or_default()
            .extend::<Vec<String>>(deps);
    }
    graph
}

/// Every crate reachable from `root`, itself excluded.
fn reachable_from(graph: &HashMap<String, Vec<String>>, root: &str) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut stack = vec![root.to_owned()];
    while let Some(name) = stack.pop() {
        for dep in graph.get(&name).into_iter().flatten() {
            if seen.insert(dep.clone()) {
                stack.push(dep.clone());
            }
        }
    }
    seen
}

#[test]
fn no_agent_or_browser_facing_crate_reaches_the_shared_crate_or_its_public_key_cryptography() {
    let graph = dependency_graph();
    assert!(
        graph.contains_key(THIS_CRATE),
        "the resolve graph has no {THIS_CRATE}; the test is not measuring anything"
    );

    for crate_name in FORBIDDEN_DEPENDENTS {
        assert!(
            graph.contains_key(*crate_name),
            "the resolve graph has no {crate_name}; the test is not measuring anything"
        );
        let reachable = reachable_from(&graph, crate_name);
        assert!(
            !reachable.contains(THIS_CRATE),
            "{crate_name} depends on {THIS_CRATE}, which enables kagisecure-core's \
             secret-material feature and decrypts shared records — see this crate's lib.rs, \
             ADR-0002 and ADR-0035 §4, §14"
        );
        for public_key_crate in PUBLIC_KEY_CRATES {
            assert!(
                !reachable.contains(*public_key_crate),
                "{crate_name} reached {public_key_crate}, which only the shared crate's subtree \
                 carries"
            );
        }
    }
}

#[test]
fn the_shared_crate_reaches_no_network_code() {
    let graph = dependency_graph();
    let reachable = reachable_from(&graph, THIS_CRATE);
    let found: Vec<&str> = NETWORK_CRATES
        .iter()
        .copied()
        .filter(|name| reachable.contains(*name))
        .collect();
    assert!(
        found.is_empty(),
        "{THIS_CRATE} reaches {found:?}: shared vaults are exchanged as files, with no network \
         code (ADR-0035 §7, threat-model N-9)"
    );
}

#[test]
fn the_shared_crate_does_reach_the_core_and_its_cryptography() {
    // The negative assertions above are only worth something if the positive ones hold: this is
    // what a graph that is actually being read looks like.
    let graph = dependency_graph();
    let reachable = reachable_from(&graph, THIS_CRATE);
    for expected in [
        "kagisecure-core",
        "hpke",
        "ed25519-dalek",
        "curve25519-dalek",
        "x25519-dalek",
    ] {
        assert!(
            reachable.contains(expected),
            "{THIS_CRATE} does not reach {expected}; the graph is not being read correctly"
        );
    }
    // And the network list names crates that really are in the workspace graph elsewhere, so it
    // is not checking for names that could never appear: the MCP sidecar runs on tokio, and the
    // IPC layer on interprocess.
    assert!(reachable_from(&graph, "kagisecure-mcp").contains("tokio"));
    assert!(reachable_from(&graph, "kagisecure-ipc").contains("interprocess"));
}

/// The crates that serve agents and browsers, or carry what they say, whose source must never
/// name [`kagisecure_shared::admin`] (ADR-0035 §14; decision 29). `kagisecure-agent` depends on
/// this crate to read shared vaults and release their values; the other four do not depend on it
/// at all (the test above) and are listed so that they never start.
const ADMIN_FREE_CRATES: &[&str] = &[
    "kagisecure-agent",
    "kagisecure-ipc",
    "kagisecure-mcp",
    "kagisecure-extension-ipc",
    "kagisecure-nmhost",
];

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether `source` names this crate's `admin` module: a path through it, or `admin` inside a
/// `use kagisecure_shared::{…}` group. Whitespace is ignored, so a line break cannot hide it.
fn names_admin(source: &str) -> bool {
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("kagisecure_shared::admin") {
        return true;
    }
    let mut rest = compact.as_str();
    while let Some(at) = rest.find("kagisecure_shared::{") {
        let group = &rest[at + "kagisecure_shared::{".len()..];
        let mut depth = 1usize;
        let mut end = group.len();
        for (i, c) in group.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = &group[..end];
        if inner
            .split([',', '{', '}'])
            .any(|part| part == "admin" || part.starts_with("admin::"))
        {
            return true;
        }
        rest = &group[end..];
    }
    false
}

/// No agent or browser can change who a vault is shared with (ADR-0035 §14): the one module that
/// creates, invites, joins, removes, imports and exports is out of reach of every crate an agent
/// or a web page talks to — by their source, not only by their dependency graph, since
/// `kagisecure-agent` does depend on this crate.
#[test]
fn no_agent_facing_crate_names_the_admin_module() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory");
    for name in ADMIN_FREE_CRATES {
        let mut files = Vec::new();
        rust_files(&crates.join(name).join("src"), &mut files);
        assert!(!files.is_empty(), "{name} has sources to check");
        for file in files {
            let source = std::fs::read_to_string(&file).expect("read a source file");
            assert!(
                !names_admin(&source),
                "{} names kagisecure_shared::admin, which no agent-facing crate may reach",
                file.display()
            );
        }
    }
}

#[test]
fn the_admin_check_sees_through_groups_and_line_breaks() {
    assert!(names_admin("use kagisecure_shared::admin::create;"));
    assert!(names_admin(
        "kagisecure_shared::\n    admin::enroll::join(x)"
    ));
    assert!(names_admin("use kagisecure_shared::{read, admin};"));
    assert!(names_admin(
        "use kagisecure_shared::{read::Snapshot, admin::{create}};"
    ));
    assert!(!names_admin(
        "use kagisecure_shared::{read::SharedSnapshot, DeviceSecret};"
    ));
    assert!(!names_admin("let administrator = 1;"));
}

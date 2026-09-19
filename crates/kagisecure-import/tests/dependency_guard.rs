//! The dependency-graph rule from `src/lib.rs`, asserted.
//!
//! `kagisecure-mcp` and `kagisecure-ipc` are the two crates whose security property is "they
//! cannot name [`kagisecure_core::Secret`]" — they depend on the core with
//! `default-features = false`, so the `secret-material` feature is not in their build graph and a
//! tool that returned a value would not compile (ADR-0002 §3 point 2).
//!
//! `kagisecure-import` enables that feature. An edge from either sidecar crate to this one would
//! switch it on for them — not through any change to their source, but through Cargo's feature
//! unification — and the whole structural argument would quietly stop being true.
//!
//! `crates/kagisecure-cli/tests/mcp.rs` asserts the feature's absence from the *running* sidecar.
//! This test asserts the edge that would cause it, and it lives here rather than in the CLI's test
//! target on purpose: the crate whose existence creates the hazard is the one that should carry
//! the test, so that deleting this crate deletes the test with it and adding a consumer is the
//! moment someone reads the reason.

use std::collections::{HashMap, HashSet};
use std::process::Command;

/// The crates that must not reach `kagisecure-import`, however indirectly.
const FORBIDDEN_DEPENDENTS: &[&str] = &["kagisecure-mcp", "kagisecure-ipc"];

/// The package under test.
const THIS_CRATE: &str = "kagisecure-import";

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
        graph.insert(name.clone(), deps);
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
fn the_sidecar_crates_do_not_depend_on_the_import_crate() {
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
             secret-material feature — see this crate's lib.rs and ADR-0002 §3"
        );
        // The parser dependencies are the concrete shape of the widening this forbids. Only the
        // ones this crate is the sole source of: `serde_json` is an honest dependency of the
        // sidecar and the IPC layer in their own right, so its presence says nothing.
        for parser in ["zip", "csv", "flate2"] {
            assert!(
                !reachable.contains(parser),
                "{crate_name} reached {parser}, which only the import crate's subtree carries"
            );
        }
    }
}

#[test]
fn the_import_crate_does_reach_the_core_and_its_parsers() {
    // The negative assertions above are only worth something if the positive ones hold: this is
    // what a graph that is actually being read looks like.
    let graph = dependency_graph();
    let reachable = reachable_from(&graph, THIS_CRATE);
    for expected in ["kagisecure-core", "zip", "csv", "serde_json"] {
        assert!(
            reachable.contains(expected),
            "{THIS_CRATE} does not reach {expected}; the graph is not being read correctly"
        );
    }
}

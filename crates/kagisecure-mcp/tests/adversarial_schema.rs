//! Adversarial tests against the MCP surface as a *client* actually sees it.
//!
//! `src/server.rs` already has unit tests that walk `tool_router().list_all()`. Those check the
//! schemas as Rust values. This file checks the bytes: it spawns the real `kagisecure-mcp`
//! binary, speaks real JSON-RPC to its stdio, and inspects exactly what a model would be handed
//! — `tools/list` in full, including every nested `$defs`, `oneOf`, `anyOf` and `allOf` branch
//! that a `schemars` derive may have introduced without anyone noticing.
//!
//! The claim under test is the product's central one: **there is no way to ask for a value.**
//! Not a tool, not an argument, not an enum variant, not a branch of a union three levels down in
//! a generated schema. A property that appeared there would widen the surface silently, because
//! nobody reads a generated schema by hand.
//!
//! No agent socket is needed: listing tools is answered by the sidecar itself, which is the point
//! — the surface is fixed at compile time and does not depend on what a vault happens to contain.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Property names that would each represent a way to ask for, or hand back, a secret value.
const FORBIDDEN_PROPERTY_SUBSTRINGS: [&str; 10] = [
    "value",
    "secret",
    "password",
    "reveal",
    "plaintext",
    "unmask",
    "no_masking",
    "passphrase",
    "credential_data",
    "decrypt",
];

/// The sidecar's file name, matching `kagisecure-agent`'s `bundle::SIDECAR` (this crate has no
/// dependency on that one, so the constant is repeated rather than imported).
#[cfg(windows)]
const SIDECAR_BIN: &str = "kagisecure-mcp.exe";
#[cfg(not(windows))]
const SIDECAR_BIN: &str = "kagisecure-mcp";

/// The sidecar binary, built on demand — see `kagisecure_test_support::binary`, the shared helper
/// `kagisecure-agent`'s `sidecar.rs` and `extension.rs` also use, so `cargo test -p kagisecure-mcp`
/// alone does not silently skip, and a hardcoded `target/debug` never gets a second chance to be
/// wrong here.
fn sidecar() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-mcp", SIDECAR_BIN)
}

struct RawSidecar {
    /// Kept alive for the child's lifetime: it holds the socket path the sidecar was told about.
    _dir: tempfile::TempDir,
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl RawSidecar {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // A socket that does not exist: nothing here needs a daemon, and pointing at a real one
        // would make the test depend on a vault.
        let socket = dir.path().join("no-such-agent.sock");
        let mut child = Command::new(sidecar())
            .current_dir(dir.path())
            .env("KAGISECURE_SOCKET", &socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning kagisecure-mcp");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut me = Self {
            _dir: dir,
            child,
            stdout,
            next_id: 0,
        };
        me.call(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "adversarial-schema-walk", "version": "0"}
            }),
        );
        let body = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        me.send(&body);
        me
    }

    fn send(&mut self, value: &serde_json::Value) {
        let stdin = self.child.stdin.as_mut().expect("piped");
        writeln!(stdin, "{value}").expect("writing to the sidecar");
        stdin.flush().expect("flush");
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }));
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .expect("reading the sidecar");
            assert!(read > 0, "the sidecar closed its stdout");
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if value.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                return value;
            }
        }
    }
}

impl Drop for RawSidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Every `properties` key anywhere in a JSON Schema value, with the JSON pointer that reached it.
///
/// Deliberately blind to structure: it descends into `$defs`, `definitions`, `oneOf`, `anyOf`,
/// `allOf`, `items`, `additionalProperties`, `patternProperties` and anything else, because the
/// point is to be unable to miss a branch a future `schemars` version invents.
fn collect_properties(schema: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    match schema {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if (key == "properties" || key == "patternProperties")
                    && let Some(props) = value.as_object()
                {
                    for name in props.keys() {
                        out.push((name.clone(), format!("{path}/{key}/{name}")));
                    }
                }
                collect_properties(value, &format!("{path}/{key}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_properties(item, &format!("{path}/{index}"), out);
            }
        }
        _ => {}
    }
}

/// Every string that appears as an `enum` member or a `const`, anywhere.
fn collect_enum_members(schema: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    match schema {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "enum"
                    && let Some(members) = value.as_array()
                {
                    for member in members.iter().filter_map(serde_json::Value::as_str) {
                        out.push((member.to_owned(), format!("{path}/enum")));
                    }
                }
                if key == "const"
                    && let Some(member) = value.as_str()
                {
                    out.push((member.to_owned(), format!("{path}/const")));
                }
                collect_enum_members(value, &format!("{path}/{key}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_enum_members(item, &format!("{path}/{index}"), out);
            }
        }
        _ => {}
    }
}

fn tools() -> Vec<serde_json::Value> {
    let mut sidecar = RawSidecar::start();
    let listed = sidecar.call("tools/list", serde_json::json!({}));
    listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list returned {listed}"))
        .clone()
}

/// A-23: no property named after a value exists anywhere in any schema the client is served.
#[test]
fn no_property_anywhere_in_any_served_schema_asks_for_a_value() {
    let tools = tools();
    assert!(!tools.is_empty(), "the sidecar served no tools at all");

    let mut checked = 0_usize;
    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>").to_owned();
        for key in ["inputSchema", "outputSchema"] {
            let Some(schema) = tool.get(key) else {
                continue;
            };
            let mut found = Vec::new();
            collect_properties(schema, &format!("{name}.{key}"), &mut found);
            checked += found.len();
            for (property, pointer) in &found {
                let lowered = property.to_lowercase();
                for forbidden in FORBIDDEN_PROPERTY_SUBSTRINGS {
                    assert!(
                        !lowered.contains(forbidden),
                        "{pointer} is a property named {property:?}, which contains {forbidden:?}"
                    );
                }
            }
        }
    }
    assert!(
        checked > 10,
        "the walk found only {checked} properties, which suggests it is not descending"
    );
}

/// The same question for enum members: a mode called `plaintext` would be a value switch.
#[test]
fn no_enum_member_anywhere_in_any_served_schema_offers_an_unmasked_mode() {
    let tools = tools();
    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>").to_owned();
        for key in ["inputSchema", "outputSchema"] {
            let Some(schema) = tool.get(key) else {
                continue;
            };
            let mut found = Vec::new();
            collect_enum_members(schema, &format!("{name}.{key}"), &mut found);
            for (member, pointer) in &found {
                let lowered = member.to_lowercase();
                for forbidden in ["plaintext", "reveal", "unmask", "raw_value", "secret"] {
                    assert!(
                        !lowered.contains(forbidden),
                        "{pointer} offers {member:?}, which contains {forbidden:?}"
                    );
                }
            }
        }
    }
}

/// The tool list itself is the documented one and nothing more.
///
/// A tool the documentation does not name is a tool nobody reviewed, so the set is pinned here
/// against the bytes on the wire rather than against the router in the same crate.
#[test]
fn the_served_tool_list_is_exactly_the_documented_one() {
    let mut names: Vec<String> = tools()
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "add_variables",
            "create_environment",
            "create_test_login",
            "describe_item",
            "list_environments",
            "list_items",
            "list_test_logins",
            "list_vaults",
            "request_fill",
            "request_type",
            "revoke_env_file",
            "run_with_env",
            "store_command_output",
            "trash_test_logins",
            "write_env_file",
        ]
    );
}

/// A tool whose schema names `$ref` must have the target present, or the walk above was blind.
///
/// This is the test that keeps the two above honest: if `schemars` started emitting references
/// to definitions the sidecar does not serve, the property walk would silently stop at the
/// reference and report success on a schema it never saw.
#[test]
fn every_schema_reference_resolves_inside_the_schema_that_names_it() {
    for tool in &tools() {
        let name = tool["name"].as_str().unwrap_or("<unnamed>").to_owned();
        for key in ["inputSchema", "outputSchema"] {
            let Some(schema) = tool.get(key) else {
                continue;
            };
            let rendered = serde_json::to_string(schema).expect("serialize");
            let mut refs = Vec::new();
            collect_refs(schema, &mut refs);
            for reference in refs {
                let Some(fragment) = reference.strip_prefix("#/") else {
                    panic!("{name}.{key} names an external reference {reference:?}");
                };
                let last = fragment.rsplit('/').next().unwrap_or_default();
                assert!(
                    rendered.contains(&format!("\"{last}\"")),
                    "{name}.{key} refers to {reference:?}, which is not in the schema served"
                );
            }
        }
    }
}

fn collect_refs(schema: &serde_json::Value, out: &mut Vec<String>) {
    match schema {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref"
                    && let Some(target) = value.as_str()
                {
                    out.push(target.to_owned());
                }
                collect_refs(value, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_refs(item, out);
            }
        }
        _ => {}
    }
}

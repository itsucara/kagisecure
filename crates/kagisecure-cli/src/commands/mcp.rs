//! `kagisecure mcp path` and `kagisecure mcp install` (mcp-server.md §9).
//!
//! The path an MCP client needs is not knowable from a document — it depends on where the binary
//! actually landed. So the CLI prints it, and prints the exact configuration snippet around it.
//!
//! `install` **prints** by default. Editing a user's editor configuration behind their back is
//! not something a secrets manager should do casually, so writing is opt-in with `--write`, and
//! even then it only ever touches that client's own standard file.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kagisecure_agent::setup::{self, SIDECAR, SetupClient};

use crate::cli::{McpClient, McpInstallArgs};

/// How the CLI's client flag maps onto the shared table in `kagisecure-agent`.
fn shared(client: McpClient) -> SetupClient {
    match client {
        McpClient::ClaudeCode => SetupClient::ClaudeCode,
        McpClient::ClaudeDesktop => SetupClient::ClaudeDesktop,
        McpClient::Codex => SetupClient::Codex,
        McpClient::Cursor => SetupClient::Cursor,
    }
}

/// Where the `kagisecure-mcp` binary is.
///
/// The search itself lives in [`kagisecure_agent::setup::sidecar_path`], so the CLI and the app's
/// "Set up your agent" screen cannot disagree about which binary they are telling a client to
/// spawn (mcp-server.md §9).
///
/// # Errors
///
/// If it is in none of the places that search looks.
pub fn sidecar_path() -> Result<PathBuf> {
    setup::sidecar_path(None).with_context(|| {
        format!(
            "could not find {SIDECAR} next to this binary, inside {}, or on PATH. Install the \
             app from the DMG, `brew install --cask kagisecure`, or build it with \
             `cargo build -p kagisecure-mcp`.",
            kagisecure_agent::bundle::INSTALLED_APP
        )
    })
}

/// `kagisecure mcp path`.
///
/// # Errors
///
/// If the sidecar cannot be found.
pub fn path() -> Result<()> {
    println!("{}", sidecar_path()?.display());
    Ok(())
}

/// `kagisecure mcp install`.
///
/// # Errors
///
/// If the sidecar cannot be found, or `--write` was given and the file cannot be updated.
pub fn install(args: &McpInstallArgs) -> Result<()> {
    let sidecar = sidecar_path()?;
    let snippet = snippet_for(args.client, &sidecar);

    if !args.write {
        println!("{}", snippet.body);
        if let Some(target) = config_path(args.client) {
            println!();
            println!("# Put that in: {}", target.display());
            println!(
                "# Or let kagisecure do it: kagisecure mcp install {} --write",
                flag(args.client)
            );
        }
        return Ok(());
    }

    match args.client {
        McpClient::ClaudeCode => {
            bail!(
                "Claude Code keeps its MCP registry itself; there is no file to write. Run the \
                 command printed by `kagisecure mcp install claude-code`."
            );
        }
        McpClient::ClaudeDesktop | McpClient::Cursor => {
            let target = config_path(args.client).context("no standard config path")?;
            write_json_config(&target, &sidecar)?;
            println!("Updated {}", target.display());
        }
        McpClient::Codex => {
            let target = config_path(args.client).context("no standard config path")?;
            append_toml_config(&target, &sidecar)?;
            println!("Updated {}", target.display());
        }
    }
    println!("Restart the client so it picks the server up.");
    Ok(())
}

/// A rendered configuration snippet.
pub struct Snippet {
    /// What to show the user.
    pub body: String,
}

fn flag(client: McpClient) -> &'static str {
    match client {
        McpClient::ClaudeCode => "claude-code",
        McpClient::ClaudeDesktop => "claude-desktop",
        McpClient::Codex => "codex",
        McpClient::Cursor => "cursor",
    }
}

/// The snippet for one client.
#[must_use]
pub fn snippet_for(client: McpClient, sidecar: &Path) -> Snippet {
    Snippet {
        body: setup::snippet_for(shared(client), sidecar).body,
    }
}

/// That client's standard configuration file, when it has one.
#[must_use]
pub fn config_path(client: McpClient) -> Option<PathBuf> {
    setup::config_path(shared(client))
}

/// Merge our entry into a client's JSON config, preserving everything else in the file.
fn write_json_config(target: &Path, sidecar: &Path) -> Result<()> {
    let mut root: serde_json::Value = if target.exists() {
        let text = std::fs::read_to_string(target)
            .with_context(|| format!("reading {}", target.display()))?;
        if text.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&text)
                .with_context(|| format!("{} is not valid JSON; fix it first", target.display()))?
        }
    } else {
        serde_json::json!({})
    };

    let servers = root
        .as_object_mut()
        .context("the config file's top level is not a JSON object")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    servers
        .as_object_mut()
        .context("\"mcpServers\" is not a JSON object")?
        .insert(
            "kagisecure".to_owned(),
            serde_json::json!({
                "command": sidecar.display().to_string(),
                "args": [],
            }),
        );

    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        target,
        format!("{}\n", serde_json::to_string_pretty(&root)?),
    )?;
    Ok(())
}

/// Append our table to Codex's TOML config if it is not already there.
///
/// Deliberately not a TOML round-trip: rewriting a user's whole config to add four lines risks
/// losing comments and ordering, and appending is both safe and reviewable.
fn append_toml_config(target: &Path, sidecar: &Path) -> Result<()> {
    let existing = if target.exists() {
        std::fs::read_to_string(target)?
    } else {
        String::new()
    };
    if existing.contains("[mcp_servers.kagisecure]") {
        bail!(
            "{} already has an [mcp_servers.kagisecure] entry; edit it by hand rather than \
             ending up with two.",
            target.display()
        );
    }
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&snippet_for(McpClient::Codex, sidecar).body);
    out.push('\n');
    std::fs::write(target, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_claude_code_snippet_is_the_command_from_the_docs() {
        let s = snippet_for(McpClient::ClaudeCode, Path::new("/opt/bin/kagisecure-mcp"));
        assert!(s.body.contains(
            "claude mcp add --transport stdio kagisecure -s local -- /opt/bin/kagisecure-mcp"
        ));
        assert!(s.body.contains("claude mcp remove kagisecure -s local"));
    }

    #[test]
    fn the_json_snippets_parse_as_json() {
        for client in [McpClient::ClaudeDesktop, McpClient::Cursor] {
            let s = snippet_for(client, Path::new("/opt/bin/kagisecure-mcp"));
            let parsed: serde_json::Value = serde_json::from_str(&s.body).unwrap();
            assert_eq!(
                parsed["mcpServers"]["kagisecure"]["command"],
                "/opt/bin/kagisecure-mcp"
            );
        }
    }

    #[test]
    fn the_codex_snippet_is_the_documented_table() {
        let s = snippet_for(McpClient::Codex, Path::new("/opt/bin/kagisecure-mcp"));
        assert!(s.body.starts_with("[mcp_servers.kagisecure]"));
        assert!(s.body.contains("command = \"/opt/bin/kagisecure-mcp\""));
    }

    #[test]
    fn writing_json_preserves_everything_else_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("claude_desktop_config.json");
        std::fs::write(
            &target,
            r#"{"theme":"dark","mcpServers":{"other":{"command":"/bin/true"}}}"#,
        )
        .unwrap();

        write_json_config(&target, Path::new("/opt/bin/kagisecure-mcp")).unwrap();

        let back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(back["theme"], "dark");
        assert_eq!(back["mcpServers"]["other"]["command"], "/bin/true");
        assert_eq!(
            back["mcpServers"]["kagisecure"]["command"],
            "/opt/bin/kagisecure-mcp"
        );
    }

    #[test]
    fn writing_json_creates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested").join("mcp.json");
        write_json_config(&target, Path::new("/opt/bin/kagisecure-mcp")).unwrap();
        assert!(target.exists());
    }

    #[test]
    fn appending_toml_refuses_to_duplicate_an_entry() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "model = \"gpt\"\n").unwrap();
        append_toml_config(&target, Path::new("/opt/bin/kagisecure-mcp")).unwrap();
        let text = std::fs::read_to_string(&target).unwrap();
        assert!(text.starts_with("model = \"gpt\"\n"));
        assert!(text.contains("[mcp_servers.kagisecure]"));

        assert!(append_toml_config(&target, Path::new("/opt/bin/kagisecure-mcp")).is_err());
    }

    #[test]
    fn claude_code_has_no_file_to_write() {
        assert!(config_path(McpClient::ClaudeCode).is_none());
        assert!(config_path(McpClient::Codex).is_some());
    }
}

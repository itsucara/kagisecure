//! "Set up your agent": where the sidecar is, and what to paste into each MCP client.
//!
//! mcp-server.md §9 says the app's setup screen shows the exact path for the current install and
//! copies these snippets, and that `kagisecure mcp install --print` emits the same thing. Two
//! renderings of one table is one rendering too many, so the table lives here and both callers
//! read it: the CLI directly, the app through `kagisecure-ffi`.

use std::path::{Path, PathBuf};

/// The sidecar's file name. Re-exported from [`crate::bundle`], which owns the search.
pub use crate::bundle::SIDECAR;

/// Points the sidecar search at a build a developer made. See [`crate::bundle::find`] for where
/// it sits in the order: after a bundled copy, before everything else.
pub const SIDECAR_ENV: &str = "KAGISECURE_MCP";

/// The MCP clients mcp-server.md §9 has snippets for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupClient {
    /// Claude Code — a command to run, not a file to write.
    ClaudeCode,
    /// Claude Desktop — `claude_desktop_config.json`.
    ClaudeDesktop,
    /// OpenAI Codex CLI — `~/.codex/config.toml`.
    Codex,
    /// Cursor — `.cursor/mcp.json`.
    Cursor,
}

impl SetupClient {
    /// Every client, in the order the setup screen lists them.
    #[must_use]
    pub fn all() -> [Self; 4] {
        [
            Self::ClaudeCode,
            Self::ClaudeDesktop,
            Self::Codex,
            Self::Cursor,
        ]
    }

    /// The display name.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::Codex => "OpenAI Codex CLI",
            Self::Cursor => "Cursor",
        }
    }

    /// The `kagisecure mcp install` flag spelling.
    #[must_use]
    pub fn flag(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::ClaudeDesktop => "claude-desktop",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    /// What language the snippet is in, for a syntax label in the UI.
    #[must_use]
    pub fn language(self) -> &'static str {
        match self {
            Self::ClaudeCode => "shell",
            Self::ClaudeDesktop | Self::Cursor => "json",
            Self::Codex => "toml",
        }
    }
}

/// One client's snippet, ready to render with a copy button.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snippet {
    /// Which client it is for.
    pub client: SetupClient,
    /// Its display name.
    pub title: String,
    /// `shell`, `json` or `toml`.
    pub language: String,
    /// The text to copy.
    pub body: String,
    /// Where it goes, when the client has a file. Claude Code has none.
    pub config_path: Option<String>,
}

/// Where the `kagisecure-mcp` binary is.
///
/// `hint` is the app's own `Contents/Helpers`, which is where architecture.md §8 puts the bundled
/// sidecar. The order — bundled copy, then `KAGISECURE_MCP`, then beside the running executable,
/// then an installed `Kagisecure.app`, then `PATH` — is [`crate::bundle::find`]'s, shared with
/// the native messaging host so that the two cannot disagree.
#[must_use]
pub fn sidecar_path(hint: Option<&Path>) -> Option<PathBuf> {
    crate::bundle::find(SIDECAR, hint, SIDECAR_ENV)
}

/// The sidecar path an install *would* have, for a screen that found nothing and has to say so.
#[must_use]
pub fn placeholder_sidecar_path() -> PathBuf {
    crate::bundle::installed_helper(SIDECAR)
}

/// The snippet for one client.
#[must_use]
pub fn snippet_for(client: SetupClient, sidecar: &Path) -> Snippet {
    let path = sidecar.display();
    let body = match client {
        SetupClient::ClaudeCode => format!(
            "# Claude Code — run this once, in the project you want kagisecure available in:\n\
             claude mcp add --transport stdio kagisecure -s local -- {path}\n\
             \n\
             # Check it:\n\
             claude mcp list\n\
             \n\
             # And remove it again with:\n\
             claude mcp remove kagisecure -s local"
        ),
        SetupClient::ClaudeDesktop | SetupClient::Cursor => format!(
            "{{\n  \"mcpServers\": {{\n    \"kagisecure\": {{\n      \"command\": \"{path}\",\n      \"args\": []\n    }}\n  }}\n}}"
        ),
        SetupClient::Codex => {
            format!("[mcp_servers.kagisecure]\ncommand = \"{path}\"\nargs = []")
        }
    };
    Snippet {
        client,
        title: client.title().to_owned(),
        language: client.language().to_owned(),
        body,
        config_path: config_path(client).map(|p| p.display().to_string()),
    }
}

/// Every snippet, for the setup screen.
#[must_use]
pub fn all_snippets(sidecar: &Path) -> Vec<Snippet> {
    SetupClient::all()
        .into_iter()
        .map(|c| snippet_for(c, sidecar))
        .collect()
}

/// That client's standard configuration file, when it has one.
#[must_use]
pub fn config_path(client: SetupClient) -> Option<PathBuf> {
    let dirs = directories::BaseDirs::new()?;
    let home = dirs.home_dir();
    match client {
        SetupClient::ClaudeCode => None,
        SetupClient::ClaudeDesktop => {
            #[cfg(target_os = "macos")]
            {
                Some(
                    home.join("Library")
                        .join("Application Support")
                        .join("Claude")
                        .join("claude_desktop_config.json"),
                )
            }
            #[cfg(not(target_os = "macos"))]
            {
                Some(
                    home.join(".config")
                        .join("Claude")
                        .join("claude_desktop_config.json"),
                )
            }
        }
        SetupClient::Codex => Some(home.join(".codex").join("config.toml")),
        SetupClient::Cursor => Some(home.join(".cursor").join("mcp.json")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_claude_code_snippet_is_the_command_from_the_docs() {
        let s = snippet_for(
            SetupClient::ClaudeCode,
            Path::new("/opt/bin/kagisecure-mcp"),
        );
        assert!(s.body.contains(
            "claude mcp add --transport stdio kagisecure -s local -- /opt/bin/kagisecure-mcp"
        ));
        assert!(s.body.contains("claude mcp remove kagisecure -s local"));
        assert!(s.config_path.is_none(), "Claude Code has no file to write");
    }

    #[test]
    fn the_json_snippets_parse_as_json() {
        for client in [SetupClient::ClaudeDesktop, SetupClient::Cursor] {
            let s = snippet_for(client, Path::new("/opt/bin/kagisecure-mcp"));
            let parsed: serde_json::Value = serde_json::from_str(&s.body).expect("valid json");
            assert_eq!(
                parsed["mcpServers"]["kagisecure"]["command"],
                "/opt/bin/kagisecure-mcp"
            );
        }
    }

    #[test]
    fn the_codex_snippet_is_the_documented_table() {
        let s = snippet_for(SetupClient::Codex, Path::new("/opt/bin/kagisecure-mcp"));
        assert!(s.body.starts_with("[mcp_servers.kagisecure]"));
        assert!(s.body.contains("command = \"/opt/bin/kagisecure-mcp\""));
    }

    #[test]
    fn every_client_has_a_snippet_and_a_language() {
        let all = all_snippets(Path::new("/opt/bin/kagisecure-mcp"));
        assert_eq!(all.len(), 4);
        for snippet in all {
            assert!(!snippet.body.is_empty());
            assert!(["shell", "json", "toml"].contains(&snippet.language.as_str()));
            assert!(snippet.body.contains("/opt/bin/kagisecure-mcp"));
        }
    }

    #[test]
    fn a_hint_directory_wins_over_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join(SIDECAR);
        std::fs::write(&fake, b"#!/bin/sh\n").expect("write");
        assert_eq!(sidecar_path(Some(dir.path())), Some(fake));
    }

    /// The path a screen shows when it found nothing must be the one a real install has —
    /// otherwise the sentence "install the app and it will be here" points at the wrong place.
    #[test]
    fn the_placeholder_is_where_a_real_install_puts_the_sidecar() {
        let shown = placeholder_sidecar_path();
        assert_eq!(
            shown,
            std::path::PathBuf::from(
                "/Applications/Kagisecure.app/Contents/Helpers/kagisecure-mcp"
            )
        );
        // Every snippet the setup screen renders quotes that path verbatim.
        for snippet in all_snippets(&shown) {
            assert!(snippet.body.contains(&shown.display().to_string()));
        }
    }

    #[test]
    fn a_hint_that_holds_nothing_falls_through() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Whatever this machine has on PATH, the empty hint directory must not be the answer.
        let found = sidecar_path(Some(dir.path()));
        assert!(found.is_none_or(|p| p.parent() != Some(dir.path())));
    }
}

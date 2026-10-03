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

/// Escape a path for a JSON string literal or a TOML basic string.
///
/// The two formats agree on the escapes that a filesystem path can actually need: a backslash
/// and a double quote. Without this a Windows path is pasted into `claude_desktop_config.json`
/// as `"C:\Program Files\..."`, where `\P` and `\k` are invalid escape sequences and the whole
/// file fails to parse — the snippet looks right and the client silently starts no server. The
/// same is true of Codex's TOML, whose basic strings escape identically.
///
/// On macOS and Linux this changes nothing for any path a real install has; it also stops a `"`
/// or `\` in an unusual path from producing a broken snippet there.
fn escape_for_quoted_string(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', r"\\")
        .replace('"', "\\\"")
}

/// Quote the sidecar path for the Claude Code snippet's one shell command line.
///
/// Every other snippet here is JSON or TOML, and [`escape_for_quoted_string`] already handles
/// those. This is the one snippet that is a shell command, and a command line's quoting rules
/// come from the shell that runs it — a fact about the platform, not a formatting preference —
/// so which shell it targets is decided here, once, at compile time, rather than guessed at
/// render time for a shell nobody asked about:
///
/// * **Windows** targets PowerShell, the default shell Windows Terminal opens (`cmd.exe` and
///   PowerShell quote differently, and PowerShell is the one a fresh install actually lands in).
///   [`quote_for_powershell`] wraps the path in single quotes and doubles any embedded `'`, which
///   is PowerShell's own escape for a literal quote inside a single-quoted string. No `&`-call
///   operator is needed: `&` is only required when a quoted string names the *command itself*
///   (`& 'C:\Program Files\...\foo.exe'`); here the path is one **argument** to `claude`, which is
///   already the command, so `claude mcp add ... -- 'C:\Program Files\...'` parses as a single
///   argument on its own.
/// * **Everywhere else** targets a POSIX shell (`sh`/`bash`/`zsh` — what a terminal on macOS or
///   Linux actually runs). [`quote_for_posix_shell`] leaves the path bare when it contains none of
///   a POSIX shell's special characters, which is every path an ordinary install has today and is
///   what `the_claude_code_snippet_is_the_command_from_the_docs` pins verbatim; only a path that
///   actually needs it — a space being the realistic case, since macOS is happy to put an app
///   under `~/Library/Application Support/...` — is single-quoted, with an embedded `'`
///   closed-and-reopened as `'\''` (POSIX has no escape *inside* a single-quoted string).
#[must_use]
fn quote_for_shell(path: &Path) -> String {
    let raw = path.display().to_string();
    if cfg!(windows) {
        quote_for_powershell(&raw)
    } else {
        quote_for_posix_shell(&raw)
    }
}

/// PowerShell single-quoting: wrap, doubling any embedded `'`.
///
/// Unlike the POSIX case below there is no "leave it bare" branch: a single-quoted PowerShell
/// string does no interpolation at all, so quoting unconditionally costs nothing and a bare path
/// with a space in it (`C:\Program Files\...`, the common case) would otherwise split into two
/// arguments.
fn quote_for_powershell(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "''"))
}

/// POSIX single-quoting, applied only when the path needs it.
///
/// A path made only of characters no POSIX shell treats specially is returned unchanged — which
/// is what every snippet rendered before this function existed did, and what
/// `the_claude_code_snippet_is_the_command_from_the_docs` continues to assert byte-for-byte.
/// Anything else is wrapped in single quotes, with an embedded `'` closed and reopened as `'\''`.
fn quote_for_posix_shell(raw: &str) -> String {
    const SAFE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-";
    if !raw.is_empty() && raw.chars().all(|c| SAFE.contains(c)) {
        raw.to_owned()
    } else {
        format!("'{}'", raw.replace('\'', r"'\''"))
    }
}

/// The snippet for one client.
#[must_use]
pub fn snippet_for(client: SetupClient, sidecar: &Path) -> Snippet {
    let shell_quoted = quote_for_shell(sidecar);
    let quoted = escape_for_quoted_string(sidecar);
    let body = match client {
        SetupClient::ClaudeCode => format!(
            "# Claude Code — run this once, in the project you want kagisecure available in:\n\
             claude mcp add --transport stdio kagisecure -s local -- {shell_quoted}\n\
             \n\
             # Check it:\n\
             claude mcp list\n\
             \n\
             # And remove it again with:\n\
             claude mcp remove kagisecure -s local"
        ),
        SetupClient::ClaudeDesktop | SetupClient::Cursor => format!(
            "{{\n  \"mcpServers\": {{\n    \"kagisecure\": {{\n      \"command\": \"{quoted}\",\n      \"args\": []\n    }}\n  }}\n}}"
        ),
        SetupClient::Codex => {
            format!("[mcp_servers.kagisecure]\ncommand = \"{quoted}\"\nargs = []")
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
///
/// Only Claude Desktop differs by platform: it follows each OS's own convention for
/// application data, where Codex and Cursor both use a dot-directory in `$HOME` on every
/// platform (`%USERPROFILE%\.codex` and `%USERPROFILE%\.cursor` on Windows, which is what those
/// tools actually read).
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
            // `%APPDATA%` — the roaming one, which is where Claude Desktop for Windows keeps
            // `claude_desktop_config.json`, and not `%LOCALAPPDATA%`, which is where its
            // installed program files go. `BaseDirs::config_dir` is `FOLDERID_RoamingAppData`
            // here, so this is `%APPDATA%\Claude\claude_desktop_config.json`. Falling through to
            // the `~/.config` branch below, as this used to, would have named a directory
            // Windows has no concept of and nothing would ever read.
            #[cfg(windows)]
            {
                Some(
                    dirs.config_dir()
                        .join("Claude")
                        .join("claude_desktop_config.json"),
                )
            }
            // Linux and the BSDs: XDG.
            #[cfg(not(any(target_os = "macos", windows)))]
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
        // Quoted per the shell this build's snippet targets (`quote_for_shell`): bare on a POSIX
        // build, since this path has none of a POSIX shell's special characters and that is what
        // mcp-server.md §9 shows verbatim; single-quoted on a Windows build, since PowerShell
        // quoting is unconditional (`quote_for_powershell`) — a Windows build never renders the
        // macOS doc's exact bytes, only its equivalent for the shell it targets.
        let path = if cfg!(windows) {
            "'/opt/bin/kagisecure-mcp'"
        } else {
            "/opt/bin/kagisecure-mcp"
        };
        assert!(s.body.contains(&format!(
            "claude mcp add --transport stdio kagisecure -s local -- {path}"
        )));
        assert!(s.body.contains("claude mcp remove kagisecure -s local"));
        assert!(s.config_path.is_none(), "Claude Code has no file to write");
    }

    /// PowerShell quoting is exercised directly rather than through `cfg!(windows)`, so this
    /// holds on every platform this crate builds on and not only on a Windows CI runner.
    #[test]
    fn a_plain_path_is_quoted_unconditionally_for_powershell() {
        assert_eq!(
            quote_for_powershell(r"C:\Program Files\Kagisecure\Helpers\kagisecure-mcp.exe"),
            r"'C:\Program Files\Kagisecure\Helpers\kagisecure-mcp.exe'"
        );
    }

    /// PowerShell's escape for a literal `'` inside a single-quoted string is `''`, not `\'`.
    #[test]
    fn an_embedded_single_quote_is_doubled_for_powershell() {
        assert_eq!(
            quote_for_powershell(r"C:\Users\o'brien\kagisecure-mcp.exe"),
            r"'C:\Users\o''brien\kagisecure-mcp.exe'"
        );
    }

    /// The common case — no special characters — is left bare, which is what
    /// `the_claude_code_snippet_is_the_command_from_the_docs` pins for the rendered snippet.
    #[test]
    fn an_ordinary_posix_path_is_left_bare() {
        assert_eq!(
            quote_for_posix_shell("/opt/homebrew/bin/kagisecure-mcp"),
            "/opt/homebrew/bin/kagisecure-mcp"
        );
    }

    /// A space is the realistic case a real macOS install can have
    /// (`~/Library/Application Support/...`), and turns one argument into two if left bare.
    #[test]
    fn a_posix_path_with_a_space_is_single_quoted() {
        assert_eq!(
            quote_for_posix_shell("/Users/x/Application Support/kagisecure-mcp"),
            "'/Users/x/Application Support/kagisecure-mcp'"
        );
    }

    /// POSIX has no escape inside a single-quoted string, so an embedded `'` has to close the
    /// quoting, contribute an escaped quote, and reopen it: `'\''`.
    #[test]
    fn an_embedded_single_quote_closes_and_reopens_the_posix_quoting() {
        assert_eq!(
            quote_for_posix_shell("/Users/o'brien/kagisecure-mcp"),
            r"'/Users/o'\''brien/kagisecure-mcp'"
        );
    }

    /// The snippet actually rendered for `SetupClient::ClaudeCode` reflects whichever shell this
    /// binary targets — asserted end to end, unlike the two tests above which test the quoting
    /// functions directly regardless of host platform.
    #[test]
    fn the_claude_code_snippet_quotes_a_path_with_a_space() {
        let sidecar = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\Program Files\Kagisecure\Helpers\kagisecure-mcp.exe")
        } else {
            std::path::PathBuf::from("/Users/x/Application Support/kagisecure-mcp")
        };
        let expected = if cfg!(windows) {
            quote_for_powershell(&sidecar.display().to_string())
        } else {
            quote_for_posix_shell(&sidecar.display().to_string())
        };
        let s = snippet_for(SetupClient::ClaudeCode, &sidecar);
        assert!(s.body.contains(&format!("-- {expected}")), "{}", s.body);
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

    /// A Windows install path goes into a JSON string and a TOML basic string, both of which
    /// treat `\` as the start of an escape sequence. Asserted on every platform, because the
    /// symptom on Windows — a config file the client refuses to parse, and therefore no server
    /// at all — gives the user nothing to go on, and nobody would think to look at a snippet
    /// that renders perfectly well on a Mac.
    #[test]
    fn a_windows_path_survives_json_and_toml_quoting() {
        let sidecar =
            std::path::PathBuf::from(r"C:\Program Files\Kagisecure\Helpers\kagisecure-mcp.exe");

        for client in [SetupClient::ClaudeDesktop, SetupClient::Cursor] {
            let body = snippet_for(client, &sidecar).body;
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("a backslash path must still be valid JSON");
            assert_eq!(
                parsed["mcpServers"]["kagisecure"]["command"]
                    .as_str()
                    .expect("command is a string"),
                sidecar.display().to_string(),
                "and must round-trip back to the original path"
            );
        }

        let toml = snippet_for(SetupClient::Codex, &sidecar).body;
        assert!(
            toml.contains(r"C:\\Program Files\\Kagisecure\\Helpers\\kagisecure-mcp.exe"),
            "TOML basic strings escape backslashes too: {toml}"
        );
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
        // Built from the same constants `bundle::installed_helper` composes, joined with
        // `Path::join` rather than typed out with `/`, so this holds on Windows (`\` separator,
        // `SIDECAR` carrying a `.exe` suffix) as well as on macOS.
        let expected = std::path::PathBuf::from(crate::bundle::INSTALLED_APP)
            .join("Contents")
            .join(crate::bundle::HELPERS_DIR)
            .join(SIDECAR);
        assert_eq!(shown, expected);
        // Every snippet the setup screen renders quotes that path — verbatim in the shell
        // snippet, escaped (per `escape_for_quoted_string`) in the JSON and TOML ones, which
        // matters on Windows where the path itself contains `\`.
        let raw = shown.display().to_string();
        let escaped = escape_for_quoted_string(&shown);
        for snippet in all_snippets(&shown) {
            assert!(
                snippet.body.contains(&raw) || snippet.body.contains(&escaped),
                "{snippet:?}"
            );
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

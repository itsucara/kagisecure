//! Command line grammar.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Long help shown at the bottom of `kagisecure --help`.
pub const EXIT_CODE_HELP: &str = "\
Exit codes:
  0   success
  1   an unexpected error
  2   usage error (bad arguments)
  3   could not unlock: wrong password or recovery code, or the vault was tampered with
  4   no vault at the given path
  5   a vault already exists at the given path
  6   no such item or field
  7   the import source could not be read or parsed

`kagisecure run` is the exception: once the child process has started, kagisecure exits with
the child's own exit status.";

/// Exit code for an unexpected failure.
pub const EXIT_ERROR: u8 = 1;
/// Exit code for a usage error: bad arguments, or arguments this build refuses to honour.
///
/// clap already exits 2 on a grammar error it catches itself. This constant is for the same
/// category of mistake expressed in a rule clap cannot state — `--auto-approve` on a release
/// build, say — so that a caller branching on 2 sees one thing, not two.
pub const EXIT_USAGE: u8 = 2;
/// Exit code for a failed unlock.
pub const EXIT_UNLOCK_FAILED: u8 = 3;
/// Exit code when the vault file is missing.
pub const EXIT_NO_VAULT: u8 = 4;
/// Exit code when a vault already exists where one was to be created.
pub const EXIT_VAULT_EXISTS: u8 = 5;
/// Exit code when an item or field reference does not resolve.
pub const EXIT_NOT_FOUND: u8 = 6;
/// Exit code when an import source could not be read or parsed, including an unsupported format.
pub const EXIT_IMPORT_FAILED: u8 = 7;

/// A usage error, carried out of a command so `main` can map it to exit 2.
///
/// `anyhow` flattens everything into one type, and the exit-code mapping downcasts to recover the
/// category. There is no `kagisecure_core::Error` variant for "you asked this binary for something
/// it will not do", because it is not a vault problem — so this is the marker.
#[derive(Debug)]
pub struct UsageError(pub String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// kagisecure — the vault your AI agents can use but never see.
#[derive(Debug, Parser)]
#[command(
    name = "kagisecure",
    version,
    about = "A local encrypted vault for secrets, built for AI coding agents.",
    after_help = EXIT_CODE_HELP,
    after_long_help = EXIT_CODE_HELP
)]
pub struct Cli {
    /// Path to the vault file. Defaults to the per-user location shown in `--help`.
    #[arg(long, global = true, env = "KAGISECURE_VAULT")]
    pub vault: Option<PathBuf>,

    /// Read the master password from the first line of standard input instead of prompting.
    ///
    /// For CI and scripts. The password is still never an argv entry, which would put it in
    /// `ps` output and shell history.
    #[arg(long, global = true)]
    pub password_stdin: bool,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a vault, or check that you can open one.
    #[command(subcommand)]
    Vault(VaultCommand),

    /// Add, list, inspect and remove items.
    #[command(subcommand)]
    Item(ItemCommand),

    /// Run a command with secrets injected into its environment.
    ///
    /// The command and its arguments are handed to the operating system directly. There is no
    /// shell, so `;`, `|` and `$(...)` in an argument are just characters.
    Run(RunArgs),

    /// Unlock with the printable recovery code and set a new master password.
    ///
    /// With `--password-stdin`, the recovery code is read from the first line of standard input
    /// and the new master password from the second.
    Recover(RecoverArgs),

    /// Create and inspect environments: named sets of variables a project needs.
    #[command(subcommand)]
    Env(EnvCommand),

    /// Own the unlocked vault and answer agent requests over local IPC.
    ///
    /// This is the temporary stand-in for the macOS app (M3/M4). It approves in this terminal
    /// instead of behind Touch ID, which is a weaker channel, and it says so when it starts.
    Daemon(DaemonArgs),

    /// Tell a running daemon to drop the vault key and every lease.
    Lock,

    /// Print the audit log.
    Audit(AuditArgs),

    /// Set up an MCP client to talk to kagisecure.
    #[command(subcommand)]
    Mcp(McpCommand),

    /// Generate a password. Does not open, and does not need, a vault.
    Generate(GenerateArgs),

    /// Print an item's current one-time password.
    Totp(TotpArgs),

    /// Import items exported from another password manager.
    Import(ImportArgs),
}

/// `kagisecure generate`
///
/// Two modes, selected by `--words`: without it the generator draws characters, with it words.
/// The character-class switches are all `--no-...` so that the default — every class on — is what
/// you get by typing nothing, and turning something off is the thing you have to say out loud.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// How many characters (8–128). Ignored in word mode.
    #[arg(long, default_value_t = 20, value_name = "N")]
    pub length: u32,

    /// Leave out lower-case letters.
    #[arg(long)]
    pub no_lowercase: bool,

    /// Leave out upper-case letters.
    #[arg(long)]
    pub no_uppercase: bool,

    /// Leave out digits.
    #[arg(long)]
    pub no_digits: bool,

    /// Leave out symbols.
    #[arg(long)]
    pub no_symbols: bool,

    /// Leave out characters that are easy to misread: 0, O, 1, l and I.
    #[arg(long)]
    pub avoid_ambiguous: bool,

    /// Switch to word mode and produce this many words (3–10).
    #[arg(long, value_name = "N")]
    pub words: Option<u32>,

    /// What goes between words: hyphen, underscore, period, space or none.
    #[arg(long, default_value = "hyphen", value_name = "SEP")]
    pub separator: String,

    /// Capitalize each word. Word mode only.
    #[arg(long)]
    pub capitalize: bool,

    /// Append one random digit to one of the words. Word mode only.
    #[arg(long)]
    pub include_digit: bool,

    /// Print this many passwords, one per line.
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub count: u32,

    /// Also print the estimated entropy and strength label to standard error.
    #[arg(long)]
    pub strength: bool,
}

/// `kagisecure totp`
#[derive(Debug, Args)]
pub struct TotpArgs {
    /// The item, optionally with a field: `ITEM` or `ITEM/FIELD`. `ITEM` may be an id, a unique
    /// id prefix or an exact title; with no `/FIELD`, the item's first one-time-password field
    /// is used.
    #[arg(value_name = "ITEM[/FIELD]")]
    pub item: String,

    /// Copy the code to the clipboard instead of printing it (macOS only, via `pbcopy`).
    #[arg(long)]
    pub copy: bool,
}

/// `kagisecure env ...`
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Create an empty environment.
    Create(EnvCreateArgs),

    /// List environments and their variable names. Never prints a value.
    List(EnvListArgs),

    /// Add or replace a variable in an environment.
    AddVar(EnvAddVarArgs),

    /// Remove a variable, or a whole environment.
    Rm(EnvRmArgs),

    /// Write an environment into a `.env` file.
    Write(EnvWriteArgs),

    /// Show or change whether agents may see an environment, item or vault.
    AgentAccess(AgentAccessArgs),
}

/// `kagisecure env create`
#[derive(Debug, Args)]
pub struct EnvCreateArgs {
    /// Environment name, e.g. `acme-api / staging`.
    pub name: String,

    /// A description shown in listings.
    #[arg(long)]
    pub description: Option<String>,

    /// Make it visible to agents straight away. Default-deny otherwise (threat-model M-9).
    #[arg(long)]
    pub agent_visible: bool,
}

/// `kagisecure env list`
#[derive(Debug, Args)]
pub struct EnvListArgs {
    /// Print metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure env add-var`
#[derive(Debug, Args)]
pub struct EnvAddVarArgs {
    /// Environment id, unique id prefix, or exact name.
    #[arg(long = "environment", value_name = "ENV")]
    pub environment: String,

    /// Variable name, e.g. `STRIPE_SECRET_KEY`.
    #[arg(long)]
    pub name: String,

    /// Bind to an existing item's field, as `ITEM/FIELD`. Preferred: rotate once, every
    /// environment that references it follows.
    #[arg(long, value_name = "ITEM/FIELD", conflicts_with = "literal")]
    pub bind: Option<String>,

    /// Store the value inline in the environment. The value is prompted for, never taken from
    /// the command line.
    #[arg(long)]
    pub literal: bool,
}

/// `kagisecure env rm`
#[derive(Debug, Args)]
pub struct EnvRmArgs {
    /// Environment id, unique id prefix, or exact name.
    pub environment: String,

    /// Remove just this variable instead of the whole environment.
    #[arg(long, value_name = "NAME")]
    pub var: Option<String>,
}

/// `kagisecure env write`
#[derive(Debug, Args)]
pub struct EnvWriteArgs {
    /// Environment id, unique id prefix, or exact name.
    #[arg(long = "environment", value_name = "ENV")]
    pub environment: String,

    /// Directory to write into.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub dir: PathBuf,

    /// File name within that directory.
    #[arg(long, default_value = ".env")]
    pub filename: String,

    /// Write only these variables. Repeatable. Default: all of them.
    #[arg(long = "var", value_name = "NAME")]
    pub vars: Vec<String>,

    /// Replace a file that is already there.
    #[arg(long)]
    pub overwrite: bool,
}

/// `kagisecure env agent-access`
#[derive(Debug, Args)]
pub struct AgentAccessArgs {
    /// Grant agent visibility rather than revoking it.
    #[arg(long, conflicts_with = "deny")]
    pub allow: bool,

    /// Revoke agent visibility.
    #[arg(long)]
    pub deny: bool,

    /// A logical vault *inside* the file, by id, unique id prefix or exact name.
    ///
    /// Spelled `--logical-vault` rather than `--vault` because the global `--vault` already
    /// means "which vault file", and two flags of the same name meaning different things is how
    /// people end up granting agent access to the wrong thing.
    #[arg(long = "logical-vault", value_name = "VAULT")]
    pub vault_ref: Option<String>,

    /// An item, by id, unique id prefix or exact title.
    #[arg(long, value_name = "ITEM")]
    pub item: Option<String>,

    /// An environment, by id, unique id prefix or exact name.
    #[arg(long = "environment", value_name = "ENV")]
    pub environment: Option<String>,
}

/// `kagisecure daemon`
#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Listen here instead of at the per-user default.
    #[arg(long, value_name = "PATH", env = "KAGISECURE_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Never prompt on this terminal; refuse anything not already covered by a lease.
    #[arg(long)]
    pub non_interactive: bool,

    /// Approve every request without asking. **Debug builds only** — a release build refuses to
    /// start with this flag, so a shipped binary cannot be talked into it (ADR-0007).
    #[arg(long)]
    pub auto_approve: bool,
}

/// `kagisecure audit`
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Show at most this many entries, newest last.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Verify the hash chain and say whether it is intact.
    #[arg(long)]
    pub verify: bool,

    /// Print entries as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure mcp ...`
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Print the absolute path of the `kagisecure-mcp` sidecar binary.
    Path,

    /// Print the configuration snippet an MCP client needs.
    Install(McpInstallArgs),
}

/// Which MCP client to print configuration for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum McpClient {
    /// Anthropic's Claude Code CLI.
    ClaudeCode,
    /// The Claude desktop application.
    ClaudeDesktop,
    /// OpenAI's Codex CLI.
    Codex,
    /// Cursor.
    Cursor,
}

/// `kagisecure mcp install`
#[derive(Debug, Args)]
pub struct McpInstallArgs {
    /// The client to configure.
    #[arg(value_enum)]
    pub client: McpClient,

    /// Print the snippet without writing anything. The default, and the only thing that happens
    /// unless `--write` is given.
    #[arg(long)]
    pub print: bool,

    /// Write the snippet into that client's standard configuration file.
    #[arg(long, conflicts_with = "print")]
    pub write: bool,
}

/// `kagisecure vault ...`
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create a new vault and print its one-time recovery code.
    Init(InitArgs),

    /// Check that the master password opens the vault. Prints a summary, never a value.
    Unlock,
}

/// `kagisecure vault init`
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Display name of the first logical vault inside the file.
    #[arg(long, default_value = "Personal")]
    pub name: String,

    /// Argon2id memory cost in KiB. The default is the documented desktop profile.
    #[arg(long, value_name = "KIB", default_value_t = kagisecure_core::crypto::kdf::DEFAULT_M_KIB)]
    pub kdf_m_kib: u32,

    /// Argon2id iterations.
    #[arg(long, value_name = "N", default_value_t = kagisecure_core::crypto::kdf::DEFAULT_T)]
    pub kdf_t: u32,

    /// Argon2id parallelism.
    #[arg(long, value_name = "N", default_value_t = kagisecure_core::crypto::kdf::DEFAULT_P)]
    pub kdf_p: u32,

    /// A human note recorded in the header next to the KDF parameters.
    #[arg(long, value_name = "TEXT")]
    pub kdf_hint: Option<String>,
}

/// `kagisecure item ...`
#[derive(Debug, Subcommand)]
pub enum ItemCommand {
    /// Add an item.
    Add(AddArgs),

    /// List items. Titles, categories and field labels only.
    List(ListArgs),

    /// Show one item's metadata.
    Show(ShowArgs),

    /// Remove an item.
    Rm(RmArgs),
}

/// `kagisecure item add`
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Item title.
    #[arg(long)]
    pub title: String,

    /// Item category: login, password, secure-note, credit-card, identity, api-credential,
    /// server, database, ssh-key, software-license, document, environment, or any other name,
    /// which is preserved verbatim.
    #[arg(long, default_value = "login")]
    pub category: String,

    /// A public field, as `label=value`. Repeatable.
    #[arg(long = "field", value_name = "LABEL=VALUE")]
    pub fields: Vec<String>,

    /// A concealed field. Repeatable. The value is prompted for, never taken from the command
    /// line, so it does not reach `ps` output or shell history.
    #[arg(long = "secret", value_name = "LABEL")]
    pub secrets: Vec<String>,

    /// A one-time-password field. Repeatable. The `otpauth://` URI is prompted for rather than
    /// taken from the command line: the URI carries the shared seed, so it is as sensitive as a
    /// password and must not reach `ps` output or shell history.
    #[arg(long = "totp", value_name = "LABEL")]
    pub totps: Vec<String>,

    /// Read the concealed and one-time-password values from standard input, one per line, in the
    /// order the `--secret` and then `--totp` flags were given, instead of prompting.
    #[arg(long)]
    pub value_stdin: bool,

    /// A tag. Repeatable.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// A URL. Repeatable.
    #[arg(long = "url", value_name = "URL")]
    pub urls: Vec<String>,

    /// A free-form note.
    #[arg(long)]
    pub note: Option<String>,
}

/// `kagisecure item list`
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Print metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure item show`
#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Item id, unique id prefix, or exact title.
    pub item: String,

    /// Also print concealed values.
    ///
    /// This is the CLI, which is your own trusted local tool, so the flag exists. It has no
    /// equivalent over MCP and never will (ADR-0002, ADR-0005).
    #[arg(long)]
    pub reveal: bool,

    /// Print metadata as JSON. Never includes concealed values, even with `--reveal`.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure item rm`
#[derive(Debug, Args)]
pub struct RmArgs {
    /// Item id, unique id prefix, or exact title.
    pub item: String,
}

/// `kagisecure run`
#[derive(Debug, Args)]
pub struct RunArgs {
    /// A variable to inject, as `NAME=item/field`, where `item` is an item id, a unique id
    /// prefix or an exact title, and `field` is a field label or id. Repeatable.
    #[arg(long = "env", value_name = "NAME=ITEM/FIELD", required = true)]
    pub env: Vec<String>,

    /// Print the child's output as it came, without replacing injected values.
    ///
    /// Masking is best effort in either case — it is an exact-value substring replacement, so a
    /// command that transforms a secret before printing it defeats it. It is a guard against
    /// accidental echo, not a security boundary.
    #[arg(long)]
    pub no_masking: bool,

    /// Working directory for the child process.
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<PathBuf>,

    /// The program to run and its arguments, after `--`.
    #[arg(last = true, required = true, num_args = 1..)]
    pub command: Vec<OsString>,
}

/// `kagisecure import`
///
/// See `docs/import.md` for what each format brings across and what it necessarily leaves
/// behind. Nothing this command prints is ever a value: the report and the summary are built
/// from names, kinds and counts only (`kagisecure_import::report`).
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Path to the exported file.
    #[arg(value_name = "PATH")]
    pub source: PathBuf,

    /// Which export format to read. Detected from the file itself when omitted.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,

    /// Put every imported item in this logical vault inside the file, creating it if needed.
    ///
    /// Spelled `--logical-vault` rather than `--vault`: the global `--vault` already means
    /// "which vault *file*", and giving a subcommand argument the same name silently lets the
    /// later one win over the earlier — `kagisecure --vault work.kagivault import x.1pux --vault
    /// Personal` would otherwise open `Personal` instead of `work.kagivault`. `env
    /// agent-access --logical-vault` avoids the same collision the same way.
    #[arg(long = "logical-vault", value_name = "NAME")]
    pub logical_vault: Option<String>,

    /// Show what would happen and exit. Never writes to the vault, never shreds the source.
    #[arg(long)]
    pub dry_run: bool,

    /// What to do when an imported item matches one already in the vault: skip, update or
    /// keep-both.
    #[arg(long = "on-duplicate", value_name = "POLICY", default_value = "skip")]
    pub on_duplicate: String,

    /// Also bring in items the source had in its trash.
    #[arg(long)]
    pub include_trashed: bool,

    /// Write the report as Markdown to this path (created with mode 0600).
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,

    /// Print the report as JSON instead of a plain-text summary.
    #[arg(long)]
    pub json: bool,

    /// Skip the confirmation prompt that a source of more than 100 items would otherwise show.
    #[arg(long)]
    pub yes: bool,

    /// Best-effort overwrite and remove the source file, once the import has been saved.
    #[arg(long)]
    pub shred_source: bool,
}

/// `kagisecure recover`
#[derive(Debug, Args)]
pub struct RecoverArgs {
    /// Issue a fresh recovery code as well, retiring the one just used.
    #[arg(long)]
    pub reissue_recovery_code: bool,
}

impl Cli {
    /// Whether this invocation will consume lines of standard input for secrets.
    #[must_use]
    pub fn reads_stdin(&self) -> bool {
        self.password_stdin
            || matches!(
                &self.command,
                Command::Item(ItemCommand::Add(a)) if a.value_stdin
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_grammar_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_collects_everything_after_the_double_dash() {
        let cli = Cli::try_parse_from([
            "kagisecure",
            "run",
            "--env",
            "TOKEN=item/field",
            "--",
            "printenv",
            "--weird-flag",
            "TOKEN",
        ])
        .unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run")
        };
        assert_eq!(args.env, ["TOKEN=item/field"]);
        assert_eq!(args.command, ["printenv", "--weird-flag", "TOKEN"]);
        assert!(!args.no_masking);
    }

    #[test]
    fn there_is_no_way_to_pass_a_secret_value_on_the_command_line() {
        // `item add` takes labels for concealed fields, never values.
        let cli = Cli::try_parse_from([
            "kagisecure",
            "item",
            "add",
            "--title",
            "t",
            "--secret",
            "password",
        ])
        .unwrap();
        let Command::Item(ItemCommand::Add(args)) = cli.command else {
            panic!("expected item add")
        };
        assert_eq!(args.secrets, ["password"]);
        assert!(!args.value_stdin);
    }
}

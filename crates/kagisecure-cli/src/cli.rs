//! Command line grammar.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use kagisecure_shared::{RemovalReason, Role};

/// Long help shown at the bottom of `kagisecure --help`.
pub const EXIT_CODE_HELP: &str = "\
Exit codes:
  0   success
  1   an unexpected error
  2   usage error (bad arguments)
  3   could not unlock: wrong password or recovery code, or the vault was tampered with
  4   no vault at the given path
  5   a vault already exists at the given path
  6   no such item, field, environment or variable
  7   the import source could not be read or parsed
  8   another kagisecure process is writing to the vault; gave up waiting for it (also: the lock
      file itself was moved or deleted while held)
  9   could not durably record permission before releasing a secret (env write, run); nothing was
      written and nothing ran
  10  the vault changed unexpectedly (replaced by another process, or its audit log no longer
      matches what this run last saw)
  11  the file system holding the vault does not support file locks; kagisecure will not write to
      it (it can still be opened and read)
  12  this vault was written by a newer kagisecure than this build; upgrade before writing to it
  13  a shared vault refused: this device does not hold the role or key the change needs, or the
      change would leave the shared vault with no admin

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
/// Exit code when an item, field, environment or variable reference does not resolve.
pub const EXIT_NOT_FOUND: u8 = 6;
/// Exit code when an import source could not be read or parsed, including an unsupported format.
pub const EXIT_IMPORT_FAILED: u8 = 7;
/// Exit code when another kagisecure process held the vault's lock for longer than this run was
/// willing to wait ([`kagisecure_core::Error::VaultBusy`]).
pub const EXIT_VAULT_BUSY: u8 = 8;
/// Exit code for [`crate::commands::AuditUnavailable`]: `kagisecure env write` and `kagisecure
/// run` are audit-first (design doc "transactions-and-audit", part B) — the `Allowed` entry has to
/// be appended and durably saved *before* the `.env` file is written or the child is spawned. If
/// that transaction fails for any reason (a save error, [`kagisecure_core::Error::VaultBusy`] after
/// the usual wait, [`kagisecure_core::Error::VaultDiverged`], [`kagisecure_core::Error::VaultReplaced`]),
/// the release is refused: nothing was written and nothing ran, and — unlike [`EXIT_VAULT_BUSY`] or
/// [`EXIT_VAULT_CHANGED`], which describe *why* a write did not happen — this code says
/// specifically that permission could not be made durable, which is the one thing an audit-first
/// release must never skip.
pub const EXIT_AUDIT_UNAVAILABLE: u8 = 9;
/// Exit code when a transaction found the vault file changed in a way it cannot merge:
/// [`kagisecure_core::Error::VaultDiverged`] (the file no longer continues this run's audit log —
/// an older copy restored from under it), [`kagisecure_core::Error::VaultReplaced`] (a different
/// vault at the same path), or [`kagisecure_core::Error::VaultConflict`] (the non-transactional
/// `save` path, or a refused `install_master_password`/`install_recovery_code` inside a
/// transaction). Nothing was written in any of the three.
pub const EXIT_VAULT_CHANGED: u8 = 10;
/// Exit code when the file system holding the vault does not support file locks
/// ([`kagisecure_core::Error::LockUnsupported`]). Unlike [`EXIT_VAULT_BUSY`], retrying cannot
/// help: no process on this file system can ever take the lock a write needs. The vault can
/// still be opened and read; only writes are refused.
pub const EXIT_LOCK_UNSUPPORTED: u8 = 11;
/// Exit code when the vault's header or body schema is newer than this build writes
/// ([`kagisecure_core::Error::VaultSchemaTooNew`]) or newer than this build can even read
/// ([`kagisecure_core::Error::UnsupportedFormatVersion`]). Both mean the same thing to a script:
/// a newer kagisecure wrote this file, and the fix is to upgrade, not to retry.
pub const EXIT_VAULT_TOO_NEW: u8 = 12;
/// Exit code for [`kagisecure_shared::SharedError::Refused`]: this device does not hold the role
/// or the epoch key a shared-vault change needs, or the change would leave the vault with no
/// admin (`kagisecure_shared::admin`'s doc comments name every case this can be). Distinct from
/// [`EXIT_ERROR`] so a script can tell "not allowed" apart from "something broke"; distinct from
/// every other exit code above because none of them is about a *shared* vault's roster or keys.
pub const EXIT_SHARED_REFUSED: u8 = 13;

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

/// A `<vault>` argument to a `kagisecure shared` subcommand that names no shared vault, or more
/// than one.
///
/// There is no `kagisecure_core::Error` variant for a *shared* vault reference — only items,
/// fields, environments and variables (`Error::ItemNotFound` and its siblings, reused as-is for a
/// shared item or environment reference, since those categories are identical whichever vault they
/// live in). A shared vault itself has no such variant, so this crate names the category and maps
/// it to the same exit code those already use ([`EXIT_NOT_FOUND`]): a reference that resolves to
/// nothing, or to more than one thing, is one category to a script, whichever kind of reference it
/// was.
#[derive(Debug)]
pub struct NoSuchSharedVault(pub String);

impl std::fmt::Display for NoSuchSharedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoSuchSharedVault {}

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

    /// Create, join and use shared vaults: separate files of signed records exchanged by hand,
    /// out of band, and merged as a set union (ADR-0035).
    #[command(subcommand)]
    Shared(SharedCommand),

    /// Not a public command: `kagisecure totp --copy` spawns this, detached, to clear the
    /// clipboard later without needing to stay alive itself. See
    /// `commands::generate::schedule_clear`.
    #[command(name = "__clipboard-clear", hide = true)]
    ClipboardClear(ClipboardClearArgs),
}

/// A member's role, from `reader`, `writer` or `admin` on the command line.
fn parse_role(s: &str) -> Result<Role, String> {
    Role::from_name(s).ok_or_else(|| format!("expected reader, writer or admin, got {s:?}"))
}

/// Why a device or a member was removed, from `left`, `retired` or `compromised`.
fn parse_removal_reason(s: &str) -> Result<RemovalReason, String> {
    RemovalReason::from_name(s)
        .ok_or_else(|| format!("expected left, retired or compromised, got {s:?}"))
}

/// `kagisecure shared ...`
#[derive(Debug, Subcommand)]
pub enum SharedCommand {
    /// Create a shared vault, with this computer as its first admin.
    Create(SharedCreateArgs),

    /// List shared vaults with a replica beside this vault file.
    List(SharedListArgs),

    /// Show one shared vault's members, devices and warnings.
    Status(SharedStatusArgs),

    /// Add, change, remove and show items in a shared vault.
    #[command(subcommand)]
    Item(SharedItemCommand),

    /// Create environments and add variables in a shared vault.
    #[command(subcommand)]
    Env(SharedEnvCommand),

    /// Invite a device to a shared vault: one file and a passphrase, shown once.
    Invite(SharedInviteArgs),

    /// Join a shared vault from an invitation file and its passphrase.
    Join(SharedJoinArgs),

    /// Remove a device or a member from a shared vault.
    Remove(SharedRemoveArgs),

    /// Change a member's role.
    Role(SharedRoleArgs),

    /// List what a removed device could have read (informational; nothing is enforced).
    RotationList(SharedRotationListArgs),

    /// Import from, then export to, the configured exchange folder.
    Sync(SharedSyncArgs),

    /// Import records from a folder or a bundle file.
    Import(SharedImportArgs),

    /// Export every record to a folder, or write the whole replica as a bundle file.
    Export(SharedExportArgs),

    /// Rebuild a replica that no longer opens, from a folder or a bundle file.
    Rebuild(SharedRebuildArgs),

    /// Set or change the folder this device syncs a shared vault through.
    SetDir(SharedSetDirArgs),
}

/// `kagisecure shared create`
#[derive(Debug, Args)]
pub struct SharedCreateArgs {
    /// The shared vault's display name.
    pub name: String,

    /// The folder to exchange records through: a synced folder or a git working copy. Can be set
    /// or changed later with `kagisecure shared set-dir`.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Label for this computer's device key. Kept only in this device's own settings — never
    /// carried by a record or shown to another member.
    #[arg(long, value_name = "LABEL", default_value = "this computer")]
    pub device_label: String,
}

/// `kagisecure shared list`
#[derive(Debug, Args)]
pub struct SharedListArgs {
    /// Print as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure shared status`
#[derive(Debug, Args)]
pub struct SharedStatusArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Print as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure shared item ...`
#[derive(Debug, Subcommand)]
pub enum SharedItemCommand {
    /// Add an item.
    Add(SharedItemAddArgs),

    /// Change an item.
    Set(SharedItemSetArgs),

    /// Delete an item. A later edit brings it back (last-writer-wins; ADR-0035 addendum,
    /// decision 80).
    Rm(SharedItemRmArgs),

    /// Show one item's metadata.
    Show(SharedItemShowArgs),
}

/// `kagisecure shared item add`
#[derive(Debug, Args)]
pub struct SharedItemAddArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Item title.
    #[arg(long)]
    pub title: String,

    /// Item category: login, password, secure-note, credit-card, identity, api-credential,
    /// server, database, ssh-key, software-license, document, environment, or any other name.
    #[arg(long, default_value = "login")]
    pub category: String,

    /// A public field, as `label=value`. Repeatable.
    #[arg(long = "field", value_name = "LABEL=VALUE")]
    pub fields: Vec<String>,

    /// A concealed field. Repeatable. The value is prompted for, never taken from the command
    /// line.
    #[arg(long = "secret", value_name = "LABEL")]
    pub secrets: Vec<String>,

    /// A one-time-password field. Repeatable. The `otpauth://` URI is prompted for, never taken
    /// from the command line.
    #[arg(long = "totp", value_name = "LABEL")]
    pub totps: Vec<String>,

    /// Read the concealed and one-time-password values from standard input, one per line, in the
    /// order the `--secret` and then `--totp` flags were given, instead of prompting. See
    /// `kagisecure item add --value-stdin` for the same convention.
    #[arg(long)]
    pub value_stdin: bool,

    /// A tag. Repeatable.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// A URL. Repeatable.
    #[arg(long = "url", value_name = "URL")]
    pub urls: Vec<String>,

    /// Add a free-form note. Bare, like `kagisecure item add --note`: the value is read the way a
    /// `--secret` value is, a hidden prompt or, with `--value-stdin`, the next stdin line after
    /// every `--secret` and `--totp` value.
    #[arg(long, conflicts_with = "note_file")]
    pub note: bool,

    /// Read the note from this file's contents, verbatim, instead of a prompt or standard input.
    #[arg(long, value_name = "PATH")]
    pub note_file: Option<PathBuf>,
}

/// `kagisecure shared item set`
#[derive(Debug, Args)]
pub struct SharedItemSetArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Item id, unique id prefix, or exact title.
    pub item: String,

    /// Replace the title.
    #[arg(long)]
    pub title: Option<String>,

    /// Replace the category.
    #[arg(long)]
    pub category: Option<String>,

    /// Replace the tags. Repeatable; passing any replaces the whole list.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// Replace the URLs. Repeatable; passing any replaces the whole list.
    #[arg(long = "url", value_name = "URL")]
    pub urls: Vec<String>,

    /// Add or replace a public field, as `label=value`. Repeatable.
    #[arg(long = "field", value_name = "LABEL=VALUE")]
    pub fields: Vec<String>,

    /// Add or replace a concealed field. Repeatable. The value is prompted for.
    #[arg(long = "secret", value_name = "LABEL")]
    pub secrets: Vec<String>,

    /// Add or replace a one-time-password field. Repeatable. The `otpauth://` URI is prompted
    /// for.
    #[arg(long = "totp", value_name = "LABEL")]
    pub totps: Vec<String>,

    /// Remove a field, by id or exact label. Repeatable.
    #[arg(long = "rm-field", value_name = "LABEL")]
    pub rm_fields: Vec<String>,

    /// Read the concealed and one-time-password values from standard input, one per line, in the
    /// order `--secret` and then `--totp` were given.
    #[arg(long)]
    pub value_stdin: bool,

    /// Replace the note. Read the same way `item add --note` reads it.
    #[arg(long, conflicts_with = "note_file")]
    pub note: bool,

    /// Replace the note from this file's contents, verbatim.
    #[arg(long, value_name = "PATH")]
    pub note_file: Option<PathBuf>,

    /// Delete the note.
    #[arg(long, conflicts_with_all = ["note", "note_file"])]
    pub clear_note: bool,
}

/// `kagisecure shared item rm`
#[derive(Debug, Args)]
pub struct SharedItemRmArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Item id, unique id prefix, or exact title.
    pub item: String,
}

/// `kagisecure shared item show`
#[derive(Debug, Args)]
pub struct SharedItemShowArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Item id, unique id prefix, or exact title.
    pub item: String,

    /// Also print concealed values.
    #[arg(long)]
    pub reveal: bool,

    /// Print metadata as JSON. Never includes concealed values, even with `--reveal`.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure shared env ...`
#[derive(Debug, Subcommand)]
pub enum SharedEnvCommand {
    /// Create an empty environment.
    Create(SharedEnvCreateArgs),

    /// Add or replace a variable in an environment.
    AddVar(SharedEnvAddVarArgs),
}

/// `kagisecure shared env create`
#[derive(Debug, Args)]
pub struct SharedEnvCreateArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Environment name, e.g. `acme-api / staging`.
    pub name: String,

    /// A description shown in listings.
    #[arg(long)]
    pub description: Option<String>,

    /// Make it visible to this device's agents straight away. Default-deny otherwise
    /// (threat-model M-9); this setting is local to this device, like every shared-vault agent
    /// visibility choice.
    #[arg(long)]
    pub agent_visible: bool,
}

/// `kagisecure shared env add-var`
#[derive(Debug, Args)]
pub struct SharedEnvAddVarArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Environment id, unique id prefix, or exact name.
    #[arg(long = "environment", value_name = "ENV")]
    pub environment: String,

    /// Variable name, e.g. `STRIPE_SECRET_KEY`.
    #[arg(long)]
    pub name: String,

    /// Bind to an existing item's field, as `ITEM/FIELD`.
    #[arg(long, value_name = "ITEM/FIELD", conflicts_with = "literal")]
    pub bind: Option<String>,

    /// Store the value inline in the environment. The value is prompted for.
    #[arg(long)]
    pub literal: bool,
}

/// `kagisecure shared invite`
#[derive(Debug, Args)]
pub struct SharedInviteArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Label for the invited device, e.g. `"Bob's laptop"`.
    #[arg(long)]
    pub name: String,

    /// Add a device to this existing member instead of a new one, by member id (hex, from
    /// `kagisecure shared status`).
    #[arg(long, value_name = "MEMBER")]
    pub member: Option<String>,

    /// The new member's role. Required unless `--member` names an existing one.
    #[arg(long, value_parser = parse_role, value_name = "ROLE")]
    pub role: Option<Role>,

    /// Where to write the invitation file (mode 0600 on Unix).
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// `kagisecure shared join`
#[derive(Debug, Args)]
pub struct SharedJoinArgs {
    /// The invitation file.
    pub file: PathBuf,

    /// The folder to exchange records through, once joined.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Read the invitation passphrase from the next line of standard input instead of prompting.
    #[arg(long)]
    pub passphrase_stdin: bool,
}

/// `kagisecure shared remove`
#[derive(Debug, Args)]
pub struct SharedRemoveArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// The device to remove, by id (hex, from `kagisecure shared status`).
    #[arg(long, value_name = "ID", conflicts_with = "member")]
    pub device: Option<String>,

    /// The member to remove, with every device of theirs, by id (hex).
    #[arg(long, value_name = "ID")]
    pub member: Option<String>,

    /// Why: left, retired or compromised.
    #[arg(long, value_parser = parse_removal_reason, default_value = "left")]
    pub reason: RemovalReason,
}

/// `kagisecure shared role`
#[derive(Debug, Args)]
pub struct SharedRoleArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// The member's id (hex, from `kagisecure shared status`).
    pub member: String,

    /// The role to give them: reader, writer or admin.
    #[arg(value_parser = parse_role)]
    pub role: Role,
}

/// `kagisecure shared rotation-list`
#[derive(Debug, Args)]
pub struct SharedRotationListArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Print as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kagisecure shared sync`
#[derive(Debug, Args)]
pub struct SharedSyncArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,
}

/// `kagisecure shared import`
#[derive(Debug, Args)]
pub struct SharedImportArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Import every record of this bundle file.
    #[arg(long, value_name = "FILE", conflicts_with = "dir")]
    pub bundle: Option<PathBuf>,

    /// Import every record of this exchange folder.
    #[arg(long, value_name = "DIR", conflicts_with = "bundle")]
    pub dir: Option<PathBuf>,
}

/// `kagisecure shared export`
#[derive(Debug, Args)]
pub struct SharedExportArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Write the whole replica as one bundle file here.
    #[arg(long, value_name = "FILE", conflicts_with = "dir")]
    pub bundle: Option<PathBuf>,

    /// Write every record this exchange folder is missing.
    #[arg(long, value_name = "DIR", conflicts_with = "bundle")]
    pub dir: Option<PathBuf>,
}

/// `kagisecure shared rebuild`
#[derive(Debug, Args)]
pub struct SharedRebuildArgs {
    /// The shared vault's id, or a unique prefix of it — matched against the replica files beside
    /// this vault, since a replica that will not open cannot be asked its own name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// Rebuild from this exchange folder.
    #[arg(long, value_name = "DIR", conflicts_with = "from_bundle")]
    pub from_dir: Option<PathBuf>,

    /// Rebuild from this bundle file.
    #[arg(long, value_name = "FILE", conflicts_with = "from_dir")]
    pub from_bundle: Option<PathBuf>,
}

/// `kagisecure shared set-dir`
#[derive(Debug, Args)]
pub struct SharedSetDirArgs {
    /// Shared vault id, unique id prefix, or exact name.
    #[arg(value_name = "VAULT")]
    pub shared_vault: String,

    /// The folder to exchange records through from now on.
    pub dir: PathBuf,
}

/// `kagisecure __clipboard-clear` (hidden; see [`Command::ClipboardClear`]).
#[derive(Debug, Args)]
pub struct ClipboardClearArgs {
    /// The `NSPasteboard.general.changeCount` observed right after the copy this clear follows.
    /// Skipped if the count has since moved on, so a copy made in the meantime survives.
    #[arg(long)]
    pub if_unchanged: i64,

    /// How long to wait before checking, in seconds.
    #[arg(long)]
    pub after_seconds: u64,
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

    /// Copy the code to the clipboard instead of printing it (macOS or Windows).
    ///
    /// On macOS it is marked `org.nspasteboard.ConcealedType` and
    /// `org.nspasteboard.TransientType` — the same concealed marker the app's clipboard uses, plus
    /// one it does not set yet — and cleared automatically after 60 seconds unless something else
    /// was copied first. On Windows it goes through the Win32 clipboard API, excluded from
    /// clipboard history and Cloud Clipboard, and is not cleared automatically. See
    /// `commands::generate::copy_to_clipboard` for what this cannot do that the app can (Universal
    /// Clipboard is not blocked either way).
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

    /// A shared vault, by id, unique id prefix or exact name: `--item`, `--field` and
    /// `--environment` then name its items and environments, and the change is this computer's
    /// own — kept in its copy of the shared vault, never sent to the other members (ADR-0035
    /// §14). Without `--allow` or `--deny`, lists what its agents may see.
    #[arg(
        long = "shared-vault",
        value_name = "SHARED",
        conflicts_with = "vault_ref"
    )]
    pub shared_vault: Option<String>,

    /// An item, by id, unique id prefix or exact title.
    #[arg(long, value_name = "ITEM")]
    pub item: Option<String>,

    /// One field of `--item`, by id or exact label. Changes that field's own agent-visibility
    /// override instead of the item's (ui-spec.md §4.4) — the same per-field flag
    /// `describe_item` reports and `add_variables`'s `bind_to` requires before an agent may bind
    /// to it (docs/mcp-server.md §2.6). Requires `--item`; a field is meaningless without one.
    #[arg(long, value_name = "FIELD", requires = "item")]
    pub field: Option<String>,

    /// An environment, by id, unique id prefix or exact name.
    #[arg(long = "environment", value_name = "ENV")]
    pub environment: Option<String>,
}

/// `kagisecure daemon`
#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Listen here instead of at the per-user default. A socket path on Unix; a named pipe name
    /// on Windows, which has no filesystem sockets.
    ///
    /// The same string `KAGISECURE_SOCKET` carries, so that the flag and the variable a sidecar
    /// reads cannot mean two different things. On Windows pass a pipe name —
    /// `kagisecure-mine.sock`, or `\\.\pipe\kagisecure-mine.sock` — and note that a pipe name is
    /// machine-global rather than a private file. A value this platform cannot listen on is
    /// refused with a sentence saying what it accepts, not carried as far as `bind`.
    ///
    /// An [`OsString`] rather than a [`PathBuf`] because on one of the two
    /// platforms it is not a path — `kagisecure_ipc::endpoint::Endpoint::parse` is what decides
    /// which it is — and rather than a [`String`] because a Unix socket path is bytes, not
    /// necessarily UTF-8, and it has always been accepted verbatim.
    #[arg(long, value_name = "SOCKET", env = "KAGISECURE_SOCKET")]
    pub socket: Option<std::ffi::OsString>,

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

    /// Set "Show new items to agents" for the first logical vault: whether items created by the
    /// app, the CLI or an import start visible to agents. On by default.
    NewItemsAgentVisible(NewItemsAgentVisibleArgs),
}

/// `kagisecure vault new-items-agent-visible`
#[derive(Debug, Args)]
pub struct NewItemsAgentVisibleArgs {
    /// `on` or `off`.
    pub state: OnOff,
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

    /// Show items to agents, or hide them, in bulk: named items, a tag, a category, or all.
    /// Agents see titles, categories, tags and field names; values still need an approval.
    /// One transaction, one audit entry with counts only.
    AgentVisible(AgentVisibleArgs),
}

/// `on` or `off`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OnOff {
    /// Turn it on.
    On,
    /// Turn it off.
    Off,
}

impl OnOff {
    /// `true` for [`OnOff::On`].
    #[must_use]
    pub fn is_on(self) -> bool {
        self == Self::On
    }
}

/// `kagisecure item agent-visible`
#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("scope")
        .required(true)
        .args(["items", "tag", "category", "all"])
))]
pub struct AgentVisibleArgs {
    /// `on` to show the items (and every field) to agents, `off` to hide them.
    pub state: OnOff,

    /// An item id, unique id prefix, or exact title. Repeatable.
    #[arg(long = "item", value_name = "ITEM")]
    pub items: Vec<String>,

    /// Every item, not in the trash, with this tag (for example `imported:chromium`).
    #[arg(long, value_name = "TAG")]
    pub tag: Option<String>,

    /// Every item, not in the trash, of this category.
    #[arg(long, value_name = "CATEGORY")]
    pub category: Option<String>,

    /// Every item not in the trash.
    #[arg(long)]
    pub all: bool,
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
    /// order the `--secret` and then `--totp` flags were given, instead of prompting. A bare
    /// `--note` follows last, still a single line — see `--note`'s own doc comment for why a note
    /// with more than one line needs `--note-file` instead.
    #[arg(long)]
    pub value_stdin: bool,

    /// A tag. Repeatable.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// A URL. Repeatable.
    #[arg(long = "url", value_name = "URL")]
    pub urls: Vec<String>,

    /// Add a free-form note. Bare — no text after it — the note's value is then read exactly the
    /// way a `--secret` or `--totp` value is: a hidden terminal prompt, or, with `--value-stdin`,
    /// the next line of standard input, after every `--secret` and then `--totp` value.
    ///
    /// A value used to be accepted directly after this flag (`--note "text"`). It no longer is:
    /// notes are secret material like any other field (ADR-0038), and text placed straight on
    /// argv reaches `ps` output and shell history — exactly what `--secret` and `--totp` already
    /// refuse to do above. This flag now takes no value at all, so that old invocation is instead
    /// refused by clap itself, as an unexpected argument (exit 2), the same way any other
    /// argv-shaped mistake in this command already is.
    ///
    /// A prompt and `--value-stdin` both stop at the first line break, so neither can carry a note
    /// with more than one line — that is what `--note-file PATH` is for.
    #[arg(long, conflicts_with = "note_file")]
    pub note: bool,

    /// Read the note from this file's contents, verbatim — including every embedded newline —
    /// instead of a prompt or standard input. The only way to give a note with more than one
    /// line. A single trailing newline (or `\r\n`), if the file ends with one, is trimmed, the
    /// way a shell's own `$(cat file)` would. Conflicts with `--note`: pick exactly one source.
    #[arg(long, value_name = "PATH")]
    pub note_file: Option<PathBuf>,
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

    /// Delete every `<vault>.bak-*` format-upgrade backup beside the vault without asking
    /// (threat-model W-22: each one still opens with the master password and recovery code that
    /// were current when it was made, even after this command replaces them).
    #[arg(long)]
    pub delete_backups: bool,
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
            || matches!(
                &self.command,
                Command::Shared(SharedCommand::Item(SharedItemCommand::Add(a))) if a.value_stdin
            )
            || matches!(
                &self.command,
                Command::Shared(SharedCommand::Item(SharedItemCommand::Set(a))) if a.value_stdin
            )
            || matches!(
                &self.command,
                Command::Shared(SharedCommand::Join(a)) if a.passphrase_stdin
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

    #[test]
    fn the_note_flag_takes_no_value_and_the_old_form_is_a_grammar_error() {
        // `--note` used to take the note's text directly. It is now a bare switch, so the old form
        // must fail to parse — clap treating the text as a stray positional argument, never as
        // this flag's value — rather than silently accepting a secret value on argv.
        let err = Cli::try_parse_from([
            "kagisecure",
            "item",
            "add",
            "--title",
            "t",
            "--note",
            "some text typed straight on the command line",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);

        // The bare form parses, and reads as "there is a note", nothing more.
        let cli =
            Cli::try_parse_from(["kagisecure", "item", "add", "--title", "t", "--note"]).unwrap();
        let Command::Item(ItemCommand::Add(args)) = cli.command else {
            panic!("expected item add")
        };
        assert!(args.note);
        assert!(args.note_file.is_none());
    }

    #[test]
    fn note_and_note_file_cannot_both_be_given() {
        let err = Cli::try_parse_from([
            "kagisecure",
            "item",
            "add",
            "--title",
            "t",
            "--note",
            "--note-file",
            "notes.txt",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}

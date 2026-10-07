//! The message types.
//!
//! # The invariant, restated as a type rule
//!
//! **No message in this module carries a secret value.** That is not a convention here, it is a
//! property of the crate graph: `kagisecure-ipc` depends on `kagisecure-core` with
//! `default-features = false`, so [`Secret`] does not exist in this compilation unit and no
//! variant below could be given one even by a contributor who wanted to.
//!
//! The two fields that come closest are [`Response::Ran`]'s `stdout` and `stderr`. Those are the
//! child process's own output with injected values substituted out — mcp-server.md §2.8 decides
//! that they are returned, and documents that the scrubbing is **best effort and not a security
//! boundary**. They are not "a secret value" in the sense this crate forbids: nothing in the
//! vault is read to produce them.
//!
//! [`Secret`]: https://docs.rs/kagisecure-core/latest/kagisecure_core/model/struct.Secret.html

use serde::{Deserialize, Serialize};

use kagisecure_core::audit::AuditEntry;
use kagisecure_core::proto::{
    EnvId, EnvironmentSummary, FieldId, ItemId, ItemSummary, LeaseId, LeaseSummary, VaultId,
    VaultSummary,
};

/// The protocol version this build speaks. Bumped when a message changes shape.
///
/// Also bumped when [`ErrorCode`] gains a variant: the enum is closed on the wire (no catch-all
/// variant), so a peer built before the addition cannot decode a reply that carries the new code
/// and would report it as a garbled frame, at whatever moment the code first happened to be sent.
/// Refusing the mismatch once, at `Hello`, is the legible failure.
///
/// * 2 — `VAULT_BUSY` and `VAULT_CONFLICT`, for vault files written by more than one process;
///   `AUDIT_UNAVAILABLE`, for a release refused because its audit entry could not be written
///   first; `INVALID_ARGUMENT`, for an argument that breaks a documented schema rule;
///   [`Request::RequestFill`], [`Response::FillResult`], `FILL_UNAVAILABLE`, `NOTHING_TO_FILL` and
///   `NO_MATCHING_TAB`, for `request_fill` (ADR-0036); and `RATE_LIMITED`, which returned with
///   `request_fill`'s approval-fatigue limits (ADR-0036 §9). (One version for all of them: no
///   build that speaks 2 was released before the last of them was added.)
/// * 3 — [`Request::RunWithEnv`]'s `delivery` ([`Delivery::Stdin`], ADR-0047) and
///   `NOT_POPULATED`. A peer built before it would decode a `stdin` request with the field
///   ignored — and put the values in the child's *environment*, the one place the caller asked
///   them not to go. Refusing the mismatch at `Hello` is what keeps that from happening.
/// * 4 — agent test logins (ADR-0048): [`Request::CreateTestLogin`], [`Request::ListTestLogins`],
///   [`Request::TrashTestLogins`], [`Response::TestLoginCreated`] (with its optional
///   [`TestLoginBinding`]), [`Response::TestLogins`], [`Response::TestLoginsTrashed`] and
///   `TEST_LOGINS_OFF`; and
///   `RATE_LIMITED` with two more fixed messages, for the create rate limit and the vault's cap.
///   The sidecar, the app, the extension and the native-messaging host ship together.
pub const PROTOCOL_VERSION: u32 = 4;

/// Longest `create_environment` name, in characters (mcp-server.md §2.5). One line, not empty.
pub const MAX_ENVIRONMENT_NAME_CHARS: usize = 128;

/// Longest `create_environment` description, in characters (mcp-server.md §2.5).
pub const MAX_DESCRIPTION_CHARS: usize = 512;

/// Longest `add_variables` hint, in characters (mcp-server.md §2.6). One line.
pub const MAX_HINT_CHARS: usize = 200;

/// Most variables one `add_variables` call may declare (mcp-server.md §2.6).
pub const MAX_VARIABLES_PER_CALL: usize = 50;

/// Most arguments a `run_with_env` command may carry (mcp-server.md §2.8).
pub const MAX_RUN_ARGS: usize = 64;

/// Longest `create_test_login` `app`, in characters (ADR-0048 §6). One line, not empty.
pub const MAX_TEST_LOGIN_APP_CHARS: usize = 64;

/// Longest `create_test_login` `purpose`, in characters (ADR-0048 §6). One line, not empty. It is
/// stored as a public field and shown to agents and in the app as agent-written data.
pub const MAX_TEST_LOGIN_PURPOSE_CHARS: usize = 280;

/// Longest `create_test_login` `username`, in characters (ADR-0048 §6). One line, not empty.
pub const MAX_TEST_LOGIN_USERNAME_CHARS: usize = 256;

/// Most websites one test login is saved for (ADR-0048 §6). At least one.
pub const MAX_TEST_LOGIN_WEBSITES: usize = 5;

/// Longest `trash_test_logins` `reason`, in characters (ADR-0048 §12). One line, not empty.
pub const MAX_TEST_LOGIN_TRASH_REASON_CHARS: usize = 200;

/// Most tags an agent may add to a test login beside the ones kagisecure composes (ADR-0048 §6).
pub const MAX_TEST_LOGIN_TAGS: usize = 10;

/// Longest tag an agent may add to a test login, in characters. One line.
pub const MAX_TEST_LOGIN_TAG_CHARS: usize = 64;

/// Longest `reason` an agent may give for a test login, in characters. One line.
pub const MAX_TEST_LOGIN_REASON_CHARS: usize = 200;

/// Longest website a test login may be saved for, in characters. An origin or a URL.
pub const MAX_TEST_LOGIN_WEBSITE_CHARS: usize = 2048;

/// Whether `text` is at most `max` characters and contains no control character other than, when
/// `multi_line`, a line feed or a tab.
///
/// For every string an agent supplies that a human is later shown — on an approval sheet, in the
/// app's environment editor. A limit keeps the sheet readable and the vault small; refusing
/// control characters keeps an agent from laying out lines of its own on a sheet ("Approved by
/// IT") or sneaking a carriage return or an escape sequence into a label. Checked by the process
/// that shows them, not only by the sidecar: any local process can speak this protocol directly.
#[must_use]
pub fn display_text_ok(text: &str, max: usize, multi_line: bool) -> bool {
    text.chars().count() <= max
        && text
            .chars()
            .all(|c| !c.is_control() || (multi_line && matches!(c, '\n' | '\t')))
}

/// The shortest wall-clock limit a `run_with_env` child is given, in seconds (mcp-server.md §2.8).
pub const RUN_TIMEOUT_MIN_SECONDS: u64 = 1;

/// The longest wall-clock limit a `run_with_env` child is given, in seconds (mcp-server.md §2.8).
pub const RUN_TIMEOUT_MAX_SECONDS: u64 = 3600;

/// The limit a `run_with_env` child is given when the caller names none, in seconds.
pub const RUN_TIMEOUT_DEFAULT_SECONDS: u64 = 300;

/// A requested `run_with_env` timeout, brought into the documented
/// [`RUN_TIMEOUT_MIN_SECONDS`]..=[`RUN_TIMEOUT_MAX_SECONDS`] range.
///
/// Applied by the sidecar *and* by the process that spawns the child: the sidecar is a
/// convenience for models, not a trust boundary, and any local process can speak this protocol
/// without it.
#[must_use]
pub fn clamp_run_timeout(requested: u64) -> u64 {
    requested.clamp(RUN_TIMEOUT_MIN_SECONDS, RUN_TIMEOUT_MAX_SECONDS)
}

/// The stable machine-readable error codes from mcp-server.md §7.
///
/// The MCP sidecar passes these through verbatim, so this enum and that table are one thing.
///
/// **Every variant here is constructed somewhere**, and that is the property this comment exists
/// to keep. A code no caller can ever receive is not harmless documentation: the table in §7 tells
/// the *model* what to do about each one, so an unreachable code is standing advice for a
/// situation that cannot arise.
///
/// Two were removed for failing that test rather than given implementations nobody asked for:
///
/// * `RATE_LIMITED` ("back off"), while kagisecure had no rate limiter. What bounds a hostile
///   agent on the injection tools is the approval sheet and the lease, not a counter, and adding a
///   counter to justify a string would have been the tail wagging the dog. It came back — as
///   [`Self::RateLimited`], scoped to `request_fill` — with the one limiter that bounds something
///   no lease does: the human's attention (ADR-0036 §9). `create_test_login` reuses it for the
///   per-agent create limit and the test vault's cap (ADR-0048 §11), each with its own message.
/// * `LEASE_EXPIRED` ("request a fresh injection"). Leases are matched *implicitly* — `write_env_file`
///   and `run_with_env` look for a live lease covering the request and, finding none, simply ask
///   the human again. No tool takes a lease id in order to act, so there is no call an agent can
///   make that fails because a lease expired. The one tool that accepts a `lease_id` at all,
///   `revoke_env_file`, is cleanup: revoking a lease that is already gone is a successful no-op,
///   and answering "request a fresh injection" to an agent that has just finished tidying up would
///   be precisely the wrong instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The process that owns the vault is not running or not reachable.
    #[serde(rename = "APP_NOT_RUNNING")]
    AppNotRunning,
    /// It is running, but the vault is locked.
    #[serde(rename = "VAULT_LOCKED")]
    VaultLocked,
    /// The user declined the approval.
    #[serde(rename = "USER_DENIED")]
    UserDenied,
    /// Nobody answered the approval prompt in time.
    #[serde(rename = "APPROVAL_TIMEOUT")]
    ApprovalTimeout,
    /// Unknown vault, item or environment id — **or** one the user has not made visible to
    /// agents.
    ///
    /// There is deliberately no separate "exists but hidden" code. A code that distinguished the
    /// two would let a caller walk ids and learn which ones name something real in a vault it is
    /// not allowed to read, which is the enumeration `agent_visible` exists to prevent
    /// (threat-model M-8). The agent answers both with this code and with one identical message.
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    /// The path is not absolute, not a directory, or refused by policy.
    #[serde(rename = "INVALID_PATH")]
    InvalidPath,
    /// An argument breaks a documented rule of the tool's schema — a variable name that is not
    /// `^[A-Za-z_][A-Za-z0-9_]*$`, a hint or a name over its length limit, a variable an agent may
    /// not replace — so nothing was asked and nothing changed. Fixing the argument is the only
    /// retry that can succeed.
    ///
    /// Checked by the process that owns the vault, not only by the sidecar: the sidecar is a
    /// convenience for models, and any local process can speak this protocol without it.
    #[serde(rename = "INVALID_ARGUMENT")]
    InvalidArgument,
    /// The target file exists and `overwrite` was not set.
    #[serde(rename = "FILE_EXISTS")]
    FileExists,
    /// Another kagisecure process (the CLI, a second app) held the vault file's write lock for
    /// longer than a request waits, so nothing was changed. Transient: the holder only ever keeps
    /// it for one in-memory change plus one file write.
    #[serde(rename = "VAULT_BUSY")]
    VaultBusy,
    /// The vault file on disk is no longer one this unlocked session will build on: it was
    /// restored from an older copy, replaced by a different file, or removed while the vault was
    /// unlocked. Nothing is changed or released until the user resolves it in the app; retrying
    /// cannot help before then.
    #[serde(rename = "VAULT_CONFLICT")]
    VaultConflict,
    /// A value was about to be released — a `.env` written, a command started — and the audit
    /// entry that must be on disk first could not be written, so **nothing was released**. The
    /// vault file cannot be written right now (a full disk, a broken file, another process holding
    /// the lock); the app shows the user why. Fail closed: no release happens without its record.
    #[serde(rename = "AUDIT_UNAVAILABLE")]
    AuditUnavailable,
    /// `request_fill` cannot be served at all: the user has not turned agent fills on, or no
    /// browser with the kagisecure extension is connected to ask (ADR-0036 §11). Answered before
    /// the item is looked up, so it says nothing about the item. Nothing was filled, and retrying
    /// cannot help until the user changes something.
    #[serde(rename = "FILL_UNAVAILABLE")]
    FillUnavailable,
    /// `request_fill` named a field the item has no value for, or an archived item, so there is
    /// nothing to type (ADR-0036 §11). Not an oracle: `describe_item` already reports which
    /// fields have a value. Nothing was filled; `describe_item` says what the item has.
    #[serde(rename = "NOTHING_TO_FILL")]
    NothingToFill,
    /// `request_fill` found no tab to fill: the tab in front is not at the claimed origin, is not
    /// a sign-in page kagisecure recognizes, is not visible, is not a site saved for the item, or
    /// changed before the fill — or more than one browser has such a tab in front (ADR-0036
    /// §3.2, §11.2). Deliberately one code with one message for every one of those reasons, so it
    /// is not an oracle for which websites an item is saved for. Nothing was filled.
    #[serde(rename = "NO_MATCHING_TAB")]
    NoMatchingTab,
    /// `request_fill` was refused without a sheet because the user's attention is budgeted
    /// (ADR-0036 §9.1): this agent has had three sheets in ten minutes, or another agent fill is
    /// already in progress and sheets are shown one at a time, never queued. Answered before the
    /// item is looked up, so it says nothing about the item. Nothing was filled; the user has been
    /// told about an agent over its budget.
    ///
    /// Also `create_test_login`'s answer for an agent over ten creates in ten minutes, or a test
    /// vault already holding its 200 live items (ADR-0048 §11). Nothing was created.
    #[serde(rename = "RATE_LIMITED")]
    RateLimited,
    /// Returned only by the unattended socket (ADR-0042 §6): the request is not covered by a
    /// standing grant of the calling run's job — or does not come from a run at all. One code and
    /// one message for every reason, so a job's agent learns nothing about which grants exist; the
    /// reason is in the machine vault's audit log. Nothing was released, and a request no grant
    /// covers has suspended every grant of the job.
    #[serde(rename = "NOT_GRANTED")]
    NotGranted,
    /// Returned only by the unattended socket (ADR-0042 §6): the machine vault is not armed, so
    /// nothing is released unattended. Nothing was looked at.
    #[serde(rename = "UNATTENDED_PAUSED")]
    UnattendedPaused,
    /// `run_with_env` with `delivery: "stdin"` named variables that have no value yet — the user
    /// has not entered them in kagisecure. Answered before any sheet, and the message names the
    /// variables (names are metadata: `list_environments` already reports `populated`). Nothing
    /// was asked or released (ADR-0047).
    #[serde(rename = "NOT_POPULATED")]
    NotPopulated,
    /// `create_test_login`, `list_test_logins` or `trash_test_logins` while the user has agent test logins turned off
    /// in Settings, or from a caller kagisecure cannot identify (ADR-0048 §1, §11). Answered
    /// before anything is looked up, so it says nothing about the vault. Nothing was created;
    /// retrying cannot help until the user turns the switch on.
    #[serde(rename = "TEST_LOGINS_OFF")]
    TestLoginsOff,
    /// A bug.
    #[serde(rename = "INTERNAL")]
    Internal,
}

impl ErrorCode {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AppNotRunning => "APP_NOT_RUNNING",
            Self::VaultLocked => "VAULT_LOCKED",
            Self::UserDenied => "USER_DENIED",
            Self::ApprovalTimeout => "APPROVAL_TIMEOUT",
            Self::NotFound => "NOT_FOUND",
            Self::InvalidPath => "INVALID_PATH",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::FileExists => "FILE_EXISTS",
            Self::VaultBusy => "VAULT_BUSY",
            Self::VaultConflict => "VAULT_CONFLICT",
            Self::AuditUnavailable => "AUDIT_UNAVAILABLE",
            Self::FillUnavailable => "FILL_UNAVAILABLE",
            Self::NothingToFill => "NOTHING_TO_FILL",
            Self::NoMatchingTab => "NO_MATCHING_TAB",
            Self::RateLimited => "RATE_LIMITED",
            Self::NotGranted => "NOT_GRANTED",
            Self::UnattendedPaused => "UNATTENDED_PAUSED",
            Self::NotPopulated => "NOT_POPULATED",
            Self::TestLoginsOff => "TEST_LOGINS_OFF",
            Self::Internal => "INTERNAL",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// What the caller says about itself on connect.
///
/// Every field here is **self-reported and therefore display-only** (architecture §5,
/// threat-model M-19). The daemon uses the socket's own peer credentials for anything it acts on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// The MCP client's name, as it told the sidecar in `clientInfo`.
    pub name: String,
    /// Its version string.
    pub version: String,
    /// The sidecar's own process id.
    pub pid: u32,
    /// The sidecar's parent — normally the MCP client itself.
    pub parent_pid: Option<u32>,
    /// The sidecar's `argv[0]`.
    pub argv0: String,
    /// The directory the sidecar was started in, which is usually the project root.
    pub cwd: Option<String>,
}

/// Whether captured output comes back (mcp-server.md §2.8). There is no unmasked option.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputMode {
    /// Return stdout/stderr with injected values replaced.
    #[default]
    #[serde(rename = "scrubbed")]
    Scrubbed,
    /// Return only the exit code.
    #[serde(rename = "none")]
    None,
}

/// How `run_with_env` hands the values to the command (mcp-server.md §2.8, ADR-0047).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Delivery {
    /// As environment variables of the child — what `run_with_env` always did.
    #[default]
    #[serde(rename = "environment")]
    Environment,
    /// Written once to the child's standard input as `NAME\0VALUE\0` pairs, in the order the
    /// variables were selected, which is then closed. Nothing is added to the child's
    /// environment or argv. Every such run is its own approval: no lease covers it and the grant
    /// is always for one run.
    #[serde(rename = "stdin")]
    Stdin,
}

impl Delivery {
    /// The wire spelling, which is also the name `run_with_env`'s schema uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Stdin => "stdin",
        }
    }
}

/// A field of an item, for binding a variable to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRef {
    /// The item.
    pub item_id: ItemId,
    /// The field within it.
    pub field_id: FieldId,
}

/// One variable an agent is asking for. **There is no `value` field, and there never will be.**
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableRequest {
    /// The variable name.
    pub name: String,
    /// Bind to an existing vault field instead of prompting the user.
    #[serde(default)]
    pub bind_to: Option<FieldRef>,
    /// Shown to the user to explain what to paste.
    #[serde(default)]
    pub hint: Option<String>,
}

/// A field `request_fill` may ask to have filled into a browser tab (mcp-server.md §2.10).
///
/// A **name**, not a value: which of the item's fields the user is asked to let kagisecure type
/// into the page. There is no variant, and no field on any message here, that carries what is
/// typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentFillField {
    /// The login's username.
    Username,
    /// The login's password.
    Password,
    /// A one-time code generated from the item's one-time-password field. Always requested on
    /// its own (ADR-0036 §7.4).
    OneTimeCode,
    /// A sign-up fill (ADR-0048 §7): the item's password, typed into every new-password box of a
    /// recognised sign-up form. Served only for sealed agent test logins; never requested with
    /// `password` or `one_time_code`.
    NewPassword,
}

impl AgentFillField {
    /// The wire spelling, which is also the name `request_fill`'s schema uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::OneTimeCode => "one_time_code",
            Self::NewPassword => "new_password",
        }
    }
}

/// What `request_fill` asks for when the caller names no fields.
pub const DEFAULT_AGENT_FILL_FIELDS: [AgentFillField; 2] =
    [AgentFillField::Username, AgentFillField::Password];

/// Whether `fields` is a combination `request_fill` accepts (mcp-server.md §2.10): at least one
/// field, none twice, a one-time code only on its own, and a new password (ADR-0048 §7) only
/// alone or with the username.
///
/// A one-time code never rides along with a password, because the pair is the account: an agent
/// that can read the page after both has everything needed to sign in elsewhere within the code's
/// window (ADR-0036 §7.4). Checked by the sidecar and, when it serves the request, by the process
/// that owns the vault: any local process can speak this protocol without the sidecar.
#[must_use]
pub fn agent_fill_fields_ok(fields: &[AgentFillField]) -> bool {
    let distinct: std::collections::BTreeSet<_> = fields.iter().collect();
    !fields.is_empty()
        && distinct.len() == fields.len()
        && (!fields.contains(&AgentFillField::OneTimeCode) || fields.len() == 1)
        && (!fields.contains(&AgentFillField::NewPassword)
            || fields
                .iter()
                .all(|f| matches!(f, AgentFillField::NewPassword | AgentFillField::Username)))
}

/// How a test login's password is generated (ADR-0048 §4): a length from a fixed menu, and two
/// switches. Lower case, upper case and digits are always on. There is no alphabet, no seed and
/// nothing that could carry a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestLoginGenerator {
    /// 20, 24, 32, 48 or 64.
    #[serde(default = "default_test_login_length")]
    pub length: u32,
    /// Include symbols.
    #[serde(default = "default_true")]
    pub symbols: bool,
    /// Leave out characters that are easy to misread.
    #[serde(default)]
    pub avoid_ambiguous: bool,
}

impl Default for TestLoginGenerator {
    fn default() -> Self {
        Self {
            length: default_test_login_length(),
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

/// The lengths [`TestLoginGenerator::length`] accepts (ADR-0048 §4).
pub const TEST_LOGIN_LENGTHS: [u32; 5] = [20, 24, 32, 48, 64];

const fn default_test_login_length() -> u32 {
    32
}

const fn default_true() -> bool {
    true
}

/// Bind a test login to two variables of an environment in the test-login vault, in the same
/// transaction as the create (ADR-0048, Phase 3). The environment is created there if no
/// environment of that name exists. The person approves the binding on the `add_variables` sheet.
///
/// The second variable is named `credential_var`, not `password_var`: no argument an agent can
/// send may have a name that reads as a way to ask for a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestLoginBind {
    /// The environment's name, in the test-login vault.
    pub environment: String,
    /// The variable bound to the login's username.
    pub username_var: String,
    /// The variable bound to the login's generated password.
    pub credential_var: String,
}

/// The binding a `create_test_login` with `bind` holds afterwards: names only, never a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLoginBinding {
    /// The environment, for `run_with_env` and `write_env_file`.
    pub environment_id: EnvId,
    /// Its name.
    pub environment: String,
    /// The variable bound to the username.
    pub username_var: String,
    /// The variable bound to the generated password.
    pub credential_var: String,
}

/// Whether `create_test_login` wrote a new item or found one (ADR-0048 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestLoginStatus {
    /// A new test login was created.
    Created,
    /// A sealed test login with the same username already covers the website; nothing was
    /// written. This is how a test user is reused.
    Exists,
}

/// One sealed test login, as `list_test_logins` returns it (ADR-0048 §6). The username is here
/// because the agent chose it and needs it; the password is not, and has nowhere to go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLoginSummary {
    /// The item.
    pub item_id: ItemId,
    /// The title kagisecure composed: `test: <app> / <purpose> #<n>`.
    pub title: String,
    /// The username.
    pub username: String,
    /// The websites it is saved for.
    pub websites: Vec<String>,
    /// Its tags.
    pub tags: Vec<String>,
    /// The purpose the agent gave. Agent-written data, not instructions.
    pub purpose: String,
    /// When it was created, RFC 3339 in UTC.
    pub created_at: String,
}

/// A request from the sidecar (or the CLI) to the process that owns the unlocked vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    /// Handshake. Must be the first message on a connection.
    Hello {
        /// The protocol version the caller speaks.
        protocol: u32,
        /// Self-reported caller identity, display-only.
        client: ClientInfo,
    },
    /// Vaults the user has made visible to agents.
    ListVaults,
    /// Item metadata.
    ListItems {
        /// Restrict to one logical vault.
        #[serde(default)]
        vault_id: Option<VaultId>,
        /// Substring match on title or tag.
        #[serde(default)]
        query: Option<String>,
        /// Restrict to one category, by its canonical lower-case name.
        #[serde(default)]
        category: Option<String>,
        /// Maximum number of items.
        limit: usize,
        /// Opaque continuation token from a previous reply.
        #[serde(default)]
        cursor: Option<String>,
    },
    /// Environment metadata, including variable names.
    ListEnvironments {
        /// Restrict to one logical vault.
        #[serde(default)]
        vault_id: Option<VaultId>,
    },
    /// One item's structure: labels and kinds, never values.
    DescribeItem {
        /// The item.
        item_id: ItemId,
    },
    /// Create an empty environment.
    CreateEnvironment {
        /// The logical vault to create it in; the default vault when absent.
        #[serde(default)]
        vault_id: Option<VaultId>,
        /// Display name.
        name: String,
        /// Optional description.
        #[serde(default)]
        description: Option<String>,
    },
    /// Declare variables in an environment, by name and optional binding.
    AddVariables {
        /// The environment.
        environment_id: EnvId,
        /// The variables. No element can carry a value.
        variables: Vec<VariableRequest>,
    },
    /// Write a `.env` file into a directory.
    WriteEnvFile {
        /// The environment.
        environment_id: EnvId,
        /// Absolute path to the project directory.
        directory: String,
        /// File name within it.
        filename: String,
        /// Subset of variable names; all of them when absent.
        #[serde(default)]
        variables: Option<Vec<String>>,
        /// Replace a file that is already there.
        overwrite: bool,
        /// Requested lease duration. The user may shorten it.
        ttl_seconds: u64,
    },
    /// Run a command with an environment injected.
    RunWithEnv {
        /// The environment.
        environment_id: EnvId,
        /// Executable. Not a shell string.
        command: String,
        /// Arguments, passed to the OS verbatim.
        args: Vec<String>,
        /// Absolute working directory.
        cwd: String,
        /// Subset of variable names; all of them when absent.
        #[serde(default)]
        variables: Option<Vec<String>>,
        /// Wall-clock limit for the child, in seconds. Clamped by the receiver to
        /// [`RUN_TIMEOUT_MIN_SECONDS`]..=[`RUN_TIMEOUT_MAX_SECONDS`] ([`clamp_run_timeout`]).
        timeout_seconds: u64,
        /// Whether to return the child's output.
        output: OutputMode,
        /// How the values reach the child. Absent means [`Delivery::Environment`].
        #[serde(default)]
        delivery: Delivery,
    },
    /// Shred a written `.env` and kill its lease.
    RevokeEnvFile {
        /// The lease to revoke.
        #[serde(default)]
        lease_id: Option<LeaseId>,
        /// The path to shred.
        #[serde(default)]
        path: Option<String>,
    },
    /// Ask the user to let kagisecure fill `fields` of an item into the browser tab in front
    /// (ADR-0036). The reply is [`Response::FillResult`] — which fields were written, never what.
    RequestFill {
        /// The item, by the id `list_items` returned, exactly as [`Request::DescribeItem`] takes
        /// it.
        item_id: ItemId,
        /// The origin the agent says the page it drives is at. A claim, checked against the
        /// origin the browser reports; never trusted on its own.
        origin: String,
        /// The fields to fill. See [`agent_fill_fields_ok`] for the combinations accepted.
        fields: Vec<AgentFillField>,
    },
    /// Create a test login whose password kagisecure generates and keeps (ADR-0048 §6). The reply
    /// is [`Response::TestLoginCreated`] — the item, its username and websites, never the password.
    CreateTestLogin {
        /// The app under test.
        app: String,
        /// What this test user is for, e.g. `buyer`. Stored as a public field.
        purpose: String,
        /// The username the agent chose, which it needs to drive the page.
        username: String,
        /// The websites the login is saved for: 1 to [`MAX_TEST_LOGIN_WEBSITES`].
        websites: Vec<String>,
        /// How the password is generated, from a fixed menu. Absent means the default.
        #[serde(default)]
        generator: Option<TestLoginGenerator>,
        /// Tags beside the ones kagisecure composes.
        #[serde(default)]
        tags: Vec<String>,
        /// Why, for the sheet when one is shown.
        #[serde(default)]
        reason: Option<String>,
        /// Also bind the login to two variables of an environment in the test-login vault.
        #[serde(default)]
        bind: Option<TestLoginBind>,
    },
    /// Move sealed test logins in the test-login vault to the trash (ADR-0048 §12): a soft trash,
    /// in one transaction. At least one of `website` and `tag` is required. Automatic only when
    /// every matched login's websites need no approval (§3); otherwise refused, nothing trashed.
    TrashTestLogins {
        /// Only logins saved for a website covering this one.
        #[serde(default)]
        website: Option<String>,
        /// Only logins with exactly this tag.
        #[serde(default)]
        tag: Option<String>,
        /// Why, for the audit log's reader. One line.
        reason: String,
    },
    /// Sealed test logins in the test-login vault (ADR-0048 §6).
    ListTestLogins {
        /// Only logins saved for a website covering this one.
        #[serde(default)]
        website: Option<String>,
        /// Only logins with exactly this tag.
        #[serde(default)]
        tag: Option<String>,
        /// Case-insensitive substring of the title, username, purpose or a tag.
        #[serde(default)]
        query: Option<String>,
        /// Maximum number of logins.
        limit: usize,
        /// Opaque continuation token from a previous reply.
        #[serde(default)]
        cursor: Option<String>,
    },
    /// Read the audit log, newest last.
    Audit {
        /// Maximum number of entries, taken from the end.
        limit: usize,
        /// Also verify the hash chain.
        verify: bool,
    },
    /// List live leases.
    ListLeases,
    /// Drop the vault key and every lease.
    Lock,
}

impl Request {
    /// The name recorded in the audit log for this request.
    #[must_use]
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::ListVaults => "list_vaults",
            Self::ListItems { .. } => "list_items",
            Self::ListEnvironments { .. } => "list_environments",
            Self::DescribeItem { .. } => "describe_item",
            Self::CreateEnvironment { .. } => "create_environment",
            Self::AddVariables { .. } => "add_variables",
            Self::WriteEnvFile { .. } => "write_env_file",
            Self::RunWithEnv { .. } => "run_with_env",
            Self::RevokeEnvFile { .. } => "revoke_env_file",
            Self::RequestFill { .. } => "request_fill",
            Self::CreateTestLogin { .. } => "create_test_login",
            Self::ListTestLogins { .. } => "list_test_logins",
            Self::TrashTestLogins { .. } => "trash_test_logins",
            Self::Audit { .. } => "audit",
            Self::ListLeases => "list_leases",
            Self::Lock => "lock",
        }
    }
}

/// The status `add_variables` reports back (mcp-server.md §2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddVariablesStatus {
    /// Everything was bound to an existing field; nothing is waiting on a human.
    #[serde(rename = "complete")]
    Complete,
    /// At least one variable needs a value the agent is not allowed to supply.
    #[serde(rename = "pending_user_input")]
    PendingUserInput,
}

/// A reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply")]
pub enum Response {
    /// Handshake accepted.
    Hello {
        /// The daemon's own name, for the sidecar's logs.
        server: String,
        /// Its version.
        version: String,
        /// The protocol version it speaks.
        protocol: u32,
        /// How the daemon rendered the caller's identity, after checking peer credentials.
        client_identity: String,
        /// Whether that identity was verified rather than taken on trust.
        client_verified: bool,
    },
    /// Vault metadata.
    Vaults {
        /// The vaults the user has made visible to agents.
        vaults: Vec<VaultSummary>,
    },
    /// Item metadata.
    Items {
        /// The page.
        items: Vec<ItemSummary>,
        /// Continuation token, if there is more.
        next_cursor: Option<String>,
    },
    /// Environment metadata.
    Environments {
        /// The environments.
        environments: Vec<EnvironmentSummary>,
    },
    /// One item's structure.
    Item {
        /// The item.
        item: Box<ItemSummary>,
    },
    /// One environment's structure.
    Environment {
        /// The environment.
        environment: Box<EnvironmentSummary>,
    },
    /// The outcome of `add_variables`.
    AddedVariables {
        /// The environment.
        environment_id: EnvId,
        /// Names bound to an existing field.
        bound: Vec<String>,
        /// Names awaiting a value from the user.
        pending: Vec<String>,
        /// Where the user goes to supply them.
        deep_link: String,
        /// Whether anything is waiting on a human.
        status: AddVariablesStatus,
    },
    /// A `.env` file was written.
    WroteEnvFile {
        /// Absolute path of the file.
        path: String,
        /// The names written, in order.
        variables_written: Vec<String>,
        /// Size of the file.
        bytes: usize,
        /// The lease that authorized it.
        lease_id: LeaseId,
        /// When that lease dies, RFC 3339 in UTC.
        expires_at: String,
        /// Whether a `.gitignore` covers the file; absent outside a git work tree.
        gitignored: Option<bool>,
    },
    /// A command ran.
    Ran {
        /// Exit status, or `None` if the child was killed.
        exit_code: Option<i32>,
        /// Captured stdout, scrubbed, when the caller asked for output.
        stdout: Option<String>,
        /// Captured stderr, scrubbed, when the caller asked for output.
        stderr: Option<String>,
        /// Whether either stream hit the cap.
        truncated: bool,
        /// How many injected values were replaced.
        scrubbed: usize,
        /// The lease that authorized it.
        lease_id: LeaseId,
        /// When that lease dies, RFC 3339 in UTC.
        expires_at: String,
    },
    /// `request_fill` wrote into the page.
    ///
    /// Field **names** only. There is no member a value could occupy, and the process that did
    /// the typing is the one that owns the vault, not the caller.
    FillResult {
        /// The fields written into the page.
        fields_written: Vec<AgentFillField>,
        /// Fields the same approval may still write on the sign-in's next page (ADR-0036 §7.3);
        /// empty unless the page asked for the username first.
        fields_pending: Vec<AgentFillField>,
    },
    /// `create_test_login` created or found a test login. No member carries the password.
    TestLoginCreated {
        /// Whether it was created now or already existed.
        status: TestLoginStatus,
        /// The item.
        item_id: ItemId,
        /// Its username.
        username: String,
        /// The websites it is saved for.
        websites: Vec<String>,
        /// The title kagisecure composed.
        title: String,
        /// The environment binding, when the request asked for one. Boxed: it is rare, and it
        /// would otherwise make every `Response` larger.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding: Option<Box<TestLoginBinding>>,
    },
    /// `trash_test_logins` moved these test logins to the trash.
    TestLoginsTrashed {
        /// How many.
        trashed: usize,
        /// Which.
        item_ids: Vec<ItemId>,
    },
    /// Sealed test logins.
    TestLogins {
        /// The page.
        items: Vec<TestLoginSummary>,
        /// Continuation token, if there is more.
        next_cursor: Option<String>,
    },
    /// Files were shredded and leases dropped.
    Revoked {
        /// Paths that were removed.
        shredded: Vec<String>,
    },
    /// Audit entries, oldest first.
    Audit {
        /// The entries.
        entries: Vec<AuditEntry>,
        /// Whether the chain verified, when the caller asked.
        chain_intact: Option<bool>,
    },
    /// Live leases.
    Leases {
        /// The live leases.
        leases: Vec<LeaseSummary>,
    },
    /// The vault was locked.
    Locked,
    /// Something went wrong, with a code from mcp-server.md §7.
    Error {
        /// The stable code.
        code: ErrorCode,
        /// A message written for the model: it says what to do next.
        message: String,
    },
}

impl Response {
    /// A structured error reply.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Format unix seconds as RFC 3339 in UTC, e.g. `2026-09-09T12:15:00Z`.
///
/// A date library would be a dependency for one function; the civil-from-days arithmetic is
/// Howard Hinnant's and is exact for every value this will ever see.
#[must_use]
pub fn rfc3339(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_use_the_documented_spellings() {
        for (code, spelling) in [
            (ErrorCode::AppNotRunning, "APP_NOT_RUNNING"),
            (ErrorCode::VaultLocked, "VAULT_LOCKED"),
            (ErrorCode::UserDenied, "USER_DENIED"),
            (ErrorCode::ApprovalTimeout, "APPROVAL_TIMEOUT"),
            (ErrorCode::NotFound, "NOT_FOUND"),
            (ErrorCode::InvalidPath, "INVALID_PATH"),
            (ErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (ErrorCode::FileExists, "FILE_EXISTS"),
            (ErrorCode::VaultBusy, "VAULT_BUSY"),
            (ErrorCode::VaultConflict, "VAULT_CONFLICT"),
            (ErrorCode::AuditUnavailable, "AUDIT_UNAVAILABLE"),
            (ErrorCode::FillUnavailable, "FILL_UNAVAILABLE"),
            (ErrorCode::NothingToFill, "NOTHING_TO_FILL"),
            (ErrorCode::NoMatchingTab, "NO_MATCHING_TAB"),
            (ErrorCode::RateLimited, "RATE_LIMITED"),
            (ErrorCode::NotGranted, "NOT_GRANTED"),
            (ErrorCode::UnattendedPaused, "UNATTENDED_PAUSED"),
            (ErrorCode::NotPopulated, "NOT_POPULATED"),
            (ErrorCode::TestLoginsOff, "TEST_LOGINS_OFF"),
            (ErrorCode::Internal, "INTERNAL"),
        ] {
            assert_eq!(code.as_str(), spelling);
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{spelling}\"")
            );
        }
    }

    #[test]
    fn run_timeouts_are_clamped_to_the_documented_range() {
        assert_eq!(clamp_run_timeout(0), RUN_TIMEOUT_MIN_SECONDS);
        assert_eq!(clamp_run_timeout(1), 1);
        assert_eq!(clamp_run_timeout(3600), 3600);
        assert_eq!(clamp_run_timeout(3601), RUN_TIMEOUT_MAX_SECONDS);
        assert_eq!(clamp_run_timeout(u64::MAX), RUN_TIMEOUT_MAX_SECONDS);
        assert_eq!(
            clamp_run_timeout(RUN_TIMEOUT_DEFAULT_SECONDS),
            RUN_TIMEOUT_DEFAULT_SECONDS
        );
    }

    #[test]
    fn requests_round_trip_through_json() {
        let cases = vec![
            Request::ListVaults,
            Request::ListItems {
                vault_id: None,
                query: Some("acme".to_owned()),
                category: Some("database".to_owned()),
                limit: 50,
                cursor: None,
            },
            Request::WriteEnvFile {
                environment_id: EnvId::new(),
                directory: "/tmp/p".to_owned(),
                filename: ".env".to_owned(),
                variables: Some(vec!["A".to_owned()]),
                overwrite: false,
                ttl_seconds: 900,
            },
            Request::RunWithEnv {
                environment_id: EnvId::new(),
                command: "printenv".to_owned(),
                args: vec!["A".to_owned()],
                cwd: "/tmp/p".to_owned(),
                variables: None,
                timeout_seconds: 300,
                output: OutputMode::Scrubbed,
                delivery: Delivery::Environment,
            },
            Request::RunWithEnv {
                environment_id: EnvId::new(),
                command: "/usr/local/bin/import-secrets".to_owned(),
                args: vec!["prod".to_owned()],
                cwd: "/tmp/p".to_owned(),
                variables: Some(vec!["A".to_owned()]),
                timeout_seconds: 300,
                output: OutputMode::None,
                delivery: Delivery::Stdin,
            },
            Request::RequestFill {
                item_id: ItemId::new(),
                origin: "https://example.com".to_owned(),
                fields: DEFAULT_AGENT_FILL_FIELDS.to_vec(),
            },
            Request::CreateTestLogin {
                app: "shop".to_owned(),
                purpose: "buyer".to_owned(),
                username: "buyer1@example.test".to_owned(),
                websites: vec!["http://localhost:47800".to_owned()],
                generator: Some(TestLoginGenerator::default()),
                tags: vec![],
                reason: None,
                bind: Some(TestLoginBind {
                    environment: "shop-e2e".to_owned(),
                    username_var: "SHOP_USER".to_owned(),
                    credential_var: "SHOP_PASS".to_owned(),
                }),
            },
            Request::TrashTestLogins {
                website: Some("http://localhost:47800".to_owned()),
                tag: None,
                reason: "environment rebuilt".to_owned(),
            },
            Request::ListTestLogins {
                website: None,
                tag: Some("app:shop".to_owned()),
                query: None,
                limit: 50,
                cursor: None,
            },
            Request::Lock,
        ];
        for case in cases {
            let text = serde_json::to_string(&case).unwrap();
            let back: Request = serde_json::from_str(&text).unwrap();
            assert_eq!(back, case);
        }
    }

    #[test]
    fn responses_round_trip_through_json() {
        let cases = vec![
            Response::Vaults { vaults: vec![] },
            Response::Environments {
                environments: vec![],
            },
            Response::Revoked {
                shredded: vec!["/tmp/p/.env".to_owned()],
            },
            Response::FillResult {
                fields_written: vec![AgentFillField::Username],
                fields_pending: vec![AgentFillField::Password],
            },
            Response::error(ErrorCode::UserDenied, "The user declined."),
            Response::error(ErrorCode::FillUnavailable, "Agent fills are off."),
            Response::Locked,
        ];
        for case in cases {
            let text = serde_json::to_string(&case).unwrap();
            let back: Response = serde_json::from_str(&text).unwrap();
            assert_eq!(back, case);
        }
    }

    #[test]
    fn the_add_variables_schema_has_no_place_to_put_a_value() {
        // A JSON body with a `value` is rejected rather than quietly ignored, because
        // `VariableRequest` denies unknown fields by way of its exact field set plus serde's
        // default of erroring on missing required ones. This asserts the positive half: what the
        // schema *does* accept is a name, a binding and a hint.
        let text = r#"{"name":"STRIPE_SECRET_KEY","hint":"paste the live key"}"#;
        let parsed: VariableRequest = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.name, "STRIPE_SECRET_KEY");
        assert!(parsed.bind_to.is_none());

        let rendered = serde_json::to_string(&parsed).unwrap();
        assert!(!rendered.contains("value"));
    }

    #[test]
    fn delivery_defaults_to_the_environment_and_uses_the_documented_spellings() {
        assert_eq!(Delivery::default(), Delivery::Environment);
        for (delivery, spelling) in [
            (Delivery::Environment, "environment"),
            (Delivery::Stdin, "stdin"),
        ] {
            assert_eq!(delivery.as_str(), spelling);
            assert_eq!(
                serde_json::to_string(&delivery).unwrap(),
                format!("\"{spelling}\"")
            );
        }
        // A request from a caller that predates the field is an environment delivery.
        let id = EnvId::new();
        let text = format!(
            r#"{{"op":"RunWithEnv","environment_id":"{id}","command":"true","args":[],"cwd":"/tmp","variables":null,"timeout_seconds":5,"output":"none"}}"#
        );
        let parsed: Request = serde_json::from_str(&text).unwrap();
        assert!(matches!(
            parsed,
            Request::RunWithEnv {
                delivery: Delivery::Environment,
                ..
            }
        ));
    }

    #[test]
    fn output_defaults_to_scrubbed() {
        assert_eq!(OutputMode::default(), OutputMode::Scrubbed);
    }

    #[test]
    fn timestamps_render_as_rfc_3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_757_376_000), "2025-09-09T00:00:00Z");
        assert_eq!(rfc3339(1_757_376_000 + 3661), "2025-09-09T01:01:01Z");
    }

    #[test]
    fn every_request_has_an_audit_name() {
        assert_eq!(Request::ListVaults.tool_name(), "list_vaults");
        assert_eq!(Request::Lock.tool_name(), "lock");
        let fill = Request::RequestFill {
            item_id: ItemId::new(),
            origin: "https://example.com".to_owned(),
            fields: vec![AgentFillField::Password],
        };
        assert_eq!(fill.tool_name(), "request_fill");
    }

    #[test]
    fn agent_fill_fields_use_the_documented_spellings() {
        for (field, spelling) in [
            (AgentFillField::Username, "username"),
            (AgentFillField::Password, "password"),
            (AgentFillField::OneTimeCode, "one_time_code"),
            (AgentFillField::NewPassword, "new_password"),
        ] {
            assert_eq!(field.as_str(), spelling);
            assert_eq!(
                serde_json::to_string(&field).unwrap(),
                format!("\"{spelling}\"")
            );
        }
    }

    #[test]
    fn one_time_code_cannot_be_combined_with_a_password() {
        use AgentFillField::{OneTimeCode, Password, Username};
        for accepted in [
            &[Username, Password][..],
            &[Password, Username],
            &[Username],
            &[Password],
            &[OneTimeCode],
        ] {
            assert!(agent_fill_fields_ok(accepted), "{accepted:?}");
        }
        for refused in [
            &[][..],
            &[OneTimeCode, Password],
            &[Password, OneTimeCode],
            &[Username, OneTimeCode],
            &[Username, Password, OneTimeCode],
            &[Password, Password],
            &[OneTimeCode, OneTimeCode],
        ] {
            assert!(!agent_fill_fields_ok(refused), "{refused:?}");
        }
    }

    #[test]
    fn new_password_goes_alone_or_with_the_username() {
        use AgentFillField::{NewPassword, OneTimeCode, Password, Username};
        for accepted in [
            &[Username, NewPassword][..],
            &[NewPassword, Username],
            &[NewPassword],
        ] {
            assert!(agent_fill_fields_ok(accepted), "{accepted:?}");
        }
        for refused in [
            &[NewPassword, Password][..],
            &[Username, Password, NewPassword],
            &[NewPassword, OneTimeCode],
            &[NewPassword, NewPassword],
        ] {
            assert!(!agent_fill_fields_ok(refused), "{refused:?}");
        }
    }

    #[test]
    fn a_fill_result_names_fields_and_carries_nothing_else() {
        let rendered = serde_json::to_value(Response::FillResult {
            fields_written: vec![AgentFillField::Username, AgentFillField::Password],
            fields_pending: vec![],
        })
        .unwrap();
        let mut keys: Vec<&str> = rendered
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["fields_pending", "fields_written", "reply"]);
        assert_eq!(rendered["fields_written"][1], "password");
    }

    #[test]
    fn test_login_messages_have_no_place_for_a_password() {
        let created = serde_json::to_value(Response::TestLoginCreated {
            status: TestLoginStatus::Created,
            item_id: ItemId::new(),
            username: "buyer1@example.test".to_owned(),
            websites: vec!["http://localhost:47800".to_owned()],
            title: "test: shop / buyer #1".to_owned(),
            binding: None,
        })
        .unwrap();
        let mut keys: Vec<&str> = created
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "item_id", "reply", "status", "title", "username", "websites"
            ]
        );
        assert_eq!(created["status"], "created");

        // A binding carries names, never a value.
        let bound = serde_json::to_value(TestLoginBinding {
            environment_id: EnvId::new(),
            environment: "shop-e2e".to_owned(),
            username_var: "SHOP_USER".to_owned(),
            credential_var: "SHOP_PASS".to_owned(),
        })
        .unwrap();
        let mut keys: Vec<&str> = bound
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "credential_var",
                "environment",
                "environment_id",
                "username_var"
            ]
        );
        let trashed = serde_json::to_value(Response::TestLoginsTrashed {
            trashed: 1,
            item_ids: vec![ItemId::new()],
        })
        .unwrap();
        assert_eq!(trashed["trashed"], 1);
        // `bind` refuses an unknown member.
        assert!(
            serde_json::from_str::<TestLoginBind>(
                r#"{"environment":"e","username_var":"U","credential_var":"P","value":"x"}"#
            )
            .is_err()
        );

        // The generator refuses anything beyond its menu's three members.
        let parsed: Result<TestLoginGenerator, _> =
            serde_json::from_str(r#"{"length":32,"alphabet":"ab"}"#);
        assert!(parsed.is_err());
        let defaulted: TestLoginGenerator = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, TestLoginGenerator::default());
        assert_eq!(defaulted.length, 32);
        assert!(defaulted.symbols);
        assert!(TEST_LOGIN_LENGTHS.contains(&defaulted.length));
    }
}

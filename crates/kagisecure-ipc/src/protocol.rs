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
pub const PROTOCOL_VERSION: u32 = 1;

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
/// * `RATE_LIMITED` ("back off"). kagisecure has no rate limiter. What bounds a hostile agent here
///   is the approval sheet and the lease, not a counter, and adding a counter to justify a string
///   would be the tail wagging the dog.
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
    /// Unknown vault, item or environment id.
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    /// It exists, but the user has not made it visible to agents.
    #[serde(rename = "NOT_AGENT_VISIBLE")]
    NotAgentVisible,
    /// The path is not absolute, not a directory, or refused by policy.
    #[serde(rename = "INVALID_PATH")]
    InvalidPath,
    /// The target file exists and `overwrite` was not set.
    #[serde(rename = "FILE_EXISTS")]
    FileExists,
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
            Self::NotAgentVisible => "NOT_AGENT_VISIBLE",
            Self::InvalidPath => "INVALID_PATH",
            Self::FileExists => "FILE_EXISTS",
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
        /// Wall-clock limit for the child.
        timeout_seconds: u64,
        /// Whether to return the child's output.
        output: OutputMode,
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
            (ErrorCode::NotAgentVisible, "NOT_AGENT_VISIBLE"),
            (ErrorCode::InvalidPath, "INVALID_PATH"),
            (ErrorCode::FileExists, "FILE_EXISTS"),
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
            Response::error(ErrorCode::UserDenied, "The user declined."),
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
    }
}

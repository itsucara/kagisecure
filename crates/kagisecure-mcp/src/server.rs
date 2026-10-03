//! The ten tools (mcp-server.md §2).
//!
//! # What this file is allowed to do
//!
//! Every tool here does the same three things: validate its arguments, forward one
//! [`Request`] to the process that owns the unlocked vault, and render
//! the reply as plain JSON. It cannot do anything else, because it has nothing else: no vault
//! open path, no KDF, no keychain access, and — the point — no `Secret` type in its dependency
//! graph at all.
//!
//! # Prompt-injection hygiene in tool results
//!
//! Tool results go straight into a model's context, and some of the strings in them (item
//! titles, environment names, child-process output) originate outside kagisecure. So results are
//! **plain data**: a JSON object of named fields. Nothing in this file interpolates an untrusted
//! string into a sentence that reads like an instruction, and nothing tells the model what to do
//! based on content it just read. The only prose the model gets from us is in the fixed error
//! messages, which are constants (threat-model T-2).

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ErrorData, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{Peer, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::Deserialize;
use serde_json::json;

use kagisecure_core::proto::{EnvId, ItemId, LeaseId, VaultId};
use kagisecure_ipc::client::{Client, self_info};
use kagisecure_ipc::protocol::{
    AgentFillField, DEFAULT_AGENT_FILL_FIELDS, ErrorCode, FieldRef, MAX_RUN_ARGS,
    MAX_VARIABLES_PER_CALL, OutputMode, RUN_TIMEOUT_DEFAULT_SECONDS, Request, Response,
    VariableRequest, agent_fill_fields_ok, clamp_run_timeout,
};
use kagisecure_ipc::{ClientError, Endpoint};

/// The MCP server.
#[derive(Clone)]
pub struct Kagisecure {
    tool_router: ToolRouter<Self>,
}

impl Default for Kagisecure {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Kagisecure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kagisecure").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// Argument types. These are the JSON schemas in mcp-server.md §2, expressed once.
// ---------------------------------------------------------------------------------------------

/// `list_items` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListItemsArgs {
    /// Restrict to one logical vault, by the id `list_vaults` returned.
    #[serde(default)]
    pub vault_id: Option<String>,
    /// Case-insensitive substring match on title or tag.
    #[serde(default)]
    pub query: Option<String>,
    /// Restrict to one category, e.g. `database` or `api-credential`.
    #[serde(default)]
    pub category: Option<String>,
    /// Maximum number of items to return. 1-200, default 50.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Continuation token from a previous call's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// `list_environments` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListEnvironmentsArgs {
    /// Restrict to one logical vault.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// `describe_item` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DescribeItemArgs {
    /// The item id, from `list_items`.
    pub item_id: String,
}

/// `create_environment` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateEnvironmentArgs {
    /// The logical vault to create it in. Defaults to the user's first vault.
    #[serde(default)]
    pub vault_id: Option<String>,
    /// Display name, e.g. `acme-api / staging`.
    pub name: String,
    /// What this environment is for.
    #[serde(default)]
    pub description: Option<String>,
}

/// One variable in an `add_variables` call. **There is no `value` property.**
#[derive(Debug, Deserialize, JsonSchema)]
pub struct VariableArg {
    /// The variable name, e.g. `STRIPE_SECRET_KEY`.
    pub name: String,
    /// Bind to an existing vault field instead of asking the user for a new value.
    #[serde(default)]
    pub bind_to: Option<BindArg>,
    /// Shown to the user in kagisecure to explain what they should paste.
    #[serde(default)]
    pub hint: Option<String>,
}

/// A field of an item to bind a variable to.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BindArg {
    /// The item id, from `list_items`.
    pub item_id: String,
    /// The field id, from `describe_item`.
    pub field_id: String,
}

/// `add_variables` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddVariablesArgs {
    /// The environment, from `list_environments` or `create_environment`.
    pub environment_id: String,
    /// The variables to declare. At most 50.
    pub variables: Vec<VariableArg>,
}

/// `write_env_file` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteEnvFileArgs {
    /// The environment to write.
    pub environment_id: String,
    /// Absolute path to the project directory. Symlinks are resolved before the user is asked.
    pub directory: String,
    /// File name within that directory. Defaults to `.env`.
    #[serde(default)]
    pub filename: Option<String>,
    /// Write only these variable names. Defaults to all of them.
    #[serde(default)]
    pub variables: Option<Vec<String>>,
    /// Replace a file that is already there. Requires its own approval.
    #[serde(default)]
    pub overwrite: Option<bool>,
    /// Requested lease duration in seconds, 60-86400. The user may shorten it. Default 900.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// `run_with_env` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunWithEnvArgs {
    /// The environment to inject.
    pub environment_id: String,
    /// The executable. **Not** a shell string: `;`, `|` and `$(...)` are ordinary characters.
    pub command: String,
    /// Arguments, passed to the operating system verbatim. At most 64.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Absolute working directory for the child.
    pub cwd: String,
    /// Inject only these variable names. Defaults to all of them.
    #[serde(default)]
    pub variables: Option<Vec<String>>,
    /// Wall-clock limit in seconds, 1-3600. Default 300.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// `scrubbed` (default) returns stdout/stderr with injected values, and their base64, hex and
    /// percent-encoded forms, replaced by `[kagisecure:redacted:NAME]`; `none` returns only the exit
    /// code. Scrubbing is best effort and is NOT a security boundary: a command that reverses,
    /// splits, re-chunks, compresses or otherwise re-encodes a value defeats it. Do not treat
    /// `scrubbed` output as proof a secret did not leave. There is no unmasked option.
    #[serde(default)]
    pub output: Option<String>,
}

/// `revoke_env_file` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RevokeEnvFileArgs {
    /// The lease id returned by `write_env_file`.
    #[serde(default)]
    pub lease_id: Option<String>,
    /// The path of the file to shred.
    #[serde(default)]
    pub path: Option<String>,
}

/// A field `request_fill` may ask for, by name. **There is no way to pass what is typed.**
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FillFieldArg {
    /// The login's username.
    Username,
    /// The login's password.
    Password,
    /// A one-time code from the item's one-time-code field. Only on its own.
    OneTimeCode,
}

impl From<FillFieldArg> for AgentFillField {
    fn from(field: FillFieldArg) -> Self {
        match field {
            FillFieldArg::Username => Self::Username,
            FillFieldArg::Password => Self::Password,
            FillFieldArg::OneTimeCode => Self::OneTimeCode,
        }
    }
}

/// `request_fill` arguments. Unknown properties are refused rather than ignored.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestFillArgs {
    /// The item id, from `list_items`. Titles are not accepted.
    pub item_id: String,
    /// The origin of the page you have open, e.g. `https://example.com`.
    pub origin: String,
    /// Which fields to fill: `username`, `password` or both, or `one_time_code` on its own.
    /// Default `["username", "password"]`.
    #[serde(default)]
    #[schemars(schema_with = "fill_fields_schema")]
    pub fields: Option<Vec<FillFieldArg>>,
}

/// The `fields` schema from mcp-server.md §2.10, which says the combination rule itself rather
/// than leaving it to the error: a login's fields, or a one-time code alone.
fn fill_fields_schema(_: &mut SchemaGenerator) -> Schema {
    // The description comes from the doc comment on `RequestFillArgs::fields`.
    json_schema!({
        "oneOf": [
            {
                "type": "array",
                "items": { "type": "string", "enum": ["username", "password"] },
                "minItems": 1,
                "maxItems": 2,
                "uniqueItems": true
            },
            {
                "type": "array",
                "items": { "type": "string", "const": "one_time_code" },
                "minItems": 1,
                "maxItems": 1
            }
        ],
        "default": ["username", "password"]
    })
}

/// The fields a `request_fill` call asks for, or the `INVALID_ARGUMENT` it is answered with.
///
/// The schema already says this, but a model is not obliged to follow a schema. The rule is the
/// one shared definition, [`agent_fill_fields_ok`], which the process that owns the vault applies
/// too once it serves the request: the sidecar is a convenience, not a boundary.
fn fill_fields(
    requested: Option<Vec<FillFieldArg>>,
) -> Result<Vec<AgentFillField>, CallToolResult> {
    let fields: Vec<AgentFillField> = requested.map_or_else(
        || DEFAULT_AGENT_FILL_FIELDS.to_vec(),
        |fields| fields.into_iter().map(AgentFillField::from).collect(),
    );
    if agent_fill_fields_ok(&fields) {
        Ok(fields)
    } else {
        Err(err(
            ErrorCode::InvalidArgument,
            "fields must name at least one field, none twice: username, password or both, or \
             one_time_code on its own. A one-time code is never combined with a password. \
             Nothing was asked. Fix the argument and retry.",
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// The tools.
// ---------------------------------------------------------------------------------------------

#[tool_router(router = tool_router)]
impl Kagisecure {
    /// A server with the ten tools registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "list_vaults",
        description = "List the kagisecure vaults the user has made visible to agents. Returns \
                       names and counts only. Never returns a secret value."
    )]
    async fn list_vaults(&self, peer: Peer<RoleServer>) -> Result<CallToolResult, ErrorData> {
        match ask(&peer, Request::ListVaults).await {
            Ok(Response::Vaults { vaults }) => Ok(ok(json!({ "vaults": vaults }))),
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "list_items",
        description = "List item titles, categories and tags in the user's vaults. Returns field \
                       labels, not field values. Never returns a secret value."
    )]
    async fn list_items(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<ListItemsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let vault_id = match parse_opt::<VaultId>(args.vault_id.as_deref(), "vault_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let limit = args.limit.unwrap_or(50).clamp(1, 200) as usize;
        let request = Request::ListItems {
            vault_id,
            query: args.query,
            category: args.category,
            limit,
            cursor: args.cursor,
        };
        match ask(&peer, request).await {
            Ok(Response::Items { items, next_cursor }) => {
                Ok(ok(json!({ "items": items, "next_cursor": next_cursor })))
            }
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "list_environments",
        description = "List the environments the user has made visible to agents, with the NAMES \
                       of the variables in each. There is no tool that returns their values."
    )]
    async fn list_environments(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<ListEnvironmentsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let vault_id = match parse_opt::<VaultId>(args.vault_id.as_deref(), "vault_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        match ask(&peer, Request::ListEnvironments { vault_id }).await {
            Ok(Response::Environments { environments }) => {
                Ok(ok(json!({ "environments": environments })))
            }
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "describe_item",
        description = "Describe an item's structure: field labels, kinds, and whether each holds \
                       a value. Values are withheld for concealed and non-concealed fields \
                       alike; there is no argument that changes that."
    )]
    async fn describe_item(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<DescribeItemArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let item_id = match parse_req::<ItemId>(&args.item_id, "item_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        match ask(&peer, Request::DescribeItem { item_id }).await {
            Ok(Response::Item { item }) => Ok(ok(serde_json::to_value(*item).unwrap_or_default())),
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "create_environment",
        description = "Create an empty environment. The user approves this in kagisecure because \
                       it changes their vault. The environment starts with no variables, and \
                       this tool never returns a secret value."
    )]
    async fn create_environment(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<CreateEnvironmentArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let vault_id = match parse_opt::<VaultId>(args.vault_id.as_deref(), "vault_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let request = Request::CreateEnvironment {
            vault_id,
            name: args.name,
            description: args.description,
        };
        match ask(&peer, request).await {
            Ok(Response::Environment { environment }) => {
                Ok(ok(serde_json::to_value(*environment).unwrap_or_default()))
            }
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "add_variables",
        description = "Declare variables in an environment by NAME, optionally bound to an \
                       existing vault field. This tool cannot accept a value: its schema has no \
                       such property. A variable with no binding becomes a pending entry that \
                       the user fills in inside kagisecure."
    )]
    async fn add_variables(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<AddVariablesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let environment_id = match parse_req::<EnvId>(&args.environment_id, "environment_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        if args.variables.len() > MAX_VARIABLES_PER_CALL {
            return Ok(err(
                ErrorCode::InvalidArgument,
                "At most 50 variables per call. Split the request.",
            ));
        }
        let mut variables = Vec::with_capacity(args.variables.len());
        for v in args.variables {
            let bind_to = match v.bind_to {
                None => None,
                Some(b) => {
                    let item_id = match parse_req::<ItemId>(&b.item_id, "bind_to.item_id") {
                        Ok(v) => v,
                        Err(e) => return Ok(e),
                    };
                    let field_id = match parse_req::<kagisecure_core::proto::FieldId>(
                        &b.field_id,
                        "bind_to.field_id",
                    ) {
                        Ok(v) => v,
                        Err(e) => return Ok(e),
                    };
                    Some(FieldRef { item_id, field_id })
                }
            };
            variables.push(VariableRequest {
                name: v.name,
                bind_to,
                hint: v.hint,
            });
        }

        let request = Request::AddVariables {
            environment_id,
            variables,
        };
        match ask(&peer, request).await {
            Ok(Response::AddedVariables {
                environment_id,
                bound,
                pending,
                deep_link,
                status,
            }) => Ok(ok(json!({
                "environment_id": environment_id,
                "bound": bound,
                "pending": pending,
                "deep_link": deep_link,
                "status": status,
            }))),
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "write_env_file",
        description = "Write a .env file containing an environment's variables into a directory. \
                       The user approves it in kagisecure, and kagisecure writes the bytes: the \
                       values are not returned to you. You get the path, the variable names, and \
                       a lease id to revoke with."
    )]
    async fn write_env_file(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<WriteEnvFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let environment_id = match parse_req::<EnvId>(&args.environment_id, "environment_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let request = Request::WriteEnvFile {
            environment_id,
            directory: args.directory,
            filename: args.filename.unwrap_or_else(|| ".env".to_owned()),
            variables: args.variables,
            overwrite: args.overwrite.unwrap_or(false),
            ttl_seconds: args.ttl_seconds.unwrap_or(900).clamp(60, 86_400),
        };
        match ask(&peer, request).await {
            Ok(Response::WroteEnvFile {
                path,
                variables_written,
                bytes,
                lease_id,
                expires_at,
                gitignored,
            }) => Ok(ok(json!({
                "path": path,
                "variables_written": variables_written,
                "bytes": bytes,
                "lease_id": lease_id,
                "expires_at": expires_at,
                "gitignored": gitignored,
            }))),
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "run_with_env",
        description = "Run a command with an environment's variables in its process environment. \
                       kagisecure spawns the child itself, with no shell. Output comes back with \
                       injected values replaced by [kagisecure:redacted:NAME]; that masking is \
                       best effort and is not a security boundary — a command that re-encodes or \
                       splits a value defeats it. There is no unmasked option."
    )]
    async fn run_with_env(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<RunWithEnvArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let environment_id = match parse_req::<EnvId>(&args.environment_id, "environment_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let cmd_args = args.args.unwrap_or_default();
        if cmd_args.len() > MAX_RUN_ARGS {
            return Ok(err(
                ErrorCode::InvalidArgument,
                "At most 64 arguments. Simplify the command.",
            ));
        }
        let output = match args.output.as_deref() {
            None | Some("scrubbed") => OutputMode::Scrubbed,
            Some("none") => OutputMode::None,
            Some(_) => {
                return Ok(err(
                    ErrorCode::InvalidArgument,
                    "output must be \"scrubbed\" or \"none\". There is no unmasked mode.",
                ));
            }
        };
        let request = Request::RunWithEnv {
            environment_id,
            command: args.command,
            args: cmd_args,
            cwd: args.cwd,
            variables: args.variables,
            // The agent clamps this too — it cannot rely on a sidecar a hostile caller would
            // simply not run — so the two share one definition of the range.
            timeout_seconds: clamp_run_timeout(
                args.timeout_seconds.unwrap_or(RUN_TIMEOUT_DEFAULT_SECONDS),
            ),
            output,
        };
        match ask(&peer, request).await {
            Ok(Response::Ran {
                exit_code,
                stdout,
                stderr,
                truncated,
                scrubbed,
                lease_id,
                expires_at,
            }) => {
                let mut body = json!({
                    "exit_code": exit_code,
                    "lease_id": lease_id,
                    "expires_at": expires_at,
                });
                if let (Some(out), Some(errs)) = (stdout, stderr) {
                    body["stdout"] = json!(out);
                    body["stderr"] = json!(errs);
                    body["truncated"] = json!(truncated);
                    body["scrubbed"] = json!(scrubbed);
                }
                Ok(ok(body))
            }
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "revoke_env_file",
        description = "Delete a .env file kagisecure wrote and kill its lease. No approval is \
                       needed: giving access back is always allowed. Call this when you are done \
                       with the credentials."
    )]
    async fn revoke_env_file(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<RevokeEnvFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if args.lease_id.is_none() && args.path.is_none() {
            return Ok(err(
                ErrorCode::InvalidArgument,
                "Pass lease_id, path, or both.",
            ));
        }
        let lease_id = match parse_opt::<LeaseId>(args.lease_id.as_deref(), "lease_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        match ask(
            &peer,
            Request::RevokeEnvFile {
                lease_id,
                path: args.path,
            },
        )
        .await
        {
            Ok(Response::Revoked { shredded }) => Ok(ok(json!({ "shredded": shredded }))),
            other => Ok(unexpected(other)),
        }
    }

    #[tool(
        name = "request_fill",
        description = "Ask the user to let kagisecure fill a saved login into the browser tab \
                       they are looking at. The user approves in the kagisecure app with a \
                       biometric. Returns only which fields were filled: this tool never returns \
                       a secret value. Works only in a browser with the kagisecure extension, in \
                       the tab in front, when that tab's origin is exactly `origin` and is a \
                       website saved on the item. On a sign-in that asks for the username \
                       first, one approval covers both pages: the username is filled now and \
                       `fields_pending` lists the password — press the page's own Next button, \
                       then call again for [\"password\"] within 60 seconds, and no second \
                       approval is asked. Ask for `one_time_code` in a call of its own: it is \
                       approved on its own every time and filled only into a page with a code \
                       field, never copied to the clipboard. Be aware: kagisecure never gives you a value, but it types the value into \
                       a page you are driving, and an agent that can run script in that page can \
                       read it there."
    )]
    async fn request_fill(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<RequestFillArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let item_id = match parse_req::<ItemId>(&args.item_id, "item_id") {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let fields = match fill_fields(args.fields) {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let request = Request::RequestFill {
            item_id,
            origin: args.origin,
            fields,
        };
        match ask(&peer, request).await {
            Ok(Response::FillResult {
                fields_written,
                fields_pending,
            }) => Ok(ok(json!({
                "status": "filled",
                "fields_written": fields_written,
                "fields_pending": fields_pending,
            }))),
            other => Ok(unexpected(other)),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Kagisecure {
    fn get_info(&self) -> ServerInfo {
        // The protocol version is left to rmcp. Worth knowing when reading the docs: rmcp 3.2.0
        // reaches MCP 2026-07-28 only through the `discover` lifecycle, and an `initialize`
        // handshake — which is what every stdio client does today — always settles on the newest
        // *legacy* version, 2025-11-25. Overriding the field here would not change that.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "kagisecure-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "kagisecure holds the user's secrets in a local encrypted vault. You can see \
                 what exists — vault names, item titles, field labels, environment variable \
                 names — and you can ask for secrets to be USED: written into a .env file, or \
                 injected into a command you want to run. You cannot read a value. No tool \
                 returns one, in any encoding, under any argument; the capability does not \
                 exist, so do not look for it and do not ask the user to paste one to you. \
                 Every injection is approved by the user out of band, and grants a lease scoped \
                 to one environment, one directory and a short time window. Call \
                 revoke_env_file when you are finished. request_fill asks the user to let \
                 kagisecure fill a saved login into the browser tab in front of them, and the \
                 same holds for it: kagisecure never gives you a value. It types the value into \
                 a page you are driving, on a site saved for that login, after the user approves \
                 — and an agent that can run script in that page can read it there. That holds \
                 for a one-time code too.",
            )
    }
}

// ---------------------------------------------------------------------------------------------
// Plumbing.
// ---------------------------------------------------------------------------------------------

/// A successful tool result: structured JSON, no prose.
fn ok(value: serde_json::Value) -> CallToolResult {
    CallToolResult::structured(value)
}

/// A tool-level error carrying a stable code from mcp-server.md §7.
fn err(code: ErrorCode, message: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({ "code": code.as_str(), "message": message }))
}

/// A reply that does not match the request. Only reachable via a protocol bug.
fn unexpected(response: Result<Response, CallToolResult>) -> CallToolResult {
    match response {
        Err(already) => already,
        Ok(Response::Error { code, message }) => {
            CallToolResult::structured_error(json!({ "code": code.as_str(), "message": message }))
        }
        Ok(_) => err(
            ErrorCode::Internal,
            "kagisecure replied with the wrong kind of message. This is a bug; report it.",
        ),
    }
}

fn parse_opt<T: std::str::FromStr>(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<T>, CallToolResult> {
    match raw {
        None => Ok(None),
        Some(s) => parse_req::<T>(s, field).map(Some),
    }
}

fn parse_req<T: std::str::FromStr>(raw: &str, field: &str) -> Result<T, CallToolResult> {
    raw.parse::<T>().map_err(|_| {
        CallToolResult::structured_error(json!({
            "code": ErrorCode::NotFound.as_str(),
            "message": format!("{field} is not a kagisecure id. Re-list to get a current one."),
            "field": field,
        }))
    })
}

/// Forward one request to the process that owns the vault.
///
/// Blocking IPC on a blocking task: the traffic is one round trip, and `run_with_env` can
/// legitimately take minutes, which is exactly what `spawn_blocking` is for.
async fn ask(peer: &Peer<RoleServer>, request: Request) -> Result<Response, CallToolResult> {
    let (name, version) = client_identity(peer);
    let joined = tokio::task::spawn_blocking(move || {
        let endpoint = Endpoint::discover().map_err(ClientError::from)?;
        let mut client = Client::connect(&endpoint, self_info(name, version))?;
        client.call(&request)
    })
    .await;

    match joined {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => Err(err(e.code(), &connect_message(&e))),
        Err(_) => Err(err(
            ErrorCode::Internal,
            "The kagisecure sidecar failed internally. Report it.",
        )),
    }
}

/// The fixed message for each transport failure. Written for the model: it says what to do next,
/// and it never contains anything the model or a tool result supplied.
fn connect_message(error: &ClientError) -> String {
    match error.code() {
        ErrorCode::AppNotRunning => "kagisecure is not running. Tell the user to start it \
                                     (`kagisecure daemon`, or open the kagisecure app). Do not \
                                     retry in a loop."
            .to_owned(),
        _ => "kagisecure could not be reached. Report it.".to_owned(),
    }
}

/// What the MCP client called itself. Self-reported, and passed on as such.
fn client_identity(peer: &Peer<RoleServer>) -> (String, String) {
    peer.peer_info().map_or_else(
        || ("unknown-mcp-client".to_owned(), "unknown".to_owned()),
        |info| {
            (
                info.client_info.name.clone(),
                info.client_info.version.clone(),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_tool_is_registered_and_nothing_else_is() {
        let router = Kagisecure::tool_router();
        let mut names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "add_variables",
                "create_environment",
                "describe_item",
                "list_environments",
                "list_items",
                "list_vaults",
                "request_fill",
                "revoke_env_file",
                "run_with_env",
                "write_env_file",
            ]
        );
    }

    #[test]
    fn request_fill_schema_has_no_place_for_a_value() {
        // Three arguments, all of them names: which item, which origin the agent claims, which
        // fields. Nothing the model could put a value in, and nothing it could ask for one with.
        let router = Kagisecure::tool_router();
        let tool = router
            .list_all()
            .into_iter()
            .find(|t| t.name == "request_fill")
            .expect("registered above");
        let schema = serde_json::to_value(&tool.input_schema).unwrap();
        let mut properties = Vec::new();
        collect_property_names(&schema, &mut properties);
        properties.sort();
        assert_eq!(properties, ["fields", "item_id", "origin"], "{schema}");
        assert_eq!(schema["additionalProperties"], false, "{schema}");
        let rendered = serde_json::to_string(&schema).unwrap();
        assert!(!rendered.contains("\"value\""), "{rendered}");

        // The combination rule is in the schema itself, not only in the error.
        let branches = schema["properties"]["fields"]["oneOf"]
            .as_array()
            .expect("fields is a oneOf");
        assert_eq!(branches.len(), 2, "{schema}");
        assert_eq!(branches[1]["items"]["const"], "one_time_code");
        assert_eq!(branches[1]["maxItems"], 1);

        // And the reply it maps onto names fields, never what went into them.
        let reply = serde_json::to_value(Response::FillResult {
            fields_written: vec![AgentFillField::Username, AgentFillField::Password],
            fields_pending: vec![],
        })
        .unwrap();
        let mut keys: Vec<&String> = reply.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["fields_pending", "fields_written", "reply"]);
    }

    #[test]
    fn a_field_combination_the_schema_forbids_is_invalid_argument() {
        use FillFieldArg::{OneTimeCode, Password, Username};
        for refused in [
            vec![],
            vec![OneTimeCode, Password],
            vec![Username, Password, OneTimeCode],
            vec![Password, Password],
        ] {
            let result = fill_fields(Some(refused.clone())).expect_err("refused");
            assert_eq!(result.is_error, Some(true));
            let body = result.structured_content.expect("structured");
            assert_eq!(body["code"], "INVALID_ARGUMENT", "{refused:?}");
        }
        assert_eq!(
            fill_fields(None).expect("the default is accepted"),
            DEFAULT_AGENT_FILL_FIELDS
        );
        assert_eq!(
            fill_fields(Some(vec![OneTimeCode])).expect("a code alone is accepted"),
            [AgentFillField::OneTimeCode]
        );
    }

    #[test]
    fn request_fill_arguments_refuse_an_unknown_property() {
        let parsed = serde_json::from_value::<RequestFillArgs>(json!({
            "item_id": "x",
            "origin": "https://example.com",
            "value": "anything",
        }));
        assert!(
            parsed.is_err(),
            "a value property must be refused, not ignored"
        );
        let parsed = serde_json::from_value::<RequestFillArgs>(json!({
            "item_id": "x",
            "origin": "https://example.com",
            "fields": ["one_time_code"],
        }))
        .expect("the documented shape parses");
        assert!(matches!(
            parsed.fields.as_deref(),
            Some([FillFieldArg::OneTimeCode])
        ));
    }

    #[test]
    fn no_tool_schema_offers_a_way_to_ask_for_a_value() {
        // Argument names, not prose: a description may legitimately say "there is no unmasked
        // option", but no *property* may exist that would widen a tool into returning one.
        let router = Kagisecure::tool_router();
        for tool in router.list_all() {
            let schema = serde_json::to_value(&tool.input_schema).unwrap();
            let name = tool.name.to_string();
            let mut properties: Vec<String> = Vec::new();
            collect_property_names(&schema, &mut properties);
            for property in &properties {
                for forbidden in [
                    "value",
                    "secret",
                    "reveal",
                    "plaintext",
                    "unmask",
                    "no_masking",
                    "password",
                ] {
                    assert!(
                        !property.to_lowercase().contains(forbidden),
                        "{name} has an argument {property:?}, which contains {forbidden:?}"
                    );
                }
            }
        }
    }

    /// Every `properties` key anywhere in a JSON Schema, including nested objects.
    fn collect_property_names(schema: &serde_json::Value, out: &mut Vec<String>) {
        match schema {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if key == "properties"
                        && let Some(props) = value.as_object()
                    {
                        out.extend(props.keys().cloned());
                    }
                    collect_property_names(value, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_property_names(item, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn add_variables_has_no_value_property() {
        let router = Kagisecure::tool_router();
        let tool = router
            .list_all()
            .into_iter()
            .find(|t| t.name == "add_variables")
            .expect("registered above");
        let schema = serde_json::to_value(&tool.input_schema).unwrap();
        let rendered = serde_json::to_string(&schema).unwrap();
        // The schema names `name`, `bind_to` and `hint`, and has no place to put a value.
        assert!(rendered.contains("bind_to"));
        assert!(rendered.contains("hint"));
        assert!(
            !rendered.contains("\"value\""),
            "add_variables gained a value property: {rendered}"
        );
    }

    #[test]
    fn run_with_env_offers_only_the_two_documented_output_modes() {
        let router = Kagisecure::tool_router();
        let tool = router
            .list_all()
            .into_iter()
            .find(|t| t.name == "run_with_env")
            .expect("registered above");
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(description.contains("no unmasked option"));
    }

    #[test]
    fn the_instructions_tell_the_model_not_to_look_for_a_reveal_tool() {
        let info = Kagisecure::new().get_info();
        let instructions = info.instructions.unwrap_or_default();
        assert!(instructions.contains("cannot read a value"));
        assert!(instructions.contains("revoke_env_file"));
    }

    #[test]
    fn the_instructions_say_what_an_agent_fill_does_and_does_not_protect() {
        // ADR-0036 §8.2: the true sentence for request_fill, said where the model reads it.
        let info = Kagisecure::new().get_info();
        let instructions = info.instructions.unwrap_or_default();
        assert!(instructions.contains("request_fill"), "{instructions}");
        assert!(
            instructions.contains("kagisecure never gives you a value"),
            "{instructions}"
        );
        assert!(
            instructions.contains("an agent that can run script in that page can read it there"),
            "{instructions}"
        );

        let router = Kagisecure::tool_router();
        let tool = router
            .list_all()
            .into_iter()
            .find(|t| t.name == "request_fill")
            .expect("registered");
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("can run script in that page can read it there"),
            "{description}"
        );
    }

    #[test]
    fn the_request_fill_description_says_how_page_two_and_codes_are_served() {
        // ADR-0036 Phase 3 is served, so the description says how to use it — and what it will
        // not do: no second approval is skipped for a code, and no clipboard.
        let router = Kagisecure::tool_router();
        let tool = router
            .list_all()
            .into_iter()
            .find(|t| t.name == "request_fill")
            .expect("registered");
        let description = tool.description.as_deref().unwrap_or_default();
        for phrase in [
            "fields_pending",
            "call again for [\"password\"] within 60 seconds",
            "no second approval is asked",
            "approved on its own every time",
            "never copied to the clipboard",
        ] {
            assert!(description.contains(phrase), "{phrase}: {description}");
        }
    }

    /// ADR-0042 §5: no MCP tool creates, widens, extends, re-enables or proposes a standing grant
    /// or a job, or arms the machine vault. The tool list is fixed above; this says why it must
    /// stay free of them, in words a new tool's name would trip.
    #[test]
    fn no_tool_reaches_grants_jobs_or_arming() {
        for tool in Kagisecure::tool_router().list_all() {
            let name = tool.name.to_lowercase();
            for word in ["grant", "job", "arm", "unattended", "schedule"] {
                assert!(!name.contains(word), "{name} names {word}");
            }
        }
    }

    #[test]
    fn an_agent_error_code_reaches_the_model_verbatim() {
        // The codes in mcp-server.md §7 are the agent's, passed through as they arrive: the
        // sidecar has no table of its own that a new code (here `AUDIT_UNAVAILABLE`) could be
        // missing from.
        for code in [
            ErrorCode::AuditUnavailable,
            ErrorCode::VaultBusy,
            ErrorCode::VaultConflict,
            ErrorCode::FillUnavailable,
            ErrorCode::NothingToFill,
            ErrorCode::NoMatchingTab,
            ErrorCode::RateLimited,
            ErrorCode::NotGranted,
            ErrorCode::UnattendedPaused,
        ] {
            let result = unexpected(Ok(Response::error(code, "fixed text")));
            assert_eq!(result.is_error, Some(true));
            let body = result.structured_content.expect("structured");
            assert_eq!(body["code"], code.as_str());
            assert_eq!(body["message"], "fixed text");
        }
    }

    #[test]
    fn run_with_env_timeouts_use_the_shared_range() {
        assert_eq!(clamp_run_timeout(0), 1);
        assert_eq!(clamp_run_timeout(u64::MAX), 3600);
        assert_eq!(clamp_run_timeout(RUN_TIMEOUT_DEFAULT_SECONDS), 300);
    }

    #[test]
    fn a_malformed_id_is_a_tool_error_not_a_protocol_error() {
        let result = parse_req::<EnvId>("not-a-uuid", "environment_id").unwrap_err();
        assert_eq!(result.is_error, Some(true));
        let body = serde_json::to_string(&result.structured_content).unwrap();
        assert!(body.contains("NOT_FOUND"));
        assert!(body.contains("environment_id"));
    }

    #[test]
    fn every_tool_description_says_what_it_will_not_do() {
        // The invariant has to reach the model somewhere it will actually read, which is the
        // tool description, not a document. Each one either states it or points at the tool
        // that does the injecting without returning values.
        let router = Kagisecure::tool_router();
        for tool in router.list_all() {
            let text = tool
                .description
                .as_deref()
                .unwrap_or_default()
                .to_lowercase();
            let name = tool.name.to_string();
            let mentions = text.contains("never returns a secret value")
                || text.contains("not returned to you")
                || text.contains("values are withheld")
                || text.contains("cannot accept a value")
                || text.contains("no tool that returns their values")
                || text.contains("no unmasked option")
                || text.contains("giving access back is always allowed");
            assert!(mentions, "{name} does not say what it will not do: {text}");
        }
    }
}

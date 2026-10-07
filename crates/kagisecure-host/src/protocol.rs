//! The host socket's one exchange: a request line, a response line, both JSON.
//!
//! There is one request — run a grant's command — and no message that approves, creates or
//! widens anything (ADR-0043 §2: the host has no approval path). A response never carries a value:
//! the command's output is masked against the values it was given before it is sent.

use serde::{Deserialize, Serialize};

/// The most bytes a request line may have.
pub const MAX_REQUEST: usize = 64 * 1024;

/// The most bytes of each output stream returned to the caller.
pub const MAX_OUTPUT: usize = 1024 * 1024;

/// Run the command a grant names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The grant's name.
    pub grant: String,
    /// The whole argument vector, the executable first.
    pub argv: Vec<String>,
    /// The working directory.
    pub cwd: String,
}

/// What happened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Response {
    /// The command ran.
    Ran {
        /// Its exit code; `None` if a signal or the deadline ended it.
        exit_code: Option<i32>,
        /// Whether the deadline ended it.
        timed_out: bool,
        /// Standard output, masked, lossily UTF-8.
        stdout: String,
        /// Standard error, masked, lossily UTF-8.
        stderr: String,
    },
    /// Nothing was released.
    Refused {
        /// A code from the audit vocabulary: `NO_SUCH_GRANT`, `SUSPENDED`, `PIN_CHANGED`, ...
        reason: String,
        /// For the person reading it.
        message: String,
    },
}

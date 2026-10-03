//! Command implementations.

use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::Tx;
use kagisecure_core::{Error, Vault};

pub mod audit;
pub mod daemon;
pub mod env;
pub mod generate;
pub mod import;
pub mod item;
pub mod mcp;
pub mod recover;
pub mod run;
pub mod shared;
pub mod vault;

/// A minimal CLI-authored audit draft: actor `"cli"`, the given tool name, outcome `Allowed`, and
/// every other field left at its default. Callers fill in whichever of `item_id`,
/// `environment_id`, `vault_id`, `variables` or `target_path` the action touched.
#[must_use]
pub fn cli_draft(tool: &str) -> AuditDraft {
    AuditDraft {
        actor: "cli".to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        ..AuditDraft::default()
    }
}

/// A transaction failure specific to the audit-first gate `env write` and `run` run before they
/// release anything (design doc "transactions-and-audit", part B, step 9).
///
/// Both commands append and commit an `Allowed` audit entry *before* the `.env` file is written or
/// the child is spawned — meaning "authorized and durably recorded" — and only then act, with the
/// vault's lock already released. Whatever [`kagisecure_core::Vault::transact`] returned for that
/// gate — [`Error::VaultBusy`] after the usual wait, [`Error::VaultDiverged`],
/// [`Error::VaultReplaced`], or a plain save failure — means the same thing here: permission could
/// not be made durable, so nothing may be released. That is a different, and more specific,
/// failure than the same errors from an ordinary mutating transaction (`item add`, `env create`,
/// …), which still map to [`crate::cli::EXIT_VAULT_BUSY`] / [`crate::cli::EXIT_VAULT_CHANGED`] —
/// so this wraps the error in its own type rather than letting `main::exit_code_for`'s usual
/// `Core` match catch it, and carries the source error through for the printed message.
#[derive(Debug)]
pub struct AuditUnavailable(pub Error);

impl std::fmt::Display for AuditUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not durably record permission before acting: {}",
            self.0
        )
    }
}

impl std::error::Error for AuditUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Whether `e`, returned from the audit-first gate's own transaction (`env write`'s or `run`'s
/// step 1), means permission could not be made durable — as opposed to the request never
/// resolving to something to authorize in the first place.
///
/// The gate's closure only ever raises reference-resolution errors — [`Error::ItemNotFound`],
/// [`Error::AmbiguousItem`], [`Error::FieldNotFound`], [`Error::EnvNotFound`],
/// [`Error::AmbiguousEnv`], [`Error::VarNotFound`], [`Error::VarNotPopulated`],
/// [`Error::InvalidVarName`] — and reaches them
/// *before* ever calling [`kagisecure_core::vault::Tx::append_audit`], so none of them describe a
/// commit that was attempted and failed; [`Vault::transact`] itself never produces any of them.
/// Everything else it can return — [`Error::VaultBusy`], [`Error::VaultDiverged`],
/// [`Error::VaultReplaced`], [`Error::LockUnsupported`], [`Error::LockLost`],
/// [`Error::VaultNotFound`], [`Error::VaultTooLarge`], [`Error::NestedTransaction`], or a save's
/// own I/O, RNG or decode failure — means the closure either ran and appended the entry or never
/// got the chance to for a reason that has nothing to do with what it was asked to authorize, and
/// either way the durable commit is what failed.
///
/// Only the second kind maps to [`crate::cli::EXIT_AUDIT_UNAVAILABLE`]; the first keeps its
/// ordinary exit code ([`Error::ItemNotFound`] and friends all map to
/// [`crate::cli::EXIT_NOT_FOUND`]) so a caller can still tell "that item does not exist" apart from
/// "permission could not be recorded".
#[must_use]
pub fn is_audit_gate_failure(e: &Error) -> bool {
    !matches!(
        e,
        Error::ItemNotFound(_)
            | Error::AmbiguousItem(_)
            | Error::FieldNotFound { .. }
            | Error::EnvNotFound(_)
            | Error::AmbiguousEnv(_)
            | Error::VarNotFound(..)
            | Error::VarNotPopulated(_)
            | Error::InvalidVarName(_)
    )
}

/// The `detail` of a best-effort `Failed` follow-up entry after an audited-first action's *act*
/// step fails or ends abnormally: a short machine-readable code plus the sequence number of the
/// `Allowed` entry it follows, e.g. `"WRITE_FAILED (entry 12)"` — see design doc
/// "transactions-and-audit" part B.
#[must_use]
pub fn failure_detail(code: &str, allowed_seq: u64) -> String {
    format!("{code} (entry {allowed_seq})")
}

/// How long a best-effort audit save waits for the vault's lock before giving up and warning
/// instead of blocking the value or the action it must never gate ([`record_audit_best_effort`]).
///
/// Deliberately much shorter than [`lock_wait_total`], and not retried: [`transact_patiently`]'s
/// long, retried wait exists because giving up on a real write silently drops a mutation the user
/// asked for. A best-effort audit save is the opposite case — `item show --reveal`'s value is
/// already on the terminal, `env write`'s `.env` file already exists or does not, `run`'s child
/// already ran or did not — so waiting is pure latency for a warning the user is free to see
/// instead of a delay, and there is nothing gained by trying twice.
///
/// Overridable by `KAGISECURE_TEST_BEST_EFFORT_AUDIT_TIMEOUT_MS`; see [`debug_only_override`].
fn best_effort_audit_timeout() -> Duration {
    debug_only_override("KAGISECURE_TEST_BEST_EFFORT_AUDIT_TIMEOUT_MS")
        .unwrap_or(Duration::from_millis(500))
}

/// Queue an audit draft and flush it now, with a short, non-retrying timeout, warning on stderr —
/// but never failing the caller — if it could not be saved.
///
/// For every caller of this function the audited action has already happened: a value is already
/// on the terminal or the clipboard (`item show --reveal`, `kagisecure totp`), or an audited-first
/// action's *act* step (the `.env` write, the child process) has already failed or ended abnormally
/// once its own `Allowed` entry was made durable. Losing the follow-up entry must never turn any of
/// that into a reported failure, and must never make the terminal wait long for a warning it is
/// free to skip (design doc "transactions-and-audit" part B, user decision 1: "own reveals ...
/// AUDIT them, best-effort, NEVER blocking").
pub fn record_audit_best_effort(vault: &mut Vault, draft: AuditDraft) {
    vault.queue_audit(draft);
    let previous = vault.lock_timeout();
    vault.set_lock_timeout(best_effort_audit_timeout());
    let result = vault.flush_audit();
    vault.set_lock_timeout(previous);
    if let Err(e) = result {
        eprintln!("kagisecure: warning: could not record this in the audit log: {e}");
    }
}

/// The message printed to stderr once a write has waited [`lock_wait_quiet`] for another
/// kagisecure process's lock.
const WAITING_MESSAGE: &str = "kagisecure: waiting for another kagisecure process…";

/// Read `var` as a millisecond [`Duration`], but only in a debug build — the same discipline
/// `commands::daemon::check_auto_approve` uses for `--auto-approve`: a cross-process test needs
/// waits measured in milliseconds rather than seconds, and a release build must not let an
/// environment variable decide how patient it is.
fn debug_only_override(var: &str) -> Option<Duration> {
    if cfg!(debug_assertions)
        && let Ok(ms) = std::env::var(var)
        && let Ok(ms) = ms.parse::<u64>()
    {
        return Some(Duration::from_millis(ms));
    }
    None
}

/// How long `kagisecure` waits for another kagisecure process's lock before giving up with
/// [`crate::cli::EXIT_VAULT_BUSY`] — longer than the core default of five seconds, because a
/// person at a terminal is more patient than a request an agent is waiting on.
///
/// Overridable by `KAGISECURE_TEST_LOCK_TIMEOUT_MS`; see [`debug_only_override`].
fn lock_wait_total() -> Duration {
    debug_only_override("KAGISECURE_TEST_LOCK_TIMEOUT_MS").unwrap_or(Duration::from_secs(30))
}

/// How long the wait stays quiet before the CLI says why nothing has happened yet
/// ([`WAITING_MESSAGE`]).
///
/// Overridable by `KAGISECURE_TEST_LOCK_QUIET_MS`; see [`debug_only_override`]. Needed alongside
/// [`lock_wait_total`]'s own override rather than relying on `total.min(1s)` the way a real 30s
/// wait does: a test's `total` is itself milliseconds, so without a matching override for this the
/// two would always be equal and the retry — the thing a "waits then exits busy" test exists to
/// see happen — would never fire.
fn lock_wait_quiet() -> Duration {
    debug_only_override("KAGISECURE_TEST_LOCK_QUIET_MS").unwrap_or(Duration::from_secs(1))
}

/// Run `f` as one [`Vault::transact`], waiting up to [`lock_wait_total`] for the lock, and telling
/// the user why nothing has happened yet once the wait stops being instant.
///
/// `f` runs at most once: [`Vault::transact`] only calls its closure once the lock is held, and
/// that happens on at most one of the (up to two) attempts this makes — a short first attempt so
/// an uncontended lock never prints anything, then, only if that timed out, one more covering the
/// rest of the budget. `f` is `FnMut` rather than `FnOnce` only so it can be *handed to*
/// `Vault::transact` twice, never because it is meant to run twice. A caller whose closure needs
/// to consume something it cannot clone (an `ImportPlan`, a `Prepared*Slot`) keeps it in a
/// `&mut Option<_>` outside and `.take()`s it inside — `Option::take` is safe to call more than
/// once (it is a no-op past the first), so this stays sound even though "at most once" is a
/// contract `Vault::transact` enforces, not something the type system checks here.
///
/// # Errors
///
/// Whatever `f` returns, or [`Error::VaultBusy`] if the lock is still held after the full budget
/// — reported as having waited that full budget, even though it was split across two attempts.
pub fn transact_patiently<T>(
    vault: &mut Vault,
    mut f: impl FnMut(&mut Tx<'_>) -> kagisecure_core::Result<T>,
) -> kagisecure_core::Result<T> {
    let total = lock_wait_total();
    let quiet = total.min(lock_wait_quiet());

    vault.set_lock_timeout(quiet);
    match vault.transact(|tx| f(tx)) {
        Err(Error::VaultBusy { path, .. }) if quiet < total => {
            eprintln!("{WAITING_MESSAGE}");
            vault.set_lock_timeout(total - quiet);
            match vault.transact(|tx| f(tx)) {
                Err(Error::VaultBusy { .. }) => Err(Error::VaultBusy {
                    path,
                    waited: total,
                }),
                other => other,
            }
        }
        other => other,
    }
}

/// Fail with [`kagisecure_core::Error::VaultNotFound`] before prompting for a password.
///
/// Asking for the master password and only then reporting that there is no vault to open is
/// needlessly rude, and it makes the exit code less useful.
///
/// # Errors
///
/// If no file exists at `path`.
pub fn ensure_exists(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(kagisecure_core::Error::VaultNotFound(path.to_path_buf()).into())
    }
}

/// Format Unix seconds as `YYYY-MM-DD` (UTC), without pulling in a date library.
#[must_use]
pub fn ymd(unix: u64) -> String {
    // Howard Hinnant's civil-from-days, in u64 terms. Good from 1970 to well past any plausible
    // timestamp in a vault.
    let days = (unix / 86_400) as i64;
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
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::ymd;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(1_757_376_000), "2025-09-09");
        assert_eq!(ymd(951_782_400), "2000-02-29");
    }
}

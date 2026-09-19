//! Command implementations.

pub mod audit;
pub mod daemon;
pub mod env;
pub mod generate;
pub mod import;
pub mod item;
pub mod mcp;
pub mod recover;
pub mod run;
pub mod vault;

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

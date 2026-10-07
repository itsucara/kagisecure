//! Looking an account up by name in `/etc/passwd`, for a grant's `run_as`.
//!
//! Read directly rather than through `getpwnam(3)`, which needs `unsafe` and NSS: a host's job
//! account is a local account, and a name that is only in a directory service is refused.

use std::path::{Path, PathBuf};

use kagisecure_core::inject::RunAs;

use crate::{HostError, Result, io};

/// The system's account database.
pub const PASSWD: &str = "/etc/passwd";

/// The account called `name` in the file at `path`.
///
/// # Errors
///
/// If the file cannot be read, or has no such account.
pub fn lookup(path: &Path, name: &str) -> Result<RunAs> {
    let text = std::fs::read_to_string(path).map_err(io(format!("reading {}", path.display())))?;
    parse(&text, name).ok_or_else(|| {
        HostError::Invalid(format!(
            "there is no local account {name:?} in {}",
            path.display()
        ))
    })
}

fn parse(text: &str, name: &str) -> Option<RunAs> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0] != name {
            return None;
        }
        Some(RunAs {
            uid: f[2].parse().ok()?,
            gid: f[3].parse().ok()?,
            user: name.to_owned(),
            home: PathBuf::from(f[5]),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_named_account_only() {
        let text = "root:x:0:0:root:/root:/bin/bash\n\
                    deploy:x:1000:1000:Deploy,,,:/home/deploy:/bin/bash\n\
                    broken:x:abc:1:::\n";
        let deploy = parse(text, "deploy").unwrap();
        assert_eq!((deploy.uid, deploy.gid), (1000, 1000));
        assert_eq!(deploy.home, PathBuf::from("/home/deploy"));
        assert!(parse(text, "ja").is_none());
        assert!(parse(text, "broken").is_none());
        assert!(parse(text, "nobody").is_none());
    }
}

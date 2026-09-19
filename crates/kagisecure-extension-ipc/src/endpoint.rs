//! Where the extension socket lives: beside the agent socket, in the same `0700` directory.
//!
//! Two sockets rather than one, because they are two protocols with two different trust
//! properties: the MCP socket's protocol *cannot* carry a value, and this one deliberately can.
//! Multiplexing them onto one endpoint would put the two on the same file descriptor and make the
//! distinction a matter of message dispatch rather than of which socket you are connected to.
//!
//! The directory is `kagisecure_ipc::Endpoint`'s, so the `0700` mode, the per-user location and
//! the `KAGISECURE_SOCKET` override all keep working without a second implementation of any of
//! them.

use std::path::PathBuf;

use kagisecure_ipc::endpoint::{Endpoint, EndpointError};

/// Overrides the extension endpoint. Used by the test suite and by anyone running two vaults.
pub const EXTENSION_SOCKET_ENV: &str = "KAGISECURE_EXTENSION_SOCKET";

/// The socket file name.
pub const EXTENSION_SOCKET_FILE: &str = "extension.sock";

/// The per-user extension endpoint, or whatever [`EXTENSION_SOCKET_ENV`] names.
///
/// Derived from the agent endpoint so the two always share a directory: on macOS,
/// `~/Library/Application Support/kagisecure/run/extension.sock` next to `daemon.sock`.
///
/// # Errors
///
/// [`EndpointError::NoDataDir`] if there is no home directory to put it in.
pub fn extension_endpoint() -> Result<Endpoint, EndpointError> {
    if let Some(explicit) = std::env::var_os(EXTENSION_SOCKET_ENV) {
        return Ok(Endpoint::Path(PathBuf::from(explicit)));
    }
    let agent = Endpoint::discover()?;
    match agent.path() {
        Some(path) => {
            let dir = path.parent().map_or_else(PathBuf::new, PathBuf::from);
            Ok(Endpoint::Path(dir.join(EXTENSION_SOCKET_FILE)))
        }
        // Windows named pipes: a sibling name rather than a sibling file. Not a platform this
        // milestone ships to, but the function should not be able to return the agent's endpoint.
        None => Ok(Endpoint::Namespaced(format!("{agent}-extension"))),
    }
}

// ---------------------------------------------------------------------------------------------
// Safari: a second socket, inside the App Group container
// ---------------------------------------------------------------------------------------------

/// Overrides the Safari endpoint. Used by the test suite and by anyone running two vaults.
pub const SAFARI_SOCKET_ENV: &str = "KAGISECURE_SAFARI_SOCKET";

/// The Safari socket's file name.
pub const SAFARI_SOCKET_FILE: &str = "safari.sock";

/// The directory inside the group container that holds it, so the container root is left alone.
pub const SAFARI_SOCKET_DIR: &str = "run";

/// The App Group identifier, minus the team prefix macOS requires.
///
/// The full identifier is `<TEAMID>.com.kagisecure`. The team is not a constant here on purpose:
/// a fork that signs with its own identity gets its own group, and the app derives the prefix from
/// its own code signature at run time rather than from a string somebody has to remember to change
/// (ADR-0024).
pub const APP_GROUP_SUFFIX: &str = "com.kagisecure";

/// The full App Group identifier for `team_id`.
#[must_use]
pub fn app_group_id(team_id: &str) -> String {
    format!("{team_id}.{APP_GROUP_SUFFIX}")
}

/// The App Group container directory for `team_id`.
///
/// The same path `NSFileManager.containerURL(forSecurityApplicationGroupIdentifier:)` returns
/// inside the sandboxed extension, computed here without Foundation because the app half is Rust.
/// It is a plain directory under the user's own `Library`; the sandboxed app extension reaches it
/// through `com.apple.security.application-groups`, and the unsandboxed app reaches it because it
/// is unsandboxed.
#[must_use]
pub fn app_group_container(team_id: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library")
            .join("Group Containers")
            .join(app_group_id(team_id)),
    )
}

/// Where the Safari app extension connects, or `None` when this build has no team to derive a
/// group from.
///
/// [`SAFARI_SOCKET_ENV`] wins when it is set, which is how the tests — and a second vault — get a
/// socket without an App Group at all. Otherwise a team identifier is required: an ad-hoc build
/// has none, cannot carry the App Group entitlement, and therefore has no Safari extension to
/// serve. Returning `None` is what lets the setup screen say that in words instead of offering a
/// path nothing will ever connect to.
#[must_use]
pub fn safari_endpoint(team_id: Option<&str>) -> Option<Endpoint> {
    if let Some(explicit) = std::env::var_os(SAFARI_SOCKET_ENV) {
        return Some(Endpoint::Path(PathBuf::from(explicit)));
    }
    let container = app_group_container(team_id?)?;
    Some(Endpoint::Path(
        container.join(SAFARI_SOCKET_DIR).join(SAFARI_SOCKET_FILE),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extension_socket_is_a_sibling_of_the_agent_socket_and_never_the_same_file() {
        // `discover()` reads the process environment, which other tests share, so this asserts
        // the shape of the derivation rather than calling it with a mutated environment.
        let agent = Endpoint::Path(PathBuf::from("/tmp/ks/run/daemon.sock"));
        let dir = agent.path().unwrap().parent().unwrap();
        let extension = Endpoint::Path(dir.join(EXTENSION_SOCKET_FILE));
        assert_eq!(
            extension.path().unwrap(),
            std::path::Path::new("/tmp/ks/run/extension.sock")
        );
        assert_ne!(extension.path(), agent.path());
    }

    #[test]
    fn the_environment_override_is_taken_verbatim() {
        // SAFETY-adjacent note: this is the one test that mutates the process environment, and it
        // restores it. `set_var` is unsafe in edition 2024, so it is done in a child process
        // instead: assert the code path by calling with the variable set through `Command`.
        let exe = std::env::current_exe().expect("test exe");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "endpoint::tests::the_environment_override_is_taken_verbatim_inner",
                "--nocapture",
                "--ignored",
            ])
            .env(EXTENSION_SOCKET_ENV, "/tmp/override-extension.sock")
            .output()
            .expect("re-run self");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run by the parent test above, with the environment variable set"]
    fn the_environment_override_is_taken_verbatim_inner() {
        let endpoint = extension_endpoint().expect("endpoint");
        assert_eq!(
            endpoint.path().unwrap(),
            std::path::Path::new("/tmp/override-extension.sock")
        );
    }

    #[test]
    fn the_app_group_identifier_carries_the_team_prefix_macos_requires() {
        assert_eq!(app_group_id("4CZNJKU58K"), "4CZNJKU58K.com.kagisecure");
        assert!(app_group_id("XXXXXXXXXX").ends_with(APP_GROUP_SUFFIX));
    }

    #[test]
    fn a_build_with_no_team_has_no_safari_socket_rather_than_a_made_up_one() {
        // Only meaningful when the override is unset, which is the normal case for this suite.
        if std::env::var_os(SAFARI_SOCKET_ENV).is_none() {
            assert_eq!(safari_endpoint(None), None);
        }
    }

    #[test]
    fn the_safari_socket_lives_in_the_group_container_and_not_beside_the_agent_socket() {
        if std::env::var_os(SAFARI_SOCKET_ENV).is_some() {
            return;
        }
        let endpoint = safari_endpoint(Some("4CZNJKU58K")).expect("a team gives a socket");
        let path = endpoint.path().expect("a unix path");
        let text = path.to_string_lossy();
        assert!(text.contains("Group Containers"), "{text}");
        assert!(text.contains("4CZNJKU58K.com.kagisecure"), "{text}");
        assert!(text.ends_with("run/safari.sock"), "{text}");
    }

    #[test]
    fn the_safari_socket_path_fits_in_a_sockaddr_un() {
        // `sun_path` is 104 bytes on macOS, including the terminator. A path that overflows it
        // fails at `bind` with a message about an invalid argument and no hint about length, so
        // the budget is asserted rather than discovered.
        if std::env::var_os(SAFARI_SOCKET_ENV).is_some() {
            return;
        }
        let endpoint = safari_endpoint(Some("4CZNJKU58K")).expect("endpoint");
        let len = endpoint.path().unwrap().as_os_str().len();
        assert!(len < 104, "the Safari socket path is {len} bytes");
    }
}

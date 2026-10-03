//! `overwrite: true` on a file kagisecure did not write is a question for the human every time.
//!
//! mcp-server.md §2.7 and threat-model M-16 promise that `write_env_file` never replaces a file it
//! did not write unless the call asks to *and* the user approves that overwrite. A lease is an
//! approval to write *kagisecure's* file into a directory; it said nothing about replacing the
//! user's. `LeaseRequest` carried no overwrite dimension, so once a session lease covered the
//! directory and file name, `overwrite: true` replaced whatever the user had put there since —
//! their own `.env` — with no sheet.

mod common;

use common::{REAL_DOTENV, allow_session, error_code, fixture, with_ui, write_env_file};

const USERS_OWN: &str = "DATABASE_URL=postgres://the-users-own-settings\n";

#[test]
fn a_covering_lease_does_not_authorize_replacing_a_file_the_user_put_there() {
    let fx = fixture();
    let dir = fx.canonical_project();
    let dir_s = dir.display().to_string();
    let target = dir.join(REAL_DOTENV);

    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("overwrite-lease");
        let first = client
            .call(&write_env_file(&fx, &dir_s, REAL_DOTENV, false, 900))
            .expect("call");
        assert!(error_code(&first).is_none(), "{first:?}");

        // Re-writing kagisecure's own, unchanged file is what the lease is for: no new sheet.
        let again = client
            .call(&write_env_file(&fx, &dir_s, REAL_DOTENV, true, 900))
            .expect("call");
        assert!(error_code(&again).is_none(), "{again:?}");
    });
    assert_eq!(seen.len(), 1, "one sheet for kagisecure's own file");

    // The user replaces it with their own (a distinct file renamed over it).
    let theirs = dir.join("theirs.tmp");
    std::fs::write(&theirs, USERS_OWN).expect("write");
    std::fs::rename(&theirs, &target).expect("rename");

    // The agent asks to overwrite, under the same covering lease; the user says no.
    let (reply, seen) = with_ui(
        &fx.agent,
        kagisecure_agent::approval::Decision::Deny,
        || {
            fx.client("overwrite-lease")
                .call(&write_env_file(&fx, &dir_s, REAL_DOTENV, true, 900))
                .expect("call")
        },
    );
    assert_eq!(
        seen.len(),
        1,
        "replacing a file kagisecure did not write must be put to the human, lease or not"
    );
    assert_eq!(seen[0].target_written_by_us, Some(false));
    assert!(seen[0].overwrite_requested);
    assert_eq!(error_code(&reply).as_deref(), Some("USER_DENIED"));
    assert_eq!(
        std::fs::read_to_string(&target).expect("read"),
        USERS_OWN,
        "the user's file is untouched"
    );
}

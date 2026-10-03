//! Arming from the app (ADR-0042; the owner's GUI check of 2026-09-27, item 6): a personal vault
//! with no machine vault yet is armed by creating one first. Its own test binary, since the engine
//! is one per process.
#![cfg(unix)]

use kagisecure_ffi::{
    UnattendedPresence, VaultSession, unattended_arm, unattended_disarm,
    unattended_machine_vault_path, unattended_start, unattended_status, unattended_stop,
};

#[test]
fn arming_a_vault_with_no_machine_vault_creates_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("p.kagivault");
    let session = VaultSession::create(
        path.to_string_lossy().into_owned(),
        "pw".to_owned(),
        "Personal".to_owned(),
        Some(64),
        Some(1),
    )
    .expect("create");
    let machine = unattended_machine_vault_path(session.path());
    assert!(
        !std::path::Path::new(&machine).exists(),
        "no machine vault yet"
    );

    unattended_start(
        machine.clone(),
        Some(dir.path().join("u.sock").to_string_lossy().into_owned()),
    )
    .expect("engine");
    let key = unattended_arm(session.clone(), UnattendedPresence::Confirmed).expect("arm");
    assert_eq!(key.len(), 48, "the Keychain's bytes");
    assert!(
        std::path::Path::new(&machine).exists(),
        "created by the arm"
    );
    assert!(unattended_status().armed);

    // Arming again uses the same machine vault rather than making another.
    assert!(unattended_disarm(Some(session.clone())));
    let again = unattended_arm(session.clone(), UnattendedPresence::Confirmed).expect("again");
    assert_eq!(again, key);
    assert!(unattended_disarm(Some(session)));
    unattended_stop();
}

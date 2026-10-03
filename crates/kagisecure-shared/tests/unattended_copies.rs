//! Unattended copies of shared values (ADR-0042 §13, Phase 4), through the public API: the
//! vault's policy — allowed by default, set by an admin only — and the copy records every member
//! reads, including a copy held by a device removed since.

use std::path::Path;

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::proto::EnvId;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_shared::admin::create::create;
use kagisecure_shared::admin::enroll::{Joining, invite_with_kdf, join};
use kagisecure_shared::admin::exchange::sync;
use kagisecure_shared::admin::remove::remove_device;
use kagisecure_shared::replica::Replica;
use kagisecure_shared::unattended::{CopyNote, record_copy, set_copies_allowed, unattended_state};
use kagisecure_shared::view::SharedView;
use kagisecure_shared::{DeviceSecret, RemovalReason, Role, SharedError};

fn view(replica: &Replica, device: &DeviceSecret) -> SharedView {
    SharedView::compute(
        replica.vault_id(),
        &replica.genesis(),
        &replica.envelopes(),
        device,
    )
    .unwrap()
}

fn personal(home: &Path) -> Vault {
    let options = CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Personal".to_owned(),
        kdf_hint: None,
    };
    Vault::create(home.join("vault.kagivault"), b"password", &options)
        .unwrap()
        .0
}

fn join_as(
    admin: &mut Replica,
    admin_device: &DeviceSecret,
    home: &Path,
    exchange: &Path,
    role: Role,
    now: u64,
) -> (DeviceSecret, Replica) {
    let invite = invite_with_kdf(
        admin,
        admin_device,
        Joining::NewMember(role),
        "device",
        KdfParams::new(64, 1, 1).unwrap(),
        now,
    )
    .unwrap();
    let passphrase = invite.passphrase.expose_str().unwrap().to_owned();
    let mut vault = personal(home);
    let (replica, device) =
        join(&mut vault, &invite.file, &passphrase, Some(exchange), now).unwrap();
    (device, replica)
}

fn note(copy: EnvId, source: EnvId, holder: &str, held: bool) -> CopyNote {
    CopyNote {
        copy,
        source,
        name: "deploy".to_owned(),
        variables: vec!["DEPLOY_TOKEN".to_owned()],
        holder: holder.to_owned(),
        held,
    }
}

#[test]
fn copies_are_allowed_by_default_recorded_by_any_member_and_forbidden_only_by_an_admin() {
    let dir = tempfile::tempdir().unwrap();
    let exchange = dir.path().join("exchange");
    let alice = DeviceSecret::generate().unwrap();
    let mut a = create(
        &dir.path().join("a").join("vault.kagivault"),
        &alice,
        "Team",
        Some(&exchange),
        100,
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("b")).unwrap();
    std::fs::create_dir_all(dir.path().join("c")).unwrap();
    let (bob, mut b) = join_as(
        &mut a,
        &alice,
        &dir.path().join("b"),
        &exchange,
        Role::Writer,
        101,
    );
    let (carol, mut c) = join_as(
        &mut a,
        &alice,
        &dir.path().join("c"),
        &exchange,
        Role::Reader,
        102,
    );
    let sync_all = |a: &mut Replica, b: &mut Replica, c: &mut Replica| {
        for _ in 0..2 {
            sync(a, &alice).unwrap();
            sync(b, &bob).unwrap();
            sync(c, &carol).unwrap();
        }
    };

    // Nobody said anything: copies are allowed, and none is held.
    let state = unattended_state(&view(&a, &alice));
    assert!(state.copies_allowed);
    assert!(state.copies.is_empty());

    // A writer and a reader each record a copy; every member reads both.
    let (source, bob_copy, carol_copy) = (EnvId::new(), EnvId::new(), EnvId::new());
    record_copy(
        &mut b,
        &bob,
        &note(bob_copy, source, "Bob's Mac", true),
        110,
    )
    .unwrap();
    record_copy(
        &mut c,
        &carol,
        &note(carol_copy, source, "Carol's Mac", true),
        111,
    )
    .unwrap();
    sync_all(&mut a, &mut b, &mut c);
    for (replica, device) in [(&a, &alice), (&b, &bob), (&c, &carol)] {
        let state = unattended_state(&view(replica, device));
        let holders: Vec<&str> = state
            .copies_of(&source)
            .map(|c| c.holder.as_str())
            .collect();
        assert_eq!(holders.len(), 2, "{holders:?}");
        assert!(holders.contains(&"Bob's Mac") && holders.contains(&"Carol's Mac"));
        assert!(state.copies.iter().all(|c| c.holder_active));
        assert_eq!(state.copies[0].variables, ["DEPLOY_TOKEN"]);
    }

    // Only an admin sets the policy.
    assert!(matches!(
        set_copies_allowed(&mut b, &bob, false, 120),
        Err(SharedError::Refused(_))
    ));
    set_copies_allowed(&mut a, &alice, false, 121).unwrap();
    sync_all(&mut a, &mut b, &mut c);
    assert!(!unattended_state(&view(&b, &bob)).copies_allowed);
    set_copies_allowed(&mut a, &alice, true, 122).unwrap();
    sync_all(&mut a, &mut b, &mut c);
    assert!(unattended_state(&view(&c, &carol)).copies_allowed);

    // Carol removes her copy: its latest record stands.
    record_copy(
        &mut c,
        &carol,
        &note(carol_copy, source, "Carol's Mac", false),
        130,
    )
    .unwrap();
    sync_all(&mut a, &mut b, &mut c);
    let state = unattended_state(&view(&a, &alice));
    assert_eq!(state.copies.len(), 1);
    assert_eq!(state.copies[0].holder, "Bob's Mac");

    // Bob is removed: his copy stays on his Mac, and the vault says so.
    remove_device(&mut a, &alice, bob.id(), RemovalReason::Left, 140).unwrap();
    let state = unattended_state(&view(&a, &alice));
    assert_eq!(state.copies.len(), 1);
    assert!(!state.copies[0].holder_active);
}

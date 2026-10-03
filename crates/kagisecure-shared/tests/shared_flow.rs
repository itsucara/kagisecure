//! The honest flow end to end, through the public API only: three devices create, invite, join,
//! write, sync through one exchange directory and converge; a removed device cannot read what
//! is written after its removal; and a damaged replica is rebuilt from the exchange directory.

use std::path::Path;

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Field, FieldValue, Item};
use kagisecure_core::proto::{Category, ItemId, VaultId};
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_shared::admin::create::create;
use kagisecure_shared::admin::enroll::{Joining, invite_with_kdf, join};
use kagisecure_shared::admin::exchange::{export_bundle, import_bundle, sync};
use kagisecure_shared::admin::remove::remove_device;
use kagisecure_shared::merge::materialize_item;
use kagisecure_shared::replica::{RebuildSource, Replica};
use kagisecure_shared::rotation::rotation_list;
use kagisecure_shared::view::{Ignored, SharedView};
use kagisecure_shared::write::{next_seq, put_item};
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

/// An item; writing it into a shared vault sets its vault id.
fn item(id: ItemId, title: &str, password: &str) -> Item {
    let mut item = Item::new(VaultId::new(), Category::Login, title);
    item.id = id;
    item.fields.push(Field::public("password", password));
    item
}

fn password(replica: &Replica, device: &DeviceSecret, id: ItemId) -> Option<String> {
    let merged = materialize_item(&view(replica, device), id).unwrap()?;
    let item = merged.item?;
    item.fields.iter().find_map(|f| match &f.value {
        FieldValue::Public(v) => Some(v.clone()),
        FieldValue::Secret(_) => None,
    })
}

/// A cheap personal vault at `home`: joining stores the device key there.
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

/// The admin invites a new writer; the joiner opens the one file with the passphrase.
fn invite_and_join(
    admin: &mut Replica,
    admin_device: &DeviceSecret,
    home: &Path,
    exchange: &Path,
    label: &str,
    now: u64,
) -> (DeviceSecret, Replica) {
    let cheap = KdfParams::new(64, 1, 1).unwrap();
    let invite = invite_with_kdf(
        admin,
        admin_device,
        Joining::NewMember(Role::Writer),
        label,
        cheap,
        now,
    )
    .unwrap();
    let passphrase = invite.passphrase.expose_str().unwrap().to_owned();
    assert_eq!(passphrase.split('-').count(), 6);
    let mut vault = personal(home);
    assert!(matches!(
        join(&mut vault, &invite.file, "wrong words", Some(exchange), now),
        Err(SharedError::Decrypt)
    ));
    // Typed with spaces and capitals, it still opens.
    let typed = passphrase.replace('-', "  ").to_uppercase();
    let (replica, device) = join(&mut vault, &invite.file, &typed, Some(exchange), now).unwrap();
    assert_eq!(device.id(), invite.device);
    assert_eq!(vault.device_keys().len(), 1);
    assert_eq!(vault.device_keys()[0].label(), label);

    // The label a CLI or app invite names a new member with becomes the default local name for
    // that member on both sides (no "Unnamed member" until someone changes it): the admin's own
    // replica, right where `invite_with_kdf` wrote it, and the joiner's own replica, for itself.
    let joined_member = view(admin, admin_device)
        .roster()
        .snapshot()
        .device(&device.id())
        .map(|d| d.member)
        .unwrap();
    assert_eq!(
        admin
            .local()
            .member_names
            .get(&joined_member)
            .map(String::as_str),
        Some(label)
    );
    assert_eq!(
        replica
            .local()
            .member_names
            .get(&joined_member)
            .map(String::as_str),
        Some(label)
    );
    (device, replica)
}

#[test]
fn three_devices_create_invite_join_write_sync_remove_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let exchange = dir.path().join("exchange");
    let homes: Vec<_> = ["a", "b", "c"].iter().map(|h| dir.path().join(h)).collect();

    // Create, invite, join.
    let alice = DeviceSecret::generate().unwrap();
    let mut a = create(
        &homes[0].join("vault.kagivault"),
        &alice,
        "Team",
        Some(&exchange),
        100,
    )
    .unwrap();
    let (bob, mut b) = invite_and_join(&mut a, &alice, &homes[1], &exchange, "Bob's laptop", 101);
    let (carol, mut c) =
        invite_and_join(&mut a, &alice, &homes[2], &exchange, "Carol's desktop", 102);
    assert_eq!(b.local().vault_name.as_deref(), Some("Team"));
    // Trusted on first use: Bob knows Alice's device as first seen.
    assert!(b.local().first_seen.contains_key(&alice.id()));

    // Write on every device, sync, and converge.
    let (one, two) = (ItemId::new(), ItemId::new());
    put_item(&mut a, &alice, item(one, "Database", "first"), 110).unwrap();
    put_item(&mut b, &bob, item(two, "Mail", "bob's"), 111).unwrap();
    sync(&mut c, &carol).unwrap();
    let before_carol_wrote = std::fs::read(c.path()).unwrap();
    put_item(&mut c, &carol, item(one, "Database", "rotated"), 120).unwrap();
    for _ in 0..2 {
        for (replica, device) in [(&mut a, &alice), (&mut b, &bob), (&mut c, &carol)] {
            sync(replica, device).unwrap();
        }
    }
    let digest = view(&a, &alice).state_digest();
    assert_eq!(view(&b, &bob).state_digest(), digest);
    assert_eq!(view(&c, &carol).state_digest(), digest);
    for (replica, device) in [(&a, &alice), (&b, &bob), (&c, &carol)] {
        assert_eq!(password(replica, device, one).as_deref(), Some("rotated"));
        assert_eq!(password(replica, device, two).as_deref(), Some("bob's"));
    }
    // Carol's replica restored from a copy older than her write does not reuse its seq: her
    // own records come back from the exchange directory first.
    std::fs::write(c.path(), before_carol_wrote).unwrap();
    let path = c.path().to_owned();
    let mut c = Replica::open(&path, &carol).unwrap();
    assert_eq!(next_seq(&mut c, &carol).unwrap(), 1);
    sync(&mut c, &carol).unwrap();

    // Remove Carol: a new epoch for Alice and Bob, and Carol cannot read what follows.
    remove_device(&mut a, &alice, carol.id(), RemovalReason::Left, 130).unwrap();
    let three = ItemId::new();
    put_item(&mut a, &alice, item(three, "Payroll", "secret"), 131).unwrap();
    for (replica, device) in [(&mut b, &bob), (&mut c, &carol)] {
        sync(replica, device).unwrap();
    }
    assert_eq!(password(&b, &bob, three).as_deref(), Some("secret"));
    assert_eq!(password(&c, &carol, three), None);
    let carol_view = view(&c, &carol);
    assert!(
        carol_view
            .ignored()
            .values()
            .any(|why| *why == Ignored::Unreadable)
    );
    // And she can no longer write.
    assert!(matches!(
        put_item(&mut c, &carol, item(two, "Mail", "carol's"), 140),
        Err(SharedError::Refused(_))
    ));
    let exposed = rotation_list(&view(&a, &alice));
    assert_eq!(exposed.len(), 1);
    assert_eq!(exposed[0].device, carol.id());
    assert!(!exposed[0].objects.is_empty());

    // A damaged replica refuses to open, and is rebuilt from the exchange directory.
    let digest = view(&a, &alice).state_digest();
    let path = a.path().to_owned();
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        Replica::open(&path, &alice),
        Err(SharedError::Decrypt)
    ));
    let rebuilt = Replica::rebuild_from(&path, &alice, RebuildSource::Dir(&exchange), 200).unwrap();
    assert_eq!(view(&rebuilt, &alice).state_digest(), digest);
    assert_eq!(password(&rebuilt, &alice, three).as_deref(), Some("secret"));

    // A bundle carries the same records.
    let summary = import_bundle(&mut b, &bob, &export_bundle(&rebuilt).unwrap()).unwrap();
    assert_eq!(summary.records_added, 0);
}

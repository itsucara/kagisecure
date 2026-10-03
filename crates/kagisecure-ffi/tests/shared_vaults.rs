//! Shared vaults through the app's FFI surface (ADR-0035, Phase 5): create, write, invite, join,
//! sync through one folder, remove, lock, and rebuild — two personal vaults on one machine, the
//! way two Macs would be, with a temporary folder standing in for iCloud Drive.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kagisecure_ffi::{
    FfiError, FieldDraft, ItemDraft, ItemFilter, ItemSort, ItemView, PresenceGate, PresenceOutcome,
    ReleasePurpose, SharedRole, SharedRosterWarning, SharedVaultSession, VarBinding, VaultSession,
};

/// The Argon2id cost for every personal vault and invitation here: protects nothing, costs
/// nothing.
const CHEAP_M_KIB: u32 = 64;
const CHEAP_T: u32 = 1;

struct YesGate;

#[async_trait::async_trait]
impl PresenceGate for YesGate {
    async fn confirm(&self, _reason: String) -> PresenceOutcome {
        PresenceOutcome::Confirmed
    }
}

/// A personal vault at `dir/name.kagivault`, unlocked, with a gate that always says yes.
fn personal(dir: &Path, name: &str) -> Arc<VaultSession> {
    let session = VaultSession::create(
        dir.join(format!("{name}.kagivault")).display().to_string(),
        "pw".to_owned(),
        name.to_owned(),
        Some(CHEAP_M_KIB),
        Some(CHEAP_T),
    )
    .unwrap();
    session.set_presence_gate(Arc::new(YesGate)).unwrap();
    session
}

fn text(path: &Path) -> String {
    path.display().to_string()
}

/// A login with `password` as its password, written to `vault`.
fn login(vault: &SharedVaultSession, title: &str, password: &str) -> ItemView {
    let item = vault
        .create_item("login".to_owned(), title.to_owned())
        .unwrap();
    edit(vault, &item, title, password)
}

/// `item` saved with `title` and `password`, keeping every other field.
fn edit(vault: &SharedVaultSession, item: &ItemView, title: &str, password: &str) -> ItemView {
    let fields = item
        .fields
        .iter()
        .map(|f| FieldDraft {
            id: Some(f.id.clone()),
            label: f.label.clone(),
            kind: f.kind,
            concealed: f.concealed,
            value: match f.label.as_str() {
                "password" => Some(password.to_owned()),
                "username" => Some("ada".to_owned()),
                // A concealed field nobody touched keeps its value; a public one is resent.
                _ if f.concealed => None,
                _ => Some(f.value.clone().unwrap_or_default()),
            },
            section: f.section.clone(),
            agent_visible: f.agent_visible,
        })
        // The template's one-time-password field has no value yet; leave it out.
        .filter(|f| f.label != "one-time password")
        .collect();
    vault
        .save_item(ItemDraft {
            id: item.id.clone(),
            category: item.category.clone(),
            title: title.to_owned(),
            fields,
            tags: Vec::new(),
            urls: Vec::new(),
            notes: None,
            revision: "a revision a shared save does not check".to_owned(),
        })
        .unwrap()
}

fn titles(vault: &SharedVaultSession) -> Vec<String> {
    vault
        .list_items(ItemFilter::All, None, ItemSort::Title)
        .into_iter()
        .map(|i| i.title)
        .collect()
}

fn password(vault: &SharedVaultSession, title: &str) -> String {
    let item = vault
        .list_items(ItemFilter::All, Some(title.to_owned()), ItemSort::Title)
        .into_iter()
        .find(|i| i.title == title)
        .expect("the item");
    let field = item.fields.iter().find(|f| f.label == "password").unwrap();
    let release = futures::executor::block_on(vault.release_field(
        item.id.clone(),
        field.id.clone(),
        ReleasePurpose::Reveal,
    ))
    .unwrap();
    release.value().unwrap()
}

/// Alice's Mac creates "Team" syncing through `folder`, and invites Bob, who joins.
struct Pair {
    _dir: tempfile::TempDir,
    folder: PathBuf,
    alice: Arc<VaultSession>,
    team_a: Arc<SharedVaultSession>,
    bob: Arc<VaultSession>,
    team_b: Arc<SharedVaultSession>,
    bob_member: String,
}

fn pair(role: SharedRole) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("iCloud Team");
    let alice = personal(dir.path(), "alice");
    let team_a = alice
        .create_shared_vault("Team".to_owned(), Some(text(&folder)))
        .unwrap();
    login(&team_a, "Database", "first");

    let invitation = folder.join("Bob.kagisecure-invite");
    let invite = team_a
        .invite_member(
            "Bob".to_owned(),
            role,
            text(&invitation),
            Some(CHEAP_M_KIB),
            Some(CHEAP_T),
        )
        .unwrap();
    assert_eq!(invite.passphrase.split('-').count(), 6);
    // The passphrase never shows up in a `Debug` rendering.
    assert!(!format!("{invite:?}").contains(&invite.passphrase));

    let bob = personal(dir.path(), "bob");
    assert!(matches!(
        bob.join_shared_vault(
            text(&invitation),
            "not the words".to_owned(),
            Some(text(&folder))
        ),
        Err(FfiError::WrongCredential)
    ));
    let typed = invite.passphrase.replace('-', " ").to_uppercase();
    let team_b = bob
        .join_shared_vault(text(&invitation), typed, Some(text(&folder)))
        .unwrap();
    Pair {
        _dir: dir,
        folder,
        alice,
        team_a,
        bob,
        team_b,
        bob_member: invite.member_id,
    }
}

#[test]
fn a_created_vault_is_listed_written_read_and_released() {
    let dir = tempfile::tempdir().unwrap();
    let alice = personal(dir.path(), "alice");
    assert!(alice.open_shared_vaults().unwrap().is_empty());

    let team = alice
        .create_shared_vault("  Team  ".to_owned(), None)
        .unwrap();
    let summary = team.summary();
    assert_eq!(summary.name, "Team");
    assert_eq!(summary.my_role, Some(SharedRole::Admin));
    assert_eq!(summary.member_count, 1);
    assert_eq!(summary.folder, None);
    assert_eq!(summary.problem, None);

    let item = login(&team, "Database", "s3cret");
    assert!(
        !item.agent_visible,
        "a shared item starts hidden from agents"
    );
    assert_eq!(titles(&team), ["Database"]);
    assert_eq!(password(&team, "Database"), "s3cret");
    // A concealed value is never on the view.
    let field = item.fields.iter().find(|f| f.label == "password").unwrap();
    assert!(field.concealed && field.value.is_none());

    // Favourites are this device's own, and a filter sees them.
    team.set_favorite(item.id.clone(), true).unwrap();
    let favorites = team.list_items(ItemFilter::Favorites, None, ItemSort::Title);
    assert_eq!(favorites.len(), 1);
    assert!(favorites[0].favorite);

    // Reopened after unlocking again: the same vault, the same item.
    let path = alice.path();
    alice.lock();
    let alice = VaultSession::unlock_with_password(path, "pw".to_owned()).unwrap();
    alice.set_presence_gate(Arc::new(YesGate)).unwrap();
    let vaults = alice.open_shared_vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].vault_id(), summary.id);
    assert_eq!(vaults[0].summary().name, "Team");
    assert_eq!(titles(&vaults[0]), ["Database"]);
    assert!(vaults[0].list_items(ItemFilter::Favorites, None, ItemSort::Title)[0].favorite);
    assert_eq!(password(&vaults[0], "Database"), "s3cret");

    // Moving to the trash deletes it for everyone: there is no shared trash.
    vaults[0].set_trashed(item.id, true).unwrap();
    assert!(titles(&vaults[0]).is_empty());
    assert!(
        vaults[0]
            .list_items(ItemFilter::Trash, None, ItemSort::Title)
            .is_empty()
    );
}

#[test]
fn an_empty_name_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let alice = personal(dir.path(), "alice");
    assert!(matches!(
        alice.create_shared_vault("   ".to_owned(), None),
        Err(FfiError::Invalid { .. })
    ));
    assert!(alice.open_shared_vaults().unwrap().is_empty());
}

#[test]
fn two_macs_invite_join_and_sync_through_one_folder() {
    let p = pair(SharedRole::Writer);
    // Bob reads what Alice wrote before inviting him.
    assert_eq!(titles(&p.team_b), ["Database"]);
    assert_eq!(password(&p.team_b, "Database"), "first");
    assert_eq!(p.team_b.summary().name, "Team");
    assert_eq!(p.team_b.summary().my_role, Some(SharedRole::Writer));
    assert_eq!(p.team_b.folder().as_deref(), Some(text(&p.folder).as_str()));

    // Alice knows Bob by the name she invited him with.
    let members = p.team_a.members();
    assert_eq!(members.len(), 2);
    assert!(members[0].is_you);
    assert_eq!(members[0].role, SharedRole::Admin);
    assert_eq!(members[1].name, "Bob");
    assert_eq!(members[1].id, p.bob_member);
    assert_eq!(members[1].devices.len(), 1);
    assert_eq!(members[1].devices[0].fingerprint.split(' ').count(), 10);
    // Bob names Alice on his own Mac. Nobody told him her name (decision 81: roster labels'
    // sealing is undecided, so it never synced), so he sees a fallback built from her device's
    // fingerprint rather than a bare "Unnamed member" indistinguishable from anyone else's.
    let alice_member = p.team_b.members().into_iter().find(|m| !m.is_you).unwrap();
    assert_ne!(alice_member.name, "Unnamed member");
    assert!(alice_member.name.starts_with("Device "));
    let alice_fingerprint = &alice_member.devices[0].fingerprint;
    assert!(
        alice_member
            .name
            .contains(alice_fingerprint.split(' ').next().unwrap())
    );
    p.team_b
        .set_member_name(alice_member.id.clone(), "Alice".to_owned())
        .unwrap();
    assert!(p.team_b.members().iter().any(|m| m.name == "Alice"));

    // Bob edits and adds; Alice's sync picks both up. The last writer wins, with no conflict.
    let database = p
        .team_b
        .list_items(ItemFilter::All, None, ItemSort::Title)
        .remove(0);
    edit(&p.team_b, &database, "Database", "rotated by bob");
    login(&p.team_b, "Mail", "bob's");
    let summary = p.team_a.sync().unwrap();
    assert!(summary.records_added >= 2);
    assert!(summary.items_changed.contains(&"Mail".to_owned()));
    assert_eq!(titles(&p.team_a), ["Database", "Mail"]);
    assert_eq!(password(&p.team_a, "Database"), "rotated by bob");
    // Nothing new: nothing to report.
    assert_eq!(p.team_a.sync().unwrap().records_added, 0);

    // A reader cannot write.
    p.team_a
        .set_role(p.bob_member.clone(), SharedRole::Reader)
        .unwrap();
    assert!(p.team_b.sync().unwrap().members_changed);
    assert_eq!(p.team_b.summary().my_role, Some(SharedRole::Reader));
    assert!(matches!(
        p.team_b.create_item("login".to_owned(), "Nope".to_owned()),
        Err(FfiError::Invalid { .. })
    ));
    // Nor change who is in the vault.
    assert!(matches!(
        p.team_b.invite_member(
            "Carol".to_owned(),
            SharedRole::Writer,
            text(&p.folder.join("Carol.kagisecure-invite")),
            Some(CHEAP_M_KIB),
            Some(CHEAP_T)
        ),
        Err(FfiError::Invalid { .. })
    ));
}

#[test]
fn the_summary_warns_about_the_roster_the_way_the_cli_status_does() {
    let p = pair(SharedRole::Writer);
    // Alice alone is an admin: one admin left is worth a warning (ADR-0035 addendum), the same
    // one `kagisecure shared status` prints — losing her would freeze the roster.
    assert_eq!(
        p.team_a.summary().warnings,
        vec![SharedRosterWarning::FewAdmins]
    );
    // Bob, a writer, sees the same roster and the same warning: it is about the vault, not about
    // who is looking.
    assert_eq!(
        p.team_b.summary().warnings,
        vec![SharedRosterWarning::FewAdmins]
    );

    // A second admin: the warning clears for everyone once they see the change.
    p.team_a
        .set_role(p.bob_member.clone(), SharedRole::Admin)
        .unwrap();
    assert_eq!(p.team_a.summary().warnings, Vec::new());
    p.team_b.sync().unwrap();
    assert_eq!(p.team_b.summary().warnings, Vec::new());

    // Demoting Bob back and then removing Alice's own admin role is refused (an admin cannot
    // leave nobody in charge), so the only way to reach zero admins here is to remove the last
    // one directly — `remove_member` refuses removing this device's own member (tested
    // elsewhere), so this checks the one-admin-left warning is what `set_role` demotion away from
    // it, not just member removal, also reaches.
    p.team_a
        .set_role(p.bob_member.clone(), SharedRole::Writer)
        .unwrap();
    assert_eq!(
        p.team_a.summary().warnings,
        vec![SharedRosterWarning::FewAdmins]
    );
}

#[test]
fn a_removed_member_reads_nothing_new_and_the_rotation_list_names_what_they_saw() {
    let p = pair(SharedRole::Writer);
    // Alice cannot remove herself, nor leave the vault without an admin.
    let me = p.team_a.members().into_iter().find(|m| m.is_you).unwrap();
    assert!(matches!(
        p.team_a.remove_member(me.id),
        Err(FfiError::Invalid { .. })
    ));

    p.team_a.remove_member(p.bob_member.clone()).unwrap();
    assert_eq!(p.team_a.members().len(), 1);
    let exposed = p.team_a.rotation_list();
    assert_eq!(exposed.len(), 1);
    assert_eq!(exposed[0].member_name, "Bob");
    assert_eq!(exposed[0].item_titles, ["Database"]);

    login(&p.team_a, "Payroll", "after bob");
    p.team_b.sync().unwrap();
    assert_eq!(p.team_b.summary().my_role, None);
    assert!(!titles(&p.team_b).contains(&"Payroll".to_owned()));
    let database = p
        .team_b
        .list_items(ItemFilter::All, None, ItemSort::Title)
        .remove(0);
    assert!(matches!(
        p.team_b.save_item(ItemDraft {
            id: database.id,
            category: database.category,
            title: "Taken over".to_owned(),
            fields: Vec::new(),
            tags: Vec::new(),
            urls: Vec::new(),
            notes: None,
            revision: database.revision,
        }),
        Err(FfiError::Invalid { .. })
    ));
}

#[test]
fn locking_the_personal_vault_closes_every_shared_vault() {
    let p = pair(SharedRole::Writer);
    let item = p
        .team_b
        .list_items(ItemFilter::All, None, ItemSort::Title)
        .remove(0);
    let field = item.fields.iter().find(|f| f.label == "password").unwrap();
    let shown = futures::executor::block_on(p.team_b.release_field(
        item.id.clone(),
        field.id.clone(),
        ReleasePurpose::Reveal,
    ))
    .unwrap();
    assert_eq!(shown.value().unwrap(), "first");

    p.bob.lock();
    assert!(!shown.is_live());
    assert!(matches!(shown.value(), Err(FfiError::VaultLocked)));
    assert!(
        p.team_b
            .list_items(ItemFilter::All, None, ItemSort::Title)
            .is_empty()
    );
    assert!(matches!(
        p.team_b.item(item.id.clone()),
        Err(FfiError::VaultLocked)
    ));
    assert!(p.team_b.members().is_empty());
    assert!(p.team_b.summary().problem.is_some());
    assert!(matches!(p.team_b.sync(), Err(FfiError::VaultLocked)));
    // Alice's Mac is another personal vault: still open.
    assert_eq!(titles(&p.team_a), ["Database"]);
    let _ = &p.alice;
}

#[test]
fn a_damaged_copy_is_listed_with_its_problem_and_rebuilt_from_the_folder() {
    let p = pair(SharedRole::Writer);
    let id = p.team_b.vault_id();
    let replica = Path::new(&p.bob.path())
        .with_extension("kagivault.shared")
        .join(format!("{id}.kagishared"));
    let mut bytes = std::fs::read(&replica).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&replica, bytes).unwrap();

    let reopened = p.bob.open_shared_vaults().unwrap();
    assert_eq!(reopened.len(), 1);
    let problem = reopened[0].summary().problem.expect("a problem");
    assert!(problem.contains("Rebuild"), "{problem}");
    assert!(titles(&reopened[0]).is_empty());

    reopened[0].rebuild(text(&p.folder)).unwrap();
    assert_eq!(reopened[0].summary().problem, None);
    assert_eq!(titles(&reopened[0]), ["Database"]);
    assert_eq!(password(&reopened[0], "Database"), "first");
}

/// A shared vault's environments (ui-spec.md §16): created, bound to the vault's own items and
/// to a literal value, renamed, shared with agents, and edited down to nothing — everything the
/// app's editor does, mirroring `VaultSession`'s personal-vault environment calls.
#[test]
fn environments_are_created_bound_renamed_and_deleted() {
    let p = pair(SharedRole::Writer);
    assert!(p.team_a.environments().is_empty());

    let env = p
        .team_a
        .create_environment("  prod  ".to_owned(), Some("Production".to_owned()))
        .unwrap();
    assert_eq!(env.name, "prod");
    assert_eq!(env.description.as_deref(), Some("Production"));
    assert!(!env.agent_visible, "a new environment starts hidden");
    assert!(env.variables.is_empty());
    assert_eq!(p.team_a.environment(env.id.clone()).unwrap().name, "prod");

    // A literal value.
    let env = p
        .team_a
        .set_variable_value(
            env.id.clone(),
            "TOKEN".to_owned(),
            "literal-value".to_owned(),
        )
        .unwrap();
    assert_eq!(env.variable_names, ["TOKEN"]);
    assert_eq!(env.variables[0].binding, VarBinding::Literal);

    // Bound to a field of an item in this same shared vault (module documentation: "references
    // stay inside the vault").
    let item = login(&p.team_a, "Database", "s3cret");
    let field = item.fields.iter().find(|f| f.label == "password").unwrap();
    let env = p
        .team_a
        .bind_variable(
            env.id.clone(),
            "DB_PASSWORD".to_owned(),
            item.id.clone(),
            field.id.clone(),
        )
        .unwrap();
    assert_eq!(env.variable_names, ["TOKEN", "DB_PASSWORD"]);
    let bound = env
        .variables
        .iter()
        .find(|v| v.name == "DB_PASSWORD")
        .unwrap();
    assert_eq!(bound.binding, VarBinding::ItemField);
    assert_eq!(bound.item_id.as_deref(), Some(item.id.as_str()));

    // Renamed, and shared with agents.
    let env = p
        .team_a
        .rename_environment(env.id.clone(), "  production  ".to_owned())
        .unwrap();
    assert_eq!(env.name, "production");
    let env = p
        .team_a
        .set_environment_agent_visible(env.id.clone(), true)
        .unwrap();
    assert!(env.agent_visible);

    // Bob syncs: the rename and the variables are everyone's, but agent visibility is this
    // device's own (decision 22) — his copy starts hidden regardless of Alice's choice.
    p.team_b.sync().unwrap();
    let bob_env = p
        .team_b
        .environments()
        .into_iter()
        .find(|e| e.id == env.id)
        .unwrap();
    assert_eq!(bob_env.name, "production");
    assert_eq!(bob_env.variable_names, ["TOKEN", "DB_PASSWORD"]);
    assert!(
        !bob_env.agent_visible,
        "agent visibility is this device's own"
    );

    // Removing a variable and deleting the environment: for everyone.
    let env = p
        .team_a
        .remove_variable(env.id.clone(), "TOKEN".to_owned())
        .unwrap();
    assert_eq!(env.variable_names, ["DB_PASSWORD"]);
    p.team_a.delete_environment(env.id.clone()).unwrap();
    assert!(p.team_a.environments().is_empty());
    assert!(matches!(
        p.team_a.environment(env.id.clone()),
        Err(FfiError::NotPresent { .. })
    ));
    p.team_b.sync().unwrap();
    assert!(p.team_b.environments().is_empty());
}

/// A reader sees a shared vault's environments and their variables, and may flip this device's
/// own agent-visibility flag for one — but cannot create, rename, edit, or delete (ui-spec.md
/// §16.6's item rule, applied to environments).
#[test]
fn a_reader_may_view_but_not_edit_a_shared_environment() {
    let p = pair(SharedRole::Writer);
    let env = p
        .team_a
        .create_environment("prod".to_owned(), None)
        .unwrap();
    p.team_a
        .set_variable_value(env.id.clone(), "TOKEN".to_owned(), "v".to_owned())
        .unwrap();
    p.team_a
        .set_role(p.bob_member.clone(), SharedRole::Reader)
        .unwrap();
    p.team_b.sync().unwrap();

    let seen = p.team_b.environments();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].variable_names, ["TOKEN"]);

    assert!(matches!(
        p.team_b.create_environment("nope".to_owned(), None),
        Err(FfiError::Invalid { .. })
    ));
    assert!(matches!(
        p.team_b
            .set_variable_value(env.id.clone(), "TOKEN".to_owned(), "x".to_owned()),
        Err(FfiError::Invalid { .. })
    ));
    assert!(matches!(
        p.team_b
            .rename_environment(env.id.clone(), "nope".to_owned()),
        Err(FfiError::Invalid { .. })
    ));
    assert!(matches!(
        p.team_b.remove_variable(env.id.clone(), "TOKEN".to_owned()),
        Err(FfiError::Invalid { .. })
    ));
    assert!(matches!(
        p.team_b.delete_environment(env.id.clone()),
        Err(FfiError::Invalid { .. })
    ));

    // Local-only: allowed for a reader, exactly as an item's own agent-visibility flag is, and
    // invisible to Alice's copy.
    let mine = p
        .team_b
        .set_environment_agent_visible(env.id.clone(), true)
        .unwrap();
    assert!(mine.agent_visible);
    assert!(!p.team_a.environment(env.id.clone()).unwrap().agent_visible);
}

/// ADR-0035 §14 through the app's own wiring: a shared vault the app opened is attached to the
/// agent, which lists an item only once this Mac made it visible — and nothing once the personal
/// vault locks.
#[test]
fn the_agent_serves_a_shared_vault_the_app_opened() {
    use kagisecure_ipc::protocol::{ClientInfo, Request, Response};

    let dir = tempfile::tempdir().unwrap();
    let session = personal(dir.path(), "ada");
    let vault = session.create_shared_vault("Ops".to_owned(), None).unwrap();
    let item = login(&vault, "Team login", "s3cr3t-shared");

    let socket = if cfg!(windows) {
        format!(r"\\.\pipe\kagisecure-shared-test-{}", std::process::id())
    } else {
        dir.path().join("a.sock").display().to_string()
    };
    let endpoint = kagisecure_ffi::agent_start(Arc::clone(&session), Some(socket)).unwrap();
    let endpoint = kagisecure_ipc::Endpoint::parse(std::ffi::OsStr::new(&endpoint)).unwrap();
    let ask = |request: &Request| {
        kagisecure_ipc::client::Client::connect(
            &endpoint,
            ClientInfo {
                name: "shared-vaults-test".to_owned(),
                version: "0".to_owned(),
                pid: std::process::id(),
                parent_pid: None,
                argv0: "shared_vaults".to_owned(),
                cwd: None,
            },
        )
        .unwrap()
        .call(request)
        .unwrap()
    };
    let titles = || match ask(&Request::ListItems {
        vault_id: None,
        query: None,
        category: None,
        limit: 50,
        cursor: None,
    }) {
        Response::Items { items, .. } => items.into_iter().map(|i| i.title).collect::<Vec<_>>(),
        other => panic!("unexpected reply {other:?}"),
    };

    assert!(
        !titles().contains(&"Team login".to_owned()),
        "hidden by default"
    );
    vault.set_agent_visible(item.id.clone(), true).unwrap();
    assert!(titles().contains(&"Team login".to_owned()));
    match ask(&Request::ListVaults) {
        Response::Vaults { vaults } => assert!(
            vaults.iter().any(|v| v.shared && v.name == "Ops"),
            "{vaults:?}"
        ),
        other => panic!("unexpected reply {other:?}"),
    }

    session.lock();
    assert!(matches!(ask(&Request::ListVaults), Response::Error { .. }));
    kagisecure_ffi::agent_stop();
}

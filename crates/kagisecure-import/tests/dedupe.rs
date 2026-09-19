//! Re-importing the same export: what happens the second time (plan §6).
//!
//! Every test here runs an import twice. The first run is the setup; the second is the
//! assertion. That is the shape of the real complaint an import feature gets — "I ran it again
//! and now I have everything twice" — so it is the shape of the test.

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{
    Category, EnvVar, Environment, FieldKind, Item, ItemId, Secret, VarSource,
};
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_import::commit::commit;
use kagisecure_import::dedupe::{Duplicate, DuplicatePolicy, ItemAction, find_duplicate, resolve};
use kagisecure_import::ir::{
    ForeignId, ImportPlan, ImportedField, ImportedItem, ImportedRevision, SourceKind, TargetVault,
};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Argon2id parameters cheap enough for a test suite.
fn cheap_options() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Personal".to_owned(),
        kdf_hint: Some("test-profile".to_owned()),
    }
}

fn new_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    (dir, vault)
}

/// One login item, as a 1PUX parser would hand it over.
fn acme(password: &str) -> ImportedItem {
    let mut item = ImportedItem::new("Acme staging", Category::Login);
    item.foreign_id = Some(ForeignId::onepassword("acme-uuid-0001"));
    item.push_url("https://acme.example.com/login");
    item.push_tag("imported:1password");
    item.push_field(ImportedField::public("username", FieldKind::Text, "deploy"));
    item.push_field(ImportedField::secret(
        "password",
        FieldKind::Concealed,
        password.to_owned(),
    ));
    item
}

fn plan_of(items: Vec<ImportedItem>) -> ImportPlan {
    let mut plan = ImportPlan::new(SourceKind::OnePux, "/home/ada/Downloads/export.1pux");
    for item in items {
        plan.push(item);
    }
    plan
}

fn find(vault: &Vault, title: &str) -> ItemId {
    vault
        .items()
        .iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item titled {title:?}"))
        .id
}

fn item_by_id(vault: &Vault, id: ItemId) -> &Item {
    vault.items().iter().find(|i| i.id == id).expect("item")
}

// ---------------------------------------------------------------------------------------------

#[test]
fn a_first_import_creates_everything_and_nothing_is_agent_visible() {
    let (_dir, mut vault) = new_vault();
    let outcome = commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();

    assert_eq!(outcome.created, 1);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.skipped, 0);
    assert_eq!(vault.items().len(), 1);

    // Threat-model M-9. An import is a bulk operation over data nobody has looked at yet.
    let item = &vault.items()[0];
    assert!(!item.agent_visible);
    assert!(item.fields.iter().all(|f| !f.agent_visible));
    assert_eq!(item.vault_id, vault.default_vault_id().unwrap());
    assert_eq!(
        item.extra.get(ForeignId::ONEPASSWORD_UUID),
        Some(&ciborium::Value::Text("acme-uuid-0001".to_owned()))
    );

    // Exactly one audit entry for the run, with counts and a file name and no labels.
    assert_eq!(vault.audit_entries().len(), 1);
    let entry = &vault.audit_entries()[0];
    assert_eq!(entry.tool, "import");
    assert_eq!(entry.actor, "import");
    assert_eq!(entry.target_path.as_deref(), Some("export.1pux"));
    assert_eq!(
        entry.detail.as_deref(),
        Some("1pux: 1 created, 0 updated, 0 skipped")
    );
    let rendered = serde_json::to_string(entry).unwrap();
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("Downloads"), "{rendered}");
    vault.verify_audit().unwrap();
}

#[test]
fn re_importing_with_skip_adds_nothing() {
    let (_dir, mut vault) = new_vault();
    commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();
    let first = find(&vault, "Acme staging");

    let outcome = commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();

    assert_eq!(outcome.created, 0);
    assert_eq!(outcome.skipped, 1);
    assert_eq!(vault.items().len(), 1);
    assert_eq!(find(&vault, "Acme staging"), first);
}

#[test]
fn an_item_without_a_foreign_id_is_still_recognised_by_its_fingerprint() {
    let (_dir, mut vault) = new_vault();
    let mut first = acme("hunter2");
    first.foreign_id = None;
    commit(&mut vault, plan_of(vec![first]), DuplicatePolicy::Skip).unwrap();

    let mut again = acme("rotated-2026");
    again.foreign_id = None;
    assert!(matches!(
        find_duplicate(&vault, &again),
        Some(Duplicate::ByFingerprint(_))
    ));
    // The fingerprint is title + host + username, so rotating the password does not make the
    // item look new — which is the whole reason no value goes into it.
    let outcome = commit(&mut vault, plan_of(vec![again]), DuplicatePolicy::Skip).unwrap();
    assert_eq!(outcome.skipped, 1);
    assert_eq!(vault.items().len(), 1);
}

#[test]
fn a_foreign_id_match_wins_even_when_the_title_changed() {
    let (_dir, mut vault) = new_vault();
    commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();

    let mut renamed = acme("hunter2");
    renamed.title = "Acme staging (renamed upstream)".to_owned();
    assert!(matches!(
        find_duplicate(&vault, &renamed),
        Some(Duplicate::ByForeignId(_))
    ));

    commit(&mut vault, plan_of(vec![renamed]), DuplicatePolicy::Update).unwrap();
    assert_eq!(vault.items().len(), 1);
    assert_eq!(vault.items()[0].title, "Acme staging (renamed upstream)");
}

#[test]
fn update_rotates_one_value_and_keeps_everything_local() {
    let (_dir, mut vault) = new_vault();
    commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();

    // The user then does local work on the item: a tag of their own, agent visibility they
    // deliberately opted into, and an environment bound to the password field.
    let item_id = find(&vault, "Acme staging");
    let field_id;
    {
        let item = vault.find_item_mut(&item_id.to_string()).unwrap();
        item.tags.push("mine".to_owned());
        item.agent_visible = true;
        item.trashed_at = Some(1_700_000_500);
        let field = item
            .fields
            .iter_mut()
            .find(|f| f.label == "password")
            .unwrap();
        field.agent_visible = true;
        field_id = field.id;
    }
    let vault_id = vault.default_vault_id().unwrap();
    let mut env = Environment::new(vault_id, "acme");
    env.vars.push(EnvVar {
        name: "ACME_PASSWORD".to_owned(),
        source: VarSource::ItemField {
            item: item_id,
            field: field_id,
        },
    });
    vault.add_environment(env);
    let created_at = item_by_id(&vault, item_id).created_at;

    // Now the source rotates the password and the user re-imports with --on-duplicate update.
    let outcome = commit(
        &mut vault,
        plan_of(vec![acme("rotated-2026")]),
        DuplicatePolicy::Update,
    )
    .unwrap();
    assert_eq!(outcome.updated, 1);
    assert_eq!(outcome.created, 0);
    assert_eq!(vault.items().len(), 1);

    let item = item_by_id(&vault, item_id);
    assert_eq!(item.fields.len(), 2, "no field was duplicated");
    assert_eq!(
        item.field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        b"rotated-2026"
    );
    assert_eq!(
        item.field("username").unwrap().value.as_public(),
        Some("deploy")
    );

    // Preserved: the local tag, both agent-visibility opt-ins, the bin, the creation time.
    assert!(item.tags.contains(&"mine".to_owned()));
    assert!(item.tags.contains(&"imported:1password".to_owned()));
    assert!(item.agent_visible);
    assert!(item.field("password").unwrap().agent_visible);
    assert_eq!(item.trashed_at, Some(1_700_000_500));
    assert_eq!(item.created_at, created_at);

    // Preserved, and the reason the field is overwritten in place rather than replaced: the
    // field id an environment is bound to has to survive.
    assert_eq!(item.field("password").unwrap().id, field_id);
    let injections = vault.resolve_environment("acme", None).unwrap();
    assert_eq!(injections.len(), 1);
    assert_eq!(injections[0].name, "ACME_PASSWORD");
    assert_eq!(injections[0].value.expose(), b"rotated-2026");
}

#[test]
fn updating_a_rotated_secret_field_retires_the_old_value_exactly_once() {
    let (_dir, mut vault) = new_vault();
    commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();
    let item_id = find(&vault, "Acme staging");
    let field_id = item_by_id(&vault, item_id).field("password").unwrap().id;
    assert!(item_by_id(&vault, item_id).history.is_empty());

    // The source rotates the password; the import carries no `passwordHistory` entries of its
    // own, so the only reason a history entry can appear is the field-level retirement.
    let outcome = commit(
        &mut vault,
        plan_of(vec![acme("rotated-2026")]),
        DuplicatePolicy::Update,
    )
    .unwrap();
    assert_eq!(outcome.updated, 1);
    assert_eq!(outcome.history_added, 1);

    let item = item_by_id(&vault, item_id);
    assert_eq!(item.history.len(), 1);
    let retired = &item.history[0];
    assert_eq!(retired.value.as_secret().unwrap().expose(), b"hunter2");
    assert_eq!(retired.label, "password");
    assert_eq!(retired.kind, FieldKind::Concealed);
    assert_eq!(retired.field_id, Some(field_id));
    assert_eq!(
        item.field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        b"rotated-2026"
    );

    // Re-running the same update — the field's value has not changed since the last commit — must
    // not retire "rotated-2026" against itself.
    let outcome = commit(
        &mut vault,
        plan_of(vec![acme("rotated-2026")]),
        DuplicatePolicy::Update,
    )
    .unwrap();
    assert_eq!(
        outcome.history_added, 0,
        "an unchanged field is not a rotation"
    );
    assert_eq!(item_by_id(&vault, item_id).history.len(), 1);
}

#[test]
fn update_merges_history_and_never_doubles_it() {
    let (_dir, mut vault) = new_vault();

    let mut first = acme("hunter2");
    first.push_revision(ImportedRevision::secret("older-2019".to_owned(), Some(100)));
    let outcome = commit(&mut vault, plan_of(vec![first]), DuplicatePolicy::Skip).unwrap();
    assert_eq!(outcome.history_added, 1);

    // The second export carries the entry we already have, plus one more — and also rotates the
    // live password field itself, which now retires its own old value (`hunter2`, at the moment
    // of this commit) alongside the two `passwordHistory`-style entries the source carries.
    let mut second = acme("rotated-2026");
    second.push_revision(ImportedRevision::secret("older-2019".to_owned(), Some(100)));
    second.push_revision(ImportedRevision::secret("hunter2".to_owned(), Some(200)));
    let outcome = commit(&mut vault, plan_of(vec![second]), DuplicatePolicy::Update).unwrap();
    assert_eq!(
        outcome.history_added, 2,
        "the known entry was not re-added, but the field's own rotation added one"
    );

    let item = &vault.items()[0];
    assert_eq!(item.history.len(), 3);
    // Oldest first.
    assert_eq!(item.history[0].retired_at, 100);
    assert_eq!(item.history[1].retired_at, 200);
    assert_eq!(
        item.history[1].value.as_secret().unwrap().expose(),
        b"hunter2"
    );
    assert_eq!(item.history[1].kind, FieldKind::Concealed);
    // The field's own rotation: same value as the imported entry above, but retired "now" rather
    // than at the source's own timestamp, and tied back to the field it came from.
    assert_eq!(
        item.history[2].value.as_secret().unwrap().expose(),
        b"hunter2"
    );
    assert_eq!(
        item.history[2].field_id,
        Some(item.field("password").unwrap().id)
    );
    assert_eq!(item.history[2].label, "password");

    // Same value, different moment: a real second retirement, not a duplicate.
    let mut third = acme("rotated-2026");
    third.push_revision(ImportedRevision::secret("hunter2".to_owned(), Some(300)));
    let outcome = commit(&mut vault, plan_of(vec![third]), DuplicatePolicy::Update).unwrap();
    assert_eq!(outcome.history_added, 1);
    assert_eq!(vault.items()[0].history.len(), 4);

    // And it never surfaces in metadata, on an item the user has made agent-visible.
    let item_id = vault.items()[0].id;
    vault
        .find_item_mut(&item_id.to_string())
        .unwrap()
        .agent_visible = true;
    let rendered = serde_json::to_string(&vault.item_summaries()).unwrap();
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("older-2019"), "{rendered}");
    assert!(!rendered.contains("history"), "{rendered}");
}

#[test]
fn keep_both_suffixes_the_title_with_the_import_date() {
    let (_dir, mut vault) = new_vault();
    commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();

    let outcome = commit(
        &mut vault,
        plan_of(vec![acme("rotated-2026")]),
        DuplicatePolicy::KeepBoth,
    )
    .unwrap();

    assert_eq!(outcome.kept_both, 1);
    assert_eq!(outcome.created, 0);
    assert_eq!(vault.items().len(), 2);

    let expected = format!(
        "Acme staging (imported {})",
        kagisecure_import::commit::iso_date(kagisecure_core::unix_now())
    );
    let titles: Vec<&str> = vault.items().iter().map(|i| i.title.as_str()).collect();
    assert!(titles.contains(&"Acme staging"), "{titles:?}");
    assert!(titles.contains(&expected.as_str()), "{titles:?}");

    // The original is untouched: keep-both is the policy for people who do not trust the import.
    let original = vault
        .items()
        .iter()
        .find(|i| i.title == "Acme staging")
        .unwrap();
    assert_eq!(
        original
            .field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        b"hunter2"
    );
}

#[test]
fn a_named_target_vault_is_created_once_and_reused_afterwards() {
    let (_dir, mut vault) = new_vault();

    let mut work = acme("hunter2");
    work.target_vault = TargetVault::Named("Work".to_owned());
    let mut other = ImportedItem::new("Bank", Category::Login);
    other.foreign_id = Some(ForeignId::onepassword("bank-uuid-0002"));
    other.target_vault = TargetVault::Named("Work".to_owned());

    let outcome = commit(
        &mut vault,
        plan_of(vec![work, other]),
        DuplicatePolicy::Skip,
    )
    .unwrap();
    assert_eq!(outcome.vaults_created, ["Work"]);
    assert_eq!(vault.vault_summaries().len(), 2);

    let work_id = vault.find_vault("Work").unwrap();
    assert!(vault.items().iter().all(|i| i.vault_id == work_id));
    // Default-deny travels with the new vault too.
    assert!(vault.vault_summaries().iter().all(|v| !v.agent_visible));

    // A second run finds the vault it made rather than making another.
    let mut again = acme("hunter2");
    again.target_vault = TargetVault::Named("Work".to_owned());
    let outcome = commit(&mut vault, plan_of(vec![again]), DuplicatePolicy::Skip).unwrap();
    assert!(outcome.vaults_created.is_empty());
    assert_eq!(vault.vault_summaries().len(), 2);
}

#[test]
fn retargeting_a_plan_collapses_every_source_vault_into_one() {
    let (_dir, mut vault) = new_vault();
    let mut personal = acme("hunter2");
    personal.target_vault = TargetVault::Named("Personal 1P".to_owned());
    let mut shared = ImportedItem::new("Shared thing", Category::Login);
    shared.target_vault = TargetVault::Named("Shared".to_owned());

    let mut plan = plan_of(vec![personal, shared]);
    plan.retarget_all(&TargetVault::Named("Personal".to_owned()));

    let outcome = commit(&mut vault, plan, DuplicatePolicy::Skip).unwrap();
    // "Personal" is what `cheap_options` named the vault the file was created with, so `--vault
    // Personal` must land in it rather than making a second one with the same name.
    assert!(outcome.vaults_created.is_empty(), "{outcome:?}");
    assert_eq!(vault.vault_summaries().len(), 1);
    assert_eq!(vault.items().len(), 2);
}

#[test]
fn the_preview_says_what_committing_would_do_without_doing_it() {
    let (_dir, mut vault) = new_vault();
    commit(
        &mut vault,
        plan_of(vec![acme("hunter2")]),
        DuplicatePolicy::Skip,
    )
    .unwrap();

    let plan = plan_of(vec![acme("rotated-2026"), {
        let mut fresh = ImportedItem::new("Brand new", Category::Login);
        fresh.foreign_id = Some(ForeignId::onepassword("new-uuid-0003"));
        fresh
    }]);

    let report = plan.report_against(&vault, DuplicatePolicy::Update);
    assert_eq!(report.action_count(ItemAction::Update), 1);
    assert_eq!(report.action_count(ItemAction::Create), 1);
    assert_eq!(report.totals.items, 2);
    // Reading a vault to build a preview must not change it.
    assert_eq!(vault.items().len(), 1);

    // And the resolution for one item on its own agrees with the report.
    let (action, existing) = resolve(&vault, &plan.items[0], DuplicatePolicy::Update);
    assert_eq!(action, ItemAction::Update);
    assert_eq!(existing, Some(find(&vault, "Acme staging")));
}

#[test]
fn a_committed_import_survives_a_save_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();

    let mut item = acme("hunter2");
    item.push_revision(ImportedRevision::secret("older-2019".to_owned(), Some(100)));
    item.target_vault = TargetVault::Named("Work".to_owned());
    commit(&mut vault, plan_of(vec![item]), DuplicatePolicy::Skip).unwrap();
    vault.save().unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.vault_summaries().len(), 2);
    let item = reopened.find_item("Acme staging").unwrap();
    assert_eq!(item.history.len(), 1);
    assert_eq!(
        item.history[0].value.as_secret().unwrap().expose(),
        b"older-2019"
    );
    assert_eq!(
        item.field("password").unwrap().value.as_secret().unwrap(),
        &Secret::from_string("hunter2".to_owned())
    );
    reopened.verify_audit().unwrap();
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

proptest::proptest! {
    /// The fingerprint is a function of the three metadata pieces and of nothing else, and the
    /// domain separator is what makes it one: no pair of different triples can be run together
    /// into the same byte string.
    #[test]
    fn the_fingerprint_is_stable_under_case_and_separated_across_fields(
        title in "[a-zA-Z0-9 .-]{0,24}",
        host in "[a-zA-Z0-9.-]{0,24}",
        username in "[a-zA-Z0-9@._-]{0,24}",
    ) {
        use kagisecure_import::dedupe::fingerprint;

        let lower = fingerprint(&title.to_lowercase(), Some(&host.to_lowercase()), Some(&username.to_lowercase()));
        let upper = fingerprint(&title.to_uppercase(), Some(&host.to_uppercase()), Some(&username.to_uppercase()));
        proptest::prop_assert_eq!(&lower, &upper);
        proptest::prop_assert_eq!(lower.len(), 64);

        // Moving a character across a boundary changes the fingerprint, so `("ab","")` and
        // `("a","b")` cannot be confused.
        if !host.is_empty() {
            let shifted = fingerprint(&format!("{title}{host}"), Some(""), Some(&username));
            proptest::prop_assert_ne!(
                fingerprint(&title, Some(&host), Some(&username)),
                shifted
            );
        }
    }

    /// A host extracted from a URL never contains a scheme, a path, a port or userinfo, whatever
    /// combination of those went in.
    #[test]
    fn url_hosts_never_keep_the_parts_around_them(
        scheme in "(https://|http://|)",
        user in "([a-z]{1,6}(:[a-z]{1,6})?@|)",
        host in "[a-z][a-z0-9-]{0,12}(\\.[a-z]{2,4}){0,2}",
        port in "(:[0-9]{1,5}|)",
        path in "(/[a-z/?=#-]{0,20}|)",
    ) {
        use kagisecure_import::dedupe::url_host;

        let extracted = url_host(&format!("{scheme}{user}{host}{port}{path}")).unwrap();
        proptest::prop_assert_eq!(&extracted, &host.to_lowercase());
        proptest::prop_assert!(!extracted.contains("://"));
        proptest::prop_assert!(!extracted.contains('@'));
        proptest::prop_assert!(!extracted.contains(':'));
        proptest::prop_assert!(!extracted.contains('/'));
    }
}

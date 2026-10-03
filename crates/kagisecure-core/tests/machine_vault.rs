//! The machine vault (ADR-0042 §2): its key in the personal vault's body, the file it opens, and
//! the structural rules every write of that file is held to.
//!
//! Each rule has a test that breaks it alone and finds the transaction refused with
//! `Error::MachineVault` and the file byte-for-byte unchanged.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::{PASSWORD, contains, new_vault};
use kagisecure_core::Error;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Category, Environment, Field, Item, Secret, VarSource};
use kagisecure_core::proto::{EnvId, FieldKind, ItemId, Outcome, VarName, VaultId};
use kagisecure_core::vault::machine::{
    CommandGrant, ExecutablePin, GrantId, GrantLimits, Job, JobId, LoginField, LoginGrant,
    MAX_GRANT_LIFETIME_SECS, MAX_RUN_DEADLINE_SECS, PinnedExecutable, PinnedFile, PresencePath,
    ScheduleTime, machine_vault_path,
};
use kagisecure_core::vault::{
    AUDIT_TOOL_MACHINE_VAULT_KEY_ADDED, AUDIT_TOOL_MACHINE_VAULT_KEY_REMOVED, DeviceKey,
    FileConflict, MachineVaultKey, Tx, Vault, device, header,
};

/// One way to break a record, applied to an otherwise valid one.
type Break<T> = Box<dyn Fn(&mut T)>;

const ACTOR: &str = "machine-vault-test";
const NOW: u64 = 1_790_000_000;
const SITE: &str = "https://service.example";
/// A value that must never appear outside the encrypted body.
const TOKEN: &str = "machine-token-canary-3e8d1f";
/// RFC 6238's test seed, in an `otpauth://` URI: public test data.
const OTP_URI: &str =
    "otpauth://totp/Service:bot?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Service";

fn format_ver_on_disk(path: &Path) -> u16 {
    let bytes = std::fs::read(path).unwrap();
    u16::from_le_bytes([bytes[8], bytes[9]])
}

/// A personal vault holding a machine vault key, and that machine vault, created empty.
struct Fixture {
    _dir: tempfile::TempDir,
    personal: Vault,
    personal_path: PathBuf,
    machine: Vault,
    machine_path: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (mut personal, _code, personal_path) = new_vault(dir.path());
    let key = MachineVaultKey::generate().unwrap();
    let machine_path = machine_vault_path(&personal_path);
    let machine = Vault::create_machine(&machine_path, &key, "Machine").unwrap();
    personal
        .transact(|tx| tx.set_machine_vault_key(key, ACTOR))
        .unwrap();
    Fixture {
        _dir: dir,
        personal,
        personal_path,
        machine,
        machine_path,
    }
}

fn exe(path: &str) -> PinnedExecutable {
    PinnedExecutable {
        path: path.to_owned(),
        pin: ExecutablePin::Sha256(vec![7; 32]),
    }
}

fn job(browser: bool) -> Job {
    Job {
        id: JobId::new(),
        name: "nightly deploy".to_owned(),
        root: exe("/usr/local/bin/agent"),
        args: vec!["--prompt".to_owned(), "/Users/me/jobs/deploy.md".to_owned()],
        working_dir: "/Users/me/src/app".to_owned(),
        schedule: vec![ScheduleTime::Daily {
            hour: 2,
            minute: 30,
        }],
        run_deadline_secs: 1800,
        catch_up_secs: 0,
        run_browser: browser.then(|| PinnedExecutable {
            path: "/Applications/Chromium.app/Contents/MacOS/Chromium".to_owned(),
            pin: ExecutablePin::CodeSigning {
                team_id: "TEAMID1234".to_owned(),
                signing_id: "org.chromium.Chromium".to_owned(),
            },
        }),
        created_at: NOW,
        presence: PresencePath::Confirmed,
        unknown: BTreeMap::new(),
    }
}

fn command_grant(job: JobId, env: EnvId) -> CommandGrant {
    CommandGrant {
        id: GrantId::new(),
        job,
        env,
        variables: vec!["DEPLOY_TOKEN".to_owned()],
        executable: exe("/usr/local/bin/deploy"),
        args: vec!["--prod".to_owned()],
        working_dir: "/Users/me/src/app".to_owned(),
        pinned_inputs: vec![PinnedFile {
            path: "/Users/me/src/app/deploy.toml".to_owned(),
            sha256: vec![9; 32],
        }],
        timeout_secs: 600,
        limits: GrantLimits::defaults(NOW),
        uses: 0,
        created_at: NOW,
        approved_at: NOW,
        presence: PresencePath::Confirmed,
        suspended: None,
        unknown: BTreeMap::new(),
    }
}

fn login_grant(job: JobId, item: ItemId) -> LoginGrant {
    LoginGrant {
        id: GrantId::new(),
        job,
        item,
        fields: vec![LoginField::Username, LoginField::Password],
        origin: SITE.to_owned(),
        follow_on_origins: vec!["https://id.service.example".to_owned()],
        one_time_codes: false,
        limits: GrantLimits::defaults(NOW),
        uses: 0,
        created_at: NOW,
        approved_at: NOW,
        presence: PresencePath::ConfirmedMasterPassword,
        suspended: None,
        unknown: BTreeMap::new(),
    }
}

/// Ids of what [`populate`] put in the machine vault.
#[derive(Clone, Copy)]
struct Ids {
    login: ItemId,
    token_item: ItemId,
    env: EnvId,
    command_job: JobId,
    login_job: JobId,
}

/// A machine vault with everything the rules allow: a Login item with a website and a
/// one-time-password field, an API credential, an environment bound to the credential, two jobs
/// and a grant of each kind.
fn populate(machine: &mut Vault) -> Ids {
    machine
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            let mut login = Item::new(vault_id, Category::Login, "Service bot");
            login.fields.push(Field::public("username", "bot"));
            login.fields.push(Field::concealed(
                "password",
                Secret::from_string("bot-password".to_owned()),
            ));
            login.fields.push(Field::totp(
                "one-time password",
                Secret::from_string(OTP_URI.to_owned()),
            ));
            login.urls.push(SITE.to_owned());
            let mut token = Item::new(vault_id, Category::ApiCredential, "Deploy token");
            token.fields.push(Field::concealed(
                "credential",
                Secret::from_string(TOKEN.to_owned()),
            ));
            let token_field = token.fields[0].id;
            let mut env = Environment::new(vault_id, "deploy");
            env.set_var(
                VarName::new("DEPLOY_TOKEN".to_owned()).unwrap(),
                VarSource::ItemField {
                    item: token.id,
                    field: token_field,
                },
            );
            env.set_var(
                VarName::new("REGION".to_owned()).unwrap(),
                VarSource::Literal(Secret::from_string("eu-1".to_owned())),
            );
            let ids = Ids {
                login: login.id,
                token_item: token.id,
                env: env.id,
                command_job: JobId::new(),
                login_job: JobId::new(),
            };
            tx.add_item(login);
            tx.add_item(token);
            tx.add_environment(env);
            let machine = tx.machine_mut()?;
            let mut command_job = job(false);
            command_job.id = ids.command_job;
            let mut login_job = job(true);
            login_job.id = ids.login_job;
            machine.jobs.push(command_job);
            machine.jobs.push(login_job);
            machine
                .command_grants
                .push(command_grant(ids.command_job, ids.env));
            machine
                .login_grants
                .push(login_grant(ids.login_job, ids.login));
            Ok(ids)
        })
        .unwrap()
}

/// Run `f` on the machine vault and require it refused by a structural rule, with the file
/// exactly as it was.
fn refused(machine: &mut Vault, f: impl FnOnce(&mut Tx<'_>) -> kagisecure_core::Result<()>) {
    let before = std::fs::read(machine.path()).unwrap();
    let result = machine.transact(f);
    assert!(matches!(result, Err(Error::MachineVault(_))), "{result:?}");
    assert_eq!(
        std::fs::read(machine.path()).unwrap(),
        before,
        "nothing was written"
    );
}

fn populated() -> (Fixture, Ids) {
    let mut f = fixture();
    let ids = populate(&mut f.machine);
    (f, ids)
}

// ---------------------------------------------------------------------------------------------
// The key in the personal vault
// ---------------------------------------------------------------------------------------------

#[test]
fn a_personal_vault_holding_a_machine_key_round_trips() {
    let f = fixture();
    let key = f.personal.machine_vault_key().unwrap();
    let keychain = key.to_keychain_bytes();
    assert_eq!(
        f.personal.format_ver(),
        header::MACHINE_VAULT_FORMAT_VERSION
    );
    assert_eq!(format_ver_on_disk(&f.personal_path), 3);
    assert!(
        f.personal.format_upgrade_backup().is_some(),
        "raising the personal file took the usual backup"
    );
    drop(f.personal);

    let reopened = Vault::open_with_password(&f.personal_path, PASSWORD).unwrap();
    let back = reopened.machine_vault_key().unwrap();
    assert_eq!(back.to_keychain_bytes().as_slice(), keychain.as_slice());
    assert!(!reopened.is_machine());
    assert!(reopened.items().is_empty(), "a machine key is not an item");

    // Neither the key nor any window of it is on disk in the clear, or in any Debug rendering.
    let secret = &keychain[16..];
    assert!(!contains(&std::fs::read(&f.personal_path).unwrap(), secret));
    let rendered = format!("{reopened:?} {back:?} {back:#?}");
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!rendered.contains(&hex), "{rendered}");

    // Its addition is audited by the machine vault's id alone.
    let entry = reopened
        .audit_entries()
        .iter()
        .find(|e| e.tool == AUDIT_TOOL_MACHINE_VAULT_KEY_ADDED)
        .unwrap();
    let id: String = keychain[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        entry.detail.as_deref(),
        Some(format!("vault_id={id}").as_str())
    );
    reopened.verify_audit().unwrap();

    // And the key opens the machine vault.
    let machine = Vault::open_machine(&f.machine_path, back).unwrap();
    assert!(machine.is_machine());
}

#[test]
fn a_second_machine_key_is_refused_and_removing_it_is_audited() {
    let mut f = fixture();
    refused(&mut f.personal, |tx| {
        tx.set_machine_vault_key(MachineVaultKey::generate()?, ACTOR)
    });
    let removed = f
        .personal
        .transact(|tx| Ok(tx.remove_machine_vault_key(ACTOR)))
        .unwrap();
    assert!(removed.is_some());
    assert!(f.personal.machine_vault_key().is_none());
    assert_eq!(
        f.personal.format_ver(),
        3,
        "removing the key does not lower the version"
    );
    assert!(
        f.personal
            .audit_entries()
            .iter()
            .any(|e| e.tool == AUDIT_TOOL_MACHINE_VAULT_KEY_REMOVED)
    );
}

#[test]
fn keeping_this_session_s_version_keeps_a_machine_key_only_the_file_has() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    let audited = |vault: &mut Vault, title: &str| {
        vault
            .transact(|tx| {
                tx.append_audit(AuditDraft {
                    actor: ACTOR.to_owned(),
                    tool: title.to_owned(),
                    outcome: Outcome::Allowed,
                    ..AuditDraft::default()
                });
                Ok(())
            })
            .unwrap();
    };
    audited(&mut session, "first");
    let older = std::fs::read(&path).unwrap();
    audited(&mut session, "only in the session");

    std::fs::write(&path, &older).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    let key = MachineVaultKey::generate().unwrap();
    let expected = key.to_keychain_bytes();
    other
        .transact(|tx| tx.set_machine_vault_key(key, ACTOR))
        .unwrap();
    drop(other);

    let conflict = session.examine_conflict().unwrap().unwrap();
    assert!(
        matches!(conflict, FileConflict::Diverged { .. }),
        "{conflict:?}"
    );
    session
        .overwrite_with_this_session(&conflict, ACTOR, "keep mine")
        .unwrap();

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(
        reopened
            .machine_vault_key()
            .unwrap()
            .to_keychain_bytes()
            .as_slice(),
        expected.as_slice()
    );
    assert_eq!(reopened.format_ver(), 3);
}

// ---------------------------------------------------------------------------------------------
// The machine vault file
// ---------------------------------------------------------------------------------------------

#[test]
fn the_machine_vault_opens_only_with_its_key_and_has_no_slot_of_its_own() {
    let f = fixture();
    let key = f.personal.machine_vault_key().unwrap();
    assert_eq!(format_ver_on_disk(&f.machine_path), 3);
    assert!(f.machine.header().wrapped_keys.is_empty());
    assert!(matches!(
        Vault::open_with_password(&f.machine_path, PASSWORD),
        Err(Error::NoSuchSlot(_))
    ));

    // From the Keychain's bytes, as after a restart while armed.
    let from_keychain = MachineVaultKey::from_keychain_bytes(&key.to_keychain_bytes()).unwrap();
    assert!(Vault::open_machine(&f.machine_path, &from_keychain).is_ok());

    // Another key does not open it; the right key under another id is not this vault's.
    let other = MachineVaultKey::generate().unwrap();
    assert!(matches!(
        Vault::open_machine(&f.machine_path, &other),
        Err(Error::Decrypt)
    ));
    let mut wrong_id = key.to_keychain_bytes().to_vec();
    wrong_id[0] ^= 1;
    let wrong_id = MachineVaultKey::from_keychain_bytes(&wrong_id).unwrap();
    assert!(matches!(
        Vault::open_machine(&f.machine_path, &wrong_id),
        Err(Error::MachineVault(_))
    ));

    // A personal vault opened "as a machine vault" with its own key and id is refused.
    let mut personal_as_machine = f.personal.header().vault_id.clone();
    personal_as_machine.extend_from_slice(&f.personal.export_vault_key_for_platform_wrapping());
    let personal_as_machine = MachineVaultKey::from_keychain_bytes(&personal_as_machine).unwrap();
    assert!(matches!(
        Vault::open_machine(&f.personal_path, &personal_as_machine),
        Err(Error::MachineVault(_))
    ));

    // A personal vault has no machine section to change.
    let mut personal = f.personal;
    let result = personal.transact(|tx| tx.machine_mut().map(|_| ()));
    assert!(matches!(result, Err(Error::MachineVault(_))), "{result:?}");
}

#[test]
fn a_populated_machine_vault_round_trips_and_releases_its_variables() {
    let (f, ids) = populated();
    let key = f.personal.machine_vault_key().unwrap();
    drop(f.machine);
    let machine = Vault::open_machine(&f.machine_path, key).unwrap();
    let section = machine.machine().unwrap();
    assert_eq!(section.jobs.len(), 2);
    assert_eq!(section.command_grants[0].env, ids.env);
    assert_eq!(section.login_grants[0].item, ids.login);
    assert_eq!(section.login_grants[0].origin, SITE);
    assert!(section.arm.is_none());

    let injected = machine.resolve_environment("deploy", None).unwrap();
    assert_eq!(injected[0].value.expose(), TOKEN.as_bytes());
    assert!(!contains(
        &std::fs::read(&f.machine_path).unwrap(),
        TOKEN.as_bytes()
    ));
    machine.verify_audit().unwrap();
}

#[test]
fn removing_a_job_takes_its_grants_with_it() {
    let (mut f, ids) = populated();
    f.machine
        .transact(|tx| {
            tx.machine_mut()?.remove_job(ids.login_job);
            Ok(())
        })
        .unwrap();
    let section = f.machine.machine().unwrap();
    assert!(section.login_grants.is_empty());
    assert_eq!(section.command_grants.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Rule 1: websites only as exact https origins, only on Login items
// ---------------------------------------------------------------------------------------------

#[test]
fn a_website_on_an_item_that_is_not_a_login_is_refused() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        let item = tx.item_by_id_mut(&ids.token_item).unwrap();
        item.urls.push("https://api.example".to_owned());
        Ok(())
    });
}

#[test]
fn a_website_that_is_not_an_exact_canonical_https_origin_is_refused() {
    for bad in [
        "http://service.example",
        "https://service.example/login",
        "https://service.example/",
        "https://Service.example",
        "https://service.example:443",
        "service.example",
        "https://*.example",
    ] {
        let (mut f, ids) = populated();
        refused(&mut f.machine, |tx| {
            tx.item_by_id_mut(&ids.login)
                .unwrap()
                .urls
                .push(bad.to_owned());
            Ok(())
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Rule 2: one-time passwords only on Login items, and never a variable
// ---------------------------------------------------------------------------------------------

#[test]
fn a_one_time_password_on_an_item_that_is_not_a_login_is_refused() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        tx.item_by_id_mut(&ids.token_item)
            .unwrap()
            .fields
            .push(Field::totp("otp", Secret::from_string(OTP_URI.to_owned())));
        Ok(())
    });
}

#[test]
fn a_variable_bound_to_a_one_time_password_seed_is_refused() {
    let (mut f, ids) = populated();
    let seed_field = f
        .machine
        .item_by_id(&ids.login)
        .unwrap()
        .fields
        .iter()
        .find(|field| field.kind == FieldKind::Totp)
        .unwrap()
        .id;
    refused(&mut f.machine, |tx| {
        tx.find_environment_mut("deploy")?.set_var(
            VarName::new("OTP_SEED".to_owned()).unwrap(),
            VarSource::ItemField {
                item: ids.login,
                field: seed_field,
            },
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------------------------
// Rule 3: no references out
// ---------------------------------------------------------------------------------------------

#[test]
fn a_variable_bound_to_an_item_outside_the_machine_vault_is_refused() {
    let (mut f, _ids) = populated();
    refused(&mut f.machine, |tx| {
        tx.find_environment_mut("deploy")?.set_var(
            VarName::new("PERSONAL".to_owned()).unwrap(),
            VarSource::ItemField {
                item: ItemId::new(),
                field: kagisecure_core::proto::FieldId::new(),
            },
        );
        Ok(())
    });
}

#[test]
fn removing_an_item_a_variable_is_bound_to_is_refused() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        tx.remove_item_by_id(&ids.token_item);
        Ok(())
    });
}

#[test]
fn an_item_or_environment_in_a_logical_vault_of_another_file_is_refused() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        tx.item_by_id_mut(&ids.token_item).unwrap().vault_id = VaultId::new();
        Ok(())
    });
    refused(&mut f.machine, |tx| {
        tx.find_environment_mut("deploy")?.vault_id = VaultId::new();
        Ok(())
    });
}

#[test]
fn a_reference_field_is_refused() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        let mut field = Field::public("see also", ItemId::new().to_string());
        field.kind = FieldKind::Reference;
        tx.item_by_id_mut(&ids.token_item)
            .unwrap()
            .fields
            .push(field);
        Ok(())
    });
}

#[test]
fn grants_and_jobs_naming_nothing_in_this_file_are_refused() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        let grant = command_grant(JobId::new(), ids.env);
        tx.machine_mut()?.command_grants.push(grant);
        Ok(())
    });
    refused(&mut f.machine, |tx| {
        let grant = command_grant(ids.command_job, EnvId::new());
        tx.machine_mut()?.command_grants.push(grant);
        Ok(())
    });
    refused(&mut f.machine, |tx| {
        let grant = login_grant(ids.login_job, ItemId::new());
        tx.machine_mut()?.login_grants.push(grant);
        Ok(())
    });
    // Removing the environment a grant names, without the grant.
    refused(&mut f.machine, |tx| {
        tx.remove_environment("deploy")?;
        Ok(())
    });
}

// ---------------------------------------------------------------------------------------------
// Rule 4: no keys inside a machine vault
// ---------------------------------------------------------------------------------------------

#[test]
fn a_machine_vault_holds_no_device_key_and_no_machine_key() {
    let (mut f, _ids) = populated();
    refused(&mut f.machine, |tx| {
        let key = DeviceKey::new(
            [3; device::DEVICE_KEY_ID_LEN],
            device::SUITE_X25519_ED25519_V1,
            "Laptop",
            NOW,
            Secret::new(vec![3; device::X25519_ED25519_V1_SECRET_LEN]),
        )?;
        tx.add_device_key(key, ACTOR)
    });
    refused(&mut f.machine, |tx| {
        tx.set_machine_vault_key(MachineVaultKey::generate()?, ACTOR)
    });
}

// ---------------------------------------------------------------------------------------------
// Rule 5: jobs and grants within their bounds
// ---------------------------------------------------------------------------------------------

#[test]
fn a_job_out_of_bounds_is_refused() {
    let breaks: Vec<Break<Job>> = vec![
        Box::new(|j| j.name = String::new()),
        Box::new(|j| j.root.path = "agent".to_owned()),
        Box::new(|j| j.root.path = "/usr/local/../bin/agent".to_owned()),
        Box::new(|j| j.root.pin = ExecutablePin::Sha256(vec![1; 31])),
        Box::new(|j| {
            j.root.pin = ExecutablePin::CodeSigning {
                team_id: String::new(),
                signing_id: "x".to_owned(),
            };
        }),
        Box::new(|j| j.working_dir = "src/app".to_owned()),
        Box::new(|j| j.schedule.clear()),
        Box::new(|j| {
            j.schedule = vec![ScheduleTime::Daily {
                hour: 24,
                minute: 0,
            }];
        }),
        Box::new(|j| j.run_deadline_secs = MAX_RUN_DEADLINE_SECS + 1),
        Box::new(|j| j.run_deadline_secs = 0),
        Box::new(|j| j.catch_up_secs = 24 * 60 * 60 + 1),
    ];
    for break_it in &breaks {
        let (mut f, ids) = populated();
        refused(&mut f.machine, |tx| {
            let machine = tx.machine_mut()?;
            let job = machine
                .jobs
                .iter_mut()
                .find(|j| j.id == ids.command_job)
                .unwrap();
            break_it(job);
            Ok(())
        });
    }
}

#[test]
fn a_command_grant_out_of_bounds_is_refused() {
    let breaks: Vec<Break<CommandGrant>> = vec![
        Box::new(|g| g.variables.clear()),
        Box::new(|g| g.variables.push("NOT_IN_THE_ENVIRONMENT".to_owned())),
        Box::new(|g| g.executable.path = "deploy".to_owned()),
        Box::new(|g| g.working_dir = "/Users/me/src/app/".to_owned()),
        Box::new(|g| g.pinned_inputs[0].sha256.truncate(16)),
        Box::new(|g| g.pinned_inputs[0].path = "deploy.toml".to_owned()),
        Box::new(|g| g.timeout_secs = 0),
        Box::new(|g| g.limits.per_run = 0),
        Box::new(|g| g.limits.total_uses = 0),
        Box::new(|g| g.limits.expires_at = g.created_at),
        Box::new(|g| g.limits.expires_at = g.created_at + MAX_GRANT_LIFETIME_SECS + 1),
    ];
    for break_it in &breaks {
        let (mut f, _ids) = populated();
        refused(&mut f.machine, |tx| {
            break_it(&mut tx.machine_mut()?.command_grants[0]);
            Ok(())
        });
    }
}

#[test]
fn two_grants_or_two_jobs_with_one_id_are_refused() {
    let (mut f, _ids) = populated();
    refused(&mut f.machine, |tx| {
        let machine = tx.machine_mut()?;
        machine.command_grants[0].id = machine.login_grants[0].id;
        Ok(())
    });
    refused(&mut f.machine, |tx| {
        let machine = tx.machine_mut()?;
        let mut twin = machine.jobs[0].clone();
        twin.name = "twin".to_owned();
        machine.jobs.push(twin);
        Ok(())
    });
}

#[test]
fn a_login_grant_out_of_bounds_is_refused() {
    let breaks: Vec<Break<LoginGrant>> = vec![
        // An origin that is not one of the item's websites, or not exact.
        Box::new(|g| g.origin = "https://other.example".to_owned()),
        Box::new(|g| g.origin = "https://service.example/".to_owned()),
        Box::new(|g| {
            g.follow_on_origins
                .push("https://id.example/login".to_owned())
        }),
        // Fields: none, twice, or a code with the switch off.
        Box::new(|g| g.fields.clear()),
        Box::new(|g| g.fields.push(LoginField::Password)),
        Box::new(|g| g.fields.push(LoginField::OneTimeCode)),
        Box::new(|g| g.limits.expires_at = g.created_at + MAX_GRANT_LIFETIME_SECS + 1),
    ];
    for break_it in &breaks {
        let (mut f, _ids) = populated();
        refused(&mut f.machine, |tx| {
            break_it(&mut tx.machine_mut()?.login_grants[0]);
            Ok(())
        });
    }
}

#[test]
fn a_one_time_code_is_granted_only_with_the_switch_on() {
    let (mut f, _ids) = populated();
    f.machine
        .transact(|tx| {
            let grant = &mut tx.machine_mut()?.login_grants[0];
            grant.one_time_codes = true;
            grant.fields.push(LoginField::OneTimeCode);
            Ok(())
        })
        .unwrap();
}

#[test]
fn a_login_grant_needs_a_job_with_a_run_browser_and_a_login_item() {
    let (mut f, ids) = populated();
    refused(&mut f.machine, |tx| {
        let grant = login_grant(ids.command_job, ids.login);
        tx.machine_mut()?.login_grants.push(grant);
        Ok(())
    });
    refused(&mut f.machine, |tx| {
        let grant = login_grant(ids.login_job, ids.token_item);
        tx.machine_mut()?.login_grants.push(grant);
        Ok(())
    });
    // Removing the website the grant names from the item.
    refused(&mut f.machine, |tx| {
        tx.item_by_id_mut(&ids.login).unwrap().urls.clear();
        Ok(())
    });
}

#[test]
fn a_personal_vault_is_not_held_to_the_machine_rules() {
    let dir = tempfile::tempdir().unwrap();
    let (mut personal, _code, _path) = new_vault(dir.path());
    personal
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            let mut note = Item::new(vault_id, Category::SecureNote, "note");
            note.urls.push("http://anything.example/path".to_owned());
            tx.add_item(note);
            Ok(())
        })
        .unwrap();
    assert_eq!(personal.format_ver(), 1);
}

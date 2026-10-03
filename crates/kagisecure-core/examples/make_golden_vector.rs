//! Writes the golden vault vectors used by `tests/vault.rs`.
//!
//! Golden vectors are added the day a `format_ver` is released and **never edited**
//! (vault-format §9 rule 5). This example exists so that adding the next one is a documented,
//! repeatable act rather than a one-off shell session; it refuses to overwrite an existing file.
//!
//! ```text
//! cargo run -p kagisecure-core --example make_golden_vector            # v1-argon2id-64k
//! cargo run -p kagisecure-core --example make_golden_vector v2-devices # v2-devices-argon2id-64k
//! cargo run -p kagisecure-core --example make_golden_vector v3-machine # the two below
//! ```
//!
//! `v3-machine` writes two files that belong together (ADR-0042 §2): `v3-machine-key-argon2id-64k`,
//! a personal vault at `format_ver` 3 holding a machine vault key, and `v3-machine-vault`, the
//! machine vault that key opens — no slot of its own; a Login item with a website and a
//! one-time-password field, an API credential, an environment bound to it, two jobs, a grant of
//! each kind and an arm record. The machine vault key is **public test data**:
//! [`TEST_MACHINE_KEYCHAIN_BYTES`], its `vault_id` then its key, as the Keychain would hold them.
//!
//! `v2-devices` is a `format_ver` 2 vault holding one shared-vault device key (ADR-0035 §5). Its
//! key material is **public test data, never a real key**: the X25519 secret key is Alice's from
//! RFC 7748 §6.1, and the Ed25519 seed is TEST 1's from RFC 8032 §7.1. Its id is the ADR-0035
//! addendum's device key id of their public keys,
//! `SHA-256("kagisecure/shared/device/v1" ‖ 0x00 ‖ "x25519-ed25519-v1" ‖ 0x00 ‖ kem_pk ‖ sig_pk)`,
//! computed outside this crate (which does no public-key cryptography) and written here as a
//! constant for `kagisecure-shared` to check against.

use std::collections::BTreeMap;
use std::path::Path;

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Category, Environment, Field, Item, Secret, VarSource};
use kagisecure_core::proto::VarName;
use kagisecure_core::vault::device::SUITE_X25519_ED25519_V1;
use kagisecure_core::vault::machine::{
    Arm, CommandGrant, ExecutablePin, GrantId, GrantLimits, Job, JobId, LoginField, LoginGrant,
    PinnedExecutable, PinnedFile, PresencePath, ScheduleTime, Weekday,
};
use kagisecure_core::vault::{CreateOptions, DeviceKey, MachineVaultKey, Vault};

const PASSWORD: &[u8] = b"golden vector password";

/// RFC 7748 §6.1, Alice's private key.
const TEST_X25519_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
/// RFC 8032 §7.1, TEST 1's secret key (the seed).
const TEST_ED25519_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// The device key id of the two keys' public halves (RFC 7748 Alice's public key
/// `8520f009…4e6a`, RFC 8032 TEST 1's public key `d75a9801…511a`).
const TEST_DEVICE_KEY_ID: &str = "1ccbda9a1b81bbf470d5ab39998783822db70612b841fca593e81d9222b05b8f";
/// The golden machine vault's `vault_id` (16 bytes) then its vault key (32 bytes). Test data.
const TEST_MACHINE_KEYCHAIN_BYTES: &str = "6d616368696e652d7661756c742d6964\
     000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// Fixed timestamps, so the records read back the same every time.
const T: u64 = 1_790_000_000;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let which = std::env::args().nth(1).unwrap_or_else(|| "v1".to_owned());
    let (file_name, with_device_key) = match which.as_str() {
        "v1" => ("v1-argon2id-64k.kagivault", false),
        "v2-devices" => ("v2-devices-argon2id-64k.kagivault", true),
        "v3-machine" => return machine_vectors(),
        other => {
            eprintln!("unknown vector {other:?}; expected v1, v2-devices or v3-machine");
            std::process::exit(2);
        }
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(file_name);
    if path.exists() {
        eprintln!(
            "{} already exists; refusing to overwrite it.",
            path.display()
        );
        std::process::exit(1);
    }
    std::fs::create_dir_all(path.parent().expect("vectors directory"))?;

    // Written in a scratch directory and copied in whole: raising a vault's `format_ver` leaves
    // a `.bak-1` copy beside it, which does not belong among the vectors.
    let scratch = std::env::temp_dir().join(format!(
        "kagisecure-golden-{}-{}",
        std::process::id(),
        kagisecure_core::unix_now()
    ));
    std::fs::create_dir_all(&scratch)?;
    let working = scratch.join(file_name);

    let options = CreateOptions {
        // Deliberately not the default profile: opening this file proves the reader takes its
        // parameters from the header.
        kdf: KdfParams::new(64, 1, 1)?,
        vault_name: "Golden".to_owned(),
        kdf_hint: Some("golden-vector".to_owned()),
    };
    let (mut vault, code) = Vault::create(&working, PASSWORD, &options)?;

    let mut item = Item::new(
        vault.default_vault_id()?,
        Category::ApiCredential,
        "Golden vector",
    );
    item.fields.push(Field::public("username", "vector"));
    item.fields.push(Field::concealed(
        "token",
        Secret::from_string("vector-token-value".to_owned()),
    ));
    item.tags.push("golden".to_owned());

    let device_key = if with_device_key {
        let mut secret_keys = hex(TEST_X25519_SECRET);
        secret_keys.extend(hex(TEST_ED25519_SEED));
        let id: [u8; 32] = hex(TEST_DEVICE_KEY_ID)
            .try_into()
            .expect("a device key id is 32 bytes");
        Some(DeviceKey::new(
            id,
            SUITE_X25519_ED25519_V1,
            "Golden vector device",
            1_790_000_000,
            Secret::new(secret_keys),
        )?)
    } else {
        None
    };

    vault.transact(|tx| {
        tx.add_item(item);
        if let Some(key) = device_key {
            tx.add_device_key(key, "golden-vector")?;
        }
        Ok(())
    })?;
    drop(vault);

    let bytes = std::fs::read(&working)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &bytes))?;
    std::fs::remove_dir_all(&scratch)?;

    println!("wrote {}", path.display());
    println!("password:      {}", String::from_utf8_lossy(PASSWORD));
    println!("recovery code: {}", *code.display());
    println!("This file is a test fixture. Its 'secrets' are public by construction.");
    Ok(())
}

fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Copy `from` to `to` with create-new semantics: a vector is never overwritten.
fn install(from: &Path, to: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(from)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &bytes))?;
    println!("wrote {}", to.display());
    Ok(())
}

fn exe(path: &str, sha: u8) -> PinnedExecutable {
    PinnedExecutable {
        path: path.to_owned(),
        pin: ExecutablePin::Sha256(vec![sha; 32]),
    }
}

/// `v3-machine-key-argon2id-64k.kagivault` and `v3-machine-vault.kagivault`.
fn machine_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let personal_target = vectors_dir().join("v3-machine-key-argon2id-64k.kagivault");
    let machine_target = vectors_dir().join("v3-machine-vault.kagivault");
    for target in [&personal_target, &machine_target] {
        if target.exists() {
            eprintln!(
                "{} already exists; refusing to overwrite it.",
                target.display()
            );
            std::process::exit(1);
        }
    }
    let scratch = std::env::temp_dir().join(format!(
        "kagisecure-golden-{}-{}",
        std::process::id(),
        kagisecure_core::unix_now()
    ));
    std::fs::create_dir_all(&scratch)?;
    let personal_path = scratch.join("personal.kagivault");
    let machine_path = scratch.join("machine.kagivault");
    let key = || MachineVaultKey::from_keychain_bytes(&hex(TEST_MACHINE_KEYCHAIN_BYTES));

    // The personal vault: a version 1 vault given the machine vault's key.
    let options = CreateOptions {
        kdf: KdfParams::new(64, 1, 1)?,
        vault_name: "Golden".to_owned(),
        kdf_hint: Some("golden-vector".to_owned()),
    };
    let (mut personal, code) = Vault::create(&personal_path, PASSWORD, &options)?;
    let machine_key = key()?;
    personal.transact(|tx| {
        let mut item = Item::new(
            tx.default_vault_id()?,
            Category::ApiCredential,
            "Golden vector",
        );
        item.fields.push(Field::public("username", "vector"));
        item.fields.push(Field::concealed(
            "token",
            Secret::from_string("vector-token-value".to_owned()),
        ));
        tx.add_item(item);
        tx.set_machine_vault_key(machine_key, "golden-vector")
    })?;
    drop(personal);

    // The machine vault.
    let mut machine = Vault::create_machine(&machine_path, &key()?, "Golden machine")?;
    machine.transact(|tx| {
        let vault_id = tx.default_vault_id()?;
        let mut login = Item::new(vault_id, Category::Login, "Golden service bot");
        login.fields.push(Field::public("username", "golden-bot"));
        login.fields.push(Field::concealed(
            "password",
            Secret::from_string("golden-bot-password".to_owned()),
        ));
        // RFC 6238's published test seed.
        login.fields.push(Field::totp(
            "one-time password",
            Secret::from_string(
                "otpauth://totp/Golden:bot?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Golden"
                    .to_owned(),
            ),
        ));
        login.urls.push("https://service.example".to_owned());
        login.created_at = T;
        login.updated_at = T;
        let mut token = Item::new(vault_id, Category::ApiCredential, "Golden deploy token");
        token.fields.push(Field::concealed(
            "credential",
            Secret::from_string("golden-deploy-token".to_owned()),
        ));
        token.created_at = T;
        token.updated_at = T;
        let mut env = Environment::new(vault_id, "golden deploy");
        env.set_var(
            VarName::new("DEPLOY_TOKEN".to_owned())?,
            VarSource::ItemField {
                item: token.id,
                field: token.fields[0].id,
            },
        );
        env.created_at = T;
        env.updated_at = T;

        let command_job = Job {
            id: JobId::new(),
            name: "Golden nightly deploy".to_owned(),
            root: exe("/usr/local/bin/golden-agent", 1),
            args: vec!["--prompt".to_owned(), "/opt/golden/deploy.md".to_owned()],
            working_dir: "/opt/golden".to_owned(),
            schedule: vec![
                ScheduleTime::Daily {
                    hour: 2,
                    minute: 30,
                },
                ScheduleTime::Weekly {
                    weekday: Weekday::Sunday,
                    hour: 12,
                    minute: 0,
                },
            ],
            run_deadline_secs: 1800,
            catch_up_secs: 900,
            run_browser: None,
            created_at: T,
            presence: PresencePath::Confirmed,
            unknown: BTreeMap::new(),
        };
        let login_job = Job {
            id: JobId::new(),
            name: "Golden sign-in".to_owned(),
            run_browser: Some(PinnedExecutable {
                path: "/Applications/Chromium.app/Contents/MacOS/Chromium".to_owned(),
                pin: ExecutablePin::CodeSigning {
                    team_id: "GOLDENTEAM".to_owned(),
                    signing_id: "org.chromium.Chromium".to_owned(),
                },
            }),
            ..command_job.clone()
        };
        let command_grant = CommandGrant {
            id: GrantId::new(),
            job: command_job.id,
            env: env.id,
            variables: vec!["DEPLOY_TOKEN".to_owned()],
            executable: exe("/usr/local/bin/golden-deploy", 2),
            args: vec!["--prod".to_owned()],
            working_dir: "/opt/golden".to_owned(),
            pinned_inputs: vec![PinnedFile {
                path: "/opt/golden/deploy.toml".to_owned(),
                sha256: vec![3; 32],
            }],
            timeout_secs: 600,
            limits: GrantLimits::defaults(T),
            uses: 4,
            created_at: T,
            approved_at: T,
            presence: PresencePath::Confirmed,
            suspended: None,
            unknown: BTreeMap::new(),
        };
        let login_grant = LoginGrant {
            id: GrantId::new(),
            job: login_job.id,
            item: login.id,
            fields: vec![
                LoginField::Username,
                LoginField::Password,
                LoginField::OneTimeCode,
            ],
            origin: "https://service.example".to_owned(),
            follow_on_origins: vec!["https://id.service.example".to_owned()],
            one_time_codes: true,
            limits: GrantLimits::defaults(T),
            uses: 0,
            created_at: T,
            approved_at: T,
            presence: PresencePath::ConfirmedMasterPassword,
            suspended: None,
            unknown: BTreeMap::new(),
        };
        tx.add_item(login);
        tx.add_item(token);
        tx.add_environment(env);
        let section = tx.machine_mut()?;
        section.jobs.push(command_job);
        section.jobs.push(login_job);
        section.command_grants.push(command_grant);
        section.login_grants.push(login_grant);
        section.arm = Some(Arm {
            armed_at: T,
            presence: PresencePath::Confirmed,
            unknown: BTreeMap::new(),
        });
        Ok(())
    })?;
    drop(machine);

    install(&personal_path, &personal_target)?;
    install(&machine_path, &machine_target)?;
    std::fs::remove_dir_all(&scratch)?;
    println!("password:      {}", String::from_utf8_lossy(PASSWORD));
    println!("recovery code: {}", *code.display());
    println!("These files are test fixtures. Their 'secrets' are public by construction.");
    Ok(())
}

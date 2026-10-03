//! End-to-end tests for `kagisecure shared ...`: three personal vaults in temporary directories,
//! each driven only through the CLI binary, creating, inviting, joining, writing and syncing a
//! shared vault through one exchange folder.
//!
//! Every invocation passes `--password-stdin`, so a prompted value — the master password, an
//! invitation passphrase, a concealed field's value — always comes from the next line of standard
//! input rather than a controlling terminal, and `--kdf-m-kib 64 --kdf-t 1` keeps Argon2id cheap.

use std::path::PathBuf;

use assert_cmd::Command;

const KDF_ARGS: [&str; 4] = ["--kdf-m-kib", "64", "--kdf-t", "1"];

/// One person's personal vault, in its own temporary directory.
struct Person {
    _dir: tempfile::TempDir,
    vault: PathBuf,
    password: String,
}

impl Person {
    fn new(name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("test.kagivault");
        Self {
            _dir: dir,
            vault,
            password: format!("correct horse battery staple {name}"),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("kagisecure").unwrap();
        cmd.arg("--vault").arg(&self.vault).arg("--password-stdin");
        cmd.env_remove("KAGISECURE_VAULT");
        cmd
    }

    /// Create the personal vault.
    fn init(&self) {
        self.cmd()
            .args(["vault", "init"])
            .args(KDF_ARGS)
            .write_stdin(format!("{}\n", self.password))
            .assert()
            .success();
    }

    /// Run a `kagisecure` subcommand after the password, with `extra_stdin` lines following it
    /// (already newline-terminated, or empty for none), and return its stdout.
    fn run(&self, args: &[&str], extra_stdin: &str) -> String {
        let out = self
            .cmd()
            .args(args)
            .write_stdin(format!("{}\n{extra_stdin}", self.password))
            .assert()
            .success();
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    }

    /// Like [`Self::run`], but asserting the given exit code instead of success.
    fn run_expect_code(&self, args: &[&str], extra_stdin: &str, code: i32) -> String {
        let out = self
            .cmd()
            .args(args)
            .write_stdin(format!("{}\n{extra_stdin}", self.password))
            .assert()
            .code(code);
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    }
}

/// The 36-character hyphenated UUID a line like `"Created shared vault <id>"` ends with.
fn last_word(output: &str, prefix: &str) -> String {
    output
        .lines()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no line starts with {prefix:?} in:\n{output}"))
        .trim()
        .to_owned()
}

/// The six-word passphrase `shared invite` prints once, indented on its own line.
fn passphrase_from(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .find(|l| {
            !l.is_empty()
                && l.split('-').count() == 6
                && l.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        })
        .unwrap_or_else(|| panic!("no passphrase-shaped line in:\n{output}"))
        .to_owned()
}

/// A device id line, `"Device <hex> added, unverified."`.
fn device_id_from(output: &str) -> String {
    output
        .lines()
        .find_map(|l| l.strip_prefix("Device "))
        .and_then(|l| l.strip_suffix(" added, unverified."))
        .unwrap_or_else(|| panic!("no device id line in:\n{output}"))
        .to_owned()
}

fn sync(people: &[&Person], vault: &str) {
    for person in people {
        person.run(&["shared", "sync", vault], "");
    }
}

#[test]
fn three_personal_vaults_create_invite_join_write_and_converge() {
    let exchange_dir = tempfile::tempdir().unwrap();
    let exchange = exchange_dir.path();

    let alice = Person::new("alice");
    let bob = Person::new("bob");
    let carol = Person::new("carol");
    alice.init();
    bob.init();
    carol.init();

    // Alice creates the shared vault.
    let created = alice.run(
        &[
            "shared",
            "create",
            "Household",
            "--dir",
            &exchange.display().to_string(),
        ],
        "",
    );
    let vault = last_word(&created, "Created shared vault ");
    assert_eq!(vault.len(), 36, "a hyphenated UUID: {vault:?}");

    // Alice invites Bob, and Bob joins from the file and the passphrase alone.
    let bob_invite = exchange.join("bob.kagisiv");
    let invited_bob = alice.run(
        &[
            "shared",
            "invite",
            &vault,
            "--name",
            "Bob's laptop",
            "--role",
            "writer",
            "--out",
            bob_invite.to_str().unwrap(),
        ],
        "",
    );
    let bob_passphrase = passphrase_from(&invited_bob);
    bob.run(
        &[
            "shared",
            "join",
            bob_invite.to_str().unwrap(),
            "--dir",
            &exchange.display().to_string(),
        ],
        &format!("{bob_passphrase}\n"),
    );

    // Alice invites Carol the same way.
    let carol_invite = exchange.join("carol.kagisiv");
    let invited_carol = alice.run(
        &[
            "shared",
            "invite",
            &vault,
            "--name",
            "Carol's desktop",
            "--role",
            "writer",
            "--out",
            carol_invite.to_str().unwrap(),
        ],
        "",
    );
    let carol_device = device_id_from(&invited_carol);
    let carol_passphrase = passphrase_from(&invited_carol);
    carol.run(
        &[
            "shared",
            "join",
            carol_invite.to_str().unwrap(),
            "--dir",
            &exchange.display().to_string(),
        ],
        &format!("{carol_passphrase}\n"),
    );

    // Alice and Bob each add an item; Carol syncs before either write reaches the folder, and
    // writes a rotation of Alice's item on top of what she has not seen yet.
    alice.run(
        &[
            "shared",
            "item",
            "add",
            &vault,
            "--title",
            "Database",
            "--secret",
            "password",
            "--value-stdin",
        ],
        "first\n",
    );
    bob.run(
        &[
            "shared",
            "item",
            "add",
            &vault,
            "--title",
            "Mail",
            "--secret",
            "password",
            "--value-stdin",
        ],
        "bobs\n",
    );
    sync(&[&carol], &vault);
    // Last-writer-wins is ordered by the author's claimed `created_at`, in whole seconds
    // (decision 80) — tied within the same second, the tie-break is by record id, not by which
    // write actually happened later. Crossing a second boundary here makes "the rotation wins"
    // below deterministic instead of a coin flip on a fast machine.
    std::thread::sleep(std::time::Duration::from_secs(2));
    carol.run(
        &[
            "shared",
            "item",
            "set",
            &vault,
            "Database",
            "--secret",
            "password",
            "--value-stdin",
        ],
        "rotated\n",
    );

    // Sync in two different orders, more than once: the state converges regardless.
    sync(&[&alice, &bob, &carol], &vault);
    sync(&[&carol, &bob, &alice], &vault);
    sync(&[&bob, &carol, &alice], &vault);

    let show = |person: &Person, title: &str| -> String {
        person.run(&["shared", "item", "show", &vault, title, "--reveal"], "")
    };
    let alice_db = show(&alice, "Database");
    let bob_db = show(&bob, "Database");
    let carol_db = show(&carol, "Database");
    assert_eq!(alice_db, bob_db, "Alice and Bob must see the same item");
    assert_eq!(alice_db, carol_db, "Alice and Carol must see the same item");
    assert!(
        alice_db.contains("rotated"),
        "the later-claimed rotation must win (decision 80):\n{alice_db}"
    );
    assert!(
        !alice_db.contains("first"),
        "the superseded value must be gone:\n{alice_db}"
    );

    let alice_mail = show(&alice, "Mail");
    assert!(alice_mail.contains("bobs"));

    // Remove Carol's device: a new epoch for Alice and Bob, and a value written afterwards is
    // unreadable to her.
    alice.run(
        &[
            "shared",
            "remove",
            &vault,
            "--device",
            &carol_device,
            "--reason",
            "left",
        ],
        "",
    );
    alice.run(
        &[
            "shared",
            "item",
            "add",
            &vault,
            "--title",
            "Payroll",
            "--secret",
            "password",
            "--value-stdin",
        ],
        "secret\n",
    );
    sync(&[&bob], &vault);
    sync(&[&carol], &vault);

    let payroll_for_bob = show(&bob, "Payroll");
    assert!(payroll_for_bob.contains("secret"));
    // Carol's replica has the record but cannot open it: `shared item show` reports it as any
    // other unresolved reference (`kagisecure_core::Error::ItemNotFound`, exit 6).
    carol.run_expect_code(&["shared", "item", "show", &vault, "Payroll"], "", 6);

    // Rotation list on Alice's side names Carol's device and at least the item(s) she could have
    // read before her removal.
    let rotation = alice.run(&["shared", "rotation-list", &vault, "--json"], "");
    let parsed: serde_json::Value = serde_json::from_str(&rotation).unwrap();
    let rows = parsed.as_array().expect("a JSON array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["device"], carol_device);

    // A damaged replica refuses to open; rebuilding it from the exchange folder recovers the same
    // state.
    let replica_dir = alice.vault.with_extension("kagivault.shared");
    let mut replica_files: Vec<PathBuf> = std::fs::read_dir(&replica_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("kagishared"))
        .collect();
    assert_eq!(
        replica_files.len(),
        1,
        "one replica beside Alice's personal vault"
    );
    let replica_file = replica_files.pop().unwrap();
    let mut bytes = std::fs::read(&replica_file).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&replica_file, &bytes).unwrap();

    alice.run_expect_code(&["shared", "item", "show", &vault, "Payroll"], "", 1);
    alice.run(
        &[
            "shared",
            "rebuild",
            &vault,
            "--from-dir",
            &exchange.display().to_string(),
        ],
        "",
    );
    let rebuilt = show(&alice, "Payroll");
    assert!(rebuilt.contains("secret"));
}

#[test]
fn a_vault_reference_that_matches_nothing_exits_6() {
    let alice = Person::new("solo");
    alice.init();
    alice.run_expect_code(&["shared", "status", "nonexistent"], "", 6);
}

#[test]
fn shared_env_add_var_binds_to_an_item_field_in_the_shared_vault() {
    let exchange_dir = tempfile::tempdir().unwrap();
    let exchange = exchange_dir.path();
    let alice = Person::new("env-alice");
    alice.init();
    let created = alice.run(
        &[
            "shared",
            "create",
            "Env test",
            "--dir",
            &exchange.display().to_string(),
        ],
        "",
    );
    let vault = last_word(&created, "Created shared vault ");

    alice.run(
        &[
            "shared",
            "item",
            "add",
            &vault,
            "--title",
            "API",
            "--secret",
            "token",
            "--value-stdin",
        ],
        "sk-test-123\n",
    );
    alice.run(&["shared", "env", "create", &vault, "staging"], "");
    alice.run(
        &[
            "shared",
            "env",
            "add-var",
            &vault,
            "--environment",
            "staging",
            "--name",
            "API_TOKEN",
            "--bind",
            "API/token",
        ],
        "",
    );
    let status = alice.run(&["shared", "status", &vault, "--json"], "");
    let parsed: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(parsed["members"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["devices"].as_array().unwrap().len(), 1);
}

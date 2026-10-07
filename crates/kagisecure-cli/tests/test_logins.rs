//! `kagisecure test-logins list | trash` (ADR-0048, Phase 3), driven through the binary against a
//! temporary vault whose test logins are sealed here, through the core, the way the agent seals
//! them.

use assert_cmd::Command;
use kagisecure_core::Vault;
use kagisecure_core::model::{Category, FieldValue, Item, Secret};
use kagisecure_core::proto::{ItemId, Outcome};
use predicates::str::contains;
use std::path::PathBuf;

const PASSWORD: &str = "correct horse battery staple";
/// A generated password stand-in. It must never reach stdout.
const CANARY: &str = "T3st-L0gin-Canary-9f1e2d3c4b5a";
const LOCAL: &str = "http://localhost:47800";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("test.kagivault");
        let fx = Self { _dir: dir, vault };
        fx.cmd()
            .args(["vault", "init", "--kdf-m-kib", "64", "--kdf-t", "1"])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success();
        fx
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("kagisecure").unwrap();
        cmd.arg("--vault").arg(&self.vault).arg("--password-stdin");
        cmd.env_remove("KAGISECURE_VAULT");
        cmd
    }

    fn run(&self, args: &[&str]) -> assert_cmd::assert::Assert {
        self.cmd()
            .args(args)
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
    }

    fn open(&self) -> Vault {
        Vault::open_with_password(&self.vault, PASSWORD.as_bytes()).unwrap()
    }

    /// A login in the test-login vault tagged `tag` at `website`, sealed when `sealed`.
    fn seed(&self, username: &str, tag: &str, website: &str, sealed: bool) -> ItemId {
        let mut vault = self.open();
        vault
            .transact(|tx| {
                let test_vault = tx.ensure_agent_test_vault("test")?;
                let mut item = Item::from_template(test_vault, Category::Login, username);
                let primary = item.primary_secret.unwrap();
                for field in &mut item.fields {
                    if field.id == primary {
                        field.value = FieldValue::Secret(Secret::from_string(CANARY.to_owned()));
                    } else if field.label == "username" {
                        field.value = FieldValue::Public(username.to_owned());
                    }
                }
                item.urls = vec![website.to_owned()];
                item.tags = vec!["agent-test".to_owned(), tag.to_owned()];
                item.set_agent_visible_all(true);
                if sealed {
                    tx.attach_test_login_provenance(&mut item, "mcp \"test\"", "shop", "buyer")?;
                }
                let id = item.id;
                tx.add_item(item);
                Ok(id)
            })
            .unwrap()
    }
}

#[test]
fn trash_needs_a_filter_and_a_website_must_be_a_url() {
    let fx = Fixture::new();
    fx.run(&["test-logins", "trash"]).failure().code(2);
    fx.run(&["test-logins", "trash", "--website", "not a url"])
        .failure()
        .code(2)
        .stderr(contains("--website"));
    fx.run(&["test-logins", "list", "--website", "ftp://x"])
        .failure()
        .code(2);
}

#[test]
fn list_shows_sealed_test_logins_only_and_never_a_password() {
    let fx = Fixture::new();
    fx.run(&["test-logins", "list"])
        .success()
        .stdout(contains("No agent test logins."));
    let shop = fx.seed("buyer1@example.test", "app:shop", LOCAL, true);
    fx.seed("writer@example.test", "app:blog", LOCAL, true);
    fx.seed("typed@example.test", "app:shop", LOCAL, false);

    let out = fx
        .run(&["test-logins", "list", "--tag", "app:shop", "--json"])
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(CANARY));
    let listed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1, "{stdout}");
    assert_eq!(listed[0]["item_id"], shop.to_string());
    assert_eq!(listed[0]["username"], "buyer1@example.test");

    let out = fx
        .run(&["test-logins", "list", "--website", LOCAL])
        .success();
    let table = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(table.contains("buyer1@example.test") && table.contains("writer@example.test"));
    assert!(!table.contains("typed@example.test"), "unsealed: {table}");
    assert!(!table.contains(CANARY));
}

#[test]
fn trash_moves_matching_sealed_logins_to_the_trash_in_one_audited_step() {
    let fx = Fixture::new();
    let shop = fx.seed("buyer1@example.test", "app:shop", LOCAL, true);
    // The person's own trash is not limited to the allowed origins.
    let partner = fx.seed(
        "buyer2@example.test",
        "app:shop",
        "https://staging.example-partner.com",
        true,
    );
    let blog = fx.seed("writer@example.test", "app:blog", LOCAL, true);
    let unsealed = fx.seed("typed@example.test", "app:shop", LOCAL, false);

    fx.run(&["test-logins", "trash", "--tag", "app:shop"])
        .success()
        .stdout(contains("Moved 2 test login(s) to the trash."))
        .stdout(contains(shop.to_string()));

    let vault = fx.open();
    let trashed = |id: &ItemId| vault.item_by_id(id).unwrap().is_trashed();
    assert!(trashed(&shop) && trashed(&partner));
    assert!(!trashed(&blog), "another tag");
    assert!(!trashed(&unsealed), "unsealed items are never touched");

    let entries: Vec<_> = vault
        .audit_entries()
        .iter()
        .filter(|e| e.tool == "trash_test_logins")
        .cloned()
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].actor, "cli");
    assert_eq!(entries[0].outcome, Outcome::Allowed);
    assert_eq!(
        entries[0].detail.as_deref(),
        Some("TEST_LOGINS_TRASHED matched=2")
    );

    // Both filters together narrow further; nothing left to match is still a success.
    fx.run(&[
        "test-logins",
        "trash",
        "--tag",
        "app:blog",
        "--website",
        "http://other.test",
    ])
    .success()
    .stdout(contains("Moved 0 test login(s)"));
}

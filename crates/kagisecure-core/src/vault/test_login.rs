//! Agent test logins: the dedicated vault, its policy, and the seal
//! ([ADR-0048](../../../../docs/decisions/0048-agent-test-logins.md) §1, §2, §5).
//!
//! # The seal
//!
//! kagisecure generates a test login's password itself, inside the transaction that writes the
//! item, and seals it there: HMAC-SHA256 under a key derived from the vault key with
//! [`SEAL_INFO`] — the way the body key is derived — over the item id, the primary-secret field id
//! and the password bytes. The seal is stored with the item's provenance in
//! `Item.extra["agent_test_login"]` ([`TestLoginProvenance`]).
//!
//! An item whose seal verifies is **sealed**, and only a sealed item takes ADR-0048's no-sheet
//! paths. Editing, replacing or moving the password stops it verifying, and the item is ordinary
//! from then on: nobody who cannot derive the vault key can forge a seal for a value of their
//! choosing, so a person's real password typed into a test item never inherits an exemption.
//!
//! The seal is a MAC, not secret material: it is stored in `extra`, which is printable, and that
//! is fine — it reveals nothing about the password to anyone without the vault key. The password
//! bytes are read here, in this crate, and nowhere a caller could see them.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{Tx, Vault};
use crate::audit::AuditDraft;
use crate::crypto::{self, KEY_LEN};
use crate::error::{Error, Result};
use crate::model::{Item, TestLoginPolicy, VaultMeta, VaultPurpose};
use crate::proto::{Outcome, VaultId};

/// HKDF-SHA256 `info` for the seal key: domain-separated from the body key and every other
/// subkey of the vault key.
pub const SEAL_INFO: &[u8] = b"kagisecure/agent-test-login-seal/v1";

/// The `Item.extra` key a test login's provenance and seal live under.
pub const EXTRA_KEY: &str = "agent_test_login";

/// The provenance format version written today.
pub const PROVENANCE_VERSION: u64 = 1;

/// The name the test-login vault is created with. The person may rename it; it is found by
/// [`VaultMeta::purpose`], never by this.
pub const TEST_VAULT_NAME: &str = "Agent test logins";

/// The `tool` of the audit entry [`Tx::ensure_agent_test_vault`] records when it creates the vault.
pub const AUDIT_TOOL_TEST_VAULT_CREATED: &str = "agent_test_vault_created";

/// The `tool` of the audit entry [`Tx::set_test_login_policy`] records.
pub const AUDIT_TOOL_TEST_LOGIN_POLICY: &str = "agent_test_login_policy";

/// Who created a test login, when, for which app and purpose, and the seal over its password.
///
/// Metadata only. The seal is a MAC under a vault-derived key; it says nothing about the
/// password to anyone who cannot derive that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestLoginProvenance {
    /// [`PROVENANCE_VERSION`].
    pub v: u64,
    /// HMAC-SHA256 over the item id, the primary-secret field id and the password bytes.
    pub seal: [u8; 32],
    /// The agent that asked, as the audit log names it (ADR-0048 §10).
    pub created_by: String,
    /// Unix seconds.
    pub created_at: u64,
    /// The app under test, as the agent named it.
    pub app: String,
    /// The test user's purpose, as the agent named it.
    pub purpose: String,
}

impl TestLoginProvenance {
    /// The CBOR map stored in `Item.extra`.
    #[must_use]
    pub fn to_value(&self) -> ciborium::Value {
        use ciborium::Value;
        Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(self.v.into())),
            (Value::Text("seal".into()), Value::Bytes(self.seal.to_vec())),
            (
                Value::Text("created_by".into()),
                Value::Text(self.created_by.clone()),
            ),
            (
                Value::Text("created_at".into()),
                Value::Integer(self.created_at.into()),
            ),
            (Value::Text("app".into()), Value::Text(self.app.clone())),
            (
                Value::Text("purpose".into()),
                Value::Text(self.purpose.clone()),
            ),
        ])
    }

    /// Read the provenance back from an item, if it has a well-formed one.
    #[must_use]
    pub fn of(item: &Item) -> Option<Self> {
        let map = item.extra.get(EXTRA_KEY)?.as_map()?;
        let get = |key: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v)
        };
        let int = |key: &str| -> Option<u64> { u64::try_from(get(key)?.as_integer()?).ok() };
        let text = |key: &str| get(key)?.as_text().map(str::to_owned);
        let seal: [u8; 32] = get("seal")?.as_bytes()?.as_slice().try_into().ok()?;
        Some(Self {
            v: int("v")?,
            seal,
            created_by: text("created_by")?,
            created_at: int("created_at")?,
            app: text("app")?,
            purpose: text("purpose")?,
        })
    }
}

/// The seal over `item`'s current password under `vault_key`, or `None` when it has no primary
/// secret with a value.
fn seal_of(vault_key: &[u8; KEY_LEN], item: &Item) -> Option<[u8; 32]> {
    let field = item.primary_secret_field()?;
    let password = field.value.as_secret()?.expose();
    if password.is_empty() {
        return None;
    }
    let key = crypto::derive_subkey(vault_key, SEAL_INFO);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_slice())
        .expect("HMAC accepts a key of any length");
    // Both ids are canonical, fixed-length strings, so the concatenation is unambiguous.
    mac.update(item.id.to_string().as_bytes());
    mac.update(field.id.to_string().as_bytes());
    mac.update(password);
    Some(mac.finalize().into_bytes().into())
}

impl Vault {
    /// The agent test-login vault (ADR-0048 §2), found by its purpose — never by its name.
    #[must_use]
    pub fn agent_test_vault(&self) -> Option<&VaultMeta> {
        self.body
            .vaults
            .iter()
            .find(|v| v.test_login_policy().is_some())
    }

    /// The test-login policy and the vault it governs, when there is a test-login vault.
    #[must_use]
    pub fn test_login_policy(&self) -> Option<(VaultId, &TestLoginPolicy)> {
        self.agent_test_vault()
            .and_then(|v| v.test_login_policy().map(|p| (v.id, p)))
    }

    /// Whether `item` is in the agent test-login vault — sealed or not.
    #[must_use]
    pub fn in_agent_test_vault(&self, item: &Item) -> bool {
        self.agent_test_vault()
            .is_some_and(|v| v.id == item.vault_id)
    }

    /// Whether `item` is a **sealed** test login (ADR-0048 §5): in the test-login vault, with
    /// provenance whose seal matches its password as it is now. Compared in constant time.
    #[must_use]
    pub fn test_login_sealed(&self, item: &Item) -> bool {
        if !self.in_agent_test_vault(item) {
            return false;
        }
        let Some(provenance) = TestLoginProvenance::of(item) else {
            return false;
        };
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        seal_of(vk, item).is_some_and(|seal| crypto::keys_equal(&seal, &provenance.seal))
    }
}

impl Tx<'_> {
    /// The seal over `item`'s password as it is now (ADR-0048 §5).
    ///
    /// # Errors
    ///
    /// [`Error::NotASecret`] when the item has no primary secret with a value to seal.
    pub fn seal_test_login(&self, item: &Item) -> Result<[u8; 32]> {
        let vk: &[u8; KEY_LEN] = &self.vault.vault_key;
        seal_of(vk, item).ok_or_else(|| Error::NotASecret(item.id.to_string()))
    }

    /// Seal `item` and record its provenance in `Item.extra["agent_test_login"]`.
    ///
    /// # Errors
    ///
    /// As [`Self::seal_test_login`].
    pub fn attach_test_login_provenance(
        &self,
        item: &mut Item,
        created_by: &str,
        app: &str,
        purpose: &str,
    ) -> Result<TestLoginProvenance> {
        let provenance = TestLoginProvenance {
            v: PROVENANCE_VERSION,
            seal: self.seal_test_login(item)?,
            created_by: created_by.to_owned(),
            created_at: item.created_at,
            app: app.to_owned(),
            purpose: purpose.to_owned(),
        };
        item.extra
            .insert(EXTRA_KEY.to_owned(), provenance.to_value());
        Ok(provenance)
    }

    /// The agent test-login vault, created if there is none (ADR-0048 §1, §2): agent-visible,
    /// showing new items to agents, with the policy off and no allowed domains. Its creation is
    /// recorded as [`AUDIT_TOOL_TEST_VAULT_CREATED`]; finding an existing one records nothing.
    ///
    /// # Errors
    ///
    /// [`Error::MachineVault`] in a machine vault, which holds no personal vaults.
    pub fn ensure_agent_test_vault(&mut self, actor: &str) -> Result<VaultId> {
        if self.vault.is_machine() {
            return Err(Error::MachineVault(
                "a machine vault holds no agent test logins",
            ));
        }
        if let Some(existing) = self.vault.agent_test_vault() {
            return Ok(existing.id);
        }
        let mut meta = VaultMeta::new(TEST_VAULT_NAME);
        meta.agent_visible = true;
        meta.new_items_agent_visible = true;
        meta.purpose = Some(VaultPurpose::AgentTestLogins(TestLoginPolicy::default()));
        let id = self.add_logical_vault(meta);
        self.append_audit(AuditDraft {
            actor: actor.to_owned(),
            tool: AUDIT_TOOL_TEST_VAULT_CREATED.to_owned(),
            vault_id: Some(id),
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        });
        Ok(id)
    }

    /// Replace the test-login policy, and record the change as [`AUDIT_TOOL_TEST_LOGIN_POLICY`]
    /// with detail `enabled=<on|off> domains=<n>` — counts only, never a domain.
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] when there is no test-login vault; call
    /// [`Self::ensure_agent_test_vault`] first.
    pub fn set_test_login_policy(&mut self, policy: TestLoginPolicy, actor: &str) -> Result<()> {
        let detail = format!(
            "enabled={} domains={}",
            if policy.enabled { "on" } else { "off" },
            policy.auto_domains.len()
        );
        let meta = self
            .vault
            .body
            .vaults
            .iter_mut()
            .find(|v| v.test_login_policy().is_some())
            .ok_or_else(|| Error::ItemNotFound(TEST_VAULT_NAME.to_owned()))?;
        let id = meta.id;
        meta.purpose = Some(VaultPurpose::AgentTestLogins(policy));
        self.append_audit(AuditDraft {
            actor: actor.to_owned(),
            tool: AUDIT_TOOL_TEST_LOGIN_POLICY.to_owned(),
            vault_id: Some(id),
            outcome: Outcome::Allowed,
            detail: Some(detail),
            ..AuditDraft::default()
        });
        Ok(())
    }
}

//! Opening, creating and saving vault files (vault-format §2, §3, §9).

pub mod header;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit::{self, AuditDraft, AuditEntry};
use crate::crypto::kdf::KdfParams;
use crate::crypto::wrap::{self, WrappedKey};
use crate::crypto::{self, KEY_LEN, Key, aead};
use crate::error::{Error, Result};
use crate::model::{Environment, FieldKind, Item, VaultMeta};
use crate::proto::{EnvironmentSummary, ItemSummary, VaultId, VaultSummary};
use crate::recovery::RecoveryCode;
use header::Header;

/// The body schema version this build writes.
pub const BODY_SCHEMA_VERSION: u16 = 1;
/// Slot id of the master-password slot.
pub const SLOT_ID_MASTER: &str = "master";
/// Slot id of the recovery slot.
pub const SLOT_ID_RECOVERY: &str = "recovery";

/// The decrypted vault body (vault-format §2.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct Body {
    /// Body schema version.
    pub schema: u16,
    /// Logical vaults inside this file.
    pub vaults: Vec<VaultMeta>,
    /// Items.
    pub items: Vec<Item>,
    /// Environments (vault-format §5.2).
    ///
    /// M1 reserved this key and carried it as raw CBOR; M2 gives it a type. An M1-era vault has
    /// an empty array here, which decodes unchanged.
    #[serde(default)]
    pub envs: Vec<Environment>,
    /// The append-only audit log (vault-format §8).
    ///
    /// The format doc names `audit_head` but not the array it summarises; this key is the
    /// minimal viable choice and is recorded in ADR-0007.
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
    /// Head of the audit hash chain (vault-format §8). 32 zero bytes for an empty log.
    #[serde(default, with = "serde_bytes")]
    pub audit_head: Vec<u8>,
}

impl Body {
    fn new(default_vault: VaultMeta) -> Self {
        Self {
            schema: BODY_SCHEMA_VERSION,
            vaults: vec![default_vault],
            items: Vec::new(),
            envs: Vec::new(),
            audit: Vec::new(),
            audit_head: audit::genesis(),
        }
    }
}

/// How a vault was unlocked. Recorded so callers can require a fresh master password after a
/// recovery-code unlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockedBy {
    /// The master password.
    Password,
    /// The printable recovery code.
    RecoveryCode,
    /// A platform keystore slot — Touch ID / Secure Enclave on macOS (ADR-0004).
    PlatformKey,
}

/// Options for [`Vault::create`].
#[derive(Clone, Debug)]
pub struct CreateOptions {
    /// KDF cost for the master-password slot.
    pub kdf: KdfParams,
    /// Display name of the first logical vault.
    pub vault_name: String,
    /// Optional human note stored in the header.
    pub kdf_hint: Option<String>,
}

impl CreateOptions {
    /// Defaults: the v1 desktop Argon2id profile and a logical vault called `Personal`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn new() -> Result<Self> {
        Ok(Self {
            kdf: KdfParams::defaults()?,
            vault_name: "Personal".to_owned(),
            kdf_hint: None,
        })
    }
}

/// An unlocked vault.
///
/// Holds the vault key for its lifetime and zeroizes it on drop. There is no decrypted-item cache
/// beyond the body itself (threat-model M-10); dropping this value is the "lock" operation.
pub struct Vault {
    path: PathBuf,
    header: Header,
    vault_key: Key,
    body: Body,
    unlocked_by: UnlockedBy,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("items", &self.body.items.len())
            .field("unlocked_by", &self.unlocked_by)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a new vault file and return it together with its one-time recovery code.
    ///
    /// The recovery code is generated here, printed once by the caller and never stored: only its
    /// Argon2id-stretched wrap of the vault key goes into the header (vault-format §3.2).
    ///
    /// # Errors
    ///
    /// [`Error::VaultExists`] if the path is taken, plus any I/O, RNG or KDF failure.
    pub fn create(
        path: impl Into<PathBuf>,
        master_password: &[u8],
        options: &CreateOptions,
    ) -> Result<(Self, RecoveryCode)> {
        let path = path.into();
        if path.exists() {
            return Err(Error::VaultExists(path));
        }

        options.kdf.validate()?;
        let vault_id = crypto::random::array::<16>()?;
        let vault_key = crypto::random::key()?;

        let password_kdf = options.kdf.clone();
        let kek = password_kdf.derive(master_password)?;
        let password_slot = WrappedKey::wrap(
            &vault_id,
            wrap::KIND_PASSWORD,
            SLOT_ID_MASTER,
            "Master password",
            &kek,
            &vault_key,
            None,
        )?;
        drop(kek);

        let code = RecoveryCode::generate()?;
        let recovery_slot = wrap_recovery_slot(&vault_id, &code, &options.kdf, &vault_key)?;

        let header = Header {
            v: header::HEADER_SCHEMA_VERSION,
            vault_id: vault_id.to_vec(),
            created_at: crate::unix_now(),
            kdf: password_kdf,
            body_aead: aead::ALG_XCHACHA20POLY1305.to_owned(),
            wrapped_keys: vec![password_slot, recovery_slot],
            compression: header::COMPRESSION_NONE.to_owned(),
            kdf_hint: options.kdf_hint.clone(),
        };

        let vault = Self {
            path,
            header,
            vault_key,
            body: Body::new(VaultMeta::new(options.vault_name.clone())),
            unlocked_by: UnlockedBy::Password,
        };
        vault.save()?;
        Ok((vault, code))
    }

    /// Open a vault with the master password.
    ///
    /// # Errors
    ///
    /// [`Error::VaultNotFound`], [`Error::Decrypt`] for a wrong password or a tampered file, and
    /// the header-validation errors. A wrong password and a tampered file are deliberately
    /// indistinguishable (threat-model M-8).
    pub fn open_with_password(path: impl Into<PathBuf>, master_password: &[u8]) -> Result<Self> {
        Self::open(
            path,
            wrap::KIND_PASSWORD,
            master_password,
            UnlockedBy::Password,
        )
    }

    /// Open a vault with its printable recovery code, independent of the master password.
    ///
    /// # Errors
    ///
    /// As [`Vault::open_with_password`], plus [`Error::NoSuchSlot`] if the file predates recovery
    /// codes.
    pub fn open_with_recovery_code(path: impl Into<PathBuf>, code: &RecoveryCode) -> Result<Self> {
        Self::open(
            path,
            wrap::KIND_RECOVERY,
            code.material(),
            UnlockedBy::RecoveryCode,
        )
    }

    /// Open a vault with a vault key that a platform keystore has already unwrapped.
    ///
    /// This is the second half of the Touch ID path (ADR-0004, ADR-0008): the app asks the Secure
    /// Enclave to decrypt the [`platform slot`](crate::crypto::wrap::KIND_PLATFORM)'s blob, and
    /// hands the 32 bytes that come back straight here. The bytes are copied into a
    /// [`Zeroizing`] buffer on entry and the caller's copy is its own to clear.
    ///
    /// There is no separate "is this the right key" check and none is needed: a wrong key fails
    /// to open the body, exactly as a wrong password does, and is reported the same way
    /// ([`Error::Decrypt`]) so the two are indistinguishable (threat-model M-8).
    ///
    /// # Errors
    ///
    /// [`Error::VaultNotFound`], [`Error::Malformed`] if `vault_key` is not 32 bytes,
    /// [`Error::Decrypt`] for a key that does not open this vault, plus the header-validation
    /// errors.
    pub fn open_with_vault_key(path: impl Into<PathBuf>, vault_key: &[u8]) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Err(Error::VaultNotFound(path));
        }
        let key: [u8; KEY_LEN] = vault_key.try_into().map_err(|_| Error::Malformed)?;
        let vault_key = Zeroizing::new(key);

        let file = std::fs::read(&path)?;
        let parts = header::split(&file)?;
        let header = parts.header;
        header.validate()?;

        let vk: &[u8; KEY_LEN] = &vault_key;
        let body = decrypt_body(vk, &parts.body_nonce, parts.aad, parts.body_ct)?;
        Ok(Self {
            path,
            header,
            vault_key,
            body,
            unlocked_by: UnlockedBy::PlatformKey,
        })
    }

    fn open(
        path: impl Into<PathBuf>,
        kind: &'static str,
        secret: &[u8],
        unlocked_by: UnlockedBy,
    ) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Err(Error::VaultNotFound(path));
        }
        let file = std::fs::read(&path)?;
        let parts = header::split(&file)?;
        let header = parts.header;
        header.validate()?;

        let slot = header.slot(kind).ok_or(Error::NoSuchSlot(kind))?;
        // Parameters come from the file, never from a hardcoded profile (roadmap M1).
        let kek = slot.effective_kdf(&header.kdf).derive(secret)?;
        let vault_key = slot.unwrap_with_kek(&header.vault_id, &kek)?;
        drop(kek);

        let vk: &[u8; KEY_LEN] = &vault_key;
        let body = decrypt_body(vk, &parts.body_nonce, parts.aad, parts.body_ct)?;

        Ok(Self {
            path,
            header,
            vault_key,
            body,
            unlocked_by,
        })
    }

    /// Write the vault back to disk atomically, mode `0600` on Unix (threat-model M-13).
    ///
    /// # Errors
    ///
    /// Any I/O or RNG failure. On failure the existing file is left untouched: the new contents
    /// are written to a temporary file in the same directory and renamed into place only once
    /// they are complete and flushed.
    pub fn save(&self) -> Result<()> {
        let header_cbor = self.header.to_cbor()?;
        let framed = header::framed(&header_cbor);

        let mut plaintext = Zeroizing::new(Vec::new());
        ciborium::into_writer(&self.body, &mut *plaintext)
            .map_err(|e| Error::BodyDecode(e.to_string()))?;

        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let body_key = crypto::body_key(vk);
        let nonce = aead::nonce()?;
        let ciphertext = aead::seal(&body_key, &nonce, &framed, &plaintext)?;

        let mut out = framed;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        write_atomically(&self.path, &out)
    }

    /// Where this vault lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How this vault was unlocked.
    #[must_use]
    pub fn unlocked_by(&self) -> UnlockedBy {
        self.unlocked_by
    }

    /// The header, for inspection. Contains no plaintext key material.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The id of the first logical vault, which is where the CLI puts new items.
    ///
    /// # Errors
    ///
    /// [`Error::BodyDecode`] if the body somehow contains no logical vault.
    pub fn default_vault_id(&self) -> Result<VaultId> {
        self.body
            .vaults
            .first()
            .map(|v| v.id)
            .ok_or_else(|| Error::BodyDecode("vault body has no logical vaults".to_owned()))
    }

    /// Metadata for every logical vault.
    #[must_use]
    pub fn vault_summaries(&self) -> Vec<VaultSummary> {
        self.body
            .vaults
            .iter()
            .map(|v| {
                let items = self
                    .body
                    .items
                    .iter()
                    .filter(|i| i.vault_id == v.id)
                    .count();
                let envs = self.body.envs.iter().filter(|e| e.vault_id == v.id).count();
                v.summary(items, envs)
            })
            .collect()
    }

    /// Set a logical vault's agent visibility, reporting whether the vault was found.
    ///
    /// Default-deny is the product's position (threat-model M-9); this is how a user opts in.
    pub fn set_vault_agent_visible(&mut self, id: VaultId, visible: bool) -> bool {
        match self.body.vaults.iter_mut().find(|v| v.id == id) {
            Some(v) => {
                v.agent_visible = visible;
                true
            }
            None => false,
        }
    }

    /// Add a logical vault, returning its id.
    ///
    /// [`VaultMeta::new`] has always existed with nothing to hand the result to; import needs to
    /// recreate a source's vault layout, so this is the missing half. Like [`Vault::add_item`] it
    /// only touches the in-memory body — call [`Vault::save`] afterwards.
    ///
    /// The name is not checked for uniqueness: [`Vault::find_vault`] already reports a duplicate
    /// as [`Error::AmbiguousItem`] rather than silently picking one, and refusing the second
    /// "Personal" here would make a caller that imports two accounts fail instead of asking.
    pub fn add_logical_vault(&mut self, meta: VaultMeta) -> VaultId {
        let id = meta.id;
        self.body.vaults.push(meta);
        id
    }

    /// Resolve a logical vault by id, unique id prefix, or exact name.
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] when nothing matches.
    pub fn find_vault(&self, reference: &str) -> Result<VaultId> {
        let mut hits: Vec<VaultId> = Vec::new();
        for v in &self.body.vaults {
            let id = v.id.to_string();
            if id == reference
                || v.name == reference
                || (reference.len() >= 4 && id.starts_with(reference))
            {
                hits.push(v.id);
            }
        }
        match hits.len() {
            1 => Ok(hits[0]),
            0 => Err(Error::ItemNotFound(reference.to_owned())),
            _ => Err(Error::AmbiguousItem(reference.to_owned())),
        }
    }

    /// Every item, in insertion order.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.body.items
    }

    /// Metadata for every item. This is what may be printed, logged or handed to an agent.
    #[must_use]
    pub fn item_summaries(&self) -> Vec<ItemSummary> {
        self.body.items.iter().map(Item::summary).collect()
    }

    /// Add an item.
    pub fn add_item(&mut self, item: Item) {
        self.body.items.push(item);
    }

    /// Resolve an item by id, by unique id prefix, or by exact title.
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] or [`Error::AmbiguousItem`].
    pub fn find_item(&self, reference: &str) -> Result<&Item> {
        let idx = self.resolve(reference)?;
        Ok(&self.body.items[idx])
    }

    /// Mutable version of [`Vault::find_item`].
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] or [`Error::AmbiguousItem`].
    pub fn find_item_mut(&mut self, reference: &str) -> Result<&mut Item> {
        let idx = self.resolve(reference)?;
        Ok(&mut self.body.items[idx])
    }

    /// Remove an item, returning it.
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] or [`Error::AmbiguousItem`].
    pub fn remove_item(&mut self, reference: &str) -> Result<Item> {
        let idx = self.resolve(reference)?;
        Ok(self.body.items.remove(idx))
    }

    fn resolve(&self, reference: &str) -> Result<usize> {
        let mut hits: Vec<usize> = Vec::new();
        for (i, item) in self.body.items.iter().enumerate() {
            let id = item.id.to_string();
            let matches = id == reference
                || item.title == reference
                || (reference.len() >= 4 && id.starts_with(reference));
            if matches {
                hits.push(i);
            }
        }
        match hits.len() {
            0 => Err(Error::ItemNotFound(reference.to_owned())),
            1 => Ok(hits[0]),
            _ => Err(Error::AmbiguousItem(reference.to_owned())),
        }
    }

    /// Replace the master password.
    ///
    /// This re-wraps the vault key rather than re-encrypting anything, and rolls a fresh salt for
    /// the password slot (vault-format §3, §9 rule 3). The recovery slot keeps its own salt and
    /// keeps working. Call [`Vault::save`] afterwards.
    ///
    /// # Errors
    ///
    /// Any RNG or KDF failure.
    pub fn change_master_password(&mut self, new_password: &[u8]) -> Result<()> {
        let mut kdf = self.header.kdf.clone();
        kdf.reroll_salt()?;
        let kek = kdf.derive(new_password)?;
        let vault_id = self.header.vault_id.clone();
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let slot = WrappedKey::wrap(
            &vault_id,
            wrap::KIND_PASSWORD,
            SLOT_ID_MASTER,
            "Master password",
            &kek,
            vk,
            None,
        )?;
        drop(kek);
        self.header.kdf = kdf;
        match self.header.slot_mut(wrap::KIND_PASSWORD) {
            Some(existing) => *existing = slot,
            None => self.header.wrapped_keys.insert(0, slot),
        }
        self.unlocked_by = UnlockedBy::Password;
        Ok(())
    }

    /// Raise the Argon2id cost of the master-password slot.
    ///
    /// A re-wrap, not a re-encrypt — cheap enough to offer opportunistically as hardware improves
    /// (vault-format §9 rule 3). Requires the current password, because the KEK it produces is
    /// the thing being replaced. Call [`Vault::save`] afterwards.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] if `current_password` is wrong, plus any RNG or KDF failure.
    pub fn upgrade_kdf(&mut self, current_password: &[u8], new_params: &KdfParams) -> Result<()> {
        new_params.validate()?;
        let slot = self
            .header
            .slot(wrap::KIND_PASSWORD)
            .ok_or(Error::NoSuchSlot(wrap::KIND_PASSWORD))?;
        let kek = slot
            .effective_kdf(&self.header.kdf)
            .derive(current_password)?;
        // Proves the password before anything is replaced.
        let _ = slot.unwrap_with_kek(&self.header.vault_id, &kek)?;
        drop(kek);

        let mut kdf = new_params.clone();
        kdf.reroll_salt()?;
        let kek = kdf.derive(current_password)?;
        let vault_id = self.header.vault_id.clone();
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let replacement = WrappedKey::wrap(
            &vault_id,
            wrap::KIND_PASSWORD,
            SLOT_ID_MASTER,
            "Master password",
            &kek,
            vk,
            None,
        )?;
        drop(kek);
        self.header.kdf = kdf;
        if let Some(existing) = self.header.slot_mut(wrap::KIND_PASSWORD) {
            *existing = replacement;
        }
        Ok(())
    }

    /// Every environment, in insertion order.
    #[must_use]
    pub fn environments(&self) -> &[Environment] {
        &self.body.envs
    }

    /// Metadata for every environment. This is what may be handed to an agent.
    #[must_use]
    pub fn environment_summaries(&self) -> Vec<EnvironmentSummary> {
        self.body.envs.iter().map(Environment::summary).collect()
    }

    /// Add an environment.
    pub fn add_environment(&mut self, env: Environment) {
        self.body.envs.push(env);
    }

    /// Resolve an environment by id, by unique id prefix, or by exact name.
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] or [`Error::AmbiguousEnv`].
    pub fn find_environment(&self, reference: &str) -> Result<&Environment> {
        let index = self.resolve_env(reference)?;
        Ok(&self.body.envs[index])
    }

    /// Mutable version of [`Vault::find_environment`].
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] or [`Error::AmbiguousEnv`].
    pub fn find_environment_mut(&mut self, reference: &str) -> Result<&mut Environment> {
        let index = self.resolve_env(reference)?;
        Ok(&mut self.body.envs[index])
    }

    /// Remove an environment, returning it.
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] or [`Error::AmbiguousEnv`].
    pub fn remove_environment(&mut self, reference: &str) -> Result<Environment> {
        let index = self.resolve_env(reference)?;
        Ok(self.body.envs.remove(index))
    }

    fn resolve_env(&self, reference: &str) -> Result<usize> {
        let mut hits: Vec<usize> = Vec::new();
        for (i, env) in self.body.envs.iter().enumerate() {
            let id = env.id.to_string();
            if id == reference
                || env.name == reference
                || (reference.len() >= 4 && id.starts_with(reference))
            {
                hits.push(i);
            }
        }
        match hits.len() {
            1 => Ok(hits[0]),
            0 => Err(Error::EnvNotFound(reference.to_owned())),
            _ => Err(Error::AmbiguousEnv(reference.to_owned())),
        }
    }

    /// Materialize an environment's variables as injections.
    ///
    /// This is the one place environment values become plaintext, and it is only reachable from
    /// code that enabled `secret-material` (ADR-0002, ADR-0005). `wanted`, when given, selects a
    /// subset by name and preserves the caller's order; `None` takes every variable in the
    /// environment's own order.
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] / [`Error::AmbiguousEnv`] for the environment reference,
    /// [`Error::VarNotPopulated`] for a variable the user has not filled in yet,
    /// [`Error::ItemNotFound`] / [`Error::FieldNotFound`] for a binding whose target has gone.
    pub fn resolve_environment(
        &self,
        reference: &str,
        wanted: Option<&[String]>,
    ) -> Result<Vec<crate::inject::EnvInjection>> {
        use crate::inject::EnvInjection;
        use crate::model::{FieldValue, Secret, VarSource};

        let env = self.find_environment(reference)?;
        let selected: Vec<&crate::model::EnvVar> = match wanted {
            None => env.vars.iter().collect(),
            Some(names) => names
                .iter()
                .map(|n| {
                    env.var(n)
                        .ok_or_else(|| Error::VarNotFound(n.clone(), env.name.clone()))
                })
                .collect::<Result<_>>()?,
        };

        let mut out = Vec::with_capacity(selected.len());
        for var in selected {
            let value = match &var.source {
                VarSource::Literal(secret) => Secret::new(secret.expose().to_vec()),
                VarSource::ItemField { item, field } => {
                    let item_id = item.to_string();
                    let stored = self.find_item(&item_id)?;
                    let f = stored
                        .fields
                        .iter()
                        .find(|f| f.id == *field)
                        .ok_or_else(|| Error::FieldNotFound {
                            item: stored.title.clone(),
                            field: field.to_string(),
                        })?;
                    match &f.value {
                        FieldValue::Secret(secret) => Secret::new(secret.expose().to_vec()),
                        FieldValue::Public(text) => Secret::from_string(text.clone()),
                    }
                }
                VarSource::Pending { .. } => {
                    return Err(Error::VarNotPopulated(var.name.clone()));
                }
            };
            out.push(EnvInjection {
                name: var.name.clone(),
                value,
            });
        }
        Ok(out)
    }

    /// Append an entry to the audit log and advance the chain head (vault-format §8).
    ///
    /// Call [`Vault::save`] afterwards; nothing here touches the disk.
    pub fn append_audit(&mut self, draft: AuditDraft) {
        let head = audit::append(&mut self.body.audit, &self.body.audit_head, draft);
        self.body.audit_head = head;
    }

    /// The audit log, oldest first.
    #[must_use]
    pub fn audit_entries(&self) -> &[AuditEntry] {
        &self.body.audit
    }

    /// The current chain head.
    #[must_use]
    pub fn audit_head(&self) -> &[u8] {
        &self.body.audit_head
    }

    /// Verify the audit hash chain.
    ///
    /// # Errors
    ///
    /// [`Error::AuditChain`] describing the first inconsistency.
    pub fn verify_audit(&self) -> Result<()> {
        audit::verify(&self.body.audit, &self.body.audit_head)?;
        Ok(())
    }

    /// Hand the raw vault key to a platform keystore for wrapping (ADR-0008).
    ///
    /// This is the **only** function in the crate that lets the vault key leave it, and it exists
    /// for exactly one caller: the enrolment half of the Touch ID flow, where the app must give
    /// the 32 bytes to the Secure Enclave to encrypt because nothing else can produce that
    /// ciphertext. The returned buffer zeroizes on drop; what the caller does with the copy the
    /// keystore takes is between the caller and the keystore.
    ///
    /// It is deliberately long-named and deliberately not called `vault_key()`. Every call site
    /// is expected to be justified in review, the same way [`crate::model::Secret::expose`] is
    /// (ADR-0005).
    #[must_use]
    pub fn export_vault_key_for_platform_wrapping(&self) -> Zeroizing<Vec<u8>> {
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        Zeroizing::new(vk.to_vec())
    }

    /// Store a platform keystore's wrapped copy of the vault key, replacing any existing one.
    ///
    /// `wrapped` is opaque to this crate (see [`crate::crypto::wrap::ALG_PLATFORM_OPAQUE`]). Call
    /// [`Vault::save`] afterwards.
    ///
    /// v1 keeps at most one platform slot per vault file: the design is "single owner, single
    /// Mac" (ui-spec.md §14), and a second device enrolling would otherwise silently accumulate
    /// slots that nothing can ever prune.
    pub fn install_platform_slot(&mut self, slot_id: &str, label: &str, wrapped: Vec<u8>) {
        let slot = wrap::platform_slot(slot_id, label, wrapped);
        match self.header.slot_mut(wrap::KIND_PLATFORM) {
            Some(existing) => *existing = slot,
            None => self.header.wrapped_keys.push(slot),
        }
    }

    /// The platform slot, if this vault has one.
    #[must_use]
    pub fn platform_slot(&self) -> Option<&WrappedKey> {
        self.header.slot(wrap::KIND_PLATFORM)
    }

    /// Drop the platform slot, reporting whether there was one. Call [`Vault::save`] afterwards.
    ///
    /// Used when the user turns Touch ID off, and when the app finds the Enclave key gone —
    /// `.biometryCurrentSet` invalidates it the moment the fingerprint set changes (ADR-0004), and
    /// a slot whose key no longer exists is dead weight that would make the lock screen offer an
    /// unlock it cannot perform.
    pub fn remove_platform_slot(&mut self) -> bool {
        let before = self.header.wrapped_keys.len();
        self.header
            .wrapped_keys
            .retain(|s| s.kind != wrap::KIND_PLATFORM);
        before != self.header.wrapped_keys.len()
    }

    /// Issue a fresh recovery code, replacing any existing recovery slot.
    ///
    /// Call [`Vault::save`] afterwards. The old code stops working the moment the file is saved.
    ///
    /// # Errors
    ///
    /// Any RNG or KDF failure.
    pub fn reissue_recovery_code(&mut self) -> Result<RecoveryCode> {
        let code = RecoveryCode::generate()?;
        let vault_id = self.header.vault_id.clone();
        let kdf = self.header.kdf.clone();
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let slot = wrap_recovery_slot(&vault_id, &code, &kdf, vk)?;
        match self.header.slot_mut(wrap::KIND_RECOVERY) {
            Some(existing) => *existing = slot,
            None => self.header.wrapped_keys.push(slot),
        }
        Ok(code)
    }
}

fn decrypt_body(
    vault_key: &[u8; KEY_LEN],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Body> {
    let body_key = crypto::body_key(vault_key);
    let plaintext = aead::open(&body_key, nonce, aad, ciphertext)?;
    let mut body: Body = ciborium::from_reader(plaintext.as_slice())
        .map_err(|e| Error::BodyDecode(e.to_string()))?;
    for item in &mut body.items {
        fold_legacy_website_field_into_urls(item);
    }
    Ok(body)
}

/// Fold a legacy `website` field into [`Item::urls`] (ADR-0029).
///
/// Before ADR-0029 the `Login` template put a `website` field (`FieldKind::Url`) beside
/// `Item::urls`, so an item written by an older build may carry the same website in two places —
/// and the browser-extension allow-list (`saved_websites` in `kagisecure-agent`) had to read
/// both. This is not a `body.schema` migration in the vault-format.md §9 rule 2 sense: the schema
/// is unchanged, so it runs unconditionally every time a body is decoded, the same as any other
/// in-memory normalization, rather than needing the explicit-upgrade-and-backup flow that rule 2
/// reserves for actual schema changes. Nothing is destroyed (rule 1): the value moves from the
/// field into `urls` rather than being dropped, and nothing touches disk until the caller saves.
fn fold_legacy_website_field_into_urls(item: &mut Item) {
    let mut moved = Vec::new();
    item.fields.retain(|f| {
        if f.kind == FieldKind::Url && f.label.eq_ignore_ascii_case("website") {
            if let Some(value) = f.value.as_public()
                && !value.is_empty()
            {
                moved.push(value.to_owned());
            }
            false
        } else {
            true
        }
    });
    for url in moved {
        if !item.urls.contains(&url) {
            item.urls.push(url);
        }
    }
}

fn wrap_recovery_slot(
    vault_id: &[u8],
    code: &RecoveryCode,
    template: &KdfParams,
    vault_key: &[u8; KEY_LEN],
) -> Result<WrappedKey> {
    // Same algorithm and cost as the password path, its own salt (see `WrappedKey::kdf`).
    let mut kdf = template.clone();
    kdf.reroll_salt()?;
    let kek = kdf.derive(code.material())?;
    let slot = WrappedKey::wrap(
        vault_id,
        wrap::KIND_RECOVERY,
        SLOT_ID_RECOVERY,
        "One-time recovery code",
        &kek,
        vault_key,
        Some(kdf),
    )?;
    drop(kek);
    Ok(slot)
}

/// Write `bytes` to `path` atomically, owner-read/write only.
///
/// A temporary file in the same directory is created with mode `0600` *before* any bytes are
/// written to it, flushed, then renamed over the target. A crash therefore leaves either the old
/// file or the new one, never a half-written vault, and the plaintext-adjacent window in which a
/// world-readable file exists is never opened at all.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best effort: an existing directory keeps whatever mode it has.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    let suffix = crypto::random::array::<8>()?;
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    tmp_name.push('.');
    for b in suffix {
        tmp_name.push_str(&format!("{b:02x}"));
    }
    tmp_name.push_str(".tmp");
    let tmp = dir.join(tmp_name);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| -> Result<()> {
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }

    // Best effort: make the rename durable too. Not available on Windows.
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(())
}

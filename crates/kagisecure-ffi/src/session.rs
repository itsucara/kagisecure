//! The one object the app holds: an unlocked vault, behind a lock.
//!
//! Every mutating method writes the file before it returns. That is the same "append, then save"
//! discipline the M2 daemon follows (architecture.md §2.6) and it means the app never has a
//! window where the UI shows a change the disk does not have. It costs a whole-body re-encrypt
//! per call; batching is deferred, exactly as it is for the daemon.
//!
//! Dropping this object is the lock operation: [`kagisecure_core::Vault`] zeroizes the vault key
//! on drop, so the Swift side locks by releasing its reference and swapping the root view.

use std::sync::{Arc, Mutex};

use kagisecure_agent::VaultHandle;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{EnvVar, Environment, Field, Item, VarSource, VaultId};
use kagisecure_core::proto::{Category, Outcome};
use kagisecure_core::vault::{CreateOptions, UnlockedBy, Vault};
use kagisecure_core::{RecoveryCode, unix_now};

use crate::agent::AuditRowView;
use crate::generate::TotpCodeView;
use crate::import::{
    DuplicatePolicyView, ImportFormat, ImportOutcomeView, ImportPlanHandle, ImportReportView,
};
use crate::types::{
    EnvironmentView, FieldView, ItemDraft, ItemFilter, ItemSort, ItemView, SidebarCounts, TagCount,
    UnlockKind, VaultView, field_value,
};
use crate::{FfiError, FfiResult};

/// An unlocked vault, owned by the app for as long as it stays unlocked.
///
/// # Why the vault lives behind a [`VaultHandle`]
///
/// Since M4 the app is not the only thing that needs the unlocked vault: the agent library serves
/// MCP requests from its own threads at the same time. Both hold the one
/// [`kagisecure_agent::VaultHandle`], so there is one vault, one mutex, and one definition of
/// "locked" — the handle holding nothing.
///
/// Dropping this object is still the lock operation, and now does two things rather than one: it
/// takes the vault out of the handle (which zeroizes the key) **and** runs the handle's lock hook,
/// which is what kills every lease and denies every approval the agent still has in flight. There
/// is no window in which a locked vault serves an agent.
#[derive(uniffi::Object)]
pub struct VaultSession {
    handle: Arc<VaultHandle>,
    /// The one-time recovery code from [`VaultSession::create`], handed out exactly once.
    recovery_code: Mutex<Option<String>>,
}

/// A borrow of the vault inside the handle.
///
/// The `expect` is unreachable by construction: the only thing that empties the handle is
/// [`VaultSession`]'s `Drop`, and no method can run on an object that is being destroyed.
struct VaultRef<'a>(std::sync::MutexGuard<'a, Option<Vault>>);

impl std::ops::Deref for VaultRef<'_> {
    type Target = Vault;
    fn deref(&self) -> &Vault {
        self.0
            .as_ref()
            .expect("a VaultSession is only emptied by its own Drop")
    }
}

impl std::ops::DerefMut for VaultRef<'_> {
    fn deref_mut(&mut self) -> &mut Vault {
        self.0
            .as_mut()
            .expect("a VaultSession is only emptied by its own Drop")
    }
}

impl VaultSession {
    fn wrap(vault: Vault, code: Option<RecoveryCode>) -> Arc<Self> {
        Arc::new(Self {
            handle: VaultHandle::new(vault),
            recovery_code: Mutex::new(code.map(|c| c.display().to_string())),
        })
    }

    /// A poisoned lock means another thread panicked while holding the vault. Recovering the
    /// guard is right here: the vault's own invariants are upheld by `&mut self` methods that
    /// cannot leave it half-written, and refusing to unlock would strand the user's data behind
    /// an error they cannot act on.
    fn vault(&self) -> VaultRef<'_> {
        VaultRef(self.handle.guard())
    }

    /// The handle to share with the agent library. Not exported: Swift never sees a vault.
    pub(crate) fn handle(&self) -> Arc<VaultHandle> {
        Arc::clone(&self.handle)
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        // Taking is what zeroizes, and taking is what runs the lock hook. Both matter: the key
        // goes, and so does every lease the agent minted while it existed.
        drop(self.handle.take());
    }
}

#[uniffi::export]
impl VaultSession {
    /// Create a vault file and unlock it.
    ///
    /// `kdf_m_kib` and `kdf_t` override the Argon2id cost; pass `None` for the v1 desktop profile.
    /// They exist so the test suite can create vaults that protect nothing in milliseconds, the
    /// same escape hatch the CLI's `--kdf-m-kib` flag is.
    ///
    /// The one-time recovery code is available from [`VaultSession::take_recovery_code`] and from
    /// nowhere else; the app must show it before the user gets any further (vault-format.md §3.2).
    ///
    /// # Errors
    ///
    /// [`FfiError::AlreadyExists`], plus I/O and KDF failures.
    #[uniffi::constructor]
    pub fn create(
        path: String,
        master_password: String,
        vault_name: String,
        kdf_m_kib: Option<u32>,
        kdf_t: Option<u32>,
    ) -> FfiResult<Arc<Self>> {
        let mut options = CreateOptions::new()?;
        options.vault_name = vault_name;
        if kdf_m_kib.is_some() || kdf_t.is_some() {
            let base = &options.kdf;
            options.kdf = KdfParams::new(
                kdf_m_kib.unwrap_or(base.m_kib),
                kdf_t.unwrap_or(base.t),
                base.p,
            )?;
        }
        let (vault, code) = Vault::create(&path, master_password.as_bytes(), &options)?;
        Ok(Self::wrap(vault, Some(code)))
    }

    /// Unlock with the master password (ui-spec.md §6.1).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotFound`] or [`FfiError::WrongCredential`].
    #[uniffi::constructor]
    pub fn unlock_with_password(path: String, master_password: String) -> FfiResult<Arc<Self>> {
        let vault = Vault::open_with_password(&path, master_password.as_bytes())?;
        Ok(Self::wrap(vault, None))
    }

    /// Unlock with the printable recovery code.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the code does not parse or its checksum fails,
    /// [`FfiError::WrongCredential`] if it parses but does not open this vault.
    #[uniffi::constructor]
    pub fn unlock_with_recovery_code(path: String, code: String) -> FfiResult<Arc<Self>> {
        let code = RecoveryCode::parse(&code)?;
        let vault = Vault::open_with_recovery_code(&path, &code)?;
        Ok(Self::wrap(vault, None))
    }

    /// Unlock with a vault key the platform keystore has already unwrapped.
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 4. Swift obtains
    /// these 32 bytes from `SecKeyCreateDecryptedData` after a successful Touch ID, and should
    /// clear its own buffer once this returns.
    ///
    /// # Errors
    ///
    /// [`FfiError::WrongCredential`] if the key does not open this vault — including when it is
    /// not 32 bytes, which is not distinguished, for the same reason a wrong password is not.
    #[uniffi::constructor]
    pub fn unlock_with_vault_key(path: String, vault_key: Vec<u8>) -> FfiResult<Arc<Self>> {
        let vault = Vault::open_with_vault_key(&path, &vault_key)?;
        Ok(Self::wrap(vault, None))
    }

    /// The one-time recovery code, if this session created the vault. Returns it once and then
    /// forgets it, so a second caller cannot re-read something the user was told is one-time.
    pub fn take_recovery_code(&self) -> Option<String> {
        self.recovery_code
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// Where this vault lives.
    pub fn path(&self) -> String {
        self.vault().path().display().to_string()
    }

    /// How this session unlocked.
    pub fn unlocked_by(&self) -> UnlockKind {
        match self.vault().unlocked_by() {
            UnlockedBy::Password => UnlockKind::Password,
            UnlockedBy::RecoveryCode => UnlockKind::RecoveryCode,
            UnlockedBy::PlatformKey => UnlockKind::PlatformKey,
        }
    }

    /// The logical vaults inside the file, for the sidebar's vault switcher.
    pub fn vaults(&self) -> Vec<VaultView> {
        let vault = self.vault();
        let counts = vault.vault_summaries();
        counts
            .iter()
            .map(|s| VaultView {
                id: s.id.to_string(),
                name: s.name.clone(),
                item_count: u32::try_from(s.item_count).unwrap_or(u32::MAX),
                agent_visible: s.agent_visible,
            })
            .collect()
    }

    /// Share a logical vault with agents, or stop (threat-model M-9, default-deny).
    ///
    /// This is the outermost of the three gates an agent has to get through — vault, then
    /// environment or item, then an approval. With it off, an agent cannot see that the vault
    /// exists, and no environment inside it is reachable however it is flagged.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if there is no such logical vault; I/O failures.
    pub fn set_vault_agent_visible(&self, vault_id: String, visible: bool) -> FfiResult<bool> {
        let mut vault = self.vault();
        let id = vault.find_vault(&vault_id)?;
        let changed = vault.set_vault_agent_visible(id, visible);
        vault.save()?;
        Ok(changed)
    }

    /// The logical vault new items go into.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the file somehow contains no logical vault.
    pub fn default_vault_id(&self) -> FfiResult<String> {
        Ok(self.vault().default_vault_id()?.to_string())
    }

    /// The item list for one sidebar section, optionally filtered by the search field.
    ///
    /// `query` matches title, tags and URLs, case-insensitively, and **never** field values
    /// (ui-spec.md §3): a concealed value is not indexed in plaintext, and a public one is not
    /// searched either, so that turning a field from public to concealed cannot change what a
    /// search reveals.
    pub fn list_items(
        &self,
        filter: ItemFilter,
        query: Option<String>,
        sort: ItemSort,
    ) -> Vec<ItemView> {
        let vault = self.vault();
        let needle = query
            .map(|q| q.trim().to_lowercase())
            .filter(|q| !q.is_empty());

        let mut hits: Vec<&Item> = vault
            .items()
            .iter()
            .filter(|i| matches_filter(i, &filter))
            .filter(|i| match &needle {
                None => true,
                Some(n) => {
                    i.title.to_lowercase().contains(n)
                        || i.tags.iter().any(|t| t.to_lowercase().contains(n))
                        || i.urls.iter().any(|u| u.to_lowercase().contains(n))
                }
            })
            .collect();

        match sort {
            ItemSort::Title => hits.sort_by_key(|i| i.title.to_lowercase()),
            ItemSort::DateModified => hits.sort_by_key(|i| std::cmp::Reverse(i.updated_at)),
            ItemSort::DateCreated => hits.sort_by_key(|i| std::cmp::Reverse(i.created_at)),
            ItemSort::Category => {
                hits.sort_by_key(|i| (i.category.as_str().to_owned(), i.title.to_lowercase()))
            }
        }
        hits.into_iter().map(ItemView::from_core).collect()
    }

    /// One item by id.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`].
    pub fn item(&self, item_id: String) -> FfiResult<ItemView> {
        let vault = self.vault();
        Ok(ItemView::from_core(vault.find_item(&item_id)?))
    }

    /// The counts the sidebar shows (ui-spec.md §2.2).
    pub fn sidebar_counts(&self) -> SidebarCounts {
        let vault = self.vault();
        let items = vault.items();
        let live = || items.iter().filter(|i| !i.archived && !i.is_trashed());

        let mut categories: Vec<TagCount> = Category::first_class()
            .into_iter()
            .map(|c| TagCount {
                count: count(live().filter(|i| i.category == c)),
                name: c.as_str().to_owned(),
            })
            .collect();
        // Anything a foreign version wrote keeps its own row rather than vanishing.
        let mut extra: Vec<String> = live()
            .filter_map(|i| match &i.category {
                Category::Other(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        extra.sort_unstable();
        extra.dedup();
        for name in extra {
            let count = count(live().filter(|i| i.category.as_str() == name));
            categories.push(TagCount { name, count });
        }

        let mut tag_names: Vec<String> = live().flat_map(|i| i.tags.iter().cloned()).collect();
        tag_names.sort_unstable();
        tag_names.dedup();
        let tags = tag_names
            .into_iter()
            .map(|name| {
                let count = count(live().filter(|i| i.tags.contains(&name)));
                TagCount { name, count }
            })
            .collect();

        SidebarCounts {
            all: count(live()),
            favorites: count(live().filter(|i| i.favorite)),
            archive: count(items.iter().filter(|i| i.archived && !i.is_trashed())),
            trash: count(items.iter().filter(|i| i.is_trashed())),
            categories,
            tags,
        }
    }

    /// Reveal one concealed field's value (ui-spec.md §4.2, ⌘R).
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 2, outbound. One
    /// field at a time, on an explicit user action: there is no call that returns every value in
    /// an item, so a bug in the UI layer cannot spill a whole item into a rendered view.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown item or field, [`FfiError::Invalid`] if the value
    /// is not valid UTF-8 (an imported binary key, say) and so cannot be shown as text.
    pub fn reveal_field(&self, item_id: String, field_id: String) -> FfiResult<String> {
        let vault = self.vault();
        let item = vault.find_item(&item_id)?;
        let field = item
            .field(&field_id)
            .ok_or_else(|| FfiError::missing("field", field_id))?;
        match &field.value {
            kagisecure_core::model::FieldValue::Public(s) => Ok(s.clone()),
            kagisecure_core::model::FieldValue::Secret(secret) => secret
                .expose_str()
                .map(str::to_owned)
                .ok_or_else(|| FfiError::invalid("this value is not text and cannot be shown")),
        }
    }

    /// The current one-time password for a TOTP field (ui-spec.md §4.2).
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 5, outbound. One
    /// field at a time and named explicitly, exactly like [`VaultSession::reveal_field`]: there is
    /// no call that returns every code in the vault, so the Quick Access list asks for the one row
    /// the user is on rather than being handed a screenful.
    ///
    /// `at` is the Unix time to render for. The caller passes its own clock so the code and the
    /// countdown ring around it are drawn from one instant — a ring that reached zero one tick
    /// before the code changed would be the drift the roadmap's soak-test criterion is about.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown item or field, [`FfiError::Invalid`] if the field
    /// is not a one-time password or its stored `otpauth://` URI does not parse.
    pub fn totp_code(&self, item_id: String, field_id: String, at: u64) -> FfiResult<TotpCodeView> {
        let vault = self.vault();
        let item = vault.find_item(&item_id)?;
        let field = item
            .field(&field_id)
            .ok_or_else(|| FfiError::missing("field", field_id))?;
        TotpCodeView::build(&field.totp_generator()?, at)
    }

    /// The current one-time password for an item's first TOTP field, if it has one.
    ///
    /// What the item list's hover action and Quick Access's ⌥⏎ need: they know an item, not a
    /// field. `None` — rather than an error — when the item has no TOTP field at all, because
    /// "this row has no code to copy" is an ordinary state for most rows.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown item, [`FfiError::Invalid`] if the field's stored
    /// URI does not parse.
    pub fn item_totp_code(&self, item_id: String, at: u64) -> FfiResult<Option<TotpCodeView>> {
        let vault = self.vault();
        let item = vault.find_item(&item_id)?;
        match item.totp_field() {
            Some(field) => Ok(Some(TotpCodeView::build(&field.totp_generator()?, at)?)),
            None => Ok(None),
        }
    }

    /// Create an item pre-populated with its category's default fields (vault-format.md §5.4).
    ///
    /// The item is saved immediately, so the list can select it and the detail pane can open it
    /// in edit mode. `agent_visible` is `false`, as it is on every new item.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown logical vault, plus I/O failures.
    pub fn create_item(
        &self,
        vault_id: Option<String>,
        category: String,
        title: String,
    ) -> FfiResult<ItemView> {
        let mut vault = self.vault();
        let target: VaultId = match vault_id {
            Some(v) => vault.find_vault(&v)?,
            None => vault.default_vault_id()?,
        };
        let category: Category = category.parse().unwrap_or(Category::Login);
        let item = Item::from_template(target, category, title);
        let id = item.id.to_string();
        vault.add_item(item);
        vault.save()?;
        Ok(ItemView::from_core(vault.find_item(&id)?))
    }

    /// Replace an item's editable content with what the edit sheet produced (ui-spec.md §4.3).
    ///
    /// Fields carrying an existing id keep it, so a per-field agent-visibility toggle and any
    /// future per-field state survive an edit; a field with no id is new. Fields the draft omits
    /// are deleted. `agent_visible` — item-level and field-level — is *not* taken from the draft:
    /// it has its own toggles and its own methods, so an edit sheet cannot turn agent access on
    /// as a side effect of a rename.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown item, plus I/O failures.
    pub fn save_item(&self, draft: ItemDraft) -> FfiResult<ItemView> {
        let mut vault = self.vault();
        // Per-field state the draft does not carry and an edit must not destroy: the agent
        // visibility toggle, and `Field::extra` — the metadata an importer wrote (vault-format
        // §9 rule 1 says a round trip does not drop what this build did not put in the sheet).
        let previous: Vec<_> = vault
            .find_item(&draft.id)?
            .fields
            .iter()
            .map(|f| (f.id.to_string(), f.agent_visible, f.extra.clone()))
            .collect();

        let item = vault.find_item_mut(&draft.id)?;
        item.title = draft.title;
        item.category = draft.category.parse().unwrap_or(Category::Login);
        item.tags = draft.tags;
        item.urls = draft.urls;
        item.notes = draft.notes.filter(|n| !n.is_empty());
        item.fields = draft
            .fields
            .into_iter()
            .map(|f| {
                let carried =
                    f.id.as_ref()
                        .and_then(|id| previous.iter().find(|(prev, _, _)| prev == id));
                let agent_visible = carried.map_or(f.agent_visible, |(_, visible, _)| *visible);
                let mut field = Field {
                    id: f
                        .id
                        .and_then(|id| id.parse().ok())
                        .unwrap_or_else(kagisecure_core::model::FieldId::new),
                    label: f.label,
                    kind: f.kind.to_core(),
                    value: field_value(f.concealed, f.value),
                    section: f.section.filter(|s| !s.is_empty()),
                    agent_visible,
                    extra: carried
                        .map(|(_, _, extra)| extra.clone())
                        .unwrap_or_default(),
                };
                // Keep the tag and the value in step: a field the user made concealed is a
                // `Concealed` field, whatever kind it started as.
                if field.value.is_secret() && field.kind == kagisecure_core::proto::FieldKind::Text
                {
                    field.kind = kagisecure_core::proto::FieldKind::Concealed;
                }
                field
            })
            .collect();
        item.updated_at = unix_now();
        let id = item.id.to_string();
        vault.save()?;
        Ok(ItemView::from_core(vault.find_item(&id)?))
    }

    /// Toggle the favourite star.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_favorite(&self, item_id: String, favorite: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.favorite = favorite;
        })
    }

    /// Move an item to the archive, or bring it back.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_archived(&self, item_id: String, archived: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.archived = archived;
        })
    }

    /// Move an item to the trash, or restore it. A soft delete: nothing is destroyed.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_trashed(&self, item_id: String, trashed: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.trashed_at = trashed.then(unix_now);
        })
    }

    /// Set the item-level "Visible to agents" toggle (ui-spec.md §4.4).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_agent_visible(&self, item_id: String, visible: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.agent_visible = visible;
            if !visible {
                // Turning the item off turns every field off with it, so an item that is later
                // re-exposed does not silently bring back per-field grants the user forgot about.
                for field in &mut item.fields {
                    field.agent_visible = false;
                }
            }
        })
    }

    /// Set one field's agent-visibility override (ui-spec.md §4.4).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_field_agent_visible(
        &self,
        item_id: String,
        field_id: String,
        visible: bool,
    ) -> FfiResult<ItemView> {
        let mut vault = self.vault();
        let item = vault.find_item_mut(&item_id)?;
        let field = item
            .fields
            .iter_mut()
            .find(|f| f.id.to_string() == field_id)
            .ok_or_else(|| FfiError::missing("field", field_id))?;
        field.agent_visible = visible;
        item.updated_at = unix_now();
        let id = item.id.to_string();
        vault.save()?;
        Ok(ItemView::from_core(vault.find_item(&id)?))
    }

    /// Delete an item for good. Only reachable from the Trash (ui-spec.md §2.2).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn delete_item(&self, item_id: String) -> FfiResult<()> {
        let mut vault = self.vault();
        vault.remove_item(&item_id)?;
        vault.save()?;
        Ok(())
    }

    /// One field of one item, freshly read. Used after a reveal so the UI can refresh a row.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`].
    pub fn field(&self, item_id: String, field_id: String) -> FfiResult<FieldView> {
        let vault = self.vault();
        let item = vault.find_item(&item_id)?;
        item.field(&field_id)
            .map(FieldView::from_core)
            .ok_or_else(|| FfiError::missing("field", field_id))
    }

    /// Every environment, names only (ui-spec.md §10.4). Read-only in M3.
    pub fn environments(&self) -> Vec<EnvironmentView> {
        self.vault()
            .environments()
            .iter()
            .map(EnvironmentView::from_core)
            .collect()
    }

    /// One environment.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if there is no environment with that id or name.
    pub fn environment(&self, environment_id: String) -> FfiResult<EnvironmentView> {
        Ok(EnvironmentView::from_core(
            self.vault().find_environment(&environment_id)?,
        ))
    }

    /// Create an empty environment from the app (ui-spec.md §10.4).
    ///
    /// Created **invisible to agents**, unlike one an agent asked for through
    /// `create_environment`: the user has not said anything about sharing it yet, and
    /// default-deny is the rule (threat-model M-9, ADR-0007 §6).
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] on an empty name; I/O failures.
    pub fn create_environment(
        &self,
        name: String,
        description: Option<String>,
    ) -> FfiResult<EnvironmentView> {
        if name.trim().is_empty() {
            return Err(FfiError::invalid("an environment needs a name"));
        }
        let mut vault = self.vault();
        let vault_id = vault.default_vault_id()?;
        let mut env = Environment::new(vault_id, name.trim());
        env.description = description.filter(|d| !d.trim().is_empty());
        let id = env.id.to_string();
        vault.add_environment(env);
        vault.append_audit(AuditDraft {
            actor: "app".to_owned(),
            tool: "create_environment".to_owned(),
            vault_id: Some(vault_id),
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        });
        vault.save()?;
        Ok(EnvironmentView::from_core(vault.find_environment(&id)?))
    }

    /// Share an environment with agents, or stop sharing it.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_environment_agent_visible(
        &self,
        environment_id: String,
        visible: bool,
    ) -> FfiResult<EnvironmentView> {
        let mut vault = self.vault();
        let env = vault.find_environment_mut(&environment_id)?;
        env.agent_visible = visible;
        env.updated_at = unix_now();
        let id = env.id.to_string();
        vault.save()?;
        Ok(EnvironmentView::from_core(vault.find_environment(&id)?))
    }

    /// Supply the value for a variable, in the app, with the keyboard.
    ///
    /// This is the second half of `add_variables`' pending flow (mcp-server.md §2.6): the agent
    /// named the variable and could not supply a value, and this is where the human does. It is
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 2 — a single
    /// field value going in — applied to an environment's inline binding rather than an item's
    /// field, and it is the only way a value enters an environment from Swift.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if the environment does not exist; I/O failures.
    pub fn set_variable_value(
        &self,
        environment_id: String,
        name: String,
        value: String,
    ) -> FfiResult<EnvironmentView> {
        if name.trim().is_empty() {
            return Err(FfiError::invalid("a variable needs a name"));
        }
        let mut vault = self.vault();
        let env = vault.find_environment_mut(&environment_id)?;
        env.set_var(EnvVar {
            name: name.trim().to_owned(),
            source: VarSource::Literal(kagisecure_core::Secret::from_string(value)),
        });
        env.updated_at = unix_now();
        let id = env.id.to_string();
        vault.append_audit(AuditDraft {
            actor: "app".to_owned(),
            tool: "set_variable".to_owned(),
            environment_id: Some(
                id.parse()
                    .map_err(|_| FfiError::invalid("an environment id that is not an id"))?,
            ),
            variables: vec![name.trim().to_owned()],
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        });
        vault.save()?;
        Ok(EnvironmentView::from_core(vault.find_environment(&id)?))
    }

    /// Bind a variable to an item's field instead of a literal — the preferred shape, because
    /// rotating the credential once updates every environment that references it.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if the environment, item or field does not exist.
    pub fn bind_variable(
        &self,
        environment_id: String,
        name: String,
        item_id: String,
        field_id: String,
    ) -> FfiResult<EnvironmentView> {
        let mut vault = self.vault();
        let item = vault.find_item(&item_id)?;
        let item_ref = item.id;
        let field = item
            .fields
            .iter()
            .find(|f| f.id.to_string() == field_id)
            .ok_or_else(|| FfiError::missing("field", field_id))?
            .id;
        let env = vault.find_environment_mut(&environment_id)?;
        env.set_var(EnvVar {
            name: name.trim().to_owned(),
            source: VarSource::ItemField {
                item: item_ref,
                field,
            },
        });
        env.updated_at = unix_now();
        let id = env.id.to_string();
        vault.save()?;
        Ok(EnvironmentView::from_core(vault.find_environment(&id)?))
    }

    /// Remove one variable from an environment.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn remove_variable(
        &self,
        environment_id: String,
        name: String,
    ) -> FfiResult<EnvironmentView> {
        let mut vault = self.vault();
        let env = vault.find_environment_mut(&environment_id)?;
        env.vars.retain(|v| v.name != name);
        env.updated_at = unix_now();
        let id = env.id.to_string();
        vault.save()?;
        Ok(EnvironmentView::from_core(vault.find_environment(&id)?))
    }

    /// Delete an environment.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn delete_environment(&self, environment_id: String) -> FfiResult<()> {
        let mut vault = self.vault();
        vault.remove_environment(&environment_id)?;
        vault.save()?;
        Ok(())
    }

    /// A page of the audit log, newest first (ui-spec.md §10.4's audit viewer).
    ///
    /// The log lives in the vault, not in the agent, so this is readable whether or not the
    /// listener is running — which is what a user wants after a lock, when the question is
    /// "what did that thing just do?".
    pub fn audit_page(&self, limit: u32, offset: u32) -> Vec<AuditRowView> {
        let vault = self.vault();
        let entries = vault.audit_entries();
        entries
            .iter()
            .rev()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|e| AuditRowView {
                seq: e.seq,
                timestamp: e.timestamp,
                actor: e.actor.clone(),
                tool: e.tool.clone(),
                outcome: match e.outcome {
                    Outcome::Allowed => "allowed".to_owned(),
                    Outcome::Denied => "denied".to_owned(),
                    Outcome::Failed => "failed".to_owned(),
                },
                environment_id: e.environment_id.map(|i| i.to_string()),
                item_id: e.item_id.map(|i| i.to_string()),
                variables: e.variables.clone(),
                target_path: e.target_path.clone(),
                detail: e.detail.clone(),
            })
            .collect()
    }

    /// How many entries the audit log has, for the viewer's paging.
    pub fn audit_count(&self) -> u32 {
        u32::try_from(self.vault().audit_entries().len()).unwrap_or(u32::MAX)
    }

    /// Replace the master password (ui-spec.md §6, and required after a recovery-code unlock).
    ///
    /// # Errors
    ///
    /// KDF, RNG and I/O failures.
    pub fn change_master_password(&self, new_password: String) -> FfiResult<()> {
        let mut vault = self.vault();
        vault.change_master_password(new_password.as_bytes())?;
        vault.save()?;
        Ok(())
    }

    /// Whether this vault has a platform (Touch ID) slot.
    pub fn has_platform_slot(&self) -> bool {
        self.vault().platform_slot().is_some()
    }

    /// The platform slot's identifier, if there is one.
    pub fn platform_slot_id(&self) -> Option<String> {
        self.vault().platform_slot().map(|s| s.id.clone())
    }

    /// Hand the raw vault key out for the Secure Enclave to encrypt.
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 3, and the
    /// narrowest one: it is called once, during enrolment, and the caller is expected to pass the
    /// result to `SecKeyCreateEncryptedData` and then to
    /// [`VaultSession::install_platform_slot`] without holding on to it.
    pub fn export_vault_key_for_platform_wrapping(&self) -> Vec<u8> {
        self.vault()
            .export_vault_key_for_platform_wrapping()
            .to_vec()
    }

    /// Store the keystore's wrapped copy of the vault key, replacing any existing platform slot.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty blob — which would mean the keystore returned nothing
    /// and enrolling it would produce a slot that can never unlock — plus I/O failures.
    pub fn install_platform_slot(
        &self,
        slot_id: String,
        label: String,
        wrapped_key: Vec<u8>,
    ) -> FfiResult<()> {
        if wrapped_key.is_empty() {
            return Err(FfiError::invalid("the keystore returned no wrapped key"));
        }
        let mut vault = self.vault();
        vault.install_platform_slot(&slot_id, &label, wrapped_key);
        vault.save()?;
        Ok(())
    }

    /// Forget the platform slot — the user turned Touch ID off, or the Enclave key is gone.
    ///
    /// # Errors
    ///
    /// I/O failures.
    pub fn remove_platform_slot(&self) -> FfiResult<bool> {
        let mut vault = self.vault();
        let removed = vault.remove_platform_slot();
        if removed {
            vault.save()?;
        }
        Ok(removed)
    }

    // MARK: - Import (import.md §8)

    /// Parse an export into a plan and hand back a handle to it.
    ///
    /// A method on the session rather than a free function, because importing into a vault
    /// requires one to be open — the app's File ▸ Import… is disabled while locked, and this is
    /// what makes that a property of the API rather than only of the menu.
    ///
    /// Nothing is written. The parse finishes here, so a malformed archive fails with the vault
    /// untouched; the values it produced stay inside the returned object. See `crate::import` for
    /// why that object is the only thing that crosses.
    ///
    /// `format` overrides detection the way `--format` does; `None` lets the parser be chosen
    /// from the file.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotFound`] if there is no file there, [`FfiError::Invalid`] if it cannot be
    /// parsed — a format that could not be told apart, a missing column, a parser limit.
    pub fn import_preview(
        &self,
        path: String,
        format: Option<ImportFormat>,
    ) -> FfiResult<Arc<ImportPlanHandle>> {
        crate::import::preview(&path, format)
    }

    /// The same plan, previewed against *this* vault under `policy`.
    ///
    /// [`ImportPlanHandle::report`] cannot know about duplicates, because a plan knows nothing
    /// about any vault. This is the report the sheet actually shows: same counts, plus a
    /// per-item action and the number of items the vault already has.
    ///
    /// Reads the vault. Writes nothing, to it or to the disk.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the plan has already been committed.
    pub fn import_preview_against(
        &self,
        plan: Arc<ImportPlanHandle>,
        policy: DuplicatePolicyView,
    ) -> FfiResult<ImportReportView> {
        plan.report_against(&self.vault(), policy)
    }

    /// Apply the plan and save.
    ///
    /// `target_vault` names one logical vault to put everything in, the way `--logical-vault`
    /// does; with `None` each item goes where the source said. A named vault the file does not
    /// have is created, and the outcome says which names those were.
    ///
    /// The plan is consumed: the handle is spent afterwards and a second call fails rather than
    /// importing twice. The save is the same atomic `0600` write every other mutating method on
    /// this object performs, so the file is either the old one or the new one.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the plan is spent, or I/O failures from the save.
    pub fn import_commit(
        &self,
        plan: Arc<ImportPlanHandle>,
        policy: DuplicatePolicyView,
        target_vault: Option<String>,
    ) -> FfiResult<ImportOutcomeView> {
        let mut vault = self.vault();
        let outcome = plan.commit_into(&mut vault, policy, target_vault)?;
        vault.save()?;
        Ok(outcome)
    }

    /// Write the vault to disk. Every mutating method already does; this is for a "save now"
    /// affordance and for tests.
    ///
    /// # Errors
    ///
    /// I/O failures.
    pub fn save(&self) -> FfiResult<()> {
        self.vault().save()?;
        Ok(())
    }

    /// Whether the audit hash chain verifies (vault-format.md §8).
    pub fn audit_intact(&self) -> bool {
        self.vault().verify_audit().is_ok()
    }
}

impl VaultSession {
    fn mutate(&self, item_id: &str, change: impl FnOnce(&mut Item)) -> FfiResult<ItemView> {
        let mut vault = self.vault();
        let item = vault.find_item_mut(item_id)?;
        change(item);
        item.updated_at = unix_now();
        let id = item.id.to_string();
        vault.save()?;
        Ok(ItemView::from_core(vault.find_item(&id)?))
    }
}

fn count<'a>(iter: impl Iterator<Item = &'a Item>) -> u32 {
    u32::try_from(iter.count()).unwrap_or(u32::MAX)
}

fn matches_filter(item: &Item, filter: &ItemFilter) -> bool {
    let live = !item.archived && !item.is_trashed();
    match filter {
        ItemFilter::All => live,
        ItemFilter::Favorites => live && item.favorite,
        ItemFilter::Category { category } => live && item.category.as_str() == category,
        ItemFilter::Tag { tag } => live && item.tags.iter().any(|t| t == tag),
        ItemFilter::Archive => item.archived && !item.is_trashed(),
        ItemFilter::Trash => item.is_trashed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{TotpAlgorithm, totp_uri_from_parts};
    use crate::types::{FieldDraft, FieldKind};

    const URI: &str = "otpauth://totp/ACME:ada@example.com\
        ?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30";

    /// A vault with one Login item carrying a TOTP field, at KDF parameters that protect nothing.
    fn fixture() -> (tempfile::TempDir, Arc<VaultSession>, String, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.kagivault").display().to_string();
        let session = VaultSession::create(
            path,
            "pw".to_owned(),
            "Personal".to_owned(),
            Some(8),
            Some(1),
        )
        .expect("create");
        let item = session
            .create_item(None, "login".to_owned(), "GitHub".to_owned())
            .expect("item");
        let fields = item
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: if f.kind == FieldKind::Totp {
                    URI.to_owned()
                } else {
                    String::new()
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        let saved = session
            .save_item(ItemDraft {
                id: item.id.clone(),
                category: item.category.clone(),
                title: item.title.clone(),
                fields,
                tags: Vec::new(),
                urls: Vec::new(),
                notes: None,
            })
            .expect("save");
        let field_id = saved
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .expect("a totp field")
            .id
            .clone();
        (dir, session, saved.id, field_id)
    }

    #[test]
    fn a_stored_totp_field_produces_a_code_and_a_countdown() {
        let (_dir, session, item, field) = fixture();
        let view = session
            .totp_code(item.clone(), field.clone(), 1_699_999_980)
            .expect("a code");
        assert_eq!(view.code.len(), 6);
        assert_eq!(view.seconds_remaining, 30);
        assert_eq!(view.params.issuer.as_deref(), Some("ACME"));

        // The item-level lookup finds the same field without being told which one it is.
        let by_item = session
            .item_totp_code(item, 1_699_999_980)
            .expect("no error")
            .expect("the item has one");
        assert_eq!(by_item.code, view.code);
    }

    #[test]
    fn the_stored_field_stays_concealed_in_every_list_view() {
        let (_dir, session, item, field) = fixture();
        let view = session.item(item.clone()).expect("the item");
        let totp = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .expect("the field");
        assert!(totp.concealed, "a TOTP seed is secret material");
        assert!(totp.has_value);
        assert!(
            totp.value.is_none(),
            "the seed must not ride along on a rendered field list"
        );
        // Revealing it deliberately yields the URI, which is what edit mode needs to show.
        let revealed = session.reveal_field(item, field).expect("reveal");
        assert!(revealed.starts_with("otpauth://"));
    }

    #[test]
    fn a_field_that_is_not_a_one_time_password_is_refused() {
        let (_dir, session, item, _) = fixture();
        let view = session.item(item.clone()).expect("the item");
        let password = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Concealed)
            .expect("the password field")
            .id
            .clone();
        let error = session
            .totp_code(item.clone(), password, 0)
            .expect_err("not a TOTP field");
        assert!(error.to_string().contains("not a one-time password"));
        assert!(session.totp_code(item, "nope".to_owned(), 0).is_err());
    }

    #[test]
    fn an_item_with_no_totp_field_reports_none_rather_than_failing() {
        let (_dir, session, _, _) = fixture();
        let bare = session
            .create_item(None, "secure-note".to_owned(), "Notes".to_owned())
            .expect("item");
        assert!(
            session
                .item_totp_code(bare.id, 0)
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn a_hand_built_uri_can_be_saved_and_read_back() {
        let (_dir, session, item, field) = fixture();
        let uri = totp_uri_from_parts(
            "JBSWY3DPEHPK3PXP".to_owned(),
            crate::generate::TotpParamsView {
                algorithm: TotpAlgorithm::Sha256,
                digits: 8,
                period: 60,
                issuer: Some("Manual".to_owned()),
                account: None,
                caption: None,
            },
        )
        .expect("a uri");
        let view = session.item(item.clone()).expect("the item");
        let fields = view
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: if f.id == field {
                    uri.clone()
                } else {
                    f.value.clone().unwrap_or_default()
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        session
            .save_item(ItemDraft {
                id: view.id.clone(),
                category: view.category.clone(),
                title: view.title.clone(),
                fields,
                tags: Vec::new(),
                urls: Vec::new(),
                notes: None,
            })
            .expect("save");
        let code = session.totp_code(item, field, 59).expect("a code");
        assert_eq!(code.code.len(), 8);
        assert_eq!(code.params.period, 60);
        assert_eq!(code.params.issuer.as_deref(), Some("Manual"));
    }
}

//! What this device's agents may be served from a shared vault (ADR-0035 §14, Phase 4).
//!
//! # A snapshot, not a handle
//!
//! The process that serves agents — the app, or `kagisecure daemon` — holds each open shared
//! vault as a replica and a device key. What it serves from is a [`SharedSnapshot`]: every item
//! and environment as merged now (decision 80), with this device's own settings applied —
//! agent visibility, favourites, default paths (decision 22) — and, for each field and each
//! environment variable, which record its value came from ([`crate::merge::Provenance`]) and
//! who wrote that record, when. A snapshot is owned data: a request reads one without holding
//! the replica, and a release reads the current one again inside its own transaction.
//!
//! # References stay inside the vault
//!
//! A shared environment's binding is followed into the same shared vault and nowhere else
//! ([`SharedSnapshot::resolve_environment`]; ADR-0035 §14): a reference into someone's personal
//! vault would be meaningless to every other member.
//!
//! # "Changed since you last approved it"
//!
//! The approval sheet names a value that changed since this device last approved releasing it,
//! and who changed it (ADR-0035 §14, decision 26). What is compared is the record a part's value
//! came from ([`crate::merge::Provenance::slots`]): [`SharedSnapshot::env_changes`] and
//! [`SharedSnapshot::item_changes`] against the records
//! [`crate::replica::LocalState::approved_vars`] and `approved_fields` hold, and [`Approvals`]
//! is what a granted sheet records there. A part never approved counts as changed, so the first
//! release of a shared value always shows its author. The comparison is by record alone: a new
//! version that sets a field again — even to the same value, or only relabels it — is still
//! "changed", which errs towards telling the person.
//!
//! Nothing here carries a value to anyone: a [`Change`] is a name, a label and a time.

use std::collections::BTreeMap;

use kagisecure_core::inject::EnvInjection;
use kagisecure_core::model::env::resolve_injections;
use kagisecure_core::model::{Environment, Item, VarSource};
use kagisecure_core::proto::{EnvId, FieldId, ItemId, VaultId};

use crate::device::{DeviceKeyId, DeviceSecret};
use crate::error::Result;
use crate::merge::{Slot, materialize_all};
use crate::record::RecordId;
use crate::replica::{LocalState, Replica};
use crate::view::SharedView;

/// What a shared vault is called when this device does not know its name.
pub const UNNAMED_VAULT: &str = "Shared vault";

/// The author label for this device's own records.
pub const YOU: &str = "you";

/// The author label when this device has no name for the member.
pub const ANOTHER_MEMBER: &str = "another member";

/// Apply this device's own settings — favourites and agent visibility — to `item`, which a
/// record never carries ([`crate::payload`]).
pub fn apply_local(item: &mut Item, local: &LocalState) {
    item.favorite = local.favorites.contains(&item.id);
    item.agent_visible = local.agent_visible_items.contains(&item.id);
    let fields = local.agent_visible_fields.get(&item.id);
    for field in &mut item.fields {
        field.agent_visible = fields.is_some_and(|f| f.contains(&field.id));
    }
}

/// Apply this device's own settings — agent visibility and default paths — to `env`.
pub fn apply_local_env(env: &mut Environment, local: &LocalState) {
    env.agent_visible = local.agent_visible_envs.contains(&env.id);
    env.default_paths = local
        .default_paths
        .get(&env.id)
        .cloned()
        .unwrap_or_default();
}

/// Who wrote one record, and when their device said it was.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Authorship {
    author: String,
    at: u64,
}

/// A part about to be released whose value changed since this device last approved releasing
/// it — or was never approved. Metadata only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The variable's name, or the field's label.
    pub part: String,
    /// Who wrote the version the value comes from: [`YOU`], the name this device knows their
    /// member by, or [`ANOTHER_MEMBER`].
    pub author: String,
    /// When their device said it was written, in unix seconds.
    pub at: u64,
    /// Whether this device had never approved releasing it at all.
    pub first_release: bool,
}

/// What a granted approval records in the replica's local state: the record each released
/// part's value came from (decision 26). Recorded with [`Approvals::apply`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Approvals {
    fields: Vec<(ItemId, FieldId, RecordId)>,
    vars: Vec<(EnvId, String, RecordId)>,
}

impl Approvals {
    /// Whether there is nothing to record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.vars.is_empty()
    }

    /// Record these approvals in `local`. Returns whether anything changed.
    pub fn apply(&self, local: &mut LocalState) -> bool {
        let mut changed = false;
        for (item, field, record) in &self.fields {
            let slot = local.approved_fields.entry(*item).or_default();
            changed |= slot.insert(*field, *record) != Some(*record);
        }
        for (env, name, record) in &self.vars {
            let slot = local.approved_vars.entry(*env).or_default();
            changed |= slot.insert(name.clone(), *record) != Some(*record);
        }
        changed
    }
}

/// One shared vault as this device's agents may be served it now (module documentation).
///
/// `Debug` shows ids and counts only.
pub struct SharedSnapshot {
    vault_id: VaultId,
    name: String,
    member_count: usize,
    items: Vec<Item>,
    envs: Vec<Environment>,
    field_sources: BTreeMap<(ItemId, FieldId), RecordId>,
    var_sources: BTreeMap<(EnvId, String), RecordId>,
    authors: BTreeMap<RecordId, Authorship>,
    approved_fields: BTreeMap<ItemId, BTreeMap<FieldId, RecordId>>,
    approved_vars: BTreeMap<EnvId, BTreeMap<String, RecordId>>,
}

impl std::fmt::Debug for SharedSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSnapshot")
            .field("vault_id", &self.vault_id)
            .field("items", &self.items.len())
            .field("environments", &self.envs.len())
            .finish_non_exhaustive()
    }
}

impl SharedSnapshot {
    /// The snapshot of `replica`, read through `view` — computed from the same records by
    /// `device`, the replica's own device.
    ///
    /// # Errors
    ///
    /// As [`crate::merge::materialize_all`].
    pub fn build(replica: &Replica, view: &SharedView, device: &DeviceKeyId) -> Result<Self> {
        let local = replica.local();
        let roster = view.roster().snapshot();
        let (items, envs) = materialize_all(view)?;

        let mut authors = BTreeMap::new();
        let mut note_author = |record: &RecordId| {
            if authors.contains_key(record) {
                return;
            }
            let Some(accepted) = view.version(record) else {
                return;
            };
            let author = accepted.author();
            let label = if author == *device {
                YOU.to_owned()
            } else {
                roster
                    .device(&author)
                    .and_then(|d| local.member_names.get(&d.member).cloned())
                    .unwrap_or_else(|| ANOTHER_MEMBER.to_owned())
            };
            authors.insert(
                *record,
                Authorship {
                    author: label,
                    at: accepted.created_at(),
                },
            );
        };

        let mut field_sources = BTreeMap::new();
        let mut kept_items = Vec::new();
        for merged in items {
            let Some(mut item) = merged.item else {
                continue;
            };
            for (slot, record) in &merged.provenance.slots {
                if let Slot::Field(field) = slot {
                    field_sources.insert((item.id, *field), *record);
                    note_author(record);
                }
            }
            apply_local(&mut item, local);
            kept_items.push(item);
        }
        let mut var_sources = BTreeMap::new();
        let mut kept_envs = Vec::new();
        for merged in envs {
            let Some(mut env) = merged.env else {
                continue;
            };
            for (slot, record) in &merged.provenance.slots {
                if let Slot::Var(name) = slot {
                    var_sources.insert((env.id, name.clone()), *record);
                    note_author(record);
                }
            }
            apply_local_env(&mut env, local);
            kept_envs.push(env);
        }

        Ok(Self {
            vault_id: *replica.vault_id(),
            name: local
                .vault_name
                .clone()
                .unwrap_or_else(|| UNNAMED_VAULT.to_owned()),
            member_count: roster.members().filter(|m| m.active).count(),
            items: kept_items,
            envs: kept_envs,
            field_sources,
            var_sources,
            authors,
            approved_fields: local.approved_fields.clone(),
            approved_vars: local.approved_vars.clone(),
        })
    }

    /// Read `replica` as `device` and build its snapshot: [`SharedView::compute`], then
    /// [`SharedSnapshot::build`].
    ///
    /// # Errors
    ///
    /// As both.
    pub fn read(replica: &Replica, device: &DeviceSecret) -> Result<Self> {
        let view = SharedView::compute(
            replica.vault_id(),
            &replica.genesis(),
            &replica.envelopes(),
            device,
        )?;
        Self::build(replica, &view, &device.id())
    }

    /// The shared vault's id.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// Its name, as this device knows it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many members it has now.
    #[must_use]
    pub const fn member_count(&self) -> usize {
        self.member_count
    }

    /// Every item that is not deleted, with this device's settings applied.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Every environment that is not deleted, with this device's settings applied.
    #[must_use]
    pub fn environments(&self) -> &[Environment] {
        &self.envs
    }

    /// Item `id`, if the vault holds it and it is not deleted.
    #[must_use]
    pub fn item(&self, id: &ItemId) -> Option<&Item> {
        self.items.iter().find(|item| item.id == *id)
    }

    /// Environment `id`, if the vault holds it and it is not deleted.
    #[must_use]
    pub fn environment(&self, id: &EnvId) -> Option<&Environment> {
        self.envs.iter().find(|env| env.id == *id)
    }

    /// Resolve environment `id`'s variables — `wanted`, or all — following every binding into
    /// this shared vault's own items only (module documentation).
    ///
    /// # Errors
    ///
    /// [`kagisecure_core::Error::EnvNotFound`] for an environment the vault does not hold, and as
    /// [`resolve_injections`].
    pub fn resolve_environment(
        &self,
        id: &EnvId,
        wanted: Option<&[String]>,
    ) -> kagisecure_core::Result<Vec<EnvInjection>> {
        let env = self
            .environment(id)
            .ok_or_else(|| kagisecure_core::Error::EnvNotFound(id.to_string()))?;
        resolve_injections(env, wanted, |item| self.item(item), false)
    }

    /// The parts variable `name` of `env` releases: the variable itself, and for a binding the
    /// bound field too, each with the record its value comes from.
    fn var_parts(&self, env: &Environment, name: &str) -> Vec<Part> {
        let mut parts = Vec::new();
        if let Some(record) = self.var_sources.get(&(env.id, name.to_owned())) {
            parts.push(Part::Var(env.id, name.to_owned(), *record));
        }
        if let Some(var) = env.var(name)
            && let VarSource::ItemField { item, field } = &var.source
            && let Some(record) = self.field_sources.get(&(*item, *field))
        {
            parts.push(Part::Field(*item, *field, *record));
        }
        parts
    }

    /// The record this device last approved for `part`, if any.
    fn approved_record(&self, part: &Part) -> Option<&RecordId> {
        match part {
            Part::Var(env, name, _) => self.approved_vars.get(env)?.get(name),
            Part::Field(item, field, _) => self.approved_fields.get(item)?.get(field),
        }
    }

    /// The change to report for `parts`, named `label`: the latest of those not approved as
    /// they are now, if any.
    fn change(&self, label: &str, parts: &[Part]) -> Option<Change> {
        let unapproved: Vec<&Part> = parts
            .iter()
            .filter(|p| self.approved_record(p) != Some(&p.record()))
            .collect();
        let (latest, _) = unapproved
            .iter()
            .filter_map(|p| self.authors.get(&p.record()).map(|a| (a, p.record())))
            .max_by_key(|(a, record)| (a.at, *record))?;
        Some(Change {
            part: label.to_owned(),
            author: latest.author.clone(),
            at: latest.at,
            first_release: unapproved.iter().all(|p| self.approved_record(p).is_none()),
        })
    }

    /// The variables among `names` of environment `env` whose value changed since this device
    /// last approved releasing it (module documentation), in `names`' order.
    #[must_use]
    pub fn env_changes(&self, env: &EnvId, names: &[String]) -> Vec<Change> {
        let Some(env) = self.environment(env) else {
            return Vec::new();
        };
        names
            .iter()
            .filter_map(|name| self.change(name, &self.var_parts(env, name)))
            .collect()
    }

    /// The fields among `fields` of item `item` whose value changed since this device last
    /// approved releasing it, labelled by the field's label.
    #[must_use]
    pub fn item_changes(&self, item: &ItemId, fields: &[FieldId]) -> Vec<Change> {
        let Some(found) = self.item(item) else {
            return Vec::new();
        };
        fields
            .iter()
            .filter_map(|field| {
                let label = &found.fields.iter().find(|f| f.id == *field)?.label;
                let record = self.field_sources.get(&(*item, *field))?;
                self.change(label, &[Part::Field(*item, *field, *record)])
            })
            .collect()
    }

    /// What approving the release of `names` of environment `env` records.
    #[must_use]
    pub fn env_approvals(&self, env: &EnvId, names: &[String]) -> Approvals {
        let mut approvals = Approvals::default();
        if let Some(env) = self.environment(env) {
            for name in names {
                for part in self.var_parts(env, name) {
                    part.push_to(&mut approvals);
                }
            }
        }
        approvals
    }

    /// The records the values of `names` of environment `env` come from — the variable's own and,
    /// for a binding, the bound field's — as `(name, records)` in `names`' order. What an
    /// unattended copy records, so a newer version can be noticed (ADR-0042 §13).
    #[must_use]
    pub fn env_sources(&self, env: &EnvId, names: &[String]) -> Vec<(String, Vec<RecordId>)> {
        let Some(env) = self.environment(env) else {
            return Vec::new();
        };
        names
            .iter()
            .map(|name| {
                let records = self.var_parts(env, name).iter().map(Part::record).collect();
                (name.clone(), records)
            })
            .collect()
    }

    /// What approving the release of `fields` of item `item` records.
    #[must_use]
    pub fn item_approvals(&self, item: &ItemId, fields: &[FieldId]) -> Approvals {
        let mut approvals = Approvals::default();
        for field in fields {
            if let Some(record) = self.field_sources.get(&(*item, *field)) {
                Part::Field(*item, *field, *record).push_to(&mut approvals);
            }
        }
        approvals
    }
}

/// One part whose value is released: a variable or a field, with the record it came from.
enum Part {
    Var(EnvId, String, RecordId),
    Field(ItemId, FieldId, RecordId),
}

impl Part {
    const fn record(&self) -> RecordId {
        match self {
            Self::Var(_, _, record) | Self::Field(_, _, record) => *record,
        }
    }

    fn push_to(self, approvals: &mut Approvals) {
        match self {
            Self::Var(env, name, record) => approvals.vars.push((env, name, record)),
            Self::Field(item, field, record) => approvals.fields.push((item, field, record)),
        }
    }
}

/// Record `approvals` in `replica`'s local state, as `device`: one transaction that writes
/// nothing any other member receives, and nothing at all when they were recorded already.
///
/// # Errors
///
/// As [`Replica::transact`].
pub fn record_approved(
    replica: &mut Replica,
    device: &DeviceSecret,
    approvals: &Approvals,
) -> Result<()> {
    if approvals.is_empty() {
        return Ok(());
    }
    replica.transact(device, |tx| {
        approvals.apply(tx.local_mut());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use kagisecure_core::model::{Field, Secret};
    use kagisecure_core::proto::{Category, VarName};

    use super::*;
    use crate::admin::create::create;
    use crate::write::{put_env, put_item};

    const NOW: u64 = 1_800_000_000;

    fn vault() -> (tempfile::TempDir, DeviceSecret, Replica) {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceSecret::generate().unwrap();
        let replica = create(
            &dir.path().join("vault.kagivault"),
            &device,
            "Ops",
            None,
            NOW,
        )
        .unwrap();
        (dir, device, replica)
    }

    /// An item with one concealed field holding `value`, and an environment binding `TOKEN`
    /// to it, written into `replica`.
    fn seed(replica: &mut Replica, device: &DeviceSecret, value: &str) -> (ItemId, FieldId, EnvId) {
        let mut item = Item::new(*replica.vault_id(), Category::ApiCredential, "Deploy key");
        let field = Field::concealed("token", Secret::from_string(value.to_owned()));
        let field_id = field.id;
        item.fields.push(field);
        let item_id = item.id;
        put_item(replica, device, item, NOW).unwrap();
        let mut env = Environment::new(*replica.vault_id(), "ops / prod");
        env.set_var(
            VarName::new("TOKEN".to_owned()).unwrap(),
            VarSource::ItemField {
                item: item_id,
                field: field_id,
            },
        );
        let env_id = env.id;
        put_env(replica, device, env, NOW).unwrap();
        (item_id, field_id, env_id)
    }

    /// A new version of item `id` whose one field holds `value`.
    fn rotate(replica: &mut Replica, device: &DeviceSecret, id: ItemId, value: &str, now: u64) {
        let field_id = SharedSnapshot::read(replica, device)
            .unwrap()
            .item(&id)
            .unwrap()
            .fields[0]
            .id;
        let mut item = Item::new(*replica.vault_id(), Category::ApiCredential, "Deploy key");
        item.id = id;
        let mut field = Field::concealed("token", Secret::from_string(value.to_owned()));
        field.id = field_id;
        item.fields.push(field);
        put_item(replica, device, item, now).unwrap();
    }

    #[test]
    fn everything_starts_hidden_from_agents() {
        let (_dir, device, mut replica) = vault();
        let (item, _, env) = seed(&mut replica, &device, "s3cr3t");
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        assert!(!snapshot.item(&item).unwrap().agent_visible);
        assert!(!snapshot.environment(&env).unwrap().agent_visible);
        assert_eq!(snapshot.name(), "Ops");
        assert_eq!(snapshot.member_count(), 1);
    }

    #[test]
    fn a_binding_resolves_inside_the_vault() {
        let (_dir, device, mut replica) = vault();
        let (_, _, env) = seed(&mut replica, &device, "s3cr3t");
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        let injections = snapshot.resolve_environment(&env, None).unwrap();
        assert_eq!(injections.len(), 1);
        assert_eq!(injections[0].name.as_str(), "TOKEN");
        assert_eq!(injections[0].value.expose(), b"s3cr3t");
    }

    #[test]
    fn a_binding_to_an_item_outside_the_vault_does_not_resolve() {
        let (_dir, device, mut replica) = vault();
        let mut env = Environment::new(*replica.vault_id(), "elsewhere");
        env.set_var(
            VarName::new("TOKEN".to_owned()).unwrap(),
            VarSource::ItemField {
                item: ItemId::new(),
                field: FieldId::new(),
            },
        );
        let env_id = env.id;
        put_env(&mut replica, &device, env, NOW).unwrap();
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        assert!(matches!(
            snapshot.resolve_environment(&env_id, None),
            Err(kagisecure_core::Error::ItemNotFound(_))
        ));
    }

    #[test]
    fn a_first_release_is_a_change_and_an_approved_one_is_not_until_the_value_changes() {
        let (_dir, device, mut replica) = vault();
        let (item, _, env) = seed(&mut replica, &device, "one");
        let names = vec!["TOKEN".to_owned()];

        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        let changes = snapshot.env_changes(&env, &names);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].part, "TOKEN");
        assert_eq!(changes[0].author, YOU);
        assert!(changes[0].first_release);

        record_approved(&mut replica, &device, &snapshot.env_approvals(&env, &names)).unwrap();
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        assert!(snapshot.env_changes(&env, &names).is_empty());

        rotate(&mut replica, &device, item, "two", NOW + 60);
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        let changes = snapshot.env_changes(&env, &names);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].at, NOW + 60);
        assert!(!changes[0].first_release);
    }

    #[test]
    fn approving_a_field_through_a_fill_counts_for_that_field() {
        let (_dir, device, mut replica) = vault();
        let (item, field, _) = seed(&mut replica, &device, "one");
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        assert_eq!(snapshot.item_changes(&item, &[field])[0].part, "token");
        record_approved(
            &mut replica,
            &device,
            &snapshot.item_approvals(&item, &[field]),
        )
        .unwrap();
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        assert!(snapshot.item_changes(&item, &[field]).is_empty());
    }

    #[test]
    fn this_devices_settings_are_applied() {
        let (_dir, device, mut replica) = vault();
        let (item, field, env) = seed(&mut replica, &device, "one");
        replica
            .transact(&device, |tx| {
                let local = tx.local_mut();
                local.agent_visible_items.insert(item);
                local
                    .agent_visible_fields
                    .entry(item)
                    .or_default()
                    .insert(field);
                local.agent_visible_envs.insert(env);
                Ok(())
            })
            .unwrap();
        let snapshot = SharedSnapshot::read(&replica, &device).unwrap();
        let found = snapshot.item(&item).unwrap();
        assert!(found.agent_visible);
        assert!(found.fields[0].agent_visible);
        assert!(snapshot.environment(&env).unwrap().agent_visible);
    }
}

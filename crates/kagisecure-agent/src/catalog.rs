//! One view over everything an agent may be served: the personal vault and the shared vaults
//! attached to it (ADR-0035 §14, Phase 4).
//!
//! Every agent-facing lookup goes through a [`Catalog`] — `list_vaults`, `list_items`,
//! `list_environments`, `describe_item`, `request_fill`, the releases, and the browser
//! extension's fills — so that "may an agent know this exists" has one definition per kind of
//! vault and a shared item cannot be reachable through one tool and hidden from another.
//!
//! # What an agent sees of a shared vault
//!
//! The items and environments this device has made visible to agents — this device's own
//! setting, kept in the replica's local section, **hidden by default** exactly as a personal
//! item or environment is (threat-model M-9; decision 88) — and nothing else. A shared vault
//! with nothing visible is not listed at all, so its name does not reach a model either. A
//! shared vault has no vault-wide switch of its own: its items' and environments' switches are
//! the whole of it.
//!
//! Hidden and absent are one answer, as everywhere: [`Catalog::agent_item`] and
//! [`Catalog::agent_environment`] return `None` for both.
//!
//! # Collisions (decision 89)
//!
//! * **By id.** An agent names an item or environment by id, so an id must name one thing. A
//!   personal item or environment wins over a shared one with the same id — the shared one is
//!   absent to agents, whatever either's visibility — and an id held by two shared vaults names
//!   neither, since picking one would be arbitrary. Ids are random, so neither happens unless a
//!   copy kept its id.
//! * **By name.** Names are what a model reads, and two environments called `staging` in one
//!   listing is a guess waiting to go wrong. Both stay listed: a personal one keeps its name,
//!   and every shared one whose name another listed entry also has is shown as `name (vault)`,
//!   qualified by the shared vault's name on this device. The same name is used on the
//!   approval sheet.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kagisecure_core::Vault;
use kagisecure_core::inject::EnvInjection;
use kagisecure_core::model::{Environment, Item, VarSource};
use kagisecure_core::proto::{
    EnvId, EnvironmentSummary, FieldId, ItemId, ItemSummary, VaultId, VaultSummary,
};
use kagisecure_shared::read::SharedSnapshot;

/// Where something the catalog found lives.
#[derive(Clone, Copy)]
pub enum Place<'c> {
    /// The personal vault.
    Personal,
    /// A shared vault.
    Shared(&'c SharedSnapshot),
}

impl<'c> Place<'c> {
    /// The shared vault, if that is where it lives.
    #[must_use]
    pub const fn shared(self) -> Option<&'c SharedSnapshot> {
        match self {
            Self::Personal => None,
            Self::Shared(snapshot) => Some(snapshot),
        }
    }

    /// The shared vault's id, for an audit entry (decision 24): `None` for the personal vault,
    /// whose entries have always named the logical vault only where a change needs it.
    #[must_use]
    pub fn audit_vault(self) -> Option<VaultId> {
        self.shared().map(|s| *s.vault_id())
    }
}

/// An item or environment the catalog found, and where.
pub struct Found<'c, T> {
    /// What was found.
    pub value: &'c T,
    /// Where it lives.
    pub place: Place<'c>,
}

impl<T> Clone for Found<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Found<'_, T> {}

/// The personal vault and the attached shared vaults, as one (module documentation).
pub struct Catalog<'a> {
    personal: &'a Vault,
    shared: Vec<Arc<SharedSnapshot>>,
    visible_vaults: BTreeSet<VaultId>,
}

impl<'a> Catalog<'a> {
    /// The catalog over `personal` and the snapshots of the shared vaults attached to it
    /// ([`crate::VaultHandle::shared_snapshots`]).
    #[must_use]
    pub fn new(personal: &'a Vault, shared: Vec<Arc<SharedSnapshot>>) -> Self {
        let visible_vaults = personal
            .vault_summaries()
            .into_iter()
            .filter(|v| v.agent_visible)
            .map(|v| v.id)
            .collect();
        Self {
            personal,
            shared,
            visible_vaults,
        }
    }

    /// The personal vault.
    #[must_use]
    pub const fn personal(&self) -> &'a Vault {
        self.personal
    }

    /// The personal vault's logical vaults an agent may know about.
    #[must_use]
    pub const fn visible_vaults(&self) -> &BTreeSet<VaultId> {
        &self.visible_vaults
    }

    /// The attached shared vault `id`, if it can be read.
    #[must_use]
    pub fn shared_vault(&self, id: &VaultId) -> Option<&SharedSnapshot> {
        self.shared
            .iter()
            .map(AsRef::as_ref)
            .find(|s| s.vault_id() == id)
    }

    // -----------------------------------------------------------------------------------------
    // Lookups by id, with the collision rules
    // -----------------------------------------------------------------------------------------

    /// Item `id`, wherever it is: the personal vault's if it has one, else the one shared vault
    /// that holds it. `None` when two shared vaults do (module documentation).
    #[must_use]
    pub fn item(&self, id: &ItemId) -> Option<Found<'_, Item>> {
        if let Some(item) = self.personal.item_by_id(id) {
            return Some(Found {
                value: item,
                place: Place::Personal,
            });
        }
        self.only_one(|s| s.item(id))
    }

    /// Environment `id`, by the same rule as [`Catalog::item`].
    #[must_use]
    pub fn environment(&self, id: &EnvId) -> Option<Found<'_, Environment>> {
        if let Some(env) = self.personal.environments().iter().find(|e| e.id == *id) {
            return Some(Found {
                value: env,
                place: Place::Personal,
            });
        }
        self.only_one(|s| s.environment(id))
    }

    /// The one shared vault `lookup` finds something in, or nothing if none or several do.
    fn only_one<'c, T>(
        &'c self,
        lookup: impl Fn(&'c SharedSnapshot) -> Option<&'c T>,
    ) -> Option<Found<'c, T>> {
        let mut found = None;
        for snapshot in &self.shared {
            if let Some(value) = lookup(snapshot) {
                if found.is_some() {
                    return None;
                }
                found = Some(Found {
                    value,
                    place: Place::Shared(snapshot),
                });
            }
        }
        found
    }

    // -----------------------------------------------------------------------------------------
    // Agent visibility
    // -----------------------------------------------------------------------------------------

    /// Whether an agent may know `item` exists: visible to agents itself, not in the trash, and
    /// — in the personal vault — in a logical vault visible to agents. Archived items are not
    /// excluded: `list_items` lists them.
    fn item_visible(&self, found: Found<'_, Item>) -> bool {
        let item = found.value;
        item.agent_visible
            && !item.is_trashed()
            && match found.place {
                Place::Personal => self.visible_vaults.contains(&item.vault_id),
                Place::Shared(_) => true,
            }
    }

    /// Whether an agent may know environment `found` exists, by the same rule.
    fn environment_visible(&self, found: Found<'_, Environment>) -> bool {
        found.value.agent_visible
            && match found.place {
                Place::Personal => self.visible_vaults.contains(&found.value.vault_id),
                Place::Shared(_) => true,
            }
    }

    /// The item an agent names by `reference` — an exact item id, never a title or a prefix —
    /// if it may know it exists. `None` for absent and hidden alike.
    #[must_use]
    pub fn agent_item(&self, reference: &str) -> Option<Found<'_, Item>> {
        let id = ItemId::parse_canonical(reference)?;
        self.item(&id).filter(|found| self.item_visible(*found))
    }

    /// Environment `id`, if an agent may know it exists. `None` for absent and hidden alike.
    #[must_use]
    pub fn agent_environment(&self, id: &EnvId) -> Option<Found<'_, Environment>> {
        self.environment(id)
            .filter(|found| self.environment_visible(*found))
    }

    /// Whether an agent may *bind* a personal environment's variable to `field` of `item`: the
    /// item in the personal vault and visible to agents, and the field's own agent flag. A shared
    /// item is never a target — a personal environment's binding is followed in the personal
    /// vault only, and agents cannot write to a shared vault.
    #[must_use]
    pub fn personal_field_bindable(&self, item: ItemId, field: FieldId) -> bool {
        self.personal.item_by_id(&item).is_some_and(|found| {
            self.item_visible(Found {
                value: found,
                place: Place::Personal,
            }) && found
                .fields
                .iter()
                .any(|f| f.id == field && f.agent_visible)
        })
    }

    /// Whether a release may *follow* a binding of environment `env` to `item`: the item, in the
    /// environment's own vault, visible to agents by [`Catalog::agent_item`]'s rule. The field's
    /// own flag is not required (a person may bind a field kept out of `describe_item`, to be
    /// injected without being listed).
    fn binding_followable(&self, env: Found<'_, Environment>, item: &ItemId) -> bool {
        match env.place {
            Place::Personal => self.personal.item_by_id(item).is_some_and(|found| {
                self.item_visible(Found {
                    value: found,
                    place: Place::Personal,
                })
            }),
            Place::Shared(snapshot) => snapshot.item(item).is_some_and(|found| {
                self.item_visible(Found {
                    value: found,
                    place: env.place,
                })
            }),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Listings and names
    // -----------------------------------------------------------------------------------------

    /// Every item, personal first, then each shared vault's, by the collision rules (module
    /// documentation) and nothing else: what a browser fill a person starts may offer, whatever
    /// an agent may see.
    #[must_use]
    pub fn all_items(&self) -> Vec<Found<'_, Item>> {
        let personal = self.personal.items();
        let taken: BTreeSet<ItemId> = personal.iter().map(|item| item.id).collect();
        let found = personal.iter().map(|item| Found {
            value: item,
            place: Place::Personal,
        });
        found
            .chain(self.uncontested(&taken, SharedSnapshot::items, |i| i.id))
            .collect()
    }

    /// Every entry `of` each shared vault that no personal entry's id (`taken`) and no other
    /// shared vault's entry claims — the collision rule, in one pass (module documentation).
    fn uncontested<'c, T, Id: Ord + Copy>(
        &'c self,
        taken: &BTreeSet<Id>,
        of: impl Fn(&SharedSnapshot) -> &[T],
        id: impl Fn(&T) -> Id,
    ) -> Vec<Found<'c, T>> {
        let mut holders: BTreeMap<Id, usize> = BTreeMap::new();
        for snapshot in &self.shared {
            for entry in of(snapshot) {
                *holders.entry(id(entry)).or_default() += 1;
            }
        }
        self.shared
            .iter()
            .flat_map(|snapshot| {
                of(snapshot).iter().map(move |value| Found {
                    value,
                    place: Place::Shared(snapshot),
                })
            })
            .filter(|found| {
                let id = id(found.value);
                !taken.contains(&id) && holders.get(&id) == Some(&1)
            })
            .collect()
    }

    /// Every item an agent may know exists, personal first, then each shared vault's.
    fn visible_items(&self) -> Vec<Found<'_, Item>> {
        self.all_items()
            .into_iter()
            .filter(|found| self.item_visible(*found))
            .collect()
    }

    /// Every environment an agent may know exists, personal first.
    fn visible_environments(&self) -> Vec<Found<'_, Environment>> {
        let personal = self.personal.environments();
        let taken: BTreeSet<EnvId> = personal.iter().map(|env| env.id).collect();
        personal
            .iter()
            .map(|env| Found {
                value: env,
                place: Place::Personal,
            })
            .chain(self.uncontested(&taken, SharedSnapshot::environments, |e| e.id))
            .filter(|found| self.environment_visible(*found))
            .collect()
    }

    /// The logical vaults of the personal vault an agent may know about, then every attached
    /// shared vault with something visible in it.
    #[must_use]
    pub fn agent_vaults(&self) -> Vec<VaultSummary> {
        let mut vaults: Vec<VaultSummary> = self
            .personal
            .vault_summaries()
            .into_iter()
            .filter(|v| v.agent_visible)
            .collect();
        let items = self.visible_items();
        let envs = self.visible_environments();
        for snapshot in &self.shared {
            let in_it = |place: Place<'_>| {
                place
                    .shared()
                    .is_some_and(|s| s.vault_id() == snapshot.vault_id())
            };
            let item_count = items.iter().filter(|f| in_it(f.place)).count();
            let environment_count = envs.iter().filter(|f| in_it(f.place)).count();
            if item_count + environment_count == 0 {
                continue;
            }
            vaults.push(VaultSummary {
                id: *snapshot.vault_id(),
                name: snapshot.name().to_owned(),
                item_count,
                environment_count,
                agent_visible: true,
                shared: true,
            });
        }
        vaults
    }

    /// Every item an agent may know exists, as `list_items` shows it (module documentation).
    #[must_use]
    pub fn agent_items(&self) -> Vec<ItemSummary> {
        let items = self.visible_items();
        items
            .iter()
            .map(|found| self.summary_among(*found, &items))
            .collect()
    }

    /// Every environment an agent may know exists, as `list_environments` shows it.
    #[must_use]
    pub fn agent_environments(&self) -> Vec<EnvironmentSummary> {
        let envs = self.visible_environments();
        envs.iter()
            .map(|found| {
                let mut summary = found.value.summary();
                summary.name = qualified(&found.value.name, found.place, &envs, |e| &e.name);
                summary
            })
            .collect()
    }

    /// `found`'s summary with its title as the listing shows it.
    fn summary_among(&self, found: Found<'_, Item>, among: &[Found<'_, Item>]) -> ItemSummary {
        let mut summary = found.value.summary();
        summary.title = qualified(&found.value.title, found.place, among, |i| &i.title);
        summary
    }

    /// Item `found`'s summary, as `describe_item` answers it: its title as the listing shows it.
    #[must_use]
    pub fn item_summary(&self, found: Found<'_, Item>) -> ItemSummary {
        self.summary_among(found, &self.visible_items())
    }

    /// Item `found`'s title as the listing and the sheet show it.
    #[must_use]
    pub fn item_title(&self, found: Found<'_, Item>) -> String {
        if found.place.shared().is_none() {
            return found.value.title.clone();
        }
        qualified(
            &found.value.title,
            found.place,
            &self.visible_items(),
            |i| &i.title,
        )
    }

    /// Environment `found`'s name as the listing and the sheet show it.
    #[must_use]
    pub fn environment_name(&self, found: Found<'_, Environment>) -> String {
        if found.place.shared().is_none() {
            return found.value.name.clone();
        }
        qualified(
            &found.value.name,
            found.place,
            &self.visible_environments(),
            |e| &e.name,
        )
    }

    // -----------------------------------------------------------------------------------------
    // Releases
    // -----------------------------------------------------------------------------------------

    /// Resolve variables `names` of environment `id` for a release, checking first — on this
    /// catalog, read inside the release's own transaction — that the environment is still one
    /// an agent may use and that every binding about to be followed still leads to an item an
    /// agent may know exists, in the environment's own vault.
    ///
    /// # Errors
    ///
    /// [`kagisecure_core::Error::EnvNotFound`] for an environment gone or hidden — one error
    /// for both — and [`kagisecure_core::Error::ItemNotFound`] for a binding that may not be
    /// followed, before a single value is resolved; then as the vault's own resolution.
    pub fn release_environment(
        &self,
        id: &EnvId,
        names: &[String],
    ) -> kagisecure_core::Result<Vec<EnvInjection>> {
        let found = self
            .agent_environment(id)
            .ok_or_else(|| kagisecure_core::Error::EnvNotFound(id.to_string()))?;
        for name in names {
            if let Some(var) = found.value.var(name)
                && let VarSource::ItemField { item, .. } = &var.source
                && !self.binding_followable(found, item)
            {
                return Err(kagisecure_core::Error::ItemNotFound(item.to_string()));
            }
        }
        match found.place {
            Place::Personal => self
                .personal
                .resolve_environment(&id.to_string(), Some(names)),
            Place::Shared(snapshot) => snapshot.resolve_environment(id, Some(names)),
        }
    }
}

/// `name` as a listing shows it: unchanged in the personal vault, or when no other entry of
/// `among` has it; otherwise qualified by the shared vault's name (module documentation).
fn qualified<T>(
    name: &str,
    place: Place<'_>,
    among: &[Found<'_, T>],
    name_of: impl Fn(&T) -> &String,
) -> String {
    let Some(snapshot) = place.shared() else {
        return name.to_owned();
    };
    let taken = among.iter().filter(|f| name_of(f.value) == name).count();
    if taken > 1 {
        format!("{name} ({})", snapshot.name())
    } else {
        name.to_owned()
    }
}

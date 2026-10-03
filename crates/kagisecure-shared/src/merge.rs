//! The merge: what a person sees of one item or environment, from all its accepted versions
//! (ADR-0035 §8; addendum, decision 80).
//!
//! # Last writer wins, per attribute and per field
//!
//! Every version carries the whole item. What a version **sets** is what it changed: an
//! attribute (the title, the tags, the notes, …), a field (by its id) or an environment variable
//! (by its name) whose value — its `serde` encoding, compared as bytes, with "absent" a value
//! too — differs from each of the versions it names as parents. A version with no parent among
//! the item's accepted versions sets everything it holds.
//!
//! A version beats every version it descends from — the versions it names as parents, theirs,
//! and so on, among the item's accepted versions — whatever times their authors claim: an edit
//! is never undone by the version it was made on, even one written within the same second or
//! by a device whose clock is behind. Only concurrent versions, neither descending from the
//! other, are ordered by the time their author claims, then by record id
//! ([`crate::view::Accepted::order_key`]).
//!
//! For each attribute and field, of the versions that set it, those no other of them descends
//! from are kept, and the latest of these in that order wins. The rest of the item comes from
//! the latest edit, chosen the same way among all the edits that stand. A deletion and an edit
//! are weighed the same way: a deletion beats every edit it descends from and every concurrent
//! edit before it, and an edit that descends from a deletion beats it. The edits no deletion
//! beats stand. If no edit stands, the item is deleted; otherwise it is built from the standing
//! edits only, so an edit after a deletion brings the item back without the edits the deletion
//! beat. There is nothing for a person to resolve (decision 80, the owner's priorities,
//! superseding §8's "no last-writer-wins").
//!
//! The item's `created_at` is the earliest among those edits, its `updated_at` the latest, and
//! its field history the union of theirs, so no retired value a version kept is dropped.
//!
//! The result depends only on the set of accepted versions, never on the order they arrived in,
//! so every device that accepted the same versions shows the same item.
//!
//! # Values stay in wiped buffers
//!
//! A version is taken apart from its encoding, not cloned: the item is encoded into a zeroizing
//! buffer, split into its attributes' and fields' encodings — each copied into a zeroizing
//! buffer of exactly its size — and the merged item is decoded from one zeroizing buffer built
//! at exactly its size.

use std::collections::{BTreeMap, BTreeSet};

use kagisecure_core::model::{Environment, Item};
use kagisecure_core::proto::{EnvId, FieldId, ItemId};
use zeroize::Zeroizing;

use crate::cbor;
use crate::error::{Result, SharedError};
use crate::record::RecordId;
use crate::view::{Accepted, ObjectId, SharedView, Version};

const SHAPE: &str = "a version could not be taken apart";

/// One part of an item or environment that the merge decides on its own.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    /// An attribute, by its name in the encoding: `title`, `tags`, `notes`, an unknown key, …
    Attribute(String),
    /// An item's field, by its id.
    Field(FieldId),
    /// An environment's variable, by its name.
    Var(String),
}

/// Where the merged item or environment came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// Every accepted version, in (claimed time, record id) order.
    pub versions: Vec<RecordId>,
    /// The version that won: the deletion, or the edit the rest of the item comes from.
    pub latest: RecordId,
    /// The deletion that won, if the item or environment is deleted.
    pub deleted_by: Option<RecordId>,
    /// For each attribute, field and variable of the result, the version whose value it is.
    pub slots: BTreeMap<Slot, RecordId>,
}

/// One item, as merged from its accepted versions.
pub struct MaterializedItem {
    /// The item's id.
    pub id: ItemId,
    /// The item, or `None` if a deletion won.
    pub item: Option<Item>,
    /// Where it came from.
    pub provenance: Provenance,
}

impl std::fmt::Debug for MaterializedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ids only: nothing the item holds.
        f.debug_struct("MaterializedItem")
            .field("id", &self.id)
            .field("deleted", &self.item.is_none())
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// One environment, as merged from its accepted versions.
pub struct MaterializedEnv {
    /// The environment's id.
    pub id: EnvId,
    /// The environment, or `None` if a deletion won.
    pub env: Option<Environment>,
    /// Where it came from.
    pub provenance: Provenance,
}

impl std::fmt::Debug for MaterializedEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaterializedEnv")
            .field("id", &self.id)
            .field("deleted", &self.env.is_none())
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Item `id` as merged from `view`'s accepted versions of it; `None` if it has none.
///
/// # Errors
///
/// [`SharedError::Malformed`] if a version cannot be taken apart or the merged item does not
/// read back as an item — neither of which a version this build decoded should do.
pub fn materialize_item(view: &SharedView, id: ItemId) -> Result<Option<MaterializedItem>> {
    let Some(merged) = merge(view, &ObjectId::Item(id), &ITEM)? else {
        return Ok(None);
    };
    let item = merged
        .parts
        .map(|parts| {
            let bytes = parts.assemble(&ITEM)?;
            ciborium::from_reader::<Item, _>(bytes.as_slice())
                .map_err(|_| SharedError::Malformed("a merged item does not read as an item"))
        })
        .transpose()?;
    Ok(Some(MaterializedItem {
        id,
        item,
        provenance: merged.provenance,
    }))
}

/// Environment `id` as merged from `view`'s accepted versions of it; `None` if it has none.
///
/// # Errors
///
/// As [`materialize_item`].
pub fn materialize_env(view: &SharedView, id: EnvId) -> Result<Option<MaterializedEnv>> {
    let Some(merged) = merge(view, &ObjectId::Env(id), &ENV)? else {
        return Ok(None);
    };
    let env = merged
        .parts
        .map(|parts| {
            let bytes = parts.assemble(&ENV)?;
            ciborium::from_reader::<Environment, _>(bytes.as_slice()).map_err(|_| {
                SharedError::Malformed("a merged environment does not read as an environment")
            })
        })
        .transpose()?;
    Ok(Some(MaterializedEnv {
        id,
        env,
        provenance: merged.provenance,
    }))
}

/// Every item and environment `view` has versions of, merged, in id order.
///
/// # Errors
///
/// As [`materialize_item`].
pub fn materialize_all(view: &SharedView) -> Result<(Vec<MaterializedItem>, Vec<MaterializedEnv>)> {
    let mut items = Vec::new();
    let mut envs = Vec::new();
    for object in view.objects().keys() {
        match object {
            ObjectId::Item(id) => items.extend(materialize_item(view, *id)?),
            ObjectId::Env(id) => envs.extend(materialize_env(view, *id)?),
        }
    }
    Ok((items, envs))
}

/// How an item or an environment is taken apart.
struct Schema {
    /// The list merged entry by entry.
    list: &'static str,
    /// The key naming an entry of that list.
    entry_key: &'static str,
    /// A list merged as a union, if any.
    union: Option<&'static str>,
}

const ITEM: Schema = Schema {
    list: "fields",
    entry_key: "id",
    union: Some("history"),
};

const ENV: Schema = Schema {
    list: "vars",
    entry_key: "name",
    union: None,
};

const CREATED_AT: &str = "created_at";
const UPDATED_AT: &str = "updated_at";

type Bytes = Zeroizing<Vec<u8>>;

fn copy(bytes: &[u8]) -> Bytes {
    // `to_vec` allocates exactly the length: nothing is left behind by a reallocation.
    Zeroizing::new(bytes.to_vec())
}

/// One version, taken apart.
#[derive(Default)]
struct Parts {
    /// Attributes, by name: their encodings.
    attributes: BTreeMap<String, Bytes>,
    /// The list's entries, by slot, and their order.
    entries: BTreeMap<Slot, Bytes>,
    order: Vec<Slot>,
    /// The union list's items.
    union: Vec<Bytes>,
    created_at: u64,
    updated_at: u64,
}

fn text_of(bytes: &[u8]) -> Result<String> {
    ciborium::from_reader(bytes).map_err(|_| SharedError::Malformed(SHAPE))
}

impl Parts {
    /// Take apart `version`'s encoding. `None` for a deletion.
    fn of(version: &Version, schema: &Schema) -> Result<Option<Self>> {
        let encoded = match version {
            Version::Item(v) if v.item().is_some() => v.encode()?,
            Version::Env(v) if v.env().is_some() => v.encode()?,
            _ => return Ok(None),
        };
        // `{"id": …, "item" | "env": {…}}`: the second is the item or environment.
        let outer = cbor::well_formed_map_entries(&encoded, SHAPE)?;
        let inner = outer
            .iter()
            .find(|(key, _)| cbor::is_text_key(key, "item") || cbor::is_text_key(key, "env"))
            .map(|(_, value)| *value)
            .ok_or(SharedError::Malformed(SHAPE))?;
        let mut parts = Self::default();
        for (key, value) in cbor::well_formed_map_entries(inner, SHAPE)? {
            let name = text_of(key)?;
            if name == schema.list {
                for entry in cbor::well_formed_array_items(value, SHAPE)? {
                    let slot = entry_slot(entry, schema)?;
                    // The first of an entry named twice is the one kept.
                    if !parts.entries.contains_key(&slot) {
                        parts.order.push(slot.clone());
                        parts.entries.insert(slot, copy(entry));
                    }
                }
            } else if Some(name.as_str()) == schema.union {
                parts.union = cbor::well_formed_array_items(value, SHAPE)?
                    .into_iter()
                    .map(copy)
                    .collect();
            } else if name == CREATED_AT {
                parts.created_at =
                    ciborium::from_reader(value).map_err(|_| SharedError::Malformed(SHAPE))?;
            } else if name == UPDATED_AT {
                parts.updated_at =
                    ciborium::from_reader(value).map_err(|_| SharedError::Malformed(SHAPE))?;
            } else {
                parts.attributes.insert(name, copy(value));
            }
        }
        Ok(Some(parts))
    }

    fn get(&self, slot: &Slot) -> Option<&[u8]> {
        match slot {
            Slot::Attribute(name) => self.attributes.get(name),
            _ => self.entries.get(slot),
        }
        .map(|b| b.as_slice())
    }

    fn slots(&self) -> impl Iterator<Item = Slot> + '_ {
        self.attributes
            .keys()
            .map(|name| Slot::Attribute(name.clone()))
            .chain(self.order.iter().cloned())
    }

    /// The encoding of the whole item or environment these parts make.
    fn assemble(&self, schema: &Schema) -> Result<Bytes> {
        fn text_len(text: &str) -> usize {
            cbor::head_len(text.len() as u64) + text.len()
        }
        fn uint_len(value: u64) -> usize {
            cbor::head_len(value)
        }
        let mut count = self.attributes.len() + 3;
        let mut size = 0;
        for (name, value) in &self.attributes {
            size += text_len(name) + value.len();
        }
        size += text_len(schema.list) + cbor::head_len(self.order.len() as u64);
        size += self
            .order
            .iter()
            .map(|s| self.entries[s].len())
            .sum::<usize>();
        size += text_len(CREATED_AT) + uint_len(self.created_at);
        size += text_len(UPDATED_AT) + uint_len(self.updated_at);
        if let Some(union) = schema.union.filter(|_| !self.union.is_empty()) {
            count += 1;
            size += text_len(union) + cbor::head_len(self.union.len() as u64);
            size += self.union.iter().map(|b| b.len()).sum::<usize>();
        }
        size += cbor::head_len(count as u64);

        // Written at exactly its size, so it never reallocates.
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        let text = |out: &mut Vec<u8>, text: &str| {
            cbor::write_head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        };
        cbor::write_head(&mut out, 5, count as u64);
        for (name, value) in &self.attributes {
            text(&mut out, name);
            out.extend_from_slice(value);
        }
        text(&mut out, schema.list);
        cbor::write_head(&mut out, 4, self.order.len() as u64);
        for slot in &self.order {
            out.extend_from_slice(&self.entries[slot]);
        }
        text(&mut out, CREATED_AT);
        cbor::write_head(&mut out, 0, self.created_at);
        text(&mut out, UPDATED_AT);
        cbor::write_head(&mut out, 0, self.updated_at);
        if let Some(union) = schema.union.filter(|_| !self.union.is_empty()) {
            text(&mut out, union);
            cbor::write_head(&mut out, 4, self.union.len() as u64);
            for item in &self.union {
                out.extend_from_slice(item);
            }
        }
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }
}

/// The slot an entry of the list fills: a field by its id, a variable by its name.
fn entry_slot(entry: &[u8], schema: &Schema) -> Result<Slot> {
    let key = cbor::well_formed_map_entries(entry, SHAPE)?
        .into_iter()
        .find(|(key, _)| cbor::is_text_key(key, schema.entry_key))
        .map(|(_, value)| value)
        .ok_or(SharedError::Malformed(SHAPE))?;
    if schema.list == ITEM.list {
        let id: FieldId = ciborium::from_reader(key).map_err(|_| SharedError::Malformed(SHAPE))?;
        Ok(Slot::Field(id))
    } else {
        Ok(Slot::Var(text_of(key)?))
    }
}

/// What the merge decided.
struct Merged {
    parts: Option<Parts>,
    provenance: Provenance,
}

/// The ancestry among one object's accepted versions: which version descends from which,
/// following the parents each names among them. Record ids are hashes over the parents they
/// name, so there is no cycle; a walk still visits each version once whatever it is given.
struct Ancestry {
    index: BTreeMap<RecordId, usize>,
    parents: Vec<Vec<usize>>,
    children: Vec<Vec<usize>>,
}

impl Ancestry {
    fn of(versions: &[&Accepted]) -> Self {
        let index: BTreeMap<RecordId, usize> = versions
            .iter()
            .enumerate()
            .map(|(i, v)| (v.record(), i))
            .collect();
        let mut parents = vec![Vec::new(); versions.len()];
        let mut children = vec![Vec::new(); versions.len()];
        for (i, version) in versions.iter().enumerate() {
            for parent in version.parents() {
                if let Some(&p) = index.get(parent) {
                    parents[i].push(p);
                    children[p].push(i);
                }
            }
        }
        Self {
            index,
            parents,
            children,
        }
    }

    /// Every version reached from `starts` by one step or more: through parents (`up`) the
    /// versions they descend from, through children the versions that descend from them.
    fn reached(&self, starts: impl IntoIterator<Item = usize>, up: bool) -> Vec<bool> {
        let edges = if up { &self.parents } else { &self.children };
        let mut seen = vec![false; edges.len()];
        let mut stack: Vec<usize> = starts
            .into_iter()
            .flat_map(|i| edges[i].iter().copied())
            .collect();
        while let Some(i) = stack.pop() {
            if !seen[i] {
                seen[i] = true;
                stack.extend(edges[i].iter().copied());
            }
        }
        seen
    }

    /// Of `candidates`, the one that wins: those that no other candidate descends from, then the
    /// latest of them in (claimed time, record id) order.
    fn winner<'a>(&self, candidates: &[&'a Accepted]) -> Option<&'a Accepted> {
        let ancestors = self.reached(candidates.iter().map(|c| self.index[&c.record()]), true);
        let heads = candidates
            .iter()
            .filter(|c| !ancestors[self.index[&c.record()]]);
        // Without a cycle there is always a head; with one, every candidate is a head.
        heads
            .max_by_key(|c| c.order_key())
            .or_else(|| candidates.iter().max_by_key(|c| c.order_key()))
            .copied()
    }
}

/// Merge `view`'s accepted versions of `object` (module documentation).
fn merge(view: &SharedView, object: &ObjectId, schema: &Schema) -> Result<Option<Merged>> {
    let versions = view.versions_of(object);
    if versions.is_empty() {
        return Ok(None);
    }
    let mut parts: BTreeMap<RecordId, Option<Parts>> = BTreeMap::new();
    for version in &versions {
        parts.insert(version.record(), Parts::of(version.version(), schema)?);
    }
    let order: Vec<RecordId> = versions.iter().map(|v| v.record()).collect();
    let ancestry = Ancestry::of(&versions);
    let (deletions, all_edits): (Vec<&Accepted>, Vec<&Accepted>) = versions
        .iter()
        .copied()
        .partition(|v| parts[&v.record()].is_none());

    // An edit stands unless a deletion beats it: one that descends from it, or one concurrent
    // with it and later in (claimed time, record id) order. An edit that descends from a
    // deletion beats it.
    let mut standing = vec![true; versions.len()];
    for deletion in &deletions {
        let d = ancestry.index[&deletion.record()];
        let before = ancestry.reached([d], true);
        let after = ancestry.reached([d], false);
        for edit in &all_edits {
            let e = ancestry.index[&edit.record()];
            let beaten = before[e] || (!after[e] && deletion.order_key() > edit.order_key());
            if beaten {
                standing[e] = false;
            }
        }
    }
    // The edits no deletion beats, oldest first.
    let edits: Vec<&Accepted> = all_edits
        .iter()
        .filter(|e| standing[ancestry.index[&e.record()]])
        .copied()
        .collect();
    let Some(latest) = ancestry.winner(&edits) else {
        // Every edit is beaten: the item is deleted, by the deletion that wins among them.
        let deleted_by = ancestry
            .winner(&deletions)
            .expect("a version that is not an edit is a deletion")
            .record();
        return Ok(Some(Merged {
            parts: None,
            provenance: Provenance {
                versions: order,
                latest: deleted_by,
                deleted_by: Some(deleted_by),
                slots: BTreeMap::new(),
            },
        }));
    };
    let of = |record: &RecordId| parts[record].as_ref().expect("an edit");

    // What each version of the whole set sets, against its parents among these versions.
    let sets = |version: &Accepted, slot: &Slot| -> bool {
        let value = parts[&version.record()].as_ref().and_then(|p| p.get(slot));
        let parents: Vec<&Option<Parts>> = version
            .parents()
            .iter()
            .filter_map(|p| parts.get(p))
            .collect();
        if parents.is_empty() {
            return value.is_some();
        }
        parents
            .iter()
            .all(|parent| parent.as_ref().and_then(|p| p.get(slot)) != value)
    };

    let mut merged = Parts::default();
    let mut slots_from: BTreeMap<Slot, RecordId> = BTreeMap::new();
    let mut every_slot: BTreeSet<Slot> = BTreeSet::new();
    for edit in &edits {
        every_slot.extend(of(&edit.record()).slots());
    }
    for slot in &every_slot {
        // The winner among the standing edits that set it; one that no edit set is the latest
        // edit's.
        let setters: Vec<&Accepted> = edits.iter().filter(|e| sets(e, slot)).copied().collect();
        let winner = ancestry.winner(&setters).unwrap_or(latest);
        let Some(value) = of(&winner.record()).get(slot) else {
            continue;
        };
        // Where the value came from: the winner among all versions that set it to this value.
        let same: Vec<&Accepted> = versions
            .iter()
            .filter(|v| {
                parts[&v.record()].as_ref().and_then(|p| p.get(slot)) == Some(value)
                    && sets(v, slot)
            })
            .copied()
            .collect();
        let origin = ancestry.winner(&same).unwrap_or(winner).record();
        slots_from.insert(slot.clone(), origin);
        match slot {
            Slot::Attribute(name) => {
                merged.attributes.insert(name.clone(), copy(value));
            }
            _ => {
                merged.entries.insert(slot.clone(), copy(value));
            }
        }
    }
    // Entries in the latest edit's order, then the others in the order the other edits that
    // hold them give, latest first.
    let mut placed: BTreeSet<Slot> = BTreeSet::new();
    for edit in std::iter::once(&latest).chain(edits.iter().rev()) {
        for slot in &of(&edit.record()).order {
            if merged.entries.contains_key(slot) && placed.insert(slot.clone()) {
                merged.order.push(slot.clone());
            }
        }
    }
    // The union of the edits' retired values, each once, oldest edit's first.
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for edit in &edits {
        for item in &of(&edit.record()).union {
            if seen.insert(item.to_vec()) {
                merged.union.push(copy(item));
            }
        }
    }
    // The set above held copies; wipe them.
    for mut item in std::mem::take(&mut seen) {
        zeroize::Zeroize::zeroize(&mut item);
    }
    merged.created_at = edits
        .iter()
        .map(|e| of(&e.record()).created_at)
        .min()
        .unwrap_or_default();
    merged.updated_at = edits
        .iter()
        .map(|e| of(&e.record()).updated_at)
        .max()
        .unwrap_or_default();
    Ok(Some(Merged {
        parts: Some(merged),
        provenance: Provenance {
            versions: order,
            latest: latest.record(),
            deleted_by: None,
            slots: slots_from,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{EnvVersion, ItemVersion};
    use crate::test_support::test_vault;
    use crate::view::tests::{World, item, put, shuffled, view, world, write};
    use kagisecure_core::model::FieldValue;
    use proptest::prelude::*;

    fn materialized(w: &World, id: ItemId) -> MaterializedItem {
        materialize_item(&view(&w.records, &w.alice), id)
            .unwrap()
            .unwrap()
    }

    fn value(item: &Item, field: FieldId) -> Option<&str> {
        item.fields
            .iter()
            .find(|f| f.id == field)
            .and_then(|f| match &f.value {
                FieldValue::Public(v) => Some(v.as_str()),
                FieldValue::Secret(_) => None,
            })
    }

    #[test]
    fn one_version_reads_back_as_itself() {
        let mut w = world();
        let (id, f) = (ItemId::new(), FieldId::new());
        let mut original = item(id, "a", &[(f, "user", "x")]);
        original.tags = vec!["t".to_owned()];
        original.notes = Some(kagisecure_core::model::SecretText::new("note".to_owned()));
        let version = put(original);
        let encoded = version.encode().unwrap().to_vec();
        let record = write(&mut w, 2, 10, &[], &version);
        let m = materialized(&w, id);
        let again = ItemVersion::put(test_vault(), m.item.unwrap())
            .encode()
            .unwrap();
        assert_eq!(again.as_slice(), encoded.as_slice());
        assert_eq!(m.provenance.latest, record);
        assert!(m.provenance.slots.values().all(|r| *r == record));
    }

    #[test]
    fn concurrent_edits_to_different_fields_are_both_kept() {
        let mut w = world();
        let (id, f, g) = (ItemId::new(), FieldId::new(), FieldId::new());
        let v1 = write(
            &mut w,
            2,
            10,
            &[],
            &put(item(id, "a", &[(f, "f", "1"), (g, "g", "1")])),
        );
        let b = write(
            &mut w,
            2,
            20,
            &[v1],
            &put(item(id, "a", &[(f, "f", "2"), (g, "g", "1")])),
        );
        let c = write(
            &mut w,
            3,
            15,
            &[v1],
            &put(item(id, "c", &[(f, "f", "1"), (g, "g", "3")])),
        );
        let m = materialized(&w, id);
        let merged = m.item.unwrap();
        assert_eq!(merged.title, "c");
        assert_eq!(value(&merged, f), Some("2"));
        assert_eq!(value(&merged, g), Some("3"));
        assert_eq!(m.provenance.slots[&Slot::Field(f)], b);
        assert_eq!(m.provenance.slots[&Slot::Field(g)], c);
        assert_eq!(m.provenance.slots[&Slot::Attribute("title".to_owned())], c);
    }

    #[test]
    fn the_later_write_to_one_field_wins_and_a_tie_goes_to_the_larger_id() {
        let mut w = world();
        let (id, f) = (ItemId::new(), FieldId::new());
        let v1 = write(&mut w, 2, 10, &[], &put(item(id, "a", &[(f, "f", "1")])));
        write(
            &mut w,
            2,
            20,
            &[v1],
            &put(item(id, "a", &[(f, "f", "late")])),
        );
        write(
            &mut w,
            3,
            15,
            &[v1],
            &put(item(id, "a", &[(f, "f", "early")])),
        );
        assert_eq!(value(&materialized(&w, id).item.unwrap(), f), Some("late"));

        let mut w = world();
        let v1 = write(&mut w, 2, 10, &[], &put(item(id, "a", &[(f, "f", "1")])));
        let x = write(&mut w, 2, 20, &[v1], &put(item(id, "a", &[(f, "f", "x")])));
        let y = write(&mut w, 3, 20, &[v1], &put(item(id, "a", &[(f, "f", "y")])));
        let winner = if x > y { "x" } else { "y" };
        assert_eq!(value(&materialized(&w, id).item.unwrap(), f), Some(winner));
    }

    #[test]
    fn a_removed_field_stays_removed_unless_set_later() {
        let mut w = world();
        let (id, f, g) = (ItemId::new(), FieldId::new(), FieldId::new());
        let v1 = write(
            &mut w,
            2,
            10,
            &[],
            &put(item(id, "a", &[(f, "f", "1"), (g, "g", "1")])),
        );
        write(&mut w, 2, 20, &[v1], &put(item(id, "a", &[(g, "g", "1")])));
        write(
            &mut w,
            3,
            15,
            &[v1],
            &put(item(id, "a", &[(f, "f", "1"), (g, "g", "2")])),
        );
        let merged = materialized(&w, id).item.unwrap();
        assert_eq!(value(&merged, f), None);
        assert_eq!(value(&merged, g), Some("2"));
    }

    #[test]
    fn a_deletion_and_an_edit_are_ordered_by_time() {
        let mut w = world();
        let (id, f) = (ItemId::new(), FieldId::new());
        let v1 = write(&mut w, 2, 10, &[], &put(item(id, "a", &[(f, "f", "1")])));
        let deletion = write(&mut w, 3, 20, &[v1], &ItemVersion::delete(id));
        write(&mut w, 2, 15, &[v1], &put(item(id, "b", &[(f, "f", "2")])));
        let m = materialized(&w, id);
        assert!(m.item.is_none());
        assert_eq!(m.provenance.deleted_by, Some(deletion));

        let revived = write(&mut w, 2, 30, &[v1], &put(item(id, "c", &[(f, "f", "1")])));
        let m = materialized(&w, id);
        let item = m.item.unwrap();
        // Built from the edits after the deletion only: the edit at 15 is not in it.
        assert_eq!(item.title, "c");
        assert_eq!(value(&item, f), Some("1"));
        assert_eq!(m.provenance.latest, revived);
    }

    /// The bug decision 80's first text had: an edit written in the same second as the version
    /// it edits — a new item's edit sheet saved right after it was created from its template —
    /// lost to that version whenever its record id happened to be the smaller.
    #[test]
    fn an_edit_in_the_same_second_beats_the_version_it_edits() {
        let (id, f) = (ItemId::new(), FieldId::new());
        let mut smaller_seen = false;
        for _ in 0..64 {
            let mut w = world();
            let created = write(&mut w, 2, 10, &[], &put(item(id, "", &[(f, "f", "")])));
            let edited = write(
                &mut w,
                2,
                10,
                &[created],
                &put(item(id, "mine", &[(f, "f", "x")])),
            );
            let m = materialized(&w, id);
            let merged = m.item.unwrap();
            assert_eq!(merged.title, "mine");
            assert_eq!(value(&merged, f), Some("x"));
            assert_eq!(m.provenance.latest, edited);
            assert_eq!(m.provenance.slots[&Slot::Field(f)], edited);
            smaller_seen |= edited < created;
            if smaller_seen {
                break;
            }
        }
        assert!(smaller_seen, "the edit's id was never the smaller");
    }

    #[test]
    fn a_descendant_beats_its_ancestor_whatever_their_clocks_say() {
        let mut w = world();
        let (id, f) = (ItemId::new(), FieldId::new());
        let v1 = write(&mut w, 2, 50, &[], &put(item(id, "a", &[(f, "f", "1")])));
        // Carol's clock is behind: her edit on v1 claims an earlier time than v1.
        let v2 = write(&mut w, 3, 40, &[v1], &put(item(id, "b", &[(f, "f", "1")])));
        // Bob, concurrent with Carol, changes the field later than v1.
        let v3 = write(&mut w, 2, 60, &[v1], &put(item(id, "a", &[(f, "f", "3")])));
        let m = materialized(&w, id);
        let merged = m.item.unwrap();
        assert_eq!(merged.title, "b");
        assert_eq!(value(&merged, f), Some("3"));
        assert_eq!(m.provenance.slots[&Slot::Attribute("title".to_owned())], v2);
        assert_eq!(m.provenance.slots[&Slot::Field(f)], v3);

        // A concurrent edit to the same attribute is still ordered by time: 45 beats 40.
        let v4 = write(&mut w, 2, 45, &[v1], &put(item(id, "c", &[(f, "f", "1")])));
        let m = materialized(&w, id);
        assert_eq!(m.item.unwrap().title, "c");
        assert_eq!(m.provenance.slots[&Slot::Attribute("title".to_owned())], v4);
    }

    #[test]
    fn a_deletion_and_an_edit_follow_ancestry_before_time() {
        let mut w = world();
        let (id, f) = (ItemId::new(), FieldId::new());
        let v1 = write(&mut w, 2, 50, &[], &put(item(id, "a", &[(f, "f", "1")])));
        // Deleted on v1 by a device whose clock is behind.
        let deletion = write(&mut w, 3, 40, &[v1], &ItemVersion::delete(id));
        let m = materialized(&w, id);
        assert!(m.item.is_none());
        assert_eq!(m.provenance.deleted_by, Some(deletion));
        assert_eq!(m.provenance.latest, deletion);

        // Restored on the deletion, in the same second: back.
        let restored = write(
            &mut w,
            3,
            40,
            &[deletion],
            &put(item(id, "b", &[(f, "f", "1")])),
        );
        let m = materialized(&w, id);
        assert_eq!(m.item.unwrap().title, "b");
        assert_eq!(m.provenance.latest, restored);
    }

    #[test]
    fn an_environment_merges_by_variable_name() {
        use kagisecure_core::model::{Environment, VarSource};
        use kagisecure_core::proto::VarName;
        let mut w = world();
        let env = |vars: &[(&str, &str)]| {
            let mut env = Environment::new(test_vault(), "ci");
            env.id = EnvId(uuid::Uuid::from_bytes([3; 16]));
            env.created_at = 1;
            env.updated_at = 1;
            for (name, hint) in vars {
                env.set_var(
                    VarName::new(*name).unwrap(),
                    VarSource::Pending {
                        hint: Some((*hint).to_owned()),
                    },
                );
            }
            EnvVersion::put(test_vault(), env)
        };
        let seal = |w: &mut World, who: u8, at: u64, parents: &[RecordId], v: &EnvVersion| {
            let (head, e0) = (w.head, w.e0);
            let writer = if who == 2 { &mut w.bob } else { &mut w.carol };
            let mut header = writer.header(&[head], Some(e0));
            header.parents = parents.to_vec();
            header.created_at = at;
            let envelope = v.seal(&writer.device, header, &w.k0).unwrap();
            let envelope = writer.wrote(envelope);
            w.records.push(envelope)
        };
        let v1 = seal(&mut w, 2, 10, &[], &env(&[("A", "1")]));
        seal(&mut w, 2, 20, &[v1], &env(&[("A", "2")]));
        seal(&mut w, 3, 15, &[v1], &env(&[("A", "1"), ("B", "3")]));
        let m = materialize_env(
            &view(&w.records, &w.alice),
            EnvId(uuid::Uuid::from_bytes([3; 16])),
        )
        .unwrap()
        .unwrap();
        let merged = m.env.unwrap();
        let names: Vec<&str> = merged.vars.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["A", "B"]);
        assert!(matches!(
            &merged.var("A").unwrap().source,
            VarSource::Pending { hint: Some(h) } if h == "2"
        ));
    }

    /// A digest of a merged item: its encoding and where it came from.
    fn digest(m: &MaterializedItem) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Wire<'a> {
            item: Option<&'a Item>,
        }
        let mut out = format!("{:?}", m.provenance).into_bytes();
        ciborium::into_writer(
            &Wire {
                item: m.item.as_ref(),
            },
            &mut out,
        )
        .unwrap();
        out
    }

    /// One step of a random history: who writes, when, on which earlier versions, and what.
    #[derive(Clone, Debug)]
    struct Step {
        who: u8,
        at: u64,
        parents: Vec<prop::sample::Index>,
        title: u8,
        field: Option<u8>,
        delete: bool,
    }

    fn step() -> impl Strategy<Value = Step> {
        (
            2u8..4,
            0u64..6,
            proptest::collection::vec(any::<prop::sample::Index>(), 0..3),
            0u8..3,
            proptest::option::of(0u8..3),
            proptest::bool::weighted(0.2),
        )
            .prop_map(|(who, at, parents, title, field, delete)| Step {
                who,
                at,
                parents,
                title,
                field,
                delete,
            })
    }

    /// Write `steps` as versions of item `id`: each on the earlier versions its `parents` pick,
    /// or, with `chain`, on the one before it.
    fn history(
        w: &mut World,
        id: ItemId,
        f: FieldId,
        steps: &[Step],
        chain: bool,
    ) -> Vec<RecordId> {
        let mut written: Vec<RecordId> = Vec::new();
        for s in steps {
            let mut parents: Vec<RecordId> = if written.is_empty() {
                vec![]
            } else if chain {
                vec![*written.last().unwrap()]
            } else {
                s.parents.iter().map(|i| *i.get(&written)).collect()
            };
            parents.sort();
            parents.dedup();
            written.push(write(w, s.who, s.at, &parents, &version_of(id, f, s)));
        }
        written
    }

    fn version_of(id: ItemId, f: FieldId, s: &Step) -> ItemVersion {
        if s.delete {
            ItemVersion::delete(id)
        } else {
            let fields: Vec<(FieldId, &str, &str)> = s
                .field
                .map(|v| vec![(f, "f", ["x", "y", "z"][usize::from(v)])])
                .unwrap_or_default();
            put(item(id, ["a", "b", "c"][usize::from(s.title)], &fields))
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Any order, any repetition: the same item (ADR-0035 §8).
        #[test]
        fn the_merge_converges_whatever_the_order(
            steps in proptest::collection::vec(step(), 1..8),
            seed in any::<u64>(),
            repeats in proptest::collection::vec(any::<prop::sample::Index>(), 0..6),
        ) {
            let mut w = world();
            let (id, f) = (ItemId::new(), FieldId::new());
            history(&mut w, id, f, &steps, false);
            let expected = materialize_item(&view(&w.records, &w.alice), id).unwrap().unwrap();
            let records = shuffled(&w.records.records, seed, &repeats);
            for device in [&w.alice, &w.bob] {
                let v = SharedView::compute(
                    &test_vault(), &w.records.genesis, &records, &device.device,
                ).unwrap();
                let got = materialize_item(&v, id).unwrap().unwrap();
                prop_assert_eq!(digest(&got), digest(&expected));
            }
        }

        /// A history where each version edits the one before: whatever times the authors
        /// claim, the item is the last version — each version beats every one it descends from.
        #[test]
        fn a_chain_of_edits_ends_in_its_last_version(
            steps in proptest::collection::vec(step(), 1..8),
        ) {
            let mut w = world();
            let (id, f) = (ItemId::new(), FieldId::new());
            let written = history(&mut w, id, f, &steps, true);
            let m = materialized(&w, id);
            let last = steps.last().unwrap();
            prop_assert_eq!(m.provenance.latest, *written.last().unwrap());
            if last.delete {
                prop_assert!(m.item.is_none());
            } else {
                let merged = m.item.unwrap();
                prop_assert_eq!(merged.title.as_str(), ["a", "b", "c"][usize::from(last.title)]);
                prop_assert_eq!(
                    value(&merged, f),
                    last.field.map(|v| ["x", "y", "z"][usize::from(v)])
                );
            }
        }

        /// An edit made on every version there is wins what it changes, even claiming the
        /// earliest time of all; a deletion made so deletes the item.
        #[test]
        fn a_version_on_everything_wins(
            steps in proptest::collection::vec(step(), 1..8),
            delete in any::<bool>(),
        ) {
            let mut w = world();
            let (id, f) = (ItemId::new(), FieldId::new());
            let written = history(&mut w, id, f, &steps, false);
            // The versions no other names.
            let v = view(&w.records, &w.alice);
            let named: BTreeSet<RecordId> = v
                .versions_of(&ObjectId::Item(id))
                .iter()
                .flat_map(|v| v.parents().iter().copied())
                .collect();
            let heads: Vec<RecordId> =
                written.iter().copied().filter(|r| !named.contains(r)).collect();
            let last = if delete {
                ItemVersion::delete(id)
            } else {
                put(item(id, "fresh", &[(f, "f", "fresh")]))
            };
            let on_top = write(&mut w, 3, 0, &heads, &last);
            let m = materialized(&w, id);
            prop_assert_eq!(m.provenance.latest, on_top);
            if delete {
                prop_assert!(m.item.is_none());
            } else {
                let merged = m.item.unwrap();
                prop_assert_eq!(merged.title.as_str(), "fresh");
                prop_assert_eq!(value(&merged, f), Some("fresh"));
            }
        }
    }
}

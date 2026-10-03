//! What an item or environment record carries, once decrypted (ADR-0035 §8, §14; addendum,
//! decisions 7, 22).
//!
//! Every item record carries the whole item as of that version — or, for a deletion, only its id
//! — and every environment record the whole environment. The plaintext is a CBOR map:
//!
//! ```text
//! ItemVersion := { "id": ItemId, "item": Item | null }        # null: deleted
//! EnvVersion  := { "id": EnvId,  "env":  Environment | null }  # null: deleted
//! ```
//!
//! with `Item` and `Environment` encoded exactly as the personal vault's body encodes them
//! (vault-format §5), so an item's unknown keys survive a shared vault the way they survive the
//! personal one.
//!
//! # Local-only fields never travel
//!
//! Whether an agent may see an item, a field or an environment, whether an item is a favourite,
//! and an environment's `default_paths` are this device's own settings (decision 22). They are
//! cleared when a version is **written**, so they never leave this computer, and cleared again
//! when one is **read**, so a record that sets them — written by an older or a hostile build —
//! cannot make anything visible to this device's agents: everything received from a shared vault
//! starts hidden (ADR-0035 §14, threat-model M-9). The item's and environment's `vault_id` is set
//! to the shared vault's id on writing (the author's personal logical vault is nobody else's
//! business) and must match the record's on reading.
//!
//! # Read strictly
//!
//! The plaintext is `serde`'s encoding, with map keys in field order rather than sorted, so it is
//! not deterministic CBOR and is not required to be. It is still read strictly: scanned before it
//! is decoded (`crate::cbor::scan`) and refused unless it is exactly one well-formed item with
//! shortest heads, no key twice in any map and nothing after it (a map or array may have an
//! indefinite length, which is how `serde` writes an item's flattened unknown keys). A key given
//! twice is the case that matters: one reader would take the first value and another the last,
//! and one record would then say two things.

use kagisecure_core::model::{Environment, Item};
use kagisecure_core::proto::{EnvId, ItemId, VaultId};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cbor::{self, Strictness};
use crate::device::DeviceSecret;
use crate::epoch_key::EpochKey;
use crate::error::{Result, SharedError};
use crate::record::{Envelope, NewRecord, RecordKind, VerifiedRecord};

/// Clear what is local to one device from an item (module documentation).
fn clear_local_item(item: &mut Item) {
    item.agent_visible = false;
    item.favorite = false;
    for field in &mut item.fields {
        field.agent_visible = false;
    }
}

/// Clear what is local to one device from an environment (module documentation).
fn clear_local_env(env: &mut Environment) {
    env.agent_visible = false;
    env.default_paths.clear();
}

/// Counts what an encoder writes, and keeps none of it.
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encode a payload into a zeroizing buffer: it holds secret values.
///
/// The encoding is measured first, into a writer that keeps nothing, and the buffer allocated at
/// exactly that size, so writing into it never reallocates — a reallocation would leave an
/// unwiped copy of everything written so far behind in the old allocation.
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    const REFUSED: SharedError = SharedError::Malformed("a version could not be encoded");
    let mut counter = Counter(0);
    ciborium::into_writer(value, &mut counter).map_err(|_| REFUSED)?;
    let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
    let capacity = out.capacity();
    ciborium::into_writer(value, &mut *out).map_err(|_| REFUSED)?;
    // The same value encodes to the same length both times, so the buffer never grew.
    debug_assert_eq!(out.len(), counter.0);
    debug_assert_eq!(out.capacity(), capacity);
    Ok(out)
}

/// One version of an item: the whole item, or its deletion.
#[derive(Debug)]
pub struct ItemVersion {
    id: ItemId,
    item: Option<Item>,
}

#[derive(Serialize)]
struct ItemWireRef<'a> {
    id: ItemId,
    item: Option<&'a Item>,
}

#[derive(Deserialize)]
struct ItemWire {
    id: ItemId,
    item: Option<Item>,
}

impl ItemVersion {
    /// `item` as it now is, for shared vault `vault_id`: its `vault_id` set to the shared
    /// vault's and its local-only fields cleared.
    #[must_use]
    pub fn put(vault_id: VaultId, mut item: Item) -> Self {
        item.vault_id = vault_id;
        clear_local_item(&mut item);
        Self {
            id: item.id,
            item: Some(item),
        }
    }

    /// The deletion of item `id`.
    #[must_use]
    pub const fn delete(id: ItemId) -> Self {
        Self { id, item: None }
    }

    /// The item's id.
    #[must_use]
    pub const fn id(&self) -> ItemId {
        self.id
    }

    /// The item, or `None` if this version deletes it.
    #[must_use]
    pub const fn item(&self) -> Option<&Item> {
        self.item.as_ref()
    }

    /// The item, taken out.
    #[must_use]
    pub fn into_item(self) -> Option<Item> {
        self.item
    }

    /// The plaintext, in a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] if the item cannot be encoded.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        encode(&ItemWireRef {
            id: self.id,
            item: self.item.as_ref(),
        })
    }

    /// Read a plaintext written for shared vault `vault_id`, clearing local-only fields.
    ///
    /// It is read strictly (module documentation): exactly one well-formed CBOR item, scanned
    /// before it is decoded, so trailing bytes or a key given twice — which two readers could
    /// resolve differently — are refused rather than read one way.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] if it is not a version, is not read strictly, or names an item
    /// or vault other than its own.
    pub fn decode(bytes: &[u8], vault_id: &VaultId) -> Result<Self> {
        cbor::scan(bytes, Strictness::WellFormed)?;
        let wire: ItemWire = ciborium::from_reader(bytes)
            .map_err(|_| SharedError::Malformed("not an item version"))?;
        let mut item = wire.item;
        if let Some(item) = &mut item {
            if item.id != wire.id {
                return Err(SharedError::Malformed(
                    "an item version's item has another id",
                ));
            }
            if item.vault_id != *vault_id {
                return Err(SharedError::Malformed(
                    "an item version's item is in another vault",
                ));
            }
            clear_local_item(item);
        }
        Ok(Self { id: wire.id, item })
    }

    /// Write this version as an item record signed by `author`, sealed under `epoch_key` (the
    /// key of `record.epoch`).
    ///
    /// # Errors
    ///
    /// As [`Envelope::seal`], and [`SharedError::Malformed`] if the item is in another vault.
    pub fn seal(
        &self,
        author: &DeviceSecret,
        record: NewRecord,
        epoch_key: &EpochKey,
    ) -> Result<Envelope> {
        if self
            .item
            .as_ref()
            .is_some_and(|i| i.vault_id != record.vault_id)
        {
            return Err(SharedError::Malformed(
                "an item version's item is in another vault",
            ));
        }
        Envelope::seal(author, RecordKind::Item, record, epoch_key, &self.encode()?)
    }

    /// Decrypt and read an item record.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] for a record of another kind or a payload that is not an item
    /// version for the record's vault; [`SharedError::Decrypt`] as for
    /// [`VerifiedRecord::open_payload`].
    pub fn open(record: &VerifiedRecord, epoch_key: &EpochKey) -> Result<Self> {
        if record.body().kind() != &RecordKind::Item {
            return Err(SharedError::Malformed("not an item record"));
        }
        Self::decode(&record.open_payload(epoch_key)?, record.body().vault_id())
    }
}

/// One version of an environment: the whole environment, or its deletion.
#[derive(Debug)]
pub struct EnvVersion {
    id: EnvId,
    env: Option<Environment>,
}

#[derive(Serialize)]
struct EnvWireRef<'a> {
    id: EnvId,
    env: Option<&'a Environment>,
}

#[derive(Deserialize)]
struct EnvWire {
    id: EnvId,
    env: Option<Environment>,
}

impl EnvVersion {
    /// `env` as it now is, for shared vault `vault_id`: its `vault_id` set to the shared vault's
    /// and its local-only fields cleared.
    #[must_use]
    pub fn put(vault_id: VaultId, mut env: Environment) -> Self {
        env.vault_id = vault_id;
        clear_local_env(&mut env);
        Self {
            id: env.id,
            env: Some(env),
        }
    }

    /// The deletion of environment `id`.
    #[must_use]
    pub const fn delete(id: EnvId) -> Self {
        Self { id, env: None }
    }

    /// The environment's id.
    #[must_use]
    pub const fn id(&self) -> EnvId {
        self.id
    }

    /// The environment, or `None` if this version deletes it.
    #[must_use]
    pub const fn env(&self) -> Option<&Environment> {
        self.env.as_ref()
    }

    /// The environment, taken out.
    #[must_use]
    pub fn into_env(self) -> Option<Environment> {
        self.env
    }

    /// The plaintext, in a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] if the environment cannot be encoded.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        encode(&EnvWireRef {
            id: self.id,
            env: self.env.as_ref(),
        })
    }

    /// Read a plaintext written for shared vault `vault_id`, clearing local-only fields. Read
    /// as strictly as [`ItemVersion::decode`] reads.
    ///
    /// # Errors
    ///
    /// [`SharedError::Malformed`] if it is not a version, is not read strictly, or names an
    /// environment or vault other than its own.
    pub fn decode(bytes: &[u8], vault_id: &VaultId) -> Result<Self> {
        cbor::scan(bytes, Strictness::WellFormed)?;
        let wire: EnvWire = ciborium::from_reader(bytes)
            .map_err(|_| SharedError::Malformed("not an environment version"))?;
        let mut env = wire.env;
        if let Some(env) = &mut env {
            if env.id != wire.id {
                return Err(SharedError::Malformed(
                    "an environment version's environment has another id",
                ));
            }
            if env.vault_id != *vault_id {
                return Err(SharedError::Malformed(
                    "an environment version's environment is in another vault",
                ));
            }
            clear_local_env(env);
        }
        Ok(Self { id: wire.id, env })
    }

    /// Write this version as an environment record signed by `author`, sealed under
    /// `epoch_key` (the key of `record.epoch`).
    ///
    /// # Errors
    ///
    /// As [`Envelope::seal`], and [`SharedError::Malformed`] if the environment is in another
    /// vault.
    pub fn seal(
        &self,
        author: &DeviceSecret,
        record: NewRecord,
        epoch_key: &EpochKey,
    ) -> Result<Envelope> {
        if self
            .env
            .as_ref()
            .is_some_and(|e| e.vault_id != record.vault_id)
        {
            return Err(SharedError::Malformed(
                "an environment version's environment is in another vault",
            ));
        }
        Envelope::seal(author, RecordKind::Env, record, epoch_key, &self.encode()?)
    }

    /// Decrypt and read an environment record.
    ///
    /// # Errors
    ///
    /// As [`ItemVersion::open`], for environments.
    pub fn open(record: &VerifiedRecord, epoch_key: &EpochKey) -> Result<Self> {
        if record.body().kind() != &RecordKind::Env {
            return Err(SharedError::Malformed("not an environment record"));
        }
        Self::decode(&record.open_payload(epoch_key)?, record.body().vault_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_key::{EpochId, fixed_epoch_key};
    use crate::record::tests::vault;
    use crate::test_support::golden_device;
    use kagisecure_core::Secret;
    use kagisecure_core::model::{Category, Field, VarSource};
    use kagisecure_core::proto::VarName;

    fn header() -> NewRecord {
        NewRecord {
            vault_id: vault(),
            seq: 0,
            prev: None,
            parents: vec![],
            roster: vec![],
            epoch: Some(EpochId::from_bytes([1; 16])),
            created_at: 1,
        }
    }

    fn local_item() -> Item {
        let mut item = Item::new(VaultId::new(), Category::Login, "Database");
        item.favorite = true;
        item.agent_visible = true;
        let mut password = Field::concealed("password", Secret::from_string("s3cret".to_owned()));
        password.agent_visible = true;
        item.fields.push(Field::public("username", "admin"));
        item.fields.push(password);
        item
    }

    fn local_env() -> Environment {
        let mut env = Environment::new(VaultId::new(), "api / staging");
        env.agent_visible = true;
        env.default_paths.push("/home/someone/project".to_owned());
        env.set_var(
            VarName::new("API_KEY").unwrap(),
            VarSource::Literal(Secret::from_string("k".to_owned())),
        );
        env
    }

    #[test]
    fn a_writer_clears_local_only_fields_and_sets_the_shared_vault() {
        let version = ItemVersion::put(vault(), local_item());
        let item = version.item().unwrap();
        assert_eq!(item.vault_id, vault());
        assert!(!item.favorite);
        assert!(!item.agent_visible);
        assert!(item.fields.iter().all(|f| !f.agent_visible));

        let version = EnvVersion::put(vault(), local_env());
        let env = version.env().unwrap();
        assert_eq!(env.vault_id, vault());
        assert!(!env.agent_visible);
        assert!(env.default_paths.is_empty());
    }

    /// A version that sets them anyway — an older or hostile writer — reads back with them
    /// cleared: nothing received starts visible to an agent.
    #[test]
    fn a_reader_clears_local_only_fields_whatever_the_writer_did() {
        let mut item = local_item();
        item.vault_id = vault();
        let bytes = encode(&ItemWireRef {
            id: item.id,
            item: Some(&item),
        })
        .unwrap();
        let read = ItemVersion::decode(&bytes, &vault()).unwrap();
        let read = read.item().unwrap();
        assert!(!read.favorite && !read.agent_visible);
        assert!(read.fields.iter().all(|f| !f.agent_visible));
        assert_eq!(read.fields.len(), 2);
        assert_eq!(
            read.fields[1].value.as_secret().unwrap().expose(),
            b"s3cret"
        );

        let mut env = local_env();
        env.vault_id = vault();
        let bytes = encode(&EnvWireRef {
            id: env.id,
            env: Some(&env),
        })
        .unwrap();
        let read = EnvVersion::decode(&bytes, &vault()).unwrap();
        let read = read.env().unwrap();
        assert!(!read.agent_visible);
        assert!(read.default_paths.is_empty());
        assert_eq!(read.vars.len(), 1);
    }

    #[test]
    fn an_item_record_round_trips_through_seal_verify_and_open() {
        let device = golden_device();
        let key = fixed_epoch_key(9);
        let version = ItemVersion::put(vault(), local_item());
        let id = version.id();
        let envelope = version.seal(&device, header(), &key).unwrap();
        let record = Envelope::parse(envelope.to_bytes())
            .unwrap()
            .verify(device.public(), &vault())
            .unwrap();
        let back = ItemVersion::open(&record, &key).unwrap();
        assert_eq!(back.id(), id);
        let item = back.into_item().unwrap();
        assert_eq!(item.title, "Database");
        assert_eq!(item.username(), Some("admin"));
        // Neither an environment nor with the wrong key.
        assert!(EnvVersion::open(&record, &key).is_err());
        assert!(matches!(
            ItemVersion::open(&record, &fixed_epoch_key(8)),
            Err(SharedError::Decrypt)
        ));
    }

    #[test]
    fn deletions_round_trip_for_items_and_environments() {
        let device = golden_device();
        let key = fixed_epoch_key(9);
        let item_id = ItemId::new();
        let record = ItemVersion::delete(item_id)
            .seal(&device, header(), &key)
            .unwrap()
            .verify(device.public(), &vault())
            .unwrap();
        let back = ItemVersion::open(&record, &key).unwrap();
        assert_eq!(back.id(), item_id);
        assert!(back.item().is_none());

        let env_id = EnvId::new();
        let record = EnvVersion::delete(env_id)
            .seal(&device, header(), &key)
            .unwrap()
            .verify(device.public(), &vault())
            .unwrap();
        assert_eq!(record.body().kind(), &RecordKind::Env);
        let back = EnvVersion::open(&record, &key).unwrap();
        assert_eq!(back.id(), env_id);
        assert!(back.env().is_none());
    }

    #[test]
    fn an_environment_record_round_trips() {
        let device = golden_device();
        let key = fixed_epoch_key(9);
        let record = EnvVersion::put(vault(), local_env())
            .seal(&device, header(), &key)
            .unwrap()
            .verify(device.public(), &vault())
            .unwrap();
        let env = EnvVersion::open(&record, &key).unwrap().into_env().unwrap();
        assert_eq!(env.name, "api / staging");
        assert_eq!(env.vars[0].name, "API_KEY");
    }

    #[test]
    fn a_version_naming_another_item_or_vault_is_refused() {
        let mut item = local_item();
        item.vault_id = vault();
        let other_id = encode(&ItemWireRef {
            id: ItemId::new(),
            item: Some(&item),
        })
        .unwrap();
        assert!(ItemVersion::decode(&other_id, &vault()).is_err());
        let right = encode(&ItemWireRef {
            id: item.id,
            item: Some(&item),
        })
        .unwrap();
        assert!(ItemVersion::decode(&right, &VaultId::new()).is_err());
        assert!(ItemVersion::decode(b"\xa0", &vault()).is_err());

        // Sealing into a vault the version was not made for is refused too.
        let version = ItemVersion::put(VaultId::new(), local_item());
        assert!(
            version
                .seal(&golden_device(), header(), &fixed_epoch_key(1))
                .is_err()
        );
    }

    /// Trailing bytes and a key given twice — at the top or inside the item, where an unknown
    /// key would otherwise be kept as whichever copy a reader happened to take — are refused.
    #[test]
    fn a_version_not_read_strictly_is_refused() {
        let mut item = local_item();
        item.vault_id = vault();
        let right = encode(&ItemWireRef {
            id: item.id,
            item: Some(&item),
        })
        .unwrap();
        assert!(ItemVersion::decode(&right, &vault()).is_ok());
        let mut trailing = right.to_vec();
        trailing.push(0x00);
        assert!(matches!(
            ItemVersion::decode(&trailing, &vault()),
            Err(SharedError::Malformed(_))
        ));

        let ciborium::Value::Map(mut entries) =
            ciborium::from_reader::<ciborium::Value, _>(right.as_slice()).unwrap()
        else {
            unreachable!()
        };
        let (_, ciborium::Value::Map(fields)) = &mut entries[1] else {
            unreachable!()
        };
        for value in [1, 2] {
            fields.push((
                ciborium::Value::Text("zz-unknown".into()),
                ciborium::Value::Integer(value.into()),
            ));
        }
        let nested = cbor::encode(&ciborium::Value::Map(entries.clone()));
        let (_, first) = entries[0].clone();
        entries.push((ciborium::Value::Text("id".into()), first));
        let top = cbor::encode(&ciborium::Value::Map(entries));
        for bytes in [nested, top] {
            assert!(matches!(
                ItemVersion::decode(&bytes, &vault()),
                Err(SharedError::Malformed(_))
            ));
        }

        let mut env = local_env();
        env.vault_id = vault();
        let mut trailing = encode(&EnvWireRef {
            id: env.id,
            env: Some(&env),
        })
        .unwrap()
        .to_vec();
        trailing.push(0xf6);
        assert!(EnvVersion::decode(&trailing, &vault()).is_err());
    }

    /// A version larger than any fixed reservation is encoded into a buffer of exactly its
    /// size: nothing reallocated, so no unwiped copy was left behind.
    #[test]
    fn a_large_version_is_encoded_without_reallocating() {
        let mut item = local_item();
        item.fields.push(Field::concealed(
            "long",
            Secret::from_string("x".repeat(64 * 1024)),
        ));
        let bytes = ItemVersion::put(vault(), item).encode().unwrap();
        assert!(bytes.len() > 64 * 1024);
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn debug_of_a_version_renders_no_secret_value() {
        let version = ItemVersion::put(vault(), local_item());
        let rendered = format!("{version:?}");
        assert!(rendered.contains("Database"));
        assert!(!rendered.contains("s3cret"), "{rendered}");
        let version = EnvVersion::put(vault(), local_env());
        assert!(!format!("{version:?}").contains("\"k\""));
    }
}

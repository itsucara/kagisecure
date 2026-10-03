//! Shared-vault device keys, held in the personal vault body (ADR-0035 §5).
//!
//! A device key is this computer's own key pair for every shared vault it belongs to: an X25519
//! key that epoch keys are wrapped to and an Ed25519 key that signs its records. The public halves
//! travel in shared vaults' rosters; the secret halves live only here, inside the personal vault's
//! encrypted body, as [`Secret`]s. So a device key is usable exactly while the personal vault is
//! unlocked, through the same password, platform or recovery slot, and no new unlock path or
//! entitlement exists for it.
//!
//! **Device keys are not items.** They have no category, are never agent-visible, are never
//! covered by `item show --reveal`, are never exported and are never shown. [`DeviceKey`] has no
//! `Serialize`, no `Deserialize`, no `Clone` and a `Debug` that prints no key material; the one
//! encoding of a device key is the crate-private one below, used only for the body inside the
//! vault's AEAD.
//!
//! This crate does no public-key cryptography: it stores the key material a caller produced and
//! hands it back. Generating the keys and deriving the device key id from their public halves
//! (ADR-0035 addendum, "Device key id") belong to `kagisecure-shared`.
//!
//! # Retired device keys
//!
//! Removing a device key records its id in the body's `retired_devices` list (ids only, no key
//! material). The list only grows: a retired id can never be added again, and nothing that
//! combines two versions of a vault — "keep this app's version" today, whatever merges personal
//! vaults later — brings a retired key back. That keeps a removal, which is usually someone
//! retiring a computer, from being undone by an older copy of the file.
//!
//! **Which device key is usable** (for `kagisecure-shared`, Phases 1 and 2): one that is in the
//! personal vault's device list, **and** not in its retired list
//! (`Vault::active_device_keys` applies both), **and** not removed in the roster of the shared
//! vault in question. Any of the three alone is not enough.
//!
//! A body that holds any device key is written as `format_ver` 2
//! ([`super::header::DEVICE_KEYS_FORMAT_VERSION`]), so that a build predating the unknown-key
//! passthrough refuses the file rather than open it and drop the keys on its next save.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::Secret;

/// Length of a device key id: a SHA-256 digest of the suite and the public keys.
pub const DEVICE_KEY_ID_LEN: usize = 32;

/// The suite every device key this build knows how to use is created for: X25519 for wrapping
/// epoch keys (HPKE, RFC 9180), Ed25519 for signing records (RFC 8032).
pub const SUITE_X25519_ED25519_V1: &str = "x25519-ed25519-v1";

/// Length of the secret key material of a [`SUITE_X25519_ED25519_V1`] device key: the 32-byte
/// X25519 secret key followed by the 32-byte Ed25519 seed.
pub const X25519_ED25519_V1_SECRET_LEN: usize = 64;

/// The longest device label, in characters (ADR-0035 addendum, limits).
pub const MAX_DEVICE_LABEL_CHARS: usize = 128;

/// One device key: this computer's key pair for shared vaults. See the module documentation.
///
/// Built with [`DeviceKey::new`], added with `Tx::add_device_key` and read back with
/// `Vault::device_keys`.
pub struct DeviceKey {
    id: [u8; DEVICE_KEY_ID_LEN],
    suite: String,
    label: String,
    created_at: u64,
    secret_keys: Secret,
    /// Keys of this entry that this build does not recognize, preserved (vault-format §9 rule 1).
    ///
    /// **Not zeroized, and not for secrets.** These are ordinary `ciborium::Value`s, dropped
    /// without being wiped. A later format that adds secret material to a device key must not
    /// rely on this passthrough to carry it — it needs a named `Secret` field, and a build that
    /// knows it.
    unknown: BTreeMap<String, ciborium::Value>,
}

impl DeviceKey {
    /// A device key for `suite`, with the secret key material `secret_keys` a caller generated
    /// and the `id` it derived from the matching public keys.
    ///
    /// Only [`SUITE_X25519_ED25519_V1`] is accepted, with exactly
    /// [`X25519_ED25519_V1_SECRET_LEN`] bytes of secret key material. A key read from a file
    /// written by a newer build may carry another suite; it is kept as it is, but this build does
    /// not create one.
    ///
    /// # Errors
    ///
    /// [`Error::DeviceKey`] for another suite, secret key material of the wrong length, or a
    /// label longer than [`MAX_DEVICE_LABEL_CHARS`] characters.
    pub fn new(
        id: [u8; DEVICE_KEY_ID_LEN],
        suite: &str,
        label: &str,
        created_at: u64,
        secret_keys: Secret,
    ) -> Result<Self> {
        if suite != SUITE_X25519_ED25519_V1 {
            return Err(Error::DeviceKey(
                "this build creates device keys only for suite x25519-ed25519-v1",
            ));
        }
        if secret_keys.len() != X25519_ED25519_V1_SECRET_LEN {
            return Err(Error::DeviceKey(
                "the secret keys of an x25519-ed25519-v1 device key are 64 bytes",
            ));
        }
        if label.chars().count() > MAX_DEVICE_LABEL_CHARS {
            return Err(Error::DeviceKey("a device label is at most 128 characters"));
        }
        Ok(Self {
            id,
            suite: suite.to_owned(),
            label: label.to_owned(),
            created_at,
            secret_keys,
            unknown: BTreeMap::new(),
        })
    }

    /// The device key id. Public: it names the device in every shared vault's roster.
    #[must_use]
    pub fn id(&self) -> &[u8; DEVICE_KEY_ID_LEN] {
        &self.id
    }

    /// The suite the key was made for, e.g. [`SUITE_X25519_ED25519_V1`].
    #[must_use]
    pub fn suite(&self) -> &str {
        &self.suite
    }

    /// The label the device was given, e.g. `"Work laptop"`.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Unix seconds, as claimed by the device that created the key.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The secret key material, for `kagisecure-shared` to sign and unwrap with. For
    /// [`SUITE_X25519_ED25519_V1`]: the X25519 secret key, then the Ed25519 seed.
    #[must_use]
    pub fn secret_keys(&self) -> &Secret {
        &self.secret_keys
    }

    /// Keys of this entry that this build does not recognize, preserved as read. Not zeroized:
    /// see the field's documentation.
    #[must_use]
    pub fn unknown(&self) -> &BTreeMap<String, ciborium::Value> {
        &self.unknown
    }

    /// Whether two entries are the same in every field, secret keys included. Compared field by
    /// field — the secret keys through [`Secret`]'s own comparison — so no copy of the key
    /// material is made to compare it.
    pub(crate) fn same_entry(&self, other: &Self) -> bool {
        self.id == other.id
            && self.suite == other.suite
            && self.label == other.label
            && self.created_at == other.created_at
            && self.secret_keys == other.secret_keys
            && self.unknown == other.unknown
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The id, suite and label are public (they appear in shared rosters); the secret keys
        // are not rendered at all, not even redacted, so no formatting of this type can grow a
        // path to them.
        let id: String = self.id.iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("DeviceKey")
            .field("id", &id)
            .field("suite", &self.suite)
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// How a device key is written into the body: a CBOR map with these keys and whatever unknown
/// keys it was read with.
#[derive(Deserialize)]
struct Wire {
    #[serde(with = "serde_bytes")]
    device_key_id: Vec<u8>,
    suite: String,
    label: String,
    created_at: u64,
    #[serde(with = "crate::model::secret_cbor")]
    secret_keys: Secret,
    #[serde(flatten)]
    unknown: BTreeMap<String, ciborium::Value>,
}

/// [`Wire`], borrowed, for writing.
#[derive(Serialize)]
struct WireRef<'a> {
    #[serde(with = "serde_bytes")]
    device_key_id: &'a [u8],
    suite: &'a str,
    label: &'a str,
    created_at: u64,
    #[serde(with = "crate::model::secret_cbor")]
    secret_keys: &'a Secret,
    #[serde(flatten)]
    unknown: &'a BTreeMap<String, ciborium::Value>,
}

impl<'a> WireRef<'a> {
    fn of(key: &'a DeviceKey) -> Self {
        Self {
            device_key_id: &key.id,
            suite: &key.suite,
            label: &key.label,
            created_at: key.created_at,
            secret_keys: &key.secret_keys,
            unknown: &key.unknown,
        }
    }
}

/// The crate-private serde adapter `Body::devices` is encoded with. The only encoding of a
/// [`DeviceKey`] there is.
pub(crate) mod cbor_list {
    use serde::de::Error as _;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{
        DEVICE_KEY_ID_LEN, DeviceKey, SUITE_X25519_ED25519_V1, Wire, WireRef,
        X25519_ED25519_V1_SECRET_LEN,
    };

    // `serde(with)` hands the field by reference, so the signature is fixed by serde.
    #[allow(clippy::ptr_arg)]
    pub(crate) fn serialize<S: Serializer>(
        keys: &Vec<DeviceKey>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(keys.len()))?;
        for key in keys {
            seq.serialize_element(&WireRef::of(key))?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Vec<DeviceKey>, D::Error> {
        let wires = Vec::<Wire>::deserialize(de)?;
        wires
            .into_iter()
            .map(|w| {
                // A device key id of any other length is not one this format defines, and
                // guessing at it could attach the wrong key to a roster entry: refuse the body.
                let id: [u8; DEVICE_KEY_ID_LEN] = w
                    .device_key_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| D::Error::custom("a device key id is 32 bytes"))?;
                // The one suite this build knows has a fixed secret length; anything else is
                // damage, and using it would sign or unwrap with the wrong key. A suite this
                // build does not know is kept as read.
                if w.suite == SUITE_X25519_ED25519_V1
                    && w.secret_keys.len() != X25519_ED25519_V1_SECRET_LEN
                {
                    return Err(D::Error::custom(
                        "an x25519-ed25519-v1 device key has 64 bytes of secret keys",
                    ));
                }
                Ok(DeviceKey {
                    id,
                    suite: w.suite,
                    label: w.label,
                    created_at: w.created_at,
                    secret_keys: w.secret_keys,
                    unknown: w.unknown,
                })
            })
            .collect()
    }
}

/// The crate-private serde adapter `Body::retired_devices` is encoded with: an array of 32-byte
/// byte strings. An id of any other length fails the body's decode.
pub(crate) mod cbor_ids {
    use serde::de::Error as _;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::DEVICE_KEY_ID_LEN;

    // `serde(with)` hands the field by reference, so the signature is fixed by serde.
    #[allow(clippy::ptr_arg)]
    pub(crate) fn serialize<S: Serializer>(
        ids: &Vec<[u8; DEVICE_KEY_ID_LEN]>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(ids.len()))?;
        for id in ids {
            seq.serialize_element(serde_bytes::Bytes::new(id))?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Vec<[u8; DEVICE_KEY_ID_LEN]>, D::Error> {
        Vec::<serde_bytes::ByteBuf>::deserialize(de)?
            .into_iter()
            .map(|id| {
                id.as_slice()
                    .try_into()
                    .map_err(|_| D::Error::custom("a retired device key id is 32 bytes"))
            })
            .collect()
    }
}

/// How the device keys of a diverged file differ from this session's.
///
/// `kept.only_in_file` counts the file's keys this session lacks and has not retired (an
/// overwrite keeps them); `kept.differing` the keys both hold with different entries (this
/// session's is written). The second value counts keys this session holds that the file has
/// retired (an overwrite removes them).
pub(crate) fn difference(file: &super::Body, session: &super::Body) -> (super::Difference, usize) {
    let mut kept = super::Difference::default();
    for theirs in &file.devices {
        if session.retired_devices.contains(&theirs.id) {
            continue;
        }
        match session.devices.iter().find(|mine| mine.id == theirs.id) {
            None => kept.only_in_file += 1,
            Some(mine) => {
                if !theirs.same_entry(mine) {
                    kept.differing += 1;
                }
            }
        }
    }
    let retired_in_file = session
        .devices
        .iter()
        .filter(|mine| file.retired_devices.contains(&mine.id))
        .count();
    (kept, retired_in_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u8, label: &str) -> DeviceKey {
        DeviceKey::new(
            [id; DEVICE_KEY_ID_LEN],
            SUITE_X25519_ED25519_V1,
            label,
            1_790_000_000,
            Secret::new(vec![id; X25519_ED25519_V1_SECRET_LEN]),
        )
        .unwrap()
    }

    #[test]
    fn only_the_known_suite_with_64_bytes_of_secret_keys_is_created() {
        let secret = || Secret::new(vec![1; X25519_ED25519_V1_SECRET_LEN]);
        assert!(DeviceKey::new([1; 32], SUITE_X25519_ED25519_V1, "Laptop", 1, secret()).is_ok());
        assert!(matches!(
            DeviceKey::new([1; 32], "p256-v1", "Laptop", 1, secret()),
            Err(Error::DeviceKey(_))
        ));
        assert!(matches!(
            DeviceKey::new(
                [1; 32],
                SUITE_X25519_ED25519_V1,
                "Laptop",
                1,
                Secret::new(vec![1; 32])
            ),
            Err(Error::DeviceKey(_))
        ));
    }

    #[test]
    fn a_label_is_limited_by_characters_not_bytes() {
        let secret = || Secret::new(vec![1; X25519_ED25519_V1_SECRET_LEN]);
        let longest = "\u{e9}".repeat(MAX_DEVICE_LABEL_CHARS);
        assert!(DeviceKey::new([1; 32], SUITE_X25519_ED25519_V1, &longest, 1, secret()).is_ok());
        let too_long = "a".repeat(MAX_DEVICE_LABEL_CHARS + 1);
        assert!(matches!(
            DeviceKey::new([1; 32], SUITE_X25519_ED25519_V1, &too_long, 1, secret()),
            Err(Error::DeviceKey(_))
        ));
    }

    #[test]
    fn debug_shows_the_id_and_label_and_nothing_of_the_secret_keys() {
        let key = DeviceKey::new(
            [0xab; 32],
            SUITE_X25519_ED25519_V1,
            "Laptop",
            7,
            Secret::new(
                b"0123456789abcdef0123456789abcdef-secret-key-material-canary-xyz!".to_vec(),
            ),
        )
        .unwrap();
        let rendered = format!("{key:?} {key:#?}");
        assert!(rendered.contains("abababab"), "{rendered}");
        assert!(rendered.contains("Laptop"), "{rendered}");
        assert!(!rendered.contains("canary"), "{rendered}");
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn the_wire_encoding_round_trips_with_unknown_keys() {
        let mut first = key(1, "One");
        first.unknown.insert(
            "enclave_binding".to_owned(),
            ciborium::Value::Text("later".to_owned()),
        );
        let holder = Holder {
            devices: vec![first, key(2, "Two")],
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&holder, &mut bytes).unwrap();
        let back: Holder = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.devices.len(), 2);
        assert_eq!(back.devices[0].id(), &[1; 32]);
        assert_eq!(back.devices[0].label(), "One");
        assert_eq!(back.devices[0].secret_keys().expose(), &[1; 64][..]);
        assert_eq!(
            back.devices[0].unknown().get("enclave_binding"),
            Some(&ciborium::Value::Text("later".to_owned()))
        );
        assert!(back.devices[1].same_entry(&key(2, "Two")));
        assert!(!back.devices[1].same_entry(&key(2, "Two, renamed")));
    }

    #[derive(Serialize, Deserialize)]
    struct Holder {
        #[serde(with = "cbor_list")]
        devices: Vec<DeviceKey>,
    }

    #[test]
    fn an_id_of_the_wrong_length_refuses_the_whole_list() {
        let text = |t: &str| ciborium::Value::Text(t.to_owned());
        let entry = |id_len: usize| {
            ciborium::Value::Map(vec![
                (
                    text("device_key_id"),
                    ciborium::Value::Bytes(vec![1; id_len]),
                ),
                (text("suite"), text(SUITE_X25519_ED25519_V1)),
                (text("label"), text("Laptop")),
                (text("created_at"), ciborium::Value::Integer(1.into())),
                (text("secret_keys"), ciborium::Value::Bytes(vec![1; 64])),
            ])
        };
        let holder = |id_len: usize| {
            let value = ciborium::Value::Map(vec![(
                text("devices"),
                ciborium::Value::Array(vec![entry(DEVICE_KEY_ID_LEN), entry(id_len)]),
            )]);
            let mut bytes = Vec::new();
            ciborium::into_writer(&value, &mut bytes).unwrap();
            ciborium::from_reader::<Holder, _>(bytes.as_slice())
        };
        assert_eq!(holder(DEVICE_KEY_ID_LEN).unwrap().devices.len(), 2);
        assert!(holder(31).is_err());
        assert!(holder(33).is_err());
    }

    fn body(devices: Vec<DeviceKey>, retired: Vec<[u8; DEVICE_KEY_ID_LEN]>) -> super::super::Body {
        let mut body = super::super::Body::emptied();
        body.devices = devices;
        body.retired_devices = retired;
        body
    }

    fn decode_one(
        suite: &str,
        secret_len: usize,
    ) -> std::result::Result<Holder, ciborium::de::Error<std::io::Error>> {
        let text = |t: &str| ciborium::Value::Text(t.to_owned());
        let value = ciborium::Value::Map(vec![(
            text("devices"),
            ciborium::Value::Array(vec![ciborium::Value::Map(vec![
                (text("device_key_id"), ciborium::Value::Bytes(vec![1; 32])),
                (text("suite"), text(suite)),
                (text("label"), text("Laptop")),
                (text("created_at"), ciborium::Value::Integer(1.into())),
                (
                    text("secret_keys"),
                    ciborium::Value::Bytes(vec![1; secret_len]),
                ),
            ])]),
        )]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).unwrap();
        ciborium::from_reader::<Holder, _>(bytes.as_slice())
    }

    #[test]
    fn a_known_suite_key_with_the_wrong_secret_length_refuses_the_body() {
        assert!(decode_one(SUITE_X25519_ED25519_V1, 64).is_ok());
        assert!(decode_one(SUITE_X25519_ED25519_V1, 63).is_err());
        assert!(decode_one(SUITE_X25519_ED25519_V1, 65).is_err());
        // A suite this build does not know is kept as read, whatever its length.
        let kept = decode_one("p256-enclave-v1", 97).unwrap();
        assert_eq!(kept.devices[0].suite(), "p256-enclave-v1");
        assert_eq!(kept.devices[0].secret_keys().len(), 97);
    }

    #[test]
    fn entries_that_differ_only_in_their_secret_keys_are_not_the_same() {
        let one = key(1, "One");
        let other = DeviceKey::new(
            [1; DEVICE_KEY_ID_LEN],
            SUITE_X25519_ED25519_V1,
            "One",
            1_790_000_000,
            Secret::new(vec![2; X25519_ED25519_V1_SECRET_LEN]),
        )
        .unwrap();
        assert!(one.same_entry(&key(1, "One")));
        assert!(!one.same_entry(&other));
    }

    #[test]
    fn difference_counts_kept_differing_and_retired_keys() {
        let file = body(
            vec![
                key(1, "One"),
                key(2, "Two, renamed"),
                key(3, "Three"),
                key(5, "Five"),
            ],
            vec![[6; 32]],
        );
        let session = body(
            vec![key(1, "One"), key(2, "Two"), key(4, "Four"), key(6, "Six")],
            vec![[5; 32]],
        );
        let (kept, retired_in_file) = difference(&file, &session);
        // 3 is kept; 5 only in the file but retired here, so neither kept nor counted.
        assert_eq!(kept.only_in_file, 1);
        assert_eq!(kept.differing, 1);
        // 6 is held here and retired in the file.
        assert_eq!(retired_in_file, 1);
    }
}

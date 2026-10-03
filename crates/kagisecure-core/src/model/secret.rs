//! The `Secret` newtype — the enforcement point for the product's central invariant.

use zeroize::Zeroizing;

/// Plaintext secret material.
///
/// Deliberately hostile to accidental disclosure:
///
/// * no `Display`, and a `Debug` that prints `Secret(<redacted>)`;
/// * no `Serialize` / `Deserialize` — the on-disk encoding goes through a crate-private adapter
///   used only by [`crate::vault`] (vault-format §5.1);
/// * no `Clone`, so a secret cannot be duplicated by accident;
/// * zeroized on drop via [`Zeroizing`].
///
/// The whole type only exists when the `secret-material` feature is enabled. A crate that must
/// never hold plaintext — the MCP sidecar — depends on `kagisecure-core` without that feature
/// and cannot name this type at all (architecture §2.2, ADR-0002).
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Take ownership of raw secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take ownership of a secret string.
    ///
    /// The `String`'s buffer is moved into the secret and zeroized on drop. Note the honest
    /// caveat from vault-format §7: any *earlier* copy the caller made (a terminal line editor,
    /// a `read_line` buffer that was reallocated) is beyond this type's reach.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self::new(s.into_bytes())
    }

    /// Length of the secret in bytes. Length is metadata, not the value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the plaintext bytes.
    ///
    /// This is the single, explicitly-named escape hatch. It exists because the CLI is a trusted
    /// local tool that must be able to inject values into a child process and — at the user's own
    /// explicit request — print one to their own terminal. It is reachable only from code that
    /// enabled `secret-material`; see ADR-0005.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the plaintext as `&str`, if it is valid UTF-8.
    #[must_use]
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl PartialEq for Secret {
    /// Constant-time-ish equality on equal-length inputs. Not a security boundary; provided so
    /// tests can assert round-trips.
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        let mut acc = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }
}

impl Eq for Secret {}

/// Secret material that is known to be text — an item's notes (ADR-0038 user decision 3).
///
/// A [`Secret`] underneath, with every one of its guarantees — no `Display`, a redacted `Debug`,
/// no `Serialize`/`Deserialize` of its own, no `Clone`, zeroized on drop — plus one more: it can
/// only be built from a `String`, so it is always valid UTF-8 and [`SecretText::expose`] can hand
/// back a `&str` without a fallible conversion at every call site.
///
/// The UTF-8 guarantee is also what keeps the on-disk encoding exactly what it was when notes
/// were a plain `Option<String>`: the crate-private adapter below writes a CBOR *text* string,
/// never the byte string [`Secret`]'s own adapter writes, so a vault saved by this build is
/// byte-for-byte what an older build would have written for the same note, and an older build
/// reads it back unchanged (vault-format §9: no `body.schema` bump). The golden vectors in
/// `tests/vectors/item-with-notes-v1.cbor` and `v1-notes-argon2id-64k.kagivault` pin that.
pub struct SecretText(Secret);

impl SecretText {
    /// Take ownership of secret text. The `String`'s buffer is moved, not copied — the same
    /// caveat as [`Secret::from_string`] about any earlier copy the caller made applies.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(Secret::from_string(text))
    }

    /// Borrow the plaintext. The single, explicitly-named escape hatch, exactly as
    /// [`Secret::expose`] is.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0
            .expose_str()
            .expect("SecretText is only ever built from a String, so it is always UTF-8")
    }

    /// The underlying [`Secret`].
    #[must_use]
    pub fn as_secret(&self) -> &Secret {
        &self.0
    }

    /// Length in bytes. Length is metadata, not the value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The same rendering as `Secret`, so a canary search for the redaction marker finds it.
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl PartialEq for SecretText {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SecretText {}

/// Crate-private serde adapter. Used through `#[serde(with = ...)]` by the item model so that the
/// vault body can be encoded; `Secret` itself remains un-`Serialize`, so no caller outside this
/// crate can serialize one on its own.
pub(crate) mod cbor {
    use super::Secret;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(secret: &Secret, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(secret.expose())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Secret, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(de)?;
        Ok(Secret::new(bytes.into_vec()))
    }
}

/// Crate-private serde adapter for an optional [`SecretText`] — an item's notes.
///
/// Encodes exactly as `Option<&str>` does, and decodes exactly as `Option<String>` does, which is
/// what a note was before it became secret: `null` for none, a CBOR text string for some. Nothing
/// about the file changes; only what the process holds in memory does.
pub(crate) mod cbor_text_opt {
    use super::SecretText;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // `serde(with)` hands the field by reference, so the signature is fixed by serde.
    #[allow(clippy::ref_option)]
    pub(crate) fn serialize<S: Serializer>(
        text: &Option<SecretText>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        text.as_ref().map(SecretText::expose).serialize(ser)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<SecretText>, D::Error> {
        Ok(Option::<String>::deserialize(de)?.map(SecretText::new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::from_string("hunter2-correct-horse".to_owned());
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn debug_of_a_containing_struct_is_also_redacted() {
        #[derive(Debug)]
        struct Wrapper {
            #[allow(dead_code)]
            value: Secret,
        }
        let w = Wrapper {
            value: Secret::from_string("swordfish".to_owned()),
        };
        assert!(!format!("{w:?}").contains("swordfish"));
    }

    #[test]
    fn exposes_the_bytes_it_was_given() {
        let s = Secret::new(b"\x00\xffbytes".to_vec());
        assert_eq!(s.expose(), b"\x00\xffbytes");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());
        assert!(s.expose_str().is_none());
    }

    #[test]
    fn equality_is_by_value() {
        assert_eq!(
            Secret::from_string("a".to_owned()),
            Secret::from_string("a".to_owned())
        );
        assert_ne!(
            Secret::from_string("a".to_owned()),
            Secret::from_string("b".to_owned())
        );
        assert_ne!(
            Secret::from_string("a".to_owned()),
            Secret::from_string("ab".to_owned())
        );
    }

    #[test]
    fn secret_text_is_redacted_and_exposes_its_text() {
        let t = SecretText::new("recovery: 1234-5678".to_owned());
        assert_eq!(format!("{t:?}"), "Secret(<redacted>)");
        assert_eq!(t.expose(), "recovery: 1234-5678");
        assert_eq!(t.as_secret().expose(), b"recovery: 1234-5678");
        assert_eq!(t.len(), 19);
        assert!(!t.is_empty());
        assert_eq!(t, SecretText::new("recovery: 1234-5678".to_owned()));
    }

    /// The adapter writes what `Option<String>` wrote — a text string or `null` — and reads it
    /// back, so a note's bytes on disk are unchanged by it becoming secret.
    #[test]
    fn optional_secret_text_encodes_exactly_as_an_optional_string() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct New {
            #[serde(default, with = "cbor_text_opt")]
            notes: Option<SecretText>,
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Old {
            #[serde(default)]
            notes: Option<String>,
        }
        for value in [None, Some(""), Some("line one\nline two — ✓")] {
            let mut old = Vec::new();
            ciborium::into_writer(
                &Old {
                    notes: value.map(str::to_owned),
                },
                &mut old,
            )
            .unwrap();
            let mut new = Vec::new();
            ciborium::into_writer(
                &New {
                    notes: value.map(|v| SecretText::new(v.to_owned())),
                },
                &mut new,
            )
            .unwrap();
            assert_eq!(old, new, "{value:?}");
            let back: New = ciborium::from_reader(old.as_slice()).unwrap();
            assert_eq!(back.notes.as_ref().map(SecretText::expose), value);
        }
        // A key an older file never wrote still reads back as no note.
        let mut empty = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(Vec::new()), &mut empty).unwrap();
        let back: New = ciborium::from_reader(empty.as_slice()).unwrap();
        assert!(back.notes.is_none());
    }

    /// Zeroize sanity.
    ///
    /// Reading freed memory to prove `Drop` wiped it needs `unsafe`, which this crate forbids, so
    /// the property is asserted one level down: the `Zeroizing` wrapper that `Secret` is built on
    /// does clear its contents in place. `Secret`'s own wipe-on-drop follows from that plus
    /// `Zeroizing`'s `Drop` impl.
    #[test]
    fn zeroizing_clears_the_buffer_in_place() {
        use zeroize::Zeroize;
        let mut buf = Zeroizing::new(*b"top-secret-12345");
        assert_ne!(*buf, [0u8; 16]);
        buf.zeroize();
        assert_eq!(*buf, [0u8; 16]);
    }
}

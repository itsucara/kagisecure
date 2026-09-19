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

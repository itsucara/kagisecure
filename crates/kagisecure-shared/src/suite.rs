//! Cryptographic suites (ADR-0035 §4): which algorithms a device key and a shared vault use.
//!
//! Parameters are data (vault-format §1, goal 4). Every device key and every shared vault names
//! its suite, so a later one — P-256 for Secure Enclave-held keys, a post-quantum hybrid KEM — is
//! a new value here rather than a format break. A suite this build does not implement is refused
//! by name ([`SharedError::UnsupportedSuite`]), never guessed at (ADR-0035 §16).

use kagisecure_core::vault::device::SUITE_X25519_ED25519_V1;

use crate::error::{Result, SharedError};

/// A cryptographic suite this build implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Suite {
    /// `x25519-ed25519-v1`: X25519 for wrapping epoch keys (HPKE Base mode, RFC 9180, with
    /// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305) and Ed25519 for signing
    /// records (RFC 8032, verified strictly).
    X25519Ed25519V1,
}

impl Suite {
    /// The suite's ASCII name, exactly as it is written in files and fed into the device key id
    /// (ADR-0035 addendum, "Device key id").
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X25519Ed25519V1 => SUITE_X25519_ED25519_V1,
        }
    }

    /// The suite called `name`.
    ///
    /// # Errors
    ///
    /// [`SharedError::UnsupportedSuite`] for any name this build does not implement, including a
    /// different spelling of a known one: the name is compared byte for byte.
    pub fn from_name(name: &str) -> Result<Self> {
        if name == SUITE_X25519_ED25519_V1 {
            Ok(Self::X25519Ed25519V1)
        } else {
            Err(SharedError::UnsupportedSuite(name.to_owned()))
        }
    }
}

impl std::fmt::Display for Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_one_suite_round_trips_by_its_name() {
        assert_eq!(Suite::X25519Ed25519V1.name(), "x25519-ed25519-v1");
        assert_eq!(
            Suite::from_name("x25519-ed25519-v1").unwrap(),
            Suite::X25519Ed25519V1
        );
        assert_eq!(Suite::X25519Ed25519V1.to_string(), "x25519-ed25519-v1");
    }

    #[test]
    fn an_unknown_or_respelled_suite_is_refused_by_name() {
        for name in [
            "p256-enclave-v1",
            "X25519-ED25519-V1",
            "x25519-ed25519-v1 ",
            "",
        ] {
            match Suite::from_name(name) {
                Err(SharedError::UnsupportedSuite(got)) => assert_eq!(got, name),
                other => panic!("{name:?}: {other:?}"),
            }
        }
    }
}

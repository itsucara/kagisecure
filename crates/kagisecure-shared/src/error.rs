//! Error type for `kagisecure-shared`.
//!
//! The same rule as [`kagisecure_core::error`]: **no variant may carry a value, a key or a
//! decrypted payload**, and here it matters for a second reason — the bytes being parsed came from
//! another person's computer, and an error is the first thing a person reads about them. Sizes,
//! limits, counts and structural complaints are fine; what was in the record is not.

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, SharedError>;

/// Everything that can go wrong reading, verifying or writing a shared vault.
///
/// `#[non_exhaustive]`: Phases 1 and 2 add the record, roster and exchange failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharedError {
    /// The personal vault (or a core primitive — the file lock, the atomic write) refused.
    #[error(transparent)]
    Core(#[from] kagisecure_core::Error),

    /// A file or directory could not be read or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A device key or shared vault names a suite this build does not implement. The vault
    /// refuses to open rather than guess (ADR-0035 §16).
    #[error("unsupported shared-vault suite {0:?}")]
    UnsupportedSuite(String),

    /// Something is larger than the encoding contract allows (ADR-0035 addendum, limits), found
    /// before it was decoded.
    #[error("{what} exceeds the limit of {limit}")]
    LimitExceeded {
        /// What was too large, e.g. `"record"` or `"bundle"`.
        what: &'static str,
        /// The limit, in the unit `what` is counted in.
        limit: u64,
    },

    /// The bytes are not the structure they claim to be. Says what is wrong, never what was
    /// there.
    #[error("malformed shared-vault data: {0}")]
    Malformed(&'static str),

    /// A public key is not one this format accepts: not a canonical encoding, not a point on the
    /// curve, or of small order (ADR-0035 §4, "strict verification"). Says which rule failed,
    /// never the key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(&'static str),

    /// A signature does not verify, under strict verification, for the key and the domain it
    /// was checked against.
    #[error("the signature does not verify")]
    BadSignature,

    /// A device key's stored id is not the id of its own key material: the personal vault's
    /// entry is damaged, or was written by something that computed the id differently. Signing
    /// or unwrapping with it would act as a device the roster does not know.
    #[error("a device key's id does not match its key material")]
    DeviceKeyMismatch,

    /// Something encrypted did not open: the key is not the one it was sealed to, or the bytes,
    /// or what they were bound to (a vault id, an epoch id, an author), are not what they were.
    /// Which of those it was is deliberately not reported (threat-model M-8).
    #[error("could not decrypt: the wrong key, or the data or its context was altered")]
    Decrypt,

    /// A record's signature verified, but its body names another shared vault than the one it
    /// was verified for. It is never read as this vault's: its payload's AAD and record key are
    /// bound to its own vault id, and its authority would be another roster's (ADR-0035
    /// addendum, decision 13).
    #[error("the record belongs to another shared vault")]
    WrongVault,

    /// The genesis record a roster is computed from is not in the record set. A device knows
    /// its shared vault's genesis from a source it trusts — its replica's header, or the
    /// invitation it joined by (ADR-0035 addendum, decision 41) — so a set without it is not
    /// that vault.
    #[error("the shared vault's genesis record is missing")]
    GenesisMissing,

    /// The record named as a shared vault's genesis is not one: says which rule it breaks. A
    /// roster is never computed from anything else (ADR-0035 addendum, decision 41).
    #[error("the genesis record is invalid: {0}")]
    InvalidGenesis(&'static str),

    /// This device may not do that now: says why — its role, a key it does not hold yet, a
    /// change that would leave the vault with no admin. Never names a value.
    #[error("refused: {0}")]
    Refused(&'static str),

    /// The file at a replica's path is not the replica asked for: another shared vault's,
    /// another genesis's, or another device's local section. Says which, never what was there.
    #[error("the replica file does not match: {0}")]
    ReplicaMismatch(&'static str),

    /// A record or file carries a version this build does not read. It is not guessed at; a
    /// record is still kept and forwarded as the bytes it is (ADR-0035 §16).
    #[error("{what} version {version} is not supported by this build")]
    UnsupportedVersion {
        /// What carried the version, e.g. `"record envelope"`.
        what: &'static str,
        /// The version found.
        version: u64,
    },

    /// A host bundle (ADR-0043) that is well formed and correctly signed but not for this host,
    /// or not signed by the owner this host trusts, or older than one it already holds. Says
    /// which; never what the bundle carries.
    #[error("host bundle refused: {0}")]
    HostBundleRefused(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_core_error_passes_through_unchanged() {
        let error: SharedError = kagisecure_core::Error::Malformed.into();
        assert_eq!(
            error.to_string(),
            kagisecure_core::Error::Malformed.to_string()
        );
    }

    #[test]
    fn a_limit_names_what_and_how_much_and_nothing_else() {
        let error = SharedError::LimitExceeded {
            what: "record",
            limit: 1 << 20,
        };
        assert_eq!(error.to_string(), "record exceeds the limit of 1048576");
    }
}

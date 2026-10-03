//! Argon2id key derivation, with the parameters carried as data in the vault header.
//!
//! Vault-format §9 rule: **parameters are read from the header, never hardcoded in the open
//! path**, so they can be raised without a format break. That has a consequence: the header is
//! plaintext and is only authenticated *after* the KDF has already run, so a tampered header can
//! ask us to allocate an arbitrary amount of memory before the AEAD gets a chance to reject it.
//! [`KdfParams::validate`] therefore bounds every parameter before it reaches Argon2.

use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{KEY_LEN, Key};
use crate::error::{Error, Result};

/// The only KDF this build implements.
pub const ALG_ARGON2ID: &str = "argon2id";

/// Default memory cost in KiB (64 MiB), the desktop profile from threat-model M-17.
pub const DEFAULT_M_KIB: u32 = 65_536;
/// Default iteration count.
pub const DEFAULT_T: u32 = 3;
/// Default parallelism.
pub const DEFAULT_P: u32 = 1;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Lower bound on `m_kib` accepted from a file.
///
/// Argon2's own absolute minimum (`Params::MIN_M_COST`, 8 KiB) is not a policy: a file that
/// genuinely declares it unlocks at essentially no work factor, so a stolen vault is only as
/// strong as the password. This floor refuses that.
///
/// **It is deliberately low.** The v1 golden vector (`tests/vectors/v1-argon2id-64k.kagivault`)
/// was written at m = 64 KiB and golden vectors are never edited (vault-format §9 rule 5), so
/// the strongest floor the *open* path can carry without breaking format compatibility is the
/// cost of that file. A security-meaningful floor (OWASP's m = 19 MiB, t = 2) belongs on the
/// *creation* path and on the UI's "this vault is weak" warning, where it can be raised without
/// making an existing file unopenable; see [`MEANINGFUL_M_KIB`] / [`MEANINGFUL_T`] and
/// [`KdfParams::meets_recommended_floor`].
pub const MIN_M_KIB: u32 = 64;
/// Lower bound on `t` accepted from a file. Same compatibility constraint as [`MIN_M_KIB`]: the
/// v1 golden vector declares `t = 1`.
pub const MIN_T: u32 = 1;

/// The memory cost a *new* vault should be created with at the very least (OWASP 2024 Argon2id
/// minimum). Not enforced by [`KdfParams::validate`]; see [`MIN_M_KIB`].
pub const MEANINGFUL_M_KIB: u32 = 19 * 1024;
/// The iteration count a *new* vault should be created with at the very least.
pub const MEANINGFUL_T: u32 = 2;

/// Upper bound on `m_kib` accepted from a file: 1 GiB.
///
/// This is not a cryptographic limit. It stops a corrupted or hostile header from turning an
/// unlock attempt into an out-of-memory abort before the AEAD can reject the header.
pub const MAX_M_KIB: u32 = 1024 * 1024;
/// Upper bound on `t` accepted from a file.
pub const MAX_T: u32 = 64;
/// Upper bound on `p` accepted from a file.
pub const MAX_P: u32 = 16;

/// The KDF descriptor stored in the vault header (vault-format §2.1).
///
/// `PartialEq` but not `Eq`: [`KdfParams::unknown`] holds CBOR values, which may be floats.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Algorithm name; only `"argon2id"` is implemented.
    pub alg: String,
    /// Per-slot random salt.
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
    /// Output length in bytes; only 32 is implemented.
    pub out_len: u32,
    /// Descriptor keys this build does not recognize, preserved verbatim (vault-format §9 rule
    /// 1), so an older build rewriting the header does not drop what a newer one added — a
    /// dropped KDF parameter would leave the newer build deriving a different key and the slot
    /// unopenable.
    ///
    /// Preserved, but never *used*: a derivation this build cannot fully understand would produce
    /// the wrong key and look like a wrong password, so [`KdfParams::derive`] refuses a
    /// descriptor that carries any (`Unsupported`: upgrade Kagisecure), and [`KdfParams::reroll_salt`] — the
    /// start of every fresh wrap this build makes — drops them, so a descriptor this build writes
    /// for its own derivation never claims a parameter it did not apply.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl KdfParams {
    /// Fresh parameters with a new random salt and the given cost.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails, or [`Error::KdfParams`] if the
    /// cost values are out of range.
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self> {
        let params = Self {
            alg: ALG_ARGON2ID.to_owned(),
            salt: super::random::array::<SALT_LEN>()?.to_vec(),
            m_kib,
            t,
            p,
            out_len: KEY_LEN as u32,
            unknown: BTreeMap::new(),
        };
        params.validate()?;
        Ok(params)
    }

    /// Fresh parameters at the v1 desktop defaults (m = 64 MiB, t = 3, p = 1).
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn defaults() -> Result<Self> {
        Self::new(DEFAULT_M_KIB, DEFAULT_T, DEFAULT_P)
    }

    /// Re-roll the salt, keeping the cost parameters — the start of every fresh wrap: a password
    /// change, a KDF upgrade and a new recovery code (vault-format §2.1).
    ///
    /// Also drops [`KdfParams::unknown`]. The descriptor that comes out describes a derivation
    /// *this* build is about to perform, with only the parameters it understands; carrying over a
    /// key a newer build added would write a descriptor claiming a parameter that was never
    /// applied, and the newer build would then derive a different key from it than the one the
    /// slot was wrapped under.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn reroll_salt(&mut self) -> Result<()> {
        self.salt = super::random::array::<SALT_LEN>()?.to_vec();
        self.unknown.clear();
        Ok(())
    }

    /// Reject anything this build will not run.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for an unknown algorithm or output length, and
    /// [`Error::KdfParams`] for out-of-range costs or a short salt.
    pub fn validate(&self) -> Result<()> {
        if self.alg != ALG_ARGON2ID {
            return Err(Error::Unsupported {
                what: "KDF algorithm",
                value: self.alg.clone(),
            });
        }
        if self.out_len as usize != KEY_LEN {
            return Err(Error::Unsupported {
                what: "KDF output length",
                value: self.out_len.to_string(),
            });
        }
        if self.salt.len() < 8 || self.salt.len() > 64 {
            return Err(Error::KdfParams(format!(
                "salt length {} is outside 8..=64",
                self.salt.len()
            )));
        }
        let m_floor = MIN_M_KIB.max(Params::MIN_M_COST);
        if self.m_kib < m_floor || self.m_kib > MAX_M_KIB {
            return Err(Error::KdfParams(format!(
                "m_kib {} is outside {m_floor}..={MAX_M_KIB}",
                self.m_kib,
            )));
        }
        let t_floor = MIN_T.max(Params::MIN_T_COST);
        if self.t < t_floor || self.t > MAX_T {
            return Err(Error::KdfParams(format!(
                "t {} is outside {t_floor}..={MAX_T}",
                self.t,
            )));
        }
        if self.p < Params::MIN_P_COST || self.p > MAX_P {
            return Err(Error::KdfParams(format!(
                "p {} is outside {}..={MAX_P}",
                self.p,
                Params::MIN_P_COST
            )));
        }
        Ok(())
    }

    /// Whether these parameters meet the cost a *new* vault should be created with
    /// ([`MEANINGFUL_M_KIB`] / [`MEANINGFUL_T`]).
    ///
    /// [`validate`](Self::validate) deliberately does not enforce this, because an existing file
    /// written below it must still open. A caller that is about to *create* a vault, or that
    /// wants to tell the user their vault is weak, asks this instead.
    #[must_use]
    pub fn meets_recommended_floor(&self) -> bool {
        self.m_kib >= MEANINGFUL_M_KIB && self.t >= MEANINGFUL_T
    }

    /// Stretch `password` into a 32-byte key encryption key.
    ///
    /// The same function serves the password slot and the recovery-code slot; only the input and
    /// the salt differ (vault-format §3.2).
    ///
    /// # Errors
    ///
    /// [`Error::KdfParams`] / [`Error::Unsupported`] if the parameters are unacceptable —
    /// including a parameter this build does not recognize ([`KdfParams::unknown`]) — or
    /// [`Error::KdfFailed`] if Argon2id could not run (in practice: allocation failure).
    pub fn derive(&self, password: &[u8]) -> Result<Key> {
        self.validate()?;
        // A parameter this build does not know may change what the derivation is; running it
        // without would produce the wrong key and read as a wrong password. Refuse, never guess
        // (vault-format §9). Only here, at the derivation, not in `validate`: a slot this session
        // does not open by (the recovery slot, while unlocking by password) must not stop the
        // vault from opening at all.
        if let Some(key) = self.unknown.keys().next() {
            return Err(Error::Unsupported {
                what: "KDF parameter",
                value: key.clone(),
            });
        }
        let params = Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| Error::KdfParams(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        argon
            .hash_password_into(password, &self.salt, out.as_mut_slice())
            .map_err(|_| Error::KdfFailed(self.m_kib))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the test suite does not spend a minute in Argon2.
    fn cheap() -> KdfParams {
        KdfParams::new(64, 1, 1).unwrap()
    }

    #[test]
    fn derivation_is_deterministic() {
        let p = cheap();
        assert_eq!(*p.derive(b"pw").unwrap(), *p.derive(b"pw").unwrap());
    }

    #[test]
    fn different_passwords_and_salts_diverge() {
        let p = cheap();
        assert_ne!(*p.derive(b"pw").unwrap(), *p.derive(b"pw2").unwrap());
        let mut q = p.clone();
        q.reroll_salt().unwrap();
        assert_ne!(*p.derive(b"pw").unwrap(), *q.derive(b"pw").unwrap());
    }

    #[test]
    fn parameters_are_honoured_not_ignored() {
        // Same salt, different cost: a different key. Proves the open path really uses the
        // header's parameters rather than a hardcoded profile.
        let a = cheap();
        let mut b = a.clone();
        b.t = 2;
        assert_ne!(*a.derive(b"pw").unwrap(), *b.derive(b"pw").unwrap());
    }

    #[test]
    fn absurd_parameters_are_refused_before_argon2_sees_them() {
        let mut p = cheap();
        p.m_kib = u32::MAX;
        assert!(matches!(p.validate(), Err(Error::KdfParams(_))));
        assert!(matches!(p.derive(b"pw"), Err(Error::KdfParams(_))));

        let mut p = cheap();
        p.t = 0;
        assert!(matches!(p.derive(b"pw"), Err(Error::KdfParams(_))));

        let mut p = cheap();
        p.alg = "scrypt".to_owned();
        assert!(matches!(p.derive(b"pw"), Err(Error::Unsupported { .. })));

        let mut p = cheap();
        p.out_len = 64;
        assert!(matches!(p.derive(b"pw"), Err(Error::Unsupported { .. })));

        let mut p = cheap();
        p.salt = vec![0u8; 4];
        assert!(matches!(p.derive(b"pw"), Err(Error::KdfParams(_))));
    }

    #[test]
    fn an_unknown_parameter_is_refused_for_derivation_and_dropped_by_a_fresh_wrap() {
        let mut p = cheap();
        p.unknown
            .insert("pepper_id".to_owned(), ciborium::Value::Integer(7.into()));
        assert!(matches!(
            p.derive(b"pw"),
            Err(Error::Unsupported {
                what: "KDF parameter",
                ..
            })
        ));
        // It survives an encode/decode round trip untouched…
        let mut bytes = Vec::new();
        ciborium::into_writer(&p, &mut bytes).unwrap();
        let back: KdfParams = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, p);
        // …and a fresh wrap starts clean.
        let mut fresh = p.clone();
        fresh.reroll_salt().unwrap();
        assert!(fresh.unknown.is_empty());
        assert!(fresh.derive(b"pw").is_ok());
    }

    #[test]
    fn a_cost_below_the_floor_is_refused() {
        let mut p = cheap();
        p.m_kib = Params::MIN_M_COST; // 8 KiB: Argon2's absolute minimum, no work factor at all
        assert!(matches!(p.validate(), Err(Error::KdfParams(_))));
        assert!(matches!(p.derive(b"pw"), Err(Error::KdfParams(_))));
        assert!(KdfParams::new(Params::MIN_M_COST, 1, 1).is_err());

        // The v1 golden vector's own cost must stay openable; see MIN_M_KIB.
        assert!(KdfParams::new(64, 1, 1).unwrap().validate().is_ok());
    }

    #[test]
    fn the_recommended_floor_is_separate_from_what_opens() {
        assert!(!cheap().meets_recommended_floor());
        assert!(KdfParams::defaults().unwrap().meets_recommended_floor());
    }

    #[test]
    fn defaults_match_the_documented_desktop_profile() {
        let p = KdfParams::defaults().unwrap();
        assert_eq!((p.m_kib, p.t, p.p, p.out_len), (65_536, 3, 1, 32));
        assert_eq!(p.salt.len(), SALT_LEN);
        assert_eq!(p.alg, "argon2id");
    }
}

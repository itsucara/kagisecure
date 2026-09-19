//! The one place the crate talks to the operating system CSPRNG.

use rand_core::{OsRng, TryRngCore};

use crate::error::{Error, Result};

/// Fill `buf` with bytes from the OS CSPRNG.
///
/// # Errors
///
/// [`Error::Rng`] if the operating system's generator fails. There is no fallback and no seeded
/// PRNG anywhere in this crate: a failure here fails the operation.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    OsRng.try_fill_bytes(buf).map_err(|_| Error::Rng)
}

/// A fresh array of `N` random bytes.
///
/// # Errors
///
/// [`Error::Rng`] if the operating system's generator fails.
pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// A fresh 32-byte key, zeroized on drop.
///
/// # Errors
///
/// [`Error::Rng`] if the operating system's generator fails.
pub fn key() -> Result<super::Key> {
    let mut out = zeroize::Zeroizing::new([0u8; super::KEY_LEN]);
    fill(out.as_mut_slice())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_values() {
        let a = array::<32>().unwrap();
        let b = array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}

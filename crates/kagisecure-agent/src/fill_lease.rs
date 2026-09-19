//! Fill leases: "you already said yes to this item at this origin, in this unlock session".
//!
//! # Why not `kagisecure_core::lease::LeaseStore`
//!
//! That store exists to answer a different question — *may this agent write these variable names
//! into this exact directory, for this long, this many more times* — and its `LeaseRequest` is
//! built out of an environment id, a canonical path and a variable set. A fill has none of those.
//! Reusing it would mean either widening `LeaseRequest` with three optional fields that mean
//! nothing to `write_env_file`, or encoding an origin into a `PathBuf` and hoping nobody
//! canonicalizes it. Both are worse than eighty lines of a store that says what it means.
//!
//! It also keeps a property worth having: an env-file lease can never satisfy a fill, and a fill
//! lease can never satisfy an env-file write, because they are not the same type and there is no
//! function that takes one and returns the other.
//!
//! # What a lease does and does not excuse
//!
//! A live lease excuses **the biometric**, and nothing else. Every fill still requires the user's
//! explicit action in the page — the in-field icon or ⌘\ — because the extension has no way to
//! ask for a fill the user did not initiate, and the roadmap's "there is no autofill-on-load
//! default" is a property of the *content script*, not of this store. What the lease buys is that
//! logging in twice in five minutes does not mean two fingerprints.
//!
//! # Session-scoped, so a lock is the end of it
//!
//! There is no persistence. The store lives inside the running [`crate::Agent`]-alike, and
//! `VaultHandle`'s lock hook empties it, exactly as it revokes every env lease. Locking the vault
//! and unlocking it again means the next fill at every origin prompts again.

use std::collections::HashMap;

/// Default life of a fill lease.
///
/// Five minutes rather than the env channel's fifteen: a login flow is seconds long, and the
/// window only has to cover "the site bounced me back to the login page" and "I mistyped the
/// TOTP". A longer default would buy convenience nobody asked for at the cost of a wider window
/// in which a compromised extension can fill without a fingerprint.
pub const DEFAULT_FILL_TTL_SECONDS: u64 = 300;

/// The longest a fill lease may live, whatever a UI asks for.
pub const MAX_FILL_TTL_SECONDS: u64 = 900;

/// One granted (origin, item) pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillLease {
    /// The origin the user approved, in ASCII serialization.
    pub origin: String,
    /// The item they approved it for.
    pub item_id: String,
    /// The item's title, for the leases table.
    pub item_title: String,
    /// How the caller was identified when the lease was minted.
    pub client_identity: String,
    /// Unix seconds it dies at.
    pub expires_at: u64,
}

/// Every live fill lease.
///
/// Keyed on `(origin, item_id)` rather than on the origin alone. The brief calls this a
/// "per-origin lease", and this is that plus one restriction: approving *this* password at
/// `https://example.com` does not silently approve the user's *other* `example.com` account. A
/// site where someone keeps a personal and a work login is exactly where a second fingerprint is
/// cheap and a silent substitution is expensive. Recorded as a deliberate narrowing in ADR-0020.
#[derive(Debug, Default)]
pub struct FillLeaseStore {
    leases: HashMap<(String, String), FillLease>,
}

impl FillLeaseStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant a lease, replacing any existing one for the same pair.
    ///
    /// `ttl_seconds` is clamped to [`MAX_FILL_TTL_SECONDS`], so a UI cannot grant more than the
    /// policy allows however it was asked — the same clamping discipline `approval::outcome_for`
    /// applies to env leases, in the one place that can enforce it.
    pub fn grant(
        &mut self,
        origin: &str,
        item_id: &str,
        item_title: &str,
        client_identity: &str,
        ttl_seconds: u64,
        now: u64,
    ) -> FillLease {
        let ttl = ttl_seconds.clamp(1, MAX_FILL_TTL_SECONDS);
        let lease = FillLease {
            origin: origin.to_owned(),
            item_id: item_id.to_owned(),
            item_title: item_title.to_owned(),
            client_identity: client_identity.to_owned(),
            expires_at: now + ttl,
        };
        self.leases
            .insert((origin.to_owned(), item_id.to_owned()), lease.clone());
        lease
    }

    /// Whether a live lease covers this pair, dropping it if it has expired.
    ///
    /// Expiry is enforced here, on the read, rather than by a sweeper — so a store nobody has
    /// looked at for an hour cannot answer `true` because no timer happened to fire.
    pub fn covers(&mut self, origin: &str, item_id: &str, now: u64) -> bool {
        let key = (origin.to_owned(), item_id.to_owned());
        match self.leases.get(&key) {
            Some(lease) if lease.expires_at > now => true,
            Some(_) => {
                self.leases.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Every live lease, newest expiry last, for the Leases table.
    #[must_use]
    pub fn summaries(&self, now: u64) -> Vec<FillLease> {
        let mut live: Vec<FillLease> = self
            .leases
            .values()
            .filter(|l| l.expires_at > now)
            .cloned()
            .collect();
        live.sort_by(|a, b| {
            a.expires_at
                .cmp(&b.expires_at)
                .then_with(|| a.origin.cmp(&b.origin))
                .then_with(|| a.item_id.cmp(&b.item_id))
        });
        live
    }

    /// Revoke one lease. `false` if there was no such live lease.
    pub fn revoke(&mut self, origin: &str, item_id: &str) -> bool {
        self.leases
            .remove(&(origin.to_owned(), item_id.to_owned()))
            .is_some()
    }

    /// Revoke everything. What a vault lock does.
    pub fn revoke_all(&mut self) {
        self.leases.clear();
    }

    /// How many leases are live right now.
    #[must_use]
    pub fn live_count(&self, now: u64) -> usize {
        self.leases.values().filter(|l| l.expires_at > now).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_757_000_000;

    fn store() -> FillLeaseStore {
        FillLeaseStore::new()
    }

    #[test]
    fn a_granted_lease_covers_its_own_pair_and_nothing_else() {
        let mut store = store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            "chrome",
            300,
            NOW,
        );

        assert!(store.covers("https://example.com", "item-a", NOW + 1));
        assert!(
            !store.covers("https://example.com", "item-b", NOW + 1),
            "a second account at the same site is a second decision"
        );
        assert!(
            !store.covers("https://other.test", "item-a", NOW + 1),
            "a lease is not portable between origins"
        );
        assert!(
            !store.covers("http://example.com", "item-a", NOW + 1),
            "the origin string is compared exactly — a scheme change is a different origin"
        );
    }

    #[test]
    fn a_lease_expires_on_read_rather_than_waiting_for_a_sweeper() {
        let mut store = store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            "chrome",
            300,
            NOW,
        );
        assert!(store.covers("https://example.com", "item-a", NOW + 299));
        assert!(!store.covers("https://example.com", "item-a", NOW + 300));
        assert!(!store.covers("https://example.com", "item-a", NOW + 301));
        assert_eq!(store.live_count(NOW + 301), 0);
    }

    #[test]
    fn a_ttl_past_the_ceiling_is_clamped_down() {
        let mut store = store();
        let lease = store.grant(
            "https://example.com",
            "item-a",
            "Example",
            "chrome",
            86_400,
            NOW,
        );
        assert_eq!(lease.expires_at, NOW + MAX_FILL_TTL_SECONDS);
        assert!(!store.covers("https://example.com", "item-a", NOW + MAX_FILL_TTL_SECONDS));
    }

    #[test]
    fn a_zero_ttl_is_clamped_up_to_a_second_rather_than_minting_a_dead_lease() {
        let mut store = store();
        let lease = store.grant("https://example.com", "i", "E", "chrome", 0, NOW);
        assert_eq!(lease.expires_at, NOW + 1);
    }

    #[test]
    fn granting_again_replaces_rather_than_accumulates() {
        let mut store = store();
        store.grant("https://example.com", "i", "E", "chrome", 60, NOW);
        store.grant("https://example.com", "i", "E", "chrome", 300, NOW);
        assert_eq!(store.summaries(NOW).len(), 1);
        assert_eq!(store.summaries(NOW)[0].expires_at, NOW + 300);
    }

    #[test]
    fn revoking_removes_one_lease_and_says_whether_there_was_one() {
        let mut store = store();
        store.grant("https://a.test", "i", "A", "chrome", 300, NOW);
        store.grant("https://b.test", "i", "B", "chrome", 300, NOW);
        assert!(store.revoke("https://a.test", "i"));
        assert!(
            !store.revoke("https://a.test", "i"),
            "revoking twice is not a lie"
        );
        assert_eq!(store.live_count(NOW), 1);
    }

    #[test]
    fn locking_the_vault_takes_every_lease_with_it() {
        let mut store = store();
        store.grant("https://a.test", "i", "A", "chrome", 300, NOW);
        store.grant("https://b.test", "j", "B", "chrome", 300, NOW);
        assert_eq!(store.live_count(NOW), 2);
        store.revoke_all();
        assert_eq!(store.live_count(NOW), 0);
        assert!(store.summaries(NOW).is_empty());
    }

    #[test]
    fn expired_leases_do_not_appear_in_the_table() {
        let mut store = store();
        store.grant("https://a.test", "i", "A", "chrome", 60, NOW);
        store.grant("https://b.test", "j", "B", "chrome", 600, NOW);
        let live = store.summaries(NOW + 100);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].origin, "https://b.test");
    }
}

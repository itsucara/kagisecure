//! Fill leases: "you already reviewed this item at this origin, in this unlock session".
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
//! A live lease is a **review memory**: it excuses **the sheet**, and never the biometric
//! ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)). A fill
//! it covers, from the top frame of the same origin, is asked of the human as a presence-only
//! request — a fresh Touch ID, login-password or Apple Watch check with no sheet in front of it —
//! instead of the full review. What the lease buys is that logging in twice in five minutes does
//! not mean reading the same sheet twice. What it does not buy, and until ADR-0037 did: a fill
//! with no fresh proof that a human is there.
//!
//! That distinction is the whole point. The request in the page — the in-field icon or ⌘\ — is
//! gated on `event.isTrusted`, which proves only that page script did not dispatch the event.
//! Input synthesized over the DevTools protocol and input injected at the OS level are both
//! trusted, so a browser- or OS-automation agent can make the request with nobody at the
//! keyboard. The LocalAuthentication check is the one step it cannot perform.
//!
//! A presence confirmation never mints or extends a lease: the only caller of
//! [`FillLeaseStore::grant`] takes a `Grant` from a full review answered **Allow for this
//! session**, and the approval queue refuses to mark a presence-only grant as a session.
//!
//! # Session-scoped, so a lock is the end of it
//!
//! There is no persistence. The store lives inside the running [`crate::Agent`]-alike, and
//! `VaultHandle`'s lock hook empties it, exactly as it revokes every env lease. Locking the vault
//! and unlocking it again means the next fill at every origin prompts again.

/// Default life of a fill lease.
///
/// Five minutes rather than the env channel's fifteen: a login flow is seconds long, and the
/// window only has to cover "the site bounced me back to the login page" and "I mistyped the
/// TOTP". A longer default would buy convenience nobody asked for at the cost of a wider window
/// in which a fingerprint is asked for with no sheet in front of it — the window in which a human
/// is most likely to touch the sensor for a prompt they did not cause.
pub const DEFAULT_FILL_TTL_SECONDS: u64 = 300;

/// The longest a fill lease may live, whatever a UI asks for.
pub const MAX_FILL_TTL_SECONDS: u64 = 900;

/// One granted (origin, item, fields) triple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillLease {
    /// The origin the user approved, in ASCII serialization.
    pub origin: String,
    /// The item they approved it for.
    pub item_id: String,
    /// **What** they approved, as the sheet spelled it: `username`, `password`,
    /// `one-time password`. Sorted, so two grants of the same set compare equal.
    ///
    /// The sheet says "This sends the password … once. Nothing else is sent.", and a lease that
    /// did not carry the fields made that sentence false: approving a password released the
    /// one-time code with no second sheet, and the other way round (D-3).
    pub fields: Vec<String>,
    /// The item's title, for the leases table.
    pub item_title: String,
    /// How the caller was identified when the lease was minted.
    pub client_identity: String,
    /// Unix seconds it dies at.
    pub expires_at: u64,
}

/// Every live fill lease.
///
/// Scoped to `(origin, item_id, fields)` rather than to the origin alone. The brief calls this a
/// "per-origin lease", and this is that plus two restrictions: approving *this* password at
/// `https://example.com` does not silently approve the user's *other* `example.com` account, and
/// it does not approve anything the sheet did not name. A site where someone keeps a personal and
/// a work login is exactly where a second fingerprint is cheap and a silent substitution is
/// expensive. Recorded as a deliberate narrowing in ADR-0020.
///
/// A flat `Vec` rather than a map: a live store holds a handful of entries, and the lookup is a
/// **subset** test rather than an equality one, which a hash key cannot express.
#[derive(Debug, Default)]
pub struct FillLeaseStore {
    leases: Vec<FillLease>,
}

impl FillLeaseStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant a lease, replacing any existing one for the same origin, item **and** field set.
    ///
    /// A grant for a different field set is a separate lease rather than a widening of this one:
    /// there is no place in this store where an approval for one thing becomes an approval for
    /// two.
    ///
    /// `ttl_seconds` is clamped to [`MAX_FILL_TTL_SECONDS`], so a UI cannot grant more than the
    /// policy allows however it was asked — the same clamping discipline `approval::outcome_for`
    /// applies to env leases, in the one place that can enforce it.
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &mut self,
        origin: &str,
        item_id: &str,
        item_title: &str,
        fields: &[String],
        client_identity: &str,
        ttl_seconds: u64,
        now: u64,
    ) -> FillLease {
        let ttl = ttl_seconds.clamp(1, MAX_FILL_TTL_SECONDS);
        let mut sorted: Vec<String> = fields.to_vec();
        sorted.sort();
        sorted.dedup();
        let lease = FillLease {
            origin: origin.to_owned(),
            item_id: item_id.to_owned(),
            fields: sorted,
            item_title: item_title.to_owned(),
            client_identity: client_identity.to_owned(),
            expires_at: now.saturating_add(ttl),
        };
        self.leases.retain(|l| {
            !(l.origin == lease.origin && l.item_id == lease.item_id && l.fields == lease.fields)
        });
        self.leases.push(lease.clone());
        lease
    }

    /// Whether a live lease covers this origin, item **and every field asked for**, dropping the
    /// expired ones it passes.
    ///
    /// Expiry is enforced here, on the read, rather than by a sweeper — so a store nobody has
    /// looked at for an hour cannot answer `true` because no timer happened to fire.
    pub fn covers(&mut self, origin: &str, item_id: &str, fields: &[String], now: u64) -> bool {
        self.leases.retain(|l| l.expires_at > now);
        self.leases.iter().any(|l| {
            l.origin == origin
                && l.item_id == item_id
                && fields.iter().all(|f| l.fields.contains(f))
        })
    }

    /// Every live lease, newest expiry last, for the Leases table.
    #[must_use]
    pub fn summaries(&self, now: u64) -> Vec<FillLease> {
        let mut live: Vec<FillLease> = self
            .leases
            .iter()
            .filter(|l| l.expires_at > now)
            .cloned()
            .collect();
        live.sort_by(|a, b| {
            a.expires_at
                .cmp(&b.expires_at)
                .then_with(|| a.origin.cmp(&b.origin))
                .then_with(|| a.item_id.cmp(&b.item_id))
                .then_with(|| a.fields.cmp(&b.fields))
        });
        live
    }

    /// Revoke every lease for this origin and item, whatever fields they cover. `false` if there
    /// was no such live lease.
    pub fn revoke(&mut self, origin: &str, item_id: &str) -> bool {
        let before = self.leases.len();
        self.leases
            .retain(|l| !(l.origin == origin && l.item_id == item_id));
        self.leases.len() != before
    }

    /// Revoke everything. What a vault lock does.
    pub fn revoke_all(&mut self) {
        self.leases.clear();
    }

    /// How many leases are live right now.
    #[must_use]
    pub fn live_count(&self, now: u64) -> usize {
        self.leases.iter().filter(|l| l.expires_at > now).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_757_000_000;

    fn new_store() -> FillLeaseStore {
        FillLeaseStore::new()
    }

    fn password() -> Vec<String> {
        vec!["password".to_owned()]
    }

    fn totp() -> Vec<String> {
        vec!["one-time password".to_owned()]
    }

    #[test]
    fn a_granted_lease_covers_its_own_triple_and_nothing_else() {
        let mut store = new_store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &password(),
            "chrome",
            300,
            NOW,
        );

        assert!(store.covers("https://example.com", "item-a", &password(), NOW + 1));
        assert!(
            !store.covers("https://example.com", "item-b", &password(), NOW + 1),
            "a second account at the same site is a second decision"
        );
        assert!(
            !store.covers("https://other.test", "item-a", &password(), NOW + 1),
            "a lease is not portable between origins"
        );
        assert!(
            !store.covers("http://example.com", "item-a", &password(), NOW + 1),
            "the origin string is compared exactly — a scheme change is a different origin"
        );
    }

    #[test]
    fn a_password_lease_does_not_cover_the_one_time_code_or_the_other_way_round() {
        let mut store = new_store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &password(),
            "chrome",
            300,
            NOW,
        );
        assert!(
            !store.covers("https://example.com", "item-a", &totp(), NOW + 1),
            "the sheet said password; it did not say one-time code (D-3)"
        );

        let mut store = new_store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &totp(),
            "chrome",
            300,
            NOW,
        );
        assert!(!store.covers("https://example.com", "item-a", &password(), NOW + 1));
    }

    #[test]
    fn a_lease_covers_a_subset_of_what_it_granted_but_never_a_superset() {
        let mut store = new_store();
        let both = vec!["password".to_owned(), "username".to_owned()];
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &both,
            "chrome",
            300,
            NOW,
        );
        assert!(store.covers("https://example.com", "item-a", &password(), NOW + 1));
        assert!(store.covers("https://example.com", "item-a", &both, NOW + 1));
        let more = vec![
            "password".to_owned(),
            "username".to_owned(),
            "one-time password".to_owned(),
        ];
        assert!(!store.covers("https://example.com", "item-a", &more, NOW + 1));
    }

    #[test]
    fn two_field_sets_at_one_pair_are_two_leases_rather_than_one_widened_one() {
        let mut store = new_store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &password(),
            "chrome",
            300,
            NOW,
        );
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &totp(),
            "chrome",
            300,
            NOW,
        );
        assert_eq!(store.live_count(NOW), 2);
        assert!(store.covers("https://example.com", "item-a", &password(), NOW + 1));
        assert!(store.covers("https://example.com", "item-a", &totp(), NOW + 1));
    }

    #[test]
    fn a_lease_expires_on_read_rather_than_waiting_for_a_sweeper() {
        let mut store = new_store();
        store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &password(),
            "chrome",
            300,
            NOW,
        );
        assert!(store.covers("https://example.com", "item-a", &password(), NOW + 299));
        assert!(!store.covers("https://example.com", "item-a", &password(), NOW + 300));
        assert!(!store.covers("https://example.com", "item-a", &password(), NOW + 301));
        assert_eq!(store.live_count(NOW + 301), 0);
    }

    #[test]
    fn a_ttl_past_the_ceiling_is_clamped_down() {
        let mut store = new_store();
        let lease = store.grant(
            "https://example.com",
            "item-a",
            "Example",
            &password(),
            "chrome",
            86_400,
            NOW,
        );
        assert_eq!(lease.expires_at, NOW + MAX_FILL_TTL_SECONDS);
        assert!(!store.covers(
            "https://example.com",
            "item-a",
            &password(),
            NOW + MAX_FILL_TTL_SECONDS
        ));
    }

    #[test]
    fn a_zero_ttl_is_clamped_up_to_a_second_rather_than_minting_a_dead_lease() {
        let mut store = new_store();
        let lease = store.grant(
            "https://example.com",
            "i",
            "E",
            &password(),
            "chrome",
            0,
            NOW,
        );
        assert_eq!(lease.expires_at, NOW + 1);
    }

    #[test]
    fn granting_the_same_fields_again_replaces_rather_than_accumulates() {
        let mut store = new_store();
        store.grant(
            "https://example.com",
            "i",
            "E",
            &password(),
            "chrome",
            60,
            NOW,
        );
        store.grant(
            "https://example.com",
            "i",
            "E",
            &password(),
            "chrome",
            300,
            NOW,
        );
        assert_eq!(store.summaries(NOW).len(), 1);
        assert_eq!(store.summaries(NOW)[0].expires_at, NOW + 300);
    }

    #[test]
    fn revoking_removes_one_pair_and_says_whether_there_was_one() {
        let mut store = new_store();
        store.grant("https://a.test", "i", "A", &password(), "chrome", 300, NOW);
        store.grant("https://b.test", "i", "B", &password(), "chrome", 300, NOW);
        assert!(store.revoke("https://a.test", "i"));
        assert!(
            !store.revoke("https://a.test", "i"),
            "revoking twice is not a lie"
        );
        assert_eq!(store.live_count(NOW), 1);
    }

    #[test]
    fn locking_the_vault_takes_every_lease_with_it() {
        let mut store = new_store();
        store.grant("https://a.test", "i", "A", &password(), "chrome", 300, NOW);
        store.grant("https://b.test", "j", "B", &totp(), "chrome", 300, NOW);
        assert_eq!(store.live_count(NOW), 2);
        store.revoke_all();
        assert_eq!(store.live_count(NOW), 0);
        assert!(store.summaries(NOW).is_empty());
    }

    #[test]
    fn expired_leases_do_not_appear_in_the_table() {
        let mut store = new_store();
        store.grant("https://a.test", "i", "A", &password(), "chrome", 60, NOW);
        store.grant("https://b.test", "j", "B", &password(), "chrome", 600, NOW);
        let live = store.summaries(NOW + 100);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].origin, "https://b.test");
    }
}

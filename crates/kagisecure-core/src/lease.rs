//! Approval leases (mcp-server.md §5, threat-model M-6).
//!
//! A lease is the unit of granted access. It is **memory only** — nothing here is serialized to
//! disk, so restarting the process that owns the vault is a clean slate — and it dies on expiry,
//! use exhaustion, lock, or explicit revoke.
//!
//! The rules that matter are all in [`Lease::covers`]:
//!
//! * the directory must match **exactly, after canonicalization** — no prefix matching, so
//!   `/Users/x/code` never authorizes `/Users/x/code/../../../tmp`;
//! * the requested variables must be a **subset** of the leased ones;
//! * a `RunCommand` lease is additionally bound to `(command, cwd)`;
//! * anything broader than an existing lease is simply not covered, which means a fresh approval.
//!   There is no widening, no merging, and no "always allow".
//!
//! This module holds no secret material and is compiled with and without `secret-material`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::proto::{EnvId, LeaseId, LeaseKind, LeaseSummary};

/// Default lease duration, in seconds (mcp-server.md §5).
pub const DEFAULT_TTL_SECONDS: u64 = 900;
/// Longest lease a user may grant, in seconds.
pub const MAX_TTL_SECONDS: u64 = 86_400;
/// Shortest lease the schema accepts, in seconds.
pub const MIN_TTL_SECONDS: u64 = 60;
/// Default number of uses a lease carries.
pub const DEFAULT_USES: u32 = 10;

/// A granted, bounded permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    /// Identifier, handed back to the caller so it can revoke.
    pub id: LeaseId,
    /// The one environment this lease is about.
    pub environment_id: EnvId,
    /// The one directory this lease is about, canonicalized.
    pub directory: PathBuf,
    /// The variable names covered.
    pub variables: BTreeSet<String>,
    /// What the lease permits.
    pub kind: LeaseKind,
    /// For [`LeaseKind::RunCommand`], the program and argv the user approved.
    pub command: Option<Vec<String>>,
    /// The caller the lease was minted for, as the daemon rendered it.
    pub client_identity: String,
    /// Unix seconds at which the lease expires.
    pub expires_at: u64,
    /// Uses left.
    pub uses_remaining: u32,
    /// Files written under this lease, so a revoke can shred them.
    pub written_paths: Vec<PathBuf>,
}

impl Lease {
    /// Whether the lease is still alive at `now` (unix seconds).
    #[must_use]
    pub fn is_live(&self, now: u64) -> bool {
        self.uses_remaining > 0 && now < self.expires_at
    }

    /// Whether this lease already authorizes `request`, so no fresh approval is needed.
    ///
    /// Deliberately conservative: every dimension must be equal or narrower. A request for one
    /// more variable, a different directory, a different environment, or a different command is
    /// **not** covered, and the caller must ask the human again (no privilege creep, M-6).
    #[must_use]
    pub fn covers(&self, request: &LeaseRequest, now: u64) -> bool {
        self.is_live(now)
            && self.environment_id == request.environment_id
            && self.kind == request.kind
            && self.directory == request.directory
            && request.variables.is_subset(&self.variables)
            && match (&self.command, &request.command) {
                (_, None) => true,
                (Some(mine), Some(theirs)) => mine == theirs,
                (None, Some(_)) => false,
            }
    }

    /// Metadata view, for the audit log and for a lease list in a UI.
    #[must_use]
    pub fn summary(&self) -> LeaseSummary {
        LeaseSummary {
            id: self.id,
            environment_id: self.environment_id,
            directory: self.directory.display().to_string(),
            variables: self.variables.iter().cloned().collect(),
            kind: self.kind,
            client_identity: self.client_identity.clone(),
            expires_at: self.expires_at,
            uses_remaining: self.uses_remaining,
        }
    }
}

/// What a caller is asking for, in lease terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRequest {
    /// The environment.
    pub environment_id: EnvId,
    /// The target directory, already canonicalized by the caller.
    pub directory: PathBuf,
    /// The variable names.
    pub variables: BTreeSet<String>,
    /// What is being asked for.
    pub kind: LeaseKind,
    /// For [`LeaseKind::RunCommand`], the program and argv.
    pub command: Option<Vec<String>>,
}

/// The set of live leases held by the process that owns the unlocked vault.
#[derive(Debug, Default)]
pub struct LeaseStore {
    leases: Vec<Lease>,
}

impl LeaseStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every lease that has expired or run out of uses.
    pub fn prune(&mut self, now: u64) {
        self.leases.retain(|l| l.is_live(now));
    }

    /// The first live lease covering `request`, if any.
    pub fn find(&mut self, request: &LeaseRequest, now: u64) -> Option<&Lease> {
        self.prune(now);
        self.leases.iter().find(|l| l.covers(request, now))
    }

    /// Consume one use of the lease with this id.
    ///
    /// Returns `false` if there is no such live lease, in which case nothing was consumed.
    pub fn consume(&mut self, id: LeaseId, now: u64) -> bool {
        self.prune(now);
        match self.leases.iter_mut().find(|l| l.id == id) {
            Some(lease) => {
                lease.uses_remaining = lease.uses_remaining.saturating_sub(1);
                true
            }
            None => false,
        }
    }

    /// Mint a lease for an approved request.
    ///
    /// `ttl_seconds` is clamped to [`MIN_TTL_SECONDS`]..=[`MAX_TTL_SECONDS`]; the caller is
    /// expected to have already shortened it to whatever the human agreed to.
    pub fn grant(
        &mut self,
        request: &LeaseRequest,
        client_identity: impl Into<String>,
        ttl_seconds: u64,
        uses: u32,
        now: u64,
    ) -> LeaseId {
        let ttl = ttl_seconds.clamp(MIN_TTL_SECONDS, MAX_TTL_SECONDS);
        let lease = Lease {
            id: LeaseId::new(),
            environment_id: request.environment_id,
            directory: request.directory.clone(),
            variables: request.variables.clone(),
            kind: request.kind,
            command: request.command.clone(),
            client_identity: client_identity.into(),
            expires_at: now.saturating_add(ttl),
            uses_remaining: uses.max(1),
            written_paths: Vec::new(),
        };
        let id = lease.id;
        self.leases.push(lease);
        id
    }

    /// Record that `path` was written under `id`, so a revoke can shred it.
    pub fn record_written(&mut self, id: LeaseId, path: PathBuf) {
        if let Some(lease) = self.leases.iter_mut().find(|l| l.id == id)
            && !lease.written_paths.contains(&path)
        {
            lease.written_paths.push(path);
        }
    }

    /// Remove the lease with this id, returning the paths written under it.
    pub fn revoke(&mut self, id: LeaseId) -> Option<Vec<PathBuf>> {
        let index = self.leases.iter().position(|l| l.id == id)?;
        Some(self.leases.remove(index).written_paths)
    }

    /// Remove every lease that wrote `path`, returning all paths written under them.
    pub fn revoke_by_path(&mut self, path: &Path) -> Vec<PathBuf> {
        let mut shredded = Vec::new();
        let mut kept = Vec::with_capacity(self.leases.len());
        for lease in std::mem::take(&mut self.leases) {
            if lease.written_paths.iter().any(|p| p == path) {
                shredded.extend(lease.written_paths);
            } else {
                kept.push(lease);
            }
        }
        self.leases = kept;
        shredded
    }

    /// Drop every lease. This is what locking, sleeping and screen-locking do.
    pub fn revoke_all(&mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.leases)
            .into_iter()
            .flat_map(|l| l.written_paths)
            .collect()
    }

    /// Metadata for every live lease.
    pub fn summaries(&mut self, now: u64) -> Vec<LeaseSummary> {
        self.prune(now);
        self.leases.iter().map(Lease::summary).collect()
    }

    /// How many leases are live.
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Whether there are no leases at all.
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_757_376_000;

    fn vars(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn request(env: EnvId, dir: &str, names: &[&str]) -> LeaseRequest {
        LeaseRequest {
            environment_id: env,
            directory: PathBuf::from(dir),
            variables: vars(names),
            kind: LeaseKind::EnvFile,
            command: None,
        }
    }

    #[test]
    fn a_fresh_lease_covers_the_request_that_created_it() {
        let env = EnvId::new();
        let req = request(env, "/p", &["A", "B"]);
        let mut store = LeaseStore::new();
        store.grant(&req, "test", DEFAULT_TTL_SECONDS, DEFAULT_USES, NOW);
        assert!(store.find(&req, NOW).is_some());
    }

    #[test]
    fn a_narrower_request_is_covered_but_a_broader_one_is_not() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        store.grant(
            &request(env, "/p", &["A", "B"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        assert!(store.find(&request(env, "/p", &["A"]), NOW).is_some());
        assert!(
            store.find(&request(env, "/p", &["A", "C"]), NOW).is_none(),
            "one extra variable must re-prompt"
        );
    }

    #[test]
    fn the_directory_match_is_exact_not_a_prefix() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        store.grant(
            &request(env, "/Users/x/code", &["A"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        for other in ["/Users/x/code/sub", "/Users/x", "/Users/x/code2"] {
            assert!(
                store.find(&request(env, other, &["A"]), NOW).is_none(),
                "{other} must not be covered by a lease on /Users/x/code"
            );
        }
    }

    #[test]
    fn a_different_environment_is_never_covered() {
        let mut store = LeaseStore::new();
        store.grant(
            &request(EnvId::new(), "/p", &["A"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        assert!(
            store
                .find(&request(EnvId::new(), "/p", &["A"]), NOW)
                .is_none()
        );
    }

    #[test]
    fn a_lease_expires() {
        let env = EnvId::new();
        let req = request(env, "/p", &["A"]);
        let mut store = LeaseStore::new();
        store.grant(&req, "test", MIN_TTL_SECONDS, DEFAULT_USES, NOW);
        assert!(store.find(&req, NOW + MIN_TTL_SECONDS - 1).is_some());
        assert!(store.find(&req, NOW + MIN_TTL_SECONDS).is_none());
        assert!(store.is_empty(), "an expired lease is pruned, not kept");
    }

    #[test]
    fn a_lease_runs_out_of_uses() {
        let env = EnvId::new();
        let req = request(env, "/p", &["A"]);
        let mut store = LeaseStore::new();
        let id = store.grant(&req, "test", DEFAULT_TTL_SECONDS, 2, NOW);
        assert!(store.consume(id, NOW));
        assert!(store.find(&req, NOW).is_some());
        assert!(store.consume(id, NOW));
        assert!(store.find(&req, NOW).is_none());
    }

    #[test]
    fn ttl_is_clamped_to_the_documented_range() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let id = store.grant(&request(env, "/p", &["A"]), "test", 10, 1, NOW);
        let live = store.summaries(NOW);
        assert_eq!(live[0].id, id);
        assert_eq!(live[0].expires_at, NOW + MIN_TTL_SECONDS);

        let id = store.grant(&request(env, "/q", &["A"]), "test", 10_000_000, 1, NOW);
        let live = store.summaries(NOW);
        let long = live.iter().find(|l| l.id == id).unwrap();
        assert_eq!(long.expires_at, NOW + MAX_TTL_SECONDS);
    }

    #[test]
    fn a_run_lease_is_bound_to_its_command() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let run = |argv: &[&str]| LeaseRequest {
            environment_id: env,
            directory: PathBuf::from("/p"),
            variables: vars(&["A"]),
            kind: LeaseKind::RunCommand,
            command: Some(argv.iter().map(|s| (*s).to_owned()).collect()),
        };
        store.grant(
            &run(&["npm", "run", "build"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        assert!(store.find(&run(&["npm", "run", "build"]), NOW).is_some());
        assert!(store.find(&run(&["npm", "run", "deploy"]), NOW).is_none());
        assert!(
            store.find(&request(env, "/p", &["A"]), NOW).is_none(),
            "a run lease must not authorize writing a file"
        );
    }

    #[test]
    fn revoking_returns_the_paths_to_shred_and_removes_the_lease() {
        let env = EnvId::new();
        let req = request(env, "/p", &["A"]);
        let mut store = LeaseStore::new();
        let id = store.grant(&req, "test", DEFAULT_TTL_SECONDS, DEFAULT_USES, NOW);
        store.record_written(id, PathBuf::from("/p/.env"));
        store.record_written(id, PathBuf::from("/p/.env"));
        assert_eq!(store.revoke(id), Some(vec![PathBuf::from("/p/.env")]));
        assert!(store.revoke(id).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn revoking_by_path_finds_the_lease_that_wrote_it() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let id = store.grant(
            &request(env, "/p", &["A"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        store.record_written(id, PathBuf::from("/p/.env"));
        assert_eq!(
            store.revoke_by_path(Path::new("/p/.env")),
            vec![PathBuf::from("/p/.env")]
        );
        assert!(store.is_empty());
    }

    #[test]
    fn locking_drops_everything() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let id = store.grant(
            &request(env, "/p", &["A"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        store.record_written(id, PathBuf::from("/p/.env"));
        assert_eq!(store.revoke_all(), vec![PathBuf::from("/p/.env")]);
        assert_eq!(store.len(), 0);
    }
}

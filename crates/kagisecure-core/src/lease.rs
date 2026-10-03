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
//! * an `EnvFile` lease is bound to the **one file name** the human was shown, so an approval for
//!   `.env.example` never writes `.env`;
//! * the requested variables must be a **subset** of the leased ones;
//! * a `RunCommand` lease is additionally bound to `(command, cwd)`;
//! * replacing a file kagisecure did not write is **never** covered: that is a question about the
//!   user's file, not about the directory the lease was granted for, and it goes to the human every
//!   time (mcp-server.md §2.7, threat-model M-16);
//! * anything broader than an existing lease is simply not covered, which means a fresh approval.
//!   There is no widening, no merging, and no "always allow".
//!
//! This module holds no secret material and is compiled with and without `secret-material`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::proto::{EnvId, LeaseId, LeaseKind, LeaseSummary};

/// Which file a path named at the moment kagisecure wrote it: `(device, file number)` —
/// `st_dev`/`st_ino` on Unix, volume serial number and file index on Windows.
///
/// The written ledger records this beside every path, because the path alone is not the file:
/// after a write, the path can be pointed at something else (a symlink to the user's SSH key, a
/// different file renamed over it), and the ledger is the entire authorization for shredding
/// without an approval. `kagisecure_core::inject::envfile::shred` destroys bytes only through a
/// handle whose identity equals the one recorded here. Plain data, so this module stays free of
/// any filesystem code; the envfile writer is what reads it off the file it just wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileIdentity {
    device: u64,
    index: u128,
}

impl FileIdentity {
    /// An identity from the OS's own numbers for an open file.
    #[must_use]
    pub fn new(device: u64, index: u128) -> Self {
        Self { device, index }
    }
}

/// One file this store wrote: where, and which file that was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrittenEntry {
    /// The path the file was written at.
    pub path: PathBuf,
    /// The file that path named when kagisecure wrote it — the only file a shred may touch.
    pub identity: FileIdentity,
}

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
    /// For [`LeaseKind::EnvFile`], the one file name the human approved. `None` for a lease that
    /// is not about a file.
    pub filename: Option<String>,
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
        !request.replaces_unowned_file
            && self.is_live(now)
            && self.environment_id == request.environment_id
            && self.kind == request.kind
            && self.directory == request.directory
            && self.filename == request.filename
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
    /// For [`LeaseKind::EnvFile`], the file name that would be written. Part of what the lease
    /// covers: a request for a different name is a different question for the human.
    pub filename: Option<String>,
    /// The variable names.
    pub variables: BTreeSet<String>,
    /// What is being asked for.
    pub kind: LeaseKind,
    /// For [`LeaseKind::RunCommand`], the program and argv.
    pub command: Option<Vec<String>>,
    /// The write would replace a file that is there now and is not the one kagisecure wrote at
    /// that path — the user's own `.env`, or anything else put there since. No lease covers
    /// that ([`Lease::covers`]): an approval to write kagisecure's file into a directory is not
    /// an approval to replace the user's, so the human is asked, with the sheet saying so.
    pub replaces_unowned_file: bool,
}

/// The set of live leases held by the process that owns the unlocked vault.
#[derive(Debug, Default)]
pub struct LeaseStore {
    leases: Vec<Lease>,
    /// Every path this store has ever written in this unlock session, with the identity of the
    /// file most recently written there ([`FileIdentity`]).
    ///
    /// Deliberately **outlives the leases**: a lease dies on expiry or on its last use, but the
    /// file it wrote is still on disk, and a revoke that arrives afterwards must still be able to
    /// shred it. It is also the only record of what this vault wrote, which is what makes
    /// `revoke_env_file` a cleanup tool rather than a delete-any-file primitive. Memory only, so
    /// restarting the process holding the key is a clean slate — see the module header.
    written: BTreeMap<PathBuf, FileIdentity>,
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
            filename: request.filename.clone(),
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

    /// Record that `path` was written under `id`, as the file `identity`, so a revoke can shred
    /// it — and only it. Writing the same path again replaces the recorded identity: the file
    /// there now is the one kagisecure wrote last.
    pub fn record_written(&mut self, id: LeaseId, path: PathBuf, identity: FileIdentity) {
        self.written.insert(path.clone(), identity);
        if let Some(lease) = self.leases.iter_mut().find(|l| l.id == id)
            && !lease.written_paths.contains(&path)
        {
            lease.written_paths.push(path);
        }
    }

    /// Whether this store wrote `path` at some point in this unlock session.
    ///
    /// The authorization question for shredding: a path nobody here wrote is somebody else's
    /// file, whatever a caller says about it.
    ///
    /// It is a question about the *path*. Whether the file there now is still the one written is
    /// the recorded identity ([`Self::written`]), compared against the file itself.
    #[must_use]
    pub fn wrote(&self, path: &Path) -> bool {
        self.written.contains_key(path)
    }

    /// The ledger entry for `path`, if this store wrote it in this unlock session.
    #[must_use]
    pub fn written(&self, path: &Path) -> Option<WrittenEntry> {
        self.written.get(path).map(|identity| WrittenEntry {
            path: path.to_path_buf(),
            identity: *identity,
        })
    }

    /// The ledger entries for `paths`, each with the identity most recently written there — not
    /// whatever was current when one particular lease wrote it, since a later write under another
    /// lease replaced that file.
    fn entries_for(&self, paths: impl IntoIterator<Item = PathBuf>) -> Vec<WrittenEntry> {
        paths
            .into_iter()
            .filter_map(|path| self.written(&path))
            .collect()
    }

    /// Remove the lease with this id, returning what was written under it.
    pub fn revoke(&mut self, id: LeaseId) -> Option<Vec<WrittenEntry>> {
        let index = self.leases.iter().position(|l| l.id == id)?;
        let paths = self.leases.remove(index).written_paths;
        Some(self.entries_for(paths))
    }

    /// Remove every lease that wrote `path`, returning everything written under them.
    pub fn revoke_by_path(&mut self, path: &Path) -> Vec<WrittenEntry> {
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
        self.entries_for(shredded)
    }

    /// Drop every lease and return every path this store has ever written in this unlock
    /// session, so a caller can shred all of them. This is what locking, sleeping and
    /// screen-locking do.
    ///
    /// Returns `self.written`, not `self.leases`' own `written_paths`: a lease that ran out of
    /// uses or expired before the lock — "Allow once", say — is already gone from `self.leases`
    /// by the time this runs, but the file it wrote is still on disk and this is the one moment
    /// there is no later revoke to catch it. `written` is exactly the ledger built for this (see
    /// its own doc comment) — it deliberately outlives the lease that populated it. Using
    /// `self.leases` here, as an earlier version of this method did, silently left such a file
    /// unshredded past a lock: a live key on disk after "lock" had already told the user every
    /// lease and everything written under one was gone.
    pub fn revoke_all(&mut self) -> Vec<WrittenEntry> {
        self.leases.clear();
        std::mem::take(&mut self.written)
            .into_iter()
            .map(|(path, identity)| WrittenEntry { path, identity })
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
    const ID: FileIdentity = FileIdentity {
        device: 1,
        index: 2,
    };

    fn entry(path: &str) -> WrittenEntry {
        WrittenEntry {
            path: PathBuf::from(path),
            identity: ID,
        }
    }

    fn vars(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn request(env: EnvId, dir: &str, names: &[&str]) -> LeaseRequest {
        named_request(env, dir, ".env", names)
    }

    fn named_request(env: EnvId, dir: &str, filename: &str, names: &[&str]) -> LeaseRequest {
        LeaseRequest {
            environment_id: env,
            directory: PathBuf::from(dir),
            filename: Some(filename.to_owned()),
            variables: vars(names),
            kind: LeaseKind::EnvFile,
            command: None,
            replaces_unowned_file: false,
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
    fn a_lease_is_bound_to_the_file_name_it_was_approved_for() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        store.grant(
            &named_request(env, "/p", ".env.example", &["A"]),
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        assert!(
            store
                .find(&named_request(env, "/p", ".env.example", &["A"]), NOW)
                .is_some()
        );
        assert!(
            store
                .find(&named_request(env, "/p", ".env", &["A"]), NOW)
                .is_none(),
            "an approval for one file name must not write another file"
        );
    }

    #[test]
    fn the_record_of_what_was_written_outlives_the_lease_that_wrote_it() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let id = store.grant(&request(env, "/p", &["A"]), "test", MIN_TTL_SECONDS, 1, NOW);
        store.record_written(id, PathBuf::from("/p/.env"), ID);
        store.prune(NOW + MIN_TTL_SECONDS);
        assert!(store.is_empty(), "the lease is gone");
        assert!(
            store.wrote(Path::new("/p/.env")),
            "but a revoke arriving after the expiry can still shred what it wrote"
        );
        assert!(!store.wrote(Path::new("/p/notes.txt")));
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
            filename: None,
            variables: vars(&["A"]),
            kind: LeaseKind::RunCommand,
            command: Some(argv.iter().map(|s| (*s).to_owned()).collect()),
            replaces_unowned_file: false,
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
        store.record_written(id, PathBuf::from("/p/.env"), ID);
        store.record_written(id, PathBuf::from("/p/.env"), ID);
        assert_eq!(store.revoke(id), Some(vec![entry("/p/.env")]));
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
        store.record_written(id, PathBuf::from("/p/.env"), ID);
        assert_eq!(
            store.revoke_by_path(Path::new("/p/.env")),
            vec![entry("/p/.env")]
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
        store.record_written(id, PathBuf::from("/p/.env"), ID);
        assert_eq!(store.revoke_all(), vec![entry("/p/.env")]);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn locking_shreds_what_an_already_exhausted_lease_wrote() {
        // "Allow once": the lease is granted for exactly one use, writes a file, and is consumed
        // — so by the time the user locks, `self.leases` no longer holds it at all. The file it
        // wrote must still be on the list `revoke_all` hands back, because the written-path
        // ledger (`self.written`) deliberately outlives the lease, and locking is the one moment
        // there is no later revoke to catch what an earlier version of `revoke_all` missed.
        let env = EnvId::new();
        let req = request(env, "/p", &["A"]);
        let mut store = LeaseStore::new();
        let id = store.grant(&req, "test", DEFAULT_TTL_SECONDS, 1, NOW);
        store.record_written(id, PathBuf::from("/p/.env"), ID);
        assert!(store.consume(id, NOW), "the one use is spent");
        store.prune(NOW);
        assert!(
            store.is_empty(),
            "an exhausted lease is gone before the lock ever happens"
        );
        assert!(
            store.wrote(Path::new("/p/.env")),
            "but the ledger of what this store wrote still remembers it"
        );

        assert_eq!(
            store.revoke_all(),
            vec![entry("/p/.env")],
            "locking must still shred a file written under a lease that ran out of uses first"
        );
        assert!(store.is_empty());
        assert!(
            !store.wrote(Path::new("/p/.env")),
            "the ledger itself is cleared too, so a stale entry cannot survive into the next \
             unlock session"
        );
    }

    #[test]
    fn no_lease_covers_replacing_a_file_kagisecure_did_not_write() {
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let req = request(env, "/p", &["A"]);
        store.grant(&req, "test", DEFAULT_TTL_SECONDS, DEFAULT_USES, NOW);
        assert!(store.find(&req, NOW).is_some());
        let overwrite_theirs = LeaseRequest {
            replaces_unowned_file: true,
            ..req.clone()
        };
        assert!(
            store.find(&overwrite_theirs, NOW).is_none(),
            "the same lease must not cover replacing the user's file"
        );
        // Not even a lease minted for exactly such a request covers the next one.
        store.grant(
            &overwrite_theirs,
            "test",
            DEFAULT_TTL_SECONDS,
            DEFAULT_USES,
            NOW,
        );
        assert!(store.find(&overwrite_theirs, NOW).is_none());
    }

    #[test]
    fn revoking_an_older_lease_hands_back_the_identity_of_the_file_written_last() {
        // Lease A writes `.env`; lease B (a different variable set, so a second approval)
        // overwrites it. The file on disk is B's. Revoking A must name that file, not the one A
        // wrote and B's rename replaced — otherwise the shredder would refuse kagisecure's own
        // file as "replaced".
        let env = EnvId::new();
        let mut store = LeaseStore::new();
        let a = store.grant(
            &request(env, "/p", &["A"]),
            "test",
            DEFAULT_TTL_SECONDS,
            1,
            NOW,
        );
        let b = store.grant(
            &request(env, "/p", &["B"]),
            "test",
            DEFAULT_TTL_SECONDS,
            1,
            NOW,
        );
        let later = FileIdentity::new(9, 9);
        store.record_written(a, PathBuf::from("/p/.env"), ID);
        store.record_written(b, PathBuf::from("/p/.env"), later);
        assert_eq!(
            store.revoke(a),
            Some(vec![WrittenEntry {
                path: PathBuf::from("/p/.env"),
                identity: later,
            }])
        );
    }
}

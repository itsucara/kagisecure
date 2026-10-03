# ADR-0039: Transactional vault writes and the sibling lock file

- **Status:** Accepted and implemented: every writer — the agent and browser-extension paths, the
  macOS app (through `kagisecure-ffi`), the CLI and import — commits through a transaction, and the
  human choice for a file that can no longer be built on (§9, §10) is built. What remains open is
  listed under "What is and is not implemented" below.
- **Date:** 2026-09-25
- **Renumbered:** written as ADR-0032; renumbered to ADR-0039 on 2026-09-26 when `main`'s Windows
  port, which had already taken 0032–0034, was merged. Commits before that date say ADR-0032.
- **Deciders:** feat/vault-transactions implementation
- **Refines:** [architecture.md](../architecture.md) §2.3a, §2.5, §2.6,
  [vault-format.md](../vault-format.md) §8, [threat-model.md](../threat-model.md) T-3, W-11
- **Refined by:** [ADR-0040](0040-audit-before-release.md), [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)

## Context

One vault file is written by more than one process — the macOS app, `kagisecure daemon`, the CLI —
and, inside the app, by more than one logical writer touching the same `kagisecure-agent` handle.
Every writer holds the whole decrypted body in memory and `Vault::save()` replaced the file with
its own copy. Nothing about that was unsafe for a single writer; it was unsafe the moment two of
them existed, because the second save silently discarded whatever the first had committed since it
last read the file. That is an ordinary lost-update bug in most software. Here it is worse than
ordinary, for two reasons specific to what a vault holds:

- **The lost data is often the record of something security-relevant having happened.** A revoked
  agent-access flag, a reissued recovery code, or a burst of denied MCP requests can all be
  reverted by a save from a process that read the file before that change landed — not through any
  attack, just through the app doing its own next save. The audit log documents (vault-format.md
  §8, `crates/kagisecure-core/src/audit.rs`) that a *deliberate* rollback of the file is a known
  weak point (W-11); this ADR is about the same file going backwards **by accident**, which needed
  no attacker at all, just two of this project's own processes running at once.
- **The two processes are not optional.** architecture.md §2.6 keeps `kagisecure daemon` and the
  CLI beside the app specifically for the headless cases — SSH, CI, a Linux box with no GUI — so
  "only ever run one writer" is not a constraint kagisecure can impose on its own users.

Something had to serialize writers and stop a write from building on a state that is no longer on
disk. Three questions shaped what: where does the lock live, given that a save *replaces* the file
rather than editing it in place; what does a writer do when it discovers the file changed under it,
given that re-running the caller's whole request from scratch is not always possible; and how does
this interact with the operations that need Argon2id — a new master password, a KDF upgrade, a new
recovery code — which must never happen while something else is blocked waiting for a lock.

## Decision

### 1. The lock lives on a sibling file, never the vault itself

`write_atomically` replaces a vault by renaming a complete temporary file over its path. A lock
taken on the vault file's inode would therefore be a lock on an inode the very next save unlinks:
the next writer opens the *new* file, finds it unlocked, and two processes believe they hold the
lock at once. The lock instead lives on `<vault>.lock` (`vault::lock::lock_path`) — a separate,
empty file created once, mode `0600`, **never written and never deleted**. Deleting it on release
would reintroduce the same race one level down: a waiter still holding a handle to the unlinked
inode would lock that orphan while a newcomer created and locked a fresh file at the same path.

It is `std::fs::File::lock`/`try_lock` (stable since 1.89; the workspace's `rust-version` is
1.98) — `flock(2)` on Unix, `LockFileEx` on Windows. It is **advisory and cooperative, not a
security boundary**: anything running as the user can write the vault file directly, lock or no
lock. What it stops is kagisecure's own writers erasing each other's work, nothing more. Readers
never take it: the atomic rename already guarantees a read sees either the whole old file or the
whole new one, never a mixture.

On Unix, after a successful `try_lock`, the acquirer compares the `(dev, ino)` of the handle it
holds against a fresh `stat` of the path, and starts over if the file was replaced between its
`open` and its `flock` — otherwise it would be holding a lock on an orphaned inode nobody else will
ever look at. The same check runs again immediately before a write (`ensure_current`), and fails
closed with `Error::LockLost` if the lock file was renamed or deleted while held: by then a second
process may already have created and locked a fresh one, so writing anyway would be exactly the
lost update this whole mechanism exists to prevent. A rename landing in the instant between that
check and the write is not caught — the residual price of an advisory lock any same-user process
can tamper with. On Windows the file is opened without `FILE_SHARE_DELETE`, so it cannot be renamed
or deleted out from under a holder at all, and neither check is needed there.

The kernel releases the lock when its holder exits for any reason, `SIGKILL` included, so a crashed
writer can never wedge the vault; `flock` locks belong to an open file description and std opens
every file close-on-exec, so a spawned child never inherits one.

### 2. A generation is the SHA-256 of the file's exact bytes

Recorded whenever a vault is opened or created (the bytes that were decrypted) and after every
write (the bytes that were written). It is how any writer, transactional or not, answers "is the
file still the version my memory descends from" without needing anything from the file beyond its
current contents — no separate counter to keep in step, and no distinction between a body change
and a header-only change (a password change, a KDF upgrade, a platform-slot install all produce a
new generation the same way an item edit does). `refresh_if_changed` fast-paths this on Unix via
`(dev, ino, size, mtime)` before falling back to reading and hashing.

### 3. `Vault::transact` — the shape every write should have

```rust
impl Vault {
    pub fn transact<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T>;
    pub fn refresh_if_changed(&mut self) -> Result<bool>;
}
// Tx derefs to the vault's read side and is the only holder of every mutator; Vault itself
// is read-only Deref outside a transaction.
```

A transaction is, in order: (1) acquire the sibling lock, waiting a bounded time
(`Error::VaultBusy` on timeout); (2) read and hash the file as it is *now* — if it is still the
generation this session's memory descends from, keep memory; otherwise adopt the file, after
checking it is still this vault (same `vault_id`, and its body opens with the key this session
holds — the vault key itself never changes, a password change only re-wraps it) and that it still
continues this session's audit log (§4); (3) chain the pending-audit queue (§5) onto that fresh
head; (4) run the caller's closure once, synchronously, against that state; (5) write the result
atomically and record its new generation; (6) release the lock. If step 4 or 5 fails, the session
is restored to exactly where it began by **re-decrypting the bytes read in step 2** — no disk
access, so a volume that vanishes mid-transaction cannot leave the closure's uncommitted changes
readable, and no second decrypted copy of the body has to be kept around only for rollback
(threat-model M-10). The drafts the transaction carried in go back into the pending queue rather
than being lost; entries the closure itself appended describe something that did not happen and
are discarded with the rest of it.

`Vault::save()` — the mutate-then-save API every caller used before this — stayed as the
**non-transactional path** for as long as any caller still needed it, and is now `#[cfg(test)]` and
`pub(crate)` (step 6): every mutator that used to make something worth saving outside a transaction
lives only on `Tx`, so no crate but this one — and nothing outside this module's own unit tests
within it — can even construct a change for `save` to write. It never merges, having no record of
what changed, so it was made *safe* instead of *smart* while it was still a public entry point: it
takes the same lock, and if the file is no longer the generation this
session last read or wrote, it writes nothing and fails with `Error::VaultConflict` rather than
silently overwriting another writer's work — behaviour this module's own tests still pin.
`refresh_if_changed` lets a long-lived reader catch up between writes without paying for a full
transaction, using the same vault-id, key and continuity checks.

### 4. The continuity check, and what it deliberately is not

Adopting a changed file (step 2, or `refresh_if_changed`) is not enough on its own: it stops a
write from building on stale memory, but says nothing about whether the file it is building on is
itself *forward* of what this session last saw. The continuity check closes that gap: the fresh
file's audit log must contain, at the same position, the last entry this session knows reached the
disk. A file that fails that — restored from an older copy while this session stayed unlocked —
fails with `Error::VaultDiverged` and is left completely untouched.

This is **explicitly the in-memory precursor of an external freshness anchor, not a replacement for
one** (see [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)). It only
detects a rollback while a session that saw the newer file is still unlocked and still running; a
rollback performed after every such session has locked or exited leaves nothing in memory to
compare against, and the restored file verifies cleanly. Recording that limit here rather than
overselling the check was a condition of writing it at all.

### 5. The pending audit queue replaces `audit_saved_len`

Audit drafts that could not be written — because a transaction's write failed, or because
`Vault::queue_audit` recorded one deliberately without attempting a save — wait in memory,
un-chained, each carrying `AuditDraft.timestamp: Option<u64>` captured at the moment it was
recorded (not serialized; `audit::append` uses it if present, so a draft's audit timestamp reflects
when it happened, not when it finally got written). The next successful transaction chains every
queued draft onto the head the file has *then*, in the order they were recorded, so they survive
another process having appended in between. Anything the in-memory state chained but never saved,
when that state is replaced wholesale by a fresher file, goes back into the queue as a draft rather
than being dropped. `Vault::unsaved_audit_entries()` counts both kinds and keeps its existing
meaning; `Vault::last_save_error()` is unchanged; the FFI's `AuditDurabilityView` and the Swift side
that reads it need no change for any of this.

### 6. Argon2id never runs under the lock

`prepare_master_password`, `prepare_kdf_upgrade` and `prepare_recovery_code` run **before** any
lock is taken: they derive with Argon2id against the header this session holds *now* and produce a
`PreparedPasswordSlot` / `PreparedRecoverySlot` that remembers the exact KDF descriptor and slot it
was prepared against. `Tx::install_master_password` / `Tx::install_recovery_code` then run inside
the transaction, doing no cryptographic work of their own beyond a comparison: if the file's header
no longer matches what the slot was prepared against — another process changed the password or the
KDF cost first — installation refuses with `Error::VaultConflict` rather than silently clobbering
that other change, and the caller re-prepares from a refreshed vault. This is the general answer to
"how do header operations, which need a human-scale KDF, fit inside a lock that must never be held
for human-scale time": split into a `prepare_*` half outside the lock and an `install_*` half
inside it, for every operation that needs Argon2id.

### 7. Timeouts are per caller, and the lock is never held across anything slow

`vault::lock::DEFAULT_LOCK_TIMEOUT` is 5 seconds; `Vault::set_lock_timeout` lets a caller choose
its own. `kagisecure-agent`'s `VaultHandle::transact`/`record_best_effort` take an explicit `wait`
per call (`vault::REQUEST_LOCK_TIMEOUT` = 5 seconds for an agent or extension request) and restore
the vault's own timeout afterwards, so one slow caller does not change what a different caller
waits for. The app's own UI waits 2 seconds (`APP_LOCK_TIMEOUT` in `kagisecure-ffi`'s
`session.rs`, for every `VaultSession` write including the overwrite in §10) and then reports
`FfiError::Busy`. The CLI waits up to 30 seconds (`transact_patiently` in `kagisecure-cli`'s
`commands/mod.rs`): a quiet first second, then "kagisecure: waiting for another kagisecure
process…" on stderr and the rest of the budget, so an uncontended write never prints anything.

What is load-bearing today, and enforced by the API's shape rather than by convention alone, is
that the lock is **never held across a human prompt, an approval sheet, an Argon2id derivation or a
child process**: `transact`'s closure is a synchronous `FnOnce`, so a caller cannot `.await` a
sheet or spawn a process from inside one without restructuring its code to do the slow part first
and the transaction last. `kagisecure-agent`'s migration (§"What is implemented" below) does
exactly that: the approval sheet and the injection happen with no lock held, and only the
re-check, the resolution and the commit run inside `transact`.

### 8. Error codes and CLI exit codes

`kagisecure_core::Error::VaultBusy`, `LockUnsupported`, `LockLost`, `VaultConflict`,
`VaultDiverged`, `VaultReplaced` and `NestedTransaction` are the new core variants. Over IPC they
collapse to two wire codes, both landing with protocol version 2 (`kagisecure-ipc`'s `ErrorCode`
enum is closed with no catch-all, so a peer built before this bump would otherwise see a garbled
frame rather than a legible refusal at `Hello`):

- `VAULT_BUSY` — another kagisecure process held the lock past the wait; nothing changed; safe to
  retry shortly.
- `VAULT_CONFLICT` — the file is a different vault, a body this session's key no longer opens, an
  older copy, or gone entirely; nothing changed and nothing will until a human resolves it.
  `VaultDiverged`, `VaultReplaced` and `VaultNotFound` (when discovered mid-request, not at
  startup) all sort into this one wire code — a caller cannot act differently on the three, and
  distinguishing them would only be more detail than "wait for a human" needs.

`docs/mcp-server.md` §7 documents both rows. The CLI has two matching exit codes
(`kagisecure-cli`'s `cli.rs`, mapped in `main.rs`'s `exit_code_for`):

- **8** (`EXIT_VAULT_BUSY`) — `VaultBusy` after the CLI's full 30-second wait.
- **10** (`EXIT_VAULT_CHANGED`) — `VaultDiverged`, `VaultReplaced`, or `VaultConflict` (the
  non-transactional `save` path and a refused `install_*`). `9` is skipped on purpose: the
  audit-first design reserves it for a future `AUDIT_UNAVAILABLE` code
  ([ADR-0040](0040-audit-before-release.md)). A vault file that vanished before the CLI opened it
  stays exit 4 (`EXIT_NO_VAULT`); a CLI run is a fresh session each time, so it never holds a
  newer state than the file the way a long-lived app session can.

The app sorts the same variants into `FfiError::Busy` and `FfiError::Diverged`, and records which
kind of conflict it is (`VaultSession::conflict`) for the alert in §9.

### 9. User decisions this ADR encodes

Five decisions the project owner made when this design was approved, and where each currently
lands:

3. **File replaced or diverged while unlocked: refuse writes, then let the human choose.**
   Implemented. `Error::VaultDiverged`/`VaultReplaced`/`VaultNotFound` refuse and leave the file
   untouched; `kagisecure-agent` turns that into a sticky `VAULT_CONFLICT` that keeps refusing
   until the file is resolved; the app detects it on a write or on `VaultSession::sync` (on
   becoming active, on a ~2 s timer while frontmost, before the Audit view reads the log) and shows
   one alert with the two choices this decision specifies (ui-spec.md §6.4). **"Lock and reopen
   from the file"** locks and unlocks again, and the new session records
   `vault_reopened_after_conflict`, best-effort. **"Keep this app's version (overwrite the
   file)"** is the explicit overwrite of §10, confirmed separately with what the file would lose,
   and recorded as `vault_overwritten_after_conflict` inside the file it writes. A file at the path
   that this build cannot parse at all is the same kind of conflict (`Unreadable`), not a wrong
   credential.
4. **Concurrent edits: the edit sheet's save is rejected with "changed elsewhere — reload"; a
   single toggle is last-writer-wins.** Implemented in `kagisecure-ffi`: `VaultSession::save_item`
   compares a content hash of the item as the sheet loaded it (`ItemView::revision`) with the item
   as the transaction reads it, and refuses with `FfiError::ItemChangedElsewhere`; the toggles
   (favourite, archive, trash, agent-visible) re-read the item inside their transaction and simply
   apply. A toggle that fails for any reason — `Busy` included — reaches the app's standard error
   alert; nothing swallows it.
5. **A file system without locking refuses writes.** Implemented: `vault::lock::classify` sorts
   `ENOTSUP`/`ENOLCK`/`ENOSYS` and their Windows equivalents, by raw error number per platform,
   into `Error::LockUnsupported` rather than an opaque I/O error, and every write path — the
   transactional and the non-transactional one alike — goes through the same lock acquisition, so
   the refusal is uniform regardless of which API a caller uses. The vault can still be opened and
   read.

(Decisions 1, 2 and 6 belong to [ADR-0040](0040-audit-before-release.md).)

### 10. "Keep this app's version": the explicit overwrite

Every other write in this ADR starts from the file and refuses one it cannot build on. Decision 3's
second answer needs the opposite — a write that deliberately does *not* start from the file — so
it is a separate, deliberately-named core API rather than a flag on `transact`:

```rust
impl Vault {
    pub fn examine_conflict(&self) -> Result<Option<FileConflict>>;
    pub fn overwrite_with_this_session(
        &mut self, confirmed: &FileConflict, actor: &str, reason: &str,
    ) -> Result<()>;
}
pub enum FileConflict {
    Diverged { file_sha256: [u8; 32], lost: DivergedFile },
    Replaced { file_sha256: [u8; 32] },
    Unreadable { file_sha256: [u8; 32] },
    Missing,
}
```

`examine_conflict` reads the file without the lock and says what an overwrite would discard: for a
diverged file (same vault, older or separately changed copy) how many audit entries, items,
environments and logical vaults exist only in the file or differ there, and whether its
master-password, recovery and platform slots are the same wraps as this session's; for a replaced
or unreadable file, only that it would be lost whole; for a missing one, that there is nothing to
lose. `None` means the file is not in conflict at all — an ordinary transaction merges with it.

`overwrite_with_this_session` must be handed exactly what the person was shown. Under the lock it
examines the file again and refuses with `Error::VaultNotInConflict` if an ordinary transaction
could build on it now (someone put the newer file back), or with `Error::VaultConflict` if it is in
conflict *differently* — different bytes, or different losses — so nobody ever discards something
other than what they confirmed. Otherwise it chains every pending audit draft, then one entry
recording the override, writes this session's header and body atomically, and adopts the result
as the generation later transactions start from. The entry (`tool`
`vault_overwritten_after_conflict`) is inside the file it describes, and its `detail` records what
was replaced: `found=` the kind, `file_sha256=` the first 8 bytes of the replaced file's hash,
`file_audit_len=` / `shared_audit_len=` its audit length and how much of it this session's log
shares (`unknown` when the file could not be decrypted), `session_audit_len=`, and `reason=`. A
failed write restores the session exactly — nothing chained, the drafts still pending — and a
write whose outcome cannot be confirmed is remembered like a transaction's, so its drafts are never
written twice.

**`VaultNotFound` is only ever recreated here.** A transaction refuses a vanished file; the
overwrite is the one path that writes it back, and only as an explicit choice.

**The header written is this session's, not the file's.** For a replaced or unreadable file there
is no choice: its header wraps some other key or none, and keeping it would produce a file nothing
opens. For a diverged file the header could be kept, but that would write a vault neither side ever
had — the file's unlock methods over this session's contents — and turn "restore one known version"
into a merge whose outcome depended on which fields differed. The session's header is the one its
key and body belong with. The consequence is deliberate, reported by `DivergedFile`, and stated in
the app's confirmation before anyone can choose it:

- a master password (or KDF cost) that exists only in the file's version stops working, and the
  one this session's header holds works again;
- a recovery code issued only in the file's version stops working, and the code in this session's
  header works again — **including one a person replaced because they believed it exposed**;
- a Touch ID enrolment present only in the file disappears, and one removed only in the file comes
  back.

What the overwrite cannot protect is the other side's work. A process still unlocked on the
discarded version finds that the file no longer continues *its* log and is refused
(`VaultDiverged`) — the override is itself a conflict for it, never silently merged into.

### 11. Interaction with the newer-schema write refusal

The unknown-field preservation fix (vault-format §9 rule 2) made every write refuse, with
`Error::VaultSchemaTooNew`, a vault whose `body.schema` or `header.v` is newer than this build
writes; opening and reading it still work. The check runs in `seal`, the one serializer every write
shares, so it applies to transactions, to `save` and to the overwrite alike, and always *before*
anything is written. For a transaction that adopted such a file — a newer build bumped the schema
while this one was unlocked — that means: the closure runs, the seal fails, the transaction rolls
back by reload as for any other failed write, the drafts it carried go back into the pending queue,
and `last_save_error` says why. Nothing is lost, but nothing this build records is written either
until kagisecure is upgraded: the queue simply grows. It is not a conflict — the file continues the
session — so neither the agent's `VAULT_CONFLICT` nor the app's conflict alert fires; the agent
answers `INTERNAL`, the app shows the error text. The overwrite cannot be used to force such a
write through either: it seals this session's own header and body, and a session that adopted the
newer schema holds it too.

### Alternatives considered

**A single writer that owns the file, with everything else routed through IPC to it.** Rejected.
It would break the headless CLI+daemon workflow architecture.md §2.6 exists to keep: `kagisecure
env write` and `kagisecure item add` are meant to work with no app running at all, and a design
that requires a running daemon for every CLI mutation removes exactly that case. Routing the CLI's
own writes through IPC to some other long-lived owner would also either move secret material across
a boundary that today carries none (`kagisecure-ipc` is built so it cannot even name `Secret`;
threat-model TB-1), or turn the socket into an oracle a local attacker could use to test master
passwords against a process that never has to prompt a human. A lock file that any of several
independent writers can take, each with its own copy of the key, keeps every existing process
shape and adds no new authority anywhere.

## What is and is not implemented

Stated plainly, in the spirit of ADR-0011's equivalent section, because the difference matters for
anyone reading this ADR against the code:

- **Core (commits `168ee51`, `1a523ac`):** `vault::lock` in full (§1); generations, `transact`,
  `refresh_if_changed`, the continuity check and `VaultDiverged`, rollback-by-reload, unconfirmed
  writes settled by content, the pending audit queue, and the `prepare_*`/`install_*` split for
  password, KDF-upgrade and recovery-code operations (§2–§6). Covered by
  `crates/kagisecure-core/tests/concurrent_writers.rs`, `tests/vault_lock.rs` and the unit tests in
  `vault/mod.rs` and `vault/lock.rs`.
- **Agent and browser extension (`d9c2ca9`):** `VaultHandle::sync`, `VaultHandle::transact` and the
  durable best-effort audit path; every request re-reads the file first and every state-changing
  one commits inside a transaction; `VAULT_BUSY`/`VAULT_CONFLICT` on the wire at protocol version 2.
- **FFI and the macOS app (step 4, `8900873`):** every `VaultSession` mutator — item CRUD, the
  toggles, environments, logical-vault sharing, password/recovery/platform-slot changes, import
  commit, the "save now" call — runs as one transaction at the app's 2-second wait; `sync` on
  activation, on a ~2 s timer and before the Audit view; `FfiError::Busy`/`Diverged`/
  `ItemChangedElsewhere`; the conflict alert (decisions 3 and 4, §9).
- **CLI and import (step 5, `4f35571`):** all ten CLI write commands go through
  `transact_patiently` (30-second wait, message after 1 second); exit codes 8 and 10 (§8);
  `kagisecure_import::commit` takes a `&mut Tx`, so the CLI and the app hand it the transaction's
  own and every duplicate decision is made against the state the lock is held over.
- **Unknown-field preservation (`447a325`):** body, header, item, field, environment, logical-vault
  and wrapped-key slots carry keys this build does not know through every write, and a newer schema
  number refuses writes (§11). Relevant here because every transaction re-encodes whatever the file
  held: without it, the first transaction by an older build would have been a lost update of
  another kind.
- **The explicit overwrite (§10):** `Vault::examine_conflict` / `overwrite_with_this_session` in
  core (`tests/overwrite_after_conflict.rs` and the fault-injection unit tests in `vault/mod.rs`),
  `VaultSession::conflict_details` / `keep_app_version_over_conflict` in the FFI, and the
  confirmation alert in the app.
- **The old API removed (step 6):** the 14 mutators (item, environment and logical-vault CRUD, the
  agent-visibility switch, the audit chain, the platform slot, and the two `install_*` steps of a
  header change) are inherent methods on `Tx` and no longer exist on `Vault` at all; `Vault` is
  `Deref`-only from `Tx` (no `DerefMut`), so there is no path from a running transaction's closure
  to a `&mut Vault` method, and calling one is a compile error rather than the runtime
  `Error::NestedTransaction` a few of them used to produce — see the `compile_fail` doctest on
  `kagisecure_core::vault::Tx`. `change_master_password`, `upgrade_kdf` and `reissue_recovery_code`
  — the three convenience wrappers that both ran Argon2id *and* applied the result in one `&mut
  self` call — are gone outright; every caller uses the `prepare_*` (on `Vault`, before the lock) /
  `Tx::install_*` (inside it) split they were built from. `Vault::save` still exists, for this
  module's own regression tests, but is `#[cfg(test)]` and `pub(crate)`: nothing outside this
  module's own unit tests can even see it any more, and every other caller — main-crate code
  already used `transact` (steps 4–5); this step was migrating the remaining test and example
  fixtures — now builds through `Vault::transact`/`Vault::create`. `kagisecure_import::commit`
  dropped its `VaultTarget` generic along with it, since `Tx` is the only shape left to serve.

**Not implemented / still open:**

- **The external freshness anchor** ([ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md))
  — the continuity check still only catches a rollback while a session that saw the newer file is
  unlocked (§4).
- **The overwrite keeps no copy of what it replaces.** The confirmation says what will be lost and
  the audit entry records the replaced file's hash, but the bytes themselves are gone unless the
  person kept a copy; for a replaced or unreadable file that is everything in it.

## Consequences

### Positive

- The lost-update bug that motivated this — an app save reverting a CLI-issued recovery code, or a
  revoked agent-access flag coming back after the app's next save — cannot happen any more between
  the agent daemon and any other writer, without the headless CLI+daemon workflow losing anything.
- One mechanism (generation + continuity check) protects header changes exactly as it protects body
  changes; there is no second code path for "a password change happened underneath us" the way an
  earlier, item-only merge scheme would have needed.
- Rollback-by-reload means a failed transaction never needs a second decrypted copy of the body
  sitting in memory purely for undo, which keeps threat-model M-10's "minimal plaintext lifetime"
  intact.
- No vault-format change: no `format_ver`, `header.v` or `body.schema` bump. The lock file is
  outside the format entirely, and a vault written under this scheme opens unmodified in a build
  that predates it.

### Negative — accepted

- **0.1.x builds do not lock at all.** A 0.1.x process and a locking process writing the same file
  concurrently are exactly as unsafe as before this ADR; the lock only coordinates processes that
  both know about it. Worth a release note when this ships.
- **A file that is never deleted sits next to every vault, forever.** One more path to explain, one
  more thing a user might see and wonder about (mitigated by using a name and comment explicit
  enough that "why is this here" has an obvious answer at the file itself).
- **Linux NFS gives no exclusion *within* one process.** The NFS client emulates `flock` with
  POSIX `fcntl` byte-range locks, which belong to the process, not the open file description — two
  `Vault` values on the same NFS-hosted vault, inside one process, both "acquire" the lock at once.
  Two *processes* still exclude each other there; a process that needs more than one writer on such
  a vault has to serialize them itself, which is exactly what `kagisecure-agent`'s `VaultHandle`
  mutex already does for its own two writers (§"Lock order" in `vault.rs`). Local file systems are
  unaffected.
- **A lock-less file system refuses every write outright**, per user decision 5. A vault on such a
  mount becomes read-only rather than silently unsafe, which is the right trade but is still a
  capability loss for whoever hits it, with no workaround offered beyond moving the file.
- **A `#[cfg(test)]`, `pub(crate)` `Vault::save` remains, for this module's own tests.** It is the
  same non-merging, lock-respecting write it always was, just no longer compiled into, let alone
  reachable from, any other crate (step 6); nothing about calling it changed. `Vault::flush_audit`
  — the one production path that still resembles "queue, then write without changing anything
  else" — goes through `transact`, not `save`, so this is not a second write path any production
  caller can reach, only an internal regression-test fixture.
- **"Keep this app's version" is destructive by design.** It discards whatever the file held that
  the session did not, and restores the session's unlock methods — possibly a recovery code
  someone retired on purpose (§10). The protections are that it is never a side effect (only the
  explicit, separately confirmed choice reaches it), that it acts only on exactly the file the
  person was shown, and that the file it writes records what it replaced; not that it is
  reversible.

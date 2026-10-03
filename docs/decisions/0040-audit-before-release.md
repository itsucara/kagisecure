# ADR-0040: Audit before release

- **Status:** Accepted. The fail-closed set is implemented: the agent (`write_env_file`,
  `run_with_env`), the CLI (`env write`, `run`) and browser fills and one-time codes. The app's own
  reveals are audited best-effort by ADR-0038's release calls in Rust, which the app adopts in
  ADR-0038's phase 2 — see "What is implemented" at the end.
- **Date:** 2026-09-25
- **Renumbered:** written as ADR-0033; renumbered to ADR-0040 on 2026-09-26 when `main`'s Windows
  port, which had already taken 0032–0034, was merged. Commits before that date say ADR-0033.
- **Deciders:** feat/vault-transactions implementation
- **Refines:** [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md),
  [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0014](0014-approval-queue-over-ffi.md), [mcp-server.md](../mcp-server.md) §6–§7,
  [vault-format.md](../vault-format.md) §8

## Context

Every place that releases a value today — `write_env_file`, `run_with_env`, a browser fill —
follows the same order: resolve the value, hand it to whatever is going to receive it (a file on
disk, a child process's environment, a web page's input), and only *then* append the audit entry
recording that it happened, best-effort, in a save that can fail. The code says this about itself,
in `write_env_file`'s own comment (`crates/kagisecure-agent/src/service.rs`):

> Recorded after the fact, best-effort, and the reply is the truth either way: the file *was*
> written, and answering with an error would invite the caller to do it again. A failed write
> leaves the entry queued, not lost. Making the entry durable *before* any value leaves the vault
> is the audit-first design's job, not this function's yet.

That ordering means the one scenario the audit log exists to make unforgeable — "this tool released
this value, to this target, at this time" — can be true of the world (the byte left) without ever
becoming true of the log, if the save that would have recorded it fails at the wrong moment: a full
disk, a lock held past the wait by another writer (now possible by design, per
[ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md)), a `VaultDiverged` refusal. The
entry is queued, not discarded, so it is not *lost* forever — but until it is flushed, the log
cannot answer "what did this MCP client actually get" any more honestly than it could before the
queue existed. For a fill or a metadata read this is a tolerable, recoverable gap. For
`write_env_file` and `run_with_env` — the two tools that hand raw values to a child process outside
kagisecure's control — it is the wrong default: an agent that already has the value cannot be made
to give it back, so the log missing the one entry that says it happened is the single most damaging
place for this project's audit story to have a hole.

## Decision

**Durability before release, but only where release cannot be undone if the record of it turns out
to be wrong — everywhere else, audit stays best-effort and never blocking.**

### 1. `audited_release`: commit the record, then act

```rust
audited_release(
    handle,
    prepare: FnOnce(&mut Tx) -> Result<(AuditDraft, R)>,
    act: FnOnce(R) -> Result<O>,
) -> Result<O>
```

`prepare` runs entirely inside a transaction: it re-checks existence, visibility and origin against
the fresh file (not whatever was true when the approval sheet went up), resolves the injections
into `Zeroizing` buffers, and appends an `Allowed` audit draft — all before the transaction commits.
Only after that commit has succeeded and the lock is released does `act` run, carrying the resolved
value out to the file, the child process, or the page. `run_with_env` stops holding the
`VaultHandle` mutex across the child's entire run — it only ever needed it for the part that
`audited_release` now bounds.

The property this buys: **the `Allowed` entry — "authorized and committed to be released" — is on
disk before the first byte of the value has gone anywhere it did not already live.** If the commit
fails, nothing has been released yet, so refusing is still an honest answer (§3). If the commit
succeeds and `act` then fails — the child fails to spawn, the write hits a full disk, the process is
killed mid-write — the record of authorization already exists; a second entry follows to say what
happened next (§2).

### 2. One entry on release, a second only on failure

An `Allowed` entry is written once, at the moment in §1. Nothing durable is written on an ordinary
success beyond that — the release itself is not re-recorded, because §1's entry already is the
record of it. Only on failure or an abnormal end does a second entry follow: same tool, lease,
target and variables, `outcome: Failed`, with `detail` set to `"<CODE> (entry <seq>)"` — e.g.
`WRITE_FAILED (entry 41)`, `SPAWN_FAILED (entry 41)`, `TIMED_OUT (entry 41)` — naming the sequence
number of the `Allowed` entry it follows, so a reader of the log can always find the authorization
a given failure belongs to without having to search by timestamp. This follow-up is best-effort
through the same pending queue every other audit write uses: it must never be lost, but it must
also never turn a real failure into a second, different failure ("your injection failed, and also
we could not tell you that"). No change to `AuditEntry` or `Outcome`'s schema is needed for any of
this — `detail` is already a free-form string.

### 3. Fail closed, but only at the point of committing the record

If the transaction in §1 itself fails — the write errors, the lock times out, the file has
diverged — the caller answers `AUDIT_UNAVAILABLE` (§5) rather than falling through to release the
value anyway. Any lease this call minted, and any fill lease minted during the approval that
preceded it, is revoked (`revoke_if_minted`, `extension.rs`'s equivalent), since a lease that grants
future access should not survive a call that could not even record having granted this one. The
failure itself is queued as a `Failed`/`AUDIT_UNAVAILABLE` draft, on the same best-effort footing as
every other queued entry — this refusal is not exempt from needing its own record.

**Pre-flight, before a human ever sees an approval sheet:** if the pending queue is already
non-empty when a fail-closed tool is invoked, a flush is attempted first. If that flush also fails,
the call is refused immediately, with no sheet shown at all. Showing a sheet, getting a human's
attention and a fingerprint, and *then* discovering the log cannot be written would waste the one
scarce resource this whole design protects — the user's attention — on an approval that was never
going to be actionable.

### 4. What stays best-effort, and why never blocking it is the right call, not a shortcut

**Fail-closed set:** MCP `write_env_file` and `run_with_env`; every browser-extension fill
(including a username-only fill, which writes no lease but still releases a value) and
`totp_code`; the CLI's `env write` and `run` (once migrated — see "What is implemented").

**Best-effort set, deliberately never refused:** denials and refusals (there is nothing to make
durable-before-release, since nothing was released); `lock`; `revoke_env_file`; every read-only
metadata tool; and — the decision that needed the most explicit call, because it looks at first
like it should be fail-closed too — **the user's own reveals, copies, edit-prefill values, Quick
Access, and the CLI's own `item show --reveal` and `totp` generation.** These are audited, and the
failure to save that audit entry is surfaced (the existing warning path from `a58ed41`, which made a
failed audit save visible instead of discarding it), but they are **never blocked** by a failed
audit write. This is user decision 1 (below), and the reasoning is parity with how a mainstream
team password manager treats a user opening their own item: 1Password Business logs item usage but
does not refuse to show a user their own password because the log could not be written at that
instant. An agent injecting a value into a process it controls is a materially different act from a
person looking at their own vault, and only the former earns the stronger guarantee.

**CLI `run` and `env write` are the one place a best-effort default was rejected even though a
human is present**, because from the audit log's point of view they are indistinguishable from the
MCP tools of the same name — a value crosses into a process kagisecure does not control — and a
human standing at the terminal does not make that crossing less permanent. User decision 2 makes
these fail closed for the same reason `write_env_file`/`run_with_env` are.

**Metadata-only agent tools keep answering when the audit save fails** (user decision 6): a
`list_items` or `describe_item` call releases nothing, so there is no "before release" moment to
protect, and refusing to answer a read because a log write failed would turn an availability
problem into a second, unrelated availability problem for functionality this design has nothing to
say about.

### 5. `AUDIT_UNAVAILABLE`

A new wire error code, `ErrorCode::AuditUnavailable` (`"AUDIT_UNAVAILABLE"`) in
`kagisecure-ipc`'s `protocol.rs`. It is added under `PROTOCOL_VERSION` 2, the version
[ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) §8 introduced: no build speaking
version 2 was released before the code was added, so no second bump was needed. The equivalent
exists on the browser-extension side (`kagisecure-extension-ipc`'s own `ErrorCode`, and the
matching branch in the content script), and as `FfiError::AuditUnavailable` (alongside `Busy` and
`Diverged`, which ADR-0039 already needs a Swift-visible shape for once the app migrates). The CLI
exit code is 9, alongside ADR-0039 §8's 8 and 10.

### User decisions this ADR encodes

1. **Own reveals, copies, edit prefill, Quick Access, CLI reveal and `totp`: audit them,
   best-effort, never blocking** — parity with a mainstream team password manager's treatment of a
   user's own item usage. A failed save here goes to the pending queue plus the existing `a58ed41`
   warning, exactly like any other best-effort entry.
2. **CLI `run` and `env write` fail closed**, like the MCP tools of the same shape, because the
   value crosses the same boundary regardless of who is at the keyboard.
6. **Metadata-only agent tools keep answering when the audit save fails** — best-effort, plus the
   existing warning.

(Decisions 3, 4 and 5 belong to [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md).)

### Alternatives considered

**Record the release after the fact but retry harder before giving up.** Rejected: no amount of
retrying changes that the value has already left, so a caller that ends up unable to write the
entry is in exactly the situation this ADR exists to make impossible for the fail-closed set — a
release with no record. Retrying is still what the pending queue does for the *follow-up* `Failed`
entry in §2, where the value's fate is already sealed either way.

**Widen `AuditDraft`/`Outcome` with a new variant for "authorized, release pending".** Rejected.
`Allowed` already means what is needed — this is a transaction commit like any other — and adding a
new outcome would mean every reader of the log (the app's Audit view, `kagisecure audit`, anything
built against `mcp-server.md` §6's field list) has to learn a state that exists for a few
milliseconds between commit and act, and is never itself the interesting fact. The interesting fact
is the ordering guarantee, not a new value in the schema.

## Consequences

### Positive

- The one entry that matters most — "this tool was authorized to release this value" — cannot be
  true of the world without being true of the log, for every tool where a released value cannot be
  un-released. That closes exactly the gap `write_env_file`'s own comment names.
- No schema change: `AuditEntry`/`Outcome` are untouched: the design fits inside `detail`'s existing
  free-form string and a transaction that was going to exist anyway
  ([ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md)).
- The best-effort set is not a concession — it is a deliberate, named boundary (release vs. no
  release; agent-directed vs. user-directed) rather than "everything we didn't get to yet",
  which is what makes it defensible to leave that way indefinitely.
- Pre-flight flushing means a user is never asked to authenticate for an approval that was already
  going to be refused for a reason that has nothing to do with their answer.

### Negative — accepted

- **A fail-closed tool can now refuse for a reason that has nothing to do with the request itself**
  — a wedged audit write, a lock held by another process — where before it would have proceeded and
  only best-effort-logged the outcome. This is the trade the whole design exists to make, but it is
  a new way for `write_env_file`, `run_with_env`, a fill or `totp_code` to say no.
- **`run_with_env` no longer holds the `VaultHandle` mutex for the child's entire run**, which is a
  correctness fix this design forces (the mutex must not be held across `act`) but is a larger
  change to that function's structure than the audit ordering alone would require.

## What is implemented

- **Agent** (`crates/kagisecure-agent/src/release.rs`): `audited_release` commits the `Allowed`
  entry in a transaction on the file as it is on disk, and runs the release only after the
  transaction has returned and both the handle mutex and the file lock are released. The payload
  and the act closure must be `'static`, so neither can hold a transaction, a vault borrow or a
  guard; two `compile_fail` doctests pin that. `write_env_file` and `run_with_env` use it, with
  `AUDIT_UNAVAILABLE`, the pre-flight flush, lease revocation on refusal and the `Failed`
  follow-up described above. `run_with_env` no longer holds the vault mutex while the child runs.
- **CLI**: `env write` and `run` commit the `Allowed` entry before writing or spawning and exit 9
  when they cannot; `item show --reveal` and `totp` are audited best-effort (user decision 1).
- **Browser extension** (`crates/kagisecure-agent/src/extension.rs`, step 8): every fill that
  carries a value — password, one-time code, and username-only — goes through `audited_release`,
  on top of ADR-0037's structure. The order: the metadata checks and, for a secret, the human (a
  sheet or a presence prompt, after the pre-flight flush) run first; then one transaction on the
  file as it is on disk re-checks that the item still exists, is neither trashed nor archived, and
  still covers the approved origin, reads the value through `extension/crossing.rs` with the
  approval (by value — one grant, one crossing), and appends the `Allowed` entry
  (`FILL_APPROVED`, `FILL_CONFIRMED` or `FILL_USERNAME_ONLY` as its detail). Only the built reply
  leaves the transaction, and only if it committed; the connection loop writes it after that. So
  the value that leaves is the one read from the state its entry was committed against, and
  secret reads stay in `crossing.rs` behind `Approved`. The `act` of this release is the identity:
  the frame is written by the loop that owns the connection, which records `REPLY_FAILED (entry
  <seq>)` when it cannot be written (`release::follow_up`). Where §3 says a lease minted during
  the approval is revoked, the extension goes one further: a lease asked for by **Allow for this
  session** is minted only after the commit, so a refused fill has none to revoke. The wire code is
  the extension protocol's `AUDIT_UNAVAILABLE`, added without a version bump (see
  `kagisecure-extension-ipc`'s `PROTOCOL_VERSION`), and the content script words it for the
  person.
- **App reveals and copies** (step 10, with [ADR-0038](0038-app-release-needs-presence.md) phase 1):
  `release_field`, `release_totp` and `release_notes` record every outcome best-effort through the
  pending queue — `PRESENCE_CONFIRMED`, `PRESENCE_CONFIRMED_MASTER_PASSWORD` (the master-password
  fallback, decided by Rust from its own check), `PRESENCE_CANCELLED`, `PRESENCE_UNAVAILABLE`,
  `PRESENCE_BUSY`, `VAULT_LOCKED`, `GONE_DURING_PROMPT` (outcome `failed`: what was confirmed had
  been deleted meanwhile), and `SHOWN_EARLIER` for a copy of a value already shown — and a failed
  write never withholds the value (user decision 1). A wrong master password typed into the
  fallback is recorded too (`verify_master_password`, `MASTER_PASSWORD_WRONG`, and the first
  throttled attempt of each back-off window as `MASTER_PASSWORD_THROTTLED`). The other step-10 events are recorded
  as well: a master-password change (app, and the CLI's `recover`), a recovery-code reissue (CLI),
  Touch ID enrolment and removal, each inside the transaction that makes the change, and the
  vault-key export for Touch ID enrolment, best-effort. `FfiError::AuditUnavailable` is still not
  needed: nothing the app does is in the fail-closed set.
- **Since ADR-0038 phase 2** the app calls only those release functions; the old ungated ones are
  removed from the FFI.

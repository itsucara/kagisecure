# ADR-0041: Anchor the audit log's freshness outside the vault file

- **Status:** Proposed. Blocked on the same account action as
  [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md); a Phase 0 measurement (below) has not
  been run.
- **Date:** 2026-09-25
- **Renumbered:** written as ADR-0034; renumbered to ADR-0041 on 2026-09-26 when `main`'s Windows
  port, which had already taken 0032–0034, was merged. Commits before that date say ADR-0034.
- **Deciders:** feat/vault-transactions design (proposal only — not yet implemented)
- **Refines:** [threat-model.md](../threat-model.md) W-11, C-11,
  [vault-format.md](../vault-format.md) §8, [audit.rs](../../crates/kagisecure-core/src/audit.rs)
- **Refines:** [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) §4 (the continuity
  check this proposal extends outside one running session),
  [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md) (the entitlement this shares)

## Context

`vault-format.md` §8 and `audit.rs` both document, and have documented since before this line of
work started, that the hash chain over the audit log proves only internal consistency — that no
entry was reordered or edited mid-log — and proves nothing about *completeness* or *recency*. Two
gaps follow from that, and W-11 names both:

- **Whole-file rollback.** An attacker with file access but no key — same-user malware, or an
  injected agent with shell access (T-2/T-3) — can copy the vault file, wait for it to lock, and
  copy the old file back. The restored file is fully authentic and verifies cleanly; whatever the
  log recorded after the copy — the one thing that might have shown the attack happening — is gone.
- **Key-holder truncation (C-11).** `body.audit_head` lives inside the same encrypted body as the
  entries it attests, so anything holding the vault key can drop the last *k* entries, store the
  digest of the new last entry, and have `verify` accept the result — the chain is intact, it is
  just shorter than it was.

[ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) §4 added a continuity check that
catches the *first* of these while a session that saw the newer file is still unlocked and running:
a transaction refuses to build on a file whose audit log does not still contain, at the same
position, the last entry that session saw. That is real protection, and it is explicitly not
described as more than it is — the ADR calls it "the in-memory precursor of the external freshness
anchor," because the moment every such session has locked or exited, there is nothing left in any
process's memory to compare against, and a rollback performed then leaves a file that verifies
cleanly and raises no continuity failure for the next session to open it.

Closing that residual gap needs state that survives the vault being locked, kept somewhere the
attacker model in T-2/T-3 does not already grant access to — otherwise the anchor is just another
byte the same attacker can rewrite. That rules out anywhere inside the vault file by construction:
a counter in the header's AAD is re-sealed by whoever forges the rest of the header, and the whole
premise of this proposal is that the file itself cannot be the witness to its own history.

## Decision

**Store one small anchor per vault outside the vault file, in a place a same-user process without
this app's code signature cannot reach, and use it to warn — never to refuse.**

### 1. What the anchor is, and where it lives

An anchor is `{count, head}` per `vault_id`: the number of audit entries this app last confirmed on
disk, and the SHA-256 of the last entry at that position (the same `audit_head` the in-file chain
already computes). It is stored as an item in a **code-signing-bound Keychain access group** —
`kSecAttrAccessGroup` scoped to this app's team and bundle identifier, the mechanism macOS uses to
let an item be read only by processes signed by the same team as whatever created it, regardless of
which user-level process asks.

That entitlement is `keychain-access-groups`, the same one
[ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md) documents as **restricted**: its presence in
an entitlements file forces Xcode to require a provisioning profile, and AMFI validates it against
that profile at every `exec` — a Developer ID signature alone does not satisfy it, as ADR-0011 and
[ADR-0025](0025-developer-id-for-local-builds.md) both measured directly, including the
`SIGKILL`-before-`main` failure mode when the entitlement is forced on without one. **Obtaining a
Developer ID provisioning profile is the same account action ADR-0011 has been waiting on since M3,
and unblocking it unblocks both this anchor and the Secure Enclave key in one step.** That work is
in progress; this ADR is written ahead of it, the way
[ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) was written ahead of its own later
steps, so the design is settled before the entitlement lands rather than improvised after.

### 2. When it is written: at the same commit point, under the same lock

The anchor is written **immediately after** a transaction's file write lands, while
[ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md)'s sibling lock is still held —
not as a separate, later step a crash or a second writer could interleave with. Order matters in
one direction only: **file, then anchor.** If the process dies between the two, the anchor is
behind the file it describes, which §4 below treats as the ordinary, harmless case (`Extended`) —
the next open catches it up. The reverse order would risk the anchor claiming a state the file has
not reached, which is the one condition this design must never produce, because it would flag an
honest, unmodified file as diverged.

### 3. Advance-only, and never a lock-out

The anchor's `count` never decreases. Writing it is a compare-and-set against the previously stored
value: if the fresh value is not ahead of (or, on first write, absent relative to) what is already
there, nothing is written. This is what makes the anchor meaningful evidence of a gap rather than a
value that could quietly be talked backwards by a process that opens an older copy of the vault and
saves — a scenario ADR-0039's user decision 3 explicitly allows ("keep this app's version" or "lock
and reopen from the file" are both legitimate user choices, and either can mean this session's
audit chain is, from this point on, shorter than what the anchor last recorded).

**Every verdict this check can reach is warn-only.** Nothing here refuses to open a vault, refuses a
write, or requires re-authentication to proceed past a warning it produces — that is the difference
between this and [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md)'s continuity
check, which *does* refuse, because it is comparing two things this same process is directly
responsible for keeping consistent. An external anchor can go stale for entirely innocent reasons
(a vault opened for the first time on a new machine that has never written this Keychain item; a
vault restored from a backup that predates the anchor) and a security feature whose failure mode is
"the user's own vault stops opening" would not survive contact with those cases. The anchor's job is
to make a gap **visible and recorded**, not to gate anything on being able to explain it.

### 4. Six verdicts

Computed once per unlock, comparing the freshly opened vault's own audit chain against whatever the
anchor for its `vault_id` currently says:

| Verdict | Means | Anchor afterward |
| --- | --- | --- |
| `Unanchored` | No anchor item exists yet for this `vault_id` (first run on this machine, or a platform/build with no access-group entitlement). Nothing to compare against. | Written fresh, from this open. |
| `Current` | Anchor's `count` and `head` match the file exactly. | Unchanged. |
| `Extended` | The file has more entries than the anchor recorded, and the entry *at* the anchor's `count` matches the anchor's `head` — an ordinary append since the anchor was last written (including "the process died between file-write and anchor-write," §2). | Advanced to the file's current state. |
| `TailMissing` | The file has *fewer* entries than the anchor recorded. The tail the anchor witnessed is gone — the truncation C-11 describes. | Unchanged (advance-only; there is nothing newer to advance to). |
| `Diverged` | The file has at least as many entries as the anchor's `count`, but the entry at that position does not match the anchor's `head` — the log at that point was rewritten, not merely extended or truncated. | Unchanged. |
| `Unavailable` | The anchor item could not be read at all (Keychain error, entitlement not granted on this build). Says nothing about the file either way. | Not written; treated the same as `Unanchored` for display, but distinguished in the audit entry so "we didn't check" is never confused with "we checked and it was fine." |

`TailMissing` and `Diverged` are the two verdicts that matter: they are what a same-user attacker
with the vault key, or a rollback that happened after every session had locked, would produce. Both
render as a warning in the app (a banner on the vault, not a blocking dialog) and both are — per §5
— themselves audited.

### 5. Accepting a gap is audited

If the user proceeds past a `TailMissing` or `Diverged` warning — continuing to use a vault whose
history does not match what this machine last confirmed — that acceptance is written to the audit
log as its own entry, once the vault is in a state where writing is possible again. This is
deliberate: the anchor's entire value is as a record that a gap was *seen*, and a user who
legitimately restored from an old backup (an innocent cause of the same verdict) should be able to
say so and move on, but the log should say that they did, and when. The advance-only rule (§3) means
the anchor itself keeps recording the larger, pre-gap count until the vault's own chain organically
grows past it again — so the gap stays visible on every subsequent open until it is truly
superseded, not just until the next click.

### Phase 0: does the access group actually resist a same-user attacker?

Before building on this, the premise needs a direct measurement, in the spirit of ADR-0011's own
"measured on this machine" tables: **can a process running as the same user, without this app's
code signature, delete or overwrite a `kSecAttrAccessGroup`-scoped Keychain item belonging to a
different app signed by the same team, using nothing but the tools available to any local
process** (`security` CLI, `SecItemDelete`/`SecItemUpdate` from an unsigned or differently-signed
binary)? If the access group genuinely gates both read and write by code signature the way it is
documented to, T-3's attacker — same-user, no root — cannot touch the anchor even holding the vault
key, which is exactly the property this design needs and the in-file chain cannot provide. If it
does not hold in some case this project cares about (a debug-build attacker sharing an ad-hoc
signature with the victim, say, since ad-hoc-signed binaries have no team identifier to distinguish
them — the same edge [ADR-0015](0015-peer-code-signature-verification.md) documents for peer
verification), that has to be known before this ships rather than assumed. **This measurement has
not been run.** Its result belongs in this ADR, in this section, the day it is.

### Alternatives considered

**A counter or hash inside the file, e.g. in the header's AAD.** Rejected, for the reason
`vault-format.md` §8 already gives: a counter re-sealed by whoever forges the rest of the header
proves nothing an attacker who can forge the header could not also forge. Freshness cannot be
proven from a source the same attacker who would forge it also controls; it has to live somewhere
that source cannot reach.

**A plain login-Keychain item, with no access group.** Rejected as a *tripwire at best*. Any process
running as the same user can read and write an item in its own user's login keychain regardless of
which app created it — there is no code-signature gate without an access group — so a same-user
attacker holding the vault key (exactly T-3/C-11's threat model) could rewrite the anchor to match
whatever truncated or rolled-back file it just installed, and the anchor would agree with the lie.
An access-group item is the one shape where "another process running as this user" is not
automatically "another process that can touch this value" — which is also exactly why it needs the
Phase 0 measurement above rather than being assumed to work.

**Status quo — ship the ADR-0039 continuity check and call the gap accepted.** Rejected as the
default, though it remains what ships if Phase 0 fails or the provisioning profile does not land in
a reasonable time: the continuity check is real and worth having on its own, but it only covers the
window a session stays unlocked, and W-11's whole point is the attack that becomes possible once
nothing is watching. Leaving that open indefinitely, when a mechanism exists that plausibly closes
it, is a choice this ADR exists to make explicit rather than leave implicit.

## Linux and Windows

No equivalent has been designed. Linux has no OS-provided per-app-identity secure storage with a
comparable code-signature gate (the Secret Service API scopes by application-declared identity, not
by anything a kernel or a signing authority attests to); Windows' DPAPI and Credential Manager scope
by user, not by signed identity, and Authenticode's limits for this project's purposes are already
documented in [windows-port.md](../windows-port.md) §3.1 for the peer-verification case, which
shares the underlying problem. **Not checked** is the honest status for both, and this ADR does not
propose shipping a weaker anchor there — a warning that claims to detect tampering but cannot, on a
platform where the store backing it is not actually gated, would be worse than no anchor at all
(the same reasoning [ADR-0015](0015-peer-code-signature-verification.md) applies to an unverified
caller: say so, do not pretend).

## Open questions

- **Should accepting a gap (§5) require a fresh Touch ID or password, not just a click?**
  Recommended: yes. A `TailMissing` or `Diverged` verdict is, by construction, evidence that
  something with file access did something to this vault while nobody was watching; asking for the
  same proof-of-presence an unlock already requires, before letting that warning be dismissed, costs
  little and matches the weight of what it is confirming. Not decided.
- **CLI and Linux are unchecked for v1.** Whether the CLI participates in reading or writing the
  anchor at all — and what it would even mean to on a platform with no equivalent store — is open;
  see "Linux and Windows" above.

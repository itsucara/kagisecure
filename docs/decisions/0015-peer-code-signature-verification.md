# ADR-0015: Code-signature verification of the peer happens in Swift, and says what it found

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M4 implementation
- **Refines:** [ADR-0007](0007-m2-daemon-and-ipc-deviations.md) §3,
  [architecture.md](../architecture.md) §5, [ui-spec.md](../ui-spec.md) §10.2

## Context

architecture.md §5 says the app must independently verify who is asking: `LOCAL_PEERPID` from the
socket, then "code-signing identity of that pid via `SecCodeCopyGuestWithAttributes`". M2 shipped
the first half — the uid as a hard gate, the pid from the kernel, the executable path resolved
from that pid — and rendered the identity `[UNVERIFIED]` because the second half was missing
(ADR-0007 §3). ui-spec.md §10.2 wants the sheet to show a green **Verified** badge or a red
**Unverified — proceed with caution** banner. M4 owes that check.

## Decision

**The check is performed in Swift, on the app side of the FFI, and its verdict travels down into
Rust with the decision.**

`apps/macos/Kagisecure/Services/PeerCodeSignature.swift`:

1. `SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid], [], &code)` — resolve the
   kernel's pid to a `SecCode`;
2. `SecCodeCheckValidity(code, [], nil)` — a *dynamic* check: the pages the process is running are
   the pages it was signed with, and the signature is intact;
3. `SecCodeCopySigningInformation` — read the signing identifier, the team identifier, and the
   `kSecCodeSignatureAdhoc` flag;
4. verified **iff** the identifier names a kagisecure sidecar, the signature is not ad-hoc, and
   the team identifier equals this app's own.

Anything else is unverified, with a one-line reason that goes on the sheet and into the lease and
the audit entry: *"unsigned or invalid signature"*, *"signed as com.example.thing, not a
kagisecure sidecar"*, *"ad-hoc signed — identity not attributable to a developer"*, *"signed by a
different team"*.

### Why Swift and not Rust

The same argument [ADR-0008](0008-ffi-secret-crossings.md) makes for the Secure Enclave.
`SecCode*` is Security.framework: reaching it from `kagisecure-core` or `kagisecure-ffi` means
`unsafe` in crates that are `forbid(unsafe_code)`, a CoreFoundation dependency in the shared core,
and platform integration on the wrong side of architecture.md §2.5's layering rule — where it
would then have to be `#[cfg]`-ed away for the Linux CLI that also links the agent library.

Rust never calls up into Swift (ADR-0001), so the verdict cannot be *requested* from Rust either.
Instead the request carries the pid, Swift checks it before rendering the sheet, and
`agent_resolve(id, decision, verification)` passes the verdict back down with the answer. That
keeps every FFI call app → Rust and puts the verdict where it has to end up: in
`Lease.client_identity` and in the audit log, so the record says what was established rather than
what happened to be displayed.

### Team identity, not a hardcoded team

The comparison is against `SecCodeCopySelf`'s own team identifier, not a constant. A fork that
signs both halves with its own Developer ID gets a green badge; a stranger's signed binary does
not. There is nothing to update at release time and nothing to leak in the source.

### An unverified caller is warned about, not refused

architecture.md §5 carries an assumption — "we will ship allow-listed known-good sidecar
identities and treat any other caller as 'unknown, show a stronger warning' rather than refusing
outright — refusing would break users who build from source." **That assumption is kept.** An
unverified caller reaches the sheet with a red banner; the human decides. Refusing outright would
mean nobody could use a `cargo build` sidecar, which is every contributor and every reviewer.

The gate that *is* absolute stays absolute: a connection from another local uid is refused by
`kagisecure-agent` before a single request is read.

### Path allow-listing was considered and not adopted

The brief offered it as a fallback if signature verification proved too costly. It did not: the
whole check is ~90 lines of Swift with no new dependency. And a path allow-list is weaker than
what it would replace — a path is not an identity, `/usr/local/bin/kagisecure-mcp` can be
overwritten by anything that can write there, and the executable path is *already* shown on the
sheet as one of the facts a human weighs.

## Consequences

**Positive**

- ui-spec.md §10.2's verified/unverified distinction is real, and the evidence line is specific
  enough to act on.
- The audit log and the leases table record the verdict, so "what was Cursor allowed to do, and
  did we know it was Cursor" is answerable after the fact.
- The check fails closed: no pid, no `SecCode`, an unreadable signature, or any error is
  `verified: false` with the reason attached.

**Negative — accepted**

- **On this machine, every caller is unverified**, because a `cargo build` sidecar is ad-hoc
  signed and the app is too. The screenshots in the M4 record show exactly that: *"signed as
  kagisecure_mcp-43e7de0718ccfd8e, not a kagisecure sidecar"* before the identifier prefix match
  was added, and *"ad-hoc signed"* after. The verified path — green badge, matching team — cannot
  be exercised until M7 signs both halves with a Developer ID, and is therefore **implemented and
  untested on hardware**, the same status ADR-0011 records for the Secure Enclave.
- A `SecCode` check is a snapshot. It says the process was valid when asked; it does not stop a
  process from being debugged afterwards. The audit token / `kSecGuestAttributeAudit` variant
  would tighten this against pid reuse and is deferred, noted here so it is picked up
  deliberately.
- The verdict crosses the FFI as a Swift-supplied claim. A compromised app could lie to its own
  Rust — but a compromised app already holds the vault key, so this adds no attacker capability.

# ADR-0020: Fill approvals share the queue; fill leases do not share the store

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M6 implementation
- **Refines:** [ADR-0014](0014-approval-queue-over-ffi.md),
  [mcp-server.md](../mcp-server.md) §5, [ui-spec.md](../ui-spec.md) §10

## Context

M6 adds a second thing that has to ask a human a question: a browser wants to fill a password.
M4 already built that mechanism — a queue Rust pushes to and Swift polls
([ADR-0014](0014-approval-queue-over-ffi.md)) — and a lease model that bounds what an approval
grants.

Two questions, and they have different answers.

## Decision

### 1. One approval queue, shared

`ApprovalQueue` is hoisted to a process global in `kagisecure-ffi`, and both listeners ask through
it. `agent_next_request` reads *that* queue rather than the MCP agent's own.

Why not a second queue: the app polls one thing. A second queue would mean a second poll loop, a
second timeout, a second biometric path, and — the failure that matters — a fill approval that
reached a queue nobody was watching. The failure mode of a missed approval is **silence**, which is
the worst possible failure for an approval mechanism, so the queue is hoisted above both owners
rather than handed from one to the other.

Consequences that fell out of sharing, both fixed rather than tolerated:

- `VaultHandle::set_lock_hook` **replaces**, so two listeners registering one would have left the
  other's leases alive past a lock. `add_lock_hook` is the additive form.
- `AgentService.stop()` now **waits** for its poll loop to exit. `Task.cancel()` returns
  immediately, and a loop parked inside `agentNextRequest` could wake up after its service had
  stopped and take a request off a queue that now belongs to somebody else. Bounded at three poll
  intervals so a wedged call cannot hang a lock, and anything taken off the queue in that window is
  answered `USER_DENIED` rather than dropped.

### 2. Two lease stores, deliberately separate

`kagisecure_core::lease::LeaseStore` answers *"may this agent write these variable names into this
exact directory, for this long, this many more times"*. A fill has no directory, no variable names
and no use count; it has an origin and an item.

Reusing the store would mean either widening `LeaseRequest` with three optional fields that mean
nothing to `write_env_file`, or encoding an origin into a `PathBuf` and hoping nobody
canonicalizes it. `FillLeaseStore` is eighty lines and says what it means.

It also buys a property worth having: **an env lease can never satisfy a fill and a fill lease can
never satisfy an env write**, because they are not the same type and there is no function that
takes one and returns the other.

### 3. A fill lease is keyed on (origin, item), not on origin alone

The brief says "per-origin lease". This is that, plus one restriction: approving *this* password at
`https://example.com` does not silently approve the user's *other* `example.com` account. A site
where somebody keeps a personal and a work login is exactly where a second fingerprint is cheap and
a silent substitution is expensive.

Recorded as a deliberate narrowing, in the strict direction.

### 4. A lease excuses the biometric and nothing else

Every fill still requires the user's explicit action in the page — the in-field icon or ⌘\ — and
that is enforced in the content script, not here. What the lease buys is that logging in twice in
five minutes does not mean two fingerprints.

Five minutes by default (the env channel's is fifteen), fifteen at most. A login flow is seconds
long; the window only has to cover "the site bounced me back" and "I mistyped the code". A longer
default would buy convenience nobody asked for at the cost of a wider window in which a compromised
extension can fill without a fingerprint.

**Allow once** mints no lease at all. That is the difference between the two buttons on a fill
sheet, and it is why `Outcome` gained a `session: bool` — the env channel expresses "once" as
`uses = 1`, and the fill channel has no use counter, so the queue has to say which button was
pressed rather than let the extension service infer it from a count that means nothing to it.

### 5. The sheet shows two verdicts, not one

A fill names two processes: the native messaging host that connected, and the browser that launched
it. On an unsigned build these genuinely differ — Chrome is signed by Google and verifies; a
`cargo build` helper is ad-hoc and does not — so the sheet renders both.

The **single** verdict that travels back into Rust with the decision, and into the lease and the
audit entry, is the combined one: `host.verified && browser.verified`. A record that said
"verified" because the browser was signed, while our own helper was not, would flatter the weaker
half.

The browser check compares against a **hardcoded team identifier per browser**, which is the
opposite of what [ADR-0015](0015-peer-code-signature-verification.md) decided for our own binaries,
and for the opposite reason: our own team is knowable at runtime from `SecCodeCopySelf`, and a
browser vendor's is not. "Signed by Google" is a claim only Google's team identifier supports.

## Consequences

**Positive**

- One sheet, one timeout, one biometric gate, one place to get the approval flow right.
- Two lease models that cannot be confused for each other, with two tables in the UI that show what
  each actually grants.
- The sheet's most security-critical strings — the sentence and the scope summary — became `static`
  functions in M6 so that tests assert them; they were previously private computed properties on a
  `View` and were untested.

**Negative — accepted**

- **A process-global queue.** It is a global, and globals are where surprising coupling lives. The
  two consequences above were both found this way — one by a test that started failing, which is
  the good outcome, and one by reading. A third may exist.
- **Locking can block the main actor for up to ~750 ms** in the worst case, while the poll loop
  drains. Measured worst case is one poll interval (250 ms); the bound exists so a wedged Rust call
  cannot hang a lock, not because it is expected to be reached.
- **Two lease tables in one pane.** "Leases" now shows env leases and browser fills as separate
  tables. Honest, and slightly more UI than one table would have been.

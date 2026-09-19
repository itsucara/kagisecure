# ADR-0014: Approvals are a queue the app polls, not a callback Rust makes

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M4 implementation
- **Refines:** [ADR-0001](0001-rust-core-native-ui.md),
  [architecture.md](../architecture.md) §4.1, [ui-spec.md](../ui-spec.md) §10

## Context

The approval flow is the one place in this project where Rust has a question and only the UI can
answer it. An IPC thread inside `kagisecure-agent` is holding a `write_env_file` request; a human
has to look at a sheet and press a button; the thread then has to continue or return
`USER_DENIED`.

architecture.md §4.1 already ruled out the obvious design — Rust calling up into Swift and
awaiting the answer — because UniFFI's async foreign-callback path is the least settled part of
the binding generator (`Sendable` conformance under Swift 6 strict concurrency, `async_runtime`
on exported async traits, reference cycles in foreign trait objects). It did not say what to do
instead. M4 has to.

## Decision

**The agent library queues the question. Swift pulls.**

```text
sidecar → IPC thread ── ask() ──▶ ApprovalQueue ◀── agent_next_request(timeout_ms) ── Swift
                 ▲                     │                                                │
                 └───── Outcome ───────┴──────────── agent_resolve(id, decision, …) ─────┘
```

Six exported functions, all synchronous, all app → Rust, all value-returning:

| Function | Blocks? | Returns |
| --- | --- | --- |
| `agent_start(session, socket_path)` | no | the bound endpoint, or an error a human can read |
| `agent_next_request(timeout_ms)` | **yes**, up to `timeout_ms` | an `ApprovalRequestView`, or nothing |
| `agent_resolve(id, decision, verification)` | no | whether the id was still live |
| `agent_leases()` / `agent_revoke_lease(id)` | no | the leases table / whether it existed |
| `agent_take_lock_request()` | no | whether something asked the vault to lock over IPC |
| `agent_stop()` | no | — |

Swift runs one `Task.detached` calling `agent_next_request(timeoutMs: 500)` in a loop and hops to
the main actor with whatever it gets. There is no exported `async`, no callback interface, no
foreign trait object, and nothing for `Sendable` to be wrong about.

### The blocking call is the point, not a compromise

`agent_next_request` parks a background thread inside Rust for up to half a second. That is the
well-trodden UniFFI shape: a synchronous call that returns a value. The alternative — a
zero-timeout poll on a SwiftUI timer — would either spin or add latency to every approval, and
would still need the same queue underneath.

The global agent lock is released before the wait begins, so `agent_resolve` and `agent_leases`
stay responsive while a poll is parked.

### Why the request is a record and not an object

`ApprovalRequestView` is a `uniffi::Record`: a value Swift owns, with no methods and no handle
back into Rust. It carries the client's self-reported name, the kernel's pid, the executable path,
the canonical directory, the target file, the **variable names**, the argv for `run_with_env`, the
gitignore status, and the requested TTL and use count. Read that list as the definition of what
the sheet may state — and note what is not on it. There is no value, no length, and no way to add
one without editing [ADR-0008](0008-ffi-secret-crossings.md), which is why this is not a fifth
secret crossing.

### Timeouts belong to the queue, not to the UI

`ApprovalQueue::ask` blocks for at most 60 seconds and then answers `APPROVAL_TIMEOUT` itself. The
UI's countdown bar is a rendering of `expires_at`, not the thing that enforces it: a hung, crashed
or busy UI cannot leave an agent waiting forever, and cannot turn a timeout into an approval.

### One sheet at a time

Requests queue in arrival order and `AgentService` shows the head. A second caller waits rather
than stacking sheets. Each still runs out its own 60 seconds independently, so a request that
expires while queued is dropped from the UI having already been answered on the wire.

### Clamping is in Rust

"The user may shorten the TTL but not lengthen it beyond the tool's max" (ui-spec.md §10.2) is
enforced in `approval::outcome_for`, once, not in each UI. `AllowOnce` is `uses = 1` whatever the
agent asked for. A UI that tried to grant more than was requested would be clamped down, silently
and correctly.

## Consequences

**Positive**

- The acceptance criterion "no UniFFI async foreign callbacks are used on the approval path" is
  met by construction: the crate exports none, and `#[uniffi::export]` on an `async fn` does not
  appear anywhere in `kagisecure-ffi`.
- The same queue serves the terminal: `kagisecure daemon` polls `next_request` and answers with
  `Decision::AllowSession`, so the headless path is the production path with a different
  renderer, not a bypass.
- Testable without a UI. `crates/kagisecure-agent/src/approval.rs` has unit tests for delivery,
  clamping, denial, timeout and lock-sweep; the Swift integration tests drive the whole thing with
  a `BiometricGate` double.

**Negative — accepted**

- A polling loop is running whenever the vault is unlocked. One thread, awake 40 times a minute
  at 500 ms timeouts, doing an atomic load and a condvar wait.
- An approval's latency includes up to one poll interval. 500 ms, against a flow whose next step
  is a human reading a sheet.
- The app must remember to call `agent_stop()` before releasing the vault session. It does, in
  `AppModel.lock(reason:)`, and the `VaultHandle` lock hook is the belt to that brace: even if the
  order were wrong, taking the vault out of the handle denies every pending approval and drops
  every lease.

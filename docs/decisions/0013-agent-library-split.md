# ADR-0013: The daemon's logic becomes a library, `kagisecure-agent`

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M4 implementation
- **Refines:** [ADR-0007](0007-m2-daemon-and-ipc-deviations.md),
  [architecture.md](../architecture.md) §2.5, §2.6

## Context

[architecture.md](../architecture.md) §2.5 gives the native app four jobs; §2.6 gives
`kagisecure daemon` the same four minus the UI. Until M4 there was one implementation of jobs 1–3
and it lived in `crates/kagisecure-cli/src/commands/daemon.rs`: 1 221 lines holding the IPC
accept loop, caller verification, the lease store, every tool handler, the audit append, the
`.env` writer call and the process spawner.

The macOS app cannot call into a CLI subcommand. Three ways out:

1. the app shells out to `kagisecure daemon` and drives it — a second process holding a second
   copy of the vault key, defeating "the app owns the unlocked vault";
2. the app reimplements the handlers in Swift over `kagisecure-ffi` primitives — two
   implementations of the lease rules, which is the layering bug architecture.md §2.5 names;
3. the logic moves into a library both hosts link.

## Decision

**A new crate, `crates/kagisecure-agent`, owns everything the daemon decided.** The CLI
subcommand becomes a vault unlock, a `y`/`N` read and a banner — about 380 lines, most of it the
prompt's formatting — and the macOS app reaches the same code through `kagisecure-ffi`.

### Why a crate and not a module in `kagisecure-core`

`kagisecure-core` "has no networking, no MCP types, and no UI types. It does not know what an
agent is" (architecture.md §2.1). The agent library is the opposite of all three: it binds a
socket, speaks `kagisecure-ipc`'s protocol, and exists to answer agents. Putting it in the core
would have meant either a large optional feature or a core that contradicts its own description —
and it would have dragged `interprocess` into the dependency graph of every crate that opens a
vault, including the one the sidecar links.

So the layering is:

```text
kagisecure-core     vault, crypto, items, leases, audit, injection      (no agents, no sockets)
kagisecure-ipc      the wire protocol                                   (cannot name Secret)
kagisecure-agent    listener + approval queue + tool handlers           core + ipc
kagisecure-ffi      the app's surface                                   core + agent
kagisecure-cli      the human entry point, and the headless daemon      core + ipc + agent
kagisecure-mcp      the sidecar                                         ipc only
```

`kagisecure-mcp` does **not** depend on `kagisecure-agent`, so the test (run in CI until CI was
removed on 2026-09-19, locally since) that asserts the
sidecar's feature graph excludes `secret-material` is unaffected: the new crate is on the
privileged side of the boundary, with the vault, where it belongs.

### What moved unchanged

The nine tool handlers, the lease lookup, the exact-directory canonicalization, the audit drafts,
the `USER_DENIED` / `APPROVAL_TIMEOUT` mapping, and the same-user uid gate. The M2 cross-process
suite (`crates/kagisecure-cli/tests/mcp.rs`) was not modified and passes against the rewritten
daemon, which is the evidence that the move was a move and not a rewrite.

### What changed shape

- **The vault is borrowed, not owned.** `VaultHandle` is an `Arc<Mutex<Option<Vault>>>` with a
  lock hook; see [ADR-0014](0014-approval-queue-over-ffi.md).
- **`Lock` raises a flag instead of destroying the vault.** The library does not own its host's
  vault lifetime: `Request::Lock` sets a flag the host polls (`Agent::take_lock_request`) and the
  host — the app holding a `VaultSession`, or the daemon holding a `Vault` — performs the lock.
  A library reaching in to empty its host's state would leave the host holding an object that can
  no longer answer anything.
- **`accept()` polls.** `interprocess`'s blocking `accept` cannot be interrupted, and a host that
  has to quit cleanly (or a test that has to drop its agent) would hang forever on the join. The
  listener is set to `ListenerNonblockingMode::Accept` and the loop sleeps 25 ms between polls.
  Accepted streams are explicitly set back to blocking, because BSD `accept()` — macOS included —
  hands the new socket the listener's `O_NONBLOCK`, where Linux does not.

## Consequences

**Positive**

- One implementation of the lease rules, so the app and the daemon cannot disagree about what an
  approval grants.
- The library is testable without a process: `crates/kagisecure-agent/tests/sidecar.rs` hosts the
  server in the test binary and drives a real `kagisecure-mcp` against it.
- `kagisecure mcp install`'s snippet table moved to `kagisecure_agent::setup` and the app's "Set
  up your agent" screen reads the same table, so the two renderings of mcp-server.md §9 are now
  one.

**Negative — accepted**

- A sixth crate. The workspace is now core / ipc / agent / mcp / cli / ffi, which is one more
  thing to explain, and `cargo build --workspace` is a few seconds slower.
- The accept loop polls rather than parks. 25 ms of latency on connect, and a thread that wakes
  40 times a second doing nothing. Both are invisible next to spawning a sidecar process, and the
  alternative was a shutdown path that can hang.

**Neutral**

- `kagisecure daemon` keeps `--auto-approve` and its release-build refusal (ADR-0007 §2)
  unchanged. It now expresses approval as `Decision::AllowSession { … }` through the same queue
  the app uses, so the test suite exercises the production path rather than a bypass.

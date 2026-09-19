# ADR-0007: M2 — the daemon stand-in, caller verification without FFI, and five schema deviations

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M2 implementation
- **Refines:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [architecture.md](../architecture.md) §4.2/§5, [mcp-server.md](../mcp-server.md) §2/§5/§6,
  [vault-format.md](../vault-format.md) §5.2/§8, [threat-model.md](../threat-model.md) M-19

## Context

M2 turns three documents into three processes: an MCP sidecar, a local IPC protocol, and
something that owns an unlocked vault and says yes or no. The design documents were written
assuming the third of those is the native macOS app, which does not exist until M3/M4. Filling
that hole, and building the two that do exist, forced seven decisions the documents do not
settle. They are recorded here rather than left as surprises in the source.

## Decisions

### 1. The approval channel in M2 is a terminal prompt, and says so

`kagisecure daemon` unlocks a vault, listens on the socket the app will listen on, prints the
facts [ui-spec.md](../ui-spec.md) §10.2 says the approval sheet shows, and reads `y`/`N`.

This is **weaker than the design** and the daemon states that in its own startup banner: anything
that can write to that terminal can answer the prompt, whereas nothing that is not a finger can
answer Touch ID. What is *not* weaker, and does not change in M4, is everything behind the
prompt: the lease rules, the exact-directory match, the audit chain, and the fact that no secret
value crosses the IPC boundary. The daemon is retained after M4 for headless and CI-style use
(architecture §2.3), which is why it is built as a real implementation rather than a mock.

The prompt has a 60-second deadline, served by a dedicated stdin-reader thread so the timeout is
real rather than a comment. Timing out returns `APPROVAL_TIMEOUT`, not `USER_DENIED`: they mean
different things to a model, and mcp-server.md §7 says only one of them may be retried.

### 2. `--auto-approve` is gated on `debug_assertions`, not on a cargo feature

The integration tests need a daemon that approves without a human. The obvious mechanism is a
cargo feature, and it is the wrong one: `cargo test --workspace` would not enable it, so the test
that matters most would silently not run — which is exactly the failure mode a security test must
not have.

So `--auto-approve` exists unconditionally as a flag and is **refused at startup in a release
build**:

```rust
if args.auto_approve && !cfg!(debug_assertions) { bail!(...) }
```

A shipped binary therefore cannot be talked into it by any argument, environment variable or
configuration file, and `cargo test` gets it for free. `--non-interactive` (refuse everything not
already leased) is unconditional, because refusing is always safe.

### 3. Caller verification uses the peer's uid — and, after a same-day revision, the peer's pid too

threat-model M-19 wants the peer pid from the socket and then that process's code signature.
Signature checking needs `SecCode*` and is M3+. Of what remains, `interprocess` 2.4.4 exposes:

| | Linux / OpenBSD / FreeBSD / NetBSD | macOS |
| --- | --- | --- |
| peer euid | yes | yes (`xucred.cr_uid`) |
| peer pid | yes | **no** — `xucred` carries none |

The **uid check is a hard gate**: a connection whose euid is not ours is refused outright, not
warned about.

The pid was originally left self-reported on macOS on the reasoning that reading `LOCAL_PEERPID`
directly would mean FFI, and both new crates keep `#![forbid(unsafe_code)]`. That trade did not
survive the M2 review: `LOCAL_PEERPID` (`SOL_LOCAL`, `0x002`, declared in `<sys/un.h>`) is a
narrowly scoped, well-documented `getsockopt` call, and refusing a handful of reviewed FFI lines
in exchange for a pid otherwise taken purely on the caller's own word was the wrong side of that
trade. So, revised:

- the **pid** comes from the kernel on every platform this crate ships to: `interprocess`'s own
  `peer_creds()` on Linux and the BSDs, and `kagisecure_ipc::kernel_peer::peer_pid`'s
  `LOCAL_PEERPID` call on macOS. Only when the syscall itself fails — not a platform choice, a
  failure — does the sidecar's self-reported pid get adopted, for display only, with the identity
  still rendered `[UNVERIFIED]`;
- the pid is resolved to an executable path with `/proc/<pid>/exe` on Linux,
  `kernel_peer::executable_path`'s `proc_pidpath` call on macOS, or `ps -o comm=` elsewhere (and
  as the fallback if either of those two fails).

`kagisecure-ipc` keeps `#![deny(unsafe_code)]` rather than `#![forbid(unsafe_code)]` — `forbid`
cannot be locally overridden by a nested `allow`, which is the point of `forbid`, but it also
means it cannot carry one reviewed exception. The FFI itself lives nowhere else: it is confined
to `kernel_peer`, a module with its own `#![allow(unsafe_code)]` and a `// SAFETY:` comment on
every `unsafe` block, covered by a test that connects a socket to itself and asserts the reported
pid is this process's own.

The prompt prints the self-reported client name **in quotes** and the kernel-derived facts bare,
so a caller that names itself `Claude Code (verified)` cannot borrow the word. M4 still adds the
code signature check on top of this; the uid gate and the (now kernel-verified everywhere) pid
half both stay as they are.

The socket itself is `0600` inside a `0700` directory. `interprocess`'s pre-`bind` `fchmod` is
unsupported on macOS, so there the socket is created and then chmod-ed; the `0700` directory is
the boundary that actually keeps other local users out either way.

### 4. `VarSource::Pending` — a third variant vault-format §5.2 does not list

§5.2 gives `VarSource` two variants, `Literal` and `ItemField`. `add_variables` needs a third:
the whole point of that tool is that an agent can *name* a variable it is not allowed to supply a
value for, and the environment has to be able to hold "declared, awaiting a human". Without it,
the pending-entry flow in mcp-server.md §2.6 has nowhere to live.

`VarSource::Pending { hint }` carries the agent's hint and nothing else. It is reported in
metadata as `populated: false`, and resolving an environment that still contains one fails with
`VarNotPopulated` rather than writing an empty variable.

### 5. `body.audit` — the array vault-format §8 implies but does not name

§8 specifies the chain (`entry_n.prev`, `body.audit_head`) without naming the key the entries
live under. This build writes them to `body.audit`, a CBOR array of `AuditEntry`, alongside the
already-reserved `body.audit_head`. `canonical(entry)` is the `ciborium` encoding of the struct
with its fields in declaration order; field order is therefore part of the format, and the type's
doc comment says so.

An empty log has `audit_head` = 32 zero bytes, which is exactly what M1 reserved, so an M1 vault
verifies as an intact empty chain rather than as a broken one.

`sha2` became a non-optional dependency of `kagisecure-core` to make this work: the chain has to
be verifiable from a build that has no `secret-material`, since the audit log is metadata by
construction. SHA-256 is not key material, and the existing dependency-graph assertion (no
`argon2`, `chacha20poly1305` or `zeroize` in the bare graph; run in CI until CI was removed on
2026-09-19, locally since) is unchanged.

### 6. Agent visibility: default-deny, with the approval itself as the opt-in

threat-model M-9 is default-deny, and everything created by the CLI honours that: a new item, a
new environment and a new logical vault are all invisible to agents until the user says
otherwise (`kagisecure env agent-access --allow ...`).

An environment created *through* `create_environment` is the exception: it is created
`agent_visible = true`. The user approved that specific call, from that specific caller, moments
earlier; creating an environment the requesting agent then cannot see would be theatre, not
security. The approval is the opt-in.

The CLI flag is spelled `--logical-vault`, not `--vault`, because the global `--vault` already
means "which vault file" and two flags with the same name meaning different things is how someone
grants agent access to the wrong thing.

### 7. The cross-process tests live in `kagisecure-cli`, not in `kagisecure-mcp`

Seeding a vault with a canary needs `kagisecure-core` with `secret-material`. A dev-dependency
puts that straight back into `cargo tree -e features -p kagisecure-mcp`, which is the assertion
holding up ADR-0002 §3. The CLI already has that dependency and owns the `kagisecure` binary, so
`crates/kagisecure-cli/tests/mcp.rs` is where the daemon-plus-sidecar tests live.

The canary drives the sidecar through a hand-written JSON-RPC driver rather than an MCP client
library, because the assertion is about **bytes on stdout** and a client library consumes the
stream. A second test repeats the same sweep through `rmcp`'s real client over
`TokioChildProcess`, so what an actual MCP client sees is also under test.

## Consequences

- M4 replaces §1 and adds the code-signature half of §3 (the pid half is already kernel-verified
  and does not need replacing) and nothing else. The lease store, the audit chain, the IPC
  protocol and all nine tools move to the app unchanged.
- §2 means a release build has no code path to an unattended approval. It also means the flag is
  visible in `--help` on a release binary and fails only when used; that is deliberate, so the
  message can explain why.
- §4 and §5 are additive to the on-disk format. An M1 vault opens; a vault this build writes
  round-trips through an M1 build's `extra`/`ciborium::Value` passthrough for `envs`, though M1
  does not know what an audit array is and would drop it — which is acceptable while the format
  is explicitly unfrozen (vault-format §9).
- §6 will be argued with. The alternative — an agent that cannot see the environment it was just
  allowed to create — was worse.
- One thing the documents claim is not true of this build and is not a decision so much as a fact
  about `rmcp` 3.2.0: architecture §2.2 says the sidecar speaks MCP **2026-07-28**. rmcp reaches
  that version only through the `discover` lifecycle; an `initialize` handshake, which is what
  every stdio client does today, always settles on the newest *legacy* version, **2025-11-25**.
  The sidecar advertises what rmcp supports and negotiates down; nothing in the tool surface
  depends on the difference. Revisit when clients adopt `discover`.

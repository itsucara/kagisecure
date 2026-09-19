# ADR-0005: `Secret` in M1 — `zeroize` only, a named escape hatch, and a `--reveal` flag

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M1 implementation
- **Supersedes nothing. Refines:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [vault-format.md](../vault-format.md) §5.1, [threat-model.md](../threat-model.md) W-5

## Context

M1 is the first code in the repository, and it had to turn three prose statements into types:

1. `Secret` is "deliberately un-serializable and un-printable" with "no `AsRef<[u8]>` outside
   `crate::inject`" (vault-format §5.1).
2. Whether `secrecy` 0.10.3 is a dependency, or `zeroize` 1.9.0 plus our own newtype suffices, is
   an open question tracked as threat-model W-5 and an M1 acceptance criterion.
3. The CLI must be able to run a child process with an injected value, which means *something*
   has to be able to read the bytes back out.

## Decision

### 1. No `secrecy`. `zeroize` 1.9.0 plus our own `Secret`.

`secrecy` would buy us `ExposeSecret` as a trait and a `SecretBox` wrapper. We need neither:

- The value of the pattern is the *absence* of impls (`Serialize`, `Display`, `Clone`), which a
  20-line newtype gives us directly and which we can tailor — `secrecy`'s `SecretString` is
  `Clone`, which we do not want.
- `secrecy` re-exports `zeroize` anyway, so it is a wrapper around the dependency we would keep.
- The crate looked stale at evaluation time (threat-model W-5), and this is the one type in the
  project whose behaviour must not surprise us.

`kagisecure-core` therefore depends on `zeroize` 1.9.0 and defines
`Secret(Zeroizing<Vec<u8>>)` itself. **W-5 is closed.**

### 2. The enforcement point is the `secret-material` feature, not module privacy.

vault-format §5.1 says "no `AsRef<[u8]>` outside `crate::inject`". Taken literally that makes the
CLI — a separate crate — unable to inject anything, since `crate::inject` cannot hand out a
borrow it is not allowed to expose.

What actually carries the guarantee, per ADR-0002 §2 and architecture §2.2, is the **crate
graph**: a consumer that must never hold plaintext depends on `kagisecure-core` with
`default-features = false` and cannot name `Secret` at all. Inside that boundary, a single
loudly-named method is more reviewable than a web of `pub(crate)` re-exports:

```rust
#[must_use]
pub fn expose(&self) -> &[u8]   // only compiled with `secret-material`
```

Every call site of `expose()` is greppable and is expected to be justified in review. There are
four in this milestone: the vault's serde adapter, the injector's environment builder, the
injector's masking pass, and `item show --reveal`.

`Secret` still has **no** `Serialize`, `Deserialize`, `Display` or `Clone`. Its on-disk encoding
goes through a `pub(crate)` serde adapter, so no code outside `kagisecure-core` can serialize a
`Secret` on its own.

**Known gap, recorded honestly.** `Item` derives `Serialize`/`Deserialize` (behind
`secret-material`), which means a crate that opted into the feature *can* serialize a whole item,
adapter included. The stricter reading of vault-format §5.1 — a private mirror struct inside
`crate::vault` that the public `Item` converts to — costs about 120 lines of duplication and buys
nothing while the only consumer inside the feature boundary is our own CLI. Revisit if a third
crate ever enables `secret-material`.

### 3. The CLI has `item show --reveal`. MCP never will.

Roadmap M1 says `kagisecure show` "has no flag that prints a value". The same roadmap says
`kagisecure run -- printenv MY_VAR` prints one, because "the CLI is a trusted local tool; this is
the one place a value reaches a terminal, and it is the user's own."

Those two statements are in tension, and the second is the load-bearing one. Once `run` exists,
`sh -c 'echo $VAR'` prints any value the CLI can inject, so a missing `--reveal` flag is not a
boundary — it is a detour. A user who has typed their master password into their own terminal and
asked to see their own password should be shown it, not made to invent a shell incantation.

So `item show --reveal` exists, and:

- it is off by default; `item show` prints `<concealed>` and says the flag exists;
- `--json` **never** prints a value, with or without `--reveal`, because machine-readable output
  is what ends up in a pipe or a log by accident;
- there is no equivalent anywhere near MCP. ADR-0002 is untouched: the sidecar has no `reveal`
  tool, cannot name `Secret`, and the IPC protocol has no message carrying a value.

The distinction that matters is **who is asking**, not which subcommand.

## Consequences

- M1's acceptance criterion "`kagisecure show` … has no flag that prints a value" is **not met as
  written**, deliberately, and the roadmap wording should be updated to match: metadata by
  default, values only behind an explicit flag, never over MCP.
- `cargo tree` for a future `kagisecure-mcp` must not show `argon2`, `chacha20poly1305` or
  `zeroize` — the `secret-material` feature pulls them in, and their absence is a cheap check
  (run in CI until CI was removed on 2026-09-19, locally now) that the boundary held.
- `expose()` is the review trigger. A PR that adds a call site to it is a PR that touches the
  product's central invariant.

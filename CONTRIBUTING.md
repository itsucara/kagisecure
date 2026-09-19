# Contributing to kagisecure

Thanks for looking. kagisecure is a working password manager: a Rust workspace
(`kagisecure-core` and friends), a macOS app, and browser extensions for Chrome and Safari, built
around an MCP sidecar so an agent can request items with explicit per-item approval rather than
standing access. See [docs/roadmap.md](docs/roadmap.md) for what is built, what is in progress,
and what is deliberately not scheduled, and [docs/releasing.md](docs/releasing.md) for how a
release is signed, notarized, and shipped.

The design documents in [`docs/`](docs/) are not a proposal to be reviewed before code exists —
they are the live reference the code is held to, updated in the same PR as anything that changes
the behavior they describe.

## What is most useful right now

1. **Read the code alongside the design.** Especially [docs/threat-model.md](docs/threat-model.md)
   and [docs/vault-format.md](docs/vault-format.md). If you have built or broken a password
   manager, your reading of those two files is worth more than a pull request.
2. **Challenge the assumptions.** Anything marked `> Assumption:` in the docs is a decision that
   has not been made properly yet. Open an issue on any of them.
3. **Check the facts.** The docs cite specific crate versions and platform API behavior. If
   something is out of date or wrong, say so with a link.

## Before you write code

- **Open an issue first** for anything non-trivial. The design is still moving; a large PR against
  a moving design wastes your time.
- **Cryptographic and security design changes go in an issue, not a PR.** Discussion first, code
  after. This includes the vault format, key hierarchy, KDF parameters, the MCP tool surface, and
  the approval flow.
- Decisions that shape the architecture get an ADR in [`docs/decisions/`](docs/decisions/),
  numbered sequentially, in the existing context / decision / consequences shape.

## Ground rules for code (once M1 starts)

- `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo deny check` must pass.
- Target zero `unsafe` in `kagisecure-core`. Generated FFI code is exempt; hand-written `unsafe`
  needs a comment explaining the invariant and a second reviewer.
- **Never log, print, format, or serialize a secret value.** The `Secret` type is built to make
  this a compile error; do not add impls that defeat it. See
  [ADR-0002](docs/decisions/0002-no-secret-values-over-mcp.md).
- New MCP tools need a very good reason. The small, fixed tool surface is a feature.
- Changes to `crates/kagisecure-core/src/crypto/` or `.../inject/` require a second reviewer.
- Tests for anything touching the vault format include a golden vector.
- Commit messages: a short imperative subject line, and a body explaining *why* if it is not
  obvious.
- **Run the end-to-end harness before a PR that touches a process boundary** — the MCP tool
  surface, the agent socket, the browser extension, or the CLI's exit codes. `make e2e` drives
  real processes across real sockets and writes `e2e/report/index.html`; `make e2e SUITE=mcp,cli`
  is the headless subset run locally in place of CI. See [docs/e2e-harness.md](docs/e2e-harness.md), which also has
  how to add a scenario.
- **Do not run `cargo xtask bindgen` while tests run.** Both touch `target/`, and a spawn-based
  integration test can pick up a binary `bindgen`'s own `cargo build` is mid-rewrite, which fails
  flakily rather than deterministically (seen in M7). Run `cargo test` alone, or `make check`
  (build + test, and does not invoke `bindgen`) — not either one next to a `bindgen` in another
  terminal.

## Pull requests

- One logical change per PR.
- Reference the issue it resolves.
- If it changes behavior described in `docs/`, update the doc in the same PR.
- Be patient with review on security-relevant code. Slow review there is the point.

## Reporting a vulnerability

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be straightforward and courteous. Assume the other person has a reason. No harassment, no
personal attacks. Maintainers may remove comments or contributors that make the project a worse
place to work.

## License

By contributing, you agree that your contributions are dual-licensed under MIT and Apache-2.0,
matching the project ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)). No CLA.

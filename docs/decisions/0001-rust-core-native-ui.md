# ADR-0001: Rust core with native platform UIs

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** project owner

## Context

kagisecure must run on macOS and Windows with a real desktop UI, hold key material safely, expose
an MCP server, and share one implementation of the vault format so that a vault written on one
platform opens on the other. The realistic options:

| Option | Shape |
| --- | --- |
| A. Rust core + native UIs (SwiftUI, WinUI 3) | One crate workspace, two thin platform apps over FFI |
| B. Electron or Tauri with a web UI | One UI codebase, webview on both platforms |
| C. Two full native implementations | No shared core; the format specified in prose |
| D. .NET everywhere (MAUI/Avalonia) | One managed codebase |

Considerations specific to this product:

- The core is cryptography, a binary file format, an importer for untrusted input, and a
  protocol server. That is systems code, and it must be identical on both platforms — a
  format divergence would corrupt user vaults.
- The app holds plaintext secrets in memory and must control their lifetime (zeroization,
  avoiding copies). A GC'd or JIT'd runtime makes that materially harder: managed strings are
  immutable, copied, and moved by the collector.
- The security story is the product. "It's an Electron app that holds your secrets" is a hard
  sell and pulls in a browser engine, a Node runtime, and a large dependency surface as part of
  the TCB.
- Biometric integration (Secure Enclave keychain ACLs, `KeyCredentialManager`) is
  platform-specific regardless of UI choice. A webview does not help; it just adds a bridge.
- Approval prompts must be unmistakably native and unspoofable-looking. A webview-rendered
  approval dialog is exactly what a phishing overlay looks like.

## Decision

**Option A.** A single Rust Cargo workspace holds the vault format, crypto, item model, import,
injection, audit, lease logic, and the MCP server. The macOS app is SwiftUI; the Windows app is
WinUI 3 / C#. No Electron, no Tauri, no webview anywhere in the product.

Corollaries:

1. The FFI surface is an explicit, reviewable crate (`kagisecure-ffi`), not "everything public in
   core". UniFFI 0.32.0 generates the Swift side; see [ADR-0003](0003-uniffi-vs-csbindgen.md) for
   C#.
2. The native apps contain **UI and platform integration only**. Any logic that would have to be
   written twice belongs in the core; a second implementation of a rule is a layering bug.
3. Rust never calls up into the UI to ask a question. Every FFI call is app→Rust and returns a
   value. Asynchronous, user-answered flows (approvals) go over IPC instead — see
   architecture §4.1 — because UniFFI's async foreign-callback path has known rough edges
   (Swift 6 `Sendable` conformance, `tokio` async_runtime on exported async traits, reference
   cycles in foreign trait objects) and is the wrong place for the security-critical path.
4. `unsafe` in the core is target-zero and requires review; the FFI crate's generated `unsafe`
   is regenerated, not hand-edited.

## Consequences

**Positive**

- One implementation of the vault format. Cross-platform byte compatibility becomes a test, not
  a hope.
- Fine-grained control of secret lifetime: `Zeroizing` buffers, no GC, no hidden copies, drops
  where we say they are.
- Small TCB. No browser engine, no Node, no JS package ecosystem in the process that holds keys.
- Native look, native biometric sheets, native accessibility, small binaries, fast launch.
- The core is reusable: the CLI, the MCP sidecar, and a future Linux GUI all link the same crate.

**Negative — accepted**

- **Two UIs to build and maintain.** Feature parity is manual work and will drift; the roadmap
  makes parity an explicit M4 acceptance criterion.
- **Two skill sets required.** Contributors comfortable in Rust, Swift, *and* C# are rare. This
  narrows the contributor pool, which for an OSS project is a real cost.
- **FFI is a boundary with its own failure modes** — binding generation, ABI drift, build
  plumbing in Xcode and MSBuild. Mitigated by `cargo xtask bindgen` and a check (run in CI until
  CI was removed on 2026-09-19, run locally now) that regenerated bindings are unchanged.
- **Slower to first release** than a single Electron app would have been.
- **Linux has no GUI at launch.** The CLI and MCP sidecar work there from M2; a GTK front end is
  post-v1.

**Neutral**

- The core being UI-agnostic makes a future Linux or mobile front end a UI project rather than a
  rewrite.
- Choosing native UI does not by itself make the app secure; it removes a class of risk and adds
  maintenance cost. The security properties come from the threat model, not from the toolkit.

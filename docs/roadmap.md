# Roadmap

Status as of 2026-09-13: **M0–M6 complete, including Safari (M6b); M7 substantially complete —
everything but the notarization submission itself, which is blocked on a credential (see M7
below); M8 (import) scheduled and in progress.**

Milestones are sequential in dependency, not in calendar. No dates are given — this is an OSS
project with no staffing commitment, and dated roadmaps in that situation are fiction.

| ID | Milestone | Depends on | State |
| --- | --- | --- | --- |
| M0 | Design documents | — | complete |
| M1 | Core crate + CLI | M0 | complete |
| M2 | MCP sidecar working with Claude Code | M1 | complete |
| M3 | macOS app core (three-pane UI, categories, lock screen) | M1 | complete |
| M4 | macOS app + MCP integration (approval dialog, agent access) | M1, M2, M3 | complete |
| M5 | Password generator + TOTP | M1, M3 | complete |
| M6 | Browser-extension autofill (Safari + Chrome) | M3, M4 | complete |
| M7 | Release engineering (macOS) | M3, M4, M5 | substantially complete — see below |
| M8 | Import (1PUX and the CSV family) | M1, M3 | scheduled, in progress |
| M9 | Agent-requested browser fills | M4, M6 | built on macOS with Chromium-family browsers; not yet run in a real browser — see below |
| M10 | Shared vaults (offline, file exchange) | M1, M3, M4, M8; ADR-0039/0040 implemented | scheduled, in progress — Phases 0, 1 and 2 built (library and CLI), agents and approvals (Phase 4), and the macOS app's UI (Phase 5); see below |
| M11 | Unattended jobs (machine vault, standing grants, run-browser sign-ins) | M4, M9; ADR-0035 implemented; ADR-0039/0040 implemented | in progress — Phases 0 to 5 built (the documentation page, the core, the engine, the app, shared-vault copies, unattended sign-ins); macOS only; the interactive fill of a machine-vault login is not built; see below |
| M12 | Agent test logins (kagisecure generates the password; sign-up fills) | M4, M9; ADR-0047 implemented | built on macOS — Phases 1a, 1b and 3 (ADR-0048 accepted 2026-10-07); the app's sheets, Settings and notices covered by unit tests only, not by XCUITest; see below |

**Update, 2026-09-26:** M9 — an agent driving the user's browser asks for a saved login to be
filled into the tab in front, and a human approves each fill in the app
([ADR-0036](decisions/0036-agent-requested-browser-fill.md)) — was scheduled and built, Phases 1–3,
ahead of shared vaults ([ADR-0035](decisions/0035-shared-vaults.md), accepted the same day), which
stays unscheduled. It is recorded as M9 because ADR-0036 proposed a milestone after M8, not
because M8 is finished.

**Update, 2026-09-27:** shared vaults ([ADR-0035](decisions/0035-shared-vaults.md)) are scheduled
as **M10**, Phases 0–4 of its addendum's plan, macOS only; the macOS app's shared-vault UI (Phase 5)
is not scheduled. Phase 0 — the prerequisites — is built. The next free number was M10 because
ADR-0036's milestone took M9 first, as ADR-0035's proposed roadmap changes anticipated. Those
changes are applied below: the platform decision paragraph, the Sync subsection and the post-v1
list.

**Update, 2026-09-27 (later):** unattended jobs ([ADR-0042](decisions/0042-unattended-agent-access.md),
accepted for macOS the same day) are scheduled as **M11**, in progress: Phase 0, the page
[unattended-credentials.md](unattended-credentials.md), and Phase 1, the machine vault in
`kagisecure-core`, are built. The owner chose convenience over defence in depth for it: arming
persists across restarts with no expiry, with the machine vault's key in the Keychain (ADR-0042,
"Implementation decisions"). Headless hosts stay out of it
([ADR-0043](decisions/0043-unattended-access-on-headless-hosts.md), proposed). ADR-0042 asked to
follow shared vaults; M11 is in progress beside M10 rather than after it, since its Phase 1 needs
only M10's Phase 0 (the body passthrough and the `format_ver` lever), which is built.

**Update, 2026-10-07:** agent test logins ([ADR-0048](decisions/0048-agent-test-logins.md),
proposed) are recorded as **M12**, pending the owner's acceptance of the ADR; nothing is built. The
same day the stdin delivery of `run_with_env` ([ADR-0047](decisions/0047-stdin-delivery.md),
accepted) landed on `main`. M12 lets an agent have kagisecure generate and keep a password for a
test account on a local or allowed origin and fill it into sign-up and login pages without a sheet
once a Settings switch is on; its implementation plan, with files and tests per phase, is in the
ADR, so that whoever implements it starts from the ADR and this entry.

**Update, 2026-10-07 (later):** ADR-0048 was accepted the same day, and M12 is built on macOS:
Phases 1a and 1b (create, reuse, the no-sheet login and sign-up fills) and Phase 3
(`trash_test_logins`, `kagisecure test-logins`, `create_test_login`'s `bind`, and the
non-browser recipe in [agent-test-logins.md](agent-test-logins.md)). Two e2e scenarios run headless
against the committed test app.

**Platform decision (2026-09-09):** kagisecure is macOS-first. The product is modeled on
1Password 8's desktop look and feel (see [ui-spec.md](ui-spec.md)) and has no accounts, no
server and no network code. It was scoped as single-user; sharing a vault with a small group, or
between one person's computers, is designed in
[ADR-0035](decisions/0035-shared-vaults.md) (accepted; scheduled as M10) as an offline feature in
which the users move files themselves and kagisecure adds no networking. Windows (formerly M4) and
iOS are demoted to unscheduled optional work — see
"Optional / later" below — so they no longer occupy numbered slots or block anything. Import was
demoted with them in that pass; it has since been **re-scheduled as M8** (2026-09-13), because
"you cannot get your passwords in" is the one gap that stops a working password manager from being
usable at all. M5 (password generator + TOTP) can start as soon as M3's core UI and
M1's core crate exist, in parallel with M4's MCP-integration work. M6 (browser extension) is a
committed milestone, not optional, but is sequenced after the app and its MCP integration exist
because it depends on both for native messaging and item lookup.

**Update, 2026-09-25:** Windows work was started, at the user's request, without reversing the
platform decision above — the "Windows app (optional / later, formerly M4)" entry further down
still describes the roadmap's own position; this is a record of out-of-roadmap work, not a
re-scheduling. What landed: a WinUI 3 app shell (first-run, lock/unlock, item CRUD, live TOTP,
import, Agent access, an approval sheet, Settings and Audit); a hand-written C ABI and C# interop
layer covering the full UniFFI surface ([ADR-0003](decisions/0003-uniffi-vs-csbindgen.md)'s
fallback, since `uniffi-bindgen-cs` does not support the pinned UniFFI version); Authenticode peer
verification, structurally weaker than the macOS check by design
([ADR-0032](decisions/0032-authenticode-peer-verification.md)); Windows Hello vault-key wrapping
([ADR-0033](decisions/0033-windows-hello-key-derivation.md)); named-pipe IPC hardened with an
owner-only DACL, SQOS-identified client connections and a same-user gate; HKCU native-messaging
registration; and a per-user, unelevated WiX MSI release pipeline with every PE signed
individually ([ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md)). See
[windows-port.md](windows-port.md) for the dated, itemized record of what is and is not verified —
notably, Windows Hello has been exercised only against fakes and the master-password fallback (no
Hello-capable device on the machine that built this), the release signing path is unverified (no
certificate available), a fill from a real Chrome or Edge has not been driven end to end (the
process-ancestry walk, the Windows browser executable table, registry registration and Authenticode
browser checks are built and unit-tested, but only a stand-in browser has exercised the native
host), and none of this has been run against the Unix test suite.

> Assumption: M7 (release engineering) depends on M3–M5, not M6. The password generator and TOTP
> are required features (see [ui-spec.md](ui-spec.md) §8–§9) and should gate a 1.0 release; the
> browser extension is explicitly "a later but committed milestone" per the owner's framing, with
> its own new trust boundary (browser process, extension update channel) that warrants shipping
> and hardening independently rather than delaying the core app. If the owner wants the extension
> in the first public release instead, move M7's dependency to include M6.

---

## M0 — Design documents

Establish the design in writing before any code, so that the security-critical decisions are
reviewable by people who will not read Rust.

**Scope:** README, architecture, threat model, vault format, MCP server design, import mapping,
this roadmap, ADRs 0001–0004, licenses, CONTRIBUTING, SECURITY.

**Acceptance criteria**

- [ ] All documents listed above exist and cross-link correctly.
- [ ] Every design decision that was *assumed* rather than *decided* is marked `> Assumption:`.
- [ ] The threat model states at least: assets, trust boundaries, six adversary classes, a
      threat→mitigation matrix, and an explicit non-goals list.
- [ ] The vault format is specified precisely enough that two people could write interoperable
      implementations from it (byte layout, AAD rule, key hierarchy, KDF parameters).
- [ ] The MCP tool list has JSON schemas and a stated enforcement mechanism for the
      "no secret values" invariant.
- [ ] Dual MIT/Apache-2.0 license files present with the correct copyright line.
- [ ] At least one external reviewer has read `threat-model.md` and `vault-format.md` and their
      comments are resolved or recorded as open questions.

**Explicitly not in M0:** any code, any repository scaffolding beyond docs, any website.

---

## M1 — Core crate + CLI

The vault works, end to end, from a terminal, with no GUI and no MCP.

**Scope**

- `kagisecure-core`: vault create/open/save, header + AEAD body, Argon2id KEK, random vault key,
  password-wrapped key slot, one-time printable recovery code and its wrapped key slot, item/field
  model, `Secret` type, zeroization, audit log with hash chain, lease model (in-memory), `.env`
  writer, process spawner.
- `kagisecure-cli`: `init`, `unlock`, `lock`, `add`, `ls`, `show --names-only`, `env write`,
  `run -- <cmd>`, `audit`, `recover`.
- Test suite including the first golden vector.

**Acceptance criteria**

- [ ] `kagisecure init` creates a vault; `kagisecure ls` on a wrong password fails with a clear
      error and no partial output.
- [ ] `kagisecure init` prints a one-time recovery code (256 bits, Base32 with a checksum) exactly
      once and stores its wrapped key as a third `wrapped_keys` entry (see vault-format.md §3.2);
      `kagisecure recover` unlocks the vault with that code, independent of the master password,
      and lets the user set a new master password afterward.
- [ ] `kagisecure add` stores a Login item with a concealed field; `kagisecure show` prints field
      **labels only** and has no flag that prints a value.
- [ ] `kagisecure env write --environment X --dir ./` writes a `0600` `.env` with correct contents,
      verified by a test that reads the file back.
- [ ] `kagisecure run --environment X -- printenv MY_VAR` prints the value (the CLI is a trusted
      local tool; this is the one place a value reaches a terminal, and it is the user's own).
- [ ] A vault written by this version is in `tests/vectors/` and a test opens it.
- [ ] Argon2id parameters are read from the header, not hardcoded in the open path; a vault with
      non-default parameters opens correctly.
- [ ] Tampering with any header byte causes body decryption to fail (AAD test).
- [ ] `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo deny check` all pass locally on
      Linux, macOS, and Windows (this ran in CI until CI was removed on 2026-09-19).
- [ ] Decision recorded on whether `secrecy` 0.10.3 is a dependency or whether `zeroize` 1.9.0 plus
      our own `Secret` suffices (see threat-model W-5).
- [ ] No `unsafe` in `kagisecure-core` outside a documented, reviewed allow-list (target: zero).

**Definition of done:** a contributor can build from a clean checkout on all three OSes and store
and retrieve a secret.

**Deferred from M1 to M2.** The scope above is as originally planned; in practice the M1
implementation shipped `kagisecure-core` + `kagisecure-cli` with the item/vault/run/recover path
working end to end (see [README.md](../README.md)) and deferred the following out of the listed
scope, without changing it here:

- Audit log / hash chain — **done in M2** (`kagisecure_core::audit`, `body.audit` +
  `body.audit_head`, `kagisecure audit --verify`)
- Lease model (in-memory) — **done in M2** (`kagisecure_core::lease`)
- `env write` CLI subcommand — **done in M2** (`kagisecure env write`)
- The `Environment` model (§5.2 of [vault-format.md](vault-format.md)) — **done in M2**
  (`kagisecure_core::model::env`, `kagisecure env create|list|add-var|rm`)
- `lock` CLI subcommand — **done in M2** (`kagisecure lock`, over IPC to a running daemon)
- `import` (1PUX/CSV, see [import.md](import.md)) — deferred out of M1 and now **scheduled as
  M8** below. `.env` import is the one part still unscheduled ([import.md](import.md) §10)
- Attachments — **still deferred** after M3 as well, and no longer to a numbered milestone. M3
  showed they are a core-crate piece (a sibling encrypted directory, a new HKDF path, new golden
  vectors), not the UI work the earlier note assumed; see
  [ADR-0012](decisions/0012-m3-scope-deviations.md) §2
- `cargo deny`, run in CI — **still deferred**, to M7 (release engineering), which is where the
  advisory/licence gate actually has teeth. (Delivered in M7 as a local/pre-release gate; the CI
  it was originally meant for was removed on 2026-09-19.)

---

## M2 — MCP sidecar working with Claude Code

An agent can discover and inject secrets, with approval, without a GUI.

**Scope**

- `kagisecure-mcp` on `rmcp` 3.2.0, stdio, the nine tools from
  [mcp-server.md](mcp-server.md).
- IPC over `interprocess` 2.4.4, framing, handshake, peer identification.
- The CLI runs as a foreground approval daemon (`kagisecure daemon`) that owns the unlocked vault
  and prompts in the terminal. **This is a temporary stand-in for the native app** and says so in
  its own output.
- The canary test from [threat-model.md](threat-model.md) §8.

**Acceptance criteria**

- [x] `claude mcp add --transport stdio kagisecure -- <path>` registers the server — Claude Code
      reports `✔ Connected` and lists all nine tools. **Partially met:** driving it with
      `claude -p` on the implementation machine was not possible because that install was not
      logged in (`Not logged in · Please run /login`), which is an account action outside this
      milestone's scope. The tools were instead driven through `rmcp`'s own client over
      `TokioChildProcess` and through a raw JSON-RPC driver, both against a real vault, and
      [mcp-server.md](mcp-server.md) §11 carries the exact commands for a logged-in machine.
- [x] `write_env_file` produces a `0600` `.env` after a terminal approval, and the tool result
      contains variable names and no values.
- [x] `run_with_env` returns exit code and scrubbed output, and does **not** invoke a shell
      (`run_with_env_does_not_invoke_a_shell`: an argument containing `; touch …` creates no
      file and comes back as ordinary text).
- [x] Denying an approval returns `USER_DENIED` and no partial write occurs.
- [x] `APP_NOT_RUNNING` is returned promptly (< 1 s, asserted) when no daemon is listening.
- [x] Canary test: a 32-byte marker seeded as a secret value never appears in any byte the
      sidecar writes to stdout or stderr, nor in any tool result an MCP client receives, nor in
      the audit log. **Deviation:** the sweep is exhaustive over the nine tools rather than
      property-based over fuzzed arguments; argument-level fuzzing is a fair follow-up but the
      marker can only reach stdout through a *result*, and every result shape is covered.
- [x] Dependency test: `kagisecure-mcp`'s (and `kagisecure-ipc`'s) build graph does not enable
      the `secret-material` feature — asserted by `cargo tree -e features`, run in CI until CI
      was removed on 2026-09-19, now run locally.
- [x] Leases behave per [mcp-server.md](mcp-server.md) §5: expiry, use exhaustion,
      exact-directory match, and no privilege creep on a broader request.
- [x] Audit entries are written for every call including denials, and contain no values; the
      hash chain verifies.
- [ ] Verified working against at least two of the four target clients. **Not met:** Claude Code
      connects and enumerates the tools, and `kagisecure mcp install` emits (and can write)
      configuration for Claude Desktop, Codex CLI and Cursor, but none of the other three was
      exercised against a running daemon. Carried into M4, whose last criterion is the same bar.

**Explicitly not in M2:** biometrics, any GUI.

**Delivered.** `crates/kagisecure-ipc` (the wire protocol, with no message type able to carry a
value), `crates/kagisecure-mcp` (the nine tools on `rmcp` 3.2), `kagisecure daemon` (the
terminal-approval stand-in), and the M1 carry-over list above. Design deviations are recorded in
[ADR-0007](decisions/0007-m2-daemon-and-ipc-deviations.md): the daemon's approval channel,
`--auto-approve` being gated on `debug_assertions` rather than a cargo feature, caller
verification without FFI (uid enforced, pid self-reported on macOS), `VarSource::Pending`, the
`body.audit` key, agent visibility for agent-created environments, and where the cross-process
tests live.

**Still deferred out of M2:** `import`, attachments and `cargo deny` (see the M1 carry-over list
above), and the three non-Claude-Code clients.

---

## M3 — macOS app core

The real product on macOS: browse, search, and edit a vault with a 1Password-8-styled UI, gated
by Touch ID. No MCP/agent integration yet — that's M4.

**Scope**

- `kagisecure-ffi` with UniFFI 0.32.0, Swift bindings, `cargo xtask bindgen`.
- SwiftUI app per [ui-spec.md](ui-spec.md): three-pane `NavigationSplitView` (sidebar / item list
  / item detail), sidebar sections (All Items, Favorites, Categories, Tags, Archive, Trash),
  vault switcher, search (⌘F), sort, quick-copy hover actions.
- Item CRUD across all categories in [ui-spec.md](ui-spec.md) §5, edit mode, tags, favorites,
  archive/trash, custom sections, attachments.
- Keychain + Secure Enclave wrapped key slot with `SecAccessControl(.biometryCurrentSet)`
  (ADR-0004), lock screen with Touch ID + master-password + recovery-code fallback
  ([ui-spec.md](ui-spec.md) §6).
- Auto-lock on idle, sleep, and screen lock. Menu-bar status item (lock state only in M3; Quick
  Access itself is M4).

**Acceptance criteria**

- [ ] First run creates a vault, enrolls Touch ID, and the app relaunches into a Touch ID unlock.
      **Not met.** Creating a vault on first run works and is verified. Touch ID enrolment does
      not: filing a Secure Enclave key in the keychain needs the `keychain-access-groups`
      entitlement, which needs a provisioning profile, which needs a registered device on the
      owner's Apple Developer account — an account action outside this milestone. The code is
      written and the vault-side half is fully tested; the app degrades to the password slot with
      an explicit message rather than silently. See
      [ADR-0011](decisions/0011-secure-enclave-under-ad-hoc-signing.md) for exactly what was and
      was not verified, and on which signing.
- [ ] Enrolling a new fingerprint invalidates the wrapped key and forces a password unlock
      (manual test, documented in a test plan). **Not met**, for the same reason: the
      `.biometryCurrentSet` handling is implemented (an invalidated key prunes the dead slot and
      explains itself) but could not be exercised without a working enrolment.
- [x] The three-pane layout renders sidebar, item list, and item detail per
      [ui-spec.md](ui-spec.md) §2, and every sidebar section (All Items, Favorites, each
      Category, Tags, Archive, Trash) filters the item list correctly. Filtering is asserted in
      `KagisecureTests/VaultStoreTests.swift`; the rendering was confirmed by running the app.
- [x] Create/edit/delete/favorite/archive round-trip correctly for every category in
      [ui-spec.md](ui-spec.md) §5, including the `Secret`-backed concealed fields, via
      `kagisecure-ffi` only (no logic duplicated in Swift). **Caveat:** every category's *template*
      is exercised (`Category::default_fields`, a core function), and the round-trip is asserted
      for Login, Database, API Credential and SSH Key rather than for all twelve individually —
      the code path does not vary by category.
- [x] ⌘F search filters by title/tag/URL across categories; never matches on secret field
      contents. Asserted with a canary value that a search must not find.
- [x] Screen lock, sleep, and idle timeout each drop the vault key from memory. Implemented in
      `AutoLockCoordinator` (system-wide idle via `CGEventSource`, `NSWorkspace` sleep, and the
      `com.apple.screenIsLocked` distributed notification); locking releases the `VaultSession`,
      which zeroizes the key on drop. The *next* unlock re-prompts Touch ID only where Touch ID
      works — see the first criterion.
- [ ] The app builds as a universal binary and runs on the two most recent macOS majors.
      **Deliberately deferred to M7** — M3 builds `aarch64-apple-darwin` only, because an
      untested x86_64 slice is a support claim with no evidence behind it
      ([ADR-0012](decisions/0012-m3-scope-deviations.md) §1). The deployment target is macOS 15;
      it has been run on macOS 26.1.
- [x] `agent_visible` defaults to `false` on every newly created item and is visible/toggleable in
      the item detail "Agent access" panel ([ui-spec.md](ui-spec.md) §4.4), even though no agent
      can connect yet (that's M4) — the toggle and its persistence are testable in isolation.
      Both the item-level and the per-field toggle are asserted, including that turning the item
      off turns every field off with it.

**Delivered.** `crates/kagisecure-ffi` (the UniFFI surface), `xtask` (`cargo xtask bindgen`), a
`Makefile`, `apps/macos` (XcodeGen spec, a local SwiftPM package wrapping the generated Swift and
an xcframework, the SwiftUI app, and a test bundle), and a macOS CI job (removed on 2026-09-19,
now run locally via `cargo xtask bindgen` and `make macos-test`) that regenerates the
bindings, asserts they are current and idempotent, and builds and tests the app under ad-hoc
signing.

**Deviations, each with an ADR:** [ADR-0008](decisions/0008-ffi-secret-crossings.md) (the four
secret crossings the FFI has), [ADR-0009](decisions/0009-checked-in-swift-bindings.md) (generated
Swift is committed, reversing architecture §6's assumption),
[ADR-0010](decisions/0010-app-sandbox-off-and-generated-project.md) (sandbox off; the `.xcodeproj`
is generated), [ADR-0011](decisions/0011-secure-enclave-under-ad-hoc-signing.md) (Secure Enclave
vs. signing), [ADR-0012](decisions/0012-m3-scope-deviations.md) (aarch64-only, attachments still
deferred, and the new `Item.trashed_at` field).

**Still deferred out of M3:** attachments (they are a `kagisecure-core` milestone of their own,
not UI work — [ADR-0012](decisions/0012-m3-scope-deviations.md) §2), creating and renaming custom
sections in the edit sheet (existing sections render and survive an edit), the menu-bar status
item, and the "Customize Sidebar" affordance. Quick Access, the password generator and TOTP were
never in M3 and appear in the menus as disabled entries that say which milestone they belong to.

---

## M4 — macOS app + MCP integration

The app talks to `kagisecure-mcp` and gates every agent action behind Touch ID.

**Scope**

- IPC listener in the app ([architecture.md](architecture.md) §4.2); the app spawns/points at
  the bundled sidecar and shows its path on a "Set up your agent" screen
  ([architecture.md](architecture.md) §8, [mcp-server.md](mcp-server.md) §9).
- Approval dialog per [ui-spec.md](ui-spec.md) §10: verified/unverified client identity,
  canonical directory, variable names, git-ignore warning, TTL/uses, Touch ID gate, Allow
  once / Allow for this session / Deny.
- Agent-access sidebar section ([ui-spec.md](ui-spec.md) §2.2, §10.4): Environments list and
  Leases list with live countdown and one-click revoke.
- Quick Access floating panel ([ui-spec.md](ui-spec.md) §7), `⇧⌘Space`.
- Audit viewer (filterable by client, tool, item/environment, outcome).

**Acceptance criteria**

- [x] A `write_env_file` call from Claude Code raises the native approval sheet showing the
      caller identity, the canonical directory, the variable names, and the TTL, per
      [ui-spec.md](ui-spec.md) §10.2. **Met, with one honest qualification:** the identity shown
      is the *result* of a real code-signature check
      ([ADR-0015](decisions/0015-peer-code-signature-verification.md)), and on an ad-hoc-signed
      build that result is "Unverified — proceed with caution" with the reason attached. The
      **verified** rendering — green badge, matching team identifier — cannot be produced until
      M7 signs both halves with a Developer ID, so it is implemented and untested on hardware,
      the same status [ADR-0011](decisions/0011-secure-enclave-under-ad-hoc-signing.md) records
      for the Secure Enclave.
- [x] Approving completes the injection; denying returns `USER_DENIED`; a 60 s no-answer returns
      `APPROVAL_TIMEOUT`. All three exercised end to end against a real sidecar: the first two in
      `KagisecureTests/AgentServiceTests.swift` and
      `crates/kagisecure-agent/tests/sidecar.rs`, and all three by hand against the running app
      (the timeout and the denial are entries 5 and 7 of the audit log in the M4 record).
- [x] "Allow once" mints a single-use lease; "Allow for this session" mints a TTL/use-bounded
      lease; a broader subsequent request always re-prompts (no privilege creep, per
      [mcp-server.md](mcp-server.md) §5). Asserted in
      `allow_once_does_not_cover_the_next_identical_request` and, for the broader-request half,
      by the M2 suite that still runs unchanged against the same lease store.
- [x] The Agent Access → Leases list shows every active lease live (identity, directory,
      variables, remaining TTL/uses) and Revoke immediately invalidates it. The table and its
      one-second countdown are built; revoke and revoke-all are asserted in
      `crates/kagisecure-agent/src/agent.rs`. **Caveat:** the table was not screenshotted with a
      live lease in it, because minting one by hand needs a fingerprint this environment cannot
      supply — the Swift integration test mints and asserts one through a `BiometricGate` double
      instead.
- [x] A `.env` target inside a git work tree not covered by `.gitignore` is flagged in the sheet.
      Screenshotted (`04-approval-sheet.png` in the M4 record). **Deviation:** the sheet states
      the problem in red; the one-click "Add to `.gitignore`" button [ui-spec.md](ui-spec.md)
      §10.2 offers is **not built** — see "Still deferred" below.
- [x] No secret value crosses the IPC boundary — verified by capturing and inspecting frames in a
      test build. Done one better: `crates/kagisecure-agent/tests/sidecar.rs` seeds a 32-byte
      marker as a secret value and asserts it reaches the written `.env` and appears in *neither*
      the approval request the UI is handed, *nor* any audit entry, *nor* any byte the sidecar
      wrote to stdout.
- [x] No UniFFI async foreign callbacks are used on the approval path (ADR-0001 / architecture
      §4.1) — Rust never calls up into Swift to ask a question. The approval is a queue the app
      polls with a blocking synchronous call; `kagisecure-ffi` exports no `async fn`, no callback
      interface and no foreign trait. See
      [ADR-0014](decisions/0014-approval-queue-over-ffi.md).
- [ ] `⇧⌘Space` opens Quick Access with a live-filtered flat item list and copy actions, without
      raising the main window, per [ui-spec.md](ui-spec.md) §7. **Not met — deferred to M5, and
      not attempted.** Quick Access shares nothing with the MCP integration: it is a second window
      over the item list, and the honest reading of M4's scope line is that it was bundled here
      because §7 said "roadmap M4" rather than because it belongs with the approval flow. The
      menu entry stays present and disabled and now names M5. Doing it badly to tick a box would
      have cost the review time that the approval sheet deserved.
- [ ] Verified working against at least two of the four target MCP clients (Claude Code
      required). **Half met, and for the same reason as M2's.** Claude Code registers the sidecar
      and reports `✔ Connected` against the **app** (not the CLI daemon) — the transcript is in
      the M4 record, and the socket in it is the app's. Driving it with `claude -p` still needs a
      logged-in install, which this machine does not have. The other three clients were again not
      exercised; `kagisecure mcp install` emits their configuration and the app's "Set up your
      agent" screen now shows the same snippets from the same table, but neither was run against
      a live app. Carried into M7, where the signed, installed build is the one worth testing
      against.

**Delivered.** `crates/kagisecure-agent` (the IPC listener, the approval queue, the lease store,
the tool handlers, the client-setup table — everything `kagisecure daemon` used to own), the
`agent_*` surface on `kagisecure-ffi`, and the macOS app's approval sheet, Agent access pane
(Environments with the `add_variables` pending-input flow, Leases, Audit, "Set up your agent"),
menu-bar status item, and peer code-signature verification. `kagisecure daemon` is now a thin
wrapper over the same library and is retained as the headless/CI approval channel.

**Deviations, each with an ADR:** [ADR-0013](decisions/0013-agent-library-split.md) (the daemon's
logic became a library; `Lock` raises a flag rather than destroying its host's vault; the accept
loop polls), [ADR-0014](decisions/0014-approval-queue-over-ffi.md) (the approval queue and the
six synchronous FFI calls that drive it), [ADR-0015](decisions/0015-peer-code-signature-verification.md)
(signature verification in Swift, and what "verified" can and cannot mean on an ad-hoc build),
and [ADR-0008](decisions/0008-ffi-secret-crossings.md) §2/§5 (the fourth function on crossing 2,
and why the twenty new exports are not a fifth crossing).

**Still deferred out of M4:**

- **Quick Access** (`⇧⌘Space`, [ui-spec.md](ui-spec.md) §7) — moved to M5, where it sits next to
  the generator as UI work rather than agent work.
- **The "Add to `.gitignore`" button** on the approval sheet. The warning is there and is loud;
  the one-click fix is not. It writes to the user's repository from inside an approval dialog,
  which wants its own thought about what it appends and to which `.gitignore` in a nested work
  tree.
- **Bundling the sidecar into the `.app`.** The setup screen finds `kagisecure-mcp` next to the
  app, on `PATH`, or at `KAGISECURE_MCP`, and says which; putting a signed copy inside
  `Contents/MacOS` is M7's job ([architecture.md](architecture.md) §8), and doing it now would
  mean an unsigned binary in a bundle nobody can notarize.
- **The audit viewer's item/environment filters.** It filters by outcome, by actor, and by a text
  query over tool, variable names, path and detail; a structured "everything Cursor did to this
  environment" filter is a nicer version of the same thing and was not built.
- **The three non-Claude-Code clients** and `import`, attachments and `cargo deny`, all carried
  from earlier milestones.

## M5 — Password generator + TOTP

Required features per the owner's feature set decision, not optional add-ons.

**Scope**

- `kagisecure-core`: TOTP generation per RFC 6238 (SHA1/SHA256/SHA512, configurable digits and
  period), `otpauth://` URI parsing/round-trip, and a password generator (character-class mode
  and word-list/diceware mode) with an entropy estimator. Both are core-crate functions so the
  CLI and both UI layers (app, and later extension) share one implementation.
- Quick Access ([ui-spec.md](ui-spec.md) §7), moved here from M4: a floating `⇧⌘Space` panel over
  a live-filtered flat item list, with the copy actions §3 already has. It is item-list UI, not
  agent UI, and it belongs next to the generator sheet rather than next to the approval flow.
- App UI: password generator sheet ([ui-spec.md](ui-spec.md) §8 — length slider, mode toggle,
  character/word options, live strength meter) and TOTP entry flow
  ([ui-spec.md](ui-spec.md) §9 — QR scan, `otpauth://` paste, manual entry, live preview) plus
  the TOTP field's ring-countdown display ([ui-spec.md](ui-spec.md) §4.2).

**Acceptance criteria**

- [x] TOTP implementation passes the RFC 6238 Appendix B test vectors for all three supported
      hash algorithms. All six timestamps × three algorithms, at 8 digits, in
      `totp::tests::rfc6238_appendix_b_vectors`.
- [x] `otpauth://` URIs round-trip (parse → re-serialize → same parsed fields) for label, issuer,
      secret, algorithm, digits, and period. The second round trip is byte-identical, so the
      format is a fixed point rather than merely stable in its parsed fields.
- [x] The password generator produces output honoring every toggle (length, character classes,
      ambiguous-character exclusion, word count/separator) and the strength meter's estimate
      moves monotonically with configured entropy. The meter is driven by the *recipe's* entropy,
      not by an estimate of the candidate, which is what makes monotonicity a property rather
      than a hope; asserted across the whole 8–128 slider range in Rust and again in Swift.
- [x] The TOTP field UI shows a live code with a countdown ring that regenerates the code exactly
      at period boundaries, with no visible drift after a 10-minute soak test. Met by
      construction rather than by soaking: each tick recomputes `code_at(wall clock)` instead of
      decrementing a counter, so there is nothing to drift.
      `TotpTests.tenMinutesOfRendersChangeOnlyAtPeriodBoundaries` sweeps 600 one-second renders
      and asserts the code changes exactly 20 times, at exactly the boundaries.
- [x] Generated passwords and TOTP seeds/codes are `Secret`-typed and never appear in logs or the
      audit trail (canary test extended to cover generator output). Stronger than asked: the
      `generator` and `totp` modules are compiled **only** under the `secret-material` feature, so
      the sidecar cannot call them at all. `mcp.rs::a_totp_code_never_reaches_the_model` drives
      every tool against a vault whose agent-visible item has a TOTP field and asserts the seed,
      the URI and every code valid during the run are absent from stdout, stderr and the audit
      log; `no_tool_schema_offers_a_one_time_password` asserts no tool even declares a place to
      put one.
- [x] `⇧⌘Space` opens Quick Access with a live-filtered flat item list and copy actions, without
      raising the main window, per [ui-spec.md](ui-spec.md) §7 (carried from M4). **Met in part.**
      The shortcut, the panel, the live filter, ↑/↓, ⏎/⌘⏎/⌥⏎ and Esc are all built and verified by
      hand against a running app. The main window is never made key and never ordered front — but
      the *application* is activated, because a non-activating panel in an app with a Dock icon
      cannot receive keystrokes on macOS 26 (measured: `AXFocusedUIElement` is the panel's search
      field and the frontmost app keeps every key). See
      [ADR-0017](decisions/0017-quick-access-hotkey-and-pasteboard.md) §2.
- [x] TOTP code *injection* into an environment (as opposed to display in the app) remains
      deferred per "Post-v1, unscheduled" below — this milestone covers generation and display
      only, not a new `run_with_env`-style TOTP tool. No new tool was added; the MCP tool list is
      the same nine it was after M2.

**What was built.**

- `kagisecure-core`: `generator` (character mode with uniform rejection sampling from `OsRng` and
  a guaranteed instance of every enabled class; word mode over the embedded EFF long list;
  `Recipe::entropy_bits`), `generator::strength` (a five-level bucket over entropy bits with
  run/repeat/dictionary/famous-password penalties), and `totp` (RFC 6238 over HMAC-SHA1/256/512,
  6–8 digits, `otpauth://` parse and format, forgiving Base32). Both behind `secret-material`.
- CLI: `kagisecure generate` (needs no vault at all) and `kagisecure totp <item>[/field]`, plus
  `item add --totp LABEL`, which prompts for the URI and refuses to store one that does not parse.
- FFI: ten new synchronous calls, all pure functions except `VaultSession::totp_code` and
  `item_totp_code`. [ADR-0008](decisions/0008-ffi-secret-crossings.md) grew a fifth crossing.
- macOS app: the generator sheet (from the `+` menu, ⇧⌘G, and a die button on every concealed
  field in edit mode), the TOTP field with its ring, the setup sheet with a live preview, Quick
  Access, a Quick Access entry in the menu-bar item, and `PasteboardService` — every copy in the
  app now carries the concealed-type marker and is cleared after a configurable delay.

**Deviations, each recorded:**

- [ADR-0016](decisions/0016-totp-field-storage.md) — a TOTP field is `FieldKind::Totp` +
  `Secret(<whole otpauth:// URI>)`, not a new `FieldValue` variant with the parameters stored
  beside the seed. No body-schema change, nothing about a second factor outside `Secret`, and
  unknown URI parameters survive a round trip.
- [ADR-0017](decisions/0017-quick-access-hotkey-and-pasteboard.md) — `RegisterEventHotKey` rather
  than an event monitor (no Accessibility, no Input Monitoring, no TCC prompt at all); the
  activation compromise above; and the clipboard policy. The App Nap finding is in there too: a
  60-second clear had not fired after 90 seconds with the app in the background, until the
  countdown was wrapped in `beginActivity`.
- ui-spec §8's length slider goes to 128 rather than 64, and its meter has five labels rather than
  four. Both noted in place in that document.

**Still deferred out of M5:**

- **QR-code scanning** ([ui-spec.md](ui-spec.md) §9 path 1) — neither the camera nor
  image/screen-capture decoding is built. Every service that shows a QR code also offers the URI
  behind a "can't scan the code?" link, so this is convenience over an existing path rather than a
  way in that is missing; it wants `Vision`'s barcode detector, a camera permission, and a
  screen-capture permission, which is three new pieces of platform surface for a shortcut.
- **Rebinding `⇧⌘Space`.** If another application already owns it, registration fails, Settings
  says so, and Quick Access is menu-only. A shortcut recorder is small and was not needed to make
  the feature work.
- **A real pattern-matching strength estimator.** `generator::strength` is entropy plus a short
  list of penalties, which the roadmap marked optional; zxcvbn is a dependency and a corpus.
- **Attachments, `import`, `cargo deny` and the three non-Claude-Code clients**, all carried from
  earlier milestones.

---

## M6 — Browser-extension autofill (Safari + Chrome)

A later but committed milestone: fill logins and copy TOTP codes from the browser, without
turning the browser into a new place secret values are exposed to anything untrusted.

**Scope**

- Safari Web Extension and Chrome MV3 extension, native messaging to the macOS app (a new,
  separate channel from the MCP sidecar's IPC — the extension is not an MCP client and must not
  reuse `write_env_file`/lease machinery).
- Scope limited to: filling username/password into a matched site's login form on explicit user
  action (click or shortcut, never on page load), and copying the current TOTP code for the
  matching item to the clipboard.
- A dedicated threat-model addendum (new section or sibling doc to
  [threat-model.md](threat-model.md)) covering the browser process as a new semi-trusted
  component, the extension update/distribution channel, and content-script injection surface —
  written and reviewed before this milestone ships, not after.

**Acceptance criteria**

- [x] Extension-to-app native messaging is authenticated: the app verifies the calling browser's
      code signature and the extension ID against an allow-list, mirroring the sidecar identity
      check in [architecture.md](architecture.md) §5; an unrecognized caller is refused, not
      silently trusted. **Met, with the same qualification M4 records and one addition.** The
      extension id is pinned by a committed key and refused at `Hello` if it does not match
      ([ADR-0021](decisions/0021-pinned-extension-id.md)); a native host with no recognized browser
      within three hops of process ancestry is refused with `UNTRUSTED_HOST` before it can ask
      anything, and the refusal is audited. The **code signature** is checked on two processes —
      the native host and the browser — and rendered as two verdicts. On this ad-hoc build the
      browser's verdict is genuinely *verified* (Chrome and Edge are signed by their vendors, and
      the check compares against a hardcoded per-vendor team) while our own helper's is
      *unverified*; the combined verdict that reaches the lease and the audit entry is the weaker
      of the two, deliberately. See [ADR-0020](decisions/0020-fill-approvals-and-origin-leases.md)
      §5.
- [x] Autofill only ever proposes credentials for an item whose saved URL matches the current
      page's origin; there is no fuzzy or "close enough" domain match. eTLD+1 under the Public
      Suffix List plus **exact** scheme and port, in one place
      (`crates/kagisecure-extension-ipc/src/origin.rs`), with a table covering `co.uk`,
      `github.io`, bare public suffixes, ports, `localhost`, IPv4 and IPv6 literals, IDNs, and the
      iframe policy in both directions. [ADR-0022](decisions/0022-public-suffix-list.md) records
      the list's update policy.
- [x] Autofill never fires without an explicit user action for that page load, or an approval in
      the app, with a biometric, for an agent's request naming that page (M9,
      [ADR-0036](decisions/0036-agent-requested-browser-fill.md)); there is no autofill-on-load
      default. Two entry points reach a fill — the in-field icon's click handler
      and the ⌘\ handler — and both check `event.isTrusted`, so a page cannot synthesize either.
      The e2e asserts the password field is empty after a fresh load of a page that *does* match.
- [x] TOTP copy from the extension popup requires the vault to be unlocked and matches the same
      "no bulk value exposure" posture as the app — one code, for one matched item, per explicit
      click. It is a separate request with its own approval, its own audit entry (`totp_code`) and
      its own reply type; a fill never carries a code. The code is applied by the content script —
      into a detected one-time-code field, else the clipboard — and is not returned to the popup.
- [x] The browser-extension threat-model addendum is written, reviewed, and linked from
      [threat-model.md](threat-model.md) before the extension is distributed even in beta.
      **Written and linked; not reviewed.** [threat-model-browser-extension.md](threat-model-browser-extension.md)
      exists, covers the browser process, the update channel, content-script injection, a rogue
      native host, other browser profiles, and seven residual risks — and says in its own §11 that
      it has not been read by a second person. The extension is not distributed, so the criterion's
      gate has not been crossed; the review is M7's to obtain.
- [x] No secret value is held by the extension's own storage (`chrome.storage`, Safari
      equivalent) at rest — values are requested from the app per-use, matching the "the vault
      key never leaves the trusted process" rule the rest of the product follows. Stronger than
      asked: there is **no `chrome.storage` call anywhere in the extension**, for anything —
      not a value, not a URL, not a match result.
- [x] **Safari.** Built in **M6b**, and the deferral's premise turned out to be wrong. A Safari Web
      Extension needs `com.apple.security.application-groups`, which a **Developer ID signature
      carries with no provisioning profile** — measured, along with the fact that
      `keychain-access-groups` is a restricted entitlement AMFI refuses without one and kills the
      process at exec for. The two were assumed to be the same class of blocker
      ([ADR-0023](decisions/0023-safari-deferred.md)) and are not
      ([ADR-0025](decisions/0025-developer-id-for-local-builds.md)).

      What shipped: a Safari Web Extension app-extension target inside the app bundle, sandboxed,
      reaching the (unsandboxed) app over a Unix socket in a shared App Group container
      ([ADR-0024](decisions/0024-safari-app-group-socket.md)); the same protocol, framing, origin
      rule, approval sheet, lease store and audit vocabulary as Chromium; one shared extension
      source tree (`extensions/shared`) that both browsers load; and a peer check that is
      *stronger* than the Chromium one, because the process on the socket is code we signed rather
      than a pipe with a browser somewhere above it.

      **One thing is not verified, and it is the last hop.** No fill has been performed in real
      Safari by a human: the session that built M6b could not drive Safari's interface. Everything
      below Safari is tested, including a Developer-ID-signed **sandboxed** probe carrying only the
      App Group entitlement completing `hello` → `match` → `fill` through the group-container
      socket with the shipped `AppGroupSocket.swift`. What remains untested is Safari loading the
      extension, its per-site permission model, and the icon and ⌘\ in a Safari page. See
      [browser-extension.md](browser-extension.md) §8, "What is verified, and what is not".

**Delivered.** `crates/kagisecure-extension-ipc` (the protocol, both framings, the origin rule, the
peer/ancestry identity, the socket listener), `crates/kagisecure-nmhost` (the native messaging
host: a pipe with no vault), `kagisecure-agent`'s `extension`, `fill_lease` and `browser_setup`
modules, the FFI's extension surface, the macOS app's Browser extension screen, the fill variant of
the approval sheet, the fill-lease table, and the MV3 extension (moved to `extensions/shared` in
M6b) — plain
modern JavaScript with no build step.

**Delivered in M6b.** `extensions/shared` (one source tree for both browsers, with the transport
branch confined to `native.js`), `extensions/safari/manifest.json`, the
`KagisecureSafariExtension` app-extension target with `SafariWebExtensionHandler` and
`AppGroupSocket`, the Safari front end of `ExtensionAgent`, the Safari section of the Browser
extension screen, and `make macos SIGN=developer-id`.

**Deviations, each with an ADR:**
[ADR-0018](decisions/0018-browser-extension-secret-crossing.md) (the deliberate new secret
crossing, and why it is not a sixth row in ADR-0008's table),
[ADR-0019](decisions/0019-native-messaging-forwarder.md) (the host is a pipe; a second socket with
a different byte order; the ancestry check),
[ADR-0020](decisions/0020-fill-approvals-and-origin-leases.md) (one queue, two lease stores),
[ADR-0021](decisions/0021-pinned-extension-id.md) (the committed key),
[ADR-0022](decisions/0022-public-suffix-list.md) (the list and its update policy),
[ADR-0023](decisions/0023-safari-deferred.md) (Safari deferred — **superseded**),
[ADR-0024](decisions/0024-safari-app-group-socket.md) (the App Group socket, the identity gate, and
what an ad-hoc build gets), [ADR-0025](decisions/0025-developer-id-for-local-builds.md)
(`SIGN=developer-id`, and the Secure Enclave measurement it produced). Later corrected by
[ADR-0037](decisions/0037-every-fill-needs-a-fresh-presence-proof.md): a fill lease skips the
sheet and never the Touch ID check, because a trusted click in the page is not proof of a person
— superseding ADR-0020 §4.

**Findings, recorded because they changed the plan:**

- **⌘\ cannot be a `chrome.commands` shortcut.** Chromium's command key whitelist has no entry for
  a backslash; a manifest naming one produces a shortcut that never fires, with no error anywhere.
  The shortcut is a capture-phase `keydown` handler in the content script instead, gated on
  `event.isTrusted`. It therefore works only when focus is in a page, which is where a login form
  is.
- **Chrome 137 removed `--load-extension`.** On Chrome 152 the switch is silently ignored — the
  browser starts and the extension is simply not installed. Verified with a three-line probe
  extension, so it is the browser's behaviour and not ours;
  `--enable-unsafe-extension-debugging` does not bring it back. The Playwright suite therefore
  tries browsers in order and runs against **Microsoft Edge**, which still honours it; Chrome is
  covered by the manual pass, where the extension is loaded the way a user loads it. The pinned
  key makes the id identical in both, so the app's allow-list is exercised the same either way.
  See [browser-extension.md](browser-extension.md) §9.
- **The app read `KAGISECURE_HOME` and the CLI read `KAGISECURE_VAULT`**, so pointing both at one
  scratch vault took two variables that had to agree. The app now reads `KAGISECURE_VAULT` first
  (the file) and falls back to `KAGISECURE_HOME` (the directory), which is how the manual pass
  points the app at a test vault. Both are documented on `default_vault_path`.

**Findings from M6b, recorded because they changed the plan:**

- **`keychain-access-groups` is refused by AMFI, not just by Xcode.** Force-signing it onto a
  Developer ID binary produces a process the kernel kills at exec — *"Disallowing … because no
  eligible provisioning profiles found"*. M3's Touch ID criterion is therefore still unmet, and
  Developer ID signing does not substitute for the account action.
  [ADR-0011](decisions/0011-secure-enclave-under-ad-hoc-signing.md) now records the measurement.
- **Chromium will not load a symlinked content script.** A symlinked service worker loads; a
  symlinked content script silently never runs. That is why `extensions/shared` is the extension
  root itself rather than a shared directory that per-browser folders symlink into.
- **Edge 152 reads native messaging manifests from `--user-data-dir`.** It did not, and
  [browser-extension.md](browser-extension.md) §9 used to say so; the Playwright suite was failing
  on this machine for that reason before M6b touched it, and now writes both locations. The
  product is unaffected — a default launch's user-data-dir *is* the documented directory.

**Findings after M6, recorded because they changed the plan:**

- **Identifier-first sign-ins fill nothing, and the password-anchored detector is why.** Google,
  Microsoft and Okta ask for the username on a page with no password field on it, so
  `detectLoginForm` — anchored on `input[type=password]`, and staying that way — found nothing to
  offer, and the user typed their own email address. The fix was not a looser detector but a
  second one (`detectIdentifierForm`, mutually exclusive with the first) plus a protocol change:
  `fill` names the fields it wants and the app **enforces** the selector when it builds the reply.
  [ADR-0030](decisions/0030-identifier-first-login.md).
- **A fill that carries no secret does not need the sheet — and saying so out loud was the work.**
  A request for the username alone writes a value the extension was already handed, unprompted, by
  the `match` that drew the icon, so raising an approval sheet there would ask for a fingerprint to
  authorize something already disclosed. It is served without a sheet, without a biometric and
  without a lease, keeps every other gate including the user's own click, and is audited under its
  own detail, `FILL_USERNAME_ONLY`, so the log distinguishes it from a fill a human approved.
  ADR-0030 §2 and its security argument.
- **Continuing on page two needs memory, and memory in a browser wants a policy.** Without one, a
  site with two saved accounts offered the list again and invited the user to fill the *other*
  account's password under the username already on screen. `extensions/shared/tabmemory.js`
  remembers which item a tab chose — an item id, an origin and a deadline, and no username and no
  value — for 60 seconds, carried down only to the same site or a subdomain of it, dropped on
  expiry, tab close, navigation away, vault lock, or the password fill itself. It is **in memory
  only**: the acceptance bullet above still holds literally, there is still no `chrome.storage`
  call anywhere in the extension, and a service worker Chrome evicts simply falls back to showing
  the list. The popup shows a "Continuing as …" banner with a Forget button, because a manager
  that silently decides who you are is worse than one that asks.

**Still deferred out of M6:**

- **A fill performed in real Safari by a human**, per the Safari criterion above.
- **A CI job for the end-to-end suite.** It needs a real display and a browser that will load an
  unpacked extension. The command and the runner requirements are written down in
  [browser-extension.md](browser-extension.md) §9, and it is a **documented manual gate** rather
  than an untested workflow file nobody can run locally. Moot since all CI was removed on
  2026-09-19; the suite is run locally on demand.
- **A second reader for the threat-model addendum.**
- **Saving a new login from the browser.** The extension fills; it does not offer to create or
  update an item when you type a new password. That is a second value-carrying direction — browser
  to app — and it wants its own approval design.
- **Attachments, `import`, `cargo deny` and the three non-Claude-Code clients**, all carried from
  earlier milestones.

## M7 — Release engineering (macOS)

Shipping to people who are not us. Windows release engineering is unscheduled along with the
Windows app itself (see "Optional / later").

**Update, 2026-09-25:** a Windows release pipeline was nonetheless built as part of the
out-of-roadmap Windows work — `cargo xtask dist-windows` produces a per-user, unelevated WiX MSI
with every PE Authenticode-signed individually
([ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md);
[releasing.md](releasing.md) §10). Unlike the macOS pipeline above, it has not been run with a real
signing certificate (none is available on the machine that built it), so the signed path is
unverified; an unsigned run has been verified end to end (install, launch, uninstall).

**Scope**

- Developer ID signing of the app + bundled sidecar, hardened runtime, notarization, stapling,
  DMG, Homebrew cask (and a formula for the standalone CLI/sidecar).
- Auto-update decision: Sparkle (signed appcast) vs. manual "check GitHub releases," recorded as
  an ADR either way — not left implicit.
- Reproducible-ish builds, SBOM, checksums, signed release artifacts on GitHub.
- Versioning, changelog, upgrade/migration path.

**Acceptance criteria**

- [ ] `spctl -a -vvv` and `stapler validate` pass on a downloaded DMG on a machine that has never
      seen the app; Gatekeeper shows no warning. — **Blocked, not failed.** The pipeline runs all
      the way to `xcrun notarytool submit` and stops there: no notarytool credential profile
      exists on the implementation machine, and creating one takes an Apple ID and an
      app-specific password, which is an account action the owner performs (see
      [releasing.md](releasing.md) §2.3). Everything either side of that submission is built,
      run and verified. With `--skip-notarize` the artifacts report exactly what they should:
      `rejected / source=Unnotarized Developer ID` for the app, `no usable signature` for the
      DMG, and no ticket on either.
- [x] The bundled `kagisecure-mcp` is signed and notarized as part of the app submission — the
      *bundling and signing* half is done and verified ([ADR-0026](decisions/0026-helper-binaries-inside-the-app-bundle.md)):
      all three helpers are in `Contents/Helpers`, each Developer ID signed under the Hardened
      Runtime with a secure timestamp, and `codesign --verify --deep --strict` passes. The
      notarization half is blocked with the line above. It runs when spawned by Claude Code —
      verified against the bundled binary.
- [ ] `brew install --cask kagisecure` and `brew install kagisecure` (CLI) both work on a clean
      Mac. — The cask is drafted at `packaging/homebrew/kagisecure.rb` with the real SHA-256 of
      the built DMG, and it links all three bundled helpers into `PATH`. It cannot be submitted
      until a GitHub release exists for it to point at. A separate CLI *formula* is not written.
- [ ] The auto-update mechanism decision is recorded (ADR or this doc). — **Not done.** Nothing
      was built either way, so nothing was decided; 0.1.0 tells users to `brew upgrade` or watch
      the releases page. [ADR-0028](decisions/0028-the-release-pipeline.md) records it as the
      first thing M8 should settle rather than leaving it implicit.
- [x] `cargo deny` gates the release — `deny.toml`, run locally before a release (the GitHub
      Actions workflows were removed on 2026-09-19). Release artifacts carry a SHA-256, printed by
      `cargo xtask dist` and attached to the release by hand. **An SBOM is not
      generated**; see [ADR-0028](decisions/0028-the-release-pipeline.md).
- [x] A vault created by the previous released version opens in the new one, verified by golden
      vectors, run in CI until CI was removed on 2026-09-19 and locally since. — The golden-vector job has run on every OS since M1; there is no *previous
      released* version yet, so what it proves today is cross-platform and cross-commit
      compatibility, which is the same test.
- [x] The security disclosure contact in [SECURITY.md](../SECURITY.md) is real by this point —
      "to be announced" is acceptable pre-M7, not at release. — GitHub private vulnerability
      reporting and security@kagisecure.com, both read by the maintainers.
- [ ] A published, versioned description of the vault format so a user can decrypt their data
      without our binaries. — [vault-format.md](vault-format.md) is that description and is
      complete; "published" means it is attached to a release, which is the same blocker as the
      first line.

**What M7 added**

- `Kagisecure.app` carries `kagisecure-mcp`, `kagisecure-nmhost` and the `kagisecure` CLI in
  `Contents/Helpers`, each signed on its own with minimal entitlements
  ([ADR-0026](decisions/0026-helper-binaries-inside-the-app-bundle.md)).
- Universal binaries, arm64 + x86_64 ([ADR-0027](decisions/0027-universal-binaries.md), which
  supersedes [ADR-0012](decisions/0012-m3-scope-deviations.md) §1).
- `cargo xtask dist` — the whole release in one command
  ([ADR-0028](decisions/0028-the-release-pipeline.md)), documented step by step in
  [releasing.md](releasing.md).
- `CHANGELOG.md`, a version consistency check wired into CI, a placeholder app icon, `deny.toml`,
  a Homebrew cask draft, and a release workflow (since removed along with all GitHub Actions CI).

---

## M8 — Import (1PUX and the CSV family)

Scheduled 2026-09-13, having spent one pass as optional work (formerly M5). A password manager
nobody can move into is a demo, not a product, so this is a committed milestone rather than a
contributor's spare-time task. Design: [import.md](import.md) and
[ADR-0031](decisions/0031-the-import-crate-and-its-intermediate-representation.md).

**Scope**

- A new crate, `kagisecure-import`: a source-agnostic intermediate representation, one commit
  path, dedupe, the report, and best-effort shredding of the source file. `kagisecure-mcp` and
  `kagisecure-ipc` must not depend on it (ADR-0031 §1).
- Five sources: 1PUX, and CSV from 1Password, Apple Passwords, Chromium and Firefox. Dialects are
  detected by header signature; column meaning is never guessed from content.
- Two entry points: **`kagisecure import`** in the CLI (full flag surface,
  [import.md](import.md) §7) and **File ▸ Import…** in the macOS app (preview sheet, result pane,
  shred prompt — [import.md](import.md) §8), over a new FFI surface that adds no secret crossing.
- Small additive core changes the importer needs: `Field.extra`, `Item.history`, and
  `Vault::add_logical_vault`.
- `.env` import is **out of scope** — see [import.md](import.md) §10. It is a different feature
  (it produces Environments, not items) and it is the one import source whose absence blocks
  nobody.

**Acceptance criteria** (amended from the original M5 list)

- [ ] A real `.1pux` export with at least 200 items across at least 6 categories imports with zero
      dropped *items*, and a report accounting for every field as mapped / preserved / dropped.
- [ ] Re-importing the same file with `--on-duplicate skip` produces zero new items.
- [ ] Re-importing after rotating one password with `--on-duplicate update` changes exactly one
      field and preserves locally-added tags, `agent_visible` flags, and environment bindings;
      `keep-both` suffixes the title instead.
- [ ] **Attachments are counted and reported as dropped**, with their file names, document ids and
      sizes preserved as metadata. They are not imported — there is no attachment storage to import
      them into ([vault-format.md](vault-format.md) §6 is a design, not code), and no screen or
      report says otherwise.
- [ ] **Password history is imported** into the `Secret`-typed `Item.history`: never agent-visible,
      excluded from search, counts only in the report, merged rather than replaced under `update`.
      Only unparsable entries are dropped, and they are counted.
- [ ] Every imported item defaults to `agent_visible = false`.
- [ ] Unknown/unrecognized concealed-looking field types import as `Secret` (fail-closed test over
      `is_concealed`, including a `proptest` property).
- [ ] CSV import refuses a mismatched or ambiguous header, naming the candidate formats and
      `--format`, rather than guessing; a UTF-16 BOM is a clear error, not mojibake.
- [ ] Both entry points work end to end: `kagisecure import --dry-run` writes nothing and exits 0,
      exit code 7 on an unparsable source, and the app's File ▸ Import… reaches a preview sheet
      carrying the `ks.import.*` identifiers ([ui-spec.md](ui-spec.md) §15).
- [ ] Zip bombs, `../` entry names, truncated archives, malformed JSON and over-limit item/field
      counts are rejected within the stated limits without OOM. `proptest` runs as part of `cargo
      test`, needing no nightly toolchain (in CI until CI was removed on 2026-09-19, locally
      since); `cargo-fuzz` targets need nightly and are run by hand from the root `fuzz/` crate
      (`cargo +nightly fuzz run <target>`), and none covers the import parsers yet.
- [ ] **Canary tests.** A unique marker seeded as a password by every parser appears in no byte of
      the Markdown report, the JSON report, any `Debug` of the plan or report, or any error — as a
      Rust test and again as an e2e scenario in suite C that runs `import --dry-run`,
      `import --report` and `item list`, then proves the value landed via `item show --reveal`.
- [ ] `cargo deny check` passes with the new parser dependencies in the graph.

**Not in this milestone:** `.env` import, attachment storage, passkey import, and any Windows
wizard (there is no Windows app to add one to).

**Update, 2026-09-25:** the last clause is no longer accurate — the out-of-roadmap Windows app
(see the platform-decision update above) now has an import wizard: 1PUX and the CSV variants,
detected automatically, a preview of counts and drops, a target-vault picker, commit, and an offer
to shred the source. Not built: a manual format override or per-item import detail (see
`apps/windows/README.md`).

---

## M9 — Agent-requested browser fills

Scheduled and built 2026-09-26, from [ADR-0036](decisions/0036-agent-requested-browser-fill.md)'s
proposed roadmap changes. An agent that has navigated the user's own browser to a sign-in page
calls `request_fill` with an item and the origin it believes it is on; the browser says which tab
is in front and where it really is, a human approves on the Mac with a biometric, and the value is
typed into that page. The tool returns field names, never a value — and an agent that can run
script in the page can read what was typed there, which the sheet says in one sentence
(ADR-0036 §8).

**Scope**

- Phases 1–3 of ADR-0036: username and password on one page; identifier-first sign-ins, one
  approval for two pages; one-time codes, always a separate approval and never via the clipboard;
  the approval-fatigue limits (one sheet at a time, three per agent per ten minutes, sticky
  denials, *Deny and block*, a block after a second origin mismatch); the tripwire.
- macOS with Chromium-family browsers. Off by default, behind a switch in Agent access that needs a
  presence check to turn on.
- **Not in scope:** Safari (ADR-0036 Phase 4, unscheduled until the app-to-extension push is
  measured on that transport) and Windows (excluded, not degraded — every call there is
  `FILL_UNAVAILABLE`).

**Acceptance criteria** (from ADR-0036; checked 2026-09-26 against what has been run — see its
"Implementation status" for the detail)

- [x] No tool result carries a value, asserted by the canary with a successful fill. — The real
      `kagisecure-mcp` binary drives a fill that succeeds, and the marker is in no byte it writes, in
      six encodings (`crates/kagisecure-agent/tests/agent_fill_sidecar.rs`).
- [x] A fill lands only in the visible, active, top-frame document whose browser-established origin
      is covered by the item and equals the agent's claim. — Tested against a scripted service
      worker over the real extension client, every binding refused when changed alone, and on the
      extension's side by its unit tests. **Not yet observed in a real browser:** e2e suite B's four
      agent-fill scenarios are written and have not been run.
- [x] Every agent fill needs a sheet and a biometric. — In Rust the kind is never presence-only and
      no lease is minted or consulted (tested). The app's sheet asks Touch ID every time; its unit
      tests are **compiled, not run**, and no XCUITest drives it.
- [x] Hidden and absent items are indistinguishable. — One code, one message, one path, before any
      browser is asked (tested).
- [x] Sheets per agent are bounded. — Tested by counting the sheets shown on an injectable clock.
      The app's blocks list and notices are built; their unit tests are compiled, not run.
- [x] Every request is audited, and nothing is released that could not be. — Tested, including
      the release transaction failing closed. ADR-0036's implementation decision 37 names the three
      answers that leave no entry, and why.
- [x] Safari parity or a documented reason for its absence. — Documented (ADR-0036 §12): Safari's
      transport opens one connection per message, so the app has nothing to push on. The Browser
      extension screen says Safari does not support agent fills yet.

**Still open:** an agent fill driven end to end with the real app, a real Touch ID and a real
browser — `make e2e SUITE=extension` for the browser half and the manual pass in
[browser-extension.md](browser-extension.md) §7 for the rest; running the app's unit tests
(`make macos-test`); and Phase 4 (Safari).

---

## M10 — Shared vaults (offline, file exchange)

Scheduled 2026-09-27, from [ADR-0035](decisions/0035-shared-vaults.md) and its addendum of the same
day, whose decisions, corrections and encoding contract are what is built against. A shared vault
is its own file of signed, encrypted records; members are people, and every computer has its own
device key; copies are exchanged by the users — a private git repository or sync folder per shared
vault (an exchange directory), or a bundle file — and merged as a set union, with conflicting edits
shown to a person. kagisecure adds no network code, runs no git command and has no sync server.

**Scope**

- The addendum's Phases 0–4, in its corrected order (correction C): prerequisites; crypto and
  records (`kagisecure-shared`); replica, merge, exchange, enrollment and the CLI; verification;
  agents and approvals — agents reach shared items only through the existing MCP tools, and
  ADR-0002 is unchanged.
- macOS. **Added 2026-09-27:** the macOS app's shared-vault UI (Phase 5), in the owner's
  simplified form — no conflict resolution (last writer wins), an informational rotation list, and
  invitations as one file and six words. **Not in scope:** the copied-personal-vault prompt, and
  Phase 6.

**Status by phase**

- **Phase 0 — prerequisites: built 2026-09-27.** Every vault file keeps its own `format_ver`: this
  build reads 1 and 2, refuses 3, writes new vaults as 1, and never writes a version 2 file back
  as 1. The personal vault body holds shared-vault device keys as secret material
  ([vault-format.md](vault-format.md) §2.3); a vault holding one is written as `format_ver` 2 after
  a create-new `<vault>.bak-1` backup (§9 rule 3), and "keep this app's version" keeps device keys
  only the file holds. Golden vector `v2-devices-argon2id-64k.kagivault`. The `kagisecure-shared`
  crate exists with its error type and the dependencies the addendum settled (`hpke` 0.14.1,
  `ed25519-dalek` 3.0.0), a dependency guard keeping it — and its public-key crates — out of the
  MCP, IPC, extension and native-messaging crates and network code out of it, and `deny.toml`
  bans on network crates; `cargo deny check` passes. **Not yet:** anything that creates or uses a
  device key, and anything a person can run — that starts with the Phase 2 CLI.
- **Phase 1 — crypto and records: built 2026-09-27, as a library.** `kagisecure-shared` now holds
  every format and state machine the later phases build on, specified in
  [shared-vault-format.md](shared-vault-format.md) and the ADR-0035 addendum, as simplified on
  2026-09-27 to the **trusted-admin model** (convenience first; admins are trusted, and the
  adversarial roster defences were dropped — the threat model lists them as known limitations):
  - *Keys and primitives:* strictly checked device public keys (canonical, not of small order,
    Ed25519 torsion-free), device key ids and fingerprints (ten groups of five digits and a QR
    payload); device key pairs generated from the core's generator and loaded from the personal
    vault's entry; domain-separated Ed25519 signatures over typed, unambiguously framed content,
    verified strictly; epoch keys wrapped to devices with HPKE (RFC 9180 Base mode, `hpke` pinned
    to 0.14.1, randomness drawn from the core); record keys.
  - *Records:* the signed envelope, read by hand within bounds and verified before its body is
    trusted or its payload decrypted, as a record of the vault being read; the body; item and
    environment payloads under a payload AAD binding vault, author, kind, parents, roster heads
    and epoch, with local-only settings cleared on writing and on reading; CBOR scanned before it
    is decoded and deterministic where it is signed.
  - *Roster and epochs:* the roster computed from signed roster records from a genesis pinned
    by the replica's header or a verified invitation — roster records applied in one order, each
    needing an active admin device at that point, a removed device's records ignored from its
    removal on, a warning with fewer than two admins and a frozen roster with none, read-only for
    operations this build does not understand; epochs minted on creation and on removal, wrapped
    to every current device, older keys granted to devices added later, and each device's key
    ring, writing under the newest epoch it holds.
  - *Exchange:* the bundle file and the exchange directory's export (which never replaces the
    record itself and repairs anything else under its name) and bounded import.
  - *Tests:* RFC 7748, 8032 and 9180 vectors; golden vectors `device-v1.cbor`,
    `record-item-v1.ksr`, `record-roster-genesis-v1.ksr` and `record-epoch-new-v1.ksr`; hex known
    answers for a record key and a wrap; property tests that the roster and key ring are
    independent of record order and repeats; tests of honest behaviour (a removal stops a device,
    the unknown operation, one genesis, epochs after a removal, grants to a new device); the
    `shared_record`, `shared_payloads`, `shared_bundle` and `shared_roster` fuzz targets with a
    stable driver.

  **Not yet:** anything a person can run. No replica, merge, CLI command or app screen uses any of
  it, so none of the acceptance criteria below is met by Phase 1 alone; the threat model marks
  what each mitigation has built ([threat-model.md](threat-model.md), M-22–M-28). The crates it
  adds have no independent audit of the versions in use (threat-model W-6).
- **Phase 2 — replica, merge, exchange, enrollment and the CLI: built 2026-09-27.** The library
  (ADR-0035 addendum, decisions 77–85): the replica, the view, the last-writer-wins merge, writing,
  create, enroll and join, removal, the informational rotation list, import, export, sync and
  rebuild. The CLI, on top of it: `shared create|list|status`, `shared item add|set|rm|show
  [--reveal]` and `shared env create|add-var` (the personal vault's own item and environment
  argument shapes, reused), `shared invite --role reader|writer|admin --out <file>` (the passphrase
  is printed once) and `shared join [--passphrase-stdin]`, `shared remove --device|--member
  [--reason]`, `shared role`, `shared rotation-list`, `shared sync`, `shared import|export
  --bundle|--dir` and `shared rebuild --from-dir|--from-bundle`, `shared set-dir` — a `<vault>`
  reference resolves by id, unique id prefix or exact name, the same convention an item or an
  environment reference already uses. A new exit code, `EXIT_SHARED_REFUSED` (13), for a role or
  key refusal. Phase 0's carried obligation is discharged: `shared create` and `shared join`, the
  two commands that can create this personal vault's first shared-vault device key, print the
  format-upgrade backup's path and the threat-model W-22 caveat when they do, and `kagisecure
  recover` — the only command that changes the master password or reissues the recovery code —
  offers (`--delete-backups` to skip asking) to delete every `<vault>.bak-*` beside the vault
  regardless of which command wrote it. `crates/kagisecure-cli/tests/shared_exchange.rs` drives
  three personal vaults through the binary alone: create, invite, join, write on each, sync
  through a shared folder in different orders to one converged `shared item show`, a removed
  device unable to read a later value, and rebuilding a damaged replica from the exchange folder.
  **Not yet:** `kagisecure_shared` itself changed nothing to support the CLI (no crate edits were
  needed); the macOS app's own shared-vault UI is Phase 5, unscheduled.
- **Phase 3 — verification:** not started.
- **Phase 4 — agents and approvals: built 2026-09-27, not yet tried in the running app.**
  (ADR-0035 §14; addendum, decisions 88–93, under the owner's priorities: no conflicts to refuse,
  since the merge is last-writer-wins.) Shared vaults are served to agents read-only beside the
  personal vault: the host attaches each open shared vault to the personal vault's handle — the
  app's `SharedVaultSession` when it opens one, `kagisecure daemon` at start — and the lock
  detaches them all. The MCP tools (`list_vaults`, now with `shared: true`; `list_items`;
  `list_environments`; `describe_item`; `write_env_file` and `run_with_env` on a shared
  environment; `request_fill` on a shared login) and the browser extension's own fills read the
  personal vault and the attached shared vaults as one catalog (`kagisecure-agent`'s
  `catalog.rs`): agent visibility is this computer's own setting, hidden by default (the app's
  item detail, or `kagisecure env agent-access --shared-vault`); a personal id wins over a shared
  one and two entries with one name are both listed, the shared one as `name (vault)`; writes to a
  shared vault are `INVALID_ARGUMENT`. The approval sheet, the agent-fill sheet and the daemon's
  prompt name the shared vault and every value changed since this computer last approved
  releasing it, which is never released under an earlier lease or presence-only prompt. Releases
  go to the personal vault's audit log with the shared vault's id. Tests: the extended canary, the
  roster test and the lexical guard (below), `crates/kagisecure-agent/tests/shared_vaults.rs`, a
  shared login filled through the real native host (`tests/extension.rs`), and the app's own
  wiring (`crates/kagisecure-ffi/tests/shared_vaults.rs`). **Not yet:** the Windows app's sheet
  does not show the two new facts; nothing has been driven through the running app with a real
  agent.
- **Phase 5 — the macOS app: built 2026-09-27, not yet tried on two Macs.**
  ([ui-spec.md](ui-spec.md) §16.) A Shared section in the sidebar; creating a vault (a name and a
  folder), inviting (a name and a role; a file and six words shown once), joining (the file, the
  words, the folder found beside the file); a members pane (roles, removal, local names, another
  computer, the rotation list, rebuilding a damaged copy); shared items in the existing list,
  detail and edit sheet with the same presence-gated releases; automatic sync on folder changes,
  app activation and each local change; and every shared vault closed when the personal vault
  locks. The FFI surface is `SharedVaultSession` (`crates/kagisecure-ffi/src/shared.rs`), tested
  through two personal vaults and one folder (`crates/kagisecure-ffi/tests/shared_vaults.rs`) and
  through the app's store (`apps/macos/KagisecureTests/SharedVaultStoreTests.swift`). A shared
  vault's own Environments pane (ui-spec.md §16.7) — create, bind a variable to a literal or one
  of the vault's own items, rename, share with agents, delete, with a reader able to view and to
  flip this device's own agent-visibility flag but nothing else — is built on the same
  `EnvironmentEditor` the personal vault uses (`EnvironmentEditing`), tested in
  `crates/kagisecure-ffi/tests/shared_vaults.rs` and
  `apps/macos/KagisecureTests/SharedEnvironmentsTests.swift`. **Not yet:** shared items in Quick
  Access, a notice for the personal vault's format upgrade on the first device key, and names
  that travel between members (roster labels' sealing is undecided).

**Acceptance criteria** (ADR-0035's proposed list, plus Phase 0's own)

- [x] A personal vault holding device keys is written as `format_ver` 2, a version 2 file is never
      written back as version 1, a version 3 file is refused before any key is derived, and the
      first upgrade takes a create-new backup. — `crates/kagisecure-core/tests/format_version.rs`,
      `device_keys.rs`, and the golden vector's two tests in `tests/vault.rs`.
- [x] `cargo deny check` passes with the public-key dependencies in the graph, with no new
      duplicate versions.
- [ ] Two replicas edited offline and exchanged in any order, any number of times, converge to the
      same state, and no value present in either is lost.
- [ ] A removed device's records created after the cut are rejected on every replica.
- [ ] The rotation list for a removed device matches, exactly, the set of current values encrypted
      under an epoch wrapped to it — including values written late under a stale epoch.
- [x] No MCP tool and no IPC message can add a device, change a role, import, export or resolve a
      conflict; asserted by test. — `no_ipc_message_changes_a_shared_roster`
      (`crates/kagisecure-agent/tests/shared_vaults.rs`) and the lexical guard on
      `kagisecure_shared::admin` (`crates/kagisecure-shared/tests/dependency_guard.rs`).
- [x] A value seeded into a shared vault never appears in any byte the sidecar writes (the ADR-0002
      canary, extended). — `a_value_in_a_shared_vault_never_reaches_the_model`.
- [ ] No crate and no part of the app gains a network-capable dependency or a socket other than
      the existing local ones; asserted by a dependency check. — Built for the Rust workspace in
      Phase 0 (`deny.toml` bans, and `crates/kagisecure-shared/tests/dependency_guard.rs`); left
      open until the phases that add code are done, and the macOS app is not covered by either.

---

## M11 — Unattended jobs (machine vault, standing grants, run-browser sign-ins)

Scheduled 2026-09-27, from [ADR-0042](decisions/0042-unattended-agent-access.md) (accepted for macOS; headless hosts are
[ADR-0043](decisions/0043-unattended-access-on-headless-hosts.md)'s, proposed). A separate machine
vault that a person arms, released only to jobs kagisecure starts on a schedule, under standing
grants: commands run with pinned variables, and sign-ins of dedicated service accounts typed at one
exact origin in a browser kagisecure launches for the run. The personal vault, shared vaults and
the user's own browsers are never unattended. Arming persists across restarts and has no expiry
(the owner's choice; ADR-0042 implementation decision 1, threat-model W-24).

**Phases** (ADR-0042, "Implementation plan"):

- **Phase 0 — documentation.** Built: [unattended-credentials.md](unattended-credentials.md).
- **Phase 1 — core.** Built: the machine vault file with no slot of its own
  (`Vault::create_machine`, `Vault::open_machine`), its key in the personal vault's body and the
  bytes the app will keep in the Keychain (`MachineVaultKey`), the structural rules enforced on
  every write, job and grant records of both kinds, `format_ver` 3 and its golden vectors
  (`crates/kagisecure-core/src/vault/machine.rs`, `tests/machine_vault.rs`).
- **Phase 2 — the engine in `kagisecure-agent`: command grants.** Built: arming from the
  Keychain's bytes with no expiry, the scheduler, runs in process groups of their own, ancestry
  binding, the unattended socket, the release path, suspension, both logs, `NOT_GRANTED` and
  `UNATTENDED_PAUSED`, the ordinary socket's reads of machine-vault environments, and the
  `kagisecure-ffi` calls for the app (`crates/kagisecure-agent/src/unattended/`,
  `tests/unattended.rs`).
- **Phase 3 — the app.** Built: the Keychain and re-arming at launch, the arm sheet, one-sheet
  jobs with their grants, environments copied from the personal vault (Update re-approves),
  Agent access → Unattended jobs with Run Now, Revoke, Re-enable and Pause, the menu-bar state and
  badge, "While you were away", notifications, and the Audit view's machine log with an Unattended
  filter (`apps/macos/Kagisecure/Services/UnattendedService.swift`, `Views/UnattendedView.swift`,
  `Views/NewJobSheet.swift`). Not yet exercised on a Mac by a person.
- **Phase 4 — shared-vault copies.** Built: copies of shared environments (never a login's field)
  with their provenance, the vault's policy (an admin's checkbox, allowed by default), copy records
  every member reads, removed holders flagged, and copies marked when their source changes
  instead of suspended (`crates/kagisecure-shared/src/unattended.rs`,
  `crates/kagisecure-ffi/src/unattended_manage.rs`). The app also opens at login after the first
  arm.
- **Phase 5 — unattended sign-ins.** Built: the measurement (Edge and Chromium load the extension
  headless and read the profile's manifest; Chrome and Brave do not — ADR-0042, "Phase 5: the
  measurement"; a locked screen is still to measure with the owner present), a headless run
  browser per run with a fresh profile and the job given its control endpoint, an extension
  endpoint per run gated to that browser's descendants, login grants and the second `Approved`
  constructor through ADR-0036's broker, strikes and the tripwire, logins copied from the personal
  vault, and the sheet with the one-time-code switch (`crates/kagisecure-agent/src/unattended/`
  `browser.rs` and `login.rs`, `crates/kagisecure-ffi/src/unattended_logins.rs`,
  `e2e/suites/extension/unattended.test.mjs`). Left-site and challenge detection are not built
  (implementation decision 45), nor the ordinary extension listener's interactive fill of a
  machine-vault login.

**Acceptance criteria** (ADR-0042's Phase 2 and 3 test lists, plus):

- [x] Each structural rule of the machine vault is refused in `kagisecure-core`, and a personal
      vault holding a machine key round-trips (Phase 1).
- [ ] No release from the personal vault or a shared replica is possible without a presence proof,
      armed or not; asserted by test.
- [x] A request from any process not descended from a run kagisecure started is refused, whatever
      grants exist.
- [x] No MCP tool and no IPC message creates, widens, extends, re-enables or proposes a grant or a
      job; asserted by test.
- [ ] A restart leaves the machine vault armed, and it releases only to runs kagisecure starts;
      pausing disarms and deletes the Keychain item. *(Changed from "a restart leaves it disarmed"
      by the owner's decision of 2026-09-27.)*
- [x] A value seeded into the machine vault never appears in any byte the sidecar writes, across a
      successful unattended release (the ADR-0002 canary, extended).
- [ ] An unattended fill lands only in the run's own browser, at the login grant's exact origin;
      a session from any other browser is refused before it can ask anything *(both done: e2e
      suite B, headless)*; the ordinary extension listener fills a machine-vault login only with a
      sheet and a presence proof *(not built)*.
- [ ] A one-time code is never filled unattended unless the login grant's switch is on, and never
      onto the clipboard.
- [x] A value seeded as a machine-vault password never appears in any byte the sidecar writes,
      across a successful unattended fill (e2e suite B, `unattended.test.mjs`).

---

## M12 — Agent test logins (kagisecure generates the password; sign-up fills)

Proposed and accepted 2026-10-07, from [ADR-0048](decisions/0048-agent-test-logins.md); **built on
macOS** the same day (Phases 1a, 1b and 3). The person's guide is
[agent-test-logins.md](agent-test-logins.md); the tools are in [mcp-server.md](mcp-server.md)
§2.10–§2.13. An agent asks kagisecure to create a login for a test account on a local or
allowed origin — app, purpose, username and websites, never a value — and kagisecure generates the
password inside the vault transaction, seals it, and keeps it in a dedicated personal vault that
the person's own browser extension and system AutoFill never offer. Once a Settings switch is on
(one Touch ID), creates, sign-up fills (`new_password`) and login fills at those origins need no
sheet; any other origin gets an ADR-0046-style sheet with the registrable domain shown large and
Touch ID every time. No tool returns the password; the ADR says plainly that an agent driving the
page or choosing the command can still read what kagisecure types there, and accepts that for test
values. macOS only, interactive agents only; nothing on the unattended socket.

**Phases** (ADR-0048, "Implementation plan"):

- **Phase 1a — create and reuse.** The switch and the vault, `create_test_login` and
  `list_test_logins`, the seal, the no-sheet login fill, the grace rule for runs bound only to
  test logins, protocol 4, and a purpose-built local test web app in `e2e/`.
- **Phase 1b — the sign-up fill.** `new_password` in `request_fill`, the extension's strict
  sign-up detector, delivery into every new-password box.
- **Phase 3 — cleanup and the non-browser recipe.** `trash_test_logins`, its CLI, and the
  documented recipe for XCUITest, Playwright and API seeding through `run_with_env`.

Status of each, as built:

- [x] Phase 1a: the switch, the vault, the seal, `create_test_login` / `list_test_logins`, the
      no-sheet login fill, the grace rule for runs, protocol 4, the test app; Swift sheet, Settings
      section and notices (unit tests only). `tests/test_login_create.rs`,
      `tests/test_login_sidecar.rs`, `crates/kagisecure-core/tests/test_login_seal.rs`.
- [x] Phase 1b: `new_password`, the sign-up detector, delivery into every new-password box.
      `tests/agent_fill_sign_up.rs`, `extensions/chrome/test/*`, and a headless e2e scenario.
- [x] Phase 3: `trash_test_logins` (`tests/test_login_trash.rs`), `kagisecure test-logins list |
      trash` (`crates/kagisecure-cli/tests/test_logins.rs`), `create_test_login`'s `bind`
      (`tests/test_login_bind.rs`), the recipe, and a headless e2e "environment rebuilt" scenario.
- [ ] Driven by hand in the real app with a real agent: not yet. The four older agent-fill e2e
      scenarios (ADR-0036) still have not run in a windowed browser.

Out of scope here, each behind its own prerequisite: real-service and employees' SaaS accounts
(ADR-0046's path), the itsustar AI room (needs a per-client policy and a browser in the room),
headless hosts ([ADR-0043](decisions/0043-unattended-access-on-headless-hosts.md), proposed),
native-app fills through the credential provider, passkeys.

---

## Optional / later

Not on the numbered roadmap. Kept here, with their original scope and acceptance criteria where
already written, so they are picked up deliberately rather than by drift, and so a contributor
who wants a self-contained task not on the critical path has somewhere to look.

### `.env` import (optional / later)

Split out of the import work when import was scheduled as M8. Design and the full parsing table
are in [import.md](import.md) §10, which is kept intact for whoever picks it up.

- [ ] `.env` import handles the full parsing table in [import.md](import.md) §10, including
      multi-line quoted values and non-interpolation of `$VAR`.
- [ ] `import env-scan` shows a dry-run plan before writing anything.

### Windows app (optional / later, formerly M4)

Deferred indefinitely pending macOS completion — no Windows milestone is scheduled until M3–M7
ship. `kagisecure-core` and the vault format stay platform-agnostic and sync-ready in the
meantime (per [architecture.md](architecture.md) and [vault-format.md](vault-format.md) §9), so
this work is not blocked when it eventually starts; it is simply not being built now.

**Update, 2026-09-25:** despite the above, Windows work was started at the user's request without
formally rescheduling this entry — see the dated update on the platform decision near the top of
this document, and [windows-port.md](windows-port.md) for the itemized, dated record. The
acceptance criteria below are updated in place to reflect what is now verified, per that record,
rather than left to imply nothing happened.

> Parity wording note: the original M4 acceptance criteria below said "feature parity checklist
> against M3 is complete," where M3 at the time meant the *entire* macOS app including MCP
> integration. Under the current numbering, macOS's MCP integration is M4 and its
> password-generator/TOTP support is M5, so a resumed Windows effort should target parity against
> the completed macOS app (M3 **through** M5 at minimum, M6 if the extension has also shipped by
> then), not against "M3" alone.

**Scope:** C# interop layer (`uniffi-bindgen-cs` if it supports the pinned UniFFI version, else
`csbindgen` plus hand-written P/Invoke — decision per
[ADR-0003](decisions/0003-uniffi-vs-csbindgen.md)); WinUI 3 app; `KeyCredentialManager` +
`UserConsentVerifier` wrapped key slot, TPM-backed, with the additional app-specific DPAPI
binding from [ADR-0004](decisions/0004-biometric-key-wrapping.md); named-pipe IPC listener with a
user-SID DACL; Authenticode signing, MSIX packaging, winget manifest.

> **Update, 2026-09-25:** "MSIX packaging" above did not happen as scoped —
> [ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md) picked a per-user WiX
> MSI instead, precisely because MSIX's registry/file virtualization would break the
> `browser_setup.rs` writes this scope also lists. Authenticode signing was built
> ([ADR-0032](decisions/0032-authenticode-peer-verification.md)). A winget manifest is generated
> (`cargo xtask winget-manifest`, validated with `winget validate`) but not yet submitted — see the
> winget item below.

**Acceptance criteria** (updated to not assume a stale parity baseline; checked items and notes
added 2026-09-25 against the record in [windows-port.md](windows-port.md)):

- [x] The C# binding decision is recorded in ADR-0003 with the evidence (which UniFFI version
      `uniffi-bindgen-cs` supported on the evaluation date). — Run 2026-09-25: fails C1 (targets
      UniFFI 0.31, we pin 0.32) and C5; the fallback was taken.
- [ ] Feature parity checklist against the completed macOS app (M3–M5, and M6 if shipped) is
      complete, with any gaps listed in the release notes. — Not written as a formal checklist.
      Informally: item CRUD, live TOTP, import, agent access, Windows Hello and Settings/Audit
      exist; QR-code TOTP setup, attachments, section add/rename UI and a manual import-format
      override do not (`apps/windows/README.md`).
- [ ] Windows Hello approval gates every injection; a TPM-less machine falls back to password with
      a clear, non-silent warning. — The gate and the fallback are both built and exercised end to
      end on this machine, which has no Hello device, so only the fallback path has been driven for
      real; a real Windows Hello prompt has been exercised only against fakes (see
      `b0bd595`'s commit message and `apps/windows/README.md`).
- [ ] The app-specific binding is verified: a test tool that obtains Hello consent as the same user
      but is not kagisecure cannot unwrap the vault key. — Not tested this way. `WindowsHelloServiceTests`
      cover the DPAPI round trip and fallback against fakes, not an independent consent-only tool.
- [ ] Named pipe is not accessible from a second local user account (test with two accounts). —
      Still open; needs a second account. The DACL's shape (owner-only, one allow entry) is
      asserted by tests; the refusal itself is correct-by-construction, not observed
      (windows-port.md §2 Tier 1).
- [ ] Vault files are byte-identical across platforms: a vault created on macOS opens on Windows
      and vice versa, verified by the shared golden vectors. — Not specifically re-verified as part
      of this Windows work.
- [ ] `winget install kagisecure` works on a clean Windows VM. — Not attempted end to end.
      **Update, 2026-09-25:** a winget manifest now exists — `cargo xtask winget-manifest`
      generates it from a built `dist-windows` MSI (`docs/releasing.md` §10.8,
      [ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md)'s addendum) — but it
      is only generated, not submitted to `microsoft/winget-pkgs`; nothing has installed
      `kagisecure` via `winget` on any machine yet.

### iOS

Later; not scoped, not on the roadmap yet. Listed only so it is not mistaken for an oversight.

### Sync

The format is a single file, so any file sync the user already runs works today. A first-party,
conflict-aware sync service is a different, larger project than v1 and is not planned.
Shared vaults ([ADR-0035](decisions/0035-shared-vaults.md), accepted; M10) make an existing file
sync safe for several writers by merging exchanged copies instead of replacing the file; they do
not add a sync service.

---

## Post-v1, unscheduled

Recorded so they are not mistaken for oversights:

- Linux GUI (GTK4 or a native-ish alternative); the CLI and sidecar already work on Linux from M2.
- ~~Team/shared vaults~~ Scheduled as M10 — see
  [ADR-0035](decisions/0035-shared-vaults.md) and the M10 section above.
- ~~Unattended use of machine credentials by scheduled jobs on this Mac~~ Scheduled as M11 — see
  [ADR-0042](decisions/0042-unattended-agent-access.md) and the M11 section above.
- SSH agent integration (`SSH_AUTH_SOCK`-style injection for imported SSH Key items).
- TOTP code injection with per-use approval (distinct from M5's TOTP *generation and display*,
  which is in scope — see M5's last acceptance criterion) — **the environment case only**: a code
  injected into a process or a file, the `run_with_env`-style tool M5's last criterion deferred.
  The *browser* case, an agent asking for a code to be filled into a page, is M9
  ([ADR-0036](decisions/0036-agent-requested-browser-fill.md) §7.4).
- Recovery-code UX hardening beyond v1's one-time print (e.g. re-issuing a new code after use,
  a "verify you saved it" re-entry step, physical-storage guidance).
- Watchtower-style breach/reuse checking. Explicitly out of scope for the foreseeable future per
  the owner's feature-set decision (see [ui-spec.md](ui-spec.md) §14), not merely unscheduled.

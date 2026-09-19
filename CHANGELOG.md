# Changelog

All notable changes to kagisecure are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions before 1.0.0 may change the vault format. When they do, the change is listed here with
what it means for a vault written by an earlier build — see
[docs/vault-format.md](docs/vault-format.md) §9 for the compatibility rules the format follows.

## 0.1.0 — 2026-09-19

The first release: a macOS app, a CLI, an MCP sidecar and a browser extension, signed with a
Developer ID certificate and distributed as a notarized DMG.

### Added

- **Import.** kagisecure can be moved into. A new crate, `kagisecure-import`, reads five
  sources — 1PUX (the 1Password 8 export) and CSV exports from 1Password, Apple Passwords,
  Chromium and Firefox — into one source-agnostic representation, so dedupe, the report and the
  safety rules behave identically whichever one you used
  ([ADR-0031](docs/decisions/0031-the-import-crate-and-its-intermediate-representation.md),
  [docs/import.md](docs/import.md)).
- **`kagisecure import <PATH>`**, with `--format`, `--vault`, `--dry-run`,
  `--on-duplicate skip|update|keep-both`, `--include-trashed`, `--report`, `--json`, `--yes` and
  `--shred-source`. `--dry-run` prints exactly the report a real run prints and writes nothing;
  exit code 7 means the source could not be read or parsed.
- **File ▸ Import… in the macOS app** (⇧⌘I): an open panel, a preview sheet showing the detected
  format, per-category counts, duplicates with a policy picker and what will not be imported, then
  a result pane and an offer to delete the source file.
- **Password history is imported**, into a new `Secret`-typed `Item.history`: never agent-visible,
  excluded from search, and shown in reports as a count only. Under `--on-duplicate update` it is
  merged rather than replaced.
- **The import report carries no values, structurally.** `Secret` has no `Serialize` and every
  report type has one, so a value in a report would not compile; a canary test covers the `Debug`
  and error paths as well. Every imported item arrives with `agent_visible = false`.

- **Vault.** Argon2id-derived key-encryption key, a random vault key, ChaCha20-Poly1305 over the
  body with the header as additional authenticated data, and a one-time printable recovery code
  that unlocks the vault independently of the master password.
- **Items.** Logins, passwords, secure notes, API credentials, documents and more, with typed
  fields, tags, favorites, archive and a trash with a `trashed_at` timestamp.
- **`kagisecure` CLI.** `init`, `unlock`, `lock`, `add`, `ls`, `show --names-only`,
  `env write`, `run -- <command>`, `audit`, `recover`, `generate`, `totp`, `daemon` and
  `mcp path` / `mcp install`.
- **MCP sidecar (`kagisecure-mcp`).** Nine tools over stdio. **No tool returns a secret value**,
  and the crate is built so that it cannot: it depends on the core crate with the
  `secret-material` feature off, so it cannot name the `Secret` type at all, and the build fails
  if that ever stops being true (checked in CI until CI was removed on 2026-09-19, locally since).
- **macOS app.** A native SwiftUI three-pane app: sidebar, item list, item detail; lock screen;
  agent approvals gated by Touch ID through `LAContext`; live leases with per-row revoke; a
  filterable audit log; a password generator; TOTP fields with a countdown ring; and Quick Access
  on `⇧⌘Space`.
- **Browser autofill.** A Manifest V3 extension for Chrome, Edge, Arc, Brave and Chromium over a
  native messaging host, and the same extension shipped as a Safari Web Extension inside the app
  bundle. Per-origin fill approvals and leases, with the origin rule computed against the Public
  Suffix List.
- **Bundled helpers.** `Kagisecure.app` now carries `kagisecure-mcp`, `kagisecure-nmhost` and the
  `kagisecure` CLI in `Contents/MacOS`, each signed under the Hardened Runtime and notarized in
  the same submission as the app. The app's setup screens and `kagisecure mcp path` resolve the
  bundled copy first, so a normal install needs nothing on `PATH`
  ([ADR-0026](docs/decisions/0026-helper-binaries-inside-the-app-bundle.md)).
- **Universal binaries.** Everything ships as `arm64` + `x86_64`, so the app runs on Intel Macs
  ([ADR-0027](docs/decisions/0027-universal-binaries.md)). This supersedes the aarch64-only
  deferral in [ADR-0012](docs/decisions/0012-m3-scope-deviations.md) §1.
- **Release pipeline.** `cargo xtask dist` builds, signs, notarizes, staples, packages and
  verifies in one command ([ADR-0028](docs/decisions/0028-the-release-pipeline.md)), and
  [docs/releasing.md](docs/releasing.md) documents every step.
- **App icon.** A shield with a keyhole, the same mark as kagisecure.com; the source is
  `apps/macos/Artwork/icon.svg`.
- **Release builds carry no build-machine paths.** `cargo xtask dist` passes
  `--remap-path-prefix`, so panic locations name `~/.cargo/...` and `./crates/...` instead of the
  absolute paths of whoever built the release.
- **Dependency policy.** `cargo deny check` gates licenses and advisories, run locally and before a
  release (ran in CI until CI was removed on 2026-09-19).

### Known limitations

- **Touch ID unlock of the vault is not available in this build.** Filing a Secure Enclave key
  requires the `keychain-access-groups` entitlement, which AMFI validates against a provisioning
  profile at every exec; a Developer ID signature does not satisfy it. The app says so and falls
  back to the master password. Touch ID *for approving an agent request* uses `LAContext`, needs
  no entitlement, and does work. See
  [ADR-0011](docs/decisions/0011-secure-enclave-under-ad-hoc-signing.md).
- **Permissions reset when the signature changes.** macOS ties Accessibility and Screen Recording
  grants to the code signature, so anyone who ran a locally built copy of kagisecure must grant
  them again to the signed release. No update mechanism can avoid this.
- **Attachments and QR-code scanning for TOTP setup are not implemented.** See
  the "Optional / later" section of [docs/roadmap.md](docs/roadmap.md).
- **Auto-update is not implemented.** Check
  [the releases page](https://github.com/itsucara/kagisecure/releases) or `brew upgrade`.
- **Attachments and passkeys are not imported.** kagisecure has no attachment storage yet, so
  1Password documents are dropped — counted, reported per item, and named in the summary line,
  with their file names and sizes preserved as metadata for a future pass.
- **`.env` import is not part of this work** and remains unscheduled
  ([docs/import.md](docs/import.md) §10).
- **`--shred-source` is best effort, not a secure erase.** Copy-on-write filesystems, SSD
  wear-levelling, Spotlight and local snapshots can all leave the bytes reachable
  ([docs/threat-model.md](docs/threat-model.md) W-9).
- The 1PUX `categoryUuid` table is confirmed only for `Login`; unknown codes fall through to
  `Other(<uuid>)` with the raw code preserved, rather than being guessed at.

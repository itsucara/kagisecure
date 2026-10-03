# Changelog

All notable changes to kagisecure are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions before 1.0.0 may change the vault format. When they do, the change is listed here with
what it means for a vault written by an earlier build — see
[docs/vault-format.md](docs/vault-format.md) §9 for the compatibility rules the format follows.

## Unreleased

## 0.1.3 — 2026-10-04

What changed for you:

- **One Touch ID, then no more prompts until you lock.** After you unlock or confirm with Touch ID,
  a grace window covers the whole app: fills, revealing and copying passwords inside the app do not
  ask again. It slides with use and by default lasts until Kagisecure locks; change it in
  **Settings**.
- **AI agents fill without interrupting you.** During the grace window an agent's fill request
  goes through without a sheet or Touch ID, the approval-fatigue limits are gone, fills reach
  background tabs, and agent fill is on by default.
- **AutoFill everywhere on your Mac.** Kagisecure is now a system-wide AutoFill password provider
  (ADR-0045), so native apps and Safari can fill from your vault. Turn it on in **System Settings ▸
  General ▸ AutoFill & Passwords**.
- **Touch ID unlock is on by default**, and the app offers to turn it on if it is off. After you
  lock manually, Touch ID no longer pops up on its own.
- **Redesigned Settings**, laid out like System Settings, with in-app choices for appearance and
  language.
- **The browser extension speaks Japanese** as well as English.
- **Quick Access**: the arrow keys move the highlight.
- After unlocking, the app offers to connect browsers that are not connected yet.
- **Items are visible to agents by default.** New and imported items now start visible to agents,
  with all their fields, so an agent can find a login without you turning it on first. Agents
  still see only titles, categories, tags and field names — never a value, and every value still
  needs your approval. Turn this off in **Settings ▸ Vault ▸ Show new items to agents**. Items you
  already have are not changed; use **Show All Items to Agents…** there to show them all at once.
- **Show or hide many items at once.** Select several items in the list (⌘-click, ⇧-click, ⌘A)
  and choose **Show to Agents** or **Hide from Agents**, from the right-click menu or the **Item**
  menu. Right-click a tag or category in the sidebar to show or hide everything in it — for
  example the `imported:chromium` tag after an import.
- CLI: `kagisecure item agent-visible <on|off> --tag|--category|--item|--all` and
  `kagisecure vault new-items-agent-visible <on|off>`.
- Vault format: logical vaults gain `new_items_agent_visible` (default on, including for vaults
  written by earlier builds). An earlier build keeps the key and writes it back.

The detailed list follows.

## 0.1.2 — 2026-10-03

What changed for you:

- **The Kagisecure extension is coming to the Chrome Web Store.** This version accepts the store's
  copy of the extension as well as one loaded unpacked. After updating, open **Browser extension**
  and press **Set up** next to your browser once, so the browser is told about the store copy.
- **Shared vaults**: share a vault with your team through a folder you choose (iCloud Drive or
  Dropbox), with an invitation file and a six-word passphrase.
- **Unattended jobs**: let scheduled scripts use the credentials you granted them while you are
  away, after one Touch ID to arm them.
- **Fewer prompts**: after you confirm with Touch ID, fills, agent requests and reveals do not ask
  again for a few minutes.
- **Updates itself**: the app checks kagisecure.com for new versions (you can turn this off in
  Settings).
- Many fixes: fills now reach the browser after you approve them, the extension reconnects on its
  own after a lock, field focus and save fixes, and the password field no longer stretches.

The detailed list follows.


### Added

- **Chrome Web Store packaging for the browser extension.** `cargo xtask chrome-package` (or
  `make chrome-package`) writes `dist/kagisecure-chrome-<version>.zip` from `extensions/shared`:
  the manifest's `key` removed (the store refuses a new item that has one), its `version` set from
  the workspace, no dotfiles or tests, deterministic bytes, and every file the manifest and its
  pages load checked to be present. The extension has icons now (`extensions/shared/icons/`,
  rendered from the brand mark by `extensions/make-icons.sh`), in both the Chromium and Safari
  manifests; `cargo xtask embed` copies the `icons/` subdirectory into the app bundle's
  `ChromiumExtension`, and the Safari target copies it as a folder. Both manifests now carry the
  workspace version (0.1.1), and `cargo xtask version` plus an xtask unit test fail when they
  drift. [docs/chrome-web-store.md](docs/chrome-web-store.md) has the listing text, the privacy
  answers, the assets and the upload steps. [ADR-0021](docs/decisions/0021-pinned-extension-id.md)
  is amended: a store install gets an id the store assigns, which is added to
  `PINNED_EXTENSION_IDS` after the first upload.
- **The macOS app updates itself** with Sparkle 2 ([ADR-0044](docs/decisions/0044-self-update-with-sparkle.md)),
  the same way itsustar does: a signed feed at `kagisecure.com/mac/appcast.xml`, an update found at
  launch installs and relaunches at once, one found later installs on quit. Settings ▸ Updates and
  “Check for Updates…” in the app menu. `cargo xtask dist` now also writes the signed feed to
  `dist/mac-updates/`.
- **Japanese localization of the macOS app.** UI strings now live in a String Catalog
  (`apps/macos/Kagisecure/Localizable.xcstrings`, plus `InfoPlist.xcstrings` for the Touch ID
  prompt) with English as the source language and Japanese as the first translation; the app
  follows the system language. Interpolated and computed strings (errors, notices, counts) are
  localized too; values from the Rust core and audit/protocol identifiers stay in English.
- **Agents read shared vaults** ([ADR-0035](docs/decisions/0035-shared-vaults.md) Phase 4). An
  MCP agent lists, describes and — with the same approval sheet, lease and presence rules — uses
  the items and environments of the shared vaults this computer has open, exactly as it uses the
  personal vault's: `list_vaults` lists a shared vault with `shared: true`, `write_env_file` and
  `run_with_env` release a shared environment, and `request_fill` fills a shared login. The browser
  extension fills shared logins too. What agents see of a shared vault is this computer's own
  setting — the item detail's Agent access panel, now shown for shared items, or `kagisecure env
  agent-access --shared-vault <vault>` — hidden by default and never sent to other members. The
  approval sheet (and the agent-fill sheet, and `kagisecure daemon`'s prompt) names the shared
  vault and every value that changed since this computer last approved releasing it, with who
  changed it and when; such a value always gets the full sheet, lease or not. Agents cannot write
  to a shared vault (`INVALID_ARGUMENT`) or change who it is shared with. Releases are recorded in
  the personal vault's audit log with the shared vault's id. A personal item or environment wins
  an id shared with a shared one; two with the same name are both listed, the shared one as
  `name (vault)`. `kagisecure daemon` serves every shared vault its device keys open. Behind it:
  `kagisecure-agent` gains `catalog` and `shared` (`SharedSource`, `ReplicaSource`,
  `VaultHandle::attach_shared`), `kagisecure-shared` gains `read` and `admin::visibility`,
  `kagisecure-core` gains `model::env::resolve_injections` and `VaultSummary::shared`, and the
  FFI's `ApprovalRequestView` gains `shared_source` and `changed_since_approval`.

- **Shared vaults in the macOS app** ([ADR-0035](docs/decisions/0035-shared-vaults.md) Phase 5,
  [ui-spec.md](docs/ui-spec.md) §16). The sidebar has a **Shared** section: **New Shared Vault…**
  asks for a name and a folder the members share (iCloud Drive, Dropbox); **Invite…** asks for a
  name and a role, saves an invitation file and shows six words once, with a Copy button;
  **Join Shared Vault…** takes the file and the words, and finds the folder beside the invitation.
  A shared vault's items use the same list, detail pane, edit sheet and presence-gated reveal and
  copy as personal items; a save always wins (last writer wins, no conflict alert), and deleting a
  shared item deletes it for everyone. Its **Members** pane changes roles, removes members, names
  them on this Mac, invites another computer of a member, shows what removed members could have
  seen, and rebuilds a damaged copy from the folder. Syncing is automatic — on any change in the
  folder, when the app becomes active and after each change made here — and costs nothing when
  nothing changed. Locking the personal vault closes every shared vault. Behind it,
  `kagisecure-ffi` gains `SharedVaultSession` and `VaultSession::open_shared_vaults`,
  `create_shared_vault` and `join_shared_vault`; `kagisecure-shared`'s replica local state gains
  `member_names`. Not yet tried by a person on two Macs; shared items are not in Quick Access.

- **Shared-vault environments in the macOS app** ([ADR-0035](docs/decisions/0035-shared-vaults.md),
  [ui-spec.md](docs/ui-spec.md) §16.7). A shared vault's sidebar row gains an **Environments** row
  beside **Members**: create, rename, share with agents (this device's own setting, hidden by
  default, never sent to other members), add a variable as a literal value or bound to a field of
  one of that same shared vault's own items, remove a variable, and delete — all a writer or an
  admin's actions; a reader sees every environment and its variables but cannot change them, and
  may still flip this device's own agent-visibility flag, which is never a shared write. Built on
  the same `EnvironmentEditor` the personal vault's Agent access pane uses, driven by a new
  `EnvironmentEditing` so the two need not diverge; the personal vault's editor is unchanged.
  `kagisecure-ffi`'s `SharedVaultSession` gains `environments`, `environment`,
  `create_environment`, `rename_environment`, `set_environment_agent_visible`,
  `set_variable_value`, `bind_variable`, `remove_variable` and `delete_environment`, mirroring
  `VaultSession`'s personal-vault calls (renaming is new to both). Tested in
  `crates/kagisecure-ffi/tests/shared_vaults.rs` and
  `apps/macos/KagisecureTests/SharedEnvironmentsTests.swift`.

- **The machine vault, in the core** ([ADR-0042](docs/decisions/0042-unattended-agent-access.md),
  roadmap M11, Phases 0 and 1). `kagisecure-core` can create and open a separate machine vault for
  credentials that unattended jobs use: a vault file with no unlock slot of its own, whose key is
  held in the personal vault's body and can be exported for the macOS Keychain; its structural
  rules (websites only as exact https origins on Login items, no variable bound to a
  one-time-password seed, no references out of the file) are enforced on every write; and its job
  and standing-grant records live in its body. Nothing a person runs creates one yet. New page:
  [docs/unattended-credentials.md](docs/unattended-credentials.md). **Vault format:** a personal
  vault holding a machine vault key, and every machine vault, is written as `format_ver` 3; this
  build reads versions 1 to 3, and older builds refuse such a file. The first write that raises a
  file copies it to `<vault>.bak-<old version>` first; nothing is migrated.
- **The unattended engine** (ADR-0042 Phase 2, in `kagisecure-agent`). Arming from the Keychain's
  bytes, persisting across restarts with no expiry; a scheduler that starts jobs at their local
  times; runs in process groups of their own; a second, unattended socket that serves only
  processes descended from a run kagisecure started, and releases a machine-vault environment to a
  command only under a standing command grant of that run's job, audited before release, never
  returning output; one-strike suspension; both logs. Two new error codes, `NOT_GRANTED` and
  `UNATTENDED_PAUSED`, returned only there. The ordinary socket lists and serves machine-vault
  environments with the ordinary sheet. `kagisecure-ffi` gains the calls the app will use
  (`unattended_*`, `agent_attach_machine_vault`).
- **Unattended jobs in the macOS app** (ADR-0042 Phase 3). Agent access → Unattended jobs: copy a
  personal environment into the machine vault, define a job — program, folder, schedule and
  environment — with its grant in one sheet, arm, pause, run now, revoke and re-enable. Arming
  keeps the machine vault's key in the login Keychain (this device only, never synced), so jobs
  keep running after a restart until paused. The menu bar shows the armed state and a badge;
  "While you were away" summarizes the machine log after an unlock; suspensions and pauses are
  local notifications; the Audit view shows the machine vault's log with an Unattended filter.
- **Unattended copies from shared vaults** (ADR-0042 Phase 4). A shared vault's environment can be
  copied into the machine vault — never one bound to a login's field — and every member reads that
  this device holds it; an admin can turn copies off for the vault. Two new shared-vault record
  kinds, `policy` and `unattended_copy`, which older builds keep and forward unread. A copy whose
  source changed, shared or personal, is marked for Update. Arming the first time makes the app a
  login item, with a checkbox to turn it off.
- **Unattended sign-ins** (ADR-0042 Phase 5, macOS). A job may sign in to one website with a
  service account's login copied into the machine vault ("Add a Login…"), under a login grant
  made on the New Job sheet: one exact https origin, the run's own browser (Microsoft Edge by
  default, else Chromium), and a one-time-code switch that is off by default. For each run the
  engine starts that browser headless (`--headless=new`) in a fresh profile with the extension and
  its native messaging manifest, hands the job its control endpoint as
  `KAGISECURE_RUN_BROWSER_CDP`, serves it on an extension endpoint of that run alone that refuses
  any other browser, and deletes the profile when the run ends. `request_fill` on the unattended
  socket now fills through ADR-0036's broker with a standing pass in place of the sheet
  (`UNATTENDED_FILL_APPROVED (grant … run …)`); a fill no grant covers, or a tab at a site the
  login is not saved for, suspends the job. The app bundle carries the Chromium extension in
  `Contents/Resources/ChromiumExtension`. New e2e scenario, headless:
  `e2e/suites/extension/unattended.test.mjs`.
- **Agent-requested browser fills** ([ADR-0036](docs/decisions/0036-agent-requested-browser-fill.md),
  roadmap M9). A new MCP tool, `request_fill`, lets an agent that is driving the user's own browser
  ask for a saved login to be filled into the tab in front. The agent names an item and the origin
  it believes it is on; the extension reports which tab is actually in front — the active tab of
  the last-focused window, top frame, visible — and its browser-stamped origin, which must equal
  the agent's claim and be a site saved for the item, or no sheet is raised at all. The app then
  shows a sheet of its own, leading with the site, and asks for **Touch ID on every fill** (outside
  the presence grace window, under Changed); there is no lease and no "for this session". The value
  is typed into the page by the extension exactly as
  for a human fill, and the tool returns field names, never a value — but an agent that can run
  script in that page can read it there, which the sheet, the tool's description and the server
  instructions all say. **Limits**: one agent fill at a time, three sheets per agent per ten
  minutes, a denial sticks for ten minutes, *Deny and block this agent* for thirty, and a second
  origin mismatch in one unlock session blocks the agent until it is unblocked in Agent access,
  where blocks and notices are listed. **Two-page sign-ins**: one approval fills the username on
  page one and the password on the next page of the same site, in the same tab, within 60 seconds.
  **One-time codes** need their own approval every time and go only into the page's code field,
  never onto the clipboard. A **tripwire** clears the password if the page unmasks it within ten
  seconds, records it and tells the user. Every request is audited under the agent's name.
  **macOS only, with Chromium-family browsers**: Safari does not support it yet, and Windows never
  offers it — every call there is `FILL_UNAVAILABLE`. **Off by default**; turning it on (Agent
  access → "Let agents ask to fill logins in your browser") needs a presence check. Tested
  headlessly in Rust and in the extension's unit tests; not yet run end to end with a real browser
  and the real app.

- **Windows app** (`apps/windows/Kagisecure.App`, WinUI 3 / C#), built outside the numbered
  roadmap at the user's request. First-run vault creation, lock/unlock (master password, or the
  recovery code followed by the forced master-password change), the shell (sidebar, item list,
  detail pane), item create/edit/favourite/archive/trash/restore/delete, a live TOTP code with a
  countdown, the password generator, an import wizard (1PUX and the CSV variants), and Agent
  access (Environments, Leases, MCP setup snippets, Browser extension setup) with an approval
  sheet gated by Windows Hello (`UserConsentVerifier`), falling back to the master password where
  Hello is unavailable. Settings and an Audit page. Verified on Windows 11; see
  [docs/windows-port.md](docs/windows-port.md) for exactly what is and is not verified — notably,
  no real Windows Hello prompt has been exercised, only fakes and the password fallback.
- **Windows CLI, MCP sidecar and native-messaging host**, at parity with macOS: named-pipe IPC
  hardened with an owner-only DACL, SQOS-identified client connections and a same-user gate; HKCU
  native-messaging registration for Chrome, Edge, Brave and Chromium; Authenticode peer
  verification, structurally weaker than macOS's live-process check by design
  ([ADR-0032](docs/decisions/0032-authenticode-peer-verification.md)); and Windows Hello vault-key
  wrapping ([ADR-0033](docs/decisions/0033-windows-hello-key-derivation.md)).
- **`cargo xtask dist-windows`**: a per-user, unelevated WiX v5 MSI installing flat into
  `%LOCALAPPDATA%\Programs\Kagisecure`, with every PE Authenticode-signed individually
  ([ADR-0034](docs/decisions/0034-windows-distribution-a-per-user-signed-msi.md);
  [docs/releasing.md](docs/releasing.md) §10). The signed path is unverified — no certificate is
  available on the machine that built it.
- **A C ABI for C#** (`kagisecure-ffi`'s `capi` feature): the full UniFFI surface,
  hand-marshalled per [ADR-0003](docs/decisions/0003-uniffi-vs-csbindgen.md)'s fallback, since
  `uniffi-bindgen-cs` does not support the pinned UniFFI version. Declarations are generated by
  `csbindgen` and checked in. ABI version 4 carried the presence-gated releases below, with the
  presence gate as its one callback (ADR-0003's amendment); version 5 adds only the agent-fill
  approval tag, which Windows denies (ADR-0036).
- **`kagisecure env agent-access` can now share one field of an item, not only the whole item.**
  `--field LABEL|ID` (with `--item`) toggles that field's own agent-visibility override — the
  per-field grant `add_variables`'s `bind_to` requires before an agent may bind a variable to it
  (mcp-server.md §2.6) — which previously only the app's `VaultSession.setFieldAgentVisible` could
  set; there was no CLI route to it at all. Denying the item now also clears every field's own
  override, mirroring the app's cascade, so a later re-share does not silently bring back a
  per-field grant the user forgot about.

- **Vault writes are transactional across every writer of the same file.** Previously, the app,
  `kagisecure daemon` and the CLI each held the whole vault in memory and saved by replacing the
  file with their own copy, so the last writer could silently discard another writer's changes —
  including security-relevant ones, such as an `agent-access --deny` from the CLI being reverted by
  the app's next save. A sibling `<vault>.lock` file now serializes writers, and every write — the
  app's, the CLI's, an import's, and every MCP-agent and browser-extension request — re-reads the
  vault under the lock and commits through a transaction that refuses to build on a stale or
  replaced file ([ADR-0039](docs/decisions/0039-transactional-vault-writes-and-the-lock-file.md)).
  Two new MCP error codes, `VAULT_BUSY` and `VAULT_CONFLICT`, come with it (protocol version 2),
  and two CLI exit codes: **8** when another kagisecure process held the vault for the whole
  30-second wait, **10** when the file changed in a way the command cannot build on.
- **The app keeps up with other writers.** It re-reads the vault when it becomes active, every
  couple of seconds while frontmost, and before showing the audit log. Saving an item that changed
  elsewhere since the edit sheet opened is refused with "This item was changed elsewhere —
  reload." instead of overwriting the other edit; a busy vault is reported rather than silently
  ignored, including by the favourite, archive, trash and "Visible to agents" controls.
- **A vault file that no longer continues what an unlocked session last saw on disk is refused
  outright**, rather than silently adopted — the in-memory half of closing the audit log's
  freshness gap noted below (W-11), while a session stays unlocked. The app then offers two
  choices: lock and reopen from the file, or **keep this app's version**, which overwrites the file
  only after a confirmation listing what the file would lose — including a master password or
  recovery code that exists only in the file's version, since the app's own unlock methods are
  written back with its contents — and records the overwrite in the vault's audit log. A vault file
  deleted while unlocked is recreated only by that explicit choice.
- **Fields this build does not understand survive a save.** An older build opening a vault written
  by a newer one keeps unknown keys instead of dropping them, and refuses to write a vault whose
  schema version is newer than it knows (vault-format.md §9).
- **The CLI's exit codes cover every `kagisecure_core::Error` variant deliberately.** Two new
  codes: **11** when the file system holding the vault does not support file locks
  (`LockUnsupported` — the vault still opens and reads; only writes are refused), and **12** when a
  newer kagisecure wrote the vault than this build writes (`VaultSchemaTooNew`) or can even read
  (`UnsupportedFormatVersion`) — both mean "upgrade kagisecure", never "retry". `LockLost` (the
  lock file was moved or deleted while held) now exits **8**, alongside `VaultBusy`, since both
  mean nothing was written and retrying shortly is safe; it previously fell through to the generic
  **1**. A no-such-environment or no-such-variable reference now exits **6** alongside a no-such-item
  or no-such-field one, instead of **1**. A unit test in `kagisecure-cli` fails if a future
  `kagisecure_core::Error` variant is added without a deliberate mapping being added alongside it.

### Changed

- **Shared vaults: the library's roster and epochs follow a trusted-admin model**
  ([ADR-0035](docs/decisions/0035-shared-vaults.md), "Amendment 2026-09-27: trusted-admin
  simplification"; roadmap M10 Phase 1). Nothing a person runs uses shared vaults yet. In the
  `kagisecure-shared` library, roster records now apply in one order, each needing an active
  admin device at that point, and a removed device's records are ignored from its removal on;
  epochs are minted on creation and on removal and wrapped to every current device, and a device
  added later is granted older keys. The earlier design's cuts, removal-conflict rules, epoch
  chain and key commitment were dropped for simplicity; the golden epoch vector changed with its
  payload. See the known limitations below.
- **Presence grace window for fills** ([ADR-0037, amendment of 2026-09-27](docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-09-27-presence-grace-window)).
  On macOS, after Touch ID (or the login password, or an Apple Watch) succeeds for a browser fill
  or an agent fill, further fills to the **same exact origin** within **ten minutes** do not ask
  again. A fill that has a sheet — a first fill of a login, and every agent fill — still shows it
  and its Allow still has to be pressed, but pressing it raises no prompt, and the sheet says so. A
  repeat fill that "Allow for this session" already covers, of the same item on the same origin, is
  now filled with no prompt at all. The window runs from the last real check and is not extended by
  fills that rode it; a lock (including on sleep and screen lock), stopping the agent listener, or
  restarting the app ends it; a fill inside a frame from another site never uses it. **This is a
  deliberate relaxation of "every fill needs a fresh presence proof"**: inside the window, anything
  that can click in the browser or press the sheet's Allow can fill on that site with no one at
  the keyboard, a one-time code no longer gets its own touch, and the audit log does not tell such
  a fill from a touched one (threat-model-browser-extension.md R-15). Windows is unchanged and still
  asks every time.

- **Shared vaults: `kagisecure shared ...`** (ADR-0035 addendum, decisions 81–87; roadmap M10
  Phase 2). The first commands a person can run against a shared vault: `shared create <name>
  [--dir]` and `shared list`/`status [--json]`; `shared item add|set|rm|show [--reveal]` and
  `shared env create|add-var`, reusing the personal vault's item and environment argument shapes;
  `shared invite <vault> --name <label> --role reader|writer|admin --out <file>` (the passphrase
  is printed once) and `shared join <file> [--dir] [--passphrase-stdin]`; `shared remove <vault>
  --device|--member <id> [--reason left|retired|compromised]`, `shared role` and
  `shared rotation-list`; `shared sync`, `shared import|export --bundle|--dir` and `shared rebuild
  --from-dir|--from-bundle` for a replica that no longer opens; `shared set-dir`. A new exit code,
  `EXIT_SHARED_REFUSED` (**13**), for a role or key refusal from `kagisecure_shared::admin` —
  distinct from the existing "no such X" (6) and "an unexpected error" (1) codes, so a script can
  tell "not allowed" apart from either. This device's own shared-vault key is generated once per
  (computer, shared vault) it creates or joins and kept in the personal vault's device keys, same
  as `kagisecure-shared`'s own `enroll::invite`/`join`; nothing in `kagisecure-shared` itself
  changed to support the CLI. `crates/kagisecure-cli/tests/shared_exchange.rs` drives three
  personal vaults through the binary alone: create, invite, join, write on each, sync through a
  shared folder in different orders to the same converged `shared item show` output, a removed
  device unable to read a later value, and rebuilding a damaged replica from the exchange folder.
- **Vault `format_ver` 2, for shared-vault device keys** ([ADR-0035](docs/decisions/0035-shared-vaults.md)
  §5, §16; shared vaults Phase 0). The personal vault body can now hold a `devices` list: this
  computer's key pairs for shared vaults, as secret material inside the encrypted body, never an
  item, never agent-visible, never exported. A vault holding one is written as `format_ver` 2 so
  that 0.1.1 — which predates the unknown-key passthrough and would silently drop them on its next
  save — refuses to open it instead. **This does not protect against a 0.1.1 process that already
  had the vault open** when the first device key is added: its next save writes the keys away.
  Quit 0.1.1 first. This build notices such a file (or any older copy put back) instead of
  adopting it: adding or removing a device key is audited (`device_key_added`,
  `device_key_removed`), and a file that does not continue the session's audit log, or is at a
  lower `format_ver`, is refused as diverged. This build reads versions 1 and 2, writes new
  vaults as 1, and never lowers a file's version: a vault read at 2 is written back at 2. The write
  that first raises a file to 2 copies the version 1 file to `<vault>.bak-1` beforehand (created
  new, owner-only; `<vault>.bak-1-<8 hex>` if that name is taken). Removing a device key records its
  id in a grow-only `retired_devices` list, and a retired id can never be added back. "Keep this
  app's version" after a conflict keeps device keys only the file holds, drops any key either
  version retired, and its audit entry records both counts (`device_keys_kept=`,
  `device_keys_retired=`). Nothing creates a device key yet — that arrives with the shared-vault
  commands — so no existing vault changes version. Golden vector
  `v2-devices-argon2id-64k.kagivault`, whose key material is RFC test data.
- **IPC protocol version 2 gains agent fills.** `Request::RequestFill` and `Response::FillResult`
  (field names only), and four error codes: `FILL_UNAVAILABLE`, `NO_MATCHING_TAB`,
  `NOTHING_TO_FILL` and `RATE_LIMITED`, the last scoped to `request_fill` (the injection tools
  still have no rate limiter). Version 2 is still unreleased, so these join it rather than bumping it
  again. `kagisecure-mcp` and `kagisecure-ipc` still compile without `secret-material`.
- **The browser-extension channel lets the app speak first.** Value-free pushes (`locate`,
  `deliver`), three agent-fill requests and an optional `capabilities` list on `hello`; the
  extension protocol stays at version 1, because every addition is optional and a session that does
  not declare `agent_fill` is never pushed to. `kagisecure-nmhost` is full-duplex on macOS and
  Linux to carry the pushes; on Windows it stays lock-step and forwards none.
- **C ABI version 5.** It adds only the `AgentFill` approval tag, which the Windows app denies;
  none of the agent-fill calls cross the C ABI.
- **The Audit page's agent filter matches by prefix** (macOS and Windows), so an agent fill's
  actor — `mcp "<name>" … via <browser> (extension "<id>")` — is listed under agents with every
  other agent entry.

### Fixed

- **The vault no longer relocks itself immediately after an unlock during accessibility- or
  remote-control-driven use.** The idle timer compared system-wide HID idleness (which that kind of
  input never resets) straight against the timeout, with no floor at the unlock itself — so a
  session begun while those counters were already stale could fail the very next 15-second check.
  Idle time is now the minimum of system-wide HID idleness, time since the session's own unlock,
  and time since the last in-app activity (a keystroke, click or scroll in one of the app's
  windows, or a vault operation such as a reveal, copy or save); a fresh unlock always restarts the
  clock. The default stays ten minutes, and sleep/screen-lock still lock immediately regardless
  (docs/investigations/2026-09-27-remote-idle-relock.md).
- **A fill's Allow button no longer leaves the app in front of the browser.** Kagisecure raises
  itself for the approval sheet, and used to stay there after Fill: macOS reports an occluded
  tab's document as not visible, and delivery needs it visible to land, so the fill silently failed
  (`NO_MATCHING_TAB`, or `AGENT_FILL_NOT_DELIVERED` in the audit log). Approving a fill now hands
  activation back to the browser before the grant reaches Rust — the browser named on the sheet
  first, the app that was frontmost when the request arrived as a fallback — and a delivery whose
  document is still hidden a moment later is given longer (5 seconds, up from 2) to become visible
  before it is refused.
- **Browser fills work again after an app lock without reloading the page.** The extension's own
  connection to the native messaging helper can drop when the app locks, and nothing afterward told
  it to reconnect: an already-open tab neither navigates nor opens the popup, so `request_fill` kept
  answering `FILL_UNAVAILABLE` until the page was reloaded by hand. The extension now retries the
  connection on its own, with backoff, until it reconnects.
- **Password fields no longer duplicate keystrokes with the Japanese input method on macOS 26.**
  The app now lets AppKit's secure field editor finish marked-text composition before mirroring a
  value into SwiftUI. This covers first-run vault creation, unlocks, master-password confirmations,
  and secret values entered on the Agent access screen.
- **After a vault lock and unlock, browser fills work again without opening the popup.** The
  native messaging host reconnected to the app on the next request without saying `hello` again,
  so the app refused everything on the new connection until the popup was opened or the browser
  restarted the extension's service worker. The host now replays the extension's last `hello`
  (which carries no value) on a new connection.
- **An app reply the native messaging host could not read is no longer quoted back to the
  browser.** The error the extension received carried the parser's message, which could include
  the bytes it failed on — and a reply that failed to parse could have been one carrying a value.
  It is now `PROTOCOL` with a fixed sentence.
- **Checking whether an item has a working one-time password no longer leaves copies of its seed
  in memory.** The check runs before any approval, on the extension's code path (and on an agent
  fill's), and parsing the `otpauth://` URI percent-decoded the seed into buffers that were freed
  without being zeroized. The URI is now validated in place, and building a generator decodes the
  seed straight into the zeroizing buffer that owns it.
- **Checking whether an item has a password no longer copies it.** The pre-approval check on the
  extension's paths (and an agent fill's) read the password into a plain string that was never
  zeroized; it now borrows the value from the item's own zeroizing buffer, and a copy is made only
  when the value actually crosses.
- **The macOS app can no longer be killed by an agent or browser connection that goes away
  mid-reply.** The app hosts the listeners in-process and, unlike a Rust binary, does not ignore
  `SIGPIPE`, so writing a reply to a peer that had just disconnected ended the whole app. Accepted
  sockets are now `SO_NOSIGPIPE`, and a stop's severing of live connections shuts down only their
  read side, so a denial already being written still reaches the caller.
- `kagisecure init --password-stdin` no longer locks the vault to a password with a leading UTF-8
  byte-order mark, which Windows PowerShell's UTF-8 piping added to the input.
- A failed audit-log save (a full disk, or an attacker making the data directory immutable) is no
  longer silently discarded. The vault now tracks how many audit entries have not reached disk and
  the last save error, surfaced in the Windows app's Audit and Settings pages.
- **`kagisecure audit --json` (and anything else asking `AuditEntry` for JSON) stopped printing
  UUIDs as byte arrays.** Once an entry was read back off disk, `AuditEntry`'s `Serialize` impl
  unconditionally re-emitted the exact CBOR value it was decoded from — needed so the audit chain's
  hash is reproducible byte-for-byte even for a field this build does not model, but applied to
  every serializer, not only the non-human-readable one that requirement is actually about. Every
  `item_id`, `lease_id`, `vault_id` and `environment_id` on an entry read from disk therefore came
  back as `[65, 92, 20, …]` in JSON, instead of the canonical `xxxxxxxx-xxxx-…` string every other
  JSON surface in this codebase uses. Gated on `!serializer.is_human_readable()`, matching how
  `Uuid` itself already decides string-vs-bytes; the hash chain (always CBOR) is unaffected.
- **The IPC `audit` request's reply could not be decoded by the IPC client — reproducible with a
  personal vault alone, no shared vault needed.** Two bugs, both in `AuditEntry`'s hand-written
  `Serialize`/`Deserialize` (needed for the hash chain's byte-exact CBOR, `kagisecure-core::audit`):
  first, an entry's `prev` field kept using `serde_bytes` even when the wire was human-readable
  JSON, which has no byte-string type and falls back to a plain array of numbers that nothing on
  the read side accepted ("invalid type: sequence, expected bytes"). Second, decoding always went
  through a `ciborium::Value` built from the deserializer, which reports itself as binary
  regardless of what produced it — so once the first bug was fixed, every `Uuid`-backed field
  (`vault_id`, `environment_id`, `item_id`, `lease_id`) broke the same way in the other direction
  ("invalid type: string ..., expected bytes"). `prev` now round-trips as a hex string over a
  human-readable format and as a byte string over CBOR, matching what `Uuid` already does for the
  id fields; and a human-readable deserializer now decodes straight into the typed fields rather
  than through a `ciborium::Value`, which only a **binary** source ever needed (vault-format §9's
  forward compatibility, unaffected). The shared-vault canary
  (`a_value_in_a_shared_vault_never_reaches_the_model`,
  `crates/kagisecure-agent/tests/shared_vaults.rs`) calls `audit` again, through the real IPC
  client, alongside a unit round-trip test in `kagisecure-core`.
- **Locking the app no longer stalls for up to five seconds.** The lock's final audit flush waited
  the vault's default five-second lock timeout when another process (the CLI, the daemon) held the
  file, on the app's main thread. It now waits at most one second, so a lock stays within the app's
  two-second budget; the vault locks either way. Entries that still cannot be written at that
  moment are lost with the key, as before — the flush stays on the calling thread deliberately,
  because moving it to the background would keep the vault key in memory after the lock returned.
- **KDF descriptors and password-history entries keep keys a newer build added.** `KdfParams` and
  `FieldRevision` had no `unknown` map, so an older build rewriting the vault dropped whatever a
  newer one had added there — for a KDF parameter, leaving the newer build deriving a different
  key and the slot unopenable. Both now preserve unknown keys (vault-format §9). A descriptor with
  a parameter this build does not recognize is never derived with (`Unsupported`, instead of what
  would look like a wrong password), and a fresh wrap — password change, KDF upgrade, new recovery
  code — starts clean by design. Golden vectors are unchanged.
- **`kagisecure env agent-access` no longer reports a change that did not happen.** It printed
  "item …: agent access allowed" from inside the transaction, before the write — so a later
  target in the same command that did not exist, or a failed save, rolled the change back after
  the terminal had already claimed it, and stdout was written while the vault's lock was held.
  The changed targets are now returned from the transaction and printed after it commits.
- **An app import whose write fails no longer throws the parsed plan away.** The import handle was
  spent before the transaction ran, so a busy vault, a diverged file or a failed save left the
  sheet with nothing to retry but re-reading the export. The plan now stays in the handle until a
  commit reaches the disk (it is checked out while one runs, so a double press still cannot import
  twice), with its original target vaults, and "Try again" goes straight back to the preview.
  `kagisecure_import::commit` borrows the plan and copies what it stores.
- **Delete for good checks the item is still in the Trash, and still the one shown.** The app's
  permanent delete removed whatever item the id (or a title, or an id prefix) resolved to, without
  looking at whether it was still in the Trash — an item another window or process had restored
  in the meantime was destroyed anyway. `delete_item` now takes the Trash row's revision and, inside
  the transaction, refuses an item that is not in the Trash or that changed since the row was drawn
  ("changed elsewhere — reload"), the same stale-base rule the edit sheet's save follows.
- **Changing the master password no longer freezes the app, the agent and the browser extension
  while Argon2id runs.** The derivation ran while holding the vault's in-process lock — the one
  every agent request, extension fill and app view also takes — for the whole of the deliberately
  slow key derivation. It now runs with no lock held, and only the fast wrap and the install take
  the lock.
- **Locking the vault now shreds a file written under a lease that had already run out of uses
  before the lock happened** — "Allow once" is the common case, since a single-use lease is
  consumed by the very write that mints it. `LeaseStore::revoke_all` used to return only the
  `written_paths` still attached to a *live* lease, so a file written under an already-exhausted
  lease was left on disk, with a live secret in it, right after the user had just been told every
  lease and everything written under one was gone. It now returns the store's own ledger of every
  path it has ever written in the unlock session, which was already built to outlive the lease
  that populated it for exactly this reason, but `revoke_all` was not reading from it.
- **Locking the vault now ends a `run_with_env` child still running under an injected
  environment**, instead of leaving it running with the value live in its process environment on a
  connection thread no lock hook could reach. `SIGTERM` to the child's whole process group, then
  `SIGKILL` after a short grace period if anything in it is still alive (Windows: the job-object
  equivalent, at once); the group, not just the one pid, so a command that forks its own children —
  a build tool spawning a bundler — does not keep one running after its parent is killed. The
  `run_with_env` reply for a call caught this way is `VAULT_LOCKED`, and a `Failed` audit entry is
  recorded with detail `KILLED_ON_LOCK (entry <seq>)`, written directly onto the vault by the lock
  itself a moment before that vault is gone for good — the ordinary best-effort audit path cannot
  reach it, since by the time it would run there is no vault left in the handle to write to. New
  crate `kagisecure-childproc` holds the (necessarily unsafe) process-group/job-object FFI this
  needed, since both `kagisecure-core` and `kagisecure-agent` forbid unsafe code outright.
- **Stopping the agent now ends a `run_with_env` child too, not just locking the vault.** An app
  quit or the agent being toggled off used to leave an injected environment running exactly the way
  a vault lock used to before the fix above: `Agent::stop()` denied outstanding approvals and
  dropped leases, but never reached the children a lock's own hook does. It now kills every tracked
  child the same way, records a best-effort `Failed` entry with detail `KILLED_ON_STOP (entry
  <seq>)`, and does so through the ordinary audit write path rather than a lock hook, since stopping
  does not take the vault away.
- **Stopping the MCP agent no longer silences the browser extension's own lock hook.**
  `Agent::stop()` used to call `VaultHandle::clear_lock_hook`, which emptied every hook registered
  on the shared `VaultHandle` — the MCP agent's own, and the extension listener's `add_lock_hook`
  one along with it. So once an MCP agent sharing a vault with a running extension listener
  stopped, the *next* lock no longer emptied the extension's fill-lease store — the fresh-presence
  guarantee ADR-0037 exists for. Every hook is now individually removable: registering one returns
  a `LockHookGuard` that deregisters only the entry it was issued for, by an id no other guard
  carries, and `Agent::stop` now drops only the two guards it owns.
- **The browser extension channel refuses a diverged or replaced vault file with `VAULT_CONFLICT`,
  not `INTERNAL`.** A vault file restored from an older copy, replaced, or removed while the vault
  stayed unlocked was already refused before `match`, `fill` or `totp` touched it, but the reply
  carried the generic `INTERNAL` code with a sentence explaining the real reason — the extension
  protocol's `ErrorCode` had no code of its own for it yet. It now does, added the same way
  `AUDIT_UNAVAILABLE` was: no protocol version bump, since the content script falls back to the
  app's own sentence for any code an older build does not recognize. There is deliberately no
  extension-side `VAULT_BUSY` to go with it — every value this channel releases already crosses
  through the audit-before-release path, so a lock held past a write's own wait is already
  `AUDIT_UNAVAILABLE`, and the pre-flight check that produces `VAULT_CONFLICT` only ever reads the
  file.
- **A member invited with a name now shows that name on every device that can know it, instead of
  "Unnamed member."** `kagisecure shared invite --name` set the invitation's device-key label but
  never the inviting device's own local name for the new member — only the app's own invite sheet
  did that, through a second write `enroll::invite_with_kdf` now does itself, for the CLI too. The
  joining device likewise starts with that same label as its own local name for itself. A member
  neither device named (a third device discovering them, say) shows a fallback built from one of
  their device's fingerprints rather than a bare "Unnamed member" indistinguishable from anyone
  else's.
- **Editing an item and typing into a field (Notes, say) could take two clicks on Save to actually
  save.** The first click could end up only ending the field's editing session; `Save` now resigns
  the window's first responder itself before reading the draft, so whatever was last typed is
  always what gets saved on the first click.
- **The environment editor's "Add a variable": clicking the Value field sometimes left typing in
  NAME instead.** The field is a native `NSSecureTextField` wrapper (`StableSecureField`, for
  IME-safe password entry) that did not report its own size back to SwiftUI, so its actual,
  AppKit-hit-tested frame could end up smaller than the box drawn around it. It now implements
  `sizeThatFits`, so the two agree.
- **An unattended job's socket could fail to bind with a raw "local socket name length exceeds
  capacity of sun_path" error.** It is derived next to `KAGISECURE_SOCKET` (or the per-user
  default), and neither is bounded — a synced folder, or a home directory nested deeply enough,
  can already be most of a `sun_path`'s 104 (macOS) or 108 (Linux) bytes before a label is even
  added. Every socket path this builds now falls back to a short, per-user, hashed path under this
  platform's own temporary directory when the natural one would not fit, and a path that still
  does not fit — one set explicitly with `--socket` or `KAGISECURE_SOCKET` — now fails with a
  message naming the path and the limit instead of interprocess's own.
- **The shared vault members pane did not show the roster warnings `kagisecure shared status`
  already prints** (fewer than two admins left, or the roster frozen with none). The app's
  `SharedVaultSummary` now carries them too.
- **`xcodebuild test` no longer opens this Mac's real vault.** `KagisecureTests` is hosted: the
  `Kagisecure` app itself is the test runner, launched with whatever environment its own scheme's
  Test action sets, since no test method runs early enough to redirect it. The `Kagisecure` scheme
  now points `KAGISECURE_HOME` and `KAGISECURE_SOCKET` at a scratch location for that action, so
  a test run shows the empty-vault state on a throwaway path instead of this Mac's real vault and
  its real IPC socket.
- **A unit test could lock every Kagisecure on the Mac, not just the one under test.**
  `AutoLockAdversarialTests` posted the real, machine-wide `com.apple.screenIsLocked` distributed
  notification to check that `AutoLockCoordinator` reacts to it — which every other
  `AutoLockCoordinator` listening on the same Mac reacted to as well. `AutoLockCoordinator` now
  takes the notification's name as a parameter (defaulting to the real one, unchanged in the app),
  and that one test posts a name unique to itself instead.

### Security

- **Notes and a one-time password's setup shown in the edit sheet now hide at five minutes.**
  Only concealed field rows were masked again after the five-minute cap (ADR-0038 user decision
  5); notes revealed with **Show** and a seed revealed with **Show current setup** stayed on screen
  for as long as the sheet was open. All three now share one rule: untouched at five minutes, the
  value is masked again and the stored one kept; a value the person has edited is theirs and stays.
- **A failed Touch ID or login-password check no longer falls back to the master password.** The
  app mapped every `LocalAuthentication` error but a cancellation — `authenticationFailed` and a
  biometry lockout included — to "unavailable", which is the one answer that offers the
  master-password panel. ADR-0038 allows that fallback only when `LocalAuthentication` cannot run
  at all. The mapping is now exact: no passcode, no biometry or companion device, or no way to
  prompt → unavailable (fallback offered); a check that ran and did not pass, or any unknown error
  → not confirmed (no fallback).
- **An item's revision is no longer a guessing oracle for its secrets.** `ItemView::revision` —
  the edit sheet's conflict check, handed to the app for every item with no presence check — was an
  unsalted SHA-256 over the item including every secret and the notes, so anything that could read
  the app's views could test guesses against it offline. It is now an HMAC-SHA-256 under 32 random
  bytes generated when the session unlocks, which never leave the Rust side and are zeroized with
  the session: equal items give unrelated revisions in two sessions, and the same-second conflict
  detection is unchanged.
- **Refused releases can no longer rewrite the vault file at will.** Every `PRESENCE_BUSY`,
  `PRESENCE_CANCELLED` and `PRESENCE_UNAVAILABLE` refusal wrote its own audit entry, and with it
  the whole vault file, so anything that could click Show — or call a release while a prompt was
  up — in a loop could rewrite the vault as fast as it could click. Like wrong master passwords,
  refusals are now written once per reason per minute; the rest of the minute is counted into one
  `<detail>_REPEATED:<n>` entry, written when the next refusal arrives after the minute, before the
  next grant, or at the lock, so a burst is still on record.
- **"The password" is a field the vault designates by id, not one found by label or position.**
  Quick Access ⏎ copied the first concealed field, ⇧⌘C and ⌘R's unfocused fallback the first
  concealed non-TOTP field, a browser fill preferred the field labelled "password", and the
  presence prompt named the label — all facts the edit sheet can change without a presence check,
  so a PIN relabelled "password" and moved first could be copied, filled or announced in the
  password's place. Items now carry an additive `primary_secret` field id (set by the template,
  pinned from the pre-edit state the first time an older item is saved); every one of those
  paths uses it, and the prompt says what a field *is* ("the password", "the card number", "the
  one-time password setup", "the concealed field") before its label. A stored secret's kind can
  no longer be changed without its value.
- **A card's "•••• 1234" subtitle comes only from its card-number field, by kind.** It was taken
  from whichever concealed field was labelled "number", so relabelling the PIN or CVV printed its
  digits under the item's title. New cards store the number as a `CreditCardNumber` field; a card
  from the older template shows no digits until its number field's kind is set to *Card number*.
  ⌘⏎ in Quick Access and Item ▸ Copy Username (⇧⌥⌘C) copy a real username field only — never the
  subtitle, which may be a website or those digits.
- **Secret-release channels name an item by its id and nothing else.** The browser extension's
  fills and one-time codes, and the app's presence-gated releases, used to resolve their item the
  way the command line does — by id, by any id prefix of four or more characters, or by exact
  title — and a release's field by label as well as id. Through that door a request could tell
  "no item has this title" from "two do, one of them perhaps in the trash", a title someone else
  controls could collide with the one being filled and block it, and audit entries named whatever
  string was sent instead of an item. These channels now accept only the canonical item id
  (`Vault::item_by_id` / `item_by_id_str`) and field id; anything else is answered exactly like an
  id that names nothing. `Vault::find_item` stays, documented as the command line's convenience.
- **Presence-gated release calls for the app, in Rust (ADR-0038 phase 1).** New FFI calls
  `release_field`, `release_totp` and `release_notes` hand a value to the app only after a fresh
  presence check from a `PresenceGate` the app installs once per session; with no gate installed,
  nothing is released. One check covers one field, a release stops working when the vault locks,
  after five minutes and when closed, a copy is good for one use, and a lock while the prompt is
  up refuses the release whatever the prompt then answers. The prompt names the item, the field and
  the action, with titles and labels sanitised against bidi overrides, invisible characters and
  forged quotes. Every outcome is audited best-effort (`PRESENCE_CONFIRMED`, `PRESENCE_CANCELLED`,
  `PRESENCE_UNAVAILABLE`, `PRESENCE_BUSY`, `VAULT_LOCKED`, `SHOWN_EARLIER`). A new explicit
  `VaultSession::lock()`, and `verify_master_password` — the gate's fallback where Touch ID is
  unavailable — with exponential back-off after a wrong password
  ([ADR-0038](docs/decisions/0038-app-release-needs-presence.md)).
- **The app asks for Touch ID (or your Mac password) before it shows or copies any secret
  (ADR-0038 phase 2).** Revealing a field (the eye, or ⌘R, which now works), copying a concealed
  value, starting a one-time code — now masked until you ask — copying one from the detail pane,
  the item list or Quick Access (`⏎`, `⌥⏎`), and showing or copying an item's notes each raise one
  LocalAuthentication prompt that names the item, the field and the action; one touch covers one
  field, and copying a value already on screen asks nothing. A shown value hides itself when you
  select another item, when the vault locks and five minutes after the touch, and can no longer be
  selected as text. Edit mode prefills nothing, notes included: each value has its own **Show**,
  and the one-time-password setup sheet a **Show current setup**. Only one prompt is on screen at a
  time in the whole app, shared with the browser extension's; a second is refused, not queued.
  Locking during a prompt tears it down and releases nothing. On a Mac where LocalAuthentication
  cannot run at all, a panel asks for the vault's master password instead, with the same back-off.
  There is no setting to turn this off. VoiceOver hears what a masked value is and what revealing
  it asks for, and when a value is shown, hidden or copied.
- **The Windows app asks Windows Hello before it shows or copies any secret (ADR-0038,
  "Windows").** The same Rust release calls, reached through the C ABI with the presence gate as a
  C callback that fails closed: a field's Reveal and Copy, a one-time code (masked until **Show
  code**), and the notes (masked until **Show notes**) each raise one Windows Hello prompt naming
  the item and the action; the vault master password is asked for only when Hello is unavailable,
  with the same back-off; the editor prefills nothing concealed; one prompt at a time, shared with
  the approval sheet. Windows Hello is weaker evidence of a person than Touch ID (threat-model
  W-1). **Written but not yet built or run on Windows** — see
  [docs/windows-port.md](docs/windows-port.md).
- **Windows: the vault's sibling lock file, and a directory the lock creates, get the owner-only
  DACL.** The lock is taken before a new vault's first write, so it created the vault's directory
  with an inherited ACL that the vault save then left alone.
- **Item notes are secret.** Notes are held as secret material in memory, redacted from debug
  output, left out of the item views the app lists (which now say only whether an item has
  notes), never searched — by the app or by agents — and hidden by `kagisecure item show` unless
  `--reveal` is given. The vault file format is unchanged: existing vaults open as before and a
  note is written byte for byte as it was.
- **`kagisecure item add` no longer takes a note's text as `--note <TEXT>`.** That put the note on
  argv, in `ps` output and in shell history — exactly what `--secret` and `--totp` already avoided.
  `--note` is now a bare switch: the value is prompted for, or, with `--value-stdin`, read as the
  next line of standard input after every `--secret` and `--totp` value, the same as those already
  work. A note with more than one line — which neither a prompt nor a line of stdin can carry — now
  has `--note-file PATH`. The old `--note <TEXT>` form is refused by clap itself as an unexpected
  argument (exit 2) rather than silently accepted.
- **Credential changes are audited**: a master-password change (app and `kagisecure recover`), a
  recovery-code reissue, Touch ID enrolment and removal — each recorded in the same write that
  makes the change — and the vault-key export that Touch ID enrolment performs.
- **The app's release audit tells more apart.** A value released through the master-password
  fallback is recorded `PRESENCE_CONFIRMED_MASTER_PASSWORD`, not as a Touch ID confirmation; a
  wrong master password typed into the fallback is recorded (`MASTER_PASSWORD_WRONG`, and
  `MASTER_PASSWORD_THROTTLED` once per back-off window), so a guessing burst shows in the log; and
  a confirmed release whose item, field or notes were deleted while the prompt was up is recorded
  as failed (`GONE_DURING_PROMPT`) instead of leaving no entry.
- **The ungated FFI calls are gone.** `reveal_field`, `reveal_notes`, `totp_code` and
  `item_totp_code` — which handed the app a value with no check at all — are removed; the
  presence-gated `release_*` calls are the only way a value leaves the vault for the app
  ([ADR-0008](docs/decisions/0008-ffi-secret-crossings.md) crossings 2 and 5, amended).
- **A browser fill is released only once its audit entry is on disk.** A password, a one-time code
  and a username-only fill are each read inside the transaction that commits their `Allowed` entry,
  and reach the browser only if that commit succeeded; when the audit log cannot be written the
  extension shows that nothing was filled (new extension error code `AUDIT_UNAVAILABLE`), and no
  approval is asked for while earlier entries still cannot be written
  ([ADR-0040](docs/decisions/0040-audit-before-release.md)).
- **Fill and one-time-code requests no longer serve items in the trash or the archive.** They are
  answered exactly as for an item that does not exist, as the in-page item list already treated
  them.
- **Every browser fill that carries a password or a one-time code now needs a fresh Touch ID,
  login-password or Apple Watch check.** A live fill lease used to skip both the approval sheet and
  the check, so a browser- or OS-automation agent — whose synthesized clicks the browser marks as
  trusted — could fill a saved password with nobody at the keyboard. A lease now only skips the
  sheet: a repeat fill of the same origin, item and fields from the page's top frame is asked as a
  presence-only prompt, and its audit entry reads `FILL_CONFIRMED`
  ([ADR-0037](docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
- **Revoking or locking no longer shreds through a path repointed after the write.** The shredder
  used to follow the path it was given, so swapping an agent-written `.env` for a symlink to, say,
  `~/.ssh/id_ed25519` and then calling `revoke_env_file` — which needs no approval — or simply
  waiting for the user to lock zeroed and unlinked the target. The written-file ledger now records
  the identity of the file written (device and inode; volume and file index on Windows), and the
  shredder opens the path without following a symlink and overwrites nothing unless the handle is
  that same regular file. A path left alone is recorded as `NOT_SHREDDED_FILE_REPLACED`.
- **Variable names are identifiers, enforced.** `add_variables` accepted any string as a name,
  and the `.env` writer printed it verbatim, so a name containing `=` or a newline wrote extra
  lines of an agent's choosing into the file (and odd entries into a child's environment). Names
  must now match `^[A-Za-z_][A-Za-z0-9_]*$` (at most 128 characters): the agent refuses anything
  else before asking, with a new MCP error code `INVALID_ARGUMENT` (protocol version 2, still
  unreleased); `kagisecure-core` stores and renders only a validated `VarName`, and a malformed name
  already in a vault makes `write_env_file`, `run_with_env`, `env write` and `run` refuse rather
  than print it. `env add-var` and `run --env` apply the same rule (exit 2).
- **Killing a child never signals a process that merely inherited its id, and `kagisecure run` on
  Windows no longer kills its own child.** The job object that ends a Windows child
  (`KILL_ON_JOB_CLOSE`) belonged only to the kill handle, which `kagisecure run` did not keep, so
  the job closed — and the child died — right after the spawn. A kill handle could also send its
  delayed `SIGKILL` to a process group, or `TerminateProcess` to a handle, after the child had
  been reaped and its id could belong to someone else. `kagisecure-childproc`'s new `Spawned` owns
  the child and its job until the child has been waited for, learns of the exit without reaping
  (`waitid(WNOWAIT)`) so the id stays pinned while the group is still being signalled, and every
  signal is sent under the same lock the reap takes, only while the child is unreaped.
- **`run_with_env` returns within its timeout and leaves nothing of the command running.** At the
  deadline only the direct child was killed, so a grandchild kept running with the injected value
  and, holding the output pipes, kept the call from returning until it chose to exit; a command
  that exited normally but left a background process behind held the call open the same way. The
  whole process group is now ended at the deadline, and whatever the command left in its group
  when it exits (`SIGTERM`, then `SIGKILL` after 2 s), and output from a pipe held by something
  outside the group is read for at most 0.5 s more, so the reply comes back within the timeout plus
  about 2.5 s.
- **Ctrl-C and closing the terminal reach the child of `kagisecure run` again.** Putting
  `run_with_env` children in a process group of their own (so a lock ends everything they spawned)
  was applied to every caller, including the CLI, whose child then left the terminal's foreground
  group: Ctrl-C or a closed window ended `kagisecure run` and left the child running, detached,
  with the secret in its environment. A new process group is now an explicit `RunRequest` option
  that only the MCP agent sets; the CLI's child stays in the terminal's group and gets exactly the
  signals a command typed at the prompt would.
- **A lock that races a `run_with_env` spawn, or the host's own lock handling, no longer lets
  anything through.** A child spawned just after a lock drained the registry of running children
  was never killed; it now finds the registry closed and is killed at once (`KILLED_ON_LOCK`), and
  the agent re-checks that it is still serving immediately before the spawn (`LOCKED_BEFORE_START`,
  nothing started). `Agent::take_lock_request` used to clear the lock flag as it reported it, so the
  agent served requests again between the host's poll and its taking the vault; the flag now
  stays raised for the life of the agent and only the report is consumed.
- **A lease no longer lets `write_env_file` replace a file kagisecure did not write.** Leases had
  no overwrite dimension, so once a session lease covered a directory and file name,
  `overwrite: true` silently replaced whatever the user had put there since — their own `.env` —
  without the approval mcp-server.md §2.7 promises. Replacing a file that is not the one kagisecure
  wrote at that path (compared by file identity) is now never covered by a lease and always asks.
- **A release re-checks every binding it follows, and never names a hidden item.** `write_env_file`
  and `run_with_env` re-checked only the environment, so a variable bound to an item the user had
  since hidden from agents or trashed was still released. Each binding's item is now held again,
  inside the release's transaction, to the rule `list_items` and `describe_item` use, and refused
  as not-found. When resolution failed, the reply carried core's error text, which
  named the item by its title — the metadata an invisible item must not leak; resolution errors
  now reach an agent as fixed sentences, and core names items by id in that error.
- **`add_variables` no longer replaces an existing variable.** It set variables by name, so naming
  one the user had already bound silently swapped that binding for a pending placeholder or a
  binding of the agent's choosing, under a sheet that read like an addition. An existing name is
  now refused with `INVALID_ARGUMENT`; changing a variable stays with the user.
- **A stopped MCP agent serves nothing more.** A connection idle when the agent stopped (the app
  quitting, the agent toggled off) still served the next request it read, against a lease store
  the stop had already emptied for the last time and with its lock hook already retired. The
  connection now re-checks after each read and closes, and a lease is used or granted only while
  its own agent is neither stopped nor locked, checked under the lease-store lock that stop and
  lock empty it under.
- **No lock-hook registration can displace another.** `VaultHandle::set_lock_hook` replaced
  whatever its single slot held, so a second agent on the same vault handle silently unregistered
  the first's hook and the first's leases survived the next lock. The single slot and
  `set_lock_hook` are gone; every registration is additive (`add_lock_hook`,
  `add_vault_lock_hook`) and is retired only by dropping its own guard.
- **The documented limits on strings shown to a human hold at the agent, not just the sidecar.**
  An environment name (1–128 characters, one line), description (512), `add_variables` hint (200,
  one line), variable count (50) and `run_with_env` argument count (64) are now enforced by the
  process that shows them, with `INVALID_ARGUMENT`; control characters are refused in names and
  hints so an agent cannot lay out lines of its own on an approval sheet. The sidecar's own checks
  now answer `INVALID_ARGUMENT` too, instead of `INTERNAL` ("a bug").

### Known limitations

- **Shared vaults trust their admins** (library only; see
  [threat-model.md](docs/threat-model.md) §7, "limits of the trusted-admin model"): a malicious
  or compromised admin can take a shared vault over; a removed device's records written
  concurrently with its removal may still apply; the order between concurrent admin records can
  be influenced by their authors; equivocation is not reported; a garbage epoch wrap is not
  detected.
- **0.1.x builds do not take the new lock file** and are unaffected by (and do not participate in)
  the serialization above; running a pre-transaction build alongside a newer one against the same
  vault is exactly as unsafe as before.
- The audit log's freshness gap once every session has locked (W-11) is unchanged; an external
  anchor is proposed ([ADR-0041](docs/decisions/0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md))
  but not implemented. Durable-before-release audit ordering
  ([ADR-0040](docs/decisions/0040-audit-before-release.md)) covers the MCP release tools, the CLI's
  `env write` and `run`, and browser fills; the app's own reveals and copies are audited
  best-effort, by design, once the app adopts ADR-0038's release calls — until then they are not
  audited at all.

## 0.1.1 — 2026-09-19

### Fixed

- **Release binaries no longer embed build-machine paths.** The 0.1.0 app and Safari extension
  kept the linker's debug map in their symbol tables, which named the absolute path of every
  object file on the machine that built the release. Release builds are now stripped, and
  `cargo xtask dist` refuses to package any Mach-O that contains a `/Users/` path. No change in
  behaviour; nothing about your vault or your data was involved.

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

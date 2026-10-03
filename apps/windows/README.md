# apps/windows

The C# side of kagisecure on Windows: the binding layer the WinUI 3 app is built on (see
[docs/windows-port.md](../../docs/windows-port.md)).

| Project | What it is |
| --- | --- |
| `Kagisecure.Interop` | P/Invoke over `kagisecure-ffi`'s `capi` C ABI, wrapped in an idiomatic managed API: `VaultSession` (every session method), `Categories`, `PasswordGenerator`, `Totp`, `Importer` / `ImportPlan`, `Agent`, `BrowserExtension`, records for every DTO, enums, and `KagisecureException`. `net8.0`. |
| `Kagisecure.Interop.Tests` | xUnit tests that load the real `kagisecure_ffi.dll` and exercise every public member against vaults in temp directories — including the agent end to end over its named pipe. |

Why not generated UniFFI bindings: `uniffi-bindgen-cs` does not support the UniFFI version the
project pins, so [ADR-0003](../../docs/decisions/0003-uniffi-vs-csbindgen.md)'s fallback applies:
an explicit C ABI, with the C# declarations generated from it by csbindgen. The ABI covers every
function and method the Swift app gets through UniFFI, except three Safari/App Group inputs and
outputs that mean nothing on Windows (listed in `crates/kagisecure-ffi/src/capi/mod.rs`).

## Prerequisites

- Windows 10/11, x64 or arm64
- Rust with the MSVC toolchain (the version in the root `Cargo.toml`'s `rust-version` or newer)
- .NET SDK 8.0.4xx (`global.json` here pins the 8.0 feature band, so a newer SDK installed beside
  it is not picked up by accident)

## Build and test

From the repository root:

```powershell
# 1. Regenerate Native\NativeMethods.g.cs, build kagisecure_ffi.dll with the C ABI, and stage the
#    DLL in target\windows\Debug\
cargo xtask bindgen-cs

# 2. Build and test the C# projects
dotnet test apps\windows\Kagisecure.Windows.sln
```

For a Release build, stage the Release DLL and build that configuration:

```powershell
cargo xtask bindgen-cs --release
dotnet test apps\windows\Kagisecure.Windows.sln -c Release
```

Step 1 is required in a fresh checkout and after any change to `crates/kagisecure-ffi`. Skipping
it fails the build with a message naming the command; running a stale DLL fails at the first call
if the C ABI version changed (`kgs_abi_version`), and `AbiTests` fails if a declared entry point
is missing from the DLL.

## What is checked in, and what is not

- **Checked in:** the C# sources, including the **generated** P/Invoke declarations in
  `Kagisecure.Interop/Native/NativeMethods.g.cs`, for the reasons
  [ADR-0009](../../docs/decisions/0009-checked-in-swift-bindings.md) gives for the Swift bindings:
  it is the reviewable statement of what crosses, and the solution opens without a Rust toolchain.
- **Not checked in:** `kagisecure_ffi.dll`, which `cargo xtask bindgen-cs` rebuilds, and `bin/`,
  `obj/`.

## Rules for adding to the binding

The contract is `crates/kagisecure-ffi/src/capi/`; `NativeMethods.g.cs` is generated from it and
never edited. A mismatch between the two corrupts memory instead of failing to compile, so three
checks stand between them:

1. `cargo test -p xtask` — `generated_csharp_is_up_to_date` fails if the checked-in
   `NativeMethods.g.cs` is not what the Rust generates, and `every_export_and_every_tag_enum_is_declared`
   fails if an export is missing from it;
2. `AbiTests` — every declared entry point must be exported by the DLL on disk, and
   `kgs_abi_version()` must equal the generated `KGS_ABI_VERSION`;
3. the runtime check in `Marshalling.EnsureAbi`, before the first call.

So, to add a function:

- read the rules at the top of `capi/mod.rs` first — strings are UTF-8 `{ptr, len}` slices, never
  NUL-terminated; whatever Rust allocates, Rust frees (and zeroizes) through one `kgs_*_free` per
  out type; every call returns a `KgsStatus` and a message buffer; lists are `Kgs<Elem>Array`,
  optionals `KgsOpt*`, enums `u32` tags named by the `#[repr(u32)]` `Kgs*` enums;
- bump `KGS_ABI_VERSION` on any signature or layout change (the C# constant is generated from it);
- run `cargo xtask bindgen-cs` and commit `NativeMethods.g.cs` with the Rust;
- wrap it in the public API following the existing pattern (pin, call, `Check`, copy, free in
  `finally`), and give public enums their values from the generated `Kgs*` enums;
- add a test in `Kagisecure.Interop.Tests` that exercises the new member end to end.

## Threading

Every call is synchronous and thread-safe; none belongs on the UI thread. Unlocking, creating and
changing the master password run Argon2id (about a second at the desktop profile), and every
mutating `VaultSession` method re-encrypts and saves the file — use `Task.Run`.

`Agent.NextRequest` **blocks** for up to its timeout, waiting for an approval (ADR-0014). Run one
loop on a dedicated background thread — `Agent.NextRequestAsync(Agent.DefaultPollInterval, token)`
does exactly that — and hand each request to the UI thread with the dispatcher. A parked poll
cannot be interrupted; cancellation takes effect between polls, so it lands within one poll
interval (500 ms, as in the Swift app). Browser-extension fills arrive on the same queue.

Lock order matters: `Agent.Stop()` and `BrowserExtension.Stop()` before disposing the
`VaultSession`, because each listener holds its own reference to the session.

## Secrets on the managed heap

ADR-0003 rule 5 is followed as far as C# allows:

- **Going in**, secrets are `ReadOnlySpan<char>` / `ReadOnlySpan<byte>` (`Create`, `Unlock*`,
  `ChangeMasterPassword`, `SetVariableValue`, `PasswordStrength`, `Totp.*`, `UnlockWithVaultKey`,
  `InstallPlatformSlot`), so a caller can keep them in a buffer it clears. Every argument's UTF-8
  copy lives on the pinned heap and is zeroed the moment the call returns.
- **Coming out**, byte secrets are a `byte[]` the caller must clear with
  `CryptographicOperations.ZeroMemory` (`ExportVaultKeyForPlatformWrapping`,
  `FieldRelease.ValueUtf8`, the `CopyShown*Utf8` calls).
  Rust zeroizes its own copy when the buffer is freed.
- **Unavoidably `string`**: `FieldRelease.Value`, `NotesRelease.Text`, `TakeRecoveryCode`, `PasswordGenerator.Generate`,
  `TotpCode.Code`, `Totp.UriFromParts`, and `FieldDraft.Value` going in — the same limit a Swift
  `String` has, and a WinUI `TextBox`/`PasswordBox` hands out a `string` anyway. Keep their
  lifetime short; do not cache them.

## Run the app

`Kagisecure.App` is the WinUI 3 desktop shell (Tier 3 of
[docs/windows-port.md](../../docs/windows-port.md)) — first-run vault creation, the lock screen,
the main shell (sidebar with real counts, a real item list with search/sort/filter, a read-only
item detail pane), and the password generator, per [docs/ui-spec.md](../../docs/ui-spec.md)
adapted to Fluent/WinUI conventions. `Kagisecure.App.Tests` covers the view models
(`FirstRunViewModel`, `LockViewModel`, `ShellViewModel`, `GeneratorViewModel`) against a fake
`IVaultService`/`IClipboardService` — no XAML, no UI automation, no real FFI.

It's unpackaged (`WindowsPackageType=None`, framework-dependent on the Windows App Runtime rather
than self-contained), so it runs with `dotnet run` or the built `.exe` directly, no MSIX install:

```powershell
# 1. Build kagisecure_ffi.dll (same step as above) — Kagisecure.App copies it next to its own
#    output the same way Kagisecure.Interop does.
cargo xtask bindgen-cs

# 2. Build and test everything, including the app
dotnet build apps\windows\Kagisecure.Windows.sln -c Debug
dotnet test apps\windows\Kagisecure.App.Tests\Kagisecure.App.Tests.csproj -c Debug

# 3. Run it
dotnet run --project apps\windows\Kagisecure.App\Kagisecure.App.csproj -c Debug
```

Architecture: MVVM (`CommunityToolkit.Mvvm`), with `Services.IVaultService` as the one seam
between views/view models and `Kagisecure.Interop` — views never call `NativeMethods` or hold a
`VaultSession` directly, and every call that can block (the KDF on vault create/unlock takes
roughly a second; every mutating `VaultSession` call re-encrypts and saves) runs off the UI thread
via `Task.Run`.

What's real: sidebar counts (`VaultSession.SidebarCounts`), the category list
(`Categories.Catalog`), the tag list, and the item list itself — filter, free-text search and sort
all go straight to `VaultSession.ListItems`. The detail pane renders a selected item's fields,
tags and notes for real, grouped into sections exactly like macOS's `ItemDetailView` (same fields
sharing a section name become one group wherever they fall in the list, not only when they happen
to be contiguous). A concealed value, a one-time code or the notes appear only after a Windows
Hello confirmation — or, where Hello is unavailable, the vault master password — through
`VaultSession.ReleaseField` / `ReleaseTotp` / `ReleaseNotes` behind the session's presence gate
([ADR-0038](../../docs/decisions/0038-app-release-needs-presence.md), "Windows"); the ungated
`RevealField` and `TotpCode` are gone. A TOTP row shows a masked code (`••• •••`) with **Show code**;
once confirmed, the live countdown-ring widget (ui-spec.md §4.2/§9) runs for at most five minutes.

Item **editing** (create/save/delete, `+ Add field`, tag/URL editing) is real too, and prefills
nothing concealed (ADR-0038 user decision 4): a stored secret or note starts empty and is kept
unless something is typed over it. So is section management in the editor (ui-spec.md §4.3): add
a section, rename it, delete it (its fields move to "no section" rather than being deleted),
reorder sections, and move a field between sections — all built on the FFI's existing
`Field`/`FieldDraft.Section` string, since neither the FFI nor macOS's own `ItemDraft` models a
section as anything more than that (macOS's `ItemEditView` in fact has no section UI at all yet,
despite ui-spec.md §4.3 calling for one — see `ViewModels/EditSectionViewModel.cs`'s doc comment).
Moving or relabelling a concealed field sends its value as "keep", so it never needs a release.

Setting up a TOTP field goes through a proper dialog (`Views/TotpSetupDialog.xaml`) rather than
raw-URI editing: manual entry (secret/issuer/account, advanced algorithm/digits/period) with a live
preview code, a raw-URI "advanced" tab matching macOS's `TotpSetupSheet`, and — Windows-only, since
macOS's own sheet has no QR import at all yet ("QR scanning is not here; see the roadmap's M5
notes") — importing a QR code from an image file or the clipboard, decoded with ZXing.Net (see the
`PackageReference` comment in `Kagisecure.App.csproj` for why) and never logged. The preview is
`Totp.Preview` over what is being typed, which the vault does not hold yet (ADR-0008 crossing 5),
so it asks for no presence. Over an existing field the dialog opens blank (ADR-0038 §5): "Change"
replaces the stored setup without showing it. There is no "Show current setup" on Windows yet — it
would be `ReleaseField(EditReveal)`, the edit sheet's per-field reveal ADR-0038 lists as not built
here.

What's stubbed: nothing on the item side. The recovery-code "write this down" page, Agent access,
approvals, Windows Hello and import are all wired — see "Import" and "Agent access, approvals and
Windows Hello" below. What is *not verified* rather than unbuilt (a real Windows Hello device, a
signed release, a fill from a real browser) is listed in
[docs/windows-port.md](../../docs/windows-port.md).

## Import

Import is wired into the UI (`Views/ImportPage.xaml(.cs)`, `ViewModels/ImportViewModel.cs`, the `Import*` members of
`Services/IVaultService`/`VaultService`), reachable from the sidebar's Import item
(`ShellPage.OnImportClicked`), and matches the macOS sheet (`apps/macos/Kagisecure/Views/ImportSheet.swift`)
except where noted below.

What's real: choose a `.1pux` or `.csv` file; the format is auto-detected, with a picker
(`ks.import.format`) to override it manually — 1PUX, Apple Passwords CSV, Chromium CSV, Firefox
CSV or 1Password CSV, whatever `Importer.Formats()` returns — which re-parses the same file under
the chosen format and shows the parser's own message (never file contents) if it does not match;
a preview against the open vault (totals, the duplicate-count sentence, by-category counts, the
three drop counters); a duplicate policy (skip/update/keep both) and a target-vault picker; a
per-item detail table (`ks.import.detailTable`) — one row per planned item with its title,
category (flagged when guessed), target vault, what committing would do to it, and what is being
left behind for it — filterable by action (`ks.import.itemFilter`); commit; then the
shred-or-keep prompt with the "best effort, not secure erase" caveat. Nothing on the screen is or
can be a secret value (import.md §1.1) — the FFI plan handle's only readable projection is the
report.

What's stubbed, and why: an item's action cannot be changed or excluded from the table before
committing. `ImportPlanHandle` (`Kagisecure.Interop/Import.cs`, backed by
`crates/kagisecure-ffi/src/capi/import.rs`) exposes only `Report()`, `SourcePath` and `IsSpent` —
there is no `kgs_import_plan_*` entry point to edit or drop one item from a parsed plan, only
`kgs_session_import_preview_against` (recomputes every row's action from the duplicate policy) and
`kgs_session_import_commit` (applies the whole plan). The table is therefore read-only and its
caption says so; the only per-run controls are the duplicate policy and the target vault, same as
the macOS sheet. Adding per-item overrides would be a new C ABI surface in `kagisecure-ffi`, not a
C# change.

## Agent access, approvals and Windows Hello

Agent access, the approval dialog and Windows Hello are all wired.

| Piece | Where | What it does |
| --- | --- | --- |
| Agent host | `Services/AgentHostService.cs`, `AgentRuntime.cs`, `AgentDispatcher.cs` | Starts the MCP listener and the browser-extension listener on unlock (always, like macOS; `KAGISECURE_SOCKET` / `KAGISECURE_EXTENSION_SOCKET` move them), polls `Agent.NextRequestAsync` on one cancellable background loop, keeps one sheet at a time, verifies each caller off the UI thread, retires requests whose 60 s window closed (answering Deny), polls `Agent.TakeLockRequest`, and stops both listeners from `IAgentVaultAccess.Locking` — raised by `VaultService.Lock()` *before* the session is disposed. |
| Approval sheet | `Views/ApprovalPresenter.cs`, `Views/ApprovalView.xaml`, `ViewModels/ApprovalViewModel.cs`, `ViewModels/ApprovalText.cs` | ui-spec.md §10 in its own always-on-top window, flashed in the taskbar. The `Authenticode:` verdict is a warning, never a gate. Allow needs Windows Hello (`Services/AgentConsentGate.cs`, `UserConsentVerifier` parented to the sheet); cancel/refusal grants nothing; if Hello is unavailable the master password is the fallback. Esc or closing the window is Deny. `ApprovalText` is the macOS sheet's sentence/summary/sanitizer, word for word. |
| Agent access pages | `Views/EnvironmentsPage`, `LeasesPage`, `McpSetupPage`, `BrowserExtensionPage`, `SecuritySettingsPage` (+ view models) | The sidebar's AGENT ACCESS group (`Views/ShellPage.AgentAccess.cs`) opens them over the list and detail panes. The browser page shows each manifest's path and its `HKEY_CURRENT_USER` key, and Set up/Remove go through `BrowserExtension.InstallManifest`/`UninstallManifest`. |
| Windows Hello unlock | `Services/WindowsHelloService.cs`, `WindowsHelloCrypto.cs`, `WindowsHelloPlatform.cs`, `VaultService.WindowsHello.cs`, `ViewModels/LockViewModel.WindowsHello.cs` | [ADR-0033](../../docs/decisions/0033-windows-hello-key-derivation.md): the vault key wrapped under `HKDF(Hello signature ‖ DPAPI secret)`, stored as the vault's platform slot. Turned on and off in Security; the lock screen offers "Unlock with Windows Hello" when the vault is enrolled, and prompts only when that button is pressed — never by itself, so a same-user process cannot time a look-alike prompt to one the user expects (ADR-0033 §5). Enabling it replaces the vault's one platform slot, so Security says whose slot is there (this PC, another PC, a Mac's Touch ID) and asks before overwriting. A dead slot (key deleted or replaced, secret gone) falls back to the password and asks to re-enrol. |
| Composition | `App.AgentAccess.cs` | Builds the above; `App.xaml.cs` calls it once before the window. |

**Stated plainly, as the app itself does (threat-model W-1):** Windows Hello keys belong to the
Windows user on this PC, not to kagisecure — another program running as you can use the same Hello
key and ask you to confirm. The DPAPI secret is mixed in so that Hello consent alone is not enough,
but DPAPI's current-user scope is not per-app either. Windows Hello unlock is weaker than Touch ID
on a Mac, and the Security page and the lock screen say so.

Tests (`Kagisecure.App.Tests`): `AgentHostServiceTests` (fake queue, fake consent, fake dispatcher —
consent refused or cancelled is never an Allow and ends as Deny, the timeout dismisses the sheet,
lock stops both listeners and denies what was waiting, the IPC lock request locks the vault, the
password fallback only after Hello says unavailable), `ApprovalTests`, and `WindowsHelloServiceTests`
(fake Hello keys that sign with a real RSA key, fake and real DPAPI — round trip, every buffer
cleared, a deleted/replaced credential or lost secret falls back to the password, and neither the
wrapped key nor any other secret reaches the log or a message). No test touches a real browser's
registry key: the fake runtime's manifests carry `RegistryKey = null`.

Checked end to end on Windows 11 26200 (the built exe with `KAGISECURE_VAULT` on a throwaway vault
under `target\` and a unique `KAGISECURE_SOCKET`/`KAGISECURE_EXTENSION_SOCKET`, unlocked through UI
Automation, requests sent through `target\debug\kagisecure-mcp.exe`): a `create_environment` call
raises the sheet with the quoted name and the `Authenticode:` evidence; Deny returns `USER_DENIED`;
on this PC, which has no Windows Hello device, Allow shows the master-password fallback and the
right password approves it (the environment is created and listed); an unanswered request returns
`APPROVAL_TIMEOUT` and the sheet dismisses itself; `kagisecure lock` locks the app and the sidecar
then gets `APP_NOT_RUNNING`. The sheet retires an expired request two seconds after `expires_at`
(`AgentHostService.ExpiryGraceSeconds`): retiring it at exactly `expires_at` was observed to beat
Rust's own timeout and tell the agent `USER_DENIED` instead of `APPROVAL_TIMEOUT`.

What was not exercised: a real Windows Hello prompt — this PC has no Hello device, and Hello cannot
be driven non-interactively anyway; the tests do not try to get around it. So Hello enrolment and
Hello unlock have been run only against fakes.

## Presence-gated releases (ADR-0038)

Merged on 2026-09-26 from `feat/vault-transactions`, where it was written on a Mac with no .NET
SDK; since built and run on Windows (see "Checked on Windows" below). The pieces:

- `Kagisecure.Interop/Presence.cs` — `IPresenceGate`, the `[UnmanagedCallersOnly]` bridge Rust
  calls, `FieldRelease` / `TotpRelease` / `NotesRelease`, `MasterPasswordCheck`.
- `Kagisecure.Interop/VaultSession.cs` — `SetPresenceGate`, `Release*`, `Lock`, `IsUnlocked`,
  `Sync`, `DeleteItem(id, revision)`, the rate-limited `VerifyMasterPassword`; `Dispose` locks
  first.
- `Kagisecure.App/Services/WindowsHelloPresenceGate.cs` — the gate (Windows Hello, then the master
  password only where Hello is unavailable), the app-wide `PresencePromptGuard`, and the
  password dialog.
- `Kagisecure.App/ViewModels/FieldRowViewModel.cs`, `ShellViewModel.cs`,
  `FieldDraftRowViewModel.cs`, `Views/ShellPage.xaml` — Reveal/Copy/"Show code"/"Show notes"
  through releases, hide on deselect/cap/lock, no prefilled secrets in the editor.
  The detail pane groups these rows into sections (`DetailSections`); a lock or deselect drops
  the grouped view with the rows, so nothing a release showed outlives them on screen.

Checked on Windows 11 26200 (the built exe, `KAGISECURE_VAULT` on a throwaway vault under
`target\`, driven through UI Automation): a saved one-time-password field shows `••• •••` and no
digits until **Show code**; on this PC, which has no Windows Hello device, **Show code** raises the
master-password fallback with Rust's sentence ("show the one-time code for “…”. Continue only if
you just asked Kagisecure to show it"); Cancel leaves the code masked, and the right password shows
the live code. The TOTP setup dialog's preview needs no confirmation (it derives from the seed being
typed). Not exercised: a real Windows Hello prompt, for the reason given above.


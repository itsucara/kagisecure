# ADR-0034: Windows ships as a per-user MSI, not MSIX — the package must not virtualize the writes `browser_setup.rs` already depends on

- **Status:** Accepted
- **Date:** 2026-09-25
- **Deciders:** Windows port, distribution
- **Refines:** [ADR-0025](0025-developer-id-for-local-builds.md),
  [ADR-0026](0026-helper-binaries-inside-the-app-bundle.md),
  [ADR-0028](0028-the-release-pipeline.md),
  [ADR-0032](0032-authenticode-peer-verification.md), [windows-port.md](../windows-port.md)

## Context

macOS has a release: `cargo xtask dist` builds, signs, notarizes, staples and packages a DMG
(ADR-0028). Windows has an app shell (`apps/windows/Kagisecure.App`, WinUI 3, currently
`WindowsPackageType=None`, framework-dependent on the Windows App Runtime) and a signing story for
runtime peer verification (ADR-0032), but nothing that produces something a stranger can download,
install and run. This ADR picks the package format and records the trade-offs; the accompanying
`cargo xtask dist-windows` implements it.

Three formats were on the table: MSIX, a per-user installer (WiX or Inno Setup), and a signed zip.

### What already constrains the choice

Two things this project has already built are load-bearing for whichever format is picked:

1. **`crates/kagisecure-agent/src/browser_setup.rs`** writes, at first-run/setup time (not install
   time), a JSON manifest under `%LOCALAPPDATA%\Kagisecure\NativeMessagingHosts\` naming the
   **absolute path** to `kagisecure-nmhost.exe`, and sets
   `HKCU\Software\<vendor>\NativeMessagingHosts\<host name>` to point at that manifest. Both
   operations run every time a user turns on a browser integration, by the running app, as the
   logged-in user, with no elevation. Chrome/Edge/Brave read the registry value and then read the
   manifest file's `path` field to find the executable to launch. If either write lands somewhere
   the browser process cannot see, or the path in the manifest stops being valid, native messaging
   silently never connects — there is no error dialog, because the browser has no reason to expect
   one.
2. **`crates/kagisecure-agent/src/bundle.rs::find`** resolves each helper's absolute path by, in
   order: an app-supplied hint directory, an env var, and — the step this decision leans on —
   **beside the running executable** (`std::env::current_exe()`'s parent). If every binary
   (`Kagisecure.App.exe`, `kagisecure_ffi.dll`, `kagisecure-mcp.exe`, `kagisecure-nmhost.exe`,
   `kagisecure.exe`) sits flat in one directory, this step finds all three helpers with **zero
   changes to `crates/`** — the macOS `Contents/Helpers` special-casing in `bundle.rs` (ADR-0026)
   has no Windows analogue to build, because there is no `Contents/MacOS` name collision on Windows
   in the first place (`bundle.rs`'s own test says so: `kagisecure.exe` no longer
   case-insensitively equals `Kagisecure` the way bare `kagisecure` does on APFS).

### MSIX's virtualization is a real risk to both

An MSIX package can enable registry and file-system virtualization for the app running inside it:
writes to keys like `HKCU\Software\...` are redirected into a per-package virtual registry hive
rather than the real `HKCU`, and — depending on manifest capabilities — some `%LOCALAPPDATA%`
writes can be redirected into the package's own virtual data store. An app can opt out per-key with
the `desktop6:RegistryWriteVirtualization="disabled"` capability (Windows App SDK / Desktop Bridge),
but that is a manifest capability declared at package-build time, for a specific key, not a general
"turn virtualization off" switch — and it still leaves the harder problem:

**The install location inside `WindowsApps` is not a stable, browser-reachable path.** A packaged
app runs from `C:\Program Files\WindowsApps\<PackageFamilyName>_<version>_<arch>__<publisherhash>\`
— a directory that is both access-restricted (ACL'd to the package's own identity and
administrators; an external browser process is neither) and versioned, so it *changes on every
update*. `browser_setup.rs` writes an absolute path into a manifest file **at setup time**; an
MSIX auto-update would silently invalidate that path on the next launch, and the manifest would
need to be rewritten by some other trigger the package format has to be taught (a background task,
a COM activator registered for exactly this purpose) rather than by the app's own existing
first-run code path. None of that exists today, and building it is real engineering for a format
this project is not otherwise choosing for any of its other benefits.

MSIX's actual benefits — Store distribution, an auto-update channel, cleaner uninstall telemetry —
are not decisions this release needs. There is no Store listing planned, and ADR-0028's own
precedent for macOS 0.1.0 was to ship with **no auto-update** and tell users to check the releases
page; Windows 0.1.0 can make the same call symmetrically rather than solving auto-update as a side
effect of picking a package format.

### The signed zip doesn't integrate

A signed zip (extract, run) sidesteps virtualization entirely — it is just files on disk, wherever
the user unzips them, and `bundle.rs`'s "beside the running executable" step finds every helper
exactly as it would from an installer's directory. What it does not give a user is anything
Windows treats as an installed application: no Start Menu entry, no Add/Remove Programs listing
(so no easy uninstall — the user has to know to delete a folder and separately reach the native
messaging registry keys `browser_setup.rs` wrote), and no upgrade path beyond "unzip over the old
one and hope nothing is still running." For a first release aimed at a stranger who downloaded
something, that is a worse experience than an installer for approximately the same engineering
cost, since the same signing and layout work has to happen either way. It remains useful as a
zero-friction fallback and is worth keeping in mind if a portable/no-install mode is ever asked
for, but it is not the first release's primary artifact.

## Decision

**A per-user WiX v5 MSI, installing flat into `%LOCALAPPDATA%\Programs\Kagisecure`, with no
admin/UAC prompt.**

- **`InstallScope="perUser"`** (`MSIINSTALLPERUSER=1`, `ALLUSERS` unset) — the same posture
  everything else on the Windows port already has: the named-pipe DACL and the vault/`.env`/import
  ACLs are all owner-only, single-user, no elevation (`docs/windows-port.md` §2 Tier 1). An
  installer that suddenly wants admin for the one step that puts files on disk would be the odd
  one out.
- **A flat install directory** — `Kagisecure.App.exe`, `kagisecure_ffi.dll`,
  `kagisecure-mcp.exe`, `kagisecure-nmhost.exe`, `kagisecure.exe`, and the self-contained WinUI/.NET
  runtime files the publish produces, all in one directory, no `Contents/Helpers`-style
  subdirectory. This is what makes `bundle.rs::find`'s existing "beside the running executable"
  step work with **no `crates/` changes** — see "What already constrains the choice" above. It is
  also what keeps the native-messaging manifest's path stable across an in-place MSI upgrade: WiX's
  major-upgrade pattern (same `UpgradeCode`, incrementing `ProductVersion`, `RemoveExistingProducts`
  scheduled after `InstallInitialize`) reinstalls into the **same** directory rather than a new
  versioned one, unlike MSIX's per-version `WindowsApps` folder.
- **Self-contained publish** (`WindowsAppSDKSelfContained=true`, `dotnet publish --self-contained
  -r win-x64`), not the framework-dependent build the repository currently has. A first release
  that fails to launch with "install the Windows App Runtime" on a clean machine is a worse first
  impression than a larger download. This is an additive, opt-in publish property — the existing
  `dotnet run`/`dotnet build` developer loop (`WindowsAppSDKSelfContained=false`,
  `WindowsPackageType=None`) is untouched; `dist-windows` passes the self-contained properties on
  the command line rather than changing the checked-in default, so a contributor's inner loop stays
  exactly as fast as it is today.
- **Every PE signed individually before packaging**: `kagisecure_ffi.dll`, `kagisecure-mcp.exe`,
  `kagisecure-nmhost.exe`, `kagisecure.exe`, `Kagisecure.App.exe`, then the `.msi` itself. This is
  not optional even though WiX can also sign the finished MSI: ADR-0032 says outright that "an MSIX
  signature covers the package, not the files inside it; a helper that is not itself signed is 'not
  signed' here" — the same sentence applies to an MSI wrapper, and the whole point of `verify_peer`
  reading `kagisecure_ffi.dll`'s own embedded signature (`SameSignerAsThisProcess`) is that the
  DLL's signature has to be real on disk, independent of whatever wraps it.
- **Certificate selection is generic**, matching ADR-0025's macOS precedent: `dist-windows` reads
  `KAGISECURE_SIGN_CERT_SHA1` (a thumbprint) or `KAGISECURE_SIGN_CERT_SUBJECT` (a subject-name
  match) from the environment, never a hardcoded name. Neither set → **unsigned build**, loudly
  announced, matching the macOS ad-hoc default (ADR-0011/ADR-0025) rather than failing silently or
  refusing to build at all — a contributor with no certificate can still produce and sanity-check a
  package.

## Consequences

**Positive**

- No `crates/` change was needed to make the helper search work — the flat layout is a packaging
  decision, not a code change, and it is the layout `bundle.rs::find`'s existing precedence order
  was already going to find without a hint.
- Per-user install/uninstall needs no admin prompt, matching the rest of the Windows port's
  no-elevation posture and making local testing (and CI, if it returns) straightforward.
- An in-place upgrade keeps the install directory stable, so the native-messaging manifest
  `browser_setup.rs` wrote does not silently go stale the way it structurally would under MSIX's
  per-version `WindowsApps` folders.
- The unsigned-by-default-with-a-loud-banner behavior mirrors the macOS ad-hoc default exactly, so
  a contributor's mental model transfers.

**Negative — accepted**

- **No Store distribution, no MSIX auto-update channel.** If Store presence or a managed
  update channel is wanted later, this is a second packaging effort, not a flag flip — MSIX's
  virtualization problem does not go away just because auto-update becomes desirable, and
  revisiting this decision at that point should re-examine whether `browser_setup.rs`'s
  registration needs to move to install time (a package-activated task) rather than staying
  first-run/setup-screen driven.
- **SmartScreen reputation is not solved by picking MSI over MSIX.** Either format, signed with a
  standard (non-EV) Authenticode certificate from a new publisher, is likely to show Windows
  Defender SmartScreen's "Windows protected your PC" interstitial until enough installs build
  reputation for that certificate. An EV certificate gets instant reputation; this project's
  certificate is unspecified generically (ADR-0025's pattern — nothing about a specific
  organisation's certificate tier is committed here), so this is stated as a known first-release
  rough edge rather than solved.
- **No auto-update in this release**, symmetric with macOS 0.1.0 (ADR-0028's own "Auto-update is
  still undecided" — Windows makes the same non-decision rather than picking a mechanism as a side
  effect of the package format).
- **Self-contained publish is a materially larger download** than the framework-dependent build the
  repository ships today for development, because it carries a private copy of the relevant .NET
  and Windows App SDK runtime files rather than depending on a machine-wide install. Accepted for
  the reason above; revisit if a Windows App Runtime bootstrapper becomes part of the installer
  later.
- **WiX v5 is fetched as a `dotnet tool`**, restored from a checked-in local tool manifest
  (`packaging/windows/.config/dotnet-tools.json`) rather than installed globally — this is a NuGet
  package restore, not new system-wide software, and is the one tool `dist-windows` is allowed to
  fetch on its own; `signtool` is not — see `xtask/src/dist_windows.rs`'s doc comment for what it
  does when either is missing.

### Alternatives considered

- **MSIX.** Rejected for this release for the virtualization and path-stability reasons above. Not
  rejected forever — if Store distribution or a managed update channel becomes a goal, this
  decision should be revisited together with moving native-messaging registration to install time.
- **Signed zip as the primary artifact.** Rejected: no Start Menu entry, no Add/Remove Programs
  uninstall, no upgrade story, for no packaging-effort savings over an installer given the signing
  and layout work is identical either way. Remains a plausible secondary "portable" artifact if
  asked for later.
- **A machine-wide (per-machine) MSI**, installing to `%ProgramFiles%`. Rejected: needs UAC/admin,
  which is inconsistent with the single-user, no-elevation posture the named-pipe DACL and file ACL
  work already established for this app (`docs/windows-port.md` §2 Tier 1), and buys nothing a
  single user's own machine needs.
- **Inno Setup instead of WiX.** Either would satisfy the per-user/flat-directory requirements above.
  WiX was picked because it is available as a `dotnet tool` (fits the "no system-wide install"
  constraint cleanly, restored the same way any other project tool is) and produces a real MSI,
  which Windows' own uninstall UI and enterprise deployment tooling understand natively; Inno
  Setup's installer is a bespoke `.exe` that neither speaks MSI nor installs without its own
  compiler being present on the machine (a separate, non-`dotnet`-tool-shaped download). Revisit
  if WiX's MSBuild/`dotnet build` integration turns out to be the wrong fit in practice.

## Addendum, 2026-09-25: an installer UI, and a generated (not submitted) winget manifest

Two of this ADR's own "known rough edges" — no installer wizard UI, no winget manifest — are
addressed as far as this repository's own tooling can take them, without reopening the per-user
MSI decision above.

**Installer UI.** `Product.wxs` now references `WixUI_InstallDir`
(`WixToolset.UI.wixext`) for the welcome/license/install-folder/progress/finish wizard, plus
`WixToolset.Util.wixext`'s `WixShellExec` custom action for a "Launch Kagisecure" finish-page
checkbox. Both extensions are pinned to `5.0.1` — the same release as the `wix` tool itself — and
restored by `dist_windows.rs` with `wix extension add` (no `-g`), which caches them under
`packaging/windows/.wix/extensions/`: a project-local, gitignored NuGet cache, the same
reproducible-restore posture ADR-0034's original text already committed to for the `wix` tool.
Nothing about this needed a second look at the per-user/no-elevation decision above:
`WixUI_InstallDir`'s install-folder page only lets the user choose *where under their own profile*
`%LOCALAPPDATA%\Programs\Kagisecure` differs, never a per-machine alternative — that would need
`WIXUI_SUPPORT_PERMACHINE`/`WIXUI_SUPPORT_PERUSER` properties this file deliberately never sets.

The license dialog's text — `License.rtf` — is generated, not checked in
(`xtask/src/license_rtf.rs`), by concatenating `LICENSE-MIT` and `LICENSE-APACHE` at build time
every `dist-windows` run. kagisecure is dual-licensed like the rest of the Rust ecosystem; the
alternative of checking in a hand-maintained RTF copy was rejected for the same reason the Swift
bindings are generated-and-committed-with-a-drift-check (ADR-0009) rather than hand-maintained
elsewhere in this repository — a second, independently-edited copy of licensing text is a copy that
drifts. Regenerating it every run instead of committing a copy sidesteps drift entirely rather than
merely detecting it, since (unlike the Swift bindings) nothing outside `dist-windows` itself ever
needs to read `License.rtf`.

One consequence worth naming: quiet installs are unaffected by any of this.
`msiexec /i Kagisecure.msi /quiet` runs only `InstallExecuteSequence`; the wizard dialogs and the
launch checkbox's `DoAction` event live in the UI sequence and `ExitDialog`'s `Publish` table
respectively, neither of which a quiet install enters. The same MSI, unmodified per-file, serves
both an interactive double-click and a scripted `/quiet` install exactly as it did before this
addendum.

**winget manifest — generated, still not submitted.** `cargo xtask winget-manifest --version
<x.y.z> --url <installer url>` (a separate task from `dist-windows`, since a manifest's
`InstallerUrl` cannot be known until the built MSI has actually been uploaded somewhere public)
reads the MSI `dist-windows` already built — its SHA-256 and its actual `ProductCode`, read off the
built artifact's own `Property` table via `WindowsInstaller.Installer` COM automation, since
`Product.wxs` does not pin a `ProductCode` and WiX assigns a fresh one every build — and writes the
three manifest YAML files (`version`, `installer`, `defaultLocale`; package identifier
`Itsucara.Kagisecure`, matching the publisher name the macOS Developer ID signing and Homebrew tap
already use) into `target/dist-windows/winget/<version>/`. `docs/releasing.md` §10.8 has the exact
commands, including local validation with `winget validate` (ships with Windows 11's App
Installer, no separate install) and the two ways a maintainer actually submits the result —
`wingetcreate submit` or a hand-opened PR — to `microsoft/winget-pkgs`.

This is deliberately not a submission mechanism: `microsoft/winget-pkgs` is a separate public
repository under Microsoft's own review process (including a first-time publisher identity check),
and nothing in this repository's tooling pushes to it, opens a PR against it, or holds credentials
for it. `winget install kagisecure` working end-to-end is still gated on a human running that
submission step once a real release exists to point the manifest at — the roadmap's Windows
acceptance criteria (`docs/roadmap.md`) are annotated to say exactly that: manifest generated, not
submitted.

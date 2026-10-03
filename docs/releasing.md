# Releasing kagisecure

Sections 1-9 are macOS. §10 is Windows — a different pipeline (`dist-windows`, not `dist`), a
different package format, and its own ADR; read §10 directly if that's what you're here for.

## macOS

The goal of a release is a DMG that a stranger can download, open, drag to Applications and
launch — with no right-click-Open, no `xattr` incantation, no "unidentified developer" dialog.
Everything here exists to reach that state and to prove it was reached.

The whole thing is one command:

```console
$ NOTARY_KEYCHAIN_PROFILE=<team>-notary cargo xtask dist
```

The rest of this document is what that command does, what it needs first, and how to tell whether
it worked. [ADR-0028](decisions/0028-the-release-pipeline.md) records why it is shaped this way.

---

## 1. Signing and notarization are two different things

Both are required, and Gatekeeper wants both.

**Signing** says who built it. It needs a *Developer ID Application* certificate, which needs a
paid Apple Developer Program membership — a free account only offers "Apple Development", which
cannot sign for distribution.

**Notarization** says Apple scanned it and found no malware. It needs credentials for the notary
service, and it takes minutes, sometimes half an hour.

`codesign` alone proves nothing about notarization, and `spctl` on an un-stapled app can pass by
asking Apple online — hiding the very failure you care about. §6 has the three checks that
together are the proof.

## 2. What you need on the machine, once

### 2.1 Toolchain

- Xcode 26 or later.
- `brew install xcodegen`.
- A Rust toolchain with **both** Apple targets. A release is universal
  ([ADR-0027](decisions/0027-universal-binaries.md)), so:

  ```console
  $ rustup target add aarch64-apple-darwin x86_64-apple-darwin
  ```

- `cargo install cargo-deny --locked`, which gates the release on licenses and advisories.

### 2.2 The Developer ID certificate

Once per machine. Generate the key and the CSR locally so the private key never leaves it:

```console
$ openssl genrsa -out devid.key 2048
$ openssl req -new -key devid.key -out devid.certSigningRequest \
    -subj "/emailAddress=you@example.com/CN=Your Org/C=JP"
```

Upload the CSR at developer.apple.com → Certificates → **Developer ID Application**. When it asks
which intermediate to use, pick **G2 Sub-CA**, not "Previous Sub-CA" — the latter is often
preselected and its certificates expire on 2027-02-01 regardless of when they were created.

Import the issued certificate together with the key. Apple's keychain rejects OpenSSL 3's default
PKCS#12 encryption, so ask for the legacy algorithms:

```console
$ openssl x509 -inform DER -in developerID_application.cer -out cert.pem
$ openssl pkcs12 -export -inkey devid.key -in cert.pem -out devid.p12 \
    -passout pass:temp -macalg sha1 -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES
$ security import devid.p12 -k ~/Library/Keychains/login.keychain-db -P temp -T /usr/bin/codesign
$ security find-identity -v -p codesigning        # confirm it appears
```

**Back up `devid.key`.** It cannot be reissued. Losing it means every future release has to move
to a new certificate — and macOS ties permission grants to the code signature, so every existing
install would have to grant them again.

### 2.3 The notarization credential

Once per team. The Apple ID has two-factor authentication, which a CLI cannot complete, so
`notarytool` needs an app-specific password stored in the keychain:

```console
$ xcrun notarytool store-credentials "<team>-notary" \
    --apple-id "you@example.com" --team-id "XXXXXXXXXX"
```

It prompts for the app-specific password, which is created at appleid.apple.com → Sign-In and
Security → App-Specific Passwords.

The name `<team>-notary` is a convention, not a requirement — whatever you choose is what goes in
`NOTARY_KEYCHAIN_PROFILE`. **Both the certificate and the credential are per team, not per app.**
One of each signs and notarizes everything the team ships; do not create them per project.

On this Mac, the account-wide profile for Team 4CZNJKU58K is named `koemoji-notary`. It is not
specific to kagisecure — it is documented, alongside the machines and accounts it applies to, in
the owner's release-ops repository. Check an existing profile works with `notarytool history`
before assuming it needs to be created again.

Check it works before you need it:

```console
$ xcrun notarytool history --keychain-profile "<team>-notary"
```

### 2.4 The Sparkle update key

Once, ever — the app's self-update ([ADR-0044](decisions/0044-self-update-with-sparkle.md)) trusts
exactly one EdDSA key, and every installed copy carries its public half. `cargo xtask dist`
resolves the Sparkle package, so after one run (even a failed one) the tools are under
`dist/DerivedData/SourcePackages/artifacts/sparkle/Sparkle/bin/`:

```console
$ generate_keys --account com.kagisecure.app          # creates it in the login keychain
$ generate_keys --account com.kagisecure.app -x sparkle-private-key   # back it up, offline
```

**Losing the private key means no installed copy can ever update itself again**; leaking it means
anyone who can also serve `kagisecure.com/mac/` can push code to every user. Keep the backup
where `devid.key` is kept. `dist` reads the public key from the keychain at build time and never
writes it into the tree.

## 3. Before you build

- `git status` is clean and you are on the commit you mean to release.
- `CHANGELOG.md` has a section for the version, and it is written for users rather than for
  reviewers.
- The version is right in `Cargo.toml` `[workspace.package]`. `apps/macos/project.yml` repeats it
  as `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` because XcodeGen cannot read a `Cargo.toml`;
  `cargo xtask version` fails if the three disagree; run it locally before a release (it ran in CI
  on every push until CI was removed on 2026-09-19).
- The gates are green:

  ```console
  $ cargo fmt --all --check
  $ cargo clippy --workspace --all-targets -- -D warnings
  $ cargo test --workspace
  $ cargo deny check
  $ make macos-test
  $ (cd extensions/chrome && npm test)
  $ make e2e
  ```

## 4. The release

```console
$ export NOTARY_KEYCHAIN_PROFILE="<team>-notary"
$ cargo xtask dist
```

Everything lands in `dist/`, which is gitignored:

| File | What it is |
| --- | --- |
| `dist/Kagisecure.app` | the signed, notarized, stapled app |
| `dist/Kagisecure.dmg` | what you upload |
| `dist/Kagisecure.zip` | the submission archive; `notarytool` cannot take a directory |
| `dist/DerivedData/` | a build directory of its own, so a Release never picks up a Debug object file |

Useful flags:

- `--skip-notarize` — build, sign and verify, but do not talk to Apple. This is how to check that
  a change did not break packaging, and it needs no Apple credential at all. The artifacts it
  produces are **not** shippable: `spctl` will say `rejected / source=Unnotarized Developer ID`,
  which is correct and is the point.
- `--host-only` — one architecture instead of two, for a much faster loop. Never for a release.

`KAGISECURE_TEAM_ID` overrides the team, which `dist` otherwise reads out of the Developer ID
certificate in the keychain. Nothing about a specific team or organisation is committed to this
repository; `"Developer ID Application"` is matched generically, so a fork signs with its own by
doing nothing.

### What it does, in order

1. `cargo xtask version` — the three places the number is written must agree.
2. Generate the app icon if it is missing (`apps/macos/Scripts/make-icon.sh`, from
   `apps/macos/Artwork/icon-1024.png`). After changing the artwork, delete
   `apps/macos/Kagisecure/Resources/Kagisecure.icns` so the release picks it up.
3. `bindgen --universal` — the Rust static library for both architectures, `lipo`d, plus the Swift
   bindings and the xcframework. This and step 4 build with `--remap-path-prefix`, mapping the
   home directory to `~` and the checkout to `.`, so no absolute path from the build machine
   ends up in a shipped binary.
4. `helpers --release --universal` — `kagisecure-mcp`, `kagisecure-nmhost` and the `kagisecure`
   CLI, both architectures, `lipo`d, staged in `target/helpers/Release/`.
5. `xcodegen generate`, then `xcodebuild -configuration Release` with the Developer ID identity,
   `ARCHS="arm64 x86_64"`, `--timestamp` and **`CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`**.
   The AutoFill credential provider extension is signed with
   `apps/macos/Signing/CredentialProvider.Provisioned.entitlements` (the restricted
   `autofill-credential-provider` entitlement) and its Developer ID provisioning profile, named
   by its Name: `Kagisecure CredentialProvider Developer ID` by default, `KAGISECURE_CP_PROFILE`
   to override (`CP_PROFILE` for `make macos SIGN=developer-id`). The profile must be installed
   (double-click it, or put it in `~/Library/MobileDevice/Provisioning Profiles/`) and cover
   App ID `com.kagisecure.app.credential-provider` with the AutoFill capability and the App
   Group ([ADR-0045](decisions/0045-system-wide-autofill-credential-provider.md)). Without it the build fails rather than ship an extension
   macOS will not offer.
   The **app itself** needs the same AutoFill entitlement, or macOS silently hides the
   extension (Settings lists only Apple Passwords): it is signed with
   `apps/macos/Signing/App.Provisioned.entitlements` and a second Developer ID profile, `Kagisecure
   App Developer ID` by default (`KAGISECURE_APP_PROFILE` / `APP_PROFILE` to override), for App ID
   `com.kagisecure.app` with the AutoFill Credential Provider capability enabled.
6. `cargo xtask embed` — copy the three helpers into `Contents/Helpers`, sign each under the
   Hardened Runtime with `apps/macos/Signing/Helper.entitlements`, then re-sign the app around
   them. Inside-out, because adding a file to a signed bundle invalidates its seal
   ([ADR-0026](decisions/0026-helper-binaries-inside-the-app-bundle.md)).
7. Assert that **no** Mach-O in the bundle carries `com.apple.security.get-task-allow`.
8. `codesign --verify --deep --strict`, and an `Authority=`, a hardened-runtime flag and a
   `Timestamp=` on every Mach-O.
9. Submit the zipped `.app`, wait, and **staple the ticket to the app**.
10. Build the DMG around the already-stapled app, and sign the DMG itself with the same Developer
    ID identity. `hdiutil create` leaves the image unsigned; an unsigned DMG still notarizes (the
    ticket covers the app inside), but `spctl -t open --context context:primary-signature` then
    finds no usable signature on the container and rejects it.
11. Submit the DMG, wait, staple that too.
12. Verify both artifacts three ways, and print the DMG's SHA-256.

## 5. Why the app is notarized separately, before the DMG

It is tempting to notarize only the DMG — one submission, one staple, done. Do not.

The bundle a user actually runs is the copy they dragged out of the mounted image, and that copy
carries no ticket of its own. It still launches, but Gatekeeper has to ask Apple over the network
the first time, which fails on a plane, on a locked-down network, or when Apple is having a bad
afternoon. Stapling the app first and then wrapping it gives every copy its own ticket. The second
submission is cheap: the notary has already seen that cdhash.

## 6. Verification — all three, every time

`cargo xtask dist` runs these and prints the output. Run them again by hand on the downloaded
artifact, on a Mac that has never seen the app, before you tell anyone it is out.

```console
$ codesign -dv --verbose=4 dist/Kagisecure.app 2>&1 | grep Authority
#   → Authority=Developer ID Application: YOUR ORG (TEAMID)

$ spctl -a -vv -t install dist/Kagisecure.app
#   → accepted, source=Notarized Developer ID

$ spctl -a -vv -t open --context context:primary-signature dist/Kagisecure.dmg
#   → accepted, source=Notarized Developer ID

$ xcrun stapler validate dist/Kagisecure.app
$ xcrun stapler validate dist/Kagisecure.dmg
#   → The validate action worked!
```

And the thing all of that is a proxy for: copy the app out of the mounted DMG into
`/Applications`, `open -a Kagisecure`, and watch it start with no dialog.

## 7. When it goes wrong

Read the notary log before changing anything. Guessing wastes a submission:

```console
$ xcrun notarytool log <submission-id> --keychain-profile "<team>-notary"
```

| Symptom | Cause |
| --- | --- |
| `The executable requests the com.apple.security.get-task-allow entitlement` | Xcode injected its base entitlements. `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`, which `dist` passes — and step 7 above catches it before a submission is spent. Building Release is **not** sufficient on its own. |
| `The signature does not include a secure timestamp` | Signed without `--timestamp`. |
| `The binary is not signed with a valid Developer ID certificate` | An Apple Development or ad-hoc identity leaked into the build. |
| Nested binary rejected | Something in the bundle is unsigned. Every Mach-O — helpers, the `.appex`, dylibs — must be signed inside-out under the Hardened Runtime. |
| Submission sits `In Progress` for 30+ minutes | Usually Apple's queue. Past an hour, suspect their side rather than yours. |
| The app launches into a CLI's usage text | A helper was embedded into `Contents/MacOS` and overwrote the app binary, because the filesystem is case-insensitive. See [ADR-0026](decisions/0026-helper-binaries-inside-the-app-bundle.md). |

**Permissions reset when the signature changes.** macOS ties Accessibility and Screen Recording
grants to the code signature, so anyone who ran a locally built copy has to grant them again to
the signed release. Say so in the release notes; no updater can avoid it.

## 8. Publishing

Building the DMG and publishing it are separate decisions. `cargo xtask dist` never publishes
anything.

1. Tag: `git tag -a v0.1.0 -m "v0.1.0"` and push the tag.
2. Create the GitHub release for the tag (`gh release create v0.1.0`). There is no CI workflow;
   the release is built locally with `cargo xtask dist`.
3. Attach `Kagisecure.dmg` and its `.sha256`.
4. Update `packaging/homebrew/kagisecure.rb` with the SHA-256 of the DMG **that was actually
   uploaded** — a code signature contains a timestamp, so a local rebuild has different bytes and
   a different checksum — and submit it to homebrew/homebrew-cask.

5. Upload the Sparkle feed `dist/mac-updates/` so that it is served at
   `https://kagisecure.com/mac/` — **the archive first, the feed last**, so the feed never names an
   archive that is not there yet:

   ```text
   dist/mac-updates/releases/Kagisecure-<version>.zip  ->  https://kagisecure.com/mac/releases/
   dist/mac-updates/appcast.xml                        ->  https://kagisecure.com/mac/appcast.xml
   ```

   Serve `appcast.xml` with `Cache-Control: no-cache` and the archives as immutable. `dist` read
   the live feed before adding to it, so the uploaded one keeps the last five releases. Every
   installed copy checks within the hour and, if it finds the update at launch, installs it
   without asking (ADR-0044). Check afterwards that
   `curl -s https://kagisecure.com/mac/appcast.xml` lists the new version.

6. If the browser extension changed, build `cargo xtask chrome-package` and upload it to the
   Chrome Web Store item ([chrome-web-store.md](chrome-web-store.md) §7). The extension's version
   is the app's version, so every app release that bumps it can ship an extension update too.

The DMG's filename has no version in it, on purpose, so that
`https://github.com/itsucara/kagisecure/releases/latest/download/Kagisecure.dmg` is a permanent
"always latest" link for a download button and for Homebrew's `livecheck`.

## 9. The command-line tool

The CLI ships inside the bundle at
`/Applications/Kagisecure.app/Contents/Helpers/kagisecure`, so it is signed and notarized with
everything else but is not on `PATH`. To put it there:

```console
$ ln -sf /Applications/Kagisecure.app/Contents/Helpers/kagisecure /usr/local/bin/kagisecure
```

The Homebrew cask does this for all three helpers automatically. There is deliberately no
"Install command-line tool" button in Settings: writing to `/usr/local/bin` needs an authorization
prompt and a privileged helper, which is a lot of new surface in a security-sensitive app for
something one `ln -s` does.

`kagisecure mcp path` resolves the bundled sidecar without any of this — it looks inside an
installed `Kagisecure.app` before it looks at `PATH`.

## 10. Releasing for Windows

The Windows release is a per-user MSI: everything flat in one install directory, no admin/UAC
prompt, no MSIX. [ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md) records
why — in short, MSIX's registry/file virtualization is a real risk to the two things
`crates/kagisecure-agent/src/browser_setup.rs` already depends on: an `HKCU` write that has to
land in the *real* registry a browser reads, and an absolute path that has to stay valid across an
update. A flat per-user install sidesteps both, and needs no change to `crates/` at all — see the
ADR for exactly why.

The whole thing is one command, on Windows:

```console
> cargo xtask dist-windows
```

### 10.1 What you need on the machine, once

- **A Rust MSVC toolchain** — `rustup default stable-x86_64-pc-windows-msvc` (or the `aarch64`
  equivalent on an ARM machine).
- **.NET SDK 8.0.4xx** — `apps/windows/global.json` pins the feature band.
- **The Windows SDK's Signing Tools for Desktop Apps** (`signtool.exe`) — only if you intend to
  sign. Install it via the Visual Studio Installer's Individual Components tab, or the standalone
  Windows SDK installer at <https://developer.microsoft.com/windows/downloads/windows-sdk/>.
  `dist-windows` looks for it on `PATH` and under every `...\Windows Kits\10\bin\<version>\<arch>`
  it can find, and never installs it for you — if it is missing, the error names exactly this
  paragraph.
- **Nothing else to install for packaging.** `dist-windows` restores the WiX v5 `dotnet tool` on
  its own, from the manifest checked in at `packaging/windows/.config/dotnet-tools.json` — a NuGet
  package restore, not new system-wide software.

### 10.2 The certificate

Unlike macOS, this task never searches "the one Developer ID certificate in the keychain" — a
Windows certificate store commonly holds several code-signing-capable certificates with no single
obvious choice, so the certificate is named explicitly, generically, the same way ADR-0025 keeps
any specific organisation's name out of the macOS pipeline:

```console
> $env:KAGISECURE_SIGN_CERT_SHA1 = "<the certificate's SHA-1 thumbprint>"
> cargo xtask dist-windows
```

or, by subject instead of thumbprint:

```console
> $env:KAGISECURE_SIGN_CERT_SUBJECT = "<the certificate's subject name>"
> cargo xtask dist-windows
```

Find the thumbprint of a certificate already in your user certificate store with:

```console
> Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Format-List Subject, Thumbprint
```

`KAGISECURE_TIMESTAMP_URL` overrides the RFC 3161 timestamp authority `signtool` calls
(`http://timestamp.digicert.com` by default) — change it if your certificate's issuer runs its
own, or if the default one is unreachable from your network.

**With neither variable set, `dist-windows` still runs — and produces an UNSIGNED MSI.** It says so
loudly, both while it runs and in its final summary, the same way an ad-hoc macOS build is the
default rather than a refusal (ADR-0011/ADR-0025). This is how a contributor with no certificate
checks that a change did not break packaging; it is not a release.

### 10.3 What it does, in order

1. **`cargo xtask version`** — the same Cargo.toml/`CHANGELOG.md` check `dist` runs on macOS.
   (`apps/macos/project.yml`'s `MARKETING_VERSION` is part of that check too, even on a Windows
   run — it is the one source of truth for the version number on every platform.)
2. **Build `kagisecure-mcp`, `kagisecure-nmhost` and the `kagisecure` CLI**, release, for this
   machine's Windows target.
3. **`cargo xtask bindgen-cs --release`** — `kagisecure_ffi.dll` with the `capi` C ABI.
4. **`dotnet publish` `apps/windows/Kagisecure.App`**, `-c Release -r win-x64 --self-contained
   true`, with `WindowsAppSDKSelfContained=true` — a self-contained publish, not the
   framework-dependent build the checked-in project defaults to for `dotnet run`. These are
   command-line MSBuild properties this task passes; the checked-in `.csproj` is untouched, so the
   contributor inner loop (`dotnet run`, no Windows App Runtime prerequisite question to answer)
   is exactly as fast as before.
5. **Assemble one flat layout directory**: the publish output, plus the three helpers, plus
   `kagisecure_ffi.dll`, all in the same directory, no subdirectory for any of them. This is what
   lets `kagisecure_agent::bundle::find`'s "beside the running executable" step locate every
   helper with zero code changes (ADR-0034).
6. **Sign every PE this project builds** — `kagisecure_ffi.dll`, `kagisecure-mcp.exe`,
   `kagisecure-nmhost.exe`, `kagisecure.exe`, `Kagisecure.App.exe` — with `signtool sign /fd sha256
   /tr <url> /td sha256`, individually, before packaging. Not optional even though `signtool` can
   also sign the finished MSI: [ADR-0032](decisions/0032-authenticode-peer-verification.md) reads
   `kagisecure_ffi.dll`'s *own* embedded signature at runtime to answer "is this caller signed by
   the same key as this app", and a helper that is only covered by the MSI's own signature is "not
   signed" as far as that check is concerned — or skips this step entirely, loudly, if no
   certificate is configured.
7. **Restore the WiX UI and Util extensions** (`WixToolset.UI.wixext`, `WixToolset.Util.wixext`,
   pinned to `5.0.1` — the same release as the `wix` tool itself), the same reproducible way as the
   tool: `wix extension add`, run without `-g` so it caches under
   `packaging/windows/.config`-adjacent `packaging/windows/.wix/extensions/` rather than
   machine-wide.
8. **Generate `packaging/windows/License.rtf`** from `LICENSE-MIT` and `LICENSE-APACHE` at the
   repository root (`xtask/src/license_rtf.rs`) — never checked in, regenerated every run, so the
   installer's license dialog can never show stale text.
9. **`wix build`** the MSI (`packaging/windows/Product.wxs`) around the layout directory — per-user
   install (`Scope="perUser"`, no admin), everything under
   `%LOCALAPPDATA%\Programs\Kagisecure`, a Start Menu shortcut, and the welcome/license/
   install-folder/progress/finish wizard from `WixUI_InstallDir` (§10.7 below) — then sign the MSI
   itself the same way.
10. **Verify** every signature with `signtool verify /pa`, when anything was signed, and print the
    MSI's SHA-256.

Everything lands in `dist\windows\`, which is gitignored exactly like `dist/` on macOS.

### 10.4 Verification

```console
> signtool verify /pa dist\windows\Kagisecure.msi
> signtool verify /pa dist\windows\layout\kagisecure_ffi.dll
> certutil -hashfile dist\windows\Kagisecure.msi SHA256
```

To confirm the installer UI (§10.7) actually made it into the built MSI — useful after touching
`Product.wxs`, since a missing `-ext` or a typo'd `UIRef` fails silently into "no dialogs" rather
than a build error — read the MSI's own `Dialog` and `CustomAction` tables with the
`WindowsInstaller.Installer` COM object (no extra tool: this ships with Windows):

```powershell
> $installer = New-Object -ComObject WindowsInstaller.Installer
> $db = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @("dist\windows\Kagisecure.msi", 0))
> $view = $db.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $db, @("SELECT Dialog FROM Dialog"))
> $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)
> while ($r = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)) { $r.GetType().InvokeMember("StringData", "GetProperty", $null, $r, 1) }
```

should list `WelcomeDlg`, `LicenseAgreementDlg`, `InstallDirDlg`, `VerifyReadyDlg`, `ProgressDlg`
and `ExitDialog` — the `WixUI_InstallDir` dialog set. The same technique against
`SELECT Action FROM CustomAction` should list `LaunchApplication` (the "Launch Kagisecure" finish-
page checkbox's custom action). `cargo xtask winget-manifest` (§10.8) reads this same MSI's
`ProductCode` the same way, in code, rather than by hand.

And the thing all of that is a proxy for: install it, launch the app, close it, uninstall it, and
check nothing was left behind — §10.5.

### 10.5 Installing, and what "installed" looks like

No admin prompt: `Scope="perUser"` in the MSI means Windows installs it entirely under this user's
profile.

```console
> msiexec /i dist\windows\Kagisecure.msi /quiet
```

installs to `%LOCALAPPDATA%\Programs\Kagisecure\` — `Kagisecure.App.exe`, `kagisecure_ffi.dll`,
`kagisecure-mcp.exe`, `kagisecure-nmhost.exe`, `kagisecure.exe`, and the self-contained .NET/Windows
App SDK runtime files, all in that one directory — plus a Start Menu shortcut. Nothing under
`%LOCALAPPDATA%\Kagisecure\` (the native-messaging manifests) or the
`HKCU\Software\<vendor>\NativeMessagingHosts\...` registry keys exists yet at this point: those are
written by the app's own setup screen the first time a browser integration is turned on
(`browser_setup.rs`), not by the installer — registration is a first-run action, deliberately, so
that reinstalling or upgrading the app never has to duplicate the logic that decides which browsers
are present.

```console
> msiexec /x dist\windows\Kagisecure.msi /quiet
```

removes the install directory and the Start Menu shortcut. It does **not** touch anything
`browser_setup.rs` wrote to `%LOCALAPPDATA%\Kagisecure\` or the registry — by the same
first-run/setup-screen reasoning above, uninstalling the app is not the same action as turning off
a browser integration, and the setup screen's own "remove" path is what undoes its own writes.

### 10.6 The command-line tool

The CLI ships inside the install directory at
`%LOCALAPPDATA%\Programs\Kagisecure\kagisecure.exe`, signed the same way as everything else, but is
not on `PATH` — the installer does not add it, mirroring the macOS decision in §9 not to write
anywhere outside the app's own directory automatically. Add it to your user `PATH` if you want it
there:

```console
> [Environment]::SetEnvironmentVariable("Path", "$env:Path;$env:LOCALAPPDATA\Programs\Kagisecure", "User")
```

`kagisecure mcp path` resolves the installed sidecar without any of this, the same as on macOS.

### 10.7 The installer wizard

A double-clicked `Kagisecure.msi` now shows a real wizard, not just `msiexec`'s bare progress bar:
welcome → license (both `LICENSE-MIT` and `LICENSE-APACHE`, generated into one `License.rtf` —
§10.3 step 8) → install folder (defaults to `%LOCALAPPDATA%\Programs\Kagisecure`, editable, but
still per-user — the browse dialog changes *where under this user's profile* it installs, never
*who* it installs for) → progress → finish, with a checked-by-default "Launch Kagisecure" box.
This is `WixUI_InstallDir`, the WiX UI extension's stock per-user dialog set, plus the Util
extension's `WixShellExec` custom action for the launch checkbox — both wired in
`packaging/windows/Product.wxs`, restored the same reproducible, no-global-install way as the
`wix` tool itself (§10.3 step 7). `docs/decisions/0034-windows-distribution-a-per-user-signed-msi.md`'s
2026-09-25 addendum has the choice of dialog set and why the launch checkbox needed the Util
extension too, not just UI.

**Silent installs are unaffected.** `msiexec /i Kagisecure.msi /quiet` runs the MSI's
`InstallExecuteSequence` only; the wizard dialogs and the `LaunchApplication` custom action both
live in `InstallUISequence`/`ExitDialog`'s `Publish` event, which a quiet install never enters. The
same MSI serves an interactive double-click and a scripted `/quiet` install without a build-time
choice between them, exactly as before this file gained a UI.

### 10.8 winget

`cargo xtask winget-manifest --version <x.y.z> --url <installer url>` generates the three package
manifest YAML files `winget install kagisecure` needs — version, installer, defaultLocale, under
package identifier `Itsucara.Kagisecure` — into `target/dist-windows/winget/<version>/`. It reads
`dist/windows/Kagisecure.msi` (run `dist-windows` first) for its SHA-256 and its actual
`ProductCode` (read from the built MSI's own `Property` table, the same COM technique §10.4 shows
for `Dialog`/`CustomAction`, since `Product.wxs` does not pin one — WiX assigns a fresh GUID every
build). `--url` is the public URL the built `Kagisecure.msi` will be downloadable from once
uploaded — this task does not upload anything, it only needs to know where it will end up:

```console
> cargo xtask dist-windows
> # upload dist\windows\Kagisecure.msi to the GitHub release as Kagisecure.msi, then:
> cargo xtask winget-manifest --version 0.1.0 --url https://github.com/itsucara/kagisecure/releases/download/v0.1.0/Kagisecure.msi
```

**This does not submit anything.** `microsoft/winget-pkgs` is a separate public repository this
project does not push to automatically. To actually publish a submission, a maintainer either:

- runs [`wingetcreate`](https://github.com/microsoft/winget-create) against the generated files —
  `wingetcreate submit --token <a GitHub PAT with public_repo> target\dist-windows\winget\0.1.0\Itsucara.Kagisecure.installer.yaml`
  (it reads the sibling version/defaultLocale files from the same directory and opens the PR for
  you), or
- copies the three files by hand into a clone of `microsoft/winget-pkgs` at
  `manifests/i/Itsucara/Kagisecure/<version>/` and opens a pull request the normal GitHub way.

Either way, validate locally first — `winget validate` ships with Windows 11's App Installer and
needs no install of its own:

```console
> winget validate target\dist-windows\winget\0.1.0
```

A first submission also needs `Itsucara.Kagisecure` to not already exist in `winget-pkgs`, and (per
that repository's own review process) a publisher identity check the first time a new publisher
submits — neither of which this task can do for you.

### 10.9 Known rough edges in this first release

- **No auto-update**, symmetric with macOS 0.1.0 — check the releases page or re-run the installer
  for a new version.
- **SmartScreen.** A standard (non-EV) Authenticode certificate from a new publisher is likely to
  trigger Windows Defender SmartScreen's "Windows protected your PC" interstitial until enough
  installs build reputation for that certificate, regardless of MSI vs. any other format. Signing
  is still worth doing — ADR-0032's peer verification depends on it entirely — but it does not by
  itself make the download experience friction-free on day one.
- **winget manifest generated, not submitted.** §10.8's `cargo xtask winget-manifest` produces
  files that pass local `winget validate`, but `winget install kagisecure` only works once a
  maintainer actually submits them to `microsoft/winget-pkgs` and that PR is merged — an out-of-band
  step with its own review process, not something this repository's tooling can complete on its
  own.

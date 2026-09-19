# Releasing kagisecure for macOS

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
    -subj "/emailAddress=you@example.com/CN=Your Org/C=US"
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

Before creating a profile, check whether one already exists and works — `notarytool history`
succeeds against it — since a team usually needs only one.

Check it works before you need it:

```console
$ xcrun notarytool history --keychain-profile "<team>-notary"
```

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

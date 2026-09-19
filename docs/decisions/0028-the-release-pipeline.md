# ADR-0028: The release is one command, and the order in it is not the obvious one

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M7 implementation
- **Refines:** [ADR-0025](0025-developer-id-for-local-builds.md)

## Context

[ADR-0025](0025-developer-id-for-local-builds.md) added `make macos SIGN=developer-id` and was
explicit about what it did not do:

> **`CONFIG` defaults to `Debug`, which carries `com.apple.security.get-task-allow`.** Apple
> rejects that entitlement at notarization […] M7 owns the rest of that pipeline (notarization,
> stapling, the DMG). Nothing here notarizes anything.

A release is eleven steps whose order matters and three of which are easy to get subtly wrong in a
way that only shows up on somebody else's Mac. Written as a runbook, it would be followed
correctly about as often as runbooks are.

## Decision

**`cargo xtask dist` is the release.** One command, in Rust, in the repository, alongside the
`bindgen` task that was already there — [architecture.md](../architecture.md) §7 picks `cargo
xtask` over "a Makefile or a pile of shell scripts", and this is the piece that would otherwise
have become the pile. `make release` is a one-line wrapper for people who type `make`.

[docs/releasing.md](../releasing.md) is the prose version, for a reader who wants to know what the
command does before they run it.

### The order, and why it is that order

1. **`cargo xtask version`** — Cargo.toml, `project.yml` and `CHANGELOG.md` must agree. Cheap, and
   a release with the wrong number in the About window is not fixable after the fact.
2. **Build Release**, with `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`. See below.
3. **Embed the helpers and sign inside-out** ([ADR-0026](0026-helper-binaries-inside-the-app-bundle.md)).
4. **Assert no `get-task-allow`** anywhere in the bundle, before anything is submitted.
5. **Verify the signature** — `codesign --verify --deep --strict`, plus an `Authority=`, a
   `runtime` flag and a `Timestamp=` on every Mach-O.
6. **Notarize the `.app`** — zipped, because `notarytool` cannot take a directory — and **staple
   the ticket to it**.
7. **Build the DMG around the already-stapled app.**
8. **Notarize the DMG** and staple that too.
9. **Verify all three ways** on both artifacts: `codesign`, `spctl`, `stapler validate`.
10. **Print the SHA-256** of the DMG, which is what the Homebrew cask needs.

**Steps 6 and 7 are the counter-intuitive pair.** It is tempting to notarize only the DMG: one
submission, one staple, done. That leaves the app itself without a ticket — and the bundle a user
actually runs is the copy they dragged out of the mounted image, which carries no ticket of its
own. It still launches, but Gatekeeper has to ask Apple over the network the first time, which
fails on a plane, on a locked-down network, or when Apple is having a bad afternoon. Stapling the
app first and then wrapping it gives every copy its own ticket, and the second submission is cheap
because the notary has already seen that cdhash.

### `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`, which is new evidence

ADR-0025 said the problem with `get-task-allow` was the Debug configuration. **That is not
sufficient.** Measured here: a `-configuration Release` build, signed with the Developer ID
identity, came out with

```xml
<key>com.apple.security.get-task-allow</key><true/>
```

in the app's entitlements, because Xcode *injects* its base entitlements on top of the entitlements
file, and that injection is on by default. Building Release does not turn it off; the build setting
does. Apple rejects the entitlement at notarization every time, so this would have cost a
submission and twenty minutes to discover from the notary log.

Step 4 exists so that it costs a second instead. It reads the entitlements off every Mach-O in the
bundle and refuses to submit if any of them carries it.

### `pipefail` is not used to check a signature

The idiom this pipeline deliberately does not contain:

```bash
codesign -dvv "$APP" 2>&1 | grep -q '^Authority=Developer ID Application'
```

`grep -q` exits at the first match and closes the pipe while `codesign` is still writing; the
writer takes `SIGPIPE`, the pipeline exits 141, and under `set -o pipefail` a correctly signed
build is reported as unsigned — about half the time, depending on which process wins the race. So
`xtask::util::capture` runs the command, captures its output, and searches the string afterwards.
There is no pipe.

### Credentials are named, never held

`xcrun notarytool submit --keychain-profile "$NOTARY_KEYCHAIN_PROFILE"`. The environment variable
holds the *name* of a keychain profile; the Apple ID and the app-specific password behind it are
put there once, by the person releasing, with `xcrun notarytool store-credentials`. Nothing in this
repository has ever contained a credential, and `dist` fails with the exact command to run when the
variable is unset.

A GitHub Actions `release.yml` originally built the same profile on a runner from secrets. It was
removed on 2026-09-19 together with all CI; releases are built locally only.

### The DMG's filename has no version in it

`Kagisecure.dmg`, not `Kagisecure-0.1.0.dmg`, so that

    https://github.com/itsucara/kagisecure/releases/latest/download/Kagisecure.dmg

is a permanent "always latest" link — which is what a download button and Homebrew's `livecheck`
both want. A versioned filename breaks that URL every release. The version is already in the git
tag, the release page, the About window and `Info.plist`; a fifth copy in the filename buys nothing
and creates a stale-file hazard in `dist/`.

The name is the app's **display** name, capitalised, exactly: `Kagisecure.app` → `Kagisecure.dmg`.
The lowercase namespace — `kagisecure` the CLI, the crates, `com.kagisecure.app` — is a different
one, and mixing them is the usual source of confusion about which is right.

## Consequences

**Positive**

- The release is reproducible by anyone with the certificate and the credential, and reviewable by
  anyone at all, because it is a file in the repository rather than a sequence somebody remembers.
- Every failure mode that costs a notarization round trip is caught locally first.
- `--skip-notarize` makes the whole pipeline runnable with no Apple credential, which is how it
  was developed and how a contributor can check that a change did not break packaging.

**Negative — accepted**

- **`xtask` now shells out to eight external tools** (`cargo`, `xcodegen`, `xcodebuild`, `lipo`,
  `codesign`, `ditto`, `hdiutil`, `notarytool`, `stapler`, `spctl`, `shasum`). That is inherent:
  they are the tools, and wrapping them in Rust buys ordering, error messages and a place to put
  the comments rather than any abstraction.
- **The DMG has no background image and no icon layout.** `hdiutil create -srcfolder` with an
  `/Applications` symlink produces a functional drag-to-install window and nothing prettier. A
  designed window is worth doing later; the app icon itself is now real artwork
  (`apps/macos/Artwork/`).
- **No SBOM and no `--reproducible` claim yet.** Both are on M7's acceptance list; `cargo deny`
  landed and these did not. A code signature contains a timestamp, so two builds of identical
  source do not have identical bytes, and a real reproducibility story needs more than a flag.
  Recorded as remaining work rather than quietly dropped.
- **Auto-update is still undecided.** M7's acceptance list asks for a Sparkle-vs-manual decision
  recorded as an ADR either way. It is not in this one, because nothing was built either way: the
  0.1.0 release tells users to `brew upgrade` or watch the releases page, and the decision is the
  first thing M8 should make.

## Amendment 2026-09-10

Step 7 (build the DMG) originally left the disk image itself unsigned: `hdiutil create` produces
an unsigned container, and notarizing it was assumed to be enough because the ticket covers the
`.app` inside. It is not enough. `spctl -t open --context context:primary-signature` — the check
`gatekeeper-assess` and a user's own "are you sure you want to open this" dialog both run — assesses
the **container's own** signature, not the app's, and an unsigned DMG has none to find: `spctl`
rejects it even though the app one level in is properly notarized and stapled.

**The fix: `build_dmg` in `xtask/src/dist.rs` now signs the DMG itself**, with the same Developer
ID identity used for the app, immediately after `hdiutil create` and before the DMG is submitted
for its own notarization (step 8). [`docs/releasing.md` step 10](../releasing.md) documents this in
the runbook prose: "Build the DMG around the already-stapled app, and sign the DMG itself with the
same Developer ID identity."

This does not change the step order above — the DMG was always built after the app was stapled and
notarized separately before the DMG's own submission — it corrects what step 7 does at the moment
the DMG is created, which the original numbered list did not call out as its own act of signing.

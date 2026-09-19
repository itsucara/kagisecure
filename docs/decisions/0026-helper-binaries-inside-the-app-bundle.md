# ADR-0026: The helper binaries live in `Contents/Helpers`, not `Contents/MacOS`

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M7 implementation
- **Refines:** [architecture.md](../architecture.md) §8

## Context

kagisecure is four programs that have to find each other:

| Program | Who runs it | Who needs to know where it is |
| --- | --- | --- |
| `Kagisecure.app` | the user | — |
| `kagisecure-mcp` | the user's MCP client (Claude Code, Codex, Cursor) | the client's config, which the app's "Set up your agent" screen writes |
| `kagisecure-nmhost` | the user's browser | the `NativeMessagingHosts` manifest, which the app's "Browser extension" screen writes |
| `kagisecure` (CLI) | the user | the user's `PATH`, if they want it |

Both manifests hold an **absolute path**, and both are written by the app. Until M7 the app had
nothing to point them at: `architecture.md` §8 said the sidecar would ship inside the bundle, and
a note admitted it did not, because "putting an unsigned sidecar inside a bundle nobody can
notarize would be theatre." The screens fell back to `PATH` and to `KAGISECURE_MCP` /
`KAGISECURE_NMHOST`, and said which they had found.

M7 signs and notarizes, so the theatre objection is gone and the bundling can happen. The question
left is *where in the bundle*.

## The obvious answer is wrong, and the failure is silent

`architecture.md` §8 says `Contents/MacOS/kagisecure-mcp`, which is the conventional place and is
right for two of the three. It is **catastrophically wrong for the third**.

The app's own executable is `Contents/MacOS/Kagisecure`. The CLI is called `kagisecure`. The
default macOS filesystem — APFS as it ships — is **case-insensitive**. So:

```console
$ cp target/release/kagisecure Kagisecure.app/Contents/MacOS/
$ ls -la Kagisecure.app/Contents/MacOS/
-rwxr-xr-x  1 …  5616912 …  kagisecure          # note the size, and the name
-rwxr-xr-x  1 …  6772192 …  kagisecure-mcp
-rwxr-xr-x  1 …  1591152 …  kagisecure-nmhost
```

`Kagisecure` is gone. The copy overwrote the application binary with the CLI, in place, and
nothing reported anything: not `cp`, not `codesign`, not `xcodebuild`. The bundle still has a
valid signature — over the wrong contents. The app launches into a CLI's `main`, which prints
usage to a stdout nobody is reading, and exits.

Measured on macOS 26.1, APFS (case-insensitive), during this milestone. It is the reason this ADR
exists rather than a line in ADR-0028.

## Decision

**All three helpers go in `Contents/Helpers`.**

1. `Contents/Helpers/kagisecure-mcp`
2. `Contents/Helpers/kagisecure-nmhost`
3. `Contents/Helpers/kagisecure`

`Contents/Helpers` is a directory Apple's bundle layout allows, it is nested code like any other
as far as `codesign` and the notary service are concerned, and it holds all three so that there is
one rule instead of an exception for the one whose name collides.

The alternative — keep `Contents/MacOS` and rename the bundled CLI — was rejected. The name a user
types is `kagisecure`; a bundled copy called something else is a second name for one program, and
the symlink into `/usr/local/bin` would have to paper over it.

### Each helper is signed on its own

`codesign --force --sign "<identity>" --options runtime --entitlements
apps/macos/Signing/Helper.entitlements --timestamp`, per binary, **before** the app bundle is
signed around them. Notarization requires every Mach-O in a bundle to carry its own Hardened
Runtime signature with a secure timestamp, and a bundle's `_CodeSignature/CodeResources` is a
manifest of hashes — so adding a file to a signed bundle invalidates its seal, and the outer
signature has to be applied last.

`Helper.entitlements` is as close to empty as a file can be: `com.apple.security.app-sandbox:
false` and nothing else. None of the three needs a single Hardened Runtime exception — no JIT, no
writable-executable memory, no dynamically loaded libraries, no `DYLD_*` — because every
dependency is statically linked. Stating the sandbox rather than omitting it follows
[ADR-0010](0010-app-sandbox-off-and-generated-project.md): a reader should see a decision, not an
oversight.

### The embedding is a step after the build, not a build phase

Two mechanisms were tried and both are unavailable:

- **A Copy Files phase** names files that must exist when `xcodegen generate` runs. A clean
  checkout has not built them, and the build fails on the first job (CI ran this until CI was
  removed on 2026-09-19; the same failure now shows up locally).
- **A Run Script phase** runs under `ENABLE_USER_SCRIPT_SANDBOXING`, which `project.yml` turns on
  and which is worth keeping. The sandbox denies the script the read of a binary outside the
  project directory (`deny(1) file-read-data`, observed) and would deny the `codesign` that has to
  follow it.

So `cargo xtask embed` does it, after `xcodebuild` returns. `make macos` runs it too, so a
development build has the same shape a released one does and the setup screens show the same kind
of path a user will see. `make macos-test` exercises it ad-hoc, and asserts that
`CFBundleExecutable` still names the app afterwards — which is exactly the check that would have
caught the collision above (run in CI until CI was removed on 2026-09-19, locally since).

### One search, in one place

`kagisecure_agent::bundle::find` is now the only implementation of "where is our other binary",
used by the app through `kagisecure-ffi`, by `kagisecure mcp path` and by the browser setup
screen. The order:

1. **The hint** — the app's own `Contents/Helpers`. A shipped copy beside the running app beats
   everything: same identity, same notarization submission, guaranteed same version.
2. **`KAGISECURE_MCP` / `KAGISECURE_NMHOST`** — a contributor pointing at a `target/` build.
   Second rather than first because the hint is only ever set by a *bundled* app, and a
   development build has nothing in its hint directory to shadow.
3. **Beside the running executable** — `cargo build`, a Homebrew `bin`, and the bundled CLI
   finding its bundled siblings.
4. **An installed `/Applications/Kagisecure.app`** — a CLI or a shell that is in neither of the
   above and has nothing on `PATH`.
5. **`PATH`**.

Before this, the sidecar's search put the environment variable first and the host's put the bundle
first, while both doc comments claimed the two "mirror each other deliberately". They did not.

## Consequences

**Positive**

- A user drags one thing to `/Applications` and everything works. The manifests point inside the
  bundle, so the browser and the MCP client launch a binary that is signed with the same identity
  and notarized in the same submission as the app that vouches for it —
  [ADR-0015](0015-peer-code-signature-verification.md)'s team comparison now has a *reason* to
  match, not just an ability to.
- Nothing needs to be on `PATH`. `docs/mcp-server.md` §9's paths are finally true.
- One search means the setup screen and `kagisecure mcp path` cannot disagree, which was a support
  problem waiting to happen.

**Negative — accepted**

- **`Contents/Helpers` is less conventional than `Contents/MacOS`,** and every document that said
  `Contents/MacOS` had to be corrected. The alternative is a bug that destroys the application
  binary without an error message.
- **The bundle is about 14 MB larger**, which is the three static Rust binaries. Sharing code
  between them would mean a dylib, which would mean signing and loading a dylib under the Hardened
  Runtime for no user-visible benefit.
- **The CLI is inside a bundle, so it is not on `PATH` by default.** `docs/releasing.md` documents
  the one-line symlink. A "Install command-line tool" button in Settings was considered and not
  built: writing to `/usr/local/bin` needs an authorization prompt and a privileged helper, which
  is a lot of new surface in a security-sensitive app for something `ln -s` does.

# ADR-0010: App Sandbox off, and the Xcode project is generated

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M3 implementation

Two packaging decisions that a reader of the repository will notice immediately and should not
have to guess about.

## 1. The App Sandbox is off

### Context

macOS apps distributed outside the App Store may choose. kagisecure needs three things the
sandbox complicates:

- **A Unix-domain socket at a documented path.** [architecture.md](../architecture.md) §4.2 puts
  it at `~/Library/Application Support/kagisecure/run/daemon.sock`, mode `0600` in a `0700`
  directory, and `KAGISECURE_SOCKET` overrides it. A sandboxed app's "Application Support" is
  inside its container (`~/Library/Containers/com.kagisecure.app/Data/…`), which the *sidecar* —
  a child of the MCP client, not of the app, and not sandboxed — cannot reach by that path. The
  sidecar and the app would have to agree on a path the documentation does not describe.
- **A vault file the user chooses.** A vault is a file people keep in Dropbox, in a git-crypt
  repo, wherever they like. Under the sandbox each of those is a user-selected read-write
  scope with a security-scoped bookmark to store and re-resolve, and the CLI — which has no
  sandbox and no bookmarks — must be able to open the same file.
- **`run_with_env`, in M4.** Spawning an arbitrary user-named program with an injected
  environment is not something a sandboxed process does.

### Decision

**App Sandbox off, Hardened Runtime on.** The entitlements file says so explicitly rather than by
omission, so a reader sees a decision instead of an oversight.

Hardened Runtime stays on because it is orthogonal and cheap: it is what notarization requires
(roadmap M7) and it blocks the code-injection vectors that matter to a process holding a vault
key. Nothing kagisecure does needs a hardened-runtime exception — no JIT, no unsigned-memory
execution, no library validation opt-out, no DYLD environment variables.

### Consequences

- **The app is not App-Store-distributable.** That was already true and independent of this
  decision: the roadmap's distribution channel is Developer ID + notarization + a Homebrew cask
  (M7), and the MCP sidecar model — an app that a *different* process connects to over a socket —
  does not fit App Store review anyway.
- **We lose the sandbox's containment** if the app is compromised. The mitigation is that the app
  is small, has no network stack and no HTML renderer, and its only untrusted input is IPC frames
  from a socket that is `0600` in a `0700` directory with the peer's uid checked by the kernel
  (architecture §5). That is a smaller attack surface than a browser-adjacent app, not a
  substitute for the sandbox.
- **Revisit if the socket goes away.** If M4 ends up using an XPC service or a mach port instead
  of a UDS, the strongest argument here evaporates and the sandbox should be re-evaluated on the
  remaining two.

## 2. `Kagisecure.xcodeproj` is generated and not committed

### Context

An `.xcodeproj` is a directory of XML with UUID cross-references. It merge-conflicts on almost
every concurrent change, its diffs are unreadable, and a build setting can be changed in it
without any reviewer noticing.

### Decision

**`apps/macos/project.yml` is the source of truth. `xcodegen generate` produces
`Kagisecure.xcodeproj`, which is `.gitignore`d**, as are the `Info.plist` and default
entitlements XcodeGen writes from the same spec.

The trade is a build dependency on `xcodegen` (Homebrew, or `mint`), and an extra step before
opening the project. `make macos` runs it (a CI job also did, until CI was removed on 2026-09-19),
and running it from a clean checkout is what proves the spec alone is sufficient to build.

`Signing/Provisioned.entitlements` is the exception: it is hand-written and committed, because it
is not derivable from the spec and because its contents are a security decision people should
read (see [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)).

### Consequences

- Build settings are reviewable as YAML, in a file with comments explaining why each unusual one
  is set.
- A contributor cannot open the project straight from a clone; the README says so.
- `tuist` was not evaluated; `xcodegen` was already present on the implementation machine and the
  spec is small enough that switching later would be an afternoon.

# ADR-0027: Everything ships universal (arm64 + x86_64)

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M7 implementation
- **Supersedes:** [ADR-0012](0012-m3-scope-deviations.md) §1

## Context

[ADR-0012](0012-m3-scope-deviations.md) §1 deferred the universal binary from M3 to M7, for a good
reason and with an explicit end date:

> The implementation machine has only that target installed, and `rustup target add
> x86_64-apple-darwin` plus a `lipo` step would add a second slice that nothing in this milestone
> can run or test. […] a universal binary is a *release* concern, and release engineering is M7.
> Shipping an untested x86_64 slice is worse than shipping none — it is a claim of support with no
> evidence behind it.

M7 is the release. The claim now has to be made or dropped.

## Decision

**Ship universal.** `arm64` and `x86_64`, in every Mach-O the DMG contains: the app, the Safari
app extension, and all three helpers.

`cargo xtask dist` builds the Rust side for both target triples and `lipo -create`s each result;
`xcodebuild` is given `ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO` and produces the Swift side the
same way. The static library the app links goes into the xcframework as one fat archive rather
than two entries — an xcframework's slices are *platforms*, and both architectures are the same
platform.

The prediction in ADR-0012 held exactly: "build both targets, `lipo -create` them, and pass two
`-library` pairs to `-create-xcframework`. The xtask is structured so that is a loop, not a
rewrite." It was a loop. (One `-library` pair, not two, for the reason above.)

### What was actually measured

The cross-build was the risk, so it was tested before anything was built around it:

- `rustup target add x86_64-apple-darwin`, then `cargo build --release --target x86_64-apple-darwin
  -p kagisecure-ffi -p kagisecure-mcp -p kagisecure-nmhost -p kagisecure-cli` — **succeeded on the
  first try**, on an Apple-silicon Mac running macOS 26.1 with Xcode 26.2.
- No dependency in the graph needs a C toolchain configured for cross-compilation. The crypto is
  pure Rust (`argon2`, `chacha20poly1305`, `zeroize`), and there is no `ring`, no `aws-lc-sys`, no
  `openssl-sys` — the crates whose build scripts make Apple cross-builds unpleasant.
- `lipo -archs` on every shipped Mach-O reports `x86_64 arm64`.

### What was *not* measured, stated plainly

**The x86_64 slice has never been executed.** There is no Intel Mac here. What is verified is that
it builds, links, is signed, and is present in the artifact; what is not verified is that
kagisecure runs correctly on Intel hardware.

That is a weaker claim than ADR-0012 wanted, and it is still worth shipping, because the balance
has changed. In M3 an untested slice bought nothing: nobody could install the app at all. In M7 an
Intel user's alternative is *an app that refuses to launch*, with an error message about
architecture that tells them nothing about what to do. A slice that is built from the same source
by the same compiler and is almost certainly fine beats a bundle that certainly is not.

The honest form of the claim is in `README.md` and `CHANGELOG.md`: universal, with Intel untested
on hardware. If someone reports it broken on Intel, that is a bug with a clear reproduction, which
is a much better position than having no users on the platform at all.

## Consequences

**Positive**

- The app runs on every Mac that runs macOS 15, not only on Apple silicon. The README's
  "Apple silicon only" line goes away.
- Rosetta 2 is not needed and not involved: a universal binary runs native on both.

**Negative — accepted**

- **The build takes roughly twice as long**, because everything is compiled twice. `cargo xtask
  dist --host-only` exists for trying the pipeline out; the release path has no such flag on
  purpose.
- **The artifacts are roughly twice the size.** The DMG is about 20 MB compressed. For a password
  manager downloaded once, this is not a trade worth optimising.
- **Local and CI builds stayed host-only.** `cargo xtask bindgen` and `helpers` default to the host
  architecture, and only `dist` defaults to universal, so a per-push CI run (before CI was removed
  on 2026-09-19; a local run now) did not pay for a
  second compile of everything. The *bindings* are identical either way — UniFFI reads its
  metadata out of one slice and that metadata is architecture-independent — so the idempotency
  check stays meaningful for a universal build it never makes.
- **`x86_64-apple-darwin` is now a build prerequisite for a release.** `docs/releasing.md` says
  so, and `cargo xtask dist` fails with rustup's own message, which names the command to run.

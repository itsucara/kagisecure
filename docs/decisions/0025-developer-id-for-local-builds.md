# ADR-0025: `make macos SIGN=developer-id` — a real identity for local builds, ad-hoc still the default

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M6b implementation
- **Refines:** [ADR-0010](0010-app-sandbox-off-and-generated-project.md), [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md), [ADR-0015](0015-peer-code-signature-verification.md)

## Context

Everything this project builds has, until now, been signed ad-hoc. That was a deliberate and good
choice ([ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)): a clean checkout (and, until it
was removed on 2026-09-19, CI) builds with
no Apple Developer account at all, which is the difference between an OSS project people can
contribute to and one they cannot.

It also means three things have never been seen working:

1. **The Safari Web Extension** needs an App Group, and an App Group identifier must begin with a
   team identifier ([ADR-0024](0024-safari-app-group-socket.md)).
2. **The "verified" rendering of the approval sheet.** `PeerCodeSignature` compares a peer's team
   against this app's own; on an ad-hoc build there is no team on either side, so the honest verdict
   is always *Unverified* ([ADR-0015](0015-peer-code-signature-verification.md)). The green path is
   implemented and, before this, had never rendered.
3. **The Secure Enclave key.** Still blocked — see below.

M7 will sign, notarize and package for distribution. This ADR is about the much smaller thing that
had to come first: being able to *build locally with a real identity*, so those three can be
looked at.

## Decision

**Add a signing switch to the Makefile. Ad-hoc stays the default.**

```sh
make macos                     # ad-hoc — what a clean checkout does (and what CI did, before removal)
make macos SIGN=developer-id   # the Developer ID Application identity in your keychain
```

`SIGN=developer-id` passes `CODE_SIGN_IDENTITY="Developer ID Application"`,
`DEVELOPMENT_TEAM=<TEAM_ID>` and `OTHER_CODE_SIGN_FLAGS=--timestamp` to `xcodebuild`, which signs
the app, the Safari app extension and every embedded binary, under the hardened runtime that
`project.yml` already turns on for every target.

Three details are decisions rather than mechanics:

- **The identity is named generically.** `"Developer ID Application"` matches whichever such
  certificate is in the keychain; no organisation's certificate name appears in this repository. A
  fork signs with its own by doing nothing.
- **`TEAM_ID` is read out of the same certificate** — `security find-identity -v -p codesigning`,
  parsed — and can be overridden for a machine with more than one. Nothing about a specific team is
  committed.
- **`signing-check` fails before the build, not after it.** An empty `DEVELOPMENT_TEAM` produces an
  app whose App Group entitlement expands to a group nothing can use, and the symptom is a Safari
  extension that silently never connects. A twenty-second build followed by a mystery is worse than
  an immediate sentence naming the command that lists identities.

## What this measured, which is the point of writing it down

Building with a real identity settled a question ADR-0011 left open, and the answer is **no**.

| Entitlement | Ad-hoc | Developer ID, no provisioning profile |
| --- | --- | --- |
| `com.apple.security.app-sandbox` | fine | fine |
| `com.apple.security.application-groups` | expands to a useless group | **works** — container created |
| `keychain-access-groups` | Xcode refuses to build | Xcode refuses to build; force-signed, the process is **killed at exec** |

The third row is new evidence and is sharper than ADR-0011's. Forcing the entitlement on with
`codesign --entitlements` — bypassing Xcode's build-time refusal entirely — produces a binary that
`exec` kills with `SIGKILL` before `main`. The system log says why:

```text
taskgated-helper: Disallowing <binary> because no eligible provisioning profiles found
amfid: … not valid: Error … Code=-413 "No matching profile found"
kernel: (AppleMobileFileIntegrity) AMFI: … Code has restricted entitlements, but the
        validation of its code signature failed. Unsatisfied Entitlements:
```

So `keychain-access-groups` is not merely something Xcode wants a profile for; it is a **restricted
entitlement AMFI validates against a provisioning profile at every exec**, and a Developer ID
signature does not satisfy it. Reproduced on both a bare Mach-O and the real `Kagisecure.app`.

**M3's acceptance criterion is therefore still not met, and for a reason one step further along
than ADR-0011 recorded.** Unblocking it needs a registered device and an App ID — an account
action — and Developer ID signing does not substitute for it. ADR-0011 has been updated to say so.

## Consequences

**Positive**

- Safari autofill is buildable and runnable locally ([ADR-0024](0024-safari-app-group-socket.md)).
- The one-line difference between an ad-hoc build (what CI made, before it was removed) and a
  build that exercises the signed paths
  is `SIGN=developer-id`, rather than five `xcodebuild` overrides somebody has to reconstruct.
- ADR-0011's open item has a measurement instead of an assumption, and M7 knows exactly what it is
  buying when it registers a device.

**Negative — accepted**

- **`CONFIG` defaults to `Debug`, which carries `com.apple.security.get-task-allow`.** Apple rejects
  that entitlement at notarization, so a signed build made this way is *not* a candidate for a
  release. `make macos SIGN=developer-id CONFIG=Release` is the one to submit, and M7 owns the rest
  of that pipeline (notarization, stapling, the DMG). Nothing here notarizes anything.
- **Two signing paths to keep working.** Mitigated by CI continuing to build and test the ad-hoc
  one on every push, which is the path a contributor gets (until CI was removed on 2026-09-19;
  the ad-hoc path is now exercised locally, by every contributor build).

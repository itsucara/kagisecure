# ADR-0023: Safari is deferred, and the protocol is kept browser-agnostic so it can be picked up

- **Status:** Superseded by [ADR-0024](0024-safari-app-group-socket.md) (2026-09-10, M6b)
- **Date:** 2026-09-10
- **Deciders:** M6 implementation
- **Refines:** [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)

> **Superseded, and one of its premises was wrong.** M6b built the Safari extension. The reason
> given below for deferring — that it is blocked by the same account action as the Secure Enclave —
> does not hold: a Safari Web Extension needs `com.apple.security.application-groups`, which a
> Developer ID signature carries **with no provisioning profile**, where
> `keychain-access-groups` is a restricted entitlement AMFI refuses without one. The two were
> assumed to be the same kind of blocker and are not. See
> [ADR-0024](0024-safari-app-group-socket.md) for the transport and
> [ADR-0025](0025-developer-id-for-local-builds.md) for the measurement.
>
> Everything else here held: the port replaced the transport and only the transport, and all three
> predicted threat-model improvements happened. The document is kept because that prediction, and
> its one bad premise, are both worth being able to read.

## Context

The roadmap titles M6 *"Browser-extension autofill (Safari + Chrome)"*. Only Chrome — and, through
the same code, the rest of the Chromium family — is built.

## Decision

**Chrome first; Safari deferred until the owner's Apple Developer account can sign an app
extension. Design for Safari, do not build it.**

### Why it is blocked, specifically

A Safari Web Extension is not a folder you load. It is an **app extension inside a signed
containing app bundle**: `NSExtension`, a provisioning profile, and a registered device on the
developer account. There is no unsigned mode, no developer-mode load-unpacked equivalent that
survives a relaunch, and no way to test one without the profile.

This is the same account action that has blocked the Secure Enclave path since M3
([ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)) and that M7 has to resolve anyway.
Building against it now would produce code nobody could run, review or test — which is the
situation ADR-0011 already records for the enrolment path, and repeating it deliberately in a
second place is worse than deferring.

### What was done instead of building it

**Nothing in the protocol names Chrome.**

- `kagisecure-extension-ipc`'s messages, error codes, origin rule and `FillValue` mention no
  browser. The one Chrome-specific module, `nm`, is the *native-messaging framing* and is used only
  by `kagisecure-nmhost`; the app-side socket framing is separate.
- `KnownBrowser` already has a `Safari` variant. It returns `None` from
  `native_messaging_dir_fragment`, because Safari does not use native messaging host manifests, and
  the setup screen therefore does not offer Safari a manifest it could not read — a test asserts
  that (`safari_is_not_offered_because_it_does_not_use_native_messaging_hosts`).
- The origin rule, the approval flow, the fill-lease model, the audit vocabulary and the
  `ApprovalRequest` fields are all transport-independent.

### What a Safari port replaces, and what it does not

**Replaces:** the transport, and only the transport. A Safari extension talks to its containing app
through `SFSafariApplication` / `NSExtension` messaging, not a child process over stdio. So
`kagisecure-nmhost` has no Safari equivalent, and the app's listener would gain a second front end
that speaks the same `Request`/`Response` types over a different pipe.

**Does not replace:** everything above the transport.

**Changes in the threat model**, and both changes are improvements:

- **T-10 (rogue native host) disappears.** There is no manifest naming an arbitrary binary, because
  there is no separate binary — the extension is inside the signed app.
- **The process-ancestry gate becomes an app-extension identity check.** Safari tells the containing
  app which extension is calling, signed by the same team, which is strictly better evidence than
  "a recognized browser is three hops up the process tree".
- **T-11 (other browser profiles) changes shape**, because the manifest that makes the host
  reachable from every profile of a browser does not exist.

The threat-model addendum records this in §9 as an open section rather than pretending to cover a
component that does not exist.

### The UI does not pretend

The Browser extension screen lists Chrome, Edge, Arc, Brave and Chromium, and says in plain words
that Safari is not supported and why, with a link. It does not show a greyed-out Safari row that
implies "coming soon" without saying what is missing.

## Consequences

**Positive**

- No code that cannot be run, reviewed or tested.
- The work a Safari port needs is a transport and a UI entry, not a redesign.
- The deferral has a named unblocker — the same one M7 already owns — rather than being open-ended.

**Negative — accepted**

- **The milestone's title is not fully met.** M6 says "Safari + Chrome" and this delivers Chrome and
  the Chromium family. Recorded in the roadmap's M6 section as an unmet criterion rather than
  quietly rescoped.
- **The browser-agnostic claim is untested.** Nothing has been ported, so "the protocol is
  transport-independent" is an argument from reading, not a demonstration. The nearest evidence is
  that the same code serves Chrome and Edge unchanged, which is a much smaller distance than Safari.

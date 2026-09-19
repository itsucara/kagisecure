# ADR-0024: Safari reaches the app through a Unix socket in the App Group container

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M6b implementation
- **Supersedes:** [ADR-0023](0023-safari-deferred.md)
- **Refines:** [ADR-0019](0019-native-messaging-forwarder.md), [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)

## Context

[ADR-0023](0023-safari-deferred.md) deferred Safari on the grounds that a Safari Web Extension is
an app extension inside a signed containing app, which "needs a provisioning profile, which needs
a registered device". That reasoning was inherited from
[ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md) and, measured directly, **is wrong for this
case**:

| Entitlement | Developer ID, no provisioning profile |
| --- | --- |
| `com.apple.security.app-sandbox` | builds, runs |
| `com.apple.security.application-groups` | **builds, runs** — `$(AppIdentifierPrefix)` expands, the container is created |
| `keychain-access-groups` | Xcode refuses to build; force-signed, AMFI kills the process at exec |

Measured on macOS 26.1 / Xcode 26.2 with a Developer ID Application certificate. The keychain row
is [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)'s blocker and it is unchanged; the
App Group row is what a Safari extension actually needs, and it needs no profile at all. Safari
therefore is not blocked on the same account action, and never was.

So the question became a live one: **how does a sandboxed app extension talk to the unsandboxed
app that holds the vault?**

## Decision

**A Unix domain socket inside the shared App Group container, speaking the same protocol,
framing and message types as the Chromium front end.**

- The App Group is `<TEAMID>.com.kagisecure`, from `$(AppIdentifierPrefix)com.kagisecure` in both
  targets' entitlements. The team is never hardcoded: the app derives it from its own code
  signature at run time and hands it to `kagisecure-extension-ipc`, so a fork signing with its own
  identity gets its own group with no source edit.
- The socket is `~/Library/Group Containers/<group>/run/safari.sock`, `0600` inside a `0700`
  directory — the same treatment the other two sockets get.
- The app binds it as a **second front end of the same listener**: same `Request`/`Response`, same
  4-byte big-endian framing, same origin rule, same approval queue, same fill-lease store, same
  audit vocabulary. `HostKind` selects between the two and changes exactly one thing (§5).
- `SFSafariWebExtensionHandler` connects **per message**, because Safari starts and stops the app
  extension process at its own discretion and a cached socket is usually a dead one. The app's
  session state is per connection, so the handler sends its `Hello` first on the same connection:
  one `connect(2)`, two frames each way.

### Why not XPC

The textbook answer for an app extension talking to its container app is `NSXPCListener` on a Mach
service. It does not fit here:

- **A plain `.app` cannot vend a global Mach name.** Registering one is a launchd registration, and
  an app that is not a launchd job has none. The workarounds — an embedded XPC service, a login
  item, a `LaunchAgent` — all move the vault-holding process somewhere the user cannot see in the
  Dock or quit from the menu bar, which is a worse property for a password manager than any
  transport gain.
- **It would be a second protocol.** The value of the socket is not the socket; it is that the app
  sees *one* client kind with a `browser` tag. An `NSXPCInterface` would be a second wire format to
  keep in step with `kagisecure-extension-ipc`, a second place the one secret-carrying message is
  defined, and a second thing to review.

### Why not reuse the existing extension socket

Because the sandboxed extension cannot see it. `~/Library/Application Support/kagisecure/run/` is
outside the extension's container and outside any group container; a sandboxed process is refused
there, quietly, by the sandbox.

## §4 — The extension's identity, and why the handler rewrites one field

On Chromium the extension id is pinned by a committed public key
([ADR-0021](0021-pinned-extension-id.md)). **Safari has no equivalent.** `browser.runtime.id` there
is a per-install UUID: different on every Mac, regenerated when the extension is reinstalled.
There is nothing in it to pin.

What *is* stable is the app extension's bundle identifier,
`com.kagisecure.app.safari-extension` — and, crucially, it is a fact the appex knows about *itself*
rather than a string web content chose. So `SafariWebExtensionHandler` builds the `Hello` from
`Bundle.main.bundleIdentifier` instead of forwarding whatever the JavaScript side sent. It is the
one field in the whole channel the handler does not pass through verbatim, and the reason is
written above the function.

The app then pins against that identifier — and against a **different** list from the Chromium
one. `is_pinned_extension` and `is_pinned_safari_extension` are separate functions over separate
constants, so a Chromium extension claiming to be `com.kagisecure.app.safari-extension` is refused,
and so is the reverse. Two tests assert exactly that, one on each side of the FFI boundary.

## §5 — Caller verification: the one thing `HostKind` changes

The Chromium front end's gate is process ancestry: the native host is a pipe, so the interesting
question is what launched it, and the answer must be a recognized browser within three hops
([ADR-0019](0019-native-messaging-forwarder.md)).

That gate cannot be applied to Safari, because **macOS launches an app extension from `launchd`,
not from Safari**. There is no browser anywhere in the ancestry of a genuine connection. So on the
Safari socket the gate is replaced by a test on the peer *itself*: its executable must be
`…/KagisecureSafariExtension.appex/Contents/MacOS/KagisecureSafariExtension`.

This is **stronger** evidence, not weaker, and the asymmetry is worth stating plainly:

| | Chromium | Safari |
| --- | --- | --- |
| The process on the socket | `kagisecure-nmhost`, launched by a browser | our own `.appex` |
| Rust-side gate | a recognized browser within three hops | the peer is our `.appex` |
| Swift signature check, half 1 | the native host, against **our** team | the app extension, against **our** team |
| Swift signature check, half 2 | the browser, against a **hardcoded vendor** team | — there is no second process |
| Can both halves verify on our own build? | **no** — a source-built host is ad-hoc | **yes**, on a Developer ID build |

The last row is the point. On Chrome, the app's own helper is the half that cannot be attributed to
a developer, so a fill through Chrome is `Unverified` even on a signed build. On Safari the only
process on the socket is one we signed, so a Developer-ID-signed build produces a genuinely
verified fill — the first place in this product where the green rendering
[ui-spec.md](../ui-spec.md) §10.2 specifies is reachable at all.

`FillSignature` therefore carries an explicit `peer` case rather than inferring it from a `nil`
browser verdict. On Chromium a missing browser verdict means *the browser could not be
established*, which must never pass; on Safari it means *there is no second process*, which must
not fail. One `nil` cannot honestly mean both, and a test asserts both directions.

## §6 — What an ad-hoc build gets

Nothing, and it says so. An ad-hoc build has no team, so `$(AppIdentifierPrefix)` expands to
nothing, there is no App Group, and `safari_endpoint(None)` returns `None`. The listener then:

- **still serves Chromium**, because a Safari failure that took autofill down for every browser
  would be a poor trade;
- puts one sentence on the Browser extension screen — *"This build is not signed with a team
  identity … build it with `make macos SIGN=developer-id`"* — rather than a greyed-out row.

A clean checkout is unaffected (as CI was too, until it was removed on 2026-09-19): it builds and
tests with ad-hoc signing exactly as before.

## Changes in the threat model

All three of [ADR-0023](0023-safari-deferred.md)'s predictions held.

- **T-10 (rogue native host) does not exist on this front end.** There is no manifest naming an
  arbitrary binary, because there is no separate binary — the code is inside the signed app bundle.
- **The ancestry gate became an app-extension identity check**, which is better evidence (§5).
- **T-11 (other browser profiles) does not apply.** There is no per-browser manifest that makes the
  channel reachable from every profile.

What is new, and is recorded in
[threat-model-browser-extension.md](../threat-model-browser-extension.md) §9: the App Group
container is a directory any process running **as the user** can see. The socket is `0600` in a
`0700` directory and the app checks the peer's uid before reading a byte, which is the same
boundary the other two sockets have — but it is worth saying that the group container buys
*reachability from inside a sandbox*, not confidentiality against the user's own other processes.

## Consequences

**Positive**

- Safari is shipped, and the milestone's title is met.
- One protocol, one origin rule, one approval sheet, one lease store, one audit vocabulary. The
  Safari port replaced the transport and nothing else, which is what ADR-0023 predicted and is now
  demonstrated rather than argued.
- The claim "the protocol is browser-agnostic" is no longer untested.
- The strongest identity evidence in the product is now reachable, on the Safari path.

**Negative — accepted**

- **A second socket, and a third in the product.** Three endpoints is three things to get the
  permissions right on. Mitigated by all three going through `Endpoint::prepare_dir` and the same
  `0700`/`0600` treatment, with a test on each.
- **Safari autofill needs a signed build.** A contributor working from a clean checkout can build,
  test and use everything except this. The screen says so.
- **The end-to-end pass in real Safari is not automated and, in the session that built this, was
  not performed.** What *was* measured is the whole path below Safari: a Developer-ID-signed,
  sandboxed probe carrying only the App Group entitlement, running this repository's own
  `AppGroupSocket.swift` unchanged, completed `hello` → `match` → `fill` against the app's listener
  through the group-container socket and received the value. What that does not prove is that
  Safari loads the extension, that its own permission model lets it run on a page, and that the
  icon and ⌘\ behave there as they do in Chromium. See
  [browser-extension.md](../browser-extension.md) §8 for exactly what is and is not verified.

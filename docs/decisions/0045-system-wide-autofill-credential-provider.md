# ADR-0045: System-wide password AutoFill through a credential provider extension

- **Status:** Implemented (unit-tested); not yet enabled on a real Mac — needs a provisioning
  profile, see "Owner steps".
- **Date:** 2026-10-03
- **Deciders:** the owner — convenience first: one Touch ID, then everything fills everywhere until
  the vault locks; stricter behaviour comes later as policy settings.
- **Builds on:** [ADR-0024](0024-safari-app-group-socket.md) (App Group socket),
  [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md) (grace window, amendment of
  2026-10-03), [ADR-0038](0038-app-release-needs-presence.md) (presence-gated releases)

## Context

The browser extensions fill web pages only. Native apps, and QuickType suggestions in any text
field, are served on macOS by an AuthenticationServices **credential provider** app extension
(`ASCredentialProviderViewController`) that the person enables under System Settings › General ›
AutoFill & Passwords.

## Decision

1. **A new app extension, `KagisecureCredentialProvider.appex`** (bundle id
   `com.kagisecure.app.credential-provider`), embedded in the app like the Safari extension. Its
   Info.plist declares `ProvidesPasswords` and `ProvidesOneTimeCodes` (macOS 15 SDK) and
   `ShowsConfigurationUI`.
2. **The extension holds no vault.** It asks the running app over a Unix socket in the App Group
   container, `run/autofill.sock` — the Safari extension's transport (one connection per message,
   4-byte big-endian length + JSON), but served by Swift (`CredentialProviderService`) rather than
   Rust's extension listener, because the decision it needs — is the grace window open? — lives in
   Swift, and the value goes through the same presence-gated release every in-app copy uses. The
   app accepts only a same-user peer whose code signature is our own `.appex`, signed by our team
   (`PeerCodeSignature.checkCredentialProvider`). Request kinds: `status`, `logins` (metadata
   only), `credential`, `one_time_code`.
3. **Grace and presence.** `provideCredentialWithoutUserInteraction` sends `interactive: false`:
   the app answers from the grace window with no prompt, or `interaction_required`, and the system
   then shows the extension's sheet. From the sheet (`interactive: true`) the app releases through
   `VaultSession.releaseField` / `releaseTotp`, whose `AppPresenceGate` rides the grace window or
   runs one Touch ID / login-password check, which opens it. The release purpose is `copy` (the
   audit log records a copy); a dedicated `autofill` purpose is left for later.
4. **Locked or not running.** The extension shows "Unlock it, then click Try Again" and launches or
   raises the app; an interactive request to a locked running app also brings it forward. A no-UI
   request never raises anything.
5. **Identity store.** On unlock and on every item refresh, the app replaces
   `ASCredentialIdentityStore`'s contents with one password identity per (saved website host,
   username) and one one-time-code identity per host of a login with a code — record identifier =
   item id, never a value. It is **kept on lock** (convenience first): QuickType still offers the
   login, and picking it brings the app forward to unlock.
6. **List UI.** `prepareCredentialList` shows a searchable list, logins matching the requested
   service identifiers first (host equal or subdomain either way, `www.` ignored).
7. **Policy hook.** `nativeAutofillRequiresConfirmation` (Settings › Security › "Always show the
   AutoFill sheet in other apps", off): when on, no-UI requests are always answered
   `interaction_required`, so every fill goes through the sheet.

## Consequences

- Inside the grace window, any app that can show a login field gets a suggested login filled with
  one click and no prompt. Accepted by the owner, as for browser and agent fills.
- Matching is by host only, looser than the browser extension's origin rule: the person picks the
  login, and a native app's service identifier is often only a domain.
- The AutoFill entitlement is restricted, so a clean ad-hoc build leaves it out
  (`Signing/CredentialProvider.Provisioned.entitlements` carries it). Such a build embeds the
  extension, but macOS will not list it.

## Owner steps

1. In the Apple Developer portal, register `com.kagisecure.app.credential-provider` with the
   **AutoFill Credential Provider** capability and the App Group `<TEAM>.com.kagisecure`, and
   create a **Developer ID** provisioning profile for it.
2. Build that target with `CODE_SIGN_ENTITLEMENTS=Signing/CredentialProvider.Provisioned.entitlements`
   and the profile (`PROVISIONING_PROFILE_SPECIFIER`), Developer ID signed.
3. Install the app, open it once, then enable **Kagisecure** under System Settings › General ›
   AutoFill & Passwords.

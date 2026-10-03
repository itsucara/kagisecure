# ADR-0021: The extension id is pinned by a committed key, and the private key is not

- **Status:** Accepted; amended 2026-10-03 (the Chrome Web Store assigns its own id — see the
  amendment below, which corrects "Publishing to the Web Store would change nothing")
- **Date:** 2026-09-10
- **Deciders:** M6 implementation

## Context

The app has to decide whether the extension talking to it is *our* extension. Chromium gives one
handle on that: the extension id, which the browser reports to the extension itself
(`chrome.runtime.id`) and which appears in a native messaging manifest's `allowed_origins`.

An extension's id is derived from its public key: `SHA-256(SPKI DER)`, first 16 bytes, each nibble
mapped to `a`–`p`. For an unpacked extension with no `key` in its manifest, Chromium derives it
from the **absolute path of the directory**, so it changes when the folder moves — which would make
an allow-list useless for anyone building from source.

## Decision

**Commit a public key in `manifest.json`, which pins the id everywhere.**

```json
"key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A…"
```

The id that produces is `nlijibjnmanccalmafnfbobkcfjiibmd`, and it is:

- **checked in the app** — `kagisecure_extension_ipc::PINNED_EXTENSION_IDS`, compared at `Hello`;
  anything else is refused with `UNKNOWN_EXTENSION` before a single item is matched;
- **written into every native messaging manifest** the setup screen installs, as
  `allowed_origins: ["chrome-extension://<id>/"]`, which is Chromium's own half of the check;
- **shown on the setup screen**, so a user can compare it with what `chrome://extensions` shows.

The same id whether the extension is loaded unpacked from any directory, on any machine, in Chrome
or Edge or Arc or Brave.

### Publishing to the Web Store would change nothing

> **Wrong — corrected by the amendment of 2026-10-03 below.** The Chrome Web Store refuses a new
> item whose manifest contains `key`, so the store id is not the pinned one.

A store listing's id is derived from the key the store holds. Uploading a package that already
contains a `key` keeps that id. So the pinned id survives publication, and the app's allow-list
does not need a release-time edit.

### What is committed and what is not

The **public** key is committed; it is public by construction, and it is in every copy of the
extension anyone installs.

The **private** key is not in the repository and is not needed to build, load or test the extension
— Chromium only ever reads the public half. It is needed exactly once, to sign a `.crx` for
out-of-store distribution, which this project does not do; a Web Store upload uses the store's own
signing. It was generated on the implementation machine and is not retained.

> Assumption: out-of-store `.crx` distribution is not wanted. If it ever is, a private key will
> have to be generated and kept somewhere with the same care as a signing certificate, and this ADR
> revisited. Owner should confirm.

### What pinning is not

**It is not authentication.** A *compromised* extension keeps its id — the id is a property of the
package, not of the code's integrity. Pinning stops a *different* extension the user installed from
talking to the vault. It does nothing about the extension itself being subverted, which is threat
T-9, and is what the approval sheet exists for.

Nor is the manifest's `allowed_origins` a defence against local malware: it is a file in the user's
own `Application Support` directory, which anything running as the user can rewrite. Both halves
are cheap, neither is sufficient, and having both means an attacker has to defeat two things rather
than one.

## Consequences

**Positive**

- A contributor can clone, `Load unpacked`, and have the app recognize the extension with no
  configuration.
- The setup screen can show an id worth comparing, because it is stable.
- Nothing about the allow-list changes at release time.

**Negative — accepted**

- **A base64 blob in `manifest.json` that nobody can eyeball.** A test asserts the id derived from
  it is a well-formed Chromium id and that the pinned constant matches its shape; deriving the id
  from the key inside the test would need SHA-256 and base64 in a place that currently needs
  neither.
- **One id, one extension.** A fork that wants its own id has to generate a key, replace the
  manifest's and the constant in `lib.rs`. Two edits, both greppable, and the alternative — reading
  the id from configuration — would mean the allow-list is whatever a file says, which is not an
  allow-list.

## Amendment 2026-10-03: the Chrome Web Store assigns its own id

**What this ADR got wrong.** "Publishing to the Web Store would change nothing" assumed that
uploading a package whose manifest carries `key` keeps the id that key derives. It does not, for a
**new** item: the Chrome Web Store refuses the upload of a new item whose manifest contains `key`,
and assigns the item an id of its own — derived from a key pair the store generates and holds —
at the first upload. The first upload has to be made by hand in the developer dashboard; the
store's API cannot create an item. So the store install's id is unknown until that upload, and is
not `nlijibjnmanccalmafnfbobkcfjiibmd`. The "Nothing about the allow-list changes at release time"
consequence above is withdrawn: it changes once, after the first upload.

**Decision (the owner).** Publish the extension on the Chrome Web Store, publicly listed from the
first release, under the same publisher as the macOS app's Developer ID. Keep the committed `key`
for unpacked loads. Then:

1. **The store package strips `key`.** `cargo xtask chrome-package` writes
   `dist/kagisecure-chrome-<version>.zip` from `extensions/shared` with `key` removed and `version`
   set from the workspace (`docs/chrome-web-store.md`). The committed manifest keeps its `key`, so
   `Load unpacked`, the e2e suite and the run browser (`Contents/Resources/ChromiumExtension`,
   ADR-0042) still get the pinned id.
2. **The store id joins the allow-list.** After the first upload, the item's id (shown in the
   dashboard and in the item's store URL) is added as the second entry of
   `kagisecure_extension_ipc::PINNED_EXTENSION_IDS`. That one list feeds both halves of the check:
   the app's `Hello` check, and the `allowed_origins` of every native messaging manifest the setup
   screen writes (`kagisecure_agent::browser_setup::manifest_body`). A user who installed from the
   store presses **Set up** again in an app build carrying the new entry, which rewrites the
   manifest with both origins.
3. **Optionally, one id for both.** The dashboard shows the item's public key (Package → View
   public key). Replacing the committed `key` with it makes an unpacked load get the store id too.
   If that is done, the old id stays in `PINNED_EXTENSION_IDS` for a transition — anyone with the
   old unpacked id installed keeps working until they reload — and the order is swapped so the
   store id is `[0]`, which is what the setup screen shows and what the test in
   `extensions/chrome/test/adversarial_extension_surface.test.js` derives from the committed key.
   The upload then still strips `key`: the store keeps the item's key itself, and an update whose
   manifest carries one is at best redundant.

**What is unchanged.** Pinning is still not authentication (above). The private key for
`nlijibjnmanccalmafnfbobkcfjiibmd` is still discarded and still not needed: a store item is signed
by the store, and this project still does not distribute `.crx` files. Safari is untouched — it
pins a bundle identifier, not a Chromium id (ADR-0024).

**Consequences.** Two Chromium ids are served instead of one, and the setup screen shows only the
first; a store user comparing ids there will see the unpacked one until the screen lists both or
the keys are unified as in (3). Every id on the list is one this project controls: the unpacked one
by a key nobody holds, the store one by the store account.

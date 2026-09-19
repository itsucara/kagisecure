# ADR-0021: The extension id is pinned by a committed key, and the private key is not

- **Status:** Accepted
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

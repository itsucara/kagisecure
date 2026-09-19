# Threat model addendum: the browser extension

An addendum to [threat-model.md](threat-model.md), not a replacement. Everything in the main
document still holds; what follows is what changes when a browser is added, and the roadmap makes
writing it a **blocking** deliverable for M6 rather than a follow-up:

> A dedicated threat-model addendum … covering the browser process as a new semi-trusted
> component, the extension update/distribution channel, and content-script injection surface —
> written and reviewed before this milestone ships, not after.

- **Status:** written for M6. **Not yet reviewed by anyone but its author** — the roadmap asks for
  a review before the extension is distributed even in beta, and that is an open item, recorded in
  §9.

---

## 1. The change in one paragraph

Until M6 the product had one invariant that made most of the threat model easy: **no protocol the
app speaks can carry a secret value.** The MCP channel cannot, structurally
([ADR-0002](decisions/0002-no-secret-values-over-mcp.md)); the FFI can, but the FFI is inside one
process and one trust domain ([ADR-0008](decisions/0008-ffi-secret-crossings.md)). Autofill breaks
that: a password manager that cannot put a password into a password field is not a password
manager. So M6 adds a **second channel that deliberately carries one value**, and the whole of
this document is about what that costs and what is done about it.

The value's journey, in full:

```text
  vault (encrypted)
    │  app process, unlocked
    ▼
  kagisecure-agent::extension          origin rule, approval sheet, biometric, fill lease
    │  Unix socket, 0600 in a 0700 dir, big-endian frames         ← the new crossing
    ▼
  kagisecure-nmhost                    a pipe: no vault, no decisions, cannot name `Secret`
    │  stdio, Chrome native-messaging frames
    ▼
  extension service worker             forwarded to exactly one `sendResponse`, never stored
    │  chrome.runtime message
    ▼
  content script                       written into the field, then out of scope
    │
    ▼
  the page's DOM                       ← page JavaScript can read it from here. See §6.
```

## 2. Assets

The main document's [A1–A7](threat-model.md#1-assets) are unchanged. Two are newly reachable and
one is new.

| ID | Asset | Change in M6 |
| --- | --- | --- |
| A1 | Secret values | **Now also transiently in the browser**: in the service worker for the length of one message, in the content script for the length of one function call, and in the page's DOM for as long as the form is on screen. |
| A4 | Item metadata | **Now also disclosed to the browser**, one origin at a time: titles and usernames of items matching the page the extension asked about. |
| A7 | Approval leases | A second, differently-scoped kind exists — the fill lease (origin + item, session-only). |
| **A8** | **The extension's identity** | The pinned extension id and the native-messaging manifest that names it. Compromising either is how something that is not our extension gets to ask. |

**What is *not* newly reachable:** the vault key (A3), the master password (A2), and the item list
as a whole. The extension never learns which sites the user has saved except by asking about a
site it is already on, and never learns a value it did not ask for and get approved.

## 3. New and changed adversaries

The main document's T-1 … T-7 still apply. Four are specific to this milestone.

### T-8 Malicious page JavaScript

**Capability.** Runs in the page, same document as the content script, different JavaScript world.
Can rewrite the DOM, add and remove forms, dispatch synthetic events, and read any input's value.

**What it tries.** (a) Make a fill happen the user did not ask for. (b) Read a value the user *did*
ask for. (c) Impersonate a site the user has an item for.

**Mitigations.**

- **No fill without a real gesture.** Two entry points reach a `fill` request, and both check
  `event.isTrusted`: the click on the in-field icon, and the ⌘\ handler. `isTrusted` is false for
  every event page script can dispatch, and there is no other code path from "a form appeared" to
  "a value was requested" (`extensions/shared/content.js`, rule 1).
- **The overlay is unreachable.** The icon lives in a **closed** shadow root, inside an element
  whose tag name is randomized per document load. `element.shadowRoot` is `null` from the page's
  side, so the page cannot query it, restyle it into invisibility, or click it.
- **Origin is established, not claimed.** The extension's message carries no origin the app
  trusts: the service worker replaces it with `sender.origin`, which Chrome stamps. A page that
  lies about its origin is lying to a field nobody reads.
- **(c) is refused by the match rule.** See §4.
- **(b) is not mitigated.** See §6, residual risk R-1.

### T-9 Compromised extension

**Capability.** Everything the extension can do: open the native port, send any protocol message,
read every reply.

**What it tries.** Ask for every item at every origin; ask for a fill at an origin the user is not
on; ask repeatedly, hoping the user clicks through.

**Mitigations.**

- **It cannot ask about an origin it is not on.** `match`, `fill` and `totp` all carry a page
  context the **service worker overwrites** with the browser-stamped sender origin. A compromised
  *content script* is confined to its own document; a compromised *service worker* can still
  choose which tab to ask about, but only tabs that exist.
- **It cannot enumerate.** There is no "list everything" message. `match` answers one origin, and
  returns titles and usernames — never saved URLs, so the reply does not teach the browser what
  else the user has.
- **Every value still needs a human.** The first fill of an (origin, item) pair per unlock session
  raises the sheet and needs a biometric; a lease excuses only the biometric, never the click.
- **A lock ends it.** `VaultHandle::take` runs both listeners' hooks: every fill lease dies with
  the key.
- **It is not authenticated.** A compromised extension keeps its id. Pinning stops a *different*
  extension, not a subverted one. Stated plainly because the opposite is easy to assume.

### T-10 Rogue native messaging host

**Capability.** Anything running as the user can write
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.kagisecure.nmhost.json` and
point it at its own binary. **Chrome performs no signature check on a native host** — it launches
whatever the manifest names.

**Mitigations.**

- **The host has no authority to steal.** `kagisecure-nmhost` links one crate, which depends on
  `kagisecure-core` with `proto` only. It cannot name `Secret`, cannot open a vault file, and has
  no code path to a key. Replacing it gains an attacker a pipe.
- **The app checks who connected.** Same-user uid is a hard gate. The peer pid comes from the
  kernel (`LOCAL_PEERPID`), and the app walks up to three ancestors looking for a recognized
  browser; a host with no browser above it is refused with `UNTRUSTED_HOST` before it can ask
  anything, and the refusal is recorded.
- **The sheet says what was established.** Two verdicts — the native host's code signature and the
  browser's — rendered separately, because on an unsigned build they genuinely differ.
- **Ancestry is a path test, not an identity.** Anything that can write `/Applications` can put a
  program there. It is what lets the sheet say *"launched by Google Chrome"* rather than
  *"launched by something"*; the security boundary is the sheet and the biometric.
- **The manifest is written by the app, visibly.** The setup screen shows the exact JSON and the
  exact path before the button is pressed, so a user can compare it with what is on disk.

An attacker who has already achieved "runs code as the user" is threat-model **T-3**, and T-3 is
explicitly *not* fully mitigated by this product: it can read the app's memory. The native host is
not the weak link in that scenario.

### T-11 Another browser profile, or another browser

**Capability.** A second Chrome profile, or Edge alongside Chrome, on the same account.

**What it tries.** Use the manifest the user installed for one browser, from another.

**Mitigations.** Native messaging host manifests are **per browser**, not per profile: every
profile of a browser that has the manifest can reach the host. This is Chrome's design and cannot
be narrowed from our side. What *is* narrowed: the extension id is pinned in both the manifest's
`allowed_origins` and the app's own check, so only our extension can use it, and every fill still
needs a sheet. The setup screen installs per browser and offers a **Remove** button for each.

> Assumption: a user with two Chrome profiles is one person, and a fill approved from either is a
> fill they meant. Profile isolation would need a per-profile secret the extension holds at rest,
> which the roadmap forbids. Owner should confirm.

## 4. The origin rule, as a mitigation

The roadmap's criterion is *"Autofill only ever proposes credentials for an item whose saved URL
matches the current page's origin; there is no fuzzy or 'close enough' domain match."*

Implemented in `crates/kagisecure-extension-ipc/src/origin.rs`, and it is the only place the rule
exists. A saved website covers a page when **all three** hold:

1. the schemes are equal, and both are `http` or `https` — no upgrade, no downgrade;
2. the ports are equal, after the scheme's default is filled in;
3. the hosts share a registrable domain (eTLD+1 under the Public Suffix List), or — where there is
   no registrable domain — are byte-for-byte equal.

Clause 3's fallback is the strict branch, and it fires in the three cases that matter: IP
literals, single-label hosts (`localhost`), and hosts that are themselves a public suffix. The
last is why the list is needed at all: `alice.github.io` and `mallory.github.io` are different
sites, and a naive "last two labels" rule would make them one.

**The iframe policy.** When the form is in a cross-origin frame, the **frame's** origin is matched,
not the page's. This permits the case that has to work — a federated login embedded on another
site — and refuses the case it exists for: an attacker's frame on a page the user trusts asking for
that page's password. Both directions are asserted
(`a_cross_origin_iframe_is_matched_against_the_frame_not_the_page`).

**Where the allow-list lives.** Only in the item's website fields: `Item.urls` (the edit sheet's
**Websites** box) and any public `FieldKind::Url` field. Not the title, however domain-shaped.

**Update policy for the list.** The Public Suffix List is compiled into the binary by the `psl`
crate; `Cargo.lock` records which snapshot a build used. A stale list fails *strict* for newly
delegated suffixes. Policy: treat `psl` as a security-relevant dependency and bump it whenever the
dependency audit runs ([ADR-0022](decisions/0022-public-suffix-list.md)).

## 5. `agent_visible` is deliberately not consulted

`Item::agent_visible` is default-deny, and it answers *"may a language model learn that this item
exists"*. The browser extension is the user's own browser, filling the user's own login, at their
own click, behind a biometric. Gating autofill on the agent flag would mean granting an LLM
visibility over an item in order to log into a website with it — backwards, and a footgun that
would train people to turn the agent flag on for everything.

The consequence, stated: an item invisible to agents **is** visible to the browser extension, as a
title and a username, at an origin it matches. That is a deliberate widening of A4's exposure, to
a different and less capable consumer.

## 6. Residual risks

Accepted, tracked, and not mitigated by this design.

| ID | Risk | Why it is accepted |
| --- | --- | --- |
| **R-1** | **Page JavaScript can read the filled value.** Once the password is in the input, `document.querySelector('input[type=password]').value` returns it, to any script in the page. | This is what filling a form *is*. Every password manager has it, and the alternative — a browser API for a value the page cannot read — does not exist. The exposure begins when the user asks for the fill and is confined to the origin they approved. |
| **R-2** | **Chrome cannot verify the native host binary.** No signature check, ever. | Chrome's design. Mitigated by giving the host no authority (§3, T-10), not by trying to verify it. |
| **R-3** | **On an ad-hoc build, the native host is unverifiable by *us* too.** | Same as [ADR-0011](decisions/0011-secure-enclave-under-ad-hoc-signing.md) and [ADR-0015](decisions/0015-peer-code-signature-verification.md): until M7 signs with a Developer ID, "unverified" is the truthful verdict, and the sheet says so rather than showing a badge it has not earned. |
| **R-4** | **A one-time code copied to the clipboard is on the clipboard.** | The app clears its own clipboard copies ([ADR-0017](decisions/0017-quick-access-hotkey-and-pasteboard.md)); a page's clipboard is the browser's and we cannot. Mitigated in practice by preferring to *fill* a detected one-time-code field and only falling back to the clipboard. |
| **R-5** | **The extension's update channel is a trust boundary.** A Web Store update, or an unpacked directory somebody edits, replaces the code that asks. | The pinned key means the id survives publication, so the app's allow-list is not a defence against an update — nor is it meant to be. What limits an update's blast radius is that every value still needs a sheet. Signing and a published update policy are M7's. |
| **R-6** | **Extension permissions are broader than `activeTab` alone.** A content script matches every `http(s)` page. | The in-field icon has to exist *before* the user clicks anything, which `activeTab` alone cannot do — `activeTab` is granted on interaction with the toolbar action, which is too late for an icon in a field. No `host_permissions` are requested, so the extension can fetch nothing cross-origin; the content script's only capability is the document it is in, and it never reads a value out of one. |
| **R-7** | **The match query is not audited.** `match` writes no audit entry. | The content script asks on every login form that gains focus; one entry per focus event is an audit log nobody reads. Nothing is disclosed that the extension did not already know (it named the origin), and both messages that *do* disclose — `fill` and `totp` — are recorded. |

## 7. Threat → mitigation matrix

| Threat | Mitigation | Where |
| --- | --- | --- |
| Fill without a user gesture | `isTrusted` on both entry points; no other path to a `fill` | `content.js` |
| Page reaches the overlay | Closed shadow root, randomized host tag | `content.js` |
| Page claims another origin | Origin taken from `sender.origin`, stamped by the browser | `background.js` |
| Item filled at the wrong site | eTLD+1 + exact scheme/port, in Rust, one implementation | `origin.rs` |
| Attacker's iframe borrows the page's trust | Cross-origin frames matched against the frame | `origin.rs` |
| A different extension talks to the vault | Pinned id, checked at `Hello` and in `allowed_origins` | `lib.rs`, `browser_setup.rs` |
| A non-browser program talks to the vault | uid gate, then browser-ancestry gate, then `UNTRUSTED_HOST` | `extension.rs` |
| Silent repeat fills | Fill lease is session-scoped, per (origin, item), and excuses only the biometric | `fill_lease.rs` |
| Values at rest in the browser | No `chrome.storage` call anywhere in the extension | `extensions/shared/` |
| A sheet skipped for something that is a secret | The exemption is a function of the requested fields only; the reply drops what was not asked for | `protocol.rs` |
| A tab continuing as somebody else | Memory keyed on tab id, same-site only, 60 s, in memory, dropped on lock; the popup shows it and can forget it | `tabmemory.js` |
| A value in a log | `FillValue` has no `Display` and redacts in `Debug`; nothing logs a reply | `protocol.rs` |
| A value in the audit log | `AuditEntry` has no field one fits in; asserted with a canary | `tests/extension.rs` |
| Locked vault still serving | `VaultHandle` lock hook empties fill leases; the service refuses when locked | `extension.rs` |

## 8. What is asserted rather than argued

- **The canary.** `crates/kagisecure-agent/tests/extension.rs` seeds a 32-byte marker as an item's
  password, drives a real `kagisecure-nmhost` over a real socket, and asserts the marker reaches
  the `Filled` reply and appears in **no** audit entry and on **no** standard error stream.
- **One message type.** `protocol.rs`'s `only_two_response_fields_are_fill_values` builds every
  response shape and asserts the marker survives serialization in exactly the two that are allowed
  to carry one.
- **The two wire formats do not interoperate.** A frame written for the MCP socket is refused by
  the extension reader before a byte of its body is read, and the `ksx` marker refuses anything
  that survives the length check.
- **The origin table**, including `co.uk`, `github.io`, ports, IP literals, IDNs and the iframe
  policy, in both directions.
- **The end-to-end**, in a real browser: `make e2e SUITE=extension` (Chromium — see
  [e2e-harness.md](e2e-harness.md) §6), and
  `apps/macos/KagisecureTests/SafariExtensionTransportTests.swift` plus
  `crates/kagisecure-agent/tests/safari.rs` (the Safari front end, below Safari itself).

## 9. Safari, which is a different and smaller surface

Added in M6b. The Safari front end is the same extension code over a different transport
([ADR-0024](decisions/0024-safari-app-group-socket.md)), and every difference in this section is an
improvement on the Chromium one. T-8 (malicious page JavaScript) and T-9 (compromised extension)
are unchanged: the content script and the service worker are the same files.

**T-10 does not exist here.** There is no native messaging host to be rogue. The `.appex` is inside
the app's own signed bundle; there is no manifest naming a path, so there is nothing for a hostile
program to point at itself. The peer on the socket is checked twice — its executable must be our
`.appex` (in Rust, before anything is served) and its code signature must carry our team and its
bundle identifier (in Swift, on the approval path). Both are checks the Chromium side cannot make
about its own helper, because a source-built helper is ad-hoc.

**T-11 does not apply.** There is no per-browser manifest, so there is no file that makes the
channel reachable from a profile the user did not think about. There is exactly one Safari
extension, enabled or not, in Safari's own Settings.

**What is new: the App Group container.** The socket lives in
`~/Library/Group Containers/<TEAMID>.com.kagisecure/run/safari.sock`, and that directory is visible
to any process running **as the user**. Stated plainly so nobody reads the words "App Group" as a
confidentiality boundary:

- What the group buys is *reachability from inside a sandbox*. The extension is sandboxed and could
  not otherwise see a socket anywhere.
- What protects the socket is what protects the other two: `0600` inside a `0700` directory, and
  the app refusing a peer whose uid is not the owner's before it reads a byte. That is the same
  boundary as the MCP socket and the Chromium extension socket, no weaker and no stronger.
- A process running as the user that got past all of that would still have to be the `.appex` by
  path and by signature, and would still meet the approval sheet and the biometric.

**One residual worth naming:** the app extension's bundle identifier is what the app pins, and it
is reported by the appex about itself. That is corroborated by the code-signature check on the same
pid, so a program claiming the identifier without the signature is refused — but the claim and its
corroboration are two mechanisms, not one, and the second is the one doing the work.

## 10. The per-tab memory, and the fill that raises no sheet

Added after M6, for identifier-first sign-ins
([ADR-0030](decisions/0030-identifier-first-login.md)). Two changes with a security story, stated
here rather than left in the ADR.

**A fill that names only the username raises no approval sheet.** This does not widen the crossing
in §1, because the value it writes is one the extension already has: `match` hands the browser the
username of every item at the origin it asked about, with no prompt, and has since M6 — the
disclosure is A4's, already recorded, and the exempt fill adds nothing to it. The exemption is a
function of the requested fields alone (`FillField::crosses_a_secret`), so no page, origin, lease,
timing or memory state can turn a password request into an exempt one, and the reply is built by a
constructor that drops what was not asked for, with a canary test looking for the bytes. The uid
gate, the peer check, the pinned id, the origin rule, the content script's `isTrusted` gesture and
the audit entry are all unchanged; the audit detail is `FILL_USERNAME_ONLY`, so a reader can tell a
fill nobody approved from one somebody did.

**What the per-tab memory holds.** `extensions/shared/tabmemory.js`, one `Map` entry per tab:

| Field | What it is | Why it is not a secret |
| --- | --- | --- |
| `itemId` | the opaque id the extension quoted back in the fill it just made | already in the `matches` reply for that origin; names nothing and opens nothing |
| `origin` | the origin **the browser stamped** on that request, never a page's claim | the page's own origin, which the page knows |
| `expiresAt` | 60 seconds after the fill | a number |

No username, no title, no value, and no `chrome.storage` — it lives in the service worker and dies
with it, which in MV3 can be thirty seconds of idleness. It carries down only to the same origin or
a subdomain of it (scheme and port verbatim), which is **stricter** than the app's eTLD+1 rule and
deliberately so: nothing in the browser half is a security boundary, so the half that is cheap to
be right about is the half that says no. It is dropped on expiry, on `chrome.tabs.onRemoved`, on
the `match` that follows a navigation off the site, on vault lock, and on the password fill it
existed for.

**What T-8 (malicious page JavaScript) gains: nothing.** A compromised page can ask the service
worker to recall the entry, and is answered with at most one item id — and only if the origin the
browser stamped on *its* message still satisfies the same-site rule, which means it is a page on
the site where the user made the choice. Such a page can already send `match` and be told the ids,
titles and usernames of every item saved for that origin, so the recall answer is a strict subset
of what it is already entitled to, minus the username, and it is not a value. What the page cannot
do is cause a fill: the memory decides *which* item, and the click, the `isTrusted` check and (for
the password) the sheet decide whether.

**What T-9 (compromised extension) gains: nothing either.** An extension that is already hostile
does not need a Map of item ids it can obtain by sending `match` itself.

**The popup's `peek` deliberately performs no origin check**, which looks like an omission. What
the popup renders is the origin stored in the entry — the one the browser stamped when the fill
happened — rather than a claim about where the tab is now, so there is no origin judgement for a
check to protect. Checking would mean reading the active tab's URL, which costs the `tabs`
permission over every tab the user has open, in exchange for a caption; and the popup is our own
UI, opened by the user, already listing every match for that tab.

**Residual, small:** a banner can name an origin the tab has already left, for up to the TTL, since
an entry is reaped on the next message from that tab rather than at the instant of navigation. It
shows the origin it was made at, so what it says stays true; and the item it names cannot be filled
at the new site, because the origin rule in the app is not the thing being relaxed here.

## 11. Open items

- **This document has not been reviewed by a second person.** The roadmap requires that before the
  extension is distributed even in beta. Recorded, not done. §9 has had no reader either.
- **No fill has been performed in real Safari by a human.** Everything below Safari is tested,
  including across a real sandbox boundary; the last hop is not. See
  [browser-extension.md](browser-extension.md) §8, "What is verified, and what is not".
- **The audit token variant of the peer check** (`kSecGuestAttributeAudit`) would tighten the
  signature check against pid reuse. Deferred with the same note ADR-0015 already carries.

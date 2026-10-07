# ADR-0036: An agent may ask for a fill — the browser says where, a human says whether

- **Status:** Accepted (2026-09-26); implemented for Phases 1–3 on macOS with Chromium-family
  browsers. Not offered on Windows or Safari. See Implementation decisions, and "Implementation
  status" at the end for what is tested, what is only compiled, and what still needs a person at
  the Mac with a real browser.
- **Date:** 2026-09-25 (proposed); accepted 2026-09-26
- **Deciders:** the owner
- **Refines:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0018](0018-browser-extension-secret-crossing.md),
  [ADR-0019](0019-native-messaging-forwarder.md),
  [ADR-0020](0020-fill-approvals-and-origin-leases.md),
  [ADR-0030](0030-identifier-first-login.md),
  [mcp-server.md](../mcp-server.md) §2, §7,
  [browser-extension.md](../browser-extension.md) §1, §3, §4
- **Depends on:** [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) (transactional
  vault writes) and [ADR-0040](0040-audit-before-release.md) (audit before release), both accepted
  and implemented on `main`; this document uses ADR-0040's `AUDIT_UNAVAILABLE` and its fail-closed
  rule for fills, and does not restate them. They were drafted as ADR-0032 and ADR-0033, which is
  what earlier commits of this ADR call them.
- **Overtaken in part by:** [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md), accepted
  before this one, closed the human-path gap §8.4 records; see the note there.
- **Amended 2026-09-27:** ADR-0037's
  [presence grace window](0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-09-27-presence-grace-window)
  applies to agent fills too. The sheet is still shown for every agent fill and its Allow still has
  to be pressed, but within ten minutes of a successful presence check for a fill on the same exact
  origin (by the human or an agent, any item) pressing it asks for no new Touch ID. Where this ADR
  says "Touch ID every time" or "the biometric every time", read "outside that window".
- **Amended 2026-10-03:** convenience over security, at the owner's direction. See
  [Amendment 2026-10-03](#amendment-2026-10-03-agents-fill-without-prompts-during-grace) at the end.

## Context

Agents that drive a browser — through an extension running in the user's own browser, or through a
debugging protocol attached to it — reach login pages. Today they have two options, and both are
bad:

1. **Ask for the password.** kagisecure will not give it to them, by construction
   ([ADR-0002](0002-no-secret-values-over-mcp.md)), and a user who types it into the chat instead
   has put it in a transcript, which is the outcome this project exists to prevent.
2. **Ask the human to click the key icon.** This works today and is the baseline this ADR has to
   beat. It has three defects. The approval sheet names the browser, not the agent, as the one
   asking for the password, so the audit log attributes an agent's sign-in to the browser. The
   human has to switch context into the page the agent is driving. And it trains a habit — "when
   the agent says so, press the key" — that is indistinguishable, from the app's side, from the
   agent pressing it itself (see §8.4: a browser-driving agent can produce trusted input events).

What the feature has to provide is narrow: an agent that has navigated to a sign-in page can ask
kagisecure to fill a saved login **into that page**, after a human approves on their Mac, and the
tool returns whether it happened and nothing else.

Three existing facts shape every decision below.

- **The extension channel is request/response, initiated by the browser.** Every message on it
  today starts in a content script, is stamped with the sender's real origin by the service worker
  (`extensions/shared/background.js:75-98`), and is answered once. The app has no way to speak
  first: the native host is a lockstep pipe (`crates/kagisecure-nmhost/src/main.rs:62-111`), and on
  Safari the handler opens one connection per message
  ([ADR-0024](0024-safari-app-group-socket.md)). An agent's request arrives on the *other* socket,
  the MCP one, and has to find its way to a tab.
- **Every fill today begins with a trusted gesture in the page** — `event.isTrusted` on the icon
  click (`extensions/shared/content.js:259-260`) and on ⌘\ (`content.js:600-601`) — and that gesture
  is where the fill's *target* comes from: the form the user clicked in. An agent-originated fill
  has no gesture, so the target has to come from somewhere else, and "the agent says so" is not an
  acceptable somewhere.
- **The agent may be able to read the page it drives.** That is the crux, and §8 treats it before
  anything is claimed about what this feature protects.

## Decision

### 1. The shape

```text
  agent ──request_fill{item, origin, fields}──▶ kagisecure-mcp ──IPC──▶ app: AgentService
                                                                          │ gates (§11.1)
                                                                          ▼
                                                             app: AgentFillBroker
                                     ┌────────── push: Locate{probe} ────┘   (no value, no origin)
                                     ▼
  extension service worker ── active tab of last-focused window ──▶ content script, top frame
          ▲                                                              │
          └──── TargetReport{probe, form facts}, sender stamped by the browser ◀┘
                                     │
                           app: exactly one eligible target? ── no ──▶ NO_MATCHING_TAB, no sheet
                                     │ yes
                           approval sheet + biometric (the human)
                                     │ yes
                           grant{agent, item, fields, origin, tab, frame 0, document}
                                     │
                     push: Deliver{grant} ──▶ content script re-checks, asks AgentFill{grant}
                                     │           (sender stamped again by the browser)
                   app re-checks everything, audits first (ADR-0040), answers Filled
                                     │
                           content script writes; agent is told "filled", never a value
```

The agent names **what** (an item and the fields) and **where it believes it is** (an origin). The
browser establishes **where the value would actually go**. The human decides **whether**. The value
travels on the extension channel exactly as it does today, in the same response type, and never on
the MCP channel.

### 2. The MCP tool: `request_fill`

```json
{
  "name": "request_fill",
  "description": "Ask the user to let kagisecure fill a saved login into the browser tab they are looking at. The user approves in the kagisecure app with a biometric. Returns only whether the fill happened, never a value. Works only in a browser with the kagisecure extension, in the tab in front, when that tab's origin is exactly `origin` and is a website saved on the item.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "item_id": { "type": "string", "description": "From list_items. Titles are not accepted." },
      "origin":  { "type": "string", "description": "The origin of the page you have open, e.g. https://example.com." },
      "fields": {
        "oneOf": [
          { "type": "array", "items": { "enum": ["username", "password"] },
            "minItems": 1, "maxItems": 2, "uniqueItems": true },
          { "type": "array", "items": { "const": "one_time_code" },
            "minItems": 1, "maxItems": 1 }
        ],
        "default": ["username", "password"]
      }
    },
    "required": ["item_id", "origin"],
    "additionalProperties": false
  }
}
```

Result: `{ "status": "filled", "fields_written": ["username", "password"], "fields_pending": [] }`
— `fields_pending` is non-empty only for the identifier-first case in §7.3. Everything else is an
error with a stable code (§11). The schema has no field a value could occupy, and the IPC response
it maps onto has none either, so ADR-0002's structural enforcement is unchanged:
`kagisecure-mcp` and `kagisecure-ipc` still compile without `secret-material`, and the canary
sweep gains `request_fill` — including a sweep in which the fill *succeeds* and the marker must
still appear in no byte the sidecar writes.

**Item id only, not a name.** Titles are not unique, and resolving one would add an ambiguity
answer to the tool's vocabulary for no gain: `list_items` already turns a name into an id.

**The item must be agent-visible**, by exactly the predicate `describe_item` uses — agent-visible
item, agent-visible vault, not trashed (`crates/kagisecure-agent/src/service.rs:356-374`). This is
the opposite of the extension's rule ([ADR-0018](0018-browser-extension-secret-crossing.md),
"`agent_visible` is not consulted"), and both are right: there the requester is the user's browser;
here it is a model, and `agent_visible` is precisely the user's statement of which items a model may
deal in.

> *Amended 2026-10-03: the switch is **on by default** and turning it on asks for no presence check
> (amendment item 4). The paragraph below is the original design.*

**The feature is off by default.** One switch in Agent access, "Let agents ask to fill logins in
your browser", stored in app defaults and pushed to an in-memory flag in Rust
(`agent_fill_set_enabled`). Off, every call answers `FILL_UNAVAILABLE` before any item is looked up.
Turning it on asks for a presence check; the switch itself is not a security boundary — the per-fill
sheet and its biometric are — and it stays hidden in the UI until Phase 2's limiter lands (§9).

### 3. How the request reaches a tab

#### 3.1 The app speaks first, but says nothing

The extension protocol gains a third message family beside `Request` and `Response`: **`Push`**,
unsolicited frames from the app to a connected extension. It has two members and **neither can
carry a value, an origin, an item id or a title**:

- `Push::Locate { probe_id }` — "report the tab in front";
- `Push::Deliver { probe_id, grant_id }` — "an approved fill is waiting for the tab you reported
  under `probe_id`; ask for it".

Everything that carries information is still a `Request` the extension sends and the browser
stamps. The push is a doorbell. That keeps two properties intact: the service worker remains the
only place an origin is established (`background.js:75-98`), and the one message that carries a
password is still a reply to a request the extension made (`Response::Filled`, the same type, built
by the same `Response::filled` constructor at `crates/kagisecure-extension-ipc/src/protocol.rs:384-395`).
`FillValue::new` keeps its two call sites (`crates/kagisecure-agent/src/extension.rs:961` and
`:1025`); the agent path reaches them through the same builders rather than adding a third.

On Chromium this needs `kagisecure-nmhost` to become full-duplex: today it reads a request, forwards
it, and waits for the reply (`crates/kagisecure-nmhost/src/main.rs:62-111`). It gains a second
thread that forwards app-to-browser frames to stdout. It is still a pipe — it decodes `Push` as its
own type and re-encodes it, per [ADR-0019](0019-native-messaging-forwarder.md) §2, and `Push` is
added to the test that asserts which fields may carry a `FillValue` (none).

A push needs an open connection. The extension opens its native port lazily
(`extensions/shared/native.js:147-175`) and the content script's first `match` on a detected login
form is what opens it (`content.js:493-516`), so an agent that has just navigated to a sign-in page
has normally caused one. If no extension session is connected, the answer is `FILL_UNAVAILABLE`,
not a sheet.

#### 3.2 Which tab: the one in front, and only that one

> *Superseded in part by [Amendment 2026-10-03](#amendment-2026-10-03-agents-fill-without-prompts-during-grace)
> item 5: a background tab at the claimed origin is now used, and the active/visible requirement
> is dropped. The text below, including "a background tab cannot be filled", is the original
> design.*

On `Locate`, each connected service worker takes **the active tab of the browser's last-focused
normal window** — `chrome.tabs.query({ active: true, lastFocusedWindow: true })`, which returns an
id without the `tabs` permission the extension deliberately does not hold
(`extensions/shared/manifest.json:8-11`) — and messages that tab's **top-frame** content script. The
content script answers not by replying but by sending a fresh `TargetReport` through
`chrome.runtime.sendMessage`, so that its origin, tab id, frame id and document id are stamped by the
browser (`sender.origin`, `sender.tab.id`, `sender.frameId`, `sender.documentId`) exactly as every
fill's are today. This is the pattern the popup relay already uses (`background.js:348-381`), for the
same reason: only a content script has an origin the browser will vouch for.

The report adds what only the page's own document can say, read from the content script's isolated
world so page script cannot shadow it: `document.visibilityState`, and which of username, password
and one-time-code fields the existing detectors found.

The app then picks the target by a rule with no judgement in it. A report is **eligible** when:

1. it came from frame 0 (`top_origin_established`, `protocol.rs:92-114`);
2. its browser-stamped origin is **byte-equal** to the origin the agent claimed, after both are
   put through `Origin::parse` and `ascii_serialization` (`crates/kagisecure-extension-ipc/src/origin.rs:158`);
3. the item's saved websites cover that origin by the one existing rule (`origin.rs:241`);
4. the document is visible and the tab is the active tab of its window (`sender.tab.active`);
5. the detectors found a field for every field the request names — or, for a request naming both
   username and password, an identifier-first form, which starts the two-step grant of §7.3.

**Exactly one eligible report, across every connected browser and profile, or nothing.** Zero is
`NO_MATCHING_TAB`. Two — the same site in front in two browsers, or two profiles — is also
`NO_MATCHING_TAB`, because choosing would mean guessing which window the human is looking at. No
sheet is raised in either case.

Why not the alternatives:

- **The agent names a tab.** It cannot name ours — kagisecure's tab ids are not the agent's — and
  a scheme that let it would give an agent an address for every tab in the user's browser,
  including the ones the human is using for something else.
- **Any tab whose origin matches.** That is exactly "fill in a tab the human isn't looking at".
  The sheet's claim — *the tab in front* — would be false, and a background tab on the right site
  is what an agent driving a hidden window has.
- **Require the browser window to hold focus at fill time.** It cannot: the approval sheet takes
  focus from the browser. What is required instead is that the tab is still the active tab of its
  window, still visible, and still the same document (§4) when the value is written.

The consequence is stated plainly: **a headless browser, a minimized window, or a background tab
cannot be filled.** An agent that drives a window the human cannot see gets `NO_MATCHING_TAB`
every time. That is the design, not a limitation to be lifted.

#### 3.3 Where it can work at all

> *Update: a headless, throwaway browser the agent launches itself still gets `FILL_UNAVAILABLE`,
> but a **run browser** — a headless Chromium-family browser kagisecure launches for an unattended
> run, with the extension and manifest in its profile — is fillable under a standing login grant
> ([ADR-0042](0042-unattended-agent-access.md) §12; [browser-extension.md](../browser-extension.md),
> "Run browsers and the unattended extension endpoint"; the Playwright recipe in §5 there also
> loads the extension). "Honest rather than fixable" below describes only the agent-launched case.*

Only in a browser profile that has the kagisecure extension and its native-messaging manifest: an
agent operating the user's own browser. An automation framework that launches a throwaway profile
generally will not have either — recent Chromium builds ignore `--load-extension`, and the manifest
directory follows `--user-data-dir` ([browser-extension.md](../browser-extension.md) §9) — and gets
`FILL_UNAVAILABLE`. That is honest rather than fixable: the extension is the only thing that can
tell the app where a value would land.

### 4. The origin is the browser's, checked twice

The agent's `origin` argument is **a precondition, never an input to the match**. It exists so that
an agent's belief and the browser's fact must agree before anything happens: an agent that was
steered to `https://examp1e.com` and believes it is on `https://example.com` claims the latter, the
tab reports the former, and the request dies at eligibility check 2 without a sheet. An agent that
claims what it sees in the address bar instead dies at check 3. Either way the tab's origin is not a
site saved for the item, and the human gets a notification, not a sheet (§9.4).

**Top frame only.** The existing human path matches a cross-origin iframe against the frame and
discloses it on the sheet ([threat-model-browser-extension.md](../threat-model-browser-extension.md)
§4). The agent path does not fill frames at all in its first version: the sheet's promise is "the
page you can see in the address bar", and a frame's origin is not in the address bar. Same-origin
frames are rare enough on sign-in pages to be an open question rather than a requirement.

**Re-checked immediately before the write, from scratch.** Between the probe and the write the
human reads a sheet, and the agent owns the browser for every second of it. So:

- the content script re-runs its detectors and `stillWritable` (`content.js:398-409`) before asking;
- its `AgentFill` request is stamped by the browser again, and the app requires the **same tab id,
  frame 0, the same document id** and an origin byte-equal to the one on the grant;
- the item's coverage of that origin is re-evaluated inside the ADR-0040 release transaction, so an
  item edited while the sheet was up is judged as it now is.

A redirect, a reload, a navigation to another page on the same site, or a switch to another tab
all produce a different document id or tab id, and the grant is refused. `sender.documentId` is
Chromium's (the manifest's minimum version already includes it); where it is unavailable (§12) the
check degrades to tab id + frame 0 + exact origin, and that degradation is recorded rather than
silent.

### 5. The approval sheet

A new `ApprovalKind::AgentFill` on the same queue, with the same 60-second timeout
(`crates/kagisecure-agent/src/approval.rs:32`), the same biometric gate, and a layout of its own:

```text
  ┌────────────────────────────────────────────────────────────────────────────────────┐
  │  An agent asks to sign in to  login.example.com  with “Example (work)”             │
  │  The value is typed into the page, not sent to the agent. An agent that            │
  │  controls this browser may be able to read what is typed there.                    │
  ├────────────────────────────────────────────────────────────────────────────────────┤
  │  Agent      “example-agent” — reports itself; the name is unverified               │
  │             via kagisecure-mcp · pid 51234 · started by /path/to/client            │
  │             ⚠ Unverified — code signature not attributable                         │
  │  Browser    Chromium-family browser, launched our helper · helper                  │
  │             unverified · browser verified                                          │
  │  Where      the tab in front, top of the page — not a frame                        │
  │  Site       https://  login . example.com                                          │
  │                              ‾‾‾‾‾‾‾‾‾‾‾ registrable domain                        │
  │  Saved as   https://example.com  — this page is a subdomain of it                  │
  │  Fill       username, password                                                     │
  │                                                                                    │
  │  ▓▓▓▓▓▓▓▓▓░  56 s                                                                  │
  │     [ Deny ]   [ Deny and block this agent for 30 min ]   [ Fill on example.com… ] │
  └────────────────────────────────────────────────────────────────────────────────────┘
```

**What the approval binds**, all of it carried into the grant (§6) and the audit entry (§10): the
sidecar process and the agent's identity, the item, the exact field set, the browser-established
origin, the extension session, the tab id, frame 0 and the document id. The human approves that
tuple; nothing in it can be changed afterwards without a new sheet.

**Agent identity** is shown the way every agent sheet shows it
([ui-spec.md](../ui-spec.md) §10.2): verified facts bare, self-reported names in quotation marks.
One addition. On the MCP socket the kernel-verified peer is always our own sidecar, and the client
behind it is known only by what it reports (`crates/kagisecure-ipc/src/protocol.rs:112-126`, where
`parent_pid` is self-reported). For this sheet the app resolves the sidecar's **parent** from the
kernel with the same ancestry helper the extension channel uses
(`crates/kagisecure-extension-ipc/src/peer.rs:247`) and shows its executable and signature verdict.
That parent is what "this agent" means for blocking (§9.3).

**Making a look-alike obvious.** The origin rule is what stops a look-alike — `examp1e.com` never
covers `example.com` — so the sheet is defence in depth for the cases the rule allows by design:

- **The registrable domain is emphasized and the rest is dimmed**, from `Origin::registrable_domain`
  (`origin.rs:142`), because the rule accepts any subdomain of a saved site, and
  `user-content.example.com` is a subdomain an agent can be steered to.
- **The host is shown in its ASCII (punycode) form**, which is what the rule compared
  (`origin.rs:479`). When any label is `xn--`, the Unicode rendering is shown beneath it, labelled
  *"shown by the browser as"*, with a mixed-script warning where scripts mix.
- **`http` is shown in red** as *"not encrypted"*; the rule already refuses a scheme that differs
  from the saved one, so this only appears when the saved website is itself `http`.
- **A non-default port is always shown**, never elided.
- **The saved website that matched is shown beside the page's origin**, with *"this page is a
  subdomain of it"* whenever the hosts are not byte-equal.

**Buttons.** No "Allow for this session" — there is no lease to mint (§6). **Fill on example.com…**
(§9.2) requires the biometric, as every Allow does. It is **disabled for the first 1.5 seconds** the
sheet is key and visible, so a click already in flight cannot land on it. That does nothing against
an agent that synthesizes a click and waits (§8.4); the next paragraph is what does. **Deny and
block this agent** is §9.3.

**The biometric is the human-presence proof; the click is not.** An agent with operating-system
input control can click any button in any window, including this one. What it cannot do is present
an enrolled finger, or type a login password it does not know. So the biometric is not a
convenience layered on top of the click; for this sheet it is the only step an agent cannot
perform, and it is required every time.

### 6. The grant is not a lease

An approval produces an **`AgentFillGrant`**, in a store of its own, and not a fill lease or an env
lease.

| | Env lease | Fill lease | Agent fill grant |
| --- | --- | --- | --- |
| Minted by | an agent's sheet | a browser's sheet, "Allow for this session" | an agent's sheet, "Fill on example.com…" |
| Excuses | the biometric, for identical-or-narrower requests | the biometric, for the human's next click | nothing — it *is* the approval |
| Scope | environment, directory, variables | origin + item + fields | sidecar process (pid + executable + start time) + item + fields + origin + extension session + tab + frame 0 + document |
| Uses | bounded count | unbounded within TTL | **one** (two steps for identifier-first, §7.3) |
| Lifetime | 15 min default | 5 min default | **30 s** to be picked up; 60 s for the whole two-step flow |
| Dies on | expiry, uses, lock, revoke | expiry, lock, revoke | first use, expiry, lock, the extension's connection closing, the sidecar's pid no longer alive with the same executable and start time at delivery, any failed re-check |

Why separate, following [ADR-0020](0020-fill-approvals-and-origin-leases.md) §2's argument: the
three answer different questions, and making them different types means **no function takes one and
returns another**. Concretely:

- **An agent request never consults the fill lease store.** A human who filled `example.com` two
  minutes ago holds a live fill lease for it (`crates/kagisecure-agent/src/fill_lease.rs:130`); an
  agent asking for the same item at the same origin still gets a sheet and a biometric. Otherwise
  the agent would inherit the human's convenience silently.
- **An agent approval never mints a fill lease**, so it cannot make the human's next click silent
  either, and it never mints or satisfies an env lease.
- **Grant ids never reach the agent.** They travel only between the app and the extension. A second
  agent has nothing to quote, and the grant is bound to the first sidecar process — its kernel pid
  and executable — anyway.
- **Revoked on lock** through `VaultHandle::add_lock_hook` (`crates/kagisecure-agent/src/vault.rs:105`),
  the same way fill leases go (`extension.rs:247`), and with the same care about a lock landing while
  the sheet is up (`extension.rs:1172-1194`).

Thirty seconds is the time between the human's fingerprint and the extension's `AgentFill` arriving,
which in practice is well under one. It is not a window for anything else.

### 7. Which fields, and how many approvals

#### 7.1 Password and username: one sheet

`["username", "password"]`, `["password"]` or `["username"]`, as the extension's own `fields`
selector ([ADR-0030](0030-identifier-first-login.md) §1). `Response::filled` drops whatever was not
granted, as it does today.

#### 7.2 A username-only agent fill is **not** exempt

ADR-0030 serves a username-only fill with no sheet, because the extension already holds that
username from `match`. That argument does not transfer. The agent does **not** hold the username —
`describe_item` withholds non-concealed values ([mcp-server.md](../mcp-server.md) §2.4) — and writing
it into a page the agent reads is a disclosure the metadata tools refuse. So every agent fill,
including username-only, raises the sheet and needs the biometric.

#### 7.3 Identifier-first sign-ins: one approval, two pages

A request for `["username", "password"]` on a page that has only an identifier box is granted as a
**two-step grant**: step one writes the username into the reported document; step two may write the
password into **one** later document in the same tab (or the same document, when the site swaps
the form in place — implementation decision 38), within the grant's 60-second flow window,
whose origin passes the extension's same-site rule (the stricter rule in
[ADR-0030](0030-identifier-first-login.md) §5) **and** is covered by the item. Each step is
re-checked as §4 describes, each is single-use, and the grant dies after step two. The sheet says
*"username now, password on the next page"*.

The agent drives the two steps. Its first call returns `fields_written: ["username"]` and
`fields_pending: ["password"]`; it presses the page's own Next button; it calls `request_fill`
again for `["password"]`. That second call — same sidecar process, same item, a field the grant
still holds, inside the flow window — is located afresh (§3.2, a new document in the same tab) and
served by the pending grant's second step **without a new sheet**, and anything else about it
(another item, another agent, a document that fails the same-site rule, a late call) is a new
request with a sheet of its own. The alternative — two sheets per sign-in — doubles the prompts on
exactly the sites that matter most, which §9 counts as a cost, not a safety margin.

#### 7.4 One-time codes: always a separate approval

`["one_time_code"]` is a request of its own; the schema cannot combine it with a password. It gets
its own sheet (*"…the one-time code for 'Example (work)' — this completes the second factor"*), its
own biometric, its own grant and its own audit entry, under the tool name the extension channel
already uses, `totp_code`.

A password approval never implies a code, because the pair is the account: an agent that can read
the page after both has everything needed to sign in elsewhere within the code's window.

**No clipboard fallback on this path.** The human path puts a code on the clipboard when the page
has no one-time-code field (`content.js:447-462`). The agent path writes into a detected field or
fails with `NO_MATCHING_TAB`: the clipboard is readable by every process the user runs, the agent's
included, and pasting it is an action the agent would then take on its own.

#### 7.5 Out of scope

**Passkeys and WebAuthn**, which are the platform authenticator's ceremony and not a value
kagisecure holds; **CAPTCHAs** and any other human-verification challenge, which exist to be done
by a human; **security questions, payment cards and identities**, which are separate features with
their own sheet design. An agent that meets any of these hands control back to the human.

**Registration forms** stay refused on this path for every ordinary item. The one exception is a
`new_password` fill of a login kagisecure itself generated for a test account, proposed in
[ADR-0048](0048-agent-test-logins.md) §7; it is served only for those items and never lands a
current password in a new-password box.

### 8. What the agent can see after the fill

This is the part of the design that decides what may be claimed about it, so it is stated before
the claims.

#### 8.1 The fact

**A browser-driving agent can generally read what is filled into the page it drives.** kagisecure
cannot prevent that, and nothing in this ADR pretends otherwise. By capability:

| The agent can… | Can it read the filled password? | Why |
| --- | --- | --- |
| see screenshots only | **not directly** — a `type=password` input renders masked | but it can click the site's own "show password" control, and many sites have one |
| read the page's text or accessibility tree | **usually not** — `input.value` is not page text, and a password input's accessible value is masked | depends on the browser and the tool; not a property kagisecure controls |
| run script in the page, or attach a debugger | **yes** | `input.value` is one expression; a debugger can also read the submitted request body from the network log, and can hook the field before the fill so that even an immediate submit is captured |

The value is written only into a real `type=password` input, re-checked immediately before the
write (`content.js:398-409`), so an agent that is not trying to read it will not see it by accident
in a screenshot or a text dump. An agent that *is* trying, with script or debugger access, will.

#### 8.2 What that means for ADR-0002

ADR-0002's promise is about the MCP channel — *no tool returns a secret value* — and it stays true:
`request_fill` returns a status, and the IPC response has no field a value fits in. What changes is
the product-level sentence built on top of it. For this tool, the true sentence is:

> kagisecure never gives the agent a value. It types the value into a page the agent is driving, on
> a site saved for that login, after you approve — and an agent that can run script in that page
> can read it there.

That is the same shape as `write_env_file`, which puts values into a file an agent with file access
can read — the case ADR-0002 already names as outside its boundary and threat-model N-6 records.
The sheet carries the second sentence verbatim, and the documentation for the tool says it in the
first paragraph rather than in a caveat. **Approving an agent fill is trusting that agent with that
login, for that site, for as long as it can read the page.**

What the feature still buys, against that ceiling:

- **Transcripts stay clean for an agent that behaves.** The value is not in any tool result, so it
  is not in the model's context, the client's transcript or the provider's logs unless the agent
  goes and fetches it — which is a deliberate, visible act, not an accident of a tool's output.
- **The value only ever lands on the right site.** The phishing case — the agent steered to a
  look-alike — is refused by the origin rule, before any human is asked.
- **Every use is a human decision with an agent's name on it**, audited as the agent's.
- **Prompt injection needs two steps instead of one**: cause the request, then read the page. The
  first is gated on a fingerprint the injection cannot produce.

What it does not buy: confidentiality of the credential from an agent the user approved.

#### 8.3 Submit immediately, or leave the value in the field?

Considered, and **not adopted as a default.** Submitting in the same task as the write shortens the
time the value sits in the DOM, which helps only against the screenshot-only agent in §8.1, which
was not going to read it anyway. Against an agent with script or debugger access it buys nothing —
the submitted request carries the value, and a hooked field captures it before the submit. Against
that, auto-submit breaks every form with a "stay signed in" box, a consent checkbox, or a challenge
on the same page, and submits on the agent's behalf an action the agent would otherwise take
visibly. So the content script writes and stops; the agent presses the button.

Two narrower measures are adopted, as hygiene and labelled as such:

- **A tripwire, not a guard.** For ten seconds after an agent fill, the content script watches the
  filled password input. If its `type` stops being `password` — the site's own "show password"
  control, clicked — it clears the field and reports `AGENT_FILL_UNMASKED`, which is audited and
  surfaced to the human as a notification. It catches only the crudest read, and it says so.
- **No value lingers in extension state**, exactly as today: the content script writes it and drops
  the reply; nothing is stored or logged.

#### 8.4 A related gap in the human path, recorded here because this feature exposes it

> **Closed before this ADR was accepted.**
> [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md) makes every fill that crosses a secret ask for a fresh presence proof, lease or not, so a fill
> lease no longer excuses the biometric and an automation click on the key icon raises a prompt the
> agent cannot answer. The adversary is recorded once, as
> [threat-model-browser-extension.md](../threat-model-browser-extension.md) T-15; this ADR's draft
> numbered it T-13, which was folded into T-15 on acceptance. The `navigator.webdriver` follow-up
> proposed below is therefore not needed, and is not part of this ADR. The text is kept as the
> reasoning the design was written under — in particular, that the agent path must not assume the
> human path is unreachable to agents, which still holds.

`event.isTrusted` is the gate on every human fill today (`content.js:259-260`, `:600-601`). It
proves an event came from the browser's input pipeline rather than from page script. It does
**not** prove a human produced it: input synthesized through a browser's debugging protocol, or
through operating-system input control, arrives as trusted. A browser-driving agent can therefore
click the in-field key icon — the closed shadow root stops page *script*, not a click at
coordinates — and trigger a human-path fill. If the human filled that item at that site in the last
five minutes, a fill lease covers it (`extension.rs:1098-1100`) and **no sheet appears at all**.

That is an existing weakness, not one this ADR introduces, and fixing it is not in this ADR's scope.
It matters here for two reasons: it is part of why a properly attributed agent path is worth
building, and it means the agent path must not be designed on the assumption that the human path is
unreachable to agents. Proposed follow-up, as a separate change: the content script reports
`navigator.webdriver` (read from its isolated world), and the app refuses to let a fill lease excuse
the biometric for a request from a browser that reports it is under automation, and says so on the
sheet. That catches frameworks that set the flag and not those that do not; it is a partial
mitigation and would be documented as one.

### 9. Approval fatigue

The sheet is only a boundary if it is read. An agent that can raise it at will can train a human to
dismiss it, so the number of sheets is bounded, not just each sheet.

[Threat-model](../threat-model.md) M-7 says kagisecure has no rate limiter, because for injections
the lease is the bound and a counter adds nothing. That stays true for the injection tools. It does
not fit this tool: a limiter here does not bound *access* — every fill still needs a fingerprint —
it bounds **the human's attention**, which no lease protects. So `request_fill` gets one, and
`RATE_LIMITED` returns to the error vocabulary scoped to this tool, as
[mcp-server.md](../mcp-server.md) §7 anticipated ("if either mechanism is ever built, its code
comes back with it").

#### 9.1 Limits

- **One agent-fill sheet on screen at a time**, across all agents. A second request while one is
  up is answered `RATE_LIMITED` at once rather than queued; a queue of sheets is a click-through
  exercise.
- **Three sheets per agent per ten minutes.** The fourth request inside the window is answered
  `RATE_LIMITED` without a sheet, audited, and produces **one** notification — *"example-agent has
  asked to fill logins 4 times in 10 minutes; further requests are refused for 10 minutes"* — not
  one per request.
- **A denial sticks.** After the human denies (or lets time out) a request for an (agent, item,
  origin), identical requests are answered `USER_DENIED` without a sheet for ten minutes. The human
  already answered that question.

The numbers are fixed constants, not settings (open question 3, answered 2026-09-26).

**How a notification reaches the human.** Every notification in this section — here and in §9.4 — is
queued in Rust (`agent_fill_take_notices()`, drained on the app's existing 1-second tick) and shown
in Agent access and the menu-bar badge, with `NSApp.requestUserAttention`. It also becomes a system
notification through `UNUserNotificationCenter`, but only if the user has authorized it; the app asks
for that authorization when the feature switch (§2) is turned on.

#### 9.2 A sheet that has to be read

- The sentence leads with **the site**, in the registrable-domain rendering of §5, not with the
  agent's name: the site is what the human must check, and the agent's name is what an attacker
  would choose.
- The Allow button's label names the registrable domain — *"Fill on example.com…"* — so the button
  that approves states what it approves.
- No default button; `Return` does nothing; `Esc` denies ([ui-spec.md](../ui-spec.md) §10.3).
- The 1.5-second Allow delay of §5.
- **Escalation, not repetition.** When the same agent has had two sheets in ten minutes, the third
  sheet asks the human to pick the site from three registrable domains — the real one and two
  others from the user's own saved items — before Allow enables. A human who can answer that has
  read the sheet; one who cannot should not be approving it. **Not adopted** (open question 4,
  answered 2026-09-26): it risks teaching people to pick without reading, and §9.1 already caps an
  agent at three sheets in ten minutes. The rest of §9 stands without it.

#### 9.3 Deny and block

**Deny and block this agent for 30 minutes** answers `USER_DENIED` now and for the next thirty
minutes answers every `request_fill` from that agent with `USER_DENIED`, without a sheet, audited as
`AGENT_FILL_BLOCKED`. The block is keyed on the sidecar's kernel-resolved parent executable (§5),
never on the self-reported client name, which the agent chooses. That over-blocks — every client
that runs under the same interpreter shares a key — and over-blocking is the safe direction. Blocks
are listed in Agent access with an Unblock button.

Blocks live in memory, and — unlike leases — **survive a vault lock**. A lease is a grant and must
die with the key; a block is a restriction, and a relock resetting it would hand a blocked agent a
fresh start.

#### 9.4 Origin mismatch is a signal, and it escalates

A request whose tab in front is on an origin the item is **not saved for** (eligibility check 3,
§3.2, whether or not check 2 also failed) raises **no sheet** and is answered `NO_MATCHING_TAB`.
When that tab can be the agent's own — it is the only tab in front across the connected browsers,
or it is at exactly the origin the agent claimed (implementation decision 26) — it is also the most
likely shape of an agent being steered to a phishing page, so:

- it is audited as `AGENT_FILL_ORIGIN_MISMATCH`, with the origin the browser reported;
- the human gets a notification naming the agent, the item and that origin, in the look-alike
  rendering of §5 — *"example-agent asked to fill 'Example (work)' on examp1e.com, which is not a
  site saved for it. Nothing was filled."*;
- **a second mismatch from the same agent in the same unlock session blocks that agent's
  `request_fill` until the human unblocks it in Agent access.** Not for thirty minutes: until
  somebody looks.

A tab that *is* on a saved site but not on exactly the origin the agent claimed — `www.` against the
bare domain, say — fails check 2 alone. That is an agent's bookkeeping error, not a phishing signal:
it is answered `NO_MATCHING_TAB` and audited as `AGENT_FILL_NO_TARGET`, with no notification and no
escalation.

This also bounds the one bit `NO_MATCHING_TAB` could otherwise leak (§11.2): an agent probing
whether an item's saved websites cover an origin is refused, reported to the human, and stopped on
the second try.

### 10. Audit, and failing closed

Every request produces at least one audit entry — except the three implementation decision 37
names — and none contains a value. The tool is `request_fill`
for credential fills and `totp_code` for one-time codes; the actor is the agent, rendered as
`AgentService` renders every agent actor, with the browser that carried the value appended in the
same string — `"example-agent" [UNVERIFIED] pid 51234 … via Chromium-family browser (extension …)`
— so no `AuditEntry` schema change is needed, which ADR-0040 also avoids. `variables` holds the
field **names**; `target_path` holds the browser-established origin.

| Detail | Outcome | When |
| --- | --- | --- |
| `AGENT_FILL_APPROVED` | Allowed | durable **before** the value leaves the app, inside the ADR-0040 release transaction |
| `AGENT_FILL_APPROVED (step 1 of 2)`, `AGENT_FILL_APPROVED (step 2 of 2, entry N)` | Allowed | the same, for each page of an identifier-first sign-in (§7.3); step two's names step one's entry (implementation decision 40) |
| `AGENT_FILL_DENIED` | Denied | the human denied, or the sheet timed out |
| `AGENT_FILL_DENIED (agent blocked)` | Denied | the human pressed *Deny and block this agent* (§9.3) |
| `AGENT_FILL_BLOCKED` | Denied | a block or a sticky denial answered without a sheet |
| `AGENT_FILL_RATE_LIMITED` | Denied | §9.1: three sheets in ten minutes |
| `AGENT_FILL_BUSY` | Denied | §9.1: another agent fill was in progress (implementation decision 18) |
| `AGENT_FILL_NO_TARGET` | Denied | no eligible tab, more than one, or a tab on a saved site but not at the claimed origin |
| `AGENT_FILL_ORIGIN_MISMATCH` | Denied | the tab in front is on an origin the item is not saved for (§9.4) |
| `AGENT_FILL_ORIGIN_MISMATCH (agent blocked)` | Denied | the same, and it was the agent's second in this unlock session (§9.4) |
| `AGENT_FILL_NOT_DELIVERED (entry N)` | Failed | approved, but the grant expired, a re-check refused it or a lock took it before anything was released |
| `AGENT_FILL_NOT_WRITTEN (entry N)` | Failed | released, but the content script reported it could not write |
| `AGENT_FILL_UNMASKED (entry N)` | Failed | the §8.3 tripwire fired after the password was written; the human is also notified (implementation decision 42) |
| `AGENT_FILL_PENDING_EXPIRED (entry N)` | Failed | step one wrote the username, and the password step did not come within the flow window, or the browser session ended first |
| `AGENT_FILL_PENDING_REFUSED (entry N)` | Failed | step one wrote the username, and the agent's call for the password was refused: not the same sign-in in the same tab, or not servable (implementation decision 39) |
| the answer's code | Denied (`VAULT_CONFLICT`: Failed) | any other refusal: `INVALID_ARGUMENT`, `FILL_UNAVAILABLE` (no browser), `VAULT_LOCKED`, `VAULT_CONFLICT`, `NOT_FOUND`, `NOTHING_TO_FILL`; one written before the item is looked up, or for a hidden item, names no item (implementation decision 37) |

**Fail closed, per ADR-0040.** Agent fills are in the fail-closed set with every other extension
fill. The pre-flight rule applies — if unsaved audit entries are queued and cannot be flushed, the
request is refused with `AUDIT_UNAVAILABLE` **before a sheet is shown**, so the human is never asked
to approve something that cannot be recorded — and before any browser is asked, so the refusal
says nothing about the tab (implementation decision 36). At release, if the transaction that appends
`AGENT_FILL_APPROVED` fails, nothing is released, the grant is revoked, the extension is answered
`AUDIT_UNAVAILABLE` and so is the agent. Denials, mismatches and follow-up `Failed` entries are
best-effort, as ADR-0040 makes every refusal.

`match`-style probes are not audited on their own — the `Locate` and `TargetReport` round trip is
part of one request, and that request's entry records its outcome
([threat-model-browser-extension.md](../threat-model-browser-extension.md) R-7's reasoning).

### 11. Errors, and what the agent is told

#### 11.1 The order of gates

1. **Enabled, and not blocked or limited.** `FILL_UNAVAILABLE`, `USER_DENIED` (block), or
   `RATE_LIMITED` — all answered before the item is looked up, so none can depend on it.
2. **Vault unlocked.** `VAULT_LOCKED`.
3. **The item.** Unknown, hidden, in a hidden vault or trashed: `NOT_FOUND`, with the byte-identical
   message every other tool uses (`service.rs:50`), and — the part a timing test checks — returned
   before any browser is contacted, on the same path for hidden and absent.
4. **The fields.** A requested field the item has no value for: `NOTHING_TO_FILL`. Not an oracle —
   `describe_item` already reports `has_value` and `kind: Totp` for every field. An **archived** item
   — found, unlike a trashed one, but not a candidate for a fresh sign-in — answers here too, with a
   fixed sentence, rather than `NOT_FOUND` at gate 3.
5. **A browser to ask.** No connected extension session that declared the capability:
   `FILL_UNAVAILABLE`.
6. **The target** (§3.2). `NO_MATCHING_TAB`.
7. **Audit pre-flight** (§10). `AUDIT_UNAVAILABLE`. Asked before gate 5, not after gate 6: it does
   not depend on the tab, and answered after a tab had been chosen it would tell the agent that one
   had been (implementation decision 36).
8. **The human.** `USER_DENIED` or `APPROVAL_TIMEOUT`.
9. **Delivery** (§4). `NO_MATCHING_TAB` if a re-check refuses; `AUDIT_UNAVAILABLE` if the release
   cannot be recorded.

#### 11.2 The codes

| Code | New? | Meaning | Model should |
| --- | --- | --- | --- |
| `NOT_FOUND` | no | unknown or not agent-visible item | re-list |
| `VAULT_LOCKED`, `APP_NOT_RUNNING` | no | as today | tell the user |
| `USER_DENIED` | no | the user declined, blocked this agent, or already declined this exact request | stop; do not re-request |
| `APPROVAL_TIMEOUT` | no | nobody answered in 60 s | tell the user; a retry of the identical request within ten minutes is `USER_DENIED` (§9.1, implementation decision 30) |
| `AUDIT_UNAVAILABLE` | ADR-0040 | nothing released because it could not be recorded | tell the user |
| `FILL_UNAVAILABLE` | **yes** | the user has not enabled agent fills, or no browser with the kagisecure extension is connected | tell the user; do not retry |
| `NO_MATCHING_TAB` | **yes** | the tab in front is not at `origin`, is not a sign-in page kagisecure recognizes, is not visible, is not a site saved for this item, or changed before the fill | bring the right tab to the front; retry at most once |
| `NOTHING_TO_FILL` | **yes** | the item has no value for a requested field | check `describe_item` |
| `RATE_LIMITED` | **returns** | too many sheets for this agent, and the user has been told — or another agent fill is in progress, with its own sentence | stop; for the second, retry once after that fill has finished |
| `INTERNAL` | no | a bug | report it |

**`NO_MATCHING_TAB` is deliberately one code with one message** for every reason in its row. The
agent drives the browser and already knows what is open; what it does not know, and must not learn
cheaply, is which origins an item's saved websites cover — `describe_item` does not disclose
websites (`crates/kagisecure-core/src/proto.rs:418` has no URL field). Splitting "not at `origin`"
from "not a saved site" would turn the tool into a website oracle for every agent-visible item. As
it is, the one bit that leaks — "this item is not saved for the site I am on" — is reported to the
human and stops after two tries (§9.4).

#### 11.3 Protocol versions

- **`kagisecure-extension-ipc`**: `PROTOCOL_VERSION` **stays 1**
  (`crates/kagisecure-extension-ipc/src/protocol.rs:34`) — the doc above it already says an additive
  change does not bump it, and everything here is additive. `Hello` gains an **optional**
  `capabilities: Vec<String>` (serde default, absent means none); a session that does not declare
  `"agent_fill"` is never sent a push. New: `Push` (§3.1); `Request::TargetReport`,
  `Request::AgentFill { grant_id, page }`, `Request::AgentFillOutcome { grant_id, written, failure }`;
  `Response::Noted` for the last. The value-carrying responses stay `Filled` and `TotpCode`, and
  `only_two_response_fields_are_fill_values` stays true without edits to its claim.
- **`kagisecure-ipc`**: `Request::RequestFill { item_id, origin, fields }`,
  `Response::FillResult { fields_written, fields_pending }` and four new `ErrorCode` variants join
  **protocol version 2** (`crates/kagisecure-ipc/src/protocol.rs:38`), which ADR-0040 added and which
  is unreleased — so this feature extends that version rather than bumping again, the way ADR-0040
  extended the compatibility note above the constant (`protocol.rs:26-37`). Every new variant must be
  constructed somewhere, per the every-variant rule at `protocol.rs:95-116`.
- **The extension's own error codes** gain nothing the agent sees; `AUDIT_UNAVAILABLE` arrives with
  ADR-0040.

### 12. Browsers and parity

| | Chromium family (native messaging) | Safari (App Group socket) |
| --- | --- | --- |
| Push from the app | the existing port, once `kagisecure-nmhost` is full-duplex | **not possible on the current transport**: the handler connects per message ([ADR-0024](0024-safari-app-group-socket.md)). A containing app can message a Safari web extension's `connectNative` port through the Safari services API; that path is **unmeasured in this repository** and has to be proven the way ADR-0024 proved the socket |
| Tab selection | `chrome.tabs.query` + `sender` stamping | same code in `extensions/shared`, pending the above |
| `sender.documentId` | yes | unverified; §4's degradation applies if absent |
| Windows app | **not offered at all**, whichever browser is connected | **not offered at all**, whichever browser is connected |

**Chromium first; Safari when the push is measured.** Until then a Safari session does not declare
`"agent_fill"` and a user whose only connected browser is Safari gets `FILL_UNAVAILABLE`, with the
Browser extension screen saying why. This is a parity gap, recorded rather than hidden, and it is
the kind this project closes rather than accepts: Phase 4 below exists for it.

**Windows never offers agent fills**, independent of the browser row above. The Rust switch defaults
off there, `agent_fill_*` stays under the C ABI's "what is not here" list, and every `request_fill`
answers `FILL_UNAVAILABLE` before an item is looked up. Two reasons hold regardless of browser: the
agent-fill sheet cannot be built or verified on this platform in this repository yet, and Windows
Hello accepts the account PIN rather than requiring a biometric
([threat-model.md](../threat-model.md) W-1), which is not the presence proof this feature needs on
every fill (§5).

### Alternatives considered

**(a) The agent gets a one-time token and types it; the extension swaps it for the value.** The swap
still happens in the DOM, so the exposure in §8 is identical; the token is visible to the page and
the agent; and the extension would have to watch keystrokes in every field on every page to notice
it. A variant that swaps the token in the outgoing request instead needs either request-body
rewriting, which an MV3 extension cannot do, or a local TLS-intercepting proxy, which is network
code in an offline-only product and a far larger attack surface than the feature. Rejected.

**(b) kagisecure drives the browser itself.** It would need its own debugging-protocol connection to
the user's browser — a local port that any same-user process can find, plus control of every tab —
and it would fight the agent for the same page. And the agent could still read the DOM afterwards,
so nothing in §8 improves. Rejected.

**(c) Human-initiated fill only.** The status quo: the agent asks, in chat, for the human to click.
Zero new surface, and it keeps working whatever this ADR decides. It loses on attribution (the
sheet and the log name the browser), on intent binding (nothing checks the page is where the agent
thought it was), and — per §8.4 — it is not actually closed to an agent that synthesizes the click
(since ADR-0037 such a click raises a presence prompt the agent cannot answer, but one attributed to
the browser rather than to the agent).
Kept as the fallback and as the default while the feature switch is off; not sufficient on its own.

**(d) The agent names only an origin, and the human picks the item on the sheet.** Avoids asking the
agent to see items. But then hidden items become fillable by agents — contradicting what
`agent_visible` means — and whether a sheet appeared at all would tell the agent whether *any* item,
hidden or not, is saved for that site. Rejected.

**(e) Reuse the fill-lease store with an "agent" flag**, or let "Allow for this session" apply.
Rejected for the reasons in §6 and ADR-0020 §2: a flag on a shared type is one missed check away
from a human's lease excusing an agent's fill.

**(f) Let the agent address a tab.** §3.2.

**(g) Poll instead of push.** The extension could ask the app every few seconds whether a request is
waiting. That keeps a service worker and, on Safari, a new socket connection busy forever for a
feature most sessions never use, and it still needs the target to be established by a
browser-stamped request, which is what the push-then-request design already does. Rejected.

**(h) Collect the approval through the MCP client** (SEP-2322 elicitation). Rejected for the reason
[mcp-server.md](../mcp-server.md) §8 gives for every approval: the client is the process least
entitled to answer.

## Departures from the initial sketch

The feature was first sketched as: a tool taking an item id *or name* and an origin; a Mac sheet;
the extension verifying the origin and filling; a single-use short-lived approval, possibly reusing
the origin lease; a separate TOTP approval subsuming the roadmap's TOTP-injection item; audit of
everything; and new threats. Where this ADR differs, and why:

- **"The agent never sees passwords or TOTP values" is not claimed.** It cannot be delivered against
  an agent that runs script in the page (§8). The claim made is narrower and true: kagisecure never
  gives the agent a value.
- **Item id only**, no names (§2).
- **No reuse of the origin lease**; a new, single-use grant type (§6).
- **The agent cannot choose the tab**, and the tab must be the visible, active tab of the
  last-focused window (§3.2). The sketch left this open.
- **Top frame only** (§4), stricter than the human path.
- **Username-only fills are not exempt** on this path (§7.2), unlike ADR-0030.
- **No clipboard fallback for codes** (§7.4).
- **A rate limiter**, contrary to threat-model M-7, scoped to this tool and justified by what it
  bounds (§9).
- **More than three outcomes.** "Filled / denied / no matching tab" is kept as the shape, but "not
  available", "nothing to fill" and "rate limited" need their own instructions to the model, and
  the existing lock, timeout and audit codes still apply (§11.2).
- **The TOTP half subsumes only the browser case** of the roadmap item; see Proposed roadmap
  changes.

## Consequences

**Positive**

- An agent can finish a sign-in without the value entering any tool result, transcript or log.
- The origin rule — not the agent, not the human's eye — stands between an agent steered to a
  look-alike and the credential, and the attempt reaches the human as a notification.
- Every agent sign-in is a human decision with the agent's name on it, in the sheet and in the log,
  instead of an anonymous "the browser asked".
- No new crossing: the value's route, its one response type and its two `FillValue` fields are
  those [ADR-0018](0018-browser-extension-secret-crossing.md) enumerates. What is new is an
  authorizer. ADR-0018's statement that no message returns a value "without an item id the
  extension got from a prior `match`" becomes "…or a grant the app issued", and the implementation
  must update that sentence in the same change.

**Negative — accepted**

- **The value is readable by the agent that asked for it**, if that agent can run script in the
  page. §8 is the whole argument; the sheet says so in one sentence.
- **The extension channel stops being browser-initiated only.** `Push` is value-free and asserted to
  be, but the native host becomes full-duplex, which is more code in the one binary a browser
  launches unchecked.
- **A rate limiter, a block list and an escalation state**, which is state the rest of the approval
  system has avoided. It lives in memory and is shown in Agent access, but it is state.
- **A fingerprint per agent sign-in**, and a second one for the code. That is the price of not
  having leases, and it is paid deliberately (§9's point is that sheets are a budget).
- **Safari lags** until the push path is measured (§12).
- **The tab must be in front.** Workflows that drive a hidden browser cannot use this at all.
- **Two identity stories on one sheet** — the agent's, which is weak (a self-reported name over our
  own sidecar, plus a kernel-resolved parent), and the browser's, which is the existing two-verdict
  one. The sheet cannot be simpler than the facts.

**Neutral**

- The existing human path is unchanged by this ADR. The gap §8.4 records in it was closed separately
  by ADR-0037.

## Open questions

**Answered by the owner on 2026-09-26, before implementation:** 1 — yes, build it, Phases 1–3;
3 — fixed values, no setting; 4 — no escalation challenge, a second mismatch blocks (§9.4); 6 — the
one rule, eTLD+1, with the subdomain disclosure. 2 and 5 stay deferred (no per-item flag, no
frames). 8 keeps the tripwire as §8.3 adopts it. Phase 4 (Safari) is not scheduled yet.

1. **Is the feature worth building at all, given §8?** The honest comparison is against alternative
   (c): the gain is attribution, intent binding, audit and phishing refusal; the credential is
   exposed to an approved agent either way.
2. **Should a per-item "agents may request fills" flag exist**, on top of `agent_visible`? It would
   let a user share an item's *name* with agents without making it fillable. It needs a vault-format
   change; this draft does without it.
3. **The limiter defaults** (§9.1): one sheet at a time, three per agent per ten minutes, ten-minute
   sticky denials, thirty-minute blocks. Adjustable in settings, or fixed?
4. **The escalation challenge** (§9.2): is picking the site from three worth its friction, or does
   it teach people to pick without reading, which is the thing it exists to prevent?
5. **Same-origin frames** (§4): allow them in a later version, with the existing frame disclosure?
6. **Stricter origin rule for agents?** The agent path uses the one rule, eTLD+1, and discloses a
   subdomain on the sheet. Requiring an exact host match for agent fills would close the
   "user-content subdomain" case outright at the cost of refusing many legitimate login hosts.
7. ~~**The §8.4 follow-up** — refusing lease-excused fills under automation — as its own ADR, or as
   a phase of this one?~~ Resolved by ADR-0037: no fill is lease-excused any more.
8. **Should the tripwire in §8.3 exist at all**, given how little it catches, or is a mechanism that
   is easy to over-read worse than none?

## Implementation decisions (2026-09-26)

Before implementation started, a planning pass surfaced places where the text above was ambiguous or
silent about something the code has to do one way or another. These are settled here, and the
sections above are amended in place where they said something that would now be wrong.

1. **No version bump on the extension channel.** §11.3 above proposed `PROTOCOL_VERSION` 1 → 2. It
   stays 1: every addition (`Push`, `capabilities`, the new request and response variants) is
   additive, and the protocol doc already says additive changes don't bump it. `Hello` gains
   `capabilities` as an **optional** field (absent means none); a session that never declares it is
   simply never pushed to.
2. **`RequestFill` joins the IPC protocol's already-unreleased v2, not a v3.** Protocol version 2
   (`kagisecure-ipc`) was added by [ADR-0040](0040-audit-before-release.md) and has not shipped yet,
   so this feature's request, response and error codes join it instead of forcing a further bump —
   the same way ADR-0040 itself extended the compatibility note above the version constant.
3. **There is no agent connection to bind a grant to.** The sidecar opens a connection to the app
   once per tool call rather than holding one open, so "the agent's connection" was never a stable
   thing to key on. Grants, the two-step flow and blocks are bound to and keyed on **the sidecar
   process** — its kernel pid and executable, plus the kernel-resolved parent executable as the block
   key — re-checked alive with the same executable (and, since decision 34, the same start time)
   at delivery. §6 and §7.3 above are corrected.
4. **The two-step grant is one approval and one crossing.** Read against
   [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md)'s "one Grant, one crossing" rule, the
   `AgentFillGrant` holds a single unspent `Approved`: step one writes only the username, which is
   metadata and is audited as `AGENT_FILL_APPROVED` step 1, not a crossing; step two consumes the
   `Approved` for the password. The broker lives in
   `crates/kagisecure-agent/src/extension/agent_fill.rs`, beside `crossing.rs`, and the scan test that
   checks no module but `crossing.rs` reads a secret is widened to cover it.
5. **Every agent fill is the full sheet, never a shortened presence check.** It is served through
   `AgentService.allow` → `presence.authenticate` on the shared presence-coordinator slot, with
   `presence_only` always false. `Approved::from_grant` takes an expected kind, so an `AgentFill`
   grant and a `FillCredential` grant can never satisfy each other — closing exactly the gap
   Alternative (e) above warns against.
6. **`Deliver` names both ids, and lands in the top frame through the API, not by convention.**
   `Push::Deliver { probe_id, grant_id }` still carries only opaque ids (§3.1: no value, no origin);
   `background.js` delivers with `chrome.tabs.sendMessage(tabId, msg, { frameId: 0, documentId })`,
   which is what actually enforces "top frame only" (§4) at delivery time.
7. **The audit actor string gets one explicit prefix, and the UI filters on it.** It renders as
   `mcp "<name>" [UNVERIFIED] pid N <exe> via <browser> (extension "<id>")`, with `client_pid` the
   sidecar's own pid. The macOS and Windows audit views' actor filters move from an exact match on
   `"mcp"` to a prefix match, so this and every other agent actor still match.
8. **Windows is excluded, not degraded.** §12 above gains a row for it: every `request_fill` answers
   `FILL_UNAVAILABLE` there, before any item is looked up, regardless of which browser is connected.
9. **The sheet's ui-spec section is §10.7.**
   [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md) took §10.6 first; the "a new §10.6"
   references above are corrected.
10. **The sheet's mock-up is brought in line with §9.2's button label.** §9.2 already specified
    *"Fill on example.com…"*; §5's diagram still showed *"Fill once…"* and is corrected to match.
11. **Notifications go through one queue, not an ad hoc call.** A notice queue in Rust, drained by
    `agent_fill_take_notices()` on the app's existing 1-second tick, is what §9.1 and §9.4's
    notifications above actually run on; it surfaces in Agent access, the menu-bar badge and
    `NSApp.requestUserAttention`, and as a system notification through `UNUserNotificationCenter`
    only once the user has authorized it — asked for when the feature switch is turned on.
12. **The feature switch is a convenience, not a boundary.** It lives in `AppDefaults`, pushed to an
    in-memory flag in Rust (`agent_fill_set_enabled`, default off), and turning it on asks for a
    presence check. It is not itself what makes a fill safe — the per-fill sheet and its biometric
    are — and it stays hidden in the UI until Phase 2's limiter (§9) lands.
13. **An archived item is `NOTHING_TO_FILL`, not `NOT_FOUND`.** It is found — unlike a trashed one —
    but is not a candidate for a fresh sign-in, so gate 4 in §11.1 answers it with a fixed sentence
    rather than gate 3 treating it as absent.
14. **A same-site check crosses into Rust.** `origin::continues_same_site(first, next)` mirrors
    `extensions/shared/tabmemory.js`'s `sameSite` check, so the identifier-first second step (§7.3)
    is judged identically on both sides of the wire.
15. **`request_fill`'s own description carries a "what it will not do" sentence.** The test that
    requires every tool description to say what it will not do needs one of its fixed phrases (for
    example "never returns a secret value"); the server instructions keep §8.2's sentence alongside
    the existing "cannot read a value" and `revoke_env_file` phrases.
16. **Every new error code needs code that returns it before it is documented as returned.**
    `FILL_UNAVAILABLE` lands with the feature-switch gate, `NOT_FOUND`/`NOTHING_TO_FILL`/
    `NO_MATCHING_TAB` with the item and target gates, and `RATE_LIMITED` with the limiter in Phase 2 —
    the same rule already applied to every other `ErrorCode` variant.
17. **An existing bug is fixed alongside this feature, not left for later.** Today the native host
    reconnects after a lock/unlock without re-sending `Hello`, so the session loses whatever
    capabilities it had declared. `kagisecure-nmhost` is changed to replay the last `Hello` envelope
    on reconnect, which this feature would otherwise depend on silently getting right.

Settled while building Phase 1's broker (`crates/kagisecure-agent/src/extension/agent_fill.rs`):

18. **One agent fill at a time, answered at gate 1 as `RATE_LIMITED`.** A single process-wide slot
    is held from gate 1 to the answer — a flow raises at most one sheet, so this is the stricter
    form of §9.1's "one sheet on screen at a time" — and a second request is refused at once,
    before its item is looked up, with a sentence of its own ("already asking the user about
    another agent fill"), audited as `AGENT_FILL_BUSY` so the log can tell it from an agent over
    its budget. Queuing it was rejected for §9.1's reason. Phase 1 answered it `FILL_UNAVAILABLE`,
    because decision 16 kept `RATE_LIMITED` out until the limiter produced it; Phase 2's limiter
    does, and §9.1 names that code for this case, so the busy answer moved to it. The slot is the
    last of gate 1's checks (decision 27): a blocked or over-budget agent is told so rather than
    "busy".
19. **Gate 1 also needs a sidecar the kernel vouches for.** A caller whose pid did not come from the
    kernel, or whose executable cannot be resolved, cannot be bound to (decision 3) and is
    `FILL_UNAVAILABLE`. The arguments are checked right after gate 1, before gate 2: an `origin`
    that does not parse as an http(s) origin is `INVALID_ARGUMENT`, and — until Phase 3 —
    `one_time_code` is `FILL_UNAVAILABLE` with its own sentence. Neither depends on the item.
   *(Phase 3 removed the one-time-code refusal and its entry: a code is served, decision 41.)*
20. **Gate 6 in detail.** A report is *in front* when it is frame 0 as the browser established it,
    the tab is active and the document visible. If exactly one in-front report is eligible (claim
    byte-equal, covered by the item, fields found, not identifier-only — the last lifted by
    Phase 3, decision 41), it is chosen — even if
    another browser's tab in front is somewhere else entirely. If none is, and some in-front
    report's origin is not covered by the item, the request is `AGENT_FILL_ORIGIN_MISMATCH` —
    but only when that report can be the agent's own (decision 26); otherwise
    `AGENT_FILL_NO_TARGET`. The probe window (2 s) ends early once
    every asked session has reported; the extension always reports, with an ineligible report when
    it has nothing to say. Gates 3 and 4 are asked again after the probe, on the vault as it is
    then.
21. **Any attempt to redeem a grant spends it.** The grant leaves the store before a single binding
    is compared, so a redemption from another session, tab, document or origin — or after the
    sidecar process has exited or its pid has been reused by another program — refuses that
    request *and* the rightful one after it. An `AgentFillOutcome` for a grant never redeemed
    (the delivery could not reach the document) ends it the same way.
22. **`AGENT_FILL_NOT_DELIVERED` names no entry.** The `Allowed` entry is written only at release
    (§10), so an approval that never reached a release has no entry N to follow; the table's
    "(entry N)" applies to the follow-ups only.
23. **A release the extension never reports on is `AGENT_FILL_NOT_CONFIRMED (entry N)`.** After a
    value is released, the broker waits up to ten seconds for `AgentFillOutcome`; if it does not
    come (or the extension's connection closes first) that follow-up is recorded and the agent is
    answered `NO_MATCHING_TAB` — it may have been typed, but the app cannot say so, and "filled" is
    the one answer it must not give falsely. A reply frame that could not be written is recorded as
    `REPLY_FAILED (entry N)`, as for every fill, and answered the same way.
24. **The document-id degradation is recorded in the approved entry's detail**, as
    `AGENT_FILL_APPROVED (no document id)`. The binding is to the document id *as reported*: a
    redemption whose document id differs from the report's — including one that suddenly has none
    — is refused.
25. **Notices queue in Rust from Phase 1** (`AgentFillBroker::take_notices`, bounded), with the
    origin in its look-alike rendering; the FFI export and the UI are Phase 2's (decision 11). The
    broker is process-wide (in the FFI beside the approval queue) and outlives both listeners, so
    Phase 2's blocks can live there too; its lock revocation runs from both listeners' lock hooks
    and from the `lock` tool.

Settled while building Phase 2's limits (`crates/kagisecure-agent/src/extension/agent_fill/limits.rs`):

26. **An origin mismatch counts only when the tab can be the agent's.** With more than one browser
    or profile connected, the tab in front of *another* one is the human's own browsing. Recording
    its origin would put what the human is looking at into an audit log other local processes can
    read, and counting it would let the human's browsing block an agent. So a mismatch — audited
    with its origin, reported, and counted toward §9.4's block — is only an uncovered report that
    is the **only** report in front, or whose origin **equals the agent's claim** (which the agent
    already knows). With several reports in front and none eligible, the request is
    `AGENT_FILL_NO_TARGET` with no origin recorded, and nothing is reported or counted.
27. **Gate 1, in order.** After the switch and a kernel-established sidecar: a **block**, then a
    **sticky denial**, then the agent's **budget**, then the **one-flow slot** (decision 18). All
    four are decided before the vault or the item is consulted. A blocked agent and a repeat of a
    denial are both `USER_DENIED` audited `AGENT_FILL_BLOCKED`, each with its own sentence; only the
    repeat's entry names the item and the claimed origin, because only it follows a request that
    got past gate 3 before.
28. **The key is the sidecar's kernel-resolved parent executable, resolved once, at gate 1.** It
    is also what the sheet shows as the agent's parent, so the program the human sees is the one a
    block covers. A sidecar whose parent (or the parent's executable) cannot be resolved is
    `FILL_UNAVAILABLE`, like one whose own executable cannot (decision 19): a request no limit can
    be keyed on is not served.
29. **Three sheets per ten minutes, then ten minutes of refusals.** The budget counts **sheets**,
    from the moment each is raised — not requests, since a request that ends at `NO_MATCHING_TAB`
    cost the human nothing. The request after three sheets inside a sliding ten-minute window is
    `RATE_LIMITED`, and so is every request from that agent for the ten minutes after it, as
    §9.1's notification text says ("further requests are refused for 10 minutes"). One notice
    (`AgentFillNotice::RateLimited`) is queued when that refusal period starts, none for the
    requests inside it. The budget, like every limit here, survives a lock.
30. **A sticky denial is keyed on (agent, item id, claimed origin)** — not on the fields, so asking
    for the password alone after a denied username-and-password is the same question. Both a
    denial and a sheet left to time out stick for ten minutes. A request that timed out is
    therefore answered `USER_DENIED`, not a second sheet, if it is retried within them — which
    overrides, for this tool only, `APPROVAL_TIMEOUT`'s "may retry once" in §11.2.
31. **Deny and block is a `Decision`, not a flag.** `Decision::DenyAndBlock` (UniFFI
    `ApprovalDecision.denyAndBlock`; the C ABI has no tag for it, decision 8) resolves as a denial
    and tells the broker, through `Outcome::block_agent`, to block the agent for thirty minutes; on
    any sheet but an agent fill's it is a plain denial. It needs no biometric — saying no is always
    allowed (ui-spec §10.3). Its own entry is `AGENT_FILL_DENIED (agent blocked)`, and the
    mismatch that blocks is `AGENT_FILL_ORIGIN_MISMATCH (agent blocked)`, so the log records when a
    block began; a block that is already there is never shortened.
32. **What survives a lock, and what an unblock lifts.** Blocks, sticky denials and budgets live in
    the process-wide broker and survive a vault lock; only the origin-mismatch count is per unlock
    session, reset by whatever ends the grants (a lock, the agent listener stopping, *Revoke all*).
    `agent_fill_unblock(key)` lifts the block and nothing else: a denial the human gave still
    stands for its ten minutes, and the mismatch count stays, so a further mismatch in the same
    unlock session blocks again. Unblocking is not audited — the broker holds no vault, and the
    block list is not a record of anything released.
33. **Notices are for what the human did not see.** Three kinds cross the FFI
    (`agent_fill_take_notices()`): `OriginMismatch`, `RateLimited` (once per refusal period) and
    `Blocked` (the second-mismatch block, which happened without anyone pressing anything). Deny
    and block and an unblock are the human's own acts and produce none; the blocks list
    (`agent_fill_blocks()`: key, the reported name of the agent that set it, reason, and the Unix
    time it lifts or none) is how the app shows them. The limits read an injectable clock
    (`AgentFillClock::manual_for_test`) so tests see ten and thirty minutes pass without waiting.

Settled while fixing the findings of an independent security review (2026-09-26):

34. **The sidecar is bound by its start time too.** Every sidecar runs the same executable, so
    "the pid is alive with the same executable" (decision 3) could not tell the sidecar that asked
    from another one that was handed its pid after it exited. The kernel's record of when the
    process started is captured when the request arrives and compared again at redemption:
    `proc_pidinfo(PROC_PIDTBSDINFO)` on macOS, `starttime` in `/proc/<pid>/stat` on Linux
    (`kagisecure_ipc::server::process_start_time`). Where neither exists the binding is the pid
    and executable alone, as before; that includes Windows, which never offers agent fills
    (decision 8).
35. **A redemption cannot hold the one flow slot forever.** The flow waits on a redemption for at
    most `REDEEM_DEADLINE` (the release transaction's 5-second wait for the vault file, plus ten
    seconds), and a session that goes away while its redemption is still marked as running — its
    thread panicked, which is the only way that happens, since a session is deregistered on the
    thread that redeems for it — ends the flow as `AGENT_FILL_NOT_DELIVERED` at once. Either way the
    agent is answered `NO_MATCHING_TAB` and the slot is free. A redemption settles only the flow
    that issued its grant, and only while that flow is still waiting; one that commits its
    `AGENT_FILL_APPROVED` entry after the flow gave up hands nothing to the extension and records
    `AGENT_FILL_NOT_DELIVERED (entry N)` as that entry's follow-up — the one case where that
    detail names an entry (decision 22).
36. **Past gate 6, a sheet, a notice or `NO_MATCHING_TAB` — nothing else.** Once a tab in front
    has been chosen — at the claimed origin, covered by the item, fillable — any other answer
    given without a sheet would be §11.2's one bit, "this item is saved for the site I am on", for
    free, where a mismatch costs a notice and, the second time, a block. Two answers could do
    that: `AUDIT_UNAVAILABLE` from the pre-flight (an agent that holds the vault file's lock can
    make entries queue), and `VAULT_LOCKED` from a closed approval queue (an agent that calls
    `lock` while the browsers are being asked closes the queue with the vault still in the
    handle). So the pre-flight runs before gate 5, and a lock since the flow began is answered
    right after the probe, before a report is read; both answers are then the same whatever the
    tab is. What is left is a lock landing between that check and the sheet being queued — no
    I/O happens in between — and each try at that costs a vault lock only the human can undo.
    The same rule is why a session that disconnects after being chosen is `NO_MATCHING_TAB`.
37. **Every way out is recorded, and what is not recorded is named.** §10's "at least one entry"
    now holds for the arguments (`INVALID_ARGUMENT`, and `FILL_UNAVAILABLE` for a one-time code),
    gate 2 (`VAULT_LOCKED`, `VAULT_CONFLICT`), gates 3 and 4 asked again after the probe, a lock
    found after the probe or at the sheet (`VAULT_LOCKED`, the same entry wherever it is found, with
    no browser and no origin), and an approval a lock took before anything was released
    (`AGENT_FILL_NOT_DELIVERED`, answered `VAULT_LOCKED`). Each is best-effort, as ADR-0040 makes
    every refusal, and never changes the answer. Entries written before the item is looked up,
    and the one for an item found hidden after the probe, name no item, so they read the same for
    a hidden item and an absent one. Three answers still leave none: the switch off and a sidecar
    the kernel cannot vouch for (gate 1, `FILL_UNAVAILABLE`) — nothing about the request was
    looked at, and the second has no process to name as the actor — and any refusal after a lock
    has already taken the key, when there is no vault to write to.

Settled while building Phase 3 (identifier-first sign-ins, one-time codes and the tripwire's
follow-up):

38. **Step two may come from the same document.** §7.3 said "one later document". A site whose Next
    button swaps the form in place without navigating keeps its document id, and the extension
    reports step two from it. That is accepted: what step two is bound to is the extension session,
    the tab, and an origin that continues step one's by the same-site rule and is covered by the
    item — and the same document is the same tab at the same origin, so it is strictly inside
    those bounds. Requiring a new document id would refuse exactly the single-page sign-ins
    identifier-first flows most often are, and would buy nothing: the grant for step two is still
    bound to the document step two reported.
39. **Step two is decided at gate 1, and served without a sheet or not at all.** A request is a
    *continuation* when it comes from the same sidecar process as step one (kernel pid, executable
    and start time — never the name it reports), names the same item, asks for exactly
    `["password"]`, and arrives inside the flow window with no lock since. Gate 1 takes the pending
    step out of the store for it, so it is the step's only chance (decision 21's rule). It raises
    no sheet, so the agent's budget of sheets does not apply to it; a block and a sticky denial
    still do. Only the browser session that served step one is asked, and the step is served only
    if the report from **that session and tab** is in front, at the claimed origin, continues step
    one's origin by `continues_same_site`, is covered by the item and has a password field. Anything
    else is `NO_MATCHING_TAB` — with §9.4's mismatch handling if the tab is now on a site the item is
    not saved for — and step one's entry gets `AGENT_FILL_PENDING_REFUSED (entry N)`; the agent's
    retry is then a new request with a sheet of its own. §7.3 had "a document that fails the
    same-site rule" raise that sheet at once; it does not, because a sheet raised there would have
    skipped the budget gate 1 applies to every sheet. Another item, another sidecar, another field
    set, a late call or one after a lock is never a continuation, and leaves a pending step alone.
40. **Step one is a release of its own, and the approval waits for step two.** Step one's reply is
    built by `crossing::username_only`, which borrows the `Approved` rather than spending it
    (decision 4); it goes through the same audited release as every fill, as
    `AGENT_FILL_APPROVED (step 1 of 2)` with `variables: ["username"]`. Step two's entry is
    `AGENT_FILL_APPROVED (step 2 of 2, entry N)`, naming step one's, with `variables:
    ["password"]`. The flow window runs from the approval and bounds step two's grant as well as
    the wait for it. Step one is answered `fields_written: ["username"]`, `fields_pending:
    ["password"]` — even when a lock overtook it, because the password is not written either way.
    Nobody waits on the MCP side after that answer, so a watcher thread ends a pending step whose
    window closes or whose browser session goes away, and records `AGENT_FILL_PENDING_EXPIRED
    (entry N)`; a lock clears pending steps with the key, and records nothing (decision 37).
41. **A one-time code is served, under `totp_code`.** The Phase 1 refusal (decision 19) is gone.
    A code request is always a flow of its own with its own sheet — no pending step and no other
    approval covers it, since a continuation asks for the password alone — its target must report
    a one-time-code field, and its grant is spent by `crossing::totp_code` into the extension's
    `totp_code` reply. Every entry about it, from gate 1 on, is written under the tool name
    `totp_code` with `variables: ["one_time_code"]`. The approval remembers which path asked for
    it, so the human path's approval of a code (`one-time password`) and an agent's
    (`one_time_code`) never stand in for each other. The eligibility rule of decision 20 loses its
    "not identifier-only": page one of an identifier-first sign-in is a single-step target for
    `["username"]` and a two-step target for `["username", "password"]`.
42. **The tripwire is a follow-up and a notice, never a fill.** An `UNMASKED` outcome counts only
    from the session and for the grant of a fill whose first outcome reported the password
    written, within fifteen seconds of that first outcome (the content script watches for ten),
    and once per fill — whether it arrives while the flow is still ending or after. It is recorded
    as `AGENT_FILL_UNMASKED (entry N)` and queued as `AgentFillNotice::Unmasked` (the agent, the
    item's title and the origin, rendered as the sheet rendered it). Nothing is released for it
    and no answer changes. Anything else — for step one's username, for a code, late, repeated,
    or for a grant nobody issued — is ignored.
43. **Asking whether an item has a working one-time password copies no seed.** Gate 4 and the
    extension's own code path ask before anything is approved. They used to build a generator to
    answer, which percent-decoded the seed into buffers dropped unzeroized; the question is now
    answered by `Totp::check_uri`, which validates the URI in place, and building a generator
    decodes the seed straight into the buffer its `Secret` owns. Found in the security review of
    Phases 1 and 2, as the TOTP counterpart of the password predicate's borrow.

## Implementation outline

Each phase ships on its own, with its tests, and none starts before ADR-0039 and ADR-0040 have
landed (both have, on `main`).

**Phase 1 — Chromium, username and password, single page.**
Extension protocol v2 (`Push`, `capabilities`, `TargetReport`, `AgentFill`, `AgentFillOutcome`,
`Noted`); full-duplex `kagisecure-nmhost`; `AgentFillBroker` and `AgentFillGrant` in
`kagisecure-agent`, with lock, disconnect and expiry revocation; `RequestFill` on the IPC protocol
and `request_fill` in the sidecar; `ApprovalKind::AgentFill` and its sheet (look-alike rendering,
Allow delay, biometric every time); the feature switch; audit details and ADR-0040 release; the
content script's probe and write paths, top frame only. Until Phase 3, an identifier-only page
answers `NO_MATCHING_TAB`.
Tests: the sidecar canary with a *successful* fill; `Push` carries no `FillValue` field; hidden and
absent items produce byte-identical answers on the same code path, before any push; each binding in
§6 refused when changed alone (tab, document, origin, sidecar process, extension session, expiry,
second use); a fill lease never excuses an agent fill and an agent approval never mints one; lock
during the sheet leaves no grant; the browser end-to-end suite (`make e2e SUITE=extension`) drives one
approved fill and one look-alike refusal.
Docs: [mcp-server.md](../mcp-server.md) §2 (ten tools) and §7,
[browser-extension.md](../browser-extension.md) §1, §3, §4, [ui-spec.md](../ui-spec.md) §10 (a new
§10.7 — §10.6 is ADR-0037's), and ADR-0018's sentence in Consequences.

**Phase 2 — Approval fatigue.** Phase 1 is not offered to users without it: the feature switch
stays hidden until this lands, because a sheet an agent can raise without limit is the failure §9
exists to prevent. §9 in full: the limiter, sticky denials, Deny and block, the
blocks list in Agent access, mismatch notifications and the second-mismatch block, and — if open
question 4 is answered yes — the escalation challenge. Tests drive bursts and assert the count of
sheets shown, not just the codes returned.

**Phase 3 — Identifier-first and one-time codes.** The two-step grant (§7.3), `one_time_code` with
its own sheet and no clipboard fallback (§7.4), and the tripwire (§8.3) if open question 8 keeps it.

**Phase 4 — Safari.** Measure app-to-extension messaging through a containing app on a
Developer-ID-signed build, as ADR-0024 measured the socket; then declare `"agent_fill"` from the
Safari front end, with the `documentId` degradation of §4 if it is absent.

**Related, separate:** the automation check for human-path leases (§8.4, open question 7) —
no longer needed after ADR-0037.

## Proposed roadmap changes

> **Applied 2026-09-26.** The owner chose to implement this ADR before
> [ADR-0035](0035-shared-vaults.md), which settled the order this section was waiting on, so the
> three edits below are now in [roadmap.md](../roadmap.md): the TOTP-injection item is split, the
> new milestone is **M9**, marked done with the caveats in "Implementation status" below, and M6's
> criterion carries the clause. ADR-0035 is not scheduled by this; its own proposal stands.

Recorded here rather than edited into [roadmap.md](../roadmap.md). Accepting the ADR (2026-09-26)
did not apply them: where the new milestone slots in depends on the order in which this ADR and
[ADR-0035](0035-shared-vaults.md), accepted the same day, are implemented, and they are applied
when that order is set.

- **Post-v1, "TOTP code injection with per-use approval"**: split. The *browser* case — an agent
  asks for a code to be filled into a page — is covered by this ADR's Phase 3. The *environment*
  case — a code injected into a process or file, the `run_with_env`-style tool M5's last criterion
  deferred — is not, and stays unscheduled under that name.
- **A new milestone, "Agent-requested browser fills"**, after M8, with acceptance criteria taken
  from this ADR: no tool result carries a value, asserted by the canary with a successful fill;
  a fill lands only in the visible, active, top-frame document whose browser-established origin is
  covered by the item and equals the agent's claim; every agent fill needs a sheet and a biometric;
  hidden and absent items are indistinguishable; sheets per agent are bounded; every request is
  audited, and nothing is released that could not be; Safari parity or a documented reason for its
  absence.
- **M6's criterion "Autofill never fires without an explicit user action for that page load"**
  needs one clause once this is accepted: *"…or an approval in the app, with a biometric, for an
  agent's request naming that page."* The human-path criterion itself is unchanged.

## Implementation status

Phases 1–3 are built; Phase 4 (Safari) is not scheduled. Where each piece lives:

| Piece | Where |
| --- | --- |
| `request_fill`, the tool | `crates/kagisecure-mcp/src/server.rs`; `Request::RequestFill`, `Response::FillResult` and `FILL_UNAVAILABLE`, `NO_MATCHING_TAB`, `NOTHING_TO_FILL`, `RATE_LIMITED` in the unreleased IPC protocol version 2 (`crates/kagisecure-ipc`) |
| The gates, the broker, the grant, the limits | `crates/kagisecure-agent/src/service.rs` (gates 1–4), `src/extension/agent_fill.rs` and `agent_fill/limits.rs`; the value still crosses only in `crossing.rs` |
| The extension channel | `Push`, `capabilities`, `TargetReport`, `AgentFill`, `AgentFillOutcome` in `crates/kagisecure-extension-ipc` (protocol version still 1); a full-duplex `kagisecure-nmhost` that replays the extension's `hello` after reconnecting (decision 17) |
| The extension | `extensions/shared/background.js`, `content.js`, `native.js` — Chromium declares `agent_fill`, Safari never does |
| The app | The sheet (ui-spec §10.7), Touch ID every time, the feature switch with its presence check, *Deny and block*, the blocks list and the notices, in `apps/macos`; the FFI's `agent_fill_*` calls are UniFFI only |
| Windows | Excluded (decision 8): every call is `FILL_UNAVAILABLE`; the C ABI gains only the `AgentFill` approval tag (ABI version 5), which the app denies |

### What is and is not verified

**Tested headlessly, and passing on this branch** (`make check`, `cd extensions/chrome && npm
test`, `make e2e SUITE=mcp,cli`):

- every gate in §11.1's order, each binding of §6 refused when changed alone (sidecar pid,
  executable and start time; extension session; tab; frame 0; document; origin; expiry; second
  use), a lock during the sheet, hidden and absent items answered alike before any browser is
  asked, leases never crossing in either direction — `crates/kagisecure-agent/tests/agent_fill.rs`
  and `agent_fill_adversarial.rs`, against a scripted service worker over the real extension
  client;
- the limits of §9 by counting the sheets shown, on an injectable clock — `agent_fill_limits.rs`;
- identifier-first sign-ins, one-time codes and the tripwire's follow-up —
  `agent_fill_steps_and_codes.rs`;
- the canary with a **successful** fill: the real `kagisecure-mcp` binary, and the marker in no
  byte it writes, in any of six encodings — `agent_fill_sidecar.rs`;
- no `Push` carries a fill value; the host's duplex forwarding and `hello` replay; a one-time
  password's setup checked without leaving its seed in freed memory (decision 43) — the crates' own
  tests;
- the extension's locate, deliver, code and tripwire paths — `extensions/chrome/test/agent_fill.test.js`;
- `request_fill` on the headless daemon — e2e suite A.

**Compiled, never run.** The Swift unit tests for the sheet, the switch, *Deny and block*, the
notices and the gate's agent-fill cases (`AgentFillApprovalTests`,
`AgentFillSwitchAndNoticesTests`, `BiometricGateAdversarialTests`) — they take over the GUI, and
need the owner's go-ahead. **Written, not compiled:** the two C# edits (the approval-tag enum
member and the audit view's actor prefix); there is no .NET SDK on the machine this was built on.

**Needs the owner, with a real browser and the real app.** Nobody has yet seen an agent fill end to
end: a real agent, the app's sheet, a real Touch ID, and the value landing in a real Edge or Chrome
tab. e2e suite B has four scenarios for the browser half — an approved fill lands in the tab in
front, a look-alike raises no sheet, an identifier-first sign-in needs one sheet for two pages, a
one-time code never touches the clipboard — written and wired in but **not yet run**, because the
suite opens a visible browser window. What they cannot show even when run is the app: they answer
the queue with a robot, as every browser scenario does. The app's side — the sheet raised by a
browser-bound request, the 1.5-second Allow delay, the switch's presence check, the menu-bar badge
and system notifications — has no XCUITest scenario and has been checked only by the compiled
unit tests above. Until one of those runs, the claims in this ADR about the app are the design's,
and the claims about the browser are the Rust and JavaScript tests', not an observation.

## Pointer 2026-09-27 — unattended fills of machine-vault logins

[ADR-0042](0042-unattended-agent-access.md) §12, accepted for macOS and since built (Phase 5), lets a job kagisecure starts sign in with a **machine-vault** login under a standing login
grant, in a browser kagisecure launched for that run, at one exact origin. For those fills only,
§3.2's visibility rule is dropped and §5's sheet and biometric are replaced by the grant. Every
fill this ADR describes — into the user's own browsers, of personal, shared or machine-vault
logins — is unchanged.

## Amendment 2026-10-03 — agents fill without prompts during grace

The owner's direction: one Touch ID should let everything fill, AI agents included, until the vault
locks; stricter behavior is to be layered back per organization or person later. So:

1. **No sheet, no prompt inside the grace window.** While ADR-0037's [app-wide grace window](0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-10-03-app-wide-sliding-grace-window)
   is open, an agent fill — a login, a two-step sign-in or a one-time code — is granted at once,
   with no sheet and no Touch ID, and the use extends the window. Outside it, the sheet and the
   check are as before. The stricter behavior is kept as a setting, "Always show the sheet for agent
   fills" (`agentFillRequiresSheet`, off by default), for a future policy layer to enforce.
2. **No Allow hold.** The 1.5-second hold on Allow (§5) is zero; Allow is enabled while the sheet is
   key and visible.
3. **§9 limits relaxed.** The sheet budget (§9.1), sticky denials (§9.1) and the block after a
   second origin mismatch (§9.4) are removed. A mismatch is still refused, audited and noticed; it
   no longer escalates. **Deny and block** (§9.3) and the one-flow-at-a-time slot stay.
4. **The switch is on by default** (§2), and turning it on asks for no presence check.
5. **Background tabs (§3.2).** The `locate` push now carries the claimed origin. The extension asks
   every normal-window tab's top frame for its origin and reports the one on that origin — the
   active tab of the last-focused window first, then any active tab, then the most recently used —
   falling back to the tab in front when none matches (so §9.4's look-alike signal still works).
   The app no longer requires an eligible report, a grant redemption or a step-two report to be
   active or visible; it still requires frame 0, the claimed origin, a covering saved site and the
   fields. With several eligible reports it takes the one in front if exactly one is. Delivery
   waits up to a second for a covered document to become visible, then fills anyway.

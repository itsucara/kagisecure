# The browser extension

How autofill works, how to set it up, and what is deliberately not built yet.

Companion documents: [threat-model-browser-extension.md](threat-model-browser-extension.md) for
what it costs and what is done about it, and [architecture.md](architecture.md) for everything
below the socket.

---

## 1. What it does

Two things on your explicit action, and one on an agent's request that you approve:

- **Fill a login.** Click the key icon that appears in a matched site's password field, or press
  **⌘\\**. The app raises its approval sheet and asks for Touch ID (or your login password, or an
  Apple Watch); the username and password are written into the form. If you chose **Allow for
  this session**, the same fill on the same site in the next few minutes skips the sheet — but
  not, by itself, the Touch ID check: a fill that carries a password or a one-time code asks for
  it ([ADR-0037](decisions/0037-every-fill-needs-a-fresh-presence-proof.md)) unless the app-wide
  grace window is open. Any successful Touch ID check in the app opens that window, every use
  extends it, and by default it lasts until the vault locks (10 minutes, 30 minutes or 1 hour in
  **Settings › Security & Unlock**;
  [amendment of 2026-10-03](decisions/0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-10-03-app-wide-sliding-grace-window)).
- **Fill the username on an identifier-first page.** Google, Microsoft and Okta ask for the
  username on one page and the password on the next. The icon appears in that first page's
  username box too, and the click writes **the username and nothing else** — which carries no
  secret, so there is no approval sheet and no fingerprint. Your click is still required, the
  origin rule still applies, and the fill is still audited, as `FILL_USERNAME_ONLY`
  ([ADR-0030](decisions/0030-identifier-first-login.md)).
- **Copy or fill a one-time code.** A second, separate click, and its own Touch ID. Never bundled
  into the fill.

- **Fill a login an agent asked for** ([ADR-0036](decisions/0036-agent-requested-browser-fill.md),
  Chromium only, on by default; turn it off in **Settings › AI Agents**). An agent driving your
  browser calls `request_fill` with an item and the origin it believes it is on. The app asks every
  connected browser for a tab at that origin — the tab in front if it matches, otherwise a
  background tab on that site (top frame only) — and goes ahead only if the tab is a site saved for
  the item and has the login fields. While the grace window is open, the fill goes through with
  **no sheet and no Touch ID**
  ([ADR-0036 amendment of 2026-10-03](decisions/0036-agent-requested-browser-fill.md#amendment-2026-10-03-agents-fill-without-prompts-during-grace));
  outside it, the app raises its **own sheet** naming the agent, the site and the item, with Touch
  ID. "Always show the sheet for agent fills" (Settings › Security & Unlock › Advanced, or
  Settings › AI Agents) restores the sheet for every agent fill. The value is typed into that
  tab by the extension, exactly as for your own fill; the agent is told only which fields were
  written. An agent that can run script in the page can read what is typed there — the sheet says
  so. A look-alike site raises no sheet at all: it is refused by the origin rule and audited as
  `AGENT_FILL_ORIGIN_MISMATCH`. An identifier-first sign-in is one sheet for both pages: the
  username now, and the password on the next page of the same tab when the agent asks for it,
  without another sheet. A one-time code is always its own request (with its own sheet when one is
  shown), and is written only into the page's code box — never copied to the clipboard.

There is **no autofill on page load**, ever. Not as a default, not as a setting. An agent's request
is not a page load — but it is honest to say that, inside the grace window, an agent's fill is
approved by the Touch ID you gave earlier, not by a new one for that page.

**Page two continues where page one left off.** Having picked an item on the identifier page, the
extension remembers *which item* for that tab — an id and an origin, in memory, for **60 seconds**
— so the password page fills that account instead of asking you to choose again. The popup says so
("Continuing as …") and has a **Forget** button. The memory is dropped when it expires, when the
tab is closed, when the tab leaves the site (subdomains of the site you started at still count;
nothing else does), when the vault locks, or when the password fill happens. Nothing about it is
written to disk, and it chooses *which* item, never *whether* to fill — the click is still yours,
and so is the Touch ID check for the password.

## 2. The shape

```text
   the page                    the extension                    the app
  ┌──────────┐         ┌───────────────────────────┐      ┌──────────────────┐
  │  form    │◀───────▶│ content script            │      │ ExtensionAgent   │
  │  fields  │  writes │  · finds the form         │      │  · origin rule   │
  └──────────┘         │  · draws the icon         │      │  · approval sheet│
                       │  · ⌘\ handler             │      │  · biometric     │
                       │  · writes the value       │      │  · fill leases   │
                       └─────────────┬─────────────┘      │  · audit         │
                          runtime    │  message           └────────┬─────────┘
                       ┌─────────────▼─────────────┐               │ Unix socket
                       │ service worker            │               │ 0600 in a 0700 dir
                       │  · the native port        │               │
                       │  · stamps the real origin │      ┌────────▼─────────┐
                       │  · caches nothing         │◀────▶│ kagisecure-nmhost│
                       └───────────────────────────┘ stdio│  a pipe, no vault│
                                                          └──────────────────┘
```

Four processes, three boundaries, and one value that crosses all of them — once, per approval.

**Safari takes a shorter route.** There is no helper binary and no manifest, because the extension
is an app extension *inside this app's own bundle*; it talks to the app over a second socket in the
App Group container the two of them share ([ADR-0024](decisions/0024-safari-app-group-socket.md)).
Everything to the left of the transport — the content script, the icon, ⌘\, the popup — is the
same code, from the same directory.

```text
   the page                    the extension                    the app
  ┌──────────┐         ┌───────────────────────────┐      ┌──────────────────┐
  │  form    │◀───────▶│ content script (shared)   │      │ ExtensionAgent   │
  └──────────┘         └─────────────┬─────────────┘      │  · one origin    │
                          runtime    │  message           │    rule          │
                       ┌─────────────▼─────────────┐      │  · one sheet     │
                       │ service worker (shared)   │      │  · one lease     │
                       └─────────────┬─────────────┘      │    store         │
                        sendNative-  │  Message           └────────┬─────────┘
                       ┌─────────────▼─────────────┐               │ Unix socket
                       │ SafariWebExtensionHandler │◀──────────────┘ 0600 in a 0700 dir
                       │  inside Kagisecure.app    │        inside the App Group container
                       └───────────────────────────┘
```

### Why a native messaging host at all

A browser extension cannot open a Unix socket. `chrome.runtime.connectNative` is the only channel
Chromium offers to a local program, and it launches a child process and speaks length-prefixed
JSON over its stdio. So `kagisecure-nmhost` exists to be that child.

It is deliberately nothing else: it links one crate, cannot name `Secret`, cannot open a vault, and
makes no decisions. Chrome performs **no signature check** on a native host — it launches whatever
the manifest names — so the correct amount of authority to give the thing Chrome launches is none
([ADR-0019](decisions/0019-native-messaging-forwarder.md)).

### Both directions, on macOS and Linux

The app may speak first — a *push* (§3), for agent-requested fills
([ADR-0036](decisions/0036-agent-requested-browser-fill.md)) — so on macOS and Linux the host is
**full duplex**. It connects to the app on the browser's first request, which is always `hello`,
and keeps that connection for the life of the port. A reader thread routes each reply to the
request waiting for it and each push to a second thread, which writes it to stdout; both writers
share one lock held for a whole frame, so frames never interleave. Requests are still answered one
at a time, in the order the browser sent them, each exactly once. Pushes keep their own order but
are not ordered against the replies: a push the app sends just after a reply can reach the
browser just before it.

Nothing is copied through. A push is written as a frame the host builds from its typed form, and
an app frame that is neither a well-formed push nor a well-formed reply is dropped. A reply that
does not parse is answered to the browser as `PROTOCOL` with a fixed sentence — never the parser's
message, which could quote the bytes it failed on.

**After a reconnect the host says hello again.** Locking the vault stops the app's listener and
closes the host's connection; the host reconnects on the next request. The app's session state
(which extension said hello, and what it can do) went with the old connection, so before
forwarding anything else the host replays the last `hello` it forwarded — which carries no value
— and drops the app's answer to it rather than passing the browser a reply it never asked for.
Before this, the first requests after an unlock were refused with `PROTOCOL` ("Say hello before
asking for anything else") until the popup was opened or the service worker restarted, because
the extension still believed its session was live.

**Windows is lock step, and forwards no pushes.** A client pipe there cannot be read and written
at once, so a reader thread of the host's own would deadlock against its writes. Windows never
offers agent fills (ADR-0036 §12), so the host drops any push it is handed there. The hello replay
applies on every platform.

**The extension reconnects on its own, too.** The replay above still needs *some*
request to trigger it, and an already-open tab that neither navigates nor opens the popup sends
none — so `request_fill` kept answering `FILL_UNAVAILABLE` after an unlock until the person reloaded
the page by hand. `native.js` now retries `hello` on its own after the Chromium port drops, with
backoff (1 s, doubling to 30 s), until a `welcome` comes back — locked or not, since the app only
answers `hello` at all while its listener is up. Off until `background.js` turns it on at load
(`KsNative.enableAutoReconnect`), so nothing here changes for Safari, which has no port to drop, or
for a test that drops the port on purpose and expects nothing further to happen on its own.

## 3. The protocol

A second socket, beside the agent socket in the same `0700` directory, with a **different wire
format**: 4-byte big-endian length + JSON, where the MCP channel is little-endian
([ADR-0019](decisions/0019-native-messaging-forwarder.md) §3). Frames written for one channel are
refused by the other before their body is read.

Every message is wrapped in an envelope carrying a `ksx` channel marker and a correlation id.

| Ask | Answers | Prompts? | Carries a value? |
| --- | --- | --- | --- |
| `hello` | `welcome` — protocol version, unlocked, what the app established about the host | no | no |
| `status` | `status` — unlocked | no | no |
| `match` | `matches` — item ids, titles, usernames, whether a code exists | no | no |
| `fill` | `filled` — only the fields that were asked for | only if `fields` names the password: first time per (origin, item) per unlock | **only if asked for** |
| `totp` | `totp_code` — **the code**, seconds remaining | same | **yes** |
| `target_report` | `noted` | no | no |
| `agent_fill` | `filled` (or `totp_code` for a one-time-code grant) — only the granted fields | no — the sheet was the agent's, before the `deliver` push | **yes** |
| `agent_fill_outcome` | `noted` | no | no |

The last three belong to agent-requested fills
([ADR-0036](decisions/0036-agent-requested-browser-fill.md)), where the request starts on the MCP
socket and the app has to find the tab. For that the app may **speak first**, with a *push*: a frame
`{"ksx":1,"push":{…}}` that has neither the `id` nor the `body` of a reply, so it cannot be routed as
the answer to anything and a reply cannot be read as one.

| Push | Carries | The extension answers with |
| --- | --- | --- |
| `locate` | a probe id | `target_report` from the top frame of the active tab of the last-focused window: the probe id, the page context, the tab facts the browser stamped (tab id, document id, whether the tab is active) plus whether the document is visible, and which of username, password and one-time-code fields the detectors found |
| `deliver` | the probe id and a grant id | `agent_fill` from the same tab and document, once the form has been re-checked; then `agent_fill_outcome` with the field **names** written, or why nothing was — and once more if the ten-second tripwire clears an unmasked password |

A push is a doorbell: two opaque ids and nothing else — no value, no origin, no item id, no title
(`protocol::tests::no_push_carries_a_fill_value`). Everything that carries information is still a
request the extension sends and the browser stamps, and the value an approved agent fill releases
goes back in the same `filled` reply a human fill gets, built by the same constructor.

Pushes go only to a session whose `hello` declared the `agent_fill` capability. `hello` carries an
optional `capabilities` list for that: absent means none, which is what every extension built
before the list existed sends, and a capability the app does not know is ignored rather than
refused. That is why none of this changed the protocol version — an extension that does not know
the new messages never declares the capability, so it is never pushed to and never sends them. The
Safari front end never declares it (ADR-0036 §12).

> **Status:** the messages are defined (`kagisecure-extension-ipc`), the Chromium extension speaks
> them (below), and the app serves all of them — single-page logins, identifier-first sign-ins
> across two pages, one-time codes and the tripwire's `UNMASKED` report (ADR-0036 Phases 1–3). A
> session that does not declare `agent_fill` is still never pushed to, and its three requests are
> still answered `PROTOCOL`.

#### Agent-requested fills in the extension: who establishes what

```text
  app ── push locate{probe} ──▶ service worker
                                  · tabs.query({active, lastFocusedWindow, windowType: "normal"})
                                  · tabs.sendMessage(tab, agent-locate, {frameId: 0})
                                      ▼
                                content script, top frame only
                                  · visible? which of username / password / code fields?
                                  · runtime.sendMessage(agent-report) — a fresh message
                                      ▼
  app ◀── target_report ────── service worker stamps page and tab from `sender`

  app ── push deliver{probe, grant} ──▶ service worker
                                  · tabs.sendMessage(tab, agent-deliver,
                                                     {frameId: 0, documentId: <reported>})
                                      ▼
                                content script: waits ≤ 2 s for visibility, re-detects,
                                re-checks writability, then runtime.sendMessage(agent-fill)
                                      ▼
  app ◀── agent_fill ───────── stamped again ──▶ `filled` reply to that one content script,
                                                  written, dropped
  app ◀── agent_fill_outcome ─ field names written, or why not
```

| Fact | Established by | Never taken from |
| --- | --- | --- |
| Which tab | `chrome.tabs.query` in the service worker: the active tab of the last-focused normal window | the push, the app or the agent — neither can name a tab |
| Which frame | `tabs.sendMessage(…, {frameId: 0})`, and `sender.frameId === 0` on the answer; the content script also refuses in a sub-frame | the content script's claim |
| Origin, tab id, document id, `tab_active` | the `sender` the browser attaches to the content script's message (`sender.origin`, `sender.tab.id`, `sender.documentId`, `sender.tab.active`), built by the same `trustedPageContext` a human fill uses | anything in the message |
| `visible`, `found` | the content script, from its isolated world (`document.visibilityState`, the detectors in `forms.js`) — booleans only | page script, which cannot reach the isolated world |
| Where the value lands | `tabs.sendMessage(…, {frameId: 0, documentId})`: the browser delivers to the reported document or to nothing, so a navigation, reload or redirect after the report is a delivery that goes nowhere | the `deliver` push, which carries only ids |

The service worker accepts a report only from frame 0 of the tab it asked, for a probe it is
holding, once, within five seconds; and an `agent-fill` only from frame 0 of the tab **and
document** it delivered to, once per grant. When there is no tab in front, no content script in it
(an internal page, the store, a PDF), or no answer, it still sends a `target_report` — with an
opaque origin, `top_origin_established: false`, tab id 0, not active, not visible, nothing found —
so the app can answer `NO_MATCHING_TAB` without waiting out its probe. When a delivery cannot reach
its document, or the content script's re-check fails before the grant is redeemed, the outcome is
reported at once (`FORM_CHANGED`, `NOT_VISIBLE` or `NOT_WRITABLE`, nothing written) rather than
left for the grant to expire.

**Occlusion at delivery.** The approval sheet sits over the browser while it is read, and macOS
reports a covered window's document as not visible for as long as the app's own window is in front
of it. So on Fill, before the grant reaches Rust, `AgentService` hands activation back to the
browser named on the sheet (falling back to whatever was frontmost when the request arrived, and to
hiding the app, in that order — a real-browser manual test found the app staying frontmost
otherwise); and a delivery whose document is still hidden a moment later is given
`AGENT_VISIBILITY_WAIT_MS` (5 seconds — content.js) to become visible before it is refused as
`NOT_VISIBLE`, which is margin for that activation to land rather than the ordinary case.

The write is the human path's `applyFill`, with one difference: every field the reply carries must
still be writable, checked in the same task as the writes — the password only into a real
`type=password` input — or nothing is written. The reply is handed to one `sendResponse` in the
service worker and dropped in the content script before anything else is awaited; nothing on this
path is stored, logged or put in the tab memory. Nothing is submitted: the content script writes and
stops (ADR-0036 §8.3).

What a delivery writes is decided by what the app's reply carries, never by anything the content
script remembers: it holds no state about a grant beyond one document, and never reads or makes the
human path's tab memory (ADR-0030).

**Identifier-first: one approval, two pages** (ADR-0036 §7.3). Page one reports
`username: true, password: false`. The app raises one sheet for the whole sign-in and answers page
one's `agent_fill` with a `filled` reply carrying the username alone, which is written; the outcome
is `written: ["username"]`. A reply that also carries a password is refused whole on that page —
there is no field for it — and nothing is written. When the agent has pressed Next and asks again —
`request_fill` for the password, which it is told is pending — the app starts over with a **new**
`locate` (new probe id), sent only to this browser session, and a **new** `deliver` (new grant id),
without a second sheet; the second document reports `password: true`, and is filled
exactly like a single-page login with a reply carrying the password. The app, not the extension,
holds the flow: the 60-second flow window, the same-site rule between the two documents and the
single use of each step are all judged there. Nothing on this side stands in the way of step two —
each probe gets its own five-second report window and each grant its own delivery — but a
`deliver` that repeats a grant id this worker has already delivered is ignored, so each step needs
a grant id of its own. A site whose Next button swaps the form in place rather than loading a new
page reports step two from the same document id as step one, and the app accepts that: the same
document is the same tab and origin, which is what step two is bound to (ADR-0036, implementation
decision 38). The tripwire's `UNMASKED`, when it follows a password write, is recorded by the app as
`AGENT_FILL_UNMASKED (entry N)` and shown to the user; it is never a second fill.

**One-time codes** (ADR-0036 §7.4). A report says `one_time_code: true` when `detectOtpField` finds
a code box. A `totp_code` reply to `agent_fill` is written into that box, re-detected in the same task
as the write and required to be the same element the delivery found — a page that swapped its code
box while the app answered gets nothing (`FORM_CHANGED`) — and the outcome is
`written: ["one_time_code"]`. There is **no clipboard fallback**: the human path copies a code when
the page has no code box, and the agent path has no branch that could. No box, or a box that is no
longer writable, is `NOT_WRITABLE` with nothing written. A `filled` reply on a page with only a code
box, or a `totp_code` reply on a page with none, writes nothing either.

**The tripwire** (ADR-0036 §8.3). When an agent fill has written a password, the content script
watches that input for ten seconds with a `MutationObserver` on its `type` attribute, armed in the
same task as the write, and checked once at once in case the page flipped the type from its own
`input` handler during the write. If the type stops being `password` — the site's own "show
password" control, clicked — the value is cleared and a second `agent_fill_outcome` follows the
first: `written: ["password"], failure: "UNMASKED"`, naming the password it took back. It trips at
most once, stops after ten seconds or when the page is left (`pagehide`), holds the element and
never the value, and is never armed by a human fill. The service worker accepts that second outcome
only as `UNMASKED`, only once, only from the document the grant was delivered to, and only when the
first outcome named a password. This is hygiene against the crudest read, not a guard: an agent
that can run script in the page reads `input.value` without touching the type.

A hidden document is reported as hidden. At delivery, and only then, the content script waits up
to two seconds for `visibilitychange`: Chromium can report a document as hidden while the app's
approval sheet covers its window, and the sheet has just closed.

Only the Chromium front end declares `agent_fill`. Safari's `hello` carries no `capabilities`, and
`SafariWebExtensionHandler` empties the list on the `hello` it rewrites and leaves it empty on the
one it builds, because the handler's one-connection-per-message transport gives the app nothing to
push on (ADR-0036 §12).

`fill` carries a `fields` selector — `["username","password"]`, or `["username"]` on an
identifier-first page, or `["password"]`. The app **enforces** it: the reply is built by a
constructor that drops anything the request did not name, so a username-only fill cannot carry a
password. A request that names only the username crosses no secret and is therefore served without
an approval sheet, without a biometric, and without minting or spending a fill lease — every other
gate is unchanged, and the audit entry reads `FILL_USERNAME_ONLY`
([ADR-0030](decisions/0030-identifier-first-login.md)). Absent, `fields` means both, which is what
a fill has always meant.

Every failure is `error` with a stable code: `VAULT_LOCKED`, `USER_DENIED`, `APPROVAL_TIMEOUT`,
`ORIGIN_MISMATCH`, `NO_MATCH`, `UNKNOWN_EXTENSION`, `UNTRUSTED_HOST`, `PROTOCOL`, `INTERNAL`,
`AUDIT_UNAVAILABLE`, `VAULT_CONFLICT`.

An item in the trash or the archive is answered by `fill` and `totp` exactly as an item that does
not exist — `NO_MATCH`, the same sentence, no prompt and no audit entry — just as `match` never
lists it. A caller holding an old item id cannot learn that the item is still there.

`AUDIT_UNAVAILABLE` means nothing was filled because the audit entry recording the fill could not
be written ([ADR-0040](decisions/0040-audit-before-release.md)); see §4. It was added without a
protocol version bump: the typed parsers of the code (`kagisecure-nmhost`, the Safari app
extension) ship inside the same app bundle as the listener that sends it, and the content script
shows the app's own message for any code it does not know, whereas a bump would make a
version-skewed extension refuse every request at `hello`.

`VAULT_CONFLICT` means the vault file on disk is no longer one this unlocked session will build
on — restored from an older copy, replaced by a different file, or removed while the vault was
unlocked — checked before `match`, `fill` and `totp` are served, never after. Nothing is served
from a stale file and nothing on disk changes; only resolving it in the app, not retrying, ends the
refusal. It is the extension protocol's counterpart to the MCP channel's `VAULT_CONFLICT`
(`docs/mcp-server.md` §7), added the same way `AUDIT_UNAVAILABLE` was: no protocol version bump,
because an extension built before this change still shows the app's own sentence for the code it
does not recognize — the same sentence this refusal carried as `INTERNAL` before it had a code of
its own. There is deliberately no extension-side `VAULT_BUSY`: this channel has no write that
is not audited (every value crosses only through the audit-before-release path in §4), so a lock
held past a write's own wait is already `AUDIT_UNAVAILABLE`, and the pre-flight check that produces
`VAULT_CONFLICT` only ever reads the file — it never takes the write lock and so never observes
"busy" as a distinct condition.

`matches` returns titles and usernames and **no URLs**: the extension already knows the origin it
asked about, and returning the item's other saved sites would leak the user's site list one page at
a time.

### The order of checks

1. **Same user.** Another local uid is refused before a byte is read.
2. **The right peer for this socket.** On the Chromium socket the native host's ancestry must
   contain a recognized browser within three hops. On the Safari socket the peer *is* the
   extension, so its executable must be the `.appex` inside this app's own bundle. Either failure
   is `UNTRUSTED_HOST` before anything is served, and the refusal is audited.
3. **Pinned extension id.** `hello` from anything else is refused — the key-pinned Chromium id on
   one socket, the app extension's bundle identifier on the other. The two lists are separate, so
   neither id passes on the other's socket.
4. **Origin match.** eTLD+1 + exact scheme/port. A mismatch is `ORIGIN_MISMATCH` and an audit
   entry, never a prompt — there is nothing for a human to weigh about a fill the rule refused.
5. **The human, on every fill that crosses a secret.** A password or a one-time code crosses only
   from a granted approval, and the app grants nothing without a LocalAuthentication check
   ([ADR-0037](decisions/0037-every-fill-needs-a-fresh-presence-proof.md)) — on macOS, any check
   that passed while the app-wide grace window is open counts, and a presence-only request inside
   that window is granted with no prompt at all (the grace window,
   [ADR-0037's amendment of 2026-10-03](decisions/0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-10-03-app-wide-sliding-grace-window)). The first fill of an
   (origin, item, fields) triple gets the full sheet plus the check. After **Allow for this
   session**, a repeat of that exact triple from the top frame of the same origin gets the check
   alone — a *presence-only* request. A repeat from a sub-frame, or from a page whose top frame the
   browser did not establish, gets the full sheet again.

   The click in the page is **not** the human gate. The content script checks `event.isTrusted`,
   which proves only that page script did not dispatch the event: input synthesized over the
   DevTools protocol (what a browser-automation agent sends) and input injected at the OS level
   are both trusted. Touch ID, the login password or an Apple Watch is the step a program cannot
   take.

   Skipped entirely by a fill that asks for the username alone, because nothing crosses that step 4
   did not already hand over — checks 1–4 and the request in the page are not skipped
   ([ADR-0030](decisions/0030-identifier-first-login.md)).

## 4. Approvals and leases

The fill sheet is the **same sheet** as an agent approval, on the same queue, with the same
60-second timeout and the same biometric gate — one mechanism, not two
([ADR-0020](decisions/0020-fill-approvals-and-origin-leases.md)).

What is different is what it shows and what it grants:

- **Identity verdicts.** On Chromium, two side by side: the native messaging host's code signature
  and the browser's. On an unsigned build these differ — Chrome verifies, our helper does not — and
  collapsing them into one word would either claim a verification we do not have or throw away the
  one real fact on the sheet. On Safari there is **one**, because Safari is never the process on
  the socket: the app extension is, and it is signed by us. That is why a Developer-ID-signed build
  can produce a fully *verified* fill through Safari and cannot through Chrome
  ([ADR-0024](decisions/0024-safari-app-group-socket.md) §5).
- **A frame warning.** When the form is in a cross-origin iframe, the sheet says so and names both
  origins.
- **A fill lease**, not an env lease. Scoped to one origin, one item and one field set, five
  minutes by default, fifteen at most, session-only, dead the moment the vault locks. It is a
  **review memory**: it excuses **the sheet and nothing else**. A fill it covers is asked as a
  presence-only request — the system's Touch ID prompt, naming the item and the site and saying
  "continue only if you just asked Kagisecure to fill this", with no sheet in front of it. A
  cancelled or unavailable check is a denial. A presence confirmation never mints or extends a
  lease ([ADR-0037](decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
- **Allow once** mints no lease at all, so the next fill gets the full sheet again.

On a Mac with no Touch ID, the check is the login password (outside the grace window); an Apple Watch that
unlocks the Mac can answer it instead. The Browser extension screen says so. There is no weaker
setting.

Fill leases appear in **Agent access → Leases**, under "Browser fills", with their own Revoke.

**Agent-requested fills** ([ADR-0036](decisions/0036-agent-requested-browser-fill.md)) share the
queue, the 60-second timeout and the biometric gate, and share nothing else:

- **Their own sheet, outside the grace window.** `ApprovalKind::AgentFill`, never "for this
  session" — the queue clamps whatever a UI answers to once. Inside the app-wide grace window an
  agent fill is granted with no sheet and no Touch ID, unless "Always show the sheet for agent
  fills" is on (ADR-0036 amendment of 2026-10-03).
- **A grant, not a lease.** An approval issues one single-use grant, held by the app and bound to
  the sidecar process that asked (its kernel pid, executable and start time, so a later sidecar
  handed the same pid cannot redeem it), the item, the exact fields, the
  origin the browser established, the extension session, the tab id, frame 0 and the document id.
  It must be redeemed within **30 seconds**, and dies on first use, on a lock, when the extension's
  connection closes, and on any failed re-check. When the extension redeems it, every binding is
  checked again and the item's coverage of the origin is re-evaluated inside the release
  transaction; a reload, a navigation, another tab or another sidecar process refuses it.
- **Leases do not cross.** A live fill lease never excuses an agent's sheet, and an agent's
  approval never mints a fill lease or an env lease.
- **One at a time.** While one agent fill is in progress, another is refused at once
  (`RATE_LIMITED`, with its own sentence) rather than queued. *Deny and block* blocks the agent for
  thirty minutes, and blocks survive a lock. The approval-fatigue limits that used to sit here — a
  per-agent sheet budget, sticky denials, and a block after a second origin mismatch — were
  removed in 0.1.3 (ADR-0036 amendment of 2026-10-03); a mismatch is still refused, audited and
  noticed.

Their audit entries are the agent's: tool `request_fill`, actor
`mcp "<name>" [...] pid N <exe> via <browser> (extension "<id>")`, the field names, and the
browser-established origin. `AGENT_FILL_APPROVED` is written, `Allowed`, inside the release
transaction before the value leaves; `AGENT_FILL_DENIED`, `AGENT_FILL_NO_TARGET`,
`AGENT_FILL_ORIGIN_MISMATCH`, `AGENT_FILL_NOT_DELIVERED`, `AGENT_FILL_BLOCKED`,
`AGENT_FILL_RATE_LIMITED` and `AGENT_FILL_BUSY` record requests that released nothing (a denial or
mismatch that blocked the agent carries ` (agent blocked)`);
`AGENT_FILL_NOT_WRITTEN (entry N)` and `AGENT_FILL_NOT_CONFIRMED (entry N)` follow a release the
extension then reported unwritten, or never reported on.

Audit entries are written for every fill: `FILL_APPROVED` (a full review), `FILL_CONFIRMED` (a
presence-only confirmation under a review from earlier in the session), `FILL_DENIED`,
`FILL_ORIGIN_MISMATCH`, `FILL_USERNAME_ONLY`, `HOST_REFUSED`, each with the origin and the field
**names**.

**Audit before release** ([ADR-0040](decisions/0040-audit-before-release.md)). Every reply that
carries a value — a password, a one-time code, and a username-only fill's username — is released
only once its `Allowed` entry is on disk. The value is read inside the transaction that commits
that entry, re-checked there against the vault file as it is at that moment (the item may have been
deleted, trashed, archived or given other websites while the sheet was up), and handed to the reply
only if the commit succeeded. When the entry cannot be written — a full disk, another kagisecure
process holding the vault past the five-second wait, a vault file that changed under the app —
the reply is `AUDIT_UNAVAILABLE`, no value crosses, no fill lease is minted (a lease asked for by
**Allow for this session** is minted only after the commit), and a `Failed` entry with detail
`AUDIT_UNAVAILABLE` is queued for the next write that succeeds. When entries are already waiting
because an earlier write failed, they are flushed before a sheet or a presence prompt is raised;
if that flush fails the fill is refused with `AUDIT_UNAVAILABLE` and nobody is asked. If the reply
frame carrying a released value then cannot be written to the browser, a `Failed` entry with
detail `REPLY_FAILED (entry <seq>)` follows the `Allowed` one. Refusals, denials and mismatches
stay best-effort: they release nothing. `FILL_USERNAME_ONLY` is the one that names no human, which is why it is its own word
rather than a quieter `FILL_APPROVED`. Builds before ADR-0037 also wrote `FILL_LEASED`, for a fill
that went ahead on a lease with no check at all; nothing writes it now, and an old log that has it
is showing exactly the gap ADR-0037 closed.

### Run browsers and the unattended extension endpoint *(built for macOS — [ADR-0042](decisions/0042-unattended-agent-access.md) §12, implementation decisions 40–50)*

A job kagisecure starts may sign in to a website with a **machine-vault** login and nobody present,
under a standing login grant — only in a **run browser**: a Chromium-family browser the engine
launches for that run, **headless** (`--headless=new`, no window, no focus), with a fresh profile
under `unattended-runs/` beside the machine vault that it deletes afterwards, the extension loaded
(`--load-extension`; the app's copy is `Contents/Resources/ChromiumExtension`), the native
messaging manifest written into that profile, and `KAGISECURE_EXTENSION_SOCKET` naming an
**extension endpoint of that run alone** (`ux-<app pid>-<run>.sock`, beside the unattended socket).
That endpoint accepts a native host only if the kernel's parent links from it reach that run's
browser with its recorded pid and start time — anything else gets `UNTRUSTED_HOST` and a
`HOST_REFUSED` entry — and it serves only the machine vault; its approval queue is closed, so it
never asks a person anything. The job is handed the browser's control endpoint as
`KAGISECURE_RUN_BROWSER_CDP` (`http://127.0.0.1:<port>`), drives it there, and asks its own
`kagisecure-mcp` for `request_fill`; the value goes through ADR-0036's broker exactly as an
interactive agent fill does, with a standing pass where the sheet would be, and the tab's
visibility not required. The user's own browsers never receive an unattended fill.

Which builds qualify was measured headless on 2026-09-27 (ADR-0042, "Phase 5: the
measurement"): **Microsoft Edge** and **Chromium** load the extension and read the profile's
manifest; **Google Chrome** ignores `--load-extension`; **Brave** loads the extension but does not
read the profile's manifest. The app offers Edge, then Chromium.

## 5. Setting it up

In the app: **Browser extension** in the sidebar.

1. **Check the helper path.** The screen shows where `kagisecure-nmhost` is. Building from source,
   run `cargo build -p kagisecure-nmhost` and set `KAGISECURE_NMHOST` to
   `target/debug/kagisecure-nmhost` before launching the app. A released build ships it at
   `/Applications/Kagisecure.app/Contents/Helpers/kagisecure-nmhost` and the screen shows that
   path — signed and notarized with the app, which is what makes the manifest's absolute path
   point at something the browser can trust
   ([ADR-0026](decisions/0026-helper-binaries-inside-the-app-bundle.md)).
2. **Press "Set up" next to your browser.** That writes
   `~/Library/Application Support/<browser>/NativeMessagingHosts/com.kagisecure.nmhost.json`. The
   exact JSON and the exact path are shown under "What this writes" first. **Remove** deletes it.
3. **Load the extension.** `chrome://extensions` (or `edge://extensions`) → Developer mode → Load
   unpacked → pick the folder the screen shows. An installed app ships it at
   `/Applications/Kagisecure.app/Contents/Resources/ChromiumExtension`, with **Copy** and **Show in
   Finder** next to it; the folder picker cannot open an app bundle by clicking, so press ⇧⌘G and
   paste the path. An update replaces that folder in place. Building from source, pick
   **`extensions/shared`**: that is the extension itself; `extensions/chrome` holds only the Node
   test package (§6).
4. **Check the id.** The screen shows the id the app serves; the browser shows the id it loaded.
   They must match. They will: the extension's `manifest.json` carries a committed public `key`
   that pins the id ([ADR-0021](decisions/0021-pinned-extension-id.md)).

**The Chrome Web Store.** The extension is being prepared for a public store listing:
`cargo xtask chrome-package` builds the upload (`key` stripped, version from `Cargo.toml`), and
[chrome-web-store.md](chrome-web-store.md) has the dashboard answers, the assets and the upload
steps. A store install gets an id the store assigns, not the pinned one, so it works only with an
app build that lists that id in `PINNED_EXTENSION_IDS` and after **Set up** has been pressed again
([ADR-0021, amendment of 2026-10-03](decisions/0021-pinned-extension-id.md#amendment-2026-10-03-the-chrome-web-store-assigns-its-own-id)).

Supported: Chrome, Edge, Arc, Brave and Chromium — one native-messaging manifest per browser, same
extension, same id. **Safari** is supported too and needs none of the above: no helper binary, no
manifest file, no id to check. See §8.

### The source layout

```text
extensions/
  shared/       the extension. Chromium loads THIS unpacked; the Safari app extension embeds it.
    manifest.json     the Chromium MV3 manifest, with the pinned key (ADR-0021)
    background.js     the service worker: message routing, the origin stamping
    native.js         the one file that differs per browser at run time — the transport
    content.js        the icon, ⌘\, and the only function that writes a value into a field
    tabmemory.js      which item a tab chose on an identifier page: in memory, 60s (ADR-0030)
    origin.js  forms.js  popup.html  popup.js
    icons/            icon-{16,32,48,128}.png, rendered from the brand mark by make-icons.sh
  make-icons.sh       re-renders shared/icons/ from apps/macos/Artwork/icon.svg
  safari/
    manifest.json     Safari's manifest. Copied over shared/manifest.json by the Xcode target.
  chrome/       the Node package: unit tests, the Playwright suite. No extension code.
```

Two files differ between the browsers and neither is code the user sees: the manifest (Safari's
omits the Chromium-only `key` and `minimum_chrome_version`) and the four lines in `native.js` that
choose the transport. `native.js` decides from the **scheme of the extension's own URL** —
`chrome-extension://` versus `safari-web-extension://` — which is a fact about the runtime rather
than a guess about it. The obvious feature test no longer works: Safari has grown a `connectNative`
of its own, and a wrong guess there fails as silence rather than as an error.

### Making an item fillable

Put the site in the item's **Websites** field (the edit sheet). Subdomains of the same registrable
domain are covered; a different scheme or port is not. `http://localhost:3000` and
`http://localhost:3001` are different sites, and so are `http://` and `https://` versions of the
same host.

## 6. Building and testing

```sh
cargo test -p kagisecure-extension-ipc -p kagisecure-nmhost   # protocol, framing, origin rule
cargo test -p kagisecure-agent                                # listener, leases, cross-process
cargo test -p kagisecure-agent --test safari                  # the Safari front end's gates
make macos-test                                               # incl. SafariExtensionTransportTests
cd extensions/chrome && npm install && npm test               # form detection, origin helpers
make e2e SUITE=extension                                      # a real browser, end to end
```

`make e2e SUITE=extension` includes four agent-fill scenarios (ADR-0036), in which a real
`kagisecure-mcp` asks for the fill and a robot answers the sheet; they are written and wired in and
**have not yet been run** ([e2e-harness.md](e2e-harness.md) §6). Everything below the browser is
covered headlessly by `cargo test -p kagisecure-agent` (`tests/agent_fill*.rs`) and the
extension's side by `npm test` (`test/agent_fill.test.js`).

The extension is plain modern JavaScript with **no build step**: `npm install` is only for the two
test dependencies. `origin.js` and `forms.js` are loaded both as classic content scripts and by
`node --test`, through a small UMD wrapper, so the tests test the shipped file.

`SafariExtensionTransportTests` compiles the app extension's own `AppGroupSocket.swift` into the
test bundle — the file itself, not a copy of the framing — and drives it against a real listener
started by `extension_harness`. That is what makes the two languages agree about a 4-byte
big-endian length prefix; a disagreement there would produce a Safari extension that connects,
sends, and is answered with silence.

## 7. The manual pass

What the automated suite cannot do is put a fingerprint on the sheet. To check the human half:

```sh
# 1. a scratch vault with a login saved at the page you will visit
export KAGISECURE_VAULT=/tmp/kagisecure-m6/m6.kagivault
cargo run -p kagisecure-cli -- vault init
cargo run -p kagisecure-cli -- item add --title "Demo" --category login \
    --field username=alice@example.test --secret password --url http://localhost:8788

# 2. serve a login form
(cd e2e/suites/extension/pages && python3 -m http.server 8788 --bind 127.0.0.1)

# 3. the app, pointed at that vault  (KAGISECURE_VAULT works in the app since M6)
export KAGISECURE_NMHOST=$PWD/target/debug/kagisecure-nmhost
make macos && open -a Kagisecure

# 4. Browser extension → Set up → load extensions/shared unpacked → visit the page,
#    click the key icon or press ⌘\
```

Expect: the approval sheet naming the item, the origin, the two fields and the two signature
verdicts; a Touch ID prompt; the form filled; a `FILL_APPROVED` entry in the audit viewer; a lease
under Agent access → Leases. Then clear the form and fill again: no sheet this time, but a Touch ID
prompt naming the item and the site; cancel it and nothing is filled (`FILL_DENIED`), touch it and
the form fills (`FILL_CONFIRMED`).

**The same pass for an agent-requested fill** (ADR-0036), which nobody has run yet either. Steps 1
and 2 are unchanged except that the item and its vault must be visible to agents (`kagisecure env
agent-access --allow --logical-vault Personal`, then `--allow --item Demo`). In the app, make sure
Settings › AI Agents → "Let agents fill logins in your browser" is on (the default), and — to see
the sheet rather than a silent fill inside the grace window — turn on "Always show the sheet for
agent fills". Point an MCP client at the app ([mcp-server.md](mcp-server.md) §9), open the page in
the browser, and ask the agent to call `request_fill` with the item's id and
`http://localhost:8788`. Expect: the agent-fill sheet leading with the site, Touch ID (unless the
grace window is open), the form filled, the agent told only the field names, and a
`request_fill` entry `AGENT_FILL_APPROVED` whose actor starts with `mcp`. Then ask again from a
page on `127.0.0.1:8788`: no sheet, `NO_MATCHING_TAB`, an `AGENT_FILL_ORIGIN_MISMATCH` entry and a
notice in Agent access.

**The same pass for Safari** — which is the one gate M6b could not close, so run it. Steps 1 and 2
are unchanged; steps 3 and 4 become:

```sh
# 3. a signed build, because Safari needs the App Group  (ADR-0025)
make macos SIGN=developer-id
KAGISECURE_VAULT=/tmp/kagisecure-m6/m6.kagivault \
  "$(xcodebuild -project apps/macos/Kagisecure.xcodeproj -scheme Kagisecure \
       -destination 'platform=macOS' -showBuildSettings 2>/dev/null \
     | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{print $2}' | head -1)/Kagisecure.app/Contents/MacOS/Kagisecure"

# 4. Safari → Settings → Extensions → tick "Kagisecure" → allow it on localhost,
#    then visit the page and click the key icon or press ⌘\
```

Expect the same things, plus one that only Safari can show: the sheet's identity line reading
**verified**, naming `com.kagisecure.app.safari-extension` and the team. Check the audit entry says
`Launched by: Safari (extension com.kagisecure.app.safari-extension, pid N) — signature not checked here`, and that
`Browser extension → Safari` shows "Ready for Safari" with the App Group and socket underneath.

## 8. Safari

Supported since M6b. It works differently from every other browser here, and the differences are
all in its favour.

**There is nothing to install and nothing to configure.** No helper binary, no manifest file, no
extension id to check against the app. The extension is an *app extension* inside
`Kagisecure.app` itself, so installing the app installs it; enabling it is a switch in Safari.

```text
Safari → Settings → Extensions → tick "Kagisecure"
       → "Edit Websites…"  (or the toolbar icon) → allow it on the sites you want to fill
```

Then use it exactly as in Chrome: the key icon in a password field, or **⌘\**.

### How it reaches the app

`browser.runtime.sendNativeMessage` → `SFSafariWebExtensionHandler`, inside the app's own bundle →
a Unix socket in the App Group container the app and the extension share
([ADR-0024](decisions/0024-safari-app-group-socket.md)):

```text
~/Library/Group Containers/<TEAMID>.com.kagisecure/run/safari.sock   0600, in a 0700 directory
```

The app derives `<TEAMID>` from its own code signature, so a fork signing with its own identity
gets its own group with no source edit. The Browser extension screen shows the group, the socket
and where the `.appex` is, under "How Safari reaches this app".

Above the socket, **nothing is different**: the same `Request`/`Response`, the same 4-byte
big-endian framing, the same origin rule, the same approval sheet on the same queue, the same fill
leases, the same audit entries.

### What the app checks about the caller

The Chromium gate — "a recognized browser is within three hops of the native host" — cannot apply,
because macOS launches an app extension from `launchd` and Safari is nowhere in its ancestry. It is
replaced by a check on the peer *itself*:

1. **Same user**, before a byte is read.
2. **The peer's executable is our `.appex`**: it must end in
   `KagisecureSafariExtension.appex/Contents/MacOS/KagisecureSafariExtension`. Anything else is
   `UNTRUSTED_HOST`, audited, and served nothing.
3. **The `hello` names the app extension's bundle identifier**,
   `com.kagisecure.app.safari-extension`. The handler builds that field from its own
   `Bundle.main.bundleIdentifier` rather than forwarding what the page's JavaScript sent, because
   `browser.runtime.id` in Safari is a per-install UUID with nothing in it to pin.
4. **A code-signature check in Swift**, against **our own team** — not a hardcoded vendor's, the way
   a browser has to be checked. The audit entry and the sheet then read
   `Launched by: Safari (extension com.kagisecure.app.safari-extension, pid N) — signature not checked here`.

That is why a Safari fill on a Developer-ID-signed build can be reported *verified* while a Chrome
fill on the same build cannot: on Chrome, our own native messaging host is the half that is ad-hoc.

### Building it

Safari autofill needs an App Group, and an App Group identifier must begin with a team identifier,
so it needs a signed build ([ADR-0025](decisions/0025-developer-id-for-local-builds.md)):

```sh
make macos SIGN=developer-id
```

An **ad-hoc build still works for every other browser** and says so on the Browser extension
screen, in a sentence naming this command. It does not offer a Safari row that does nothing.

### What is verified, and what is not

Stated plainly, because the difference matters.

**Verified, by test:**

- The Safari socket binds as soon as the vault is unlocked, at the App Group path, `0600` in a
  `0700` directory (`SafariExtensionTransportTests`, `crates/kagisecure-agent/tests/safari.rs`).
- The two languages agree about the framing: `hello`, `match`, `fill` and an origin mismatch all
  round-trip through the app extension's own `AppGroupSocket.swift`.
- A peer that is not the `.appex` is refused with `UNTRUSTED_HOST` and the refusal is audited, with
  the gate **on**.
- The Chromium extension id does not pass on the Safari socket, and the Safari bundle id does not
  pass on the Chromium socket.
- An ad-hoc build serves Chromium and explains why it does not serve Safari.

**Verified, by measurement on this machine:** a Developer-ID-signed, **sandboxed** probe carrying
only `com.apple.security.app-sandbox` and `com.apple.security.application-groups`, running this
repository's `AppGroupSocket.swift` unchanged, completed `hello` → `match` → `fill` against the
listener through the group-container socket and received the password. That is the one property
`xcodebuild test` cannot establish — a test bundle cannot be an app extension — and it is the
property the whole transport rests on.

**Not verified:** the last hop. Safari loading the extension, its own per-site permission model,
and the icon and ⌘\ behaving in a Safari page as they do in a Chromium one. The session that built
M6b could not drive Safari's interface, so **no fill has been performed in Safari by a human**. The
`.appex` *is* registered with the system as a `com.apple.Safari.web-extension`
(`pluginkit -m -p com.apple.Safari.web-extension` lists it), which is the step before Safari will
show it — but "the system accepts the extension" is not "a password was typed into a form in
Safari", and this document will not pretend otherwise. The manual pass in §7, run against Safari
instead of Chrome, is what closes it.

## 9. Continuous integration (removed 2026-09-19)

`npm test` runs anywhere: it is Node plus a DOM library, no browser.

The **e2e needs a real display and a browser that will load an unpacked extension**, which is a
sharper constraint than it looks:

- **MV3 extensions do not load in the old headless shell.** The interactive scenarios use
  `headless: false`. The **new headless mode** (`--headless=new`) does load them, and reads the
  profile's manifest, in Edge 154 and Chromium 153 (ADR-0042, "Phase 5: the measurement"): the
  unattended scenario (`unattended.test.mjs`) runs entirely headless.
- **Chrome 137 removed `--load-extension`.** On Chrome 152 the switch is silently ignored — the
  browser starts, the extension is not installed, nothing is logged. Verified here with a
  three-line probe extension. `--enable-unsafe-extension-debugging` does not bring it back.
- **The native messaging manifest directory follows `--user-data-dir` now.** It did not, and this
  document used to say so. On **Edge 152**, a browser launched with `--user-data-dir=X` reads its
  manifests from `X/NativeMessagingHosts` and does **not** find one in
  `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts`; `connectNative` answers
  *"Specified native messaging host not found"*. Measured with a probe extension against a host of
  `/bin/cat`, which reports *"Native host has exited"* when the manifest is found. The suite
  writes only the copy inside the throwaway profile, which is what the run's browser reads, and
  never the real per-user one ([e2e-harness.md](e2e-harness.md) §6, "The manifest"). Nothing in the
  product changed: a default launch's user-data-dir *is* `~/Library/Application Support/<browser>`,
  so the app's setup screen still writes the right file.
- **Chromium will not load a symlinked content script.** A symlinked service worker loads; a
  symlinked content script silently never runs — the extension installs, the page loads, and
  nothing happens. Measured on Edge 152 with a two-file probe. This is why `extensions/shared` is
  the extension root itself rather than a directory of per-browser symlink farms pointing into it
  (§5).

So the suite tries browsers in order and uses the first that actually installs the extension —
today, **Microsoft Edge**. It skips with an explanatory message when none will.

**Run locally:** `make e2e SUITE=extension`, with Edge installed. A macOS machine has a window
server, so `headless: false` works without Xvfb. On Linux the same suite
would need `xvfb-run -a make e2e SUITE=extension` and a Chromium that still honours
`--load-extension`. This suite was never run in CI even before CI was removed on 2026-09-19: a
macOS runner would not ship Edge, and installing it per run would be a
multi-hundred-megabyte download for a suite whose failures are overwhelmingly about the extension
source, which the JavaScript unit tests already cover. This is a **documented local gate**; see
[e2e-harness.md](e2e-harness.md) §8.

**The old `npm run e2e` is gone.** `extensions/chrome/e2e/fill.test.js` predated the harness and
wrote the native messaging manifest into the user's **real** browser profile
(`~/Library/Application Support/<browser>/NativeMessagingHosts/`), restoring it afterwards — so a
run killed between the write and the restore left a real, everyday browser pointing at a
`target/debug` binary. Suite B does the same work against a throwaway profile and never touches
the real one, so the older test was removed rather than kept alongside it.

**Safari would have been further out of CI's reach still.** It needs a signed build, an enabled
extension and a
per-site permission grant, all of which are interface actions in Safari's own Settings. The parts
that *can* be automated are: `crates/kagisecure-agent/tests/safari.rs` and
`SafariExtensionTransportTests`, both of which run locally under ad-hoc signing (and ran in CI
until CI was removed on 2026-09-19).

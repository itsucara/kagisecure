# ADR-0037: Every secret fill needs a fresh presence proof; a fill lease is a review memory

- **Status:** Accepted; amended 2026-09-27 (presence grace window — see the amendment below,
  which relaxes the "fresh" in this ADR's title on macOS); amended again 2026-10-03 (one app-wide,
  sliding, configurable window — see the last section)
- **Date:** 2026-09-25
- **Deciders:** the owner, on a vulnerability report against M6
- **Supersedes:** [ADR-0020](0020-fill-approvals-and-origin-leases.md) §4
- **Refines:** [ADR-0018](0018-browser-extension-secret-crossing.md),
  [ADR-0030](0030-identifier-first-login.md),
  [threat-model-browser-extension.md](../threat-model-browser-extension.md) T-8, T-9,
  [ui-spec.md](../ui-spec.md) §10

## Context

### The vulnerability

A browser- or OS-automation agent could make kagisecure fill a password, or hand over a one-time
code, with no person at the keyboard.

The extension's last gate before asking the app for a value is `event.isTrusted`, on the in-page
icon and on ⌘\. `isTrusted` proves one thing: the event was not dispatched by page script. It does
not prove a person made it. Input synthesized over the Chrome DevTools protocol is trusted, and so
is input injected at the OS level through Quartz events or the Accessibility API. This repository's
own browser suite does exactly that — it clicks the in-page icon with `page.mouse.click`, presses ⌘\
with `page.keyboard`, and evaluates code inside the service worker — and every one of those passes
the gate.

Without a lease the app still stopped such an agent: it could press **Allow** on the sheet through
Accessibility, but `AgentService.allow` then runs `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`,
which only Touch ID, the login password or an Apple Watch satisfies, and a cancelled or unavailable
check grants nothing.

The fill lease removed exactly that step. [ADR-0020](0020-fill-approvals-and-origin-leases.md) §4
decided that "a lease excuses the biometric and nothing else", on the premise that "every fill still
requires the user's explicit action in the page". In `ExtensionService::require_approval` a live
lease returned early — before `ApprovalQueue::ask` — and the value was built and audited as
`FILL_LEASED`. So for five minutes (up to fifteen) after every genuine login, anything that could
click in the browser could fill that login again, and the TOTP lease did the same for one-time
codes. Every entry point reached it: the icon, the item menu, ⌘\, the popup's Fill (relayed through
the service worker to the content script), and the popup's one-time-code button. Safari runs the
same shared JavaScript into the same `ExtensionService`.

The premise was wrong, and it was wrong in a way no test could catch, because the tests used the
same kind of trusted synthetic input the attacker would.

### What must hold

> **Every response that carries a secret — a password or a one-time code — comes from a granted
> `ApprovalQueue::ask`, and every grant in the app went through `gate.authenticate`.**

ADR-0030 already stated a version of this ("no secret value crosses to the browser without an
approval and a biometric"). It was not true while the lease short-circuit existed, and nothing
structural would have noticed, because the invariant was a convention held by the shape of one
function. So the decision is not only to change the policy but to make the invariant hard to break
by accident.

## Decision

### 1. A fill lease becomes a review memory

A fill lease no longer skips the LocalAuthentication check. It skips **the sheet**.

`require_approval` always calls `ApprovalQueue::ask`. What the lease decides is which question is
asked:

| Situation | Question |
| --- | --- |
| No live lease for this exact (origin, item, fields) | The full sheet, then the check |
| Live lease, request from the top frame of that same origin as the browser established it (`top_origin_established && top_origin == origin`) | `presence_only`: the check alone, no sheet |
| Live lease, but a sub-frame, or a top frame the browser did not establish | The full sheet again |

The frame rule exists because the sheet is what says "this form is inside a frame on another site"
(D-7), and a presence prompt cannot say it; a lease minted at a top-level login must not let a
same-origin frame embedded elsewhere skip that disclosure.

A lease is minted only by a **full** review answered **Allow for this session**. A presence
confirmation never mints or extends one: `approval::outcome_for` forces `session = false` for a
`presence_only` request whatever button a UI claims was pressed, and the extension service mints
only from a grant that is a session and not presence-only.

### 2. The invariant is carried by types and module boundaries

- **`Grant`** (`kagisecure_agent::approval`). Private fields, no public constructor, not `Clone`,
  constructed in exactly one place — `outcome_for`, for an `AllowOnce` or `AllowSession` handed to
  `ApprovalQueue::resolve`. `Outcome` gained a private `grant: Option<Grant>` field, which also
  means an `Outcome` can no longer be built outside that module, and `Outcome::into_grant` is the
  only way to get at it. A `Grant` carries the scope the human was shown (kind, origin, item,
  fields, `presence_only`), copied from the request.
- **`Approved`** (`kagisecure_agent::extension::crossing`). Built only by `Approved::from_grant`,
  which refuses a grant whose kind, origin, item or fields do not cover what is about to cross.
  `leased` is renamed `reviewed_earlier`.
- **The crossing module.** Every function that reads a secret for a browser — the password, the
  one-time code, and the two "does it have one" probes — lives in `extension/crossing.rs`, and every
  one that returns a value takes `&Approved`. The parent module's source is scanned by a unit test
  for `expose_str`, `as_secret`, `FillValue::new`, `code_at`, `totp_generator` and `password_of`,
  so a second path to a value has to be written next to the comment that says what it owes.
- **The lease store** is written by one method, `remember_review`, which takes a `&Grant`.
- **In the app**, `AgentService.allow` is the only code that sends Rust anything but a denial, and
  only after `gate.authenticate` returned `.authenticated`. The presence path calls `allow`; it
  does not resolve on its own.

What is not structural, and is said so: Rust cannot see whether the app ran the check before calling
`agent_resolve` with an allow. That half of the invariant rests on `AgentService.allow` being the
one granting call site, which `BiometricGateAdversarialTests` pins from the outside.

### 3. The app asks a presence-only request with the system prompt alone

- `AgentService.sheetRequest` is the head of the queue unless it is `presenceOnly`; `RootView`'s
  sheet binds to it. A presence-only head is handed to `confirmPresence`, which calls
  `allow(request, decision: .allowOnce)`.
- **Cancelled or unavailable is a denial**, answered at once. On the sheet a fumbled fingerprint
  returns to the sheet (ui-spec §10.3); here there is no sheet to return to, and a prompt left open
  is one an agent could wait out.
- **One prompt at a time, across a lock too.** `presencePrompt` (a never-reused token plus the
  request id) blocks a second prompt while one is up, and is cleared only when that prompt's own
  `authenticate` returns. A lock does not clear it: `stop()` bumps `lockGeneration` and calls
  `gate.cancelInFlight()`, which invalidates the in-flight `LAContext` so the system dismisses the
  prompt, and the flag clears when the evaluation actually completes. A quick unlock therefore
  queues its presence-only fills behind the old prompt instead of stacking a second one beside it.
  `allow` captures `lockGeneration` before the check and resolves nothing if it changed, so a touch
  that lands after a lock is never sent to Rust as a grant in the next session.
- **The reason names the item and the site** and says *"Continue only if you just asked Kagisecure
  to fill this"*; a one-time code is named as one.
- **A fresh `LAContext` every time**, and `touchIDAuthenticationAllowableReuseDuration` is never
  set. A shared context or a reuse window would reopen, one layer down, the gap this ADR closes at
  the lease.
- The sheet's caption for **Allow for this session** no longer says the fill skips anything but the
  sheet. The Browser extension screen tells a user on a Mac with no Touch ID that every fill asks
  for the login password, and suggests an Apple Watch.

### 4. Audit vocabulary

`FILL_CONFIRMED` is new: a presence confirmation under a review from earlier in the session.
`FILL_APPROVED` still means a full review. `FILL_LEASED` is no longer written; the constant stays so
an old log can be read by name, and an old log that has it is showing exactly this gap.

### 5. Decisions the owner made

- Every secret fill needs Touch ID. A Mac without Touch ID uses the login password or an Apple
  Watch; there is no weaker default and no setting for one.
- A one-time code gets its own touch, separate from the password.
- The review memory keeps the lease's durations: five minutes by default, fifteen at most. The
  argument ADR-0020 made for those numbers now bounds how long the **sheet** is skipped, which is
  the window in which a person is most likely to touch the sensor for a prompt they did not
  cause (R-13).
- A username-only fill keeps its ADR-0030 exemption: no sheet and no check. An agent that triggers
  one learns a username `match` already told it.
- Gating **reveal** and **copy** in the app itself is a separate decision, ADR-0038, not this one.

### 6. Windows (added 2026-09-26, when `main`'s Windows port was merged)

The Rust half — `ApprovalQueue::ask` on every secret fill, `Grant`, `Approved`, the crossing
module, `outcome_for` forcing `session = false` for a presence-only request — is platform code
and unchanged. The app half on Windows is `AgentHostService.AllowAsync`: it is the only code that
resolves a request with an allow, and only after Windows Hello (`UserConsentVerifier`) verified,
or — only where Hello reports itself unavailable — after the master password passed the same
rate-limited, audited check the releases use (ADR-0038). `presence_only` crosses the C ABI
(`KgsApprovalRequest.presence_only`, `ApprovalRequest.PresenceOnly`), but the Windows sheet does
not yet act on it: a presence-only request is shown as the full sheet, which still needs Windows
Hello, so it is safe and simply asks more than macOS does. The approval sheet and the app's own
releases share one prompt slot (`PresencePromptGuard`). Windows Hello is weaker evidence of a
person than Touch ID (threat-model W-1); see ADR-0038's "Windows" section.

## Amendment 2026-09-27: presence grace window

**Decision (the owner: convenience over strictness).** After a presence check for a fill succeeds,
further fills to the **same exact origin** within **ten minutes** need no new check. This relaxes
§1's "every fill needs a fresh presence proof" and the owner decision in §5 that every secret fill
needs Touch ID; the rest of this ADR stands.

- **What opens a window.** Only a check that actually ran and returned authenticated for a fill —
  a browser fill (sheet or presence-only) or an agent fill (ADR-0036) — in a top frame the browser
  established. A reveal or copy in the app (ADR-0038), turning on a switch, and every non-fill
  approval neither open nor use one. A fill that rode a window does not extend it: the window is
  measured from the last real check, so an agent that keeps filling cannot keep it open.
- **What it covers.**
  - *A fill with a sheet* — a browser fill not reviewed in this session, and every agent fill — is
    keyed on the **origin** alone, for any item: the sheet still appears, still names the site and
    the item, its Allow still has to be pressed (the agent-fill sheet keeps its 1.5-second hold),
    and pressing it asks nothing more. The sheet says so above its buttons.
  - *A presence-only fill* — the review memory of §1 already covers it — is keyed on **origin and
    item**, and is granted with **no prompt at all**: this is the "standing grant plus open window"
    case. Same item, any fields, so a one-time code for an item whose password was just confirmed
    no longer gets its own touch inside the window (§5's "a one-time code gets its own touch" is
    relaxed with it).
  - A fill in a frame embedded in another site neither opens nor rides a window, so the sheet's
    "inside a frame on another site" disclosure is always followed by a real check.
- **What closes it.** A vault lock, including the automatic ones on sleep, display sleep and screen
  lock (they all run `AgentService.stop()`); stopping the agent listener; a restart of the app —
  the windows are in memory only. A wall clock that moves backwards closes a window rather than
  stretching it.
- **Where it lives.** In the macOS app: `PresenceGrace` (`apps/macos/Kagisecure/Services/
  PresenceGrace.swift`, `PresenceGrace.window` = 10 minutes) and `AgentService.allow`, which
  resolves a covered fill with **Allow once** without calling the gate and records a window only
  after the gate returned authenticated. The Rust side is unchanged: every fill still goes through
  `ApprovalQueue::ask`, a `Grant` still comes only from a resolved `ask`, and `outcome_for` still
  forces a presence-only grant to once. §2's app-side half of the invariant now reads "every grant
  in the app went through the gate, at most ten minutes earlier for a fill to the same origin".
  The `touchIDAuthenticationAllowableReuseDuration` rule in §3 still holds: a real check always
  runs on a fresh `LAContext`; the grace is a decision not to ask, not a reused context.
- **Windows** does not implement it: `AgentHostService.AllowAsync` still asks Windows Hello on
  every fill, which is stricter and safe (the platform is on hold, per the macOS-first focus).

**What it costs, said plainly.** Inside a window, anything that can click with trusted input — the
T-15 automation agent — gets a value with no person touching anything: it can click the in-page
icon for a reviewed login (no prompt at all), or press a fill sheet's Allow through the
Accessibility API (the sheet is only a click), for up to ten minutes after the person's own genuine
fill on that site. That is the exposure §4 of this ADR closed for the five-minute lease, reopened
for a ten-minute window from the last real check, with a lock, sleep or screen lock as the
earliest end. It is recorded as residual risk **R-15** in
[threat-model-browser-extension.md](../threat-model-browser-extension.md) and against M-29 in
[threat-model.md](../threat-model.md).

**Audit.** A fill granted inside a window is written with the same code as before —
`FILL_CONFIRMED` for a presence-only fill, `FILL_APPROVED`, `AGENT_FILL_APPROVED` — because Rust
cannot see whether the app ran a check. The log therefore does not distinguish a touched fill from
one that rode a window; recording that would need a new field on `agent_resolve`, and is deferred.

**Tests.** `apps/macos/KagisecureTests/PresenceGraceTests.swift`: inside the window no check,
at ten minutes a check, another origin a check, another item on a presence-only fill a check, a
framed fill neither opens nor rides one, a failed check opens none, a ridden window is not
extended, an agent fill rides a window but still needs its sheet, and a lock clears it.

## What cannot be prevented

Stated here rather than implied by the absence of a mitigation:

- **A person touching the sensor for an agent's prompt.** The prompt names the item and the site
  and tells them when to refuse; it cannot make them read it.
- **An agent that knows the login password** answering the prompt's password fallback. On a Mac
  without Touch ID that fallback is the only method there is.
- **A page reading the value after a genuine fill.** Filling a form puts the value where the page's
  script can read it (threat model N-10, W-7, R-1).
- **The check is in-process.** The app asks LocalAuthentication and trusts the answer; the value is
  not cryptographically bound to it, so anything that can patch the running app skips it (N-1, N-2).

## Threat-model numbering

New identifiers: adversary **T-15** (browser- or OS-automation agent), mitigation **M-29**,
residual **R-13**, non-goal **N-10**. Unmerged branches already use T-12 … T-14, M-22 … M-28,
W-12 … W-17 and R-8 … R-12 (`design/agent-requested-fill`, `design/shared-vaults`), so each new
number is the next after the highest on any branch, and nothing collides when they merge.

When the two design branches merged (2026-09-26), they turned out to collide with each other:
both had drafted T-12, M-22 and W-12, and ADR-0036's draft also used T-13. ADR-0035 kept
T-12 … T-14, M-22 … M-28 and W-12 … W-17; ADR-0036's entries became **T-17**, **M-31** and
**W-21**, and its T-13 was folded into T-15, the same adversary. R-8 … R-12 stayed ADR-0036's.

## Consequences

**Positive**

- The attack is closed on every entry point at once, because the fix is in the one place all of
  them reach: the Chromium and Safari front ends, the icon, the menu, ⌘\, the popup and the
  one-time code all end in `require_approval`.
- The invariant is enforced by construction on the Rust side: a secret cannot be built without an
  `Approved`, an `Approved` without a `Grant`, or a `Grant` without a resolved `ask`.
- The first-login experience is unchanged, and a repeat login inside the window is one touch rather
  than a sheet and a touch.

**Negative — accepted**

- **One more touch per repeat fill.** Logging in twice in five minutes is two fingerprints again,
  as it was before ADR-0020 §4, minus the sheet.
- **A Mac with no Touch ID types the login password on every fill.** The owner chose this over any
  weaker default; the Browser extension screen says so up front.
- **A test seam in the app.** `AgentService.resolver` exists so a unit test can see which decision
  was sent for a request no Rust queue holds. It adds no path to a grant.

**Verified, and not**

- `crates/kagisecure-agent/tests/extension_adversarial_presence.rs` runs in `cargo test`, and its
  key test was confirmed to fail against the unfixed code (the password crossed on the replay) and
  pass against this change.
- The Swift unit tests in `FillApprovalTests` and `BiometricGateAdversarialTests` and the browser
  suite's presence scenario were written and compiled; they were not run as part of this change,
  because both occupy the GUI.

## Out of scope, recorded

- The popup's Fill sends no item id (`popup.js` → `background.js`), so the content script picks
  the item; harmless to this ADR, since whichever it picks still needs the check.
- App reveal and copy → ADR-0038.
- Step 6 of the design (further defence in depth in the extension) is deliberately not part of this
  change.

## Pointer 2026-09-27 — the machine vault's unattended fills

[ADR-0042](0042-unattended-agent-access.md) §12.6, accepted for macOS and not yet built beyond its
core, amends this ADR's invariant for machine-vault logins filled under a standing login grant: a
second `Approved` constructor, reachable only from the unattended engine and only with a
machine-vault item, with the source scan widened to it. For every other item the invariant holds
as stated here.

## Amendment 2026-10-03 — app-wide sliding grace window

Supersedes the 2026-09-27 window's keying and length, at the owner's direction (convenience over
security):

- **One window for everything.** Any successful presence check — a fill, an agent fill, an in-app
  reveal, copy, Quick Access or one-time code (ADR-0038) — opens a single app-wide window, held by
  `PresenceCoordinator`. It is no longer keyed on origin or item, and framed fills are covered too.
- **Sliding.** Every use extends it; a fill that rides the window now extends it.
- **Configurable.** Settings › Security › Confirmation: 10 minutes, 30 minutes, 1 hour or
  **Until locked** (the default), stored under `presenceGraceDuration`.
- **Inside it** a browser fill asks for no Touch ID (its sheet, if any, still shows), a
  presence-only fill and an agent fill are granted with no prompt and no sheet (ADR-0036 amendment
  of 2026-10-03), and in-app releases ask nothing.
- **Still cleared on every lock**, including sleep, screen lock and idle lock, and on restart.

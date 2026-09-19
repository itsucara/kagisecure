# ADR-0030: Identifier-first sign-ins — `fill` names its fields, and a tab remembers who it is

- **Status:** Accepted
- **Date:** 2026-09-11
- **Deciders:** Post-M6 autofill work
- **Refines:** [ADR-0018](0018-browser-extension-secret-crossing.md),
  [ADR-0020](0020-fill-approvals-and-origin-leases.md),
  [browser-extension.md](../browser-extension.md) §1, §3

## Context

Google, Microsoft, Okta and everything built on top of them ask for the username on one page and
the password on the next. The extension could fill neither half of that flow well:

- **Page one was invisible.** `KsForms.detectLoginForm` is anchored on `input[type=password]`
  ([forms.js](../../extensions/shared/forms.js)), deliberately and since M6 — the password box is
  what says "this is where a secret gets written". An identifier page has no password box at all,
  so the detector found nothing, no icon was drawn, ⌘\ did nothing, and the user typed their own
  email address before the manager had woken up.
- **Page two forgot the question.** By the time the password field appeared, the extension had no
  idea which account the user had just typed. With two logins saved at one site — a personal and a
  work Google account, which is exactly the situation this matters in — it offered the list again
  and invited the user to pick the *other* one, filling a password that does not go with the
  username already on screen.

The protocol was equally unprepared. `Request::Fill` carried a `fields` list, but the app treated
it as advisory: `Response::Filled` was built by hand at one call site and carried whatever the item
had, so a request for `["username"]` would have been answered with the password as well.

The prize is a fill that writes a username and nothing else. That is not a secret crossing — the
extension was *already* handed that username, with no prompt at all, by the `Response::Matches`
that drew the icon in the first place. Which makes the question this ADR answers: can a fill that
carries no secret skip the approval sheet without weakening the rule that no secret crosses without
one?

## Decision

### 1. `fields` is a selector the app enforces, not a hint

`FillField` gains two functions in `crates/kagisecure-extension-ipc/src/protocol.rs`:

- **`FillField::both()`** is the serde default for `Request::Fill::fields`, so a message that names
  no fields means a full login fill. That is the *compatible* answer rather than the safe-looking
  one, on purpose: `fields` has been on the wire since the protocol's first version and every
  shipped extension sends it, so the default only ever reaches a hand-written message. Defaulting
  to `[Username]` would silently turn a real fill into a half one, which is a harder failure to
  notice than a full one.
- **`FillField::crosses_a_secret(&[FillField])`** is the one question the approval rule turns on:
  true if and only if `Password` is named.

`Response::filled` becomes the only constructor used for a `Filled` message, and it drops every
field the request did not name. This is structural, not a convention: a caller hands it whatever
the item has, and a username-only request cannot carry a password even if the code above it
forgets. `Response::carries_only` states the property, `debug_assert`s check it at both call sites
in `kagisecure-agent`, and a canary test seeds a marker as the password of a username-only fill and
asserts neither the marker nor the key `password` survives serialization.

### 2. A fill that names only the username raises no sheet

`ExtensionService::fill` serves a username-only request directly: no approval sheet, no biometric,
no lease minted and none consumed.

What does **not** change is everything else. Gates 1–4 of
[browser-extension.md](../browser-extension.md) §3 all still apply — same uid, the right peer for
this socket, the pinned extension id, and the origin rule — and the content script still requires
the user's own trusted click or ⌘\, as it does for every fill. The request is audited under the
same tool name as every other fill (`fill_credential`, so the audit view's existing filter finds
it) with a distinct detail, **`FILL_USERNAME_ONLY`**, because "the app answered this without asking
anyone" is precisely the thing a reader of the log needs to be able to see.

### 3. An item with no username is refused, not answered empty

If a username-only request names an item that has no username, the app answers `NO_MATCH` rather
than a `Filled` with two `null`s. The check is deliberately scoped to the case where the username
is the *whole* request: an ordinary login fill whose item has no username has always written the
password and left the username box alone, and turning that into a refusal would be a regression
dressed up as a check.

Like the existing "does this item have a password" check, it runs *after* the origin rule, so a
page that does not match learns nothing about what the item contains.

### 4. Page one gets a second detector, not a looser one

`KsForms.detectIdentifierForm` is a separate function from `detectLoginForm`, and the two are
**mutually exclusive by construction**: the identifier detector returns `null` for any page with a
usable `input[type=password]` on it. The password-anchored rule decides where a secret gets
written, and it does not get weaker so that a username can be filled.

With no password field to anchor the guess, the identifier detector is stricter than the login one
in three ways: there must be exactly **one** candidate text box on the page (two is a form asking
for something else as well, and this is not the moment to guess which); the evidence must be
positive (a declared `autocomplete` of `username`/`email`, an `email` input type, or a username
keyword), with a longer negative list that vetoes search boxes, newsletter signups and address
fields; and there must be something to press afterwards — a real `<form>`, or a button whose text
moves a sign-in along. A username box with no way to submit is a filter or a widget, not step one
of a login.

The worst outcome of a wrong guess is bounded by §1 rather than by the detector's judgement: the
only thing this path can write is a username the extension already has.

### 5. The tab remembers which item, in memory, for sixty seconds

`extensions/shared/tabmemory.js` holds one `Map` entry per tab: **`{ itemId, origin, expiresAt }`**
— an item id, the origin the *browser* stamped on the request that created it, and a deadline.
There is no username in it, no title, and above all no value.

- **It is never persisted.** No `chrome.storage` call, here or anywhere else in the extension. The
  Map lives in the MV3 service worker and dies with it, which can be as little as thirty seconds of
  idleness. Losing it early is not a failure: page two simply offers the list, which is the
  behaviour that shipped before this file existed.
- **Sixty seconds.** Long enough to press Next and type a password, short enough that a tab left
  open over lunch has forgotten by the time anybody comes back to it.
- **Same-site only, by a rule stricter than the app's.** An entry made at `https://example.com`
  carries down to `https://login.example.com` and to nothing else; scheme and port must match
  verbatim. This is deliberately *not* the app's eTLD+1 rule and deliberately does not ship the
  Public Suffix List into the browser, for the same reason `origin.js` does not: nothing in the
  browser half is a security boundary, so the half that is cheap to be right about is the half that
  says no. Two siblings under one registrable domain lose the memory and fall back to the list.
- **Five ways an entry goes away**: it expires; the tab closes (`chrome.tabs.onRemoved`); the tab
  leaves the site (checked on the `match` that every new document sends, which is how a service
  worker with no `tabs` permission learns that a tab navigated); the vault locks (`forgetAll`, the
  same way the app drops its fill leases); or the password fill happens, which is the thing the
  memory existed for.

On page two the content script asks the worker for the remembered id and fills that item **if it is
still among the matches the app returned**. The memory chooses *which* item; it never decides
*whether* — the click and the approval sheet are unchanged.

### 6. The popup says so, and offers to forget

A **"Continuing as …"** banner with a **Forget** button. A manager that silently decided which
account you are is worse than one that asks; the banner is what makes the memory a thing the user
can see and undo. The name is resolved from the match list the popup already has, and when the
remembered item is not in it the banner says "Continuing with a saved login" rather than inventing
a name.

### Alternatives considered

**(a) Persist the choice in `chrome.storage.session`.** Rejected. It would survive the service
worker, which is the only thing it buys, and it would cost the extension's simplest and most
checkable security property: *there is no `chrome.storage` call anywhere in it*, which a reviewer
verifies with one `grep` rather than by reasoning about what a particular area does and does not
hold. The failure mode it fixes — a worker evicted mid-flow — degrades to showing a list.

**(b) Prompt again on page two and let the user re-pick.** This is the status quo, and it is what
happens today whenever the memory has expired or been dropped, so the path is still live and still
tested. It is not good enough as the *only* behaviour: at a site with two saved accounts it offers
a choice the user already made thirty seconds earlier, and the wrong answer fills a password that
does not match the username on screen.

**(c) Treat the username as a secret and keep the sheet.** Rejected as incoherent. The same
username is handed to the extension by `Response::Matches` with no prompt at all, on every focus of
every matching login form, and is rendered in the popup. A sheet on page one would ask for a
fingerprint to authorize a value the extension already had — which does not protect anything, and
does teach people that the sheet is noise. Making `Matches` prompt instead would mean an approval
sheet on page load, which §1 of browser-extension.md rules out for better reasons than this.

**(d) One looser detector instead of two.** Rejected: see §4. The password-anchored rule is the
one that governs where a secret lands, and widening it for a case that cannot write a secret would
trade the property for nothing.

**(e) Key the memory on origin rather than tab id.** Rejected. Two tabs signing into two accounts
at one site is a real thing people do, and an origin-keyed memory would make the second tab
continue as the first tab's user. The tab id is also the cheaper fact: it is stamped on the message
by the browser and costs no permission, where reading a tab's URL would cost `tabs` over every tab.

**(f) A longer TTL.** Sixty seconds covers the flow it exists for. Every second beyond that is a
second in which a tab the user walked away from will continue as them without asking.

## Consequences

### Security argument: why this does not weaken the invariant

The invariant is **no secret value crosses to the browser without an approval and a biometric**,
and it is intact, because the exemption is defined by the thing itself rather than by a
circumstance:

1. `crosses_a_secret` is a function of the requested fields only. There is no page, origin, lease,
   timing or memory state that can turn a password request into an exempt one.
2. The exemption cannot leak a password even if the logic above it is wrong, because
   `Response::filled` structurally drops what was not requested and the canary test checks the
   bytes on the wire. A username-only fill has no code path that reads a password.
3. The value it does carry — the username — has never required an approval: `Matches` hands the
   extension the same string, unprompted, whenever a matching form gains focus. The exempt fill
   discloses nothing new; it only writes what the browser already had into a box.
4. Everything that was not the sheet is unchanged: the uid gate, the peer check, the pinned id, the
   origin rule, the user's trusted gesture in the page, and an audit entry — a *distinguishable*
   one.

**What the per-tab memory exposes.** An item id, an origin, and a deadline, in one process's
memory. A compromised page can ask for it, via the content script's `recall`, and learn one item id
— but only when the browser-stamped origin of that page still satisfies the same-site rule, which
means the page is on the site where the user chose that item, and a page on that site can already
ask `match` and be told the item ids, titles and usernames of everything saved there. The recall
answer is a strict subset of what a matching page is already entitled to, and it carries no value.

**Why the popup's `peek` needs no origin check.** The popup asks for the active tab's entry without
establishing where that tab is, which looks like a missing check and is not one. What it renders is
the origin *stored in the entry* — the one the browser stamped on the fill that created it — rather
than any claim about where the tab is now, so there is no origin judgement for the check to
protect. Making it check would mean reading the active tab's URL, which costs the `tabs` permission
over every tab the user has open, in exchange for a caption. The popup is also the wrong place to
worry: it is our own UI, opened by the user, already listing every match for that tab.

### Positive

- Identifier-first sign-ins fill on both pages, which is the majority of the large providers.
- One fingerprint per login flow rather than two, and none at all on page one.
- `fields` means what it says, enforced structurally, for every future field a fill might name.
- The audit log distinguishes a fill a human approved from one the app served on its own.

### Negative — accepted

- **A third piece of extension state to reason about**, after the connected/locked flag and the
  match cache. It is bounded, in memory, and has its own unit and end-to-end tests, but it is state
  where the file used to be able to say "nothing".
- **A heuristic without a password field to anchor it.** `detectIdentifierForm` will sometimes
  decline a real identifier page (the user opens the popup — the pre-existing path) and could
  sometimes offer on a page that is not one. The ceiling on the latter is that it writes a username
  the page's own site could already learn from `match`.
- **A same-site rule in the browser that disagrees with the app's eTLD+1 rule.** Deliberately
  stricter, and the disagreement is one-directional: the browser half can only refuse to continue,
  never authorize something the app would not.
- **The banner can outlive its usefulness by up to a minute** — an entry whose tab has navigated
  cross-site is dropped on the next `match` or the next recall, not at the instant of navigation.
  It carries no value and shows the origin it was made at, so the honest reading is the one it
  gives.

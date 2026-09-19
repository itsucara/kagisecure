# macOS UI spec

Status: **§1–§13 implemented** (`apps/macos`); §1–§6/§11–§13 in M3, §10 (the
approval dialog and the Agent access section) in M4; §7 (Quick Access) moved to M5, where §8–§9
(generator, TOTP) already were. This document specifies the SwiftUI app described in
[architecture.md](architecture.md) §2.5 and its interaction with `kagisecure-ffi` (in-process) and
`kagisecure-mcp` (via the native app's IPC listener, §4 of that document).

What is built differs from this spec in a handful of places, each recorded rather than silently
dropped:

- the vault switcher and "Customize Sidebar" affordance in §2.2 are not built (there is one
  logical vault and the sidebar is fixed);
- attachments (§4.2 `File`) are deferred entirely
  ([ADR-0012](decisions/0012-m3-scope-deviations.md) §2);
- §10.2's one-click **"Add to `.gitignore`"** button is not built; the red warning it sits next to
  is;
- §7's Quick Access is built as of M5, and **activates the application** — a non-activating panel
  in an app with a Dock icon cannot take keystrokes on macOS 26, so the app comes forward even
  though the main window itself is never raised
  ([ADR-0017](decisions/0017-quick-access-hotkey-and-pasteboard.md) §2);
- §9's **QR-scan** path is not built; the `otpauth://` paste and manual-secret paths are;
- §8's length slider goes to 128 rather than 64, and its strength meter has five labels rather
  than four (both noted in place);
- the menu-bar status item (§6.3) is built as of M4, in the minimal form §6.3 describes: lock
  state, a badge when an approval is waiting, the active-lease count, Revoke All, Lock Now, and
  since M5 a Quick Access entry.

Touch ID has two halves and they have different statuses. The **unlock** half (§6.1, Secure
Enclave key) is implemented but unproven on hardware — see
[ADR-0011](decisions/0011-secure-enclave-under-ad-hoc-signing.md). The **approval** half (§10.3)
is proven and works on this build, because `LAContext.evaluatePolicy` needs no entitlement: it
answers a question about the person at the keyboard rather than handing back key material.

**Product framing.** kagisecure's macOS app is modeled on 1Password 8 for Mac's look, feel, and
core item-management flows — window chrome, sidebar structure, item list, item detail, and the
Quick Access floating panel — because that model is well-understood and this project's users
already know it. kagisecure is **single-user, local-only, no accounts, no sharing**, so
1Password's account/collection switcher, member management, and Watchtower dashboard are not
reproduced (see §14 Non-goals). The one substantively new surface, the MCP approval dialog
(§10), has no 1Password analog and is specified in full.

Sources consulted for 1Password 8 terminology and layout (support pages, not implementation —
kagisecure's own approval dialog and agent-access UI are original):

- <https://support.1password.com/sidebar/> — sidebar section names (All Items, Favorites,
  Vaults, Tags, Archive, Recently Deleted, Watchtower, Developer) and the "Customize" toggle
  model, which §2.2 below borrows for kagisecure's own sidebar.
- <https://support.1password.com/keyboard-shortcuts/> — Mac shortcut table referenced in §11
  (⌘F search, ⌘N new item, ⌘E edit, ⌘R reveal/conceal, ⌥⌘C copy one-time password, ⌘\ lock).
- <https://1password.com/features/how-to-use-quick-access-in-1password-8> and
  <https://1password.com/blog/navigate-1password-quick-access> — Quick Access as a floating,
  always-available panel triggered by a global shortcut, described in §7.
- Prior general knowledge of 1Password 8's three-pane layout and field-reveal conventions,
  used for §3–§4; where a specific claim could not be confirmed from the pages above it is
  marked `> Assumption:` rather than stated as fact.

---

## 1. Scope

Covers the SwiftUI app's window structure, navigation, item model presentation, lock/unlock,
password generator, TOTP, the MCP approval dialog, keyboard shortcuts, empty states,
accessibility, and dark mode. Does not cover Windows (no app until macOS ships — see roadmap
M-optional), the browser extension's own UI (roadmap M6, its own spec when scoped), or iOS
(unscheduled).

## 2. Window layout

### 2.1 Three-pane split

`NavigationSplitView` with three columns, matching 1Password 8's sidebar / item-list /
item-detail structure:

```
┌─────────────┬───────────────────────┬─────────────────────────────────┐
│  Sidebar    │      Item list        │          Item detail             │
│  (220–280pt)│      (300–420pt)      │          (flexible, min 480pt)   │
│             │                        │                                   │
│  ⌂ All Items│  🔍 Search        ⌘F  │  Acme production database         │
│  ★ Favorites│  ─────────────────    │  Database                         │
│             │  🗄 Acme prod DB   ★  │                                   │
│  CATEGORIES │  🔑 GitHub PAT        │  hostname   db.acme.internal  ⧉  │
│  ▸ Logins   │  🌐 staging.acme.com  │  username   svc_deploy        ⧉  │
│  ▸ Passwords│  💳 Corp Amex         │  password   •••••••••••  👁 ⧉  │
│  ▸ ...      │                        │  ...                              │
│             │                        │                                   │
│  TAGS       │                        │  ── Agent access ──               │
│  # prod     │                        │  Visible to agents      [off]    │
│  # personal │                        │  Last used by agent: never       │
│             │                        │                                   │
│  AGENT      │                        │                                   │
│  ACCESS     │                        │                                   │
│  ▸ Environ. │                        │                                   │
│  ▸ Leases   │                        │                                   │
│             │                        │                                   │
│  Archive    │                        │                                   │
│  Trash      │                        │                                   │
├─────────────┴───────────────────────┴─────────────────────────────────┤
│ 🔒 Personal ▾           1 vault, 42 items            ● 2 active leases  │
└──────────────────────────────────────────────────────────────────────┘
```

The sidebar can be collapsed to icon-only (standard `NavigationSplitView` behavior); the item
list can be collapsed when an item is open on a narrow window, mirroring 1Password 8's adaptive
column behavior.

### 2.2 Sidebar sections

Top to bottom, matching the section groupings 1Password 8 documents at
<https://support.1password.com/sidebar/> (All Items / Favorites / Vaults / Tags / Archive /
Recently Deleted), adapted to kagisecure's single-vault-file-with-logical-vaults model
(vault-format.md §2.2) and extended with the kagisecure-specific "Agent access" group:

| Section | Contents | Notes |
| --- | --- | --- |
| Vault switcher | Logical vaults inside the current file (`VaultMeta` list) | Dropdown at top, not a full account switcher — there is one file, one owner |
| All Items | Every non-archived, non-trashed item in the selected vault | Default selection on launch |
| Favorites | Items with `favorite: true` | |
| Categories | One row per `Category` (§5), each showing its icon and item count | Selecting filters the item list; a category with zero items is still shown (greyed count) |
| Tags | Every distinct tag across items, drag-and-drop to apply | |
| Agent access | **Environments** (list, each showing var count) and **Leases** (active leases, live count, one-click revoke) | kagisecure-specific; see §10.4. Badge shows count of currently active leases |
| Archive | Items with `archived: true` | |
| Trash | Soft-deleted items, permanent-delete after a retention window | |

Sections are reorderable/hideable via a "Customize Sidebar" affordance, matching the toggle model
1Password 8 offers.

> Assumption: no Watchtower-equivalent section. Breach/reuse checking is explicitly out of scope
> (owner decision; see §14).

### 2.3 Toolbar

Window toolbar carries: vault lock state indicator (tap to lock now), search field (also reachable
via ⌘F from anywhere), "+" new-item menu (one entry per category), and a "Set up your agent"
button that opens the agent-setup screen (architecture.md §8) showing the bundled
`kagisecure-mcp` path with one-click copy per client (mcp-server.md §9).

## 3. Item list pane

- **Search field** at the top, ⌘F focuses it from any pane. Matches title, tags, and URL
  hostnames; never matches secret field contents (there is nothing to match — `Secret` is not
  indexed in plaintext, matching vault-format.md §5.1's design).
- **Sort menu**: Title (A–Z), Date modified, Date created, Category. Default: Title.
- **Row content**: category icon, title, one-line subtitle (username for Login, hostname for
  Server/Database, masked "•••• 1234" for Credit Card), favorite star (filled if favorited,
  click to toggle).
- **Quick-copy hover actions**: hovering a row reveals small copy buttons for the row's primary
  field (username or URL) and, if present, current TOTP code — copy-only, no reveal, matching
  1Password's row-level "copy without opening the item" convenience.
- **Category filter chips** appear above the list when "All Items" is selected and more than one
  category is present, letting the user narrow without leaving All Items.
- Multi-select (⌘-click, ⇧-click) enables batch actions: add tag, move to archive, delete.

## 4. Item detail pane

### 4.1 Header

Category icon + title (inline-editable on click), favorite star, tag chips, "..." menu (Edit,
Duplicate, Move to Archive, Move to Trash, Copy item link).

### 4.2 Field rendering

| `FieldKind` (vault-format.md §5) | Display | Interaction |
| --- | --- | --- |
| `Text` | Plain value | ⧉ copy button on hover |
| `Concealed` | `••••••••••` dots, length-independent (does not leak length) | 👁 reveal (hold or toggle, ⌘R), ⧉ copy without revealing |
| `Email`, `Url`, `Phone` | Plain value, tappable (`mailto:`, opens in default browser, `tel:`) | ⧉ copy |
| `Date`, `MonthYear` | Formatted per locale | — |
| `Totp` | Live 6-to-8-digit code, large monospace and grouped (`123 456`), with a circular countdown ring that empties over the period and regenerates the code at expiry; the seconds remaining are drawn inside the ring, and code and ring turn orange in the last five seconds. Issuer and account are shown beneath. Each tick recomputes the code from the wall clock rather than counting down, so a window left open for hours cannot drift | ⧉ copy (⌥⌘C), ring click also copies. Copying yields the **code**, never the stored `otpauth://` URI |
| `Menu` | Value as plain text with disclosure affordance in edit mode (select from options) | — |
| `CreditCardNumber` | Masked as `•••• •••• •••• 1234` (last 4 visible) when concealed, full number on reveal | 👁 / ⧉ |
| `CreditCardType` | Plain (Visa, Amex, ...) with a small card-network glyph | — |
| `Address` | Multi-line formatted block | ⧉ copies full address |
| `Reference` | Link to another item (e.g. Identity referenced from a Login) | Click navigates |
| `File` | Attachment chip: filename, size, file-type icon | Click opens with Quick Look; drag out to Finder |

Fields are grouped into **sections** (`Field.section`, e.g. "Login", "Recovery", custom
user-named sections), rendered as collapsible groups, matching 1Password's item-section model.
Notes render as a full-width text block at the bottom of the last section.

### 4.3 Edit mode

Toggled by ⌘E or the "Edit" toolbar button. In edit mode: fields become editable inline, a
"+ Add field" menu offers every `FieldKind`, sections can be added/renamed/reordered/removed,
and a floating Save (⌘S) / Cancel (Esc) bar appears. Concealed fields show their actual value
while in edit mode for the field being edited (not for the whole item) so the user can correct a
typo without a separate reveal step.

### 4.4 Agent access panel

A dedicated section at the bottom of every item's detail view, kagisecure-specific (no 1Password
analog):

- **"Visible to agents" toggle** — bound to `Item.agent_visible` (vault-format.md, default
  `false`). Off by default on every item, including newly created ones and imports
  (roadmap M5-optional acceptance criterion). Toggling it on shows a one-line explainer: "Agents
  can see this item's title, category, tags, and field *names* — never values — via MCP, and can
  request approved actions (like writing a `.env`) using it."
- **Per-field override** — when the item is agent-visible, each field row gets a small toggle
  bound to `Field.agent_visible`, defaulting to the item-level setting; a field can be excluded
  even when the item is exposed (e.g. show `hostname` and `username` to agents, keep `password`
  concealed-only-via-injection). This exposes *field names*, never a values-visibility
  distinction — per mcp-server.md §2.4, non-concealed values are still withheld over MCP
  regardless of this toggle; the per-field toggle controls whether the field's existence is
  disclosed at all.
- **"Last used by agent" line** — most recent audit-log entry (mcp-server.md §6) referencing this
  item: verified client identity, action, timestamp. "Never" if absent. Click opens the Audit
  viewer filtered to this item.

> Assumption: the audit viewer itself (filterable log browser, "show me everything Cursor did
> today") is a separate full-pane view reachable from the sidebar/menu, not specified field-by-
> field here since mcp-server.md §6 already defines the entry schema. This document only
> specifies the item-level summary line.

## 5. Categories

Twelve categories, styled after 1Password 8's eleven plus kagisecure's own `Environment`:

| Category | Icon (SF Symbol, indicative) | Primary fields |
| --- | --- | --- |
| Login | `person.crop.circle` | username, password, TOTP, URLs |
| Password | `key` | password, notes |
| Secure Note | `note.text` | free-form notes |
| Credit Card | `creditcard` | number, expiry, CVV, cardholder |
| Identity | `person.text.rectangle` | name, address, contact fields |
| API Credential | `chevron.left.forwardslash.chevron.right` | key/token, endpoint |
| Server | `server.rack` | hostname, username, password |
| Database | `cylinder.split.1x2` | hostname, port, username, password |
| SSH Key | `terminal` | private key (concealed), public key, passphrase |
| Software License | `checkmark.seal` | license key, seller, version |
| Document | `paperclip` | attachment(s) + notes |
| Environment | `list.bullet.rectangle` | a named set of variables an agent can ask for (§10.4) |

The last row is kagisecure's, not 1Password's, and is the reason the count is twelve rather than
eleven: `Category::first_class()` in `kagisecure-core` returns it, `kagisecure item add --category`
accepts it, and the sidebar shows it. An earlier draft of this table left it out and said "eleven",
which the UI-test suite noticed by asserting the sidebar against this list.

All twelve rows above are first-class `Category` variants in
[vault-format.md](vault-format.md) §5 and in `kagisecure-core` as of M1; `Other(String)` is
reserved for categories a *future or foreign* version writes, and preserves them verbatim rather
than absorbing any of the rows in this table (see also
[import.md](import.md) §2.3). Nothing in this rail reads "Other" for a
category kagisecure knows about.

Each category's "+ New" flow pre-populates the field template above; all fields remain freely
addable/removable afterward (the template is a starting point, not a constraint).

## 6. Lock screen and auto-lock

### 6.1 Unlock

On launch (or after lock), a centered unlock card: vault name, a Touch ID prompt (auto-triggered
if a platform-wrapped key slot exists for this device, per vault-format.md §3.1/ADR-0004),
master-password field as fallback, and a "Use recovery code instead" link (vault-format.md §3.2).
Touch ID failure (not cancellation) after 3 attempts forces password fallback, matching macOS
system conventions.

### 6.2 Auto-lock

Settings-configurable idle timer (default 10 min), plus unconditional lock on: system sleep,
screen lock, and app quit (matches ADR-0004 §"Common rules" — lease and key lifetime rules
apply identically to the UI's lock state, since the UI *is* the app that holds the key). Manual
lock via the toolbar indicator or ⌘\.

### 6.3 Menu-bar status item

A persistent menu-bar (status item) icon shows lock state at a glance (open padlock = unlocked)
and a left-click menu offers: Quick Access (§7), Lock Now, active lease count with a jump to the
Agent Access sidebar section, and Quit.

## 7. Quick Access

> **Built in M5** (moved from M4 during M4's implementation: Quick Access is item-list UI and
> shares nothing with the approval flow, so it belongs next to the generator sheet).

A floating, always-on-top panel (not the main window), opened by a global shortcut
(`⇧⌘Space`, matching 1Password 8's default Quick Access binding — see
<https://1password.com/features/how-to-use-quick-access-in-1password-8>) or from the menu-bar
icon. Contents: a search field (autofocused) and a live-filtered flat list across all vaults,
each row offering copy actions identical to §3's hover actions, without opening the main window.
Requires the vault to already be unlocked — Quick Access does not itself present a Touch ID
prompt in v1; if the vault is locked, it shows a "Vault is locked" state with a button that opens
the main window's unlock card.

Keyboard, and only keyboard: ↑/↓ move the selection while the search field keeps focus, `⏎` copies
the selected item's password, `⌘⏎` its username, `⌥⏎` its current one-time password, and `esc`
closes. A row whose item has a one-time password carries a small clock badge, so `⌥⏎` is
discoverable rather than a thing you have to know. Every copy dismisses the panel — do the thing,
go away.

The panel keeps its **own** query and selection. Typing here does not re-filter the main window
behind it, and dismissing does not leave the three-pane UI showing a search the user has finished
with.

**As built, one thing differs from the paragraph above.** "Without opening the main window" holds:
the main window is never made key or ordered front, and a minimized one stays minimized. But the
*application* is activated, because on macOS 26 a non-activating panel in an app that has a Dock
icon cannot actually receive keystrokes — it becomes the app's focused element and the frontmost
app keeps the keys. A search panel you cannot type into is not the feature, so the app activates.
See [ADR-0017](decisions/0017-quick-access-hotkey-and-pasteboard.md) §2 for the measurement and
what would close the gap.

The shortcut is registered with `RegisterEventHotKey`, which needs **no Accessibility and no Input
Monitoring permission** — a password manager asking to watch the user type would be spending the
only thing this product has. If another app already owns `⇧⌘Space`, registration fails, Settings →
Quick Access says so, and the menu-bar item and Item menu still open the panel
([ADR-0017](decisions/0017-quick-access-hotkey-and-pasteboard.md) §1).

## 8. Password generator

A sheet, opened from a Login/Password item's password field ("Generate" button next to the edit
field) or standalone from the "+" menu, styled after 1Password 8's generator panel:

- **Mode toggle**: "Random characters" / "Memorable words" (word-list based, e.g. `correct-
  horse-battery`-style, separator configurable).
- **Length slider**: 8–128 for characters mode (default 20); 3–10 words for words mode (default
  4). *(As built: the upper bound is 128, not the 64 first specified. A 64-character ceiling is
  arbitrary where the generator is a uniform draw, and some services do accept longer.)*
- **Character-mode toggles**: uppercase, lowercase, digits, symbols (each independently
  switchable; at least one letter class must stay on), plus an "exclude ambiguous characters"
  (`0/O`, `1/l/I`) switch.
- **Words-mode toggles**: capitalize first letter, include a digit, separator character
  (`-`, `_`, `.`, space).
- **Strength meter**: a labeled bar driven by estimated entropy bits, recomputed live as options
  change. *(As built: five labels, not four — Very weak / Weak / Fair / Good / Excellent. "Weak"
  is the wrong word for a four-digit PIN, and a meter that gives it and a ten-character mixed-case
  password the same name is not saying anything.)* The bar is driven by the **recipe's** entropy,
  not by an estimate of the candidate on screen, so it moves monotonically as the slider does
  instead of jittering on every regeneration. `password_strength` — the estimator for a string
  that already exists — is a separate call, for a password the user typed rather than generated.
- **Regenerate** (⌘R within the sheet) and **Use this password**, which fills the field and
  closes the sheet; a history dropdown of the last few candidates in the session lets the user
  go back without regenerating (candidates are not persisted once the sheet closes).

Generation itself happens in `kagisecure-core` (roadmap M5), not in Swift, so the CLI
(`kagisecure generate`) and the app share one implementation and one CSPRNG source. The word list
is the EFF "long" list (7776 words, 12.9 bits each), embedded in the binary rather than read from
disk so that a passphrase does not depend on a file the user could lose or shorten.

## 9. TOTP entry flow

Adding a one-time-password field to an item, from the "+ Add field" menu (§4.3) or a dedicated
"Add one-time password" action on Login items:

1. **Scan QR** — opens the Mac camera (if available) or accepts a dragged/pasted image containing
   a QR code; decodes an `otpauth://totp/...` URI. **Not built in M5** — see the roadmap. Every
   service that shows a QR code also offers the URI behind a "can't scan the code?" link, so this
   is a convenience over paths 2 and 3 rather than a way in that would otherwise be missing.
2. **Paste `otpauth://` URI** — a text field validates and parses the URI directly (label, issuer,
   secret, algorithm, digits, period per vault-format.md §5.3).
3. **Manual entry** — separate fields for secret (Base32), service and account, algorithm
   (SHA1/SHA256/SHA512, default SHA1 for compatibility), digits (6/7/8, default 6), and period
   (default 30 s), for services that hand out a raw secret instead of a QR/URI. The Base32 field
   ignores case, `=` padding, spaces and hyphens, because this is the one field a user retypes by
   hand from a web page.

Both built paths converge on an `otpauth://` URI, which is what the field stores
(vault-format.md §5.3, [ADR-0016](decisions/0016-totp-field-storage.md)) — the manual form is
assembled into one by the core, so there is a single implementation of the escaping rules and the
parser round-trips against it.

Whichever path is used, the app immediately shows a live preview of the generated code (same ring
widget as §4.2) before the field is saved, so the user can confirm it matches the service before
committing — a wrong secret entered once is otherwise a silent failure discovered only at the
next login.

## 10. Approval dialog for MCP requests

The kagisecure-specific centerpiece, implementing the flow in mcp-server.md §4 and ADR-0004's
"common rules." Rendered by the native app, in its own window, never by the agent's UI.

> **M6.** The same sheet, on the same queue, also answers **browser autofill**. §10.5 records what
> is different about that variant; everything in §10.1–§10.3 applies to it unchanged.

### 10.1 Trigger and shape

A sheet (or, if the main window is not frontmost, a separate floating panel that also bounces the
Dock icon) appears when the app's IPC listener receives a request requiring approval
(`create_environment`, `add_variables`, `write_env_file`, `run_with_env` — mcp-server.md §2) and
no covering lease exists.

### 10.2 Contents

| Element | Detail |
| --- | --- |
| Client identity | The **verified** identity (code-signature check per architecture.md §5), shown prominently: app name + a green "Verified" badge, or, if unsigned/unrecognized, a red "Unverified — proceed with caution" banner with the specific reason underneath ("ad-hoc signed — identity not attributable to a developer", "signed by a different team", …). Self-reported `clientInfo` is shown only as a secondary "reports itself as ..." line, explicitly labeled as unverified, and always in quotation marks. The resolved executable path and the kernel's pid are shown below it. See [ADR-0015](decisions/0015-peer-code-signature-verification.md). |
| Action | Plain-language sentence: "Claude Code wants to write a `.env` file" / "...run `npm run migrate` with environment variables" / "...create an environment named `staging`". |
| Project directory | The canonicalized absolute path (symlinks resolved, per mcp-server.md §2.7); a path outside the client's declared workspace root is called out with a warning icon and red text. |
| Variable names | A scrollable list of variable **names only** — never values, never a hint of value length. For `run_with_env`, the full resolved executable path and argv are shown as well (mcp-server.md §2.8). |
| Git status | If the target is inside a git work tree not covered by `.gitignore`: a red "Not gitignored" callout. **The one-click "Add to `.gitignore`" button is not built** — writing to a user's repository from inside an approval dialog wants its own design, particularly about *which* `.gitignore` in a nested work tree. |
| TTL / uses | The requested lease TTL (default 15 min) and use count, shown as an editable control — the user may shorten TTL but not lengthen it beyond the tool's max (mcp-server.md §5). |
| Scope summary | One line: "This grants access to `DATABASE_URL`, `STRIPE_SECRET_KEY` in `~/code/acme` for 15 minutes, up to 10 uses." |

### 10.3 Actions

Three buttons, in this order, right-aligned, "Allow once" not the default focus (deny/cancel is
reachable by Esc without extra keys, matching macOS destructive-dialog conventions — approving
should require the biometric anyway, so accidental focus-return on Enter is not itself a
security issue, but it is a UX one):

- **Deny** — returns `USER_DENIED` immediately (mcp-server.md §7), no biometric needed to say no.
- **Allow once** — mints a lease with `uses_remaining: 1`; the *next* identical or broader request
  re-prompts.
- **Allow for this session** — mints a normal lease per the requested (possibly shortened) TTL and
  use count; covers subsequent identical-or-narrower requests until expiry, use exhaustion, lock,
  sleep, or explicit revoke (mcp-server.md §5).

Both "Allow" buttons require a successful Touch ID (or password fallback) before the lease is
minted and the action performed — the dialog does not proceed on click alone; the biometric sheet
appears inline immediately after the click, and a failed/cancelled biometric returns to the
approval dialog rather than silently denying, so a fumbled fingerprint isn't mistaken for a
policy decision.

A 60-second countdown is shown subtly (a thin progress bar under the buttons); on timeout the
dialog dismisses itself and the tool call returns `APPROVAL_TIMEOUT`.

### 10.4 Agent access sidebar section

Referenced from §2.2. Two lists:

- **Environments** — every `Environment` in the vault, each row showing name, variable count, and
  agent-visibility state; clicking opens an environment editor (name, description, variable
  list, each variable showing its binding — literal vs. `ItemField` reference — and a "pending"
  badge for `add_variables` requests awaiting user entry, mcp-server.md §2.6). A pending variable
  renders the agent's `hint` and a `SecureField`: **this is where the value is typed**, in the
  app, not in the agent's chat. The pane's header also carries the listener's state (and, when it
  could not bind, why) and the vault-level "Share this vault" switch, which is the outermost of
  the three default-deny gates.
- **Leases** — every currently active `Lease` (mcp-server.md §5), showing client identity,
  directory, variables, remaining TTL (live countdown), remaining uses, and a Revoke button per
  row plus a "Revoke all" action. This list is the only place leases are visible; they are never
  written to disk (memory-only, per ADR-0004).
- **Browser fills** (M6) — a second table under the same heading, because a fill lease is a
  different thing: scoped to an origin and one item, no use counter, and what it grants is "no
  second fingerprint" rather than "an injection may happen". Columns: website, item, browser,
  remaining TTL (live), Revoke. "Revoke all" empties both tables.

### 10.5 The browser-fill variant (M6)

Same sheet, same 60-second countdown, same three buttons, same biometric. What differs:

- **The sentence** names the browser and the item: *"Google Chrome wants the password for
  'Example account'"*. The browser is the app's own conclusion from the native host's process
  ancestry, so it is **not** in quotation marks — in this UI, quotation marks mean *the caller said
  so*, and they stay on an agent's self-reported name.
- **Two identity verdicts**, stacked: the native messaging helper's code signature and the
  browser's. On an unsigned build these genuinely differ, and collapsing them into one word would
  either claim a verification the helper does not have or discard the one real fact on the sheet.
  The pinned extension id is shown below them.
- **A target block**: the item, the website that was matched, and the field **names** that would be
  written. Never a value; the record the sheet is built from has no field one could occupy.
- **A frame warning**, in orange, when the form is inside a cross-origin iframe: it names the page
  the frame is embedded in and says that the *frame* is what was matched.
- **The TTL control means something different.** "Allow for this session" mints a fill lease —
  five minutes by default, fifteen at most — that skips the biometric for that item at that
  website. It does not skip the user's click in the page, which the content script requires every
  time. "Allow once" mints no lease at all.
- **The header line** says *"The value goes to the browser only if you allow it, and only for this
  page"* rather than *"No secret value is shown to the caller either way"*, because on this channel
  the second sentence would be false.
- **Audit** — every recorded call, newest first, filterable by outcome, by actor (agent / app /
  CLI) and by a text query over tool, variable names, path and detail, with the hash chain's
  verdict in the footer. Denials are shown by default and are the point: a burst of them is the
  only evidence a user gets that something tried an exfiltration (mcp-server.md §6).
- **Set up your agent** — the sidecar's absolute path for this install and the copy-ready snippet
  for each of the four clients (mcp-server.md §9), rendered from the same table
  `kagisecure mcp install --print` reads.

## 11. Keyboard shortcuts

| Shortcut | Action | Source |
| --- | --- | --- |
| ⌘F | Focus search | 1Password 8 |
| ⇧⌘Space | Open Quick Access (§7) | 1Password 8 |
| ⌘N | New item | 1Password 8 |
| ⌘E | Edit selected item | 1Password 8 |
| ⌘S | Save changes | 1Password 8 |
| Esc | Cancel edit / dismiss sheet | 1Password 8 |
| ⌘R | Reveal/conceal the focused concealed field | 1Password 8 |
| ⌘C | Copy the item's primary field (username) | 1Password 8 |
| ⇧⌘C | Copy password | 1Password 8 |
| ⌥⌘C | Copy current TOTP code | 1Password 8 |
| ⇧⌘G | Open the password generator (§8) | kagisecure-specific |
| ⌘R (in the generator sheet) | Regenerate | 1Password 8 |
| ⏎ / ⌘⏎ / ⌥⏎ (in Quick Access) | Copy password / username / one-time code | 1Password 8 |
| ⌘\ | Lock vault now | 1Password 8 |
| ⌘, | Settings | 1Password 8 |
| ⌘1…⌘9 | Jump to sidebar section *n* | 1Password 8 (collections) |
| Return (in approval dialog) | Nothing — no default-focus approve, see §10.3 | kagisecure-specific |

## 12. Empty states

| Context | Message | Primary action |
| --- | --- | --- |
| First launch, no vault | "Create your first vault" with a short explainer of the recovery code | Create Vault |
| A category with zero items | "No {Category} items yet" | + New {Category} |
| Search with no matches | "No items match \"{query}\"" | Clear search |
| Agent Access → Environments, none created | "Agents can request access to environment variables you create here. Nothing yet." | + New Environment |
| Agent Access → Leases, none active | "No agent currently has access. Approved requests will appear here." | (none — informational) |
| Trash, empty | "Trash is empty" | (none) |
| MCP not connected (no client has connected this session) | Shown on the "Set up your agent" screen, not as a nag elsewhere | Copy config snippet |

## 13. Accessibility and dark mode

- Full VoiceOver labeling: concealed fields announce "password, concealed, activate to reveal"
  rather than reading dots; the TOTP countdown ring exposes its remaining-seconds value as an
  accessibility value, not only a visual animation.
- Dynamic Type respected throughout; the three-pane layout collapses to a navigable stack
  (sidebar → list → detail) under Dynamic Type XL and above or narrow windows, rather than
  truncating.
- Full keyboard navigation: every action reachable via mouse (including the approval dialog's
  buttons and the reveal/copy hover actions in §3/§4) has a keyboard path; hover-only affordances
  are never the sole way to reach an action.
- Color is never the only signal: the "Unverified caller" and "Not gitignored" warnings in §10
  pair color with an icon and text, for color-blind and reduced-transparency users.
- Standard SwiftUI dark mode support (`.preferredColorScheme` respects system setting, no forced
  light/dark). The TOTP ring, strength meter, and verified/unverified badges each define both a
  light and dark palette; none rely on pure black/white for contrast-sensitive elements.
- `Reduce Motion` disables the TOTP ring's sweep animation in favor of a static countdown digit.
- The import sheet ([import.md](import.md) §8) follows the same rules: its per-item table is a real
  `Table` with a header row VoiceOver can read, the three dropped counters pair their number with
  the one-line explanation rather than relying on a badge color, and the format picker, the
  duplicate-policy picker and both buttons are reachable by keyboard alone. Its accessibility
  identifiers — `ks.import.*` — are in §15.

## 14. Explicit non-goals

Carried over from README.md and architecture.md §9, restated here for the UI layer specifically:

- **Sharing / multi-user.** No member list, no shared vaults, no permission model. Single owner,
  single Mac (per device, via the biometric-wrapped key slot in vault-format.md §3.1).
- **Watchtower-style breach/reuse monitoring.** No security-dashboard sidebar section, no
  password-health scoring UI. May be reconsidered post-v1; not designed here.
- **Sync UI.** No account, no "sync now" indicator, no conflict-resolution UI. The vault is a
  file; if the user syncs it with their own tool, that tool's UI is not kagisecure's concern.
- **Windows UI.** This document is macOS-only. A WinUI 3 equivalent is unscheduled
  ([roadmap.md](roadmap.md)); the vault format and `kagisecure-core` remain platform-agnostic so
  that work is not blocked when it starts.
- **iOS.** Not scheduled; no companion-app affordances (e.g. no "open on iPhone" handoff UI) are
  specified here.
- **Browser-extension UI.** The Safari/Chrome autofill extension (roadmap M6) has its own popup
  and native-messaging permission UI, out of this document's scope; it will get its own spec
  when M6 is scheduled, including the extension-specific threat-model addendum roadmap M6 calls
  for.

## 15. Appendix: accessibility identifiers

Every control the XCUITest suite presses, and every string it asserts on, carries an
`accessibilityIdentifier`. The convention is `ks.<screen>.<element>`: lower-camel-case segments,
ASCII only, and stable across runs — a row in a repeating list interpolates its own key rather than
its position, so `ks.item.fieldCopy.password` means the same row tomorrow. Placeholders below in
`<angle brackets>` are that interpolation.

These are **not decoration**, and they are not free to rename: they are the contract
`apps/macos/KagisecureUITests/` is written against, and [e2e-harness.md](e2e-harness.md) §7.2 is
where the rules for adding one live. The one that catches everybody: an identifier on a SwiftUI
layout container (`VStack`, `HStack`, `Group`, `DisclosureGroup`) is stamped onto every leaf inside
it, overwriting the identifiers those leaves set for themselves — so identifiers go on leaves. The
exceptions are genuine AppKit containers, `List`, `Table` and `ScrollView`, which keep it to
themselves; `ks.sidebar.list`, `ks.itemList.list`, `ks.audit.table`, `ks.leases.table` and
`ks.item.root` are those.

Identifiers are not user-visible and are not localized. `accessibilityLabel` — which *is* both — is
a separate thing and is unaffected by any of this.

**First run (§12)**

- `ks.createVault.confirmation`
- `ks.createVault.create`
- `ks.createVault.mismatch`
- `ks.createVault.password`
- `ks.createVault.title`
- `ks.createVault.tooShort`
- `ks.createVault.vaultName`
- `ks.createVault.vaultPath`

**Recovery code sheet (§12)**

- `ks.recoveryCode.acknowledge`
- `ks.recoveryCode.code`
- `ks.recoveryCode.copy`
- `ks.recoveryCode.done`
- `ks.recoveryCode.title`

**Lock screen (§6.1)**

- `ks.lock.password`
- `ks.lock.reason`
- `ks.lock.recoveryCode`
- `ks.lock.recoveryDisclosure`
- `ks.lock.recoveryUnlock`
- `ks.lock.title`
- `ks.lock.touchId`
- `ks.lock.touchIdUnavailable`
- `ks.lock.unlock`
- `ks.lock.vaultFile`

**The error alert**

- `ks.alert.ok`

**Window toolbar (§2.3)**

- `ks.toolbar.edit`
- `ks.toolbar.generator`
- `ks.toolbar.lock`
- `ks.toolbar.more`
- `ks.toolbar.newItem`
- `ks.toolbar.newItem.<category>`
- `ks.toolbar.quickAccess`
- `ks.toolbar.sort`
- `ks.toolbar.sortPicker`

**Sidebar (§2.2)**

- `ks.sidebar.agentAudit`
- `ks.sidebar.agentEnvironments`
- `ks.sidebar.agentLeases`
- `ks.sidebar.agentSetup`
- `ks.sidebar.all`
- `ks.sidebar.archive`
- `ks.sidebar.browserExtension`
- `ks.sidebar.category.<name>`
- `ks.sidebar.favorites`
- `ks.sidebar.list`
- `ks.sidebar.listenerState`
- `ks.sidebar.tag.<name>`
- `ks.sidebar.trash`
- `ks.sidebar.vaultName`

**Item list (§3)**

- `ks.itemList.list`
- `ks.itemList.rowCopySubtitle`
- `ks.itemList.rowCopyTotp`
- `ks.itemList.rowFavorite`
- `ks.itemList.rowSubtitle`
- `ks.itemList.rowTitle`

**Item detail (§4)**

- `ks.item.agentVisible`
- `ks.item.archivedBadge`
- `ks.item.category`
- `ks.item.favorite`
- `ks.item.fieldAgentVisible.<label>`
- `ks.item.fieldCopy.<label>`
- `ks.item.fieldLabel.<label>`
- `ks.item.fieldReveal.<label>`
- `ks.item.fieldValue.<label>`
- `ks.item.lastUsedByAgent`
- `ks.item.menu.archive`
- `ks.item.menu.deleteForever`
- `ks.item.menu.restore`
- `ks.item.menu.trash`
- `ks.item.noFields`
- `ks.item.notes`
- `ks.item.root`
- `ks.item.section.<name>`
- `ks.item.tag.<tag>`
- `ks.item.title`
- `ks.item.trashedBadge`

**Edit mode (§4.3)**

- `ks.edit.addField`
- `ks.edit.cancel`
- `ks.edit.fieldConcealed.<label>`
- `ks.edit.fieldGenerate.<label>`
- `ks.edit.fieldLabel.<label>`
- `ks.edit.fieldRemove.<label>`
- `ks.edit.fieldTotpSetup.<label>`
- `ks.edit.fieldValue.<label>`
- `ks.edit.notes`
- `ks.edit.save`
- `ks.edit.tags`
- `ks.edit.title`
- `ks.edit.urls`

**Empty states (§12)**

- `ks.emptyState.action`
- `ks.emptyState.message`
- `ks.emptyState.title`

**Password generator (§8)**

- `ks.generator.bits`
- `ks.generator.cancel`
- `ks.generator.candidate`
- `ks.generator.copy`
- `ks.generator.error`
- `ks.generator.history`
- `ks.generator.length`
- `ks.generator.lengthValue`
- `ks.generator.mode`
- `ks.generator.regenerate`
- `ks.generator.separator`
- `ks.generator.strength`
- `ks.generator.strengthLabel`
- `ks.generator.toggle.avoidAmbiguous`
- `ks.generator.toggle.capitalize`
- `ks.generator.toggle.digits`
- `ks.generator.toggle.includeDigit`
- `ks.generator.toggle.lowercase`
- `ks.generator.toggle.symbols`
- `ks.generator.toggle.uppercase`
- `ks.generator.use`
- `ks.generator.words`
- `ks.generator.wordsValue`

**One-time password field (§4.2)**

- `ks.totp.caption`
- `ks.totp.code`
- `ks.totp.copy`
- `ks.totp.error`
- `ks.totp.field`
- `ks.totp.ring`

**One-time password setup (§9)**

- `ks.totpSetup.account`
- `ks.totpSetup.algorithm`
- `ks.totpSetup.cancel`
- `ks.totpSetup.digits`
- `ks.totpSetup.issuer`
- `ks.totpSetup.mode`
- `ks.totpSetup.period`
- `ks.totpSetup.previewCaption`
- `ks.totpSetup.previewCode`
- `ks.totpSetup.previewEmpty`
- `ks.totpSetup.save`
- `ks.totpSetup.secret`
- `ks.totpSetup.uri`

**Quick Access (§7)**

- `ks.quickAccess.empty`
- `ks.quickAccess.legend`
- `ks.quickAccess.list`
- `ks.quickAccess.locked`
- `ks.quickAccess.openMainWindow`
- `ks.quickAccess.rowSubtitle`
- `ks.quickAccess.rowTitle`
- `ks.quickAccess.rowTotpBadge`
- `ks.quickAccess.search`
- `ks.quickAccess.toast`

**Settings (§6.2, §6.3, §7)**

- `ks.settings.auditState`
- `ks.settings.autoLockInterval`
- `ks.settings.clipboardInterval`
- `ks.settings.quickAccessError`
- `ks.settings.quickAccessShortcut`
- `ks.settings.tab.security`
- `ks.settings.tab.vault`
- `ks.settings.touchIdToggle`
- `ks.settings.touchIdUnavailable`
- `ks.settings.vaultPath`
- `ks.settings.wordlist`

**Agent access — Environments (§10.4)**

- `ks.agentAccess.activeLeases`
- `ks.agentAccess.empty`
- `ks.agentAccess.endpoint`
- `ks.agentAccess.list`
- `ks.agentAccess.listenerError`
- `ks.agentAccess.listenerState`
- `ks.agentAccess.newEnvironment`
- `ks.agentAccess.pendingBadge.<environment>`
- `ks.agentAccess.row.<environment>`
- `ks.agentAccess.shareVault`

**Agent access — the new-environment sheet (§10.4)**

- `ks.newEnvironment.cancel`
- `ks.newEnvironment.create`
- `ks.newEnvironment.name`

**Agent access — the environment editor (§10.4)**

- `ks.environment.addVariable`
- `ks.environment.binding.<label>`
- `ks.environment.description`
- `ks.environment.hint.<label>`
- `ks.environment.name`
- `ks.environment.newVariableName`
- `ks.environment.newVariableValue`
- `ks.environment.noVariables`
- `ks.environment.pendingSave.<label>`
- `ks.environment.pendingValue.<label>`
- `ks.environment.removeVariable.<label>`
- `ks.environment.share`
- `ks.environment.variable.<label>`

**Agent access — Leases (§10.4)**

- `ks.leases.cell.caller`
- `ks.leases.cell.directory`
- `ks.leases.cell.expires`
- `ks.leases.cell.uses`
- `ks.leases.cell.variables`
- `ks.leases.empty`
- `ks.leases.revoke`
- `ks.leases.revokeAll`
- `ks.leases.table`

**Agent access — Browser fills (§10.4)**

- `ks.fillLeases.cell.browser`
- `ks.fillLeases.cell.expires`
- `ks.fillLeases.cell.item`
- `ks.fillLeases.cell.website`
- `ks.fillLeases.heading`
- `ks.fillLeases.revoke`
- `ks.fillLeases.table`

**Agent access — Audit (§10.4)**

- `ks.audit.cell.outcome`
- `ks.audit.cell.tool`
- `ks.audit.chainState`
- `ks.audit.empty`
- `ks.audit.filter.actor`
- `ks.audit.filter.outcome`
- `ks.audit.filter.tool`
- `ks.audit.query`
- `ks.audit.reload`
- `ks.audit.table`

**Set up your agent (§10.4)**

- `ks.agentSetup.copy.<client>`
- `ks.agentSetup.copy.sidecar`
- `ks.agentSetup.footer`
- `ks.agentSetup.sidecarMissing`
- `ks.agentSetup.sidecarPath`
- `ks.agentSetup.snippet.<client>`
- `ks.agentSetup.title`

**Browser extension (M6)**

- `ks.browserExtension.browserRow.<browser>`
- `ks.browserExtension.browserState.<browser>`
- `ks.browserExtension.copy.extensionId`
- `ks.browserExtension.copy.hostPath`
- `ks.browserExtension.extensionId`
- `ks.browserExtension.extensionPath`
- `ks.browserExtension.hostPath`
- `ks.browserExtension.installManifest.<browser>`
- `ks.browserExtension.manifestPath.<browser>`
- `ks.browserExtension.removeManifest.<browser>`
- `ks.browserExtension.safari.appGroup`
- `ks.browserExtension.safari.bundleId`
- `ks.browserExtension.safari.socketPath`
- `ks.browserExtension.safariStatus`
- `ks.browserExtension.status`
- `ks.browserExtension.title`
- `ks.browserExtension.warning`
- `ks.browserExtension.warning.hostPath`
- `ks.browserExtension.warning.manifest`
- `ks.browserExtension.warning.safari`

**Approval dialog (§10)**

- `ks.approval.allowOnce`
- `ks.approval.allowSession`
- `ks.approval.biometricProblem`
- `ks.approval.browserProcess`
- `ks.approval.callerCwd`
- `ks.approval.command`
- `ks.approval.countdown`
- `ks.approval.deny`
- `ks.approval.directory`
- `ks.approval.environment`
- `ks.approval.evidence`
- `ks.approval.extensionId`
- `ks.approval.fill.fields`
- `ks.approval.fill.item`
- `ks.approval.fill.website`
- `ks.approval.frameWarning`
- `ks.approval.gitignoreWarning`
- `ks.approval.headline`
- `ks.approval.helperProcess`
- `ks.approval.process`
- `ks.approval.reportedName`
- `ks.approval.sentence`
- `ks.approval.summary`
- `ks.approval.targetPath`
- `ks.approval.ttlSlider`
- `ks.approval.ttlValue`
- `ks.approval.variable.<name>`
- `ks.approval.variables`
- `ks.approval.variablesNote`
- `ks.approval.verdict`
- `ks.approval.verdict.browser`
- `ks.approval.verdict.helper`

**Menu-bar status item (§6.3)**

- `ks.menuBar.agentState`
- `ks.menuBar.browserState`
- `ks.menuBar.icon`
- `ks.menuBar.lockNow`
- `ks.menuBar.lockState`
- `ks.menuBar.openMainWindow`
- `ks.menuBar.pendingApprovals`
- `ks.menuBar.quickAccess`
- `ks.menuBar.quit`
- `ks.menuBar.revokeAll`


**Import — File ▸ Import… ([import.md](import.md) §8)**

- `ks.import.cancel`
- `ks.import.category.<name>`
- `ks.import.confirm`
- `ks.import.detailTable`
- `ks.import.droppedAttachments`
- `ks.import.droppedHistory`
- `ks.import.droppedPasskeys`
- `ks.import.duplicatePolicy`
- `ks.import.duplicates`
- `ks.import.error`
- `ks.import.format`
- `ks.import.open`
- `ks.import.result`
- `ks.import.sheet`
- `ks.import.shredConfirm`
- `ks.import.shredPrompt`
- `ks.import.shredSkip`
- `ks.import.sourcePath`
- `ks.import.totalItems`

`ks.import.droppedHistory` counts **unparsable** password-history entries only. History itself is
imported ([import.md](import.md) §2.7); the counter is for entries the parser could not use.

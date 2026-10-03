# macOS UI spec

Status: **§1–§13 implemented** (`apps/macos`); §1–§6/§11–§13 in M3, §10 (the
approval dialog and the Agent access section) in M4; §7 (Quick Access) moved to M5, where §8–§9
(generator, TOTP) already were. **§16 (shared vaults)** is built as ADR-0035's Phase 5, and has not
yet been tried by a person on two Macs. This document specifies the SwiftUI app described in
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
already know it. kagisecure is **local-only, with no accounts**, so 1Password's
account/collection switcher and Watchtower dashboard are not reproduced (see §14 Non-goals).
Sharing is the one exception, and it has no server either: a shared vault
([ADR-0035](decisions/0035-shared-vaults.md)) syncs through a folder its members share, and has a
members screen of its own (§16). The one substantively new surface, the MCP approval dialog
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

**Agent sections use two columns.** While one of the Agent access rows (Environments, Leases,
Audit, Set up your agent — §10.4) or Browser extension is selected, the window is sidebar plus
one pane: there is no item list, and the pane takes its width (about 800 pt instead of about
460 pt in the minimum 1,040 pt window). Every vault section — All Items, Favorites, a category, a
tag, Archive, Trash — keeps the three columns above. The swap is two `NavigationSplitView`s, because
a three-column split cannot hide its middle column while keeping the sidebar; across it the window
keeps whether the sidebar is collapsed, each column's width, the keyboard focus when the change
came from the sidebar (so the arrow keys walk straight through), and the item selection — coming
back to a vault section shows the item list with the item that was selected before. The search
field belongs to the item list, so it is not in the toolbar in an agent section; ⌘F there goes back
to the vault section last shown and focuses its search.

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
| Shared | One row per shared vault (its items, with an item count), an **Environments** row and a **Members** row under it; a "+" menu to create or join one | See §16. A vault whose copy on this Mac cannot be read shows a warning icon |
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
  click to toggle). A card's digits come only from its **card-number field by kind**
  (`CreditCardNumber`), never from a field found by its label: a label can be edited without a
  presence check, and "the field called *number*" would let a relabelled PIN or CVV print its
  digits under the title. A card created by an older template, whose number is a plain concealed
  field, shows no digits until that field's kind is set to *Card number* (which, for a stored
  value, needs the value — Show or a new one).
- **Quick-copy hover actions**: hovering a row reveals small copy buttons for the row's primary
  field (username or URL) and, if present, current TOTP code — copy-only, no reveal, matching
  1Password's row-level "copy without opening the item" convenience. The primary field is public
  and copies at once; the one-time code is a secret, so copying it asks for presence first —
  Touch ID, an Apple Watch or the Mac's password — through its own one-use release
  ([ADR-0038](decisions/0038-app-release-needs-presence.md)), unless that item's code is already
  running in the detail pane, in which case the running code is copied with no new prompt.
- **Category filter chips** appear above the list when "All Items" is selected and more than one
  category is present, letting the user narrow without leaving All Items.
- Multi-select (⌘-click, ⇧-click, ⌘A) selects several items (`VaultStore.multiSelection`; one
  selected item stays the ordinary single selection). With two or more selected, the detail pane
  shows "N items selected" (`ks.multiSelection.count`) with **Show to Agents** and **Hide from
  Agents** (`ks.multiSelection.showToAgents`, `ks.multiSelection.hideFromAgents`); the same two
  actions are in each row's context menu (`ks.itemList.showToAgents`, `ks.itemList.hideFromAgents`
  — on the whole selection when the row is part of it, else on that row) and in the **Item** menu.
  Personal vault only. One transaction and one audit entry per action, counts only
  ([ADR-0007](decisions/0007-m2-daemon-and-ipc-deviations.md) amendment 2026-10-04). Other batch
  actions (add tag, move to archive, delete) are not built yet.

## 4. Item detail pane

### 4.1 Header

Category icon + title (inline-editable on click), favorite star, tag chips, "..." menu (Edit,
Duplicate, Move to Archive, Move to Trash, Copy item link).

### 4.2 Field rendering

| `FieldKind` (vault-format.md §5) | Display | Interaction |
| --- | --- | --- |
| `Text` | Plain value | ⧉ copy button on hover |
| `Concealed` | `••••••••••` dots, length-independent (does not leak length) | 👁 reveal (toggle, ⌘R) and ⧉ copy without revealing — each asks for presence once, for this field only; copying a value already revealed asks nothing |
| `Email`, `Url`, `Phone` | Plain value, tappable (`mailto:`, opens in default browser, `tel:`) | ⧉ copy |
| `Date`, `MonthYear` | Formatted per locale | — |
| `Totp` | Masked (`••• •••`) with a **Show** button until the person asks; one presence prompt then runs it live for at most five minutes: a 6-to-8-digit code, large monospace and grouped (`123 456`), with a circular countdown ring that empties over the period and regenerates the code at expiry; the seconds remaining are drawn inside the ring, and code and ring turn orange in the last five seconds. Issuer and account are shown beneath. Each tick recomputes the code from the wall clock rather than counting down, so a window left open for hours cannot drift | ⧉ copy (⌥⌘C), ring click also copies, 👁 hides. Copying a running code asks nothing; copying a masked one asks for presence once. Copying yields the **code**, never the stored `otpauth://` URI |
| `Menu` | Value as plain text with disclosure affordance in edit mode (select from options) | — |
| `CreditCardNumber` | Masked as `•••• •••• •••• 1234` (last 4 visible) when concealed, full number on reveal | 👁 / ⧉ |
| `CreditCardType` | Plain (Visa, Amex, ...) with a small card-network glyph | — |
| `Address` | Multi-line formatted block | ⧉ copies full address |
| `Reference` | Link to another item (e.g. Identity referenced from a Login) | Click navigates |
| `File` | Attachment chip: filename, size, file-type icon | Click opens with Quick Look; drag out to Finder |

Fields are grouped into **sections** (`Field.section`, e.g. "Login", "Recovery", custom
user-named sections), rendered as collapsible groups, matching 1Password's item-section model.
Notes render as a full-width text block at the bottom of the last section — **masked**, with a
show (👁) and a copy (⧉) button, because every note is secret
([ADR-0038](decisions/0038-app-release-needs-presence.md) user decision 3).

**Every secret the pane shows or copies needs a fresh presence proof**
([ADR-0038](decisions/0038-app-release-needs-presence.md)). Revealing a field, copying a concealed
value, starting a one-time code and showing or copying the notes each raise the system's
LocalAuthentication prompt — Touch ID, an Apple Watch or the Mac's login password — naming the
item, the field and the action, and ending "Continue only if you just asked Kagisecure to…". One
touch covers one field: the password and then the one-time code are two touches. Copying a value
already on screen asks nothing (the audit log records it `SHOWN_EARLIER`). A cancelled prompt
changes nothing and raises no alert. If LocalAuthentication cannot run at all on this Mac, a small
panel asks for the vault's **master password** instead (user decision 7); a wrong one is refused
for one second, then two, four and so on up to five minutes, and the panel says how long. Only one
prompt is on screen at a time in the whole app — a second request, from here, from Quick Access or
from a browser fill, is refused rather than stacked behind it. There is no setting to turn any of
this off (user decision 6).

A shown value **hides itself** when another item is selected, when the vault locks, and five
minutes after the touch that showed it (use does not extend it); a shown value is **not
selectable**, so ⌘C, a drag or the Services menu cannot carry it past the concealed clipboard type
and its timed clear — the copy button is the way out.

### 4.3 Edit mode

Toggled by ⌘E or the "Edit" toolbar button. In edit mode: fields become editable inline, a
"+ Add field" menu offers every `FieldKind`, sections can be added/renamed/reordered/removed,
and a floating Save (⌘S) / Cancel (Esc) bar appears.

**Edit mode prefills nothing concealed** (ADR-0038 step 3). Opening it used to fetch every
concealed field's real value — the password, a card number, a TOTP seed — into one `TextField`
apiece, on the theory that fixing a typo should not need a separate reveal step. That prefill was
also the app's largest single data-loss surface: if the fetch failed for any reason, the field
simply showed an empty string, and pressing Save then replaced the stored secret with that empty
string — silently, with no error and no confirmation. A concealed field in edit mode is masked the
same way it is in the detail view — a fixed run of dots, never a length — with a "Change" button
next to it. Pressing "Change" is the one and only door into replacing that field's value: it swaps
the mask for an ordinary text field the user can type a new value into. A field left alone (no
"Change" press) keeps its stored value byte for byte, because the app never held a copy of it to
begin with. Saving without pressing "Change" on any concealed field — the common case of fixing
the title or adding a tag — touches no secret at all. Reopening the one-time-password setup sheet
over an already-configured TOTP field follows the same rule: it opens blank, not prefilled with
the stored seed; replacing it means entering or pasting the new one, the same as first setup.

To **see** a stored value while editing — to fix a typo rather than retype it — a masked field
also has a **Show** button, which asks for presence for that one field (ADR-0038 `EditReveal`) and
puts its value in the text field; the setup sheet has **Show current setup** for the seed, and the
notes have **Show**, **Replace** and **Remove**. "Change" and "Replace" release nothing: they start
a new value without the old one ever entering the app. A value shown this way that is still
untouched five minutes later is masked again, which keeps it exactly as stored.

Unchecking "Concealed" on a field with no new value is refused rather than silently exposing the
stored secret's plaintext into the public, agent-visible slot: making a field public requires
supplying a new value in the same edit. A newly added field (one the "+ Add field" menu just
created) always needs a value, concealed or not — there is nothing stored yet for "leave it alone"
to mean.

Saving is refused, rather than silently overwriting someone else's edit, if the item changed on
disk after the sheet opened — another window, the CLI, another process. A one-button alert, "This
item changed elsewhere" / "This item was changed elsewhere — reload.", closes the sheet and
re-reads the item; whatever was typed in the sheet is lost, the same way Cancel already loses it,
because there is no way to tell which of the two conflicting edits the person meant to keep. A
plain toggle elsewhere on the item — favourite, archive, trash, "Visible to agents" — is *not* this
kind of conflict and is never refused: the last one applied simply wins, since there is nothing to
merge for a single flag (compare §6.4, which covers the file-level version of "someone else wrote
first").

### 4.4 Agent access panel

A dedicated section at the bottom of every item's detail view, kagisecure-specific (no 1Password
analog):

- **"Visible to agents" toggle** — bound to `Item.agent_visible`. A newly created or imported
  item starts **on**, with every field on, while its logical vault's **"Show new items to
  agents"** setting is on — the default (Settings ▸ AI Agents ▸ Item visibility,
  `ks.settings.newItemsAgentVisible`; [ADR-0007](decisions/0007-m2-daemon-and-ipc-deviations.md)
  amendment 2026-10-04, superseding the roadmap M5-optional "off by default" criterion). The same
  section has **Show All Items to Agents…** (`ks.settings.showAllToAgents`, confirmed) for items
  that existed before. Tag and category rows in the sidebar have **Show All in "<name>" to
  Agents** / **Hide All in "<name>" from Agents** in their context menu. Toggling it on shows a
  one-line explainer: "Agents
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

*(As built, 2026-10-04: Touch ID unlock is on by default. After a master-password or recovery-code
unlock with Touch ID available and no platform slot, the app enrols silently; if the person turned
Touch ID off in Settings, or silent enrolment failed, a small sheet asks "Turn on Touch ID unlock?"
with Turn On / Not Now and a "Don't show this again" checkbox. Turning it on in Settings clears
the turned-off mark. ADR-0004 addendum 2026-10-04.)*

### 6.2 Auto-lock

Settings-configurable idle timer (default 10 min), plus unconditional lock on: system sleep,
screen lock, and app quit (matches ADR-0004 §"Common rules" — lease and key lifetime rules
apply identically to the UI's lock state, since the UI *is* the app that holds the key). Manual
lock via the toolbar indicator or ⌘\.

*(As built: "idle" is the minimum of system-wide input idleness, time since this session's own
unlock, and time since the last in-app activity — a keystroke, click or scroll in one of our
windows, or a vault operation such as a reveal, copy or save. The unlock and in-app-activity
floors exist so that a session does not inherit hours of stale system idleness at the moment of
unlock, and so that accessibility- or remote-control-driven interaction, which does not move the
system-wide counters, is not mistaken for having left the computer; see
docs/investigations/2026-09-27-remote-idle-relock.md.)*

### 6.3 Menu-bar status item

A persistent menu-bar (status item) icon shows lock state at a glance (open padlock = unlocked)
and a left-click menu offers: Quick Access (§7), Lock Now, active lease count with a jump to the
Agent Access sidebar section, and Quit.

*(As built: a native menu — a menu-style `MenuBarExtra` — rather than a window-style panel. The
HIG's advice for a status item whose content is a handful of commands is a menu, and a native
`NSMenu` is fully accessible: every entry is in the accessibility tree with its title and enabled
state, so VoiceOver reads it and the arrow keys and type-select work. The icon says its state in
words too — "Kagisecure, vault locked", "…vault unlocked", "…vault unlocked, 1 approval(s)
waiting" — which is the status item's accessibility title.)*

The icon carries the same badge, and its title the suffix ", N agent-fill notice(s)", while an
agent-fill notice nobody has looked at is waiting (§10.4); the menu then offers "N agent-fill
notice(s) — review", which opens Agent access.

### 6.4 Other writers: busy and conflict

The vault file is written by more than one process — this app, the CLI, the agent daemon — and by
more than one window of this app. Two alerts cover what a person sees when that overlaps with
something they just did:

- **Busy.** Another writer held the file for longer than this app's ~2s wait. "Another kagisecure
  process is using the vault right now. Try again in a moment." One OK button; nothing was
  written, and the same action can simply be retried. Shown through the same generic alert every
  other failure uses (`ks.alert.ok` for unlock-time and Touch ID failures, `ks.alert.storeOk` for
  everything else once a vault is open, `ks.alert.agentOk` for the Agent-access surface — today,
  a failed lease revoke), never its own dialog — a busy vault is not a decision, so it does not
  get a decision's UI. This includes one-click actions with no UI of their own — the favourite
  star, archive, trash, restore, delete permanently, "Visible to agents" and the per-field agent
  checkboxes, reveal and copy: a failure there is shown, never swallowed, so a refused write
  cannot look like a button that did nothing (`VaultStore.attempt`, `AgentService.revoke(_:)`).
- **Conflict.** The vault file changed *underneath* this session in a way its writes can no longer
  trust: an older copy was restored over it, a different vault now sits at the path, something
  that is not a vault this app can read does (damaged, not a kagisecure file, or written by a newer
  version), or the file is simply gone. Detected either by a write that hits it, or by
  `VaultSession.sync()` — called on `NSApplicationDidBecomeActive`, on a ~2s timer while the app is
  frontmost, and right before the Audit view (§10.4) re-reads the log, so a person does not have to
  attempt an edit first to find out. Writes stop the moment this is detected. A two-button alert,
  "The vault file changed", explains what is different (the four underlying reasons share this one
  alert — see `conflictMessage(_:)` in `RootView.swift`) and offers:
  - **"Keep this app's version (overwrite the file)…"** — does not overwrite yet. It asks what the
    file holds that would be lost (`VaultSession.conflictDetails()`) and shows a second,
    destructive confirmation, "Overwrite the vault file?", whose text
    (`overwriteConfirmationMessage(_:)`) says exactly that:
    - an older or separately changed copy of this vault: how many items, environments, vault
      settings and audit log entries exist only in the file or differ there (or that there are
      none);
    - a different vault, or one this app's key cannot open: that it is destroyed entirely, and
      that the app cannot tell what it contains — keep a copy first;
    - a file this app cannot read: that it is replaced entirely, and to update instead if a newer
      kagisecure wrote it;
    - no file: that this app's version is written there, and that a vault moved on purpose would
      end up in two places.

    Because the overwrite writes this app's *header* as well as its contents, the confirmation
    also says when the unlock methods differ: the master password that opens the file now stops
    working and the one this app was last unlocked with works instead; the recovery code that
    opens the file now stops working and this app's works again, even one replaced on purpose in
    the file's version; Touch ID goes back to how this app last saw it. Every confirmation ends
    with "The overwrite is recorded in the vault's audit log."

    **"Overwrite the File"** (destructive) runs `VaultSession.keepAppVersionOverConflict`, handing
    back exactly the details that were shown. Rust refuses to act on anything else: if the file
    changed again in the meantime, nothing is written and the confirmation reappears with the new
    details; if the file turned out to continue this app's session again (the newer file was put
    back), nothing is overwritten, the session catches up the ordinary way, and a one-button
    notice, "Nothing to overwrite", says so. On success the conflict is gone, every audit entry
    still waiting in this session is written, followed by one recording what was overwritten, and
    writes work again. **"Cancel"** returns to the two-choice alert. A failure (busy, a full disk)
    is shown in the store's error alert and the conflict alert returns once it is dismissed.
  - **"Lock and reopen from the file"** — locks (`LockReason.conflict`, its own lock-screen message)
    and returns to the unlock card bound to the same path; unlocking always reads the file fresh, so
    this is the actual recovery. Once the next unlock succeeds, the app records the recovery in the
    audit log, best-effort, the same way a reveal is (§4.2) — never blocking getting back in.

### 6.5 "Connect your browsers" prompt

After an unlock (never over the lock screen), the app checks which browsers on this Mac it cannot
fill in yet and, at most once per launch, offers to connect them in a sheet titled **"Fill
passwords in your browsers"**. The sheet is queued behind every other sheet (recovery code, Touch
ID offer, approvals, "While you were away", generator, import) and appears when they close. It is
not shown to the UI-test suite.

- **Which browsers.** The Chromium-family browsers the core knows (`ExtensionSetupView.manifests`:
  Chrome, Edge, Arc, Brave, Chromium) whose app is installed, plus Safari when this build can serve
  it (Safari appex embedded and an App Group). A Chromium browser counts as **connected** when its
  native-messaging manifest is written *and* one of its profiles' `Preferences` / `Secure
  Preferences` names the extension (the unpacked id or Web Store item
  `aacppfmljihmjacphgpkbmanhbhphjgl`); Safari when `SFSafariExtensionManager` reports the extension
  enabled. Connected, silenced and snoozed browsers are not offered (`BrowserConnectPrompt`).
- **Rows.** The browser's real app icon (`NSWorkspace.icon(forFile:)`), its name, a **Connect**
  button and a **"Don't ask about this browser again"** checkbox (checking it disables Connect).
  Connect writes the manifest if missing and opens the Chrome Web Store listing *in that browser*;
  for Safari it opens Safari's Extensions settings. While the sheet is open the state is re-read
  every 2 s and a row flips to a green **"Connected"** with "Ready to fill".
- **Footer.** "More setup options…" (dismisses and opens Browser extension in the main window),
  and **Later** (Esc) — **Done** once every row is connected. Dismissing persists the checked
  browsers as silenced and snoozes the rest for 7 days.
- **Persistence** (`AppDefaults`): `browserPrompt.silenced` (array of ids such as `googlechrome`,
  `safari`) and `browserPrompt.snoozedUntil` (`[id: seconds since 1970]`).
- **Settings › AutoFill › Browsers on this Mac** lists each installed browser with a
  Connected / Not connected badge and, when not connected, an **"Ask to connect"** checkbox
  (unchecked = silenced). **Reset "Don't Ask Again"** clears every silence and snooze.

## 7. Quick Access

> **Built in M5** (moved from M4 during M4's implementation: Quick Access is item-list UI and
> shares nothing with the approval flow, so it belongs next to the generator sheet).

A floating, always-on-top panel (not the main window), opened by a global shortcut
(`⇧⌘Space`, matching 1Password 8's default Quick Access binding — see
<https://1password.com/features/how-to-use-quick-access-in-1password-8>) or from the menu-bar
icon. Contents: a search field (autofocused) and a live-filtered flat list across all vaults,
each row offering copy actions identical to §3's hover actions, without opening the main window.
Requires the vault to already be unlocked — Quick Access does not unlock the vault; if the vault
is locked, it shows a "Vault is locked" state with a button that opens the main window's unlock
card. Once unlocked, copying a **secret** from it asks for presence
([ADR-0038](decisions/0038-app-release-needs-presence.md)): `⏎` and `⌥⏎` each raise one
LocalAuthentication prompt ("copy the password “password” of “GitHub” from Quick Access. Continue
only if you just asked Kagisecure to copy it") and copy only on a confirmed touch; a cancelled one
says "Not confirmed — nothing copied" and leaves the panel open. `⌘⏎` copies the username, which is
public, and asks nothing — a real username field only; an item without one copies nothing rather
than its subtitle.

"The password" is the item's **primary secret**: the field the vault designates by id
(vault-format §5, `primary_secret`) — the same one ⇧⌘C copies, ⌘R reveals when nothing is focused,
a browser fill writes and the prompt calls "the password". Never "the field labelled password" or
"the first concealed field": labels and field order can be changed in the edit sheet without a
presence check. The prompt names what a field **is** before what it is called — "the password
“…”", "the card number “…”", "the one-time password setup “…”" or, for any other secret, "the
concealed field “…”" — so a PIN relabelled "password" is still announced as a concealed field.

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
  arbitrary where the generator is a uniform draw, and some services do accept longer.)* Beside
  the slider, a number field and a stepper bound to the same length: the field takes an exact
  value from the keyboard (a slider cannot be reached from the keyboard without Full Keyboard
  Access, §13), the stepper nudges it by one, and a number typed outside 8–128 is taken as the
  nearer bound. Words mode has the field and stepper alone — seven values do not need a slider.
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

Reopened over a field that is already set up, the sheet starts blank (§4.3) and offers **Show
current setup**, which asks for presence for that one seed and fills the URI field with it
([ADR-0038](decisions/0038-app-release-needs-presence.md)).

## 10. Approval dialog for MCP requests

The kagisecure-specific centerpiece, implementing the flow in mcp-server.md §4 and ADR-0004's
"common rules." Rendered by the native app, in its own window, never by the agent's UI.

> **M6.** The same sheet, on the same queue, also answers **browser autofill**. §10.5 records what
> is different about that variant; everything in §10.1–§10.3 applies to it unchanged. §10.6 is the
> one case where a fill is asked **without** the sheet — the Touch ID prompt alone — and never
> without the Touch ID prompt ([ADR-0037](decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
> §10.7 is a fill an **agent** asks for: a sheet of its own on the same queue, and never the
> presence prompt alone ([ADR-0036](decisions/0036-agent-requested-browser-fill.md)).

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
| TTL / uses | The requested lease TTL (default 15 min) and use count, shown as an editable control — the user may shorten TTL but not lengthen it beyond the tool's max (mcp-server.md §5). *(As built: a slider plus a minutes field and stepper bound to the same TTL, from one minute up to what the caller asked for; a number typed outside that is taken as the nearer bound. It sits in the sheet's fixed footer, directly above the buttons — never in the scrolling part — because it is "Allow for this session"'s argument and must be on screen whenever that button is.)* |
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

Referenced from §2.2. Every pane below, and Browser extension's, is shown two-column — sidebar
and pane, no item list (§2.1) — so it gets about 800 pt in the minimum window. Each still fits the
three-column detail width of about 460 pt, and must keep doing so. Two lists:

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
- **Settings › Security & Unlock › Confirmation** (2026-10-03, ADR-0037 amendment) — "Don't ask again for":
  10 minutes / 30 minutes / 1 hour / Until locked (default; `presenceGraceDuration`), and the toggle
  "Always show the sheet for agent fills" (`agentFillRequiresSheet`, off). One successful check opens
  an app-wide window that every use extends and every lock ends.
- **Browser fills** (M6) — a second table under the same heading, because a fill lease is a
  different thing: scoped to an origin and one item, no use counter, and what it grants is "no
  second sheet" — every fill still asks for Touch ID (§10.6) — rather than "an injection may
  happen". Columns: website, item, browser, remaining TTL (live), Revoke. "Revoke all" empties both
  tables, and the next browser fill shows the full sheet again.
- **Agent fills** ([ADR-0036](decisions/0036-agent-requested-browser-fill.md) §2, §9) — a section of
  the Environments pane, between its header and the environment list (`AgentFillSection`). Since
  2026-10-03 the switch is on by default, flipping it asks nothing, and the explanation says fills
  go through without asking during the grace period and may target background tabs:

  ```text
    Agent fills                              Let agents ask to fill logins in your browser  [ ○ ]
    An agent can ask kagisecure to type a saved login into the browser tab in front, and each fill
    waits for you to approve it with Touch ID or your login password. kagisecure never gives the
    agent a value — but an agent that can run script in that page can read what was typed there.

    Blocked agents
    ✋ “example-agent”                                                                [ Unblock ]
       Started by /usr/local/bin/example-client
       You chose Deny and block · until 14:32
    ✋ “other-agent”                                                                  [ Unblock ]
       Started by /opt/tools/bin/agent-runner
       Asked twice for a site not saved for the login · until you unblock it

    Recent notices                                                                        Clear
    14:02  Agent fill refused: not a saved site
           “example-agent” asked to fill “Example (work)” on examp1e.com, which is not a site
           saved for it. Nothing was filled.
  ```

  - **The switch** *(as originally built; since 2026-10-03 it is on by default and flipping it asks
    nothing — see the Settings note above)* is off by default, stored in the app's defaults and pushed to Rust's in-memory
    flag (`agentFillSetEnabled`) at launch and again on every unlock, before the agent listener
    starts. Turning it **on** asks for Touch ID or the login password through the app's one
    presence slot (`PresenceCoordinator`); cancelled, impossible, or refused because another prompt
    is up, it stays off and says why in red (`ks.agentAccess.agentFill.switchProblem`). Turning it
    **off** asks nothing. Turning it on is also when the app asks macOS for permission to post
    notifications — never at launch. The switch is a convenience, not a boundary: every fill still
    has its own sheet (§10.7) and its own check.
  - **Blocked agents** lists `agentFillBlocks()`: the agent's reported name in quotation marks (the
    agent said so; nothing checked it), the program the block is keyed on (the sidecar's
    kernel-resolved parent — every client under the same program shares the block), why, and
    *"until HH:MM"* for a Deny-and-block or *"until you unblock it"* for a second origin mismatch.
    **Unblock** calls `agentFillUnblock(key:)` and re-reads the list; it lifts the block and nothing
    else — a denial given in the last ten minutes still stands (ADR-0036 decision 32). Blocks
    survive a lock. Shown only when there is one.
  - **Recent notices** — what happened without a sheet: an origin mismatch (§9.4), an agent over
    its budget (§9.1), an agent blocked by its second mismatch, or the tripwire firing after a
    filled password was made visible on the page (ADR-0036 §8.3, `AgentFillNoticeView.unmasked`) —
    *"Filled password was revealed"* / *"'example-agent' filled a password from 'Example (work)'
    on login.example.com and the page made it visible within seconds; kagisecure cleared the
    field. The agent may have read it."* The fill already happened by the time this notice is
    shown; nothing about it can be undone, only known. Drained from `agentFillTakeNotices()` on the
    app's one-second tick; the newest five are kept, in memory only, and emptied when the vault
    locks (they name items) or by **Clear** — the audit log keeps every one. Each drain that brings
    a notice badges the menu-bar icon (§6.3), bounces the Dock icon once
    (`NSApp.requestUserAttention(.informationalRequest)`), and posts one system notification per
    notice **only if** the user allowed notifications, with the same title and sentence. The badge
    clears when this section is on screen in the active app. Every string is metadata — the
    agent's reported name, the item's title, the origin in its host-first rendering with any
    `xn--` host's Unicode form beside it — never a value.

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
  five minutes by default, fifteen at most — that skips **this sheet** for the same item, fields
  and website, and never the biometric: every later fill it covers is asked as §10.6's presence
  prompt. The caption under the control says exactly that: *"“Allow for this session” lets this
  item fill on this website for that long without showing this sheet again. A fill asks for Touch
  ID or your login password unless you confirmed recently, and locking the vault ends both."*
  While the app-wide presence grace window
  ([ADR-0037's amendment of 2026-10-03](decisions/0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-10-03-app-wide-sliding-grace-window))
  covers the request, a caption above the buttons says Allow will not ask again. "Allow once" mints no
  lease at all.
- **The header line** says *"The value goes to the browser only if you allow it, and only for this
  page"* rather than *"No secret value is shown to the caller either way"*, because on this channel
  the second sentence would be false.
- **Returning focus.** Allow hands activation back to the browser (`request.browserPid`) before the
  grant reaches Rust, the same way §10.7's sheet does — this app raised itself in front of the
  browser to be read, and a fill needs the tab visible again to land.
- **Audit** — every recorded call, newest first, filterable by outcome, by actor (agent / app /
  CLI) and by a text query over tool, variable names, path and detail, with the hash chain's
  verdict in the footer. Denials are shown by default and are the point: a burst of them is the
  only evidence a user gets that something tried an exfiltration (mcp-server.md §6).
- **Set up your agent** — the sidecar's absolute path for this install and the copy-ready snippet
  for each of the four clients (mcp-server.md §9), rendered from the same table
  `kagisecure mcp install --print` reads.

### 10.6 The presence prompt: a fill already reviewed this session

A browser fill whose exact origin, item and field set the user reviewed at a §10.5 sheet earlier in
this unlock session — and allowed for the session — arrives marked `presenceOnly`. It gets **no
sheet**. The app raises the system's LocalAuthentication prompt directly
(`.deviceOwnerAuthentication`: Touch ID, the login password, or an Apple Watch), with a reason
that names the item and the site and tells the user when to refuse:

> *Kagisecure is trying to fill “Example account” into https://example.com. Continue only if you
> just asked Kagisecure to fill this*

A one-time code says *"the one-time code for “Example account”"*, because it is its own prompt.

- **Success** answers **Allow once**. A presence confirmation never mints or extends a lease; Rust
  enforces this whatever the app sends.
- **Cancel, or no way to authenticate**, is a **denial**, answered at once. Unlike §10.3 there is
  no sheet to return to, and a prompt left open is one an automation agent could wait out; the
  user's cost is one more click in the page.
- **One prompt at a time.** A second presence-only fill waits behind the first; a sheet request
  waits behind both. This holds across a lock: locking dismisses the prompt that is up and denies
  its request, and a fill that arrives after a quick unlock waits until the old prompt has actually
  gone. A touch that lands after the lock grants nothing.
- **Never for a frame.** A fill from a sub-frame, or from a page whose top frame the browser did not
  establish, gets the full §10.5 sheet even under a lease, because the frame warning is what that
  sheet is for.
- **A fresh `LAContext` every time**, and `touchIDAuthenticationAllowableReuseDuration` is never
  set, so one touch never pays for the next fill.

Why the prompt cannot be skipped, even though the user clicked in the page: the content script's
`isTrusted` check proves only that page script did not dispatch the click. DevTools-protocol input
— what a browser-automation agent sends — and OS-injected input are trusted too. The Browser
extension screen tells a user on a Mac with no Touch ID that every fill will ask for the login
password, and suggests an Apple Watch (`ks.browserExtension.noBiometrics`).

### 10.7 The agent-fill sheet: an agent asks for a login to be typed into the tab in front

[ADR-0036](decisions/0036-agent-requested-browser-fill.md) §5 and §9.2. An agent called
`request_fill` (mcp-server.md §2.10); the browser reported the tab in front, and the origin rule
already refused anything the item is not saved for — a look-alike never reaches this sheet. What
is left for a person to decide is whether *this* agent may sign in to *this* site with *this*
login, now. Same queue and 60-second countdown as §10.1–§10.3; its own layout
(`AgentFillSheetView`):

```text
  An agent asks to sign in to  login.example.com  with “Example (work)”
  kagisecure never gives the agent a value. It types the value into a page the agent is driving,
  on a site saved for that login, after you approve — and an agent that can run script in that
  page can read it there.
  ─────────────────────────────────────────────────────────────────────────────────────────────
  Agent        “example-agent” — reports itself; the name is unverified.
               ⚠ Started by: unverified — example-client, ad-hoc signed — not attributable
               Started by  /usr/local/bin/example-client  ·  pid 51200
               Via         …/Contents/Helpers/kagisecure-mcp  ·  pid 51234
  Browser      Typed into <the browser the app established>.
               (the §10.5 pair: browser verdict, helper verdict, pinned extension id, processes)
  Where        The tab in front, top of the page — not a frame
  Site         https://  login. example.com          (registrable domain bold and underlined)
  Saved as     https://example.com   ↳ This page is a subdomain of it.
  Item         Example (work)
  Fill         username, password
  ─────────────────────────────────────────────────────────────────────────────────────────────
  ▓▓▓▓▓▓▓▓▓░  56 s to answer, then the agent is told nobody replied.
                                              Read the site first — “Fill on…” turns on in a moment.
     [ Deny ]  [ Deny and block this agent for 30 minutes ]  [ Fill on example.com… ]
```

- **The sentence leads with the site**, not the agent: the site is what the person has to check,
  and the agent's name is what an attacker would choose. The host is the ASCII form the origin
  rule compared, with the registrable domain in bold and every label before it dimmed; a
  non-default port is part of it. The agent's name is not in the sentence at all.
- **§8.2's sentence, verbatim**, where the other sheets say what is not shown to the caller —
  because on this path an agent that can run script in the page *can* read the value there, and
  approving is done knowing that.
- **Two variants, for the two other shapes a request can take** (ADR-0036 §7.3, §7.4):
  - **An identifier-first, two-page sign-in** (`AgentFillFactsView.twoStep`) keeps the same
    headline, and adds a line under it and §8.2's sentence: *"The username is filled now. The
    password follows on the next page of the same site, without asking you again. This approval
    is good for up to 60 seconds."* The Fill row says the same thing in its own words:
    *"username now, password on the next page of this site — without asking again, within 60
    seconds"*. One sheet, one biometric, for both pages.
  - **A one-time code** (`fields == [.oneTimeCode]`) changes the headline itself, because "sign
    in" would misstate what a second factor is: *"An agent asks to fill the one-time code for
    'Example (work)' on login.example.com"*. The Fill row says *"a one-time code — not the
    password"*. The Allow button is unchanged — *"Fill on example.com…"* — since it still names
    the site, not the field.
  - The Touch ID prompt behind the button (§5) names the same distinction in its own sentence —
    a plain sign-in, "the password on the next page without asking again", or "the one-time code"
    — always the site and the item, never the agent's name.
- **Two identity stories.** The *agent*: its self-reported name in quotation marks and called
  unverified; the program the kernel says started our sidecar ("Started by"), with its executable,
  pid and signature verdict — *verified* only for a valid signature carrying a developer team,
  since an agent can be any program and there is no list to compare it against; and the sidecar
  itself ("Via"). The *browser*: exactly the §10.5 pair, the same view (`BrowserIdentityBlock`).
  The verdict recorded with the decision is all of them together, so the audit entry never says
  "verified" because only the browser was.
- **The look-alike rendering** (ADR-0036 §5), below the site: *"Underlined: the registrable
  domain"*; *"Port 8443 — not the usual one for https."* whenever there is a port; a red *"Not
  encrypted"* callout for `http`; the Unicode rendering of any `xn--` label as a *"Shown by the
  browser as"* row beside — never instead of — the ASCII one; and a red warning whenever the name
  mixes writing systems or has a label that does not decode.
- **Saved as** is the website on the item that matched, with *"This page is a subdomain of it."*
  in orange whenever the page's host is not byte-equal to it.
- **Buttons: Deny, "Deny and block this agent for 30 minutes", then "Fill on *registrable
  domain*…".** No "Allow for this session" — an agent fill mints no lease (ADR-0036 §6). The Allow
  label names what it approves. **No default button: Return and keypad Enter do nothing; Esc
  denies** — a plain Deny, never the block (`AgentFillSheetKeys`).
- **Deny and block** (ADR-0036 §9.3) answers `ApprovalDecision.denyAndBlock` through
  `AgentService.denyAndBlock`: a denial now, and every `request_fill` from that agent answered
  `USER_DENIED` without a sheet for thirty minutes. Saying no needs no biometric. The block is keyed
  on the program the kernel says started the agent's sidecar — the "Started by" row — never on
  the reported name, and it survives a lock; it is listed, with an Unblock button, in Agent access
  (§10.4).
- **The Allow hold** (zero since the ADR-0036 amendment of 2026-10-03; it was 1.5 seconds). "Fill on …" is disabled for the first 1.5 seconds the sheet's window is
  key and visible, and the hold restarts from zero whenever the window loses key or is covered and
  then comes back (`AllowDelay`, driven by the window's own key and occlusion notifications). A
  caption says it is coming. It stops a click already in flight; it does nothing against an agent
  that synthesizes a click and waits, which is what the next point is for.
- **No sheet at all inside the grace window** (ADR-0036 amendment of 2026-10-03): an agent fill is
  granted at once unless Settings › Security & Unlock › Advanced (or AI Agents) › "Always show the sheet for agent fills" is on.
- **Allow is Touch ID (or the login password)**, outside the app-wide presence grace window
  (ADR-0037's amendment of 2026-10-03; the sheet says when it is open), through `AgentService.allow` →
  `PresenceCoordinator`, one prompt app-wide, and is sent to Rust as **Allow once** whatever the
  sheet was handed. A cancelled or impossible check grants nothing and denies nothing: the sheet
  stays up, as in §10.3, with the reason in red. A lock while the prompt is up means a touch that
  lands afterwards grants nothing.
- **Returning focus.** The sheet raises this app in front of whatever the person was looking at —
  usually the agent's own window, a terminal, not the browser — and Fill would otherwise leave it
  there: macOS reports an occluded tab's document as not visible, and delivery needs it visible.
  So the moment Fill is granted, before the grant reaches Rust, `AgentService` hands activation to
  the browser named on the sheet (`request.browserPid`), falling back to whatever was frontmost
  when the request arrived, and to hiding this app, in that order. Denying returns nothing — only
  a grant needs the tab back.
- **Never the presence prompt alone.** An agent fill is always this sheet, even if it ever arrived
  marked `presenceOnly` (Rust never sets it for one): the §10.6 shortcut exists for a human who
  already reviewed the same fill, and nobody has reviewed an agent's.
- **Nothing reaches this sheet while the feature is off.** The switch in Agent access (§10.4) is
  off by default, and off, every `request_fill` is answered `FILL_UNAVAILABLE` before an item is
  looked up. The Browser extension screen says that Safari does not support agent fills yet
  (`ks.browserExtension.safari.noAgentFill`, ADR-0036 §12).

### 10.8 Unattended jobs: arming, jobs and standing grants *(built on macOS, ADR-0042 Phases 3 to 5 — [ADR-0042](decisions/0042-unattended-agent-access.md))*

**As built** (ADR-0042 implementation decisions 23–31): Agent access gains **Unattended jobs**
(`ks.sidebar.agentUnattended`). At the top, whether jobs are armed ("Armed since …" or "paused")
with **Arm…** (a sheet saying what arming means, then Touch ID) or **Pause** (nothing asked). Then
the jobs — name, schedule in words, the program line, and the grant: what it may run, with which
variables from which environment, uses, per-run limit, expiry, a suspension in words with
**Re-enable…**, and **Run Now** and **Revoke**. Then **Environments jobs may use**: copies of
personal environments, each with **Update** (copy again; re-approves the grants over it) and
**Remove**, and **Add an Environment…** listing the personal environments. **New Job…** is one
sheet: name, program, arguments (one per line), folder, when (every day or one weekday, and a time),
environment, whether it may run its own program with it or another command, and expiry; it shows
ADR-0042's sentence, "Not pinned: anything else this command reads", and the interpreter box, and
**Create** asks for Touch ID. The menu bar shows "Unattended jobs armed", a count of events to
review, and **Pause Unattended Jobs**, locked or not. After an unlock, **While you were away**
lists the machine log since the last look, with counts; **Done** acknowledges it. The Audit view
has a **Personal vault / Machine vault** switch and an **Unattended** caller filter.
Since Phase 4: **Add an Environment…** also lists each open shared vault's environments (one bound
to a login's field is shown disabled, "a login: never copied"); a copy whose source changed shows
"Changed at its source since it was copied — Update to copy it again"; **Unattended copies of
shared vaults** shows, per open shared vault, whether copies are allowed (a checkbox for its admins)
and which devices hold one, a removed device's in orange; and the banner has an **Open Kagisecure
at login** checkbox, turned on by the first arm.
Since Phase 5 (implementation decisions 48 and 49): **Logins jobs may sign in with** lists the
machine vault's logins — title, username, exact https origins — each with **Update**, and **Add a
Login…** lists the personal logins; copying one asks for Touch ID. **New Job…** takes an
environment, a login, or both: with a login, **Signs in with**, **At** (one of its origins),
**In its own browser** (Microsoft Edge by default) and **Also fill one-time codes** (off; disabled
for a login with no seed; turning it on shows §12.5's box). The sheet shows ADR-0042's login
sentence and "The job's agent can read this password. Use an account that can do only what this
job needs, and that you can reset." A job's row lists its login grant — the account, the origin,
sign-ins used, per run, expiry, and a suspension with **Re-enable…**.

As designed:

- **Arm sheet.** "Arm unattended jobs" with a presence proof. Arming has no expiry and survives
  restarts (the key is kept in the Keychain); the sheet says so, and that a stolen or restarted
  Mac keeps releasing machine credentials to kagisecure-started jobs until the owner pauses them.
- **Job sheet and command-grant sheet.** Every bound fact — job, schedule, executable and its pin,
  arguments, directory, variables, pinned inputs, limits, expiry — with the two sentences ADR-0042
  §5 makes mandatory ("Not pinned: anything else this command reads."; the interpreter warning),
  then a presence proof. Changing a grant is creating a new one.
- **Login-grant sheet.** ADR-0042 §12.2's facts and its sentence that the job's agent can read the
  password; the one-time-code switch, off by default, with its own warning box.
- **Agent access (§10.4)** gains an Unattended section: jobs, grants with Revoke, suspensions with
  their reason, and Pause.
- **Menu bar (§6.3)** shows "unattended jobs armed" and a badge counting unattended releases,
  refusals and suspensions since the last summary; the first unlock after unattended activity
  shows "While you were away".

### 10.9 System-wide AutoFill *(built, [ADR-0045](decisions/0045-system-wide-autofill-credential-provider.md))*

**Setup.** The person enables **Kagisecure** under System Settings › General › AutoFill &
Passwords (only offered for a build signed with the AutoFill provisioning profile — ADR-0045
"Owner steps"). Enabling it shows the extension's configuration sheet: one sentence saying one
Touch ID fills everywhere until the vault locks, and **Done**.

**QuickType.** Native apps' login fields suggest the vault's logins (host and username, published
on unlock and kept across locks). Inside the grace window picking one fills at once, with no
prompt; outside it, the AutoFill sheet appears and the app asks once (Touch ID or the login
password), which opens the window.

**The sheet** (`prepareCredentialList`): a search field ("Search logins"), a list — title, then
username · first website — with logins for the requested site first, **Cancel**, and **Fill**
(⏎, or a double-click). While the app asks: "Confirm in Kagisecure…". Locked or not running:
"Kagisecure is locked or not running. Unlock it, then click Try Again.", the app comes forward, and
**Try Again** appears. A one-time-code request shows only logins with a code.

**Settings › Security & Unlock › Confirmation:** "Always show the AutoFill sheet in other apps"
(`ks.settings.nativeAutofillRequiresConfirmation`, `nativeAutofillRequiresConfirmation`, off).

## 11. Keyboard shortcuts

| Shortcut | Action | Source |
| --- | --- | --- |
| ⌘F | Focus search | 1Password 8 |
| ⇧⌘Space | Open Quick Access (§7) | 1Password 8 |
| ⌘N | New item | 1Password 8 |
| ⌘E | Edit selected item | 1Password 8 |
| ⌘S | Save changes | 1Password 8 |
| Esc | Cancel edit / dismiss sheet | 1Password 8 |
| ⌘R | Reveal/conceal the focused concealed field — or, with none focused, the item's password (its primary secret, §7), or failing that its one-time password, whose code is started or stopped the same way. Revealing asks for presence (ADR-0038) | 1Password 8 |
| ⇧⌥⌘C | Copy username — a real username (or email) field; nothing when the item has none, never the subtitle. **Deliberately not 1Password 8's ⌘C**: a menu item bound to plain ⌘C takes the shortcut away from Edit ▸ Copy, so ⌘C in the search field, the edit sheet or a selected public value would copy the username instead of the selection | kagisecure-specific (1Password 8 uses ⌘C) |
| ⇧⌘C | Copy password — the item's primary secret (§7: designated by field id, not by label or position; ignores what is focused, unlike ⌘R). Asks for presence unless that value is already shown (ADR-0038) | 1Password 8 |
| ⌥⌘C | Copy current TOTP code — asks for presence unless the code is already running (ADR-0038) | 1Password 8 |
| ⇧⌘G | Open the password generator (§8) | kagisecure-specific |
| ⌘R (in the generator sheet) | Regenerate | 1Password 8 |
| ⏎ / ⌘⏎ / ⌥⏎ (in Quick Access) | Copy password / username / one-time code — ⏎ and ⌥⏎ ask for presence once each (ADR-0038) | 1Password 8 |
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

- Full VoiceOver labeling: a concealed field announces what it is and what revealing it will ask
  for — "Password, concealed. Reveal asks for Touch ID or your Mac password." — rather than
  reading dots, and never its length; a masked one-time code and masked notes do the same with
  "Show". Showing and hiding a value are announced ("Password shown", "Password hidden", "…hidden
  after five minutes"), and so is a copy, with the clipboard's clear policy. The app never
  inspects *how* an action was triggered — pointer, keyboard, VoiceOver or anything else — because
  the input source is not evidence of a person; the presence prompt is
  ([ADR-0038](decisions/0038-app-release-needs-presence.md)). A running one-time code is spoken in
  full once shown, which is necessary for a VoiceOver user to use it at all (threat model W-19);
  the TOTP countdown ring exposes its remaining-seconds value as an accessibility value, not only
  a visual animation.
- Dynamic Type respected throughout; the three-pane layout collapses to a navigable stack
  (sidebar → list → detail) under Dynamic Type XL and above or narrow windows, rather than
  truncating.
- Full keyboard navigation: every action reachable via mouse (including the approval dialog's
  buttons and the reveal/copy hover actions in §3/§4) has a keyboard path; hover-only affordances
  are never the sole way to reach an action. That includes values set with a slider or a stepper:
  without Full Keyboard Access neither takes key focus on macOS, so each is paired with a number
  field bound to the same value (the generator's length and word count, §8; the approval sheet's
  TTL, §10.2). A number typed there is applied as it is typed, so a button pressed straight
  afterwards — "Use this password", "Allow for this session" — acts on it.
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

- **Sharing beyond shared vaults.** The personal vault stays single-owner, single-Mac (per
  device, via the biometric-wrapped key slot in vault-format.md §3.1). Sharing is only through
  shared vaults (§16): no accounts, no server, no per-item sharing, no roles finer than a
  vault's three.
- **Watchtower-style breach/reuse monitoring.** No security-dashboard sidebar section, no
  password-health scoring UI. May be reconsidered post-v1; not designed here.
- **Sync UI for the personal vault.** No account, no "sync now" indicator, no
  conflict-resolution UI. The vault is a file; if the user syncs it with their own tool, that
  tool's UI is not kagisecure's concern. A shared vault syncs by itself through its folder, with a
  status line and a "Sync Now" button (§16.5), and has no conflict UI either: the last writer
  wins.
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
- `ks.alert.storeOk` — the store's own errors (busy, and anything a `perform`-routed environment
  or vault-sharing call hits), separate from `ks.alert.ok`'s unlock-time and Touch ID failures.
- `ks.alert.agentOk` — the Agent-access surface's own errors (today: a failed lease revoke),
  separate from the other two because `AgentService` is its own model with its own lifetime.

**The conflict alert (§6.4)**

- `ks.alert.conflict.keepAppVersion`
- `ks.alert.conflict.reopen`
- `ks.alert.overwrite.confirm` — the overwrite confirmation's destructive button
- `ks.alert.overwrite.cancel`
- `ks.alert.conflictNotice.ok` — "Nothing to overwrite"

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

- `ks.itemList.hideFromAgents`
- `ks.itemList.list`
- `ks.itemList.rowCopySubtitle`
- `ks.itemList.rowCopyTotp`
- `ks.itemList.rowFavorite`
- `ks.itemList.rowSubtitle`
- `ks.itemList.rowTitle`
- `ks.itemList.showToAgents`
- `ks.multiSelection.count`
- `ks.multiSelection.hideFromAgents`
- `ks.multiSelection.showToAgents`

**Item detail (§4)**

- `ks.item.agentVisible`
- `ks.item.archivedBadge`
- `ks.item.category`
- `ks.item.favorite`
- `ks.item.fieldAgentVisible.<label>`
- `ks.item.fieldCopy.<label>`
- `ks.item.fieldLabel.<label>`
- `ks.item.fieldReveal.<label>`
- `ks.item.fieldValue.<label>` — the masked dots, or the revealed value
- `ks.item.lastUsedByAgent`
- `ks.item.menu.archive`
- `ks.item.menu.deleteForever`
- `ks.item.menu.restore`
- `ks.item.menu.trash`
- `ks.item.noFields`
- `ks.item.notes` — masked, or the shown notes
- `ks.item.notesCopy`
- `ks.item.notesReveal`
- `ks.item.root`
- `ks.item.section.<name>`
- `ks.item.tag.<tag>`
- `ks.item.title`
- `ks.item.trashedBadge`

**Edit mode (§4.3)**

- `ks.edit.addField`
- `ks.edit.cancel`
- `ks.edit.fieldChange.<label>` — the "Change" button that swaps a masked concealed field for a
  text field to type a new value into (§4.3's no-prefill rule)
- `ks.edit.fieldConcealed.<label>`
- `ks.edit.fieldGenerate.<label>`
- `ks.edit.fieldLabel.<label>`
- `ks.edit.fieldRemove.<label>`
- `ks.edit.fieldReveal.<label>` — "Show" on a masked concealed field: one presence-gated release
  (ADR-0038)
- `ks.edit.fieldTotpSetup.<label>`
- `ks.edit.fieldValue.<label>`
- `ks.edit.notes`
- `ks.edit.notesRemove`
- `ks.edit.notesReplace`
- `ks.edit.notesReveal`
- `ks.edit.save`
- `ks.edit.tags`
- `ks.edit.title`
- `ks.edit.urls`

**The changed-elsewhere alert (§4.3)**

- `ks.alert.itemChangedElsewhere.reload`

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
- `ks.generator.length` — the slider
- `ks.generator.lengthField`
- `ks.generator.lengthStepper`
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
- `ks.generator.wordsField`
- `ks.generator.wordsStepper`

**One-time password field (§4.2)**

- `ks.totp.caption`
- `ks.totp.code` — only while the code is running
- `ks.totp.copy`
- `ks.totp.field`
- `ks.totp.hide`
- `ks.totp.masked` — before the touch
- `ks.totp.ring`
- `ks.totp.show`

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
- `ks.totpSetup.showCurrent`
- `ks.totpSetup.uri`

**Master-password fallback panel (§4.2, ADR-0038)**

- `ks.masterPassword.cancel`
- `ks.masterPassword.confirm`
- `ks.masterPassword.field`
- `ks.masterPassword.message`
- `ks.masterPassword.reason`
- `ks.masterPassword.title`

**Quick Access (§7)**

- `ks.quickAccess.awaitingPresence`
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

**Settings (§17)**

- `ks.settings.advanced`
- `ks.settings.agentFillRequiresSheet`
- `ks.settings.agentFillSwitch`
- `ks.settings.agentListenerState`
- `ks.browserPrompt`, `ks.browserPrompt.title`, `ks.browserPrompt.later`, `ks.browserPrompt.done`, `ks.browserPrompt.moreOptions`
- `ks.browserPrompt.connect.<id>`, `ks.browserPrompt.connected.<id>`, `ks.browserPrompt.dontAsk.<id>`
- `ks.settings.browserRow.<id>`, `ks.settings.browserPrompt.ask.<id>`, `ks.settings.browserPrompt.reset`
- `ks.settings.auditState`
- `ks.settings.browserExtensionState`
- `ks.settings.graceDuration`
- `ks.settings.nativeAutofillRequiresConfirmation`
- `ks.settings.nativeAutofillState`
- `ks.settings.openAutoFillSettings`
- `ks.settings.pane.<general|security|autofill|agents|vault|updates|about>`
- `ks.settings.version`
- `ks.settings.autoLockInterval`
- `ks.settings.clipboardInterval`
- `ks.settings.newItemsAgentVisible`
- `ks.settings.quickAccessError`
- `ks.settings.quickAccessShortcut`
- `ks.settings.showAllResult`
- `ks.settings.showAllToAgents`
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

**Agent access — Agent fills (§10.4, ADR-0036)**

Rows in the blocks list share one identifier per column, as the lease tables do: a block's key is
a path, and a test tells rows apart by the name and program they read.

- `ks.agentAccess.agentFill.blockAgent` — the reported name, quoted
- `ks.agentAccess.agentFill.blockProgram` — "Started by …", the key
- `ks.agentAccess.agentFill.blockReason` — why, and until when
- `ks.agentAccess.agentFill.blocksHeading`
- `ks.agentAccess.agentFill.clearNotices`
- `ks.agentAccess.agentFill.explanation`
- `ks.agentAccess.agentFill.heading`
- `ks.agentAccess.agentFill.notice` — one per recent notice, title and sentence combined
- `ks.agentAccess.agentFill.noticesHeading`
- `ks.agentAccess.agentFill.switch`
- `ks.agentAccess.agentFill.switching` — the spinner while the presence check for "on" is up
- `ks.agentAccess.agentFill.switchProblem`
- `ks.agentAccess.agentFill.unblock`

**Agent access — the new-environment sheet (§10.4)**

- `ks.newEnvironment.cancel`
- `ks.newEnvironment.create`
- `ks.newEnvironment.name`

**Agent access — the environment editor (§10.4, §16.7)**

Shared with a shared vault's own environments pane; `ks.environment.renameButton` (its alert has
no identifiers of its own, matching the shared vault's own rename alert, §16.4) and the Bind
picker on `ks.environment.addVariable` appear there and nowhere in the personal vault's editor,
which has no rename affordance and adds only literals.

- `ks.environment.addVariable`
- `ks.environment.addVariableMode` — the Literal/Bind segmented control (shared vaults only)
- `ks.environment.bindField` — the Bind picker's field choice (shared vaults only)
- `ks.environment.bindItem` — the Bind picker's item choice (shared vaults only)
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
- `ks.environment.renameButton` — the pencil beside the name (shared vaults only)
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
- `ks.audit.saveState` — shown only when audit entries are not yet saved to disk
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
- `ks.browserExtension.noBiometrics`
- `ks.browserExtension.removeManifest.<browser>`
- `ks.browserExtension.safari.appGroup`
- `ks.browserExtension.safari.bundleId`
- `ks.browserExtension.safari.noAgentFill`
- `ks.browserExtension.safari.socketPath`
- `ks.browserExtension.safariStatus`
- `ks.browserExtension.status`
- `ks.browserExtension.title`
- `ks.browserExtension.warning`
- `ks.browserExtension.warning.hostPath`
- `ks.browserExtension.warning.manifest`
- `ks.browserExtension.warning.safari`

**Approval dialog (§10)**

- `ks.approval.agentFill.allow` — "Fill on *registrable domain*…" (§10.7)
- `ks.approval.agentFill.allowDelay` — the caption shown while the 1.5-second hold is on
- `ks.approval.agentFill.browser`
- `ks.approval.agentFill.denyAndBlock` — "Deny and block this agent for 30 minutes" (§10.7)
- `ks.approval.agentFill.fields`
- `ks.approval.agentFill.item`
- `ks.approval.agentFill.missingFacts`
- `ks.approval.agentFill.mixedScript`
- `ks.approval.agentFill.notEncrypted`
- `ks.approval.agentFill.port`
- `ks.approval.agentFill.reportedName`
- `ks.approval.agentFill.savedAs`
- `ks.approval.agentFill.sidecar`
- `ks.approval.agentFill.site`
- `ks.approval.agentFill.startedBy`
- `ks.approval.agentFill.subdomain`
- `ks.approval.agentFill.unicodeHost`
- `ks.approval.agentFill.verdict.sidecar`
- `ks.approval.agentFill.verdict.startedBy`
- `ks.approval.agentFill.where`
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
- `ks.approval.ttlMinutesField`
- `ks.approval.ttlMinutesStepper`
- `ks.approval.ttlSlider`
- `ks.approval.ttlValue`
- `ks.approval.variable.<name>`
- `ks.approval.variables`
- `ks.approval.variablesNote`
- `ks.approval.verdict`
- `ks.approval.verdict.browser`
- `ks.approval.verdict.helper`

**Menu-bar status item (§6.3)**

Only `ks.menuBar.icon` reaches the accessibility tree; its title is the lock state in words. The
rest are set in `MenuBarPanel` and dropped by the menu-style `MenuBarExtra`, which builds
`NSMenuItem`s carrying each entry's title and enabled state and not its identifier; the UI-test
suite finds those entries by title, under the status item ([e2e-harness.md](e2e-harness.md) §7.2).

- `ks.menuBar.agentFillNotices` — "N agent-fill notice(s) — review", while any is unseen
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


**Shared vaults (§16)**

- `ks.sidebar.shared.<vault id>` — a shared vault's items row
- `ks.sidebar.sharedEnvironments.<vault id>` — its Environments row
- `ks.sidebar.sharedMembers.<vault id>` — its Members row
- `ks.sidebar.shared.add` — the section's "+" menu
- `ks.sidebar.shared.new`
- `ks.sidebar.shared.join`
- `ks.shared.chooseFolder` — "Choose…" beside a folder in the create and join sheets
- `ks.shared.create.name`
- `ks.shared.create.confirm`
- `ks.shared.error` — a sheet's error line
- `ks.shared.join.chooseFile`
- `ks.shared.join.passphrase`
- `ks.shared.join.confirm`
- `ks.shared.invite.name`
- `ks.shared.invite.role`
- `ks.shared.invite.save`
- `ks.shared.invite.passphrase`
- `ks.shared.invite.copy`
- `ks.shared.invite.done`
- `ks.shared.members.root`
- `ks.shared.members.title`
- `ks.shared.members.rename`
- `ks.shared.members.invite`
- `ks.shared.members.folder`
- `ks.shared.members.chooseFolder`
- `ks.shared.members.syncNow`
- `ks.shared.members.syncProblem`
- `ks.shared.members.rebuild`
- `ks.shared.members.exposures`
- `ks.shared.member.name`
- `ks.shared.member.role`
- `ks.shared.member.menu`
- `ks.item.menu.sharedDelete`
- `ks.item.sharedDelete.confirm`

**Shared vaults — Environments (§16.7)**

- `ks.sharedEnvironments.new`
- `ks.sharedEnvironments.newName`
- `ks.sharedEnvironments.newCancel`
- `ks.sharedEnvironments.newCreate`
- `ks.sharedEnvironments.empty`
- `ks.sharedEnvironments.list`
- `ks.sharedEnvironments.row.<environment>`
- `ks.sharedEnvironments.delete` — a row's context-menu "Delete…"

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

## 16. Shared vaults

A shared vault ([ADR-0035](decisions/0035-shared-vaults.md)) is a set of items several people's
Macs hold copies of, synced through a folder they all can open — in iCloud Drive or Dropbox, for
example. The app's part is ADR-0035's Phase 5, built on `SharedVaultSession`
(`crates/kagisecure-ffi/src/shared.rs`), and designed for the fewest clicks: a vault is a name and
a folder, an invitation is a file and six words, and syncing needs nothing from anyone. A shared
vault also has its own environments (§16.7), the CLI's `kagisecure shared env` made a record for
before the app could show one at all.

**Status:** built; not yet tried by a person on two Macs (see
[roadmap.md](roadmap.md), M10).

### 16.1 In the sidebar

The **Shared** section sits between Tags and Agent access (§2.2). Each shared vault has three
rows: its name, with its item count, which shows its items in the usual three columns;
**Environments** under it, with the environment count, which shows that vault's environments pane
(§16.7) in two columns; and **Members**, with the member count, which shows the members pane
(§16.4) in two columns — the Agent access rows' own layout, for all three. The section header's
**+** menu has **New Shared Vault…** and **Join Shared Vault…**. A vault row's context menu has
**Invite…** (admins), **Members**, **Sync Now** and **Show Folder in Finder** (when it has a
folder).

While a shared vault is selected the window's title is its name and the status line reads
"Shared · *n* items · *m* members". A vault whose copy on this Mac does not open shows a warning
icon, and its members pane offers **Rebuild from Folder…** (§16.4).

### 16.2 New Shared Vault

A sheet with two fields and one button:

- **Name** — this Mac's name for the vault; carried to everyone invited, and renamable per Mac.
- **Folder** — **Choose…** opens a folder panel that can create a folder. Optional: without one
  the vault stays on this Mac until a folder is chosen in its members pane.

**Create** selects the new vault. This Mac is its first admin. Each vault created gets a device key
of its own in the personal vault; the first device key upgrades the personal vault file's format
and keeps a `.bak-1` copy beside it (vault-format.md §9). The app does not yet say so on screen.

### 16.3 Join Shared Vault

- **Invitation** — **Choose…** picks the file someone sent.
- **Words** — the six words they said. Case, spaces and hyphens do not matter.
- **Folder** — filled in with the invitation's own folder when that folder already holds the
  vault's records (an admin saving the invitation into the shared folder leaves it there), else
  **Choose…**.

**Join** selects the vault. Wrong words are said in the sheet ("Those words do not open this
invitation"), never as an alert. The words stretch through Argon2id, so the button shows progress
for a moment.

### 16.4 Members and invitations

The **members pane** has, top to bottom:

- **The header** — the vault's name (**Rename**, this Mac only), how many members, and this Mac's
  role ("You can view", "You can edit", "You are an admin"); **Invite…** for admins.
- **Warnings**, if any — the same ones `kagisecure shared status` prints: fewer than two admins
  left, or the roster frozen with none.
- **Sync** — the folder (or "Not syncing: no folder chosen"), **Choose Folder…**/**Change…**,
  **Sync Now**, and one status line: "Synced *time ago*", or why the last sync failed. A sync
  failure is never an alert.
- **Members** — one row each, this Mac's member first: the name, a "You" badge, how many
  computers (their fingerprints in the row's help tag), and the role — a menu (**Can view**,
  **Can edit**, **Admin**) for an admin looking at someone else. A row's **⋯** menu has
  **Rename…** (this Mac only), and for admins **Invite Another Computer…** and **Remove…**
  (confirmed; not for oneself). Removing mints a new key for everyone left, so nothing changed
  afterwards reaches the removed member.
- **Removed members could have seen** — ADR-0035's rotation list, informational only: for each
  removed member, the items they held a key to, to change at their source if that matters.

Names are this Mac's own: the name typed when inviting someone, or given with **Rename…**. Inviting
someone (the CLI's `shared invite --name`, or the app's own invite sheet) also starts *both* the
inviting Mac's and the joining Mac's own name for the new member as that same name, so it need not
be typed twice — either can still be changed with **Rename…** afterwards, on that Mac only. A
member neither Mac's person has named — a third Mac discovering them, say — falls back to a label
built from one of their computer's fingerprints, so two such members read as different people
rather than both "Unnamed member"; one's own is "You" until renamed. Roster records carry no names
while their sealing is undecided (ADR-0035 decision 81).

The **Invite sheet** asks for a **Name** and a **Role** (default **Can edit**), with one line under
the role saying what it allows. **Save Invitation…** opens a save panel in the vault's folder,
named "*name* – *vault*.kagisecure-invite", writes the file, and turns the sheet into its second
half: "Send *name* the file, and tell them these six words another way", the words large and
monospaced with a **Copy** button (the concealed, timed pasteboard of §4.2 — the words are not
selectable text), **Show File in Finder**, and **Done**. The words are shown this once and never
again. No presence check is asked for (ADR-0035 decision 86): the unlocked personal vault is
enough. **Invite Another Computer…** is the same sheet without the fields, for a member's second
Mac, at their role.

### 16.5 Sync

A shared vault with a folder syncs by itself, with nothing to press:

- when anything in the folder or its `records` folder changes — watched with a dispatch source on
  each, and debounced by 1.5 s so a sync client writing a burst of files is one sync;
- when the app becomes active;
- after each change made on this Mac (the change's own record is already in the folder; the sync
  picks up whatever arrived meanwhile).

A sync with nothing new reads no record file and writes nothing (ADR-0035 decision 87). It runs off
the main thread, since reading a file a sync client is still downloading can block. There is no
conflict UI: the last writer wins, field by field (decision 80).

### 16.6 Items in a shared vault

The item list, the detail pane and the edit sheet are the ones of §3–§4 — `VaultStore` routes
every item call to the selected vault — and revealing or copying a value asks for presence exactly
as for a personal item, recorded in the personal vault's audit log. What differs:

- **Agent access is this Mac's own.** The Agent access panel is the one of §4, with one more
  line: the switches are this Mac's setting only, kept in its copy of the vault and sent to
  nobody. Everything starts hidden (ADR-0035 Phase 4, decision 88).
- **Delete…, not Archive or Trash.** The **More** menu has **Delete…**, confirmed ("Delete *title*
  for everyone?"), which removes the item from every member's copy. There is no shared Trash.
- **Readers** see everything and can copy, but **Edit** is disabled and **New Item** answers that
  this Mac may not write to the vault.
- **No "changed elsewhere" alert.** A save always wins.
- **Favorites** are this Mac's own and travel to nobody.
- Shared items are not in Quick Access (§7) or the personal vault's sidebar counts. The browser
  extension fills shared logins as it fills personal ones, and the approval sheet (§10) for any
  release from a shared vault adds a **From** row naming the vault and, in orange, one line per
  value that changed since this Mac last approved releasing it — who changed it, and when.

### 16.7 Environments in a shared vault

A shared vault's **Environments** pane is `EnvironmentEditor` (§10.4) again, driven by
`EnvironmentEditing` so it renders and behaves the same wherever a shared vault does not have to
differ from the personal vault — the list on the left, the editor on the right, an empty state
when there are none yet. What differs, all of it the item rules of §16.6 applied to environments:

- **Create, rename, delete: writers and admins only.** A reader sees the list and every
  environment's variables but the toolbar's **New Environment**, a row's **Delete…** and the
  editor's rename pencil are absent for them; calling through anyway (there is no such path from
  this pane) answers the same refusal creating an item does. Renaming changes the name everyone
  sees — unlike a shared vault's own name (§16.4), an environment has one name, not one per Mac.
- **Variables are for everyone; a binding stays inside the vault.** Adding a variable offers a
  segmented **Literal value** / **Bind to an item** choice; bound, two pickers name one of this
  same shared vault's items and one of its fields — never another vault's, which
  `SharedVaultSession::bind_variable` refuses server-side regardless. Removing a variable and
  editing its value are writer/admin actions too, each a new version every member's copy picks up
  on its next sync.
- **Agent visibility is this device's own**, exactly as an item's (§16.6, decision 22): the
  **Share with agents** toggle is never disabled, even for a reader, and flipping it writes only
  to this device's local state — nothing syncs, and nobody else's copy of the environment changes.
  A new environment starts hidden from agents, as the personal vault's does.
- **No pending-value flow.** `add_variables`'s pending badge and paste-the-value flow (§10.4) are a
  personal-vault MCP tool's doing; a shared vault's environments have no agent-facing write path,
  so nothing here is ever pending.

### 16.8 Locking

Locking the personal vault closes every shared vault with it: their device keys and decrypted items
go (a lock hook in `kagisecure-ffi`), their folder watchers stop, and every shown value is hidden,
as for personal items.

## 17. Settings window

*(2026-10-04.)* ⌘, opens a System Settings–style window: a sidebar of panes, each a white SF
Symbol on a colored rounded square, and a grouped form per pane that starts with a large tile, the
pane's name and a one-line summary. The last pane shown is remembered (`settings.selectedPane`).
Default size 800×600, minimum 760×520; light and dark follow the system.

**Rule.** Everything a person *chooses* is here. Screens that show live state they work with —
Environments, Leases, Unattended jobs, Audit, Set up your agent, the browser-extension installer —
stay in the main window's sidebar, and the pane owning the topic links to them (a row with an
↗ icon that brings the main window forward on that screen; disabled while locked).

| Pane | Group | Contents |
|---|---|---|
| General | gray, gear | Quick Access shortcut (⇧⌘Space as key caps, or why it is unavailable); clipboard clear interval; appearance (System / Light / Dark, applied app-wide at once through `NSApp.appearance`, so the main window, Quick Access panel and sheets follow) and language (System default plus every localisation in the bundle, each named in itself; stored as the per-app `AppleLanguages` default, removed for System default; takes effect on relaunch, so a changed choice shows a "Restart Kagisecure to apply" notice with a Relaunch button that locks the vault, opens a new instance and quits). System Settings › Language & Region stays as a secondary link in the footer |
| Security & Unlock | red, Touch ID | Touch ID unlock toggle (needs an unlocked vault); "Don't ask again for" (grace, default Until locked); "Lock when idle for" (default 10 min); **Advanced** disclosure "Stricter confirmation" with an "Off"/"N on" badge holding "Always show the sheet for agent fills" and "Always show the AutoFill sheet in other apps" (both off) |
| AutoFill | blue, key | Passwords AutoFill status badge (On/Off from `ASCredentialIdentityStore.state().isEnabled`, refreshed when the app becomes active), "Ask before each fill" (same preference as the Advanced toggle), "Open AutoFill Settings…" (`x-apple.systempreferences:com.apple.Passwords-Settings.extension`); browser extension status badge (N connected / Waiting for a browser / Vault locked) and a link to the installer; **Browsers on this Mac** (per-browser status and "Ask to connect", §6.5) |
| AI Agents | purple, sparkles | MCP listener badge (Listening / N waiting / Stopped), link to Set up your agent; the agent-fill switch (same `AgentFillService.setEnabled`, Touch ID to turn on) and its strict toggle; Item visibility ("Show new items to agents", default on, and "Show All Items to Agents…"); links to Environments (blocked agents and notices), Leases, Unattended jobs, Audit log with counts |
| Vault | orange, drive | Vault file (path with ~, Show in Finder), Locked/Unlocked badge, backup note; Import from a File… (opens the main window and the import flow); audit-chain state and word list |
| Updates | green | Automatic checks, Check Now, last check, current version |
| About | indigo | Icon, version (build), links to kagisecure.com, GitHub, issues; licence MIT or Apache-2.0 |

There is no export or backup command and no in-app language picker; the vault pane says the file is
backed up like any other file. Status-to-badge logic is `SettingsStatus` (unit-tested in
`SettingsTests`). `SettingsTests.testRenderSettingsPanes` renders every pane in English and
Japanese, light and dark, to PNG when `KS_SETTINGS_SHOTS` names a directory
(`TEST_RUNNER_KS_SETTINGS_SHOTS=… xcodebuild … -only-testing:KagisecureTests/SettingsTests test`).

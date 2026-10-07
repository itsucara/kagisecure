# ADR-0050: Auto-type into native apps

- **Status:** Accepted (2026-10-07, by the owner)
- **Date:** 2026-10-07
- **Deciders:** the owner, who asked for 1Password-style Auto-Type: one Touch ID, then a saved login
  is typed into whatever app needs it, by the person or by an agent
- **Refines:** [ADR-0036](0036-agent-requested-browser-fill.md) (the same shape, for apps the browser
  extension cannot reach); [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md) and its
  amendments (the grace window it rides)
- **Relates to:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0038](0038-app-release-needs-presence.md), [ADR-0040](0040-audit-before-release.md),
  [ADR-0042](0042-unattended-agent-access.md), [ADR-0045](0045-system-wide-autofill-credential-provider.md),
  [ADR-0048](0048-agent-test-logins.md), [ADR-0049](0049-store-command-output.md)

> **Accepted; built in the IPC protocol, the agent, the MCP sidecar, the FFI and the macOS app.**
> Mechanisms are described in the present tense.

## Context

The browser extension fills web pages (ADR-0036) and the credential provider covers apps that use
the system's password AutoFill (ADR-0045). Everything else — a terminal's `sudo` or `ssh` prompt, a
VPN client, a database GUI, an installer dialog — still needs a person to copy and paste, which puts
the value on the clipboard. 1Password's Auto-Type answers this by typing the value as keystrokes.
The owner wants the same, for any item, available to the person and to agents.

## Decision

### 1. A new tool, `request_type`

`request_type { item_id, fields?, target: { bundle_id, team_id?, window_title? }, reason? }`.
`fields` is `username`, `password` or both, or `one_time_code` alone (the ADR-0036 §7.4 rule); the
order typed is fixed: username, Tab, password. The agent names the app it expects in front; a bundle
id of letters, digits, `.`, `-`, `_` (≤ 255), a team id of ten upper-case letters and digits, a
window-title substring on one line (≤ 256). The reply is `Typed { fields_typed, bundle_id }` —
names only. The schema has no property a value fits in and passes the MCP invariant tests.

### 2. Approval: the grace window, then the sheet

A new approval kind, `AutoType`, clamped like an agent fill: one review, once, no lease, never
presence-only. It **rides the app-wide presence grace window** (`rides_grace`): inside it the app
answers with no sheet and no prompt, unless the stricter "always show the sheet for agent fills"
setting is on. Outside it, a sheet shows the target app's icon, name and bundle id, the team and
window title the agent required, the item, what will be typed and the agent's reason, then Touch ID.
The sheet offers **Deny and block this agent** (thirty minutes, keyed by the sidecar's parent
executable).

### 3. Verified right before typing

The app — not Rust — types, because only it can see the screen. Before the first keystroke it checks:
the frontmost app's bundle id, its signing team (from its dynamic code signature) when one was named,
the focused window's title when named, that the focused element (`AXFocusedUIElement`) is a text
input, and that a password goes only into an `AXSecureTextField`. After Tab it re-checks the field;
after every eight characters it re-checks that focus has not moved. A mismatch before typing is
`NO_MATCHING_TARGET` with **one message whatever failed**, so it is no oracle; focus moving partway
is the same code with a message saying part of the value may be in the field.

After a sheet, kagisecure is frontmost; the app hands activation back to the running app with the
target bundle id and waits up to 1.5 s for it to come forward.

### 4. Keystrokes, not the clipboard

`CGEvent` keyboard events carrying unicode strings (`keyboardSetUnicodeString`), Tab as a virtual
key. Nothing touches the pasteboard. If another app holds secure event input
(`IsSecureEventInputEnabled`) keystrokes would not arrive: the app reports `SECURE_INPUT` and types
nothing (`TYPE_UNAVAILABLE`). Posting events needs the **Accessibility permission**; Settings ▸
Auto-type shows whether it is granted, opens the system prompt, and explains why. Until the app holds
it — and while the person has agent auto-type switched off — Rust answers `TYPE_UNAVAILABLE` before
any sheet.

### 5. How values reach the app

An `AutoTypeBroker` in the agent crate, one per process, like the approval queue: the IPC thread
records the `Allowed` audit entry and, in the same transaction, the crossing
(`crossing::auto_type_values`, from the `Grant`) builds the values in zeroizing buffers; the job goes
to the broker; the app polls `auto_type_next_job`, types and reports `auto_type_finish`. A job not
taken or reported within 20 s is withdrawn (`TYPE_UNAVAILABLE`). A lock withdraws every job.

### 6. Audit, limits, scope

* `Allowed` entry before typing: actor `actor_for` (the agent's full identity), tool `request_type`,
  item, field names, detail `AUTO_TYPE <bundle_id>`; a `Failed` follow-up names any outcome but
  typed (`NO_MATCHING_TARGET`, `FOCUS_CHANGED_PARTWAY`, `SECURE_INPUT`, …).
* One auto-type at a time, at most 30 per agent in ten minutes (`RATE_LIMITED`).
* Not on the unattended socket (refused like every vault-touching tool), not in `kagisecure daemon`
  (no typist), not on Windows.
* Protocol 6: `RequestType`, `Typed`, `NO_MATCHING_TARGET`, `TYPE_UNAVAILABLE`.

### 7. The person's own auto-type

Quick Access ⇧⏎ and Item ▸ Type Login into Previous App (⇧⌘T) release the password with a new
release purpose, `AutoType` (audit tool `auto_type`), which rides the grace window like every in-app
release; then kagisecure steps aside and types username, Tab, password into the app that comes
forward, with the same focus checks.

### 8. Honest wording

kagisecure never returns the value to the agent, but the target app receives it, and an agent that
controls or can read that app can read it there — the stance of ADR-0036 §8.1. The tool
description, the sheet and Settings say so.

## Consequences

### Positive

* Logins reach terminals, dialogs and native apps without the clipboard.
* One Touch ID covers the session, for the person and for agents (the owner's "one touch" ideal).

### Negative — accepted

* Inside the grace window an agent can have any visible login typed into an app it names; the
  frontmost-app check limits where, not whether. Convenience first, per the owner.
* The Accessibility permission is broad; kagisecure uses it only to read focus and post keystrokes.
* Keyboard layouts and IMEs are bypassed by unicode events; an app that ignores them receives nothing.

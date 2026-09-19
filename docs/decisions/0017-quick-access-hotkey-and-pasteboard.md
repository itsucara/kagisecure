# ADR-0017: Quick Access uses a Carbon hot key, activates the app, and every copy is on a timer

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M5 implementation
- **Refines:** [ui-spec.md](../ui-spec.md) §7, §11,
  [threat-model.md](../threat-model.md), [ADR-0010](0010-app-sandbox-off-and-generated-project.md)

## Context

M5 owes three things that all live in the same corner of AppKit:

1. a **system-wide `⇧⌘Space`** that opens Quick Access from whatever app the user is in;
2. a **floating panel** that opens "without raising the main window" (ui-spec.md §7);
3. **copy actions** — for passwords in the detail pane, for one-time codes, for anything Quick
   Access hands over — that do not leave secret material on the clipboard indefinitely.

Each has an obvious implementation that is wrong in a way worth writing down.

## Decision 1 — the hot key is `RegisterEventHotKey`, not an event monitor

**`GlobalHotKey` wraps Carbon's `RegisterEventHotKey`. The app requests no Accessibility and no
Input Monitoring permission, and none is needed.**

| Approach | What macOS asks the user | What the app can see |
| --- | --- | --- |
| `NSEvent.addGlobalMonitorForEvents(matching: .keyDown)` | **Input Monitoring** (TCC prompt) | every keystroke on the machine, in every application |
| `CGEvent` tap | **Accessibility** (TCC prompt) | the same, plus the ability to modify events |
| `RegisterEventHotKey` | nothing | that one combination fired |

For a password manager the first two are not a trade, they are a contradiction. The whole product
argument is that kagisecure sees less than you fear; asking the operating system for permission to
watch the user type — to implement a *shortcut* — spends the only thing the product has. Carbon's
API is the one macOS provides for exactly this purpose, is not deprecated, and hands back nothing
but the event.

The cost is that it is Carbon: a C callback that cannot capture, an `EventHotKeyID` signature made
of four characters, and a handler table that has to live in a static because the callback has
nowhere else to look. `GlobalHotKey` is 140 lines and none of it is interesting; the alternative
was a TCC prompt on first launch of a password manager.

**Failure is reported, not swallowed.** If another app already owns `⇧⌘Space`, registration returns
`eventHotKeyExistsErr`, the error is stored on `QuickAccessController.hotKeyError`, and Settings →
Quick Access says so. The feature still works from the menu-bar item and the Item menu; it is the
shortcut that is unavailable, and only the user can free it.

**No `deinit`.** A `deinit` is nonisolated and both things it would want to touch — an
`OpaquePointer` and a main-actor table of non-`Sendable` closures — are things Swift 6 refuses to
hand it. Teardown is an explicit `unregister()`. Nothing leaks past the process: Carbon releases a
process's registrations when it exits, and the app registers one shortcut once.

## Decision 2 — the panel activates the app, and this is a partial miss

ui-spec.md §7 asks for a floating panel "without raising the main window". The mechanism macOS
provides is `NSWindowStyleMask.nonactivatingPanel`, which is documented to let a panel take
keyboard focus while its application is in the background.

**It does not, for an application that has a Dock icon.** Measured on macOS 26.1: with the panel up
and Finder frontmost, `AXFocusedWindow` is the panel and `AXFocusedUIElement` is its search field —
and every keystroke goes to Finder. The panel looks focused and receives nothing. (The behaviour
does work for accessory / `LSUIElement` applications, which kagisecure is not: it has a Dock icon
and a main window.)

**So `QuickAccessController.open()` calls `NSApp.activate(ignoringOtherApps:)`, then
`makeKeyAndOrderFront` one run-loop hop later** — the hop matters, because activation is
asynchronous and asking for key status before it lands gets it handed to the main window instead.

What this keeps and what it costs, precisely:

- **Kept:** the main window is never sent `makeKeyAndOrderFront`, never becomes key, and stays
  behind the panel. A minimized or hidden main window stays minimized or hidden. Quick Access has
  its own query and its own selection, so nothing about the three-pane UI changes underneath.
- **Lost:** kagisecure becomes the frontmost application, so its main window — if it was visible —
  is drawn above other applications' windows. `⌘Tab` order changes. On dismissal, focus returns to
  the previously frontmost app only if the user dismisses with Esc or a copy; clicking away does
  it too.

The roadmap records this as the one M5 acceptance criterion met in part rather than in full. The
fix that would close it — making kagisecure an accessory app with no Dock icon — is a decision
about the whole product's shape, not about Quick Access, and is not M5's to make.

## Decision 3 — every copy is marked concealed and cleared on a timer

**`PasteboardService` is the only code in the app that writes secret material to the clipboard.**
Two mitigations, applied together, at one call site so they cannot drift apart:

1. **`org.nspasteboard.ConcealedType`.** The convention clipboard managers honour to keep an entry
   out of their searchable history. It costs one line and is the difference between a password
   living for a minute and living in a database on disk.
2. **A timed clear, default 60 s, configurable in Settings** (15 s / 30 s / 1 min / 2 min / 5 min /
   never).

**The clear is conditional on `NSPasteboard.changeCount`.** The timer records the count it left
behind and compares before clearing: if anything — the user, another app — has written to the
clipboard since, the countdown does nothing. Clearing unconditionally after a minute would throw
away whatever the user copied in the meantime, which turns a security feature into a bug report.
This is the rule 1Password and KeePassXC use.

**The countdown opts out of App Nap.** This was found by measurement, not by reading: a 60-second
clear had not fired after 90 seconds with the app in the background — which is the *normal* case,
because the point of copying a password is to go and paste it somewhere else. `beginActivity(…)`
around the pending clear fixes it. The option is `.userInitiatedAllowingIdleSystemSleep`: a
clipboard timer is not a reason to keep someone's Mac awake, and if the machine does sleep, the
vault locks (ADR-0004's common rules) and the clipboard is the smaller problem.

**What this is not.** It is not a guarantee. Any process on the machine can read the general
pasteboard during the window, macOS may sync it to other devices through Universal Clipboard, and
a clipboard manager that ignores the concealed-type convention will still record it. Copying a
secret is a deliberate act of handing it to the rest of the system; the timer bounds the exposure,
it does not remove it. threat-model.md's T-3 (a hostile process in the user's session) is not
addressed by any of this, and never was.

Non-secret copies do **not** go through this path. The MCP configuration snippet in Agent access is
written straight to the pasteboard, because clearing it after a minute would break the one thing
the user is about to do with it.

## Consequences

**Positive**

- No TCC prompt of any kind for Quick Access. A password manager that asks to monitor input is
  telling on itself.
- One copy path, so the concealed marker and the timer cannot be forgotten at a new call site.
- The App Nap finding is recorded rather than rediscovered.

**Negative — accepted**

- Quick Access makes kagisecure frontmost. Documented above, in ui-spec.md §7 and in the roadmap.
- `⇧⌘Space` cannot be rebound in v1. If another app owns it, Quick Access is menu-only until the
  user frees it. A shortcut recorder is a later, small piece of work.
- The pasteboard mitigations are conventions and timers, not enforcement.

**Neutral**

- `GlobalHotKey` is general enough to register a second shortcut; nothing else needs one yet.

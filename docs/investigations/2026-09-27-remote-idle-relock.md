# Investigation: immediate idle relock during remote use on macOS

Date: 2026-09-27. Investigated revision: `41df205`.
Status: fixed in `AutoLockCoordinator` (idle time is now the minimum of system-wide HID idleness,
time since this session's own unlock, and time since the last in-app activity) — see "Fix" below.
This is an investigation, not a change to the security policy or an accepted ADR; the fix itself
is ordinary implementation work, not a new ADR.

## Result

The personal vault was successfully unlocked, but returned to **“Locked after
being idle.”** during the ensuing interaction. The current idle check can count
time **before the successful unlock** against the new session. It also depends
solely on two HID event counters, which did not reflect the recently observed
remote/accessibility interaction in this session.

That combination explains an idle relock at the next timer check even though the
person has just opened the vault. The exact user input route and the exact
unlock-to-lock interval still need a controlled reproduction. It is not yet
established that every remote-control product behaves the same way.

The separate request to unlock the Mac's desktop came from the UI automation
tool operating a native app on that Mac. It is not proof that shared-vault
membership requires that particular Mac, or that all unattended work requires an
unlocked desktop.

## Observed evidence

- Environment: Mac mini, macOS 26.6.2, Xcode 27.0, local ad-hoc Debug build with
  `ENABLE_DEBUG_DYLIB=NO`. The rebuild and signature verification succeeded.
- After the person reported unlocking, accessibility inspection showed the
  unlocked `Personal` window, zero items, and the new `Shared` sidebar section.
- During subsequent UI interaction, the app returned to its lock screen with
  reason **idle**, not “Locked when the screen locked.” No shared vault was joined.
- A read-only CoreGraphics probe after those interactions returned:

  ```text
  keyboard_idle_seconds= 12485.126681708
  pointer_idle_seconds= 10798.881830791
  ```

  The minimum is approximately three hours, well beyond the default ten-minute
  threshold. These are one session's measurements, not general API guarantees.
- The app's effective preference was not captured from inside the running app.
  Ten minutes is the source default; do not describe it as a verified in-app
  setting for this incident.
- No passwords, recovery codes, invitation contents or vault records were read
  for this investigation. No auto-lock or access settings were changed.

## Relevant implementation

- [AutoLockCoordinator.swift](../../apps/macos/Kagisecure/Services/AutoLockCoordinator.swift):
  `start()` installs a repeating 15-second timer. Each callback compares
  `systemIdleSeconds()` directly with the configured timeout.
- `systemIdleSeconds()` takes the minimum of `.keyDown` and `.mouseMoved` elapsed
  times from `CGEventSource` using `.hidSystemState`. It does not explicitly
  consider mouse clicks, scrolling or app-level/accessibility actions.
- `start()` does not record a successful-unlock timestamp. It does not clamp the
  measured idle duration to the age of the current unlocked session.
- [AppModel.swift](../../apps/macos/Kagisecure/Models/AppModel.swift) calls
  `autoLock?.start()` after switching to `.unlocked`.
- Sleep, display sleep and the distributed screen-lock notification independently
  lock the personal vault. Those protections are distinct from the idle timer.

Consequently, if the HID counters are already over the timeout and unlocking does
not reset them, the next scheduled idle check can end the new session. The
15-second interval follows from the code; the incident was not timestamped finely
enough to claim that exact elapsed time was measured.

## Proposed repair, subject to implementation review

1. Treat a successful unlock as the start of a new idle interval. Use a monotonic
   clock, and count no pre-unlock time against that session. An initial model is
   `effectiveIdle = min(systemIdle, elapsedSinceSuccessfulUnlock)`.
2. Separately determine how supported remote input should refresh activity. An
   unlock baseline prevents the immediate relock but does not by itself prevent
   another relock after the timeout during continued remote interaction.
3. Preserve system-wide activity detection: actively typing in another app must
   not be mistaken for leaving the computer. Examine clicks and scrolling too.
   Compare HID and combined-session counters experimentally before choosing an
   API; do not assert that changing event-source state alone fixes every path.
4. Decide explicitly which synthetic/accessibility actions count as activity.
   An agent repeatedly querying the vault, a sync timer or a redraw must not
   silently keep an interactive vault unlocked indefinitely.
5. Keep sleep and actual screen-lock handling independent and immediate. Do not
   solve the problem by disabling auto-lock, suppressing OS lock notifications,
   or reusing an interactive unlock as blanket unattended authorization.

For diagnosis, capture only event reason, configured timeout, monotonic session
age and input-counter ages. No typed text or secret values are needed.

## Verification needed for a fix

[AutoLockAdversarialTests.swift](../../apps/macos/KagisecureTests/AutoLockAdversarialTests.swift)
currently covers notification handling and a finite/nonnegative idle probe. It
does not cover a stale HID counter immediately after successful unlock.

Use injectable time and activity probes for deterministic tests, then verify the
real input routes on a disposable vault:

- A three-hour stale counter at unlock does not lock at the first 15-second tick.
- With no subsequent activity, the configured timeout still locks the vault.
- Physical typing, pointer motion, clicks and scrolling refresh activity as
  intended, including activity in another app.
- Test the actual remote-control route and accessibility actions separately;
  observe counters and the displayed lock reason before drawing conclusions.
- Lock/unlock cycles restart the interval and do not leave duplicate timers.
- Screen lock and sleep still lock immediately, including when idle locking is
  disabled. Invalid/nonfinite counter readings have an explicit policy.
- Background sync, UI refresh and ordinary agent requests do not extend the
  interactive unlock as a side effect.

These checks were the proposed regression plan. The fix below covers the first two and the
lock/unlock-cycle one with unit tests against an injected clock and idle-seconds reader
(`AutoLockAdversarialTests`'s "Remote/automated-use idle relock" group); the invalid/nonfinite
counter policy is unchanged (`min()` still propagates a nonfinite reading, as it always has); the
"physical input" and "actual remote-control route" items still need the real hardware/software
this repository's automated tests cannot drive; and "background sync ... do not extend the
interactive unlock" is true by construction (see "Fix" and "Not done" below) but was not itself
asserted by a new test.

## Fix

Implemented in
[AutoLockCoordinator.swift](../../apps/macos/Kagisecure/Services/AutoLockCoordinator.swift),
following the "Proposed repair" above with items 1 and 3-4 adopted and item 2 covered as far as an
in-app activity signal can cover it (see "Not done" below).

The idle check now compares the timeout against `min` of three measurements, rather than
`systemIdleSeconds()` alone:

1. **`systemIdleSeconds()` (unchanged).** System-wide HID idleness from `CGEventSource`, kept so
   that switching to another app to actively type there is never mistaken for having left the
   computer.
2. **Time since this session's successful unlock.** `start()` records the unlock instant with an
   injectable clock and floors the idle measurement there, so no time from *before* the unlock
   counts against the new session — the exact defect this incident hit.
3. **Time since the last in-app activity.** `start()` installs an `NSEvent` *local* monitor (key,
   mouse and scroll events in the app's own windows only — never another app's), and
   `noteInAppActivity()` is also called directly from `VaultStore` and `ItemReleases` on every
   explicit vault operation (save, toggle, archive, delete, reveal, copy, the environment
   mutations) so that accessibility-/automation-driven use of those same code paths — which
   produces no local `NSEvent` — still counts. `start()` seeds this to the unlock instant, so a
   session with no activity yet is exactly as fresh as its unlock and no fresher.

All three are `.infinity` before a baseline exists (coordinator never started), so a real
measurement always wins the `min`. Unlock (`start()`) resets the whole clock, matching item 1's
"treat a successful unlock as the start of a new idle interval." The default stays ten minutes; a
locked screen or system sleep still lock immediately and unconditionally, independent of the idle
trigger (item 5 — unchanged, and covered by the existing `AutoLockAdversarialTests` G-23 suite).

### Not done / follow-up

- **Item 2's "another relock after the timeout during continued remote interaction" is only
  partly addressed.** The fix keeps a *supported* remote-control session alive for as long as it
  keeps producing local `NSEvent`s or vault operations in the app's windows — the same as physical
  use. It does not add a distinct "this is a remote session" concept, and it does not attempt to
  classify which remote-control products' input reaches our windows as local `NSEvent`s versus
  which (if any) bypass that path the way they bypass the HID counters; that would need the
  controlled reproduction the original investigation could not complete.
- **Item 4's "which synthetic/accessibility actions count as activity" is answered narrowly.** Only
  the vault-operation call sites named above extend the session; a background sync
  (`VaultStore.syncFromDisk()`'s ~2s timer and `didBecomeActive` callers), a UI refresh, or an
  agent/browser-extension request through the local socket does **not** call
  `noteInAppActivity()` and so cannot keep an unattended, interactive vault open by itself. This
  was not re-verified with a dedicated test in this change; see "Verification needed for a fix"
  below for what such a test would need to assert.
- **The real remote-control and accessibility input routes were not tested against a live
  build.** Everything above is unit-tested against an injected clock and a fake idle-seconds
  reader (`AutoLockAdversarialTests`'s new "Remote/automated-use idle relock" group); the original
  incident's controlled reproduction is still open work.

## Mac login, vault unlock and unattended work are different states

| State | Meaning in this incident |
| --- | --- |
| macOS login session | The native app runs in a user's session on the selected host. |
| Desktop screen lock | UI automation cannot operate the locked desktop; the personal vault also locks by policy. |
| Personal vault unlock | The master password opens the local vault. This is not a company-account login. |
| Shared-vault membership | The current app accepts an invitation file, six invitation words and a shared folder. Setup remains separate from personal-vault creation. |
| Unattended jobs | A separately armed machine vault and explicit grants support defined background work. They were not enabled during this session. |

[ADR-0042](../decisions/0042-unattended-agent-access.md), **Implementation
decisions 1 and 32**, describes persistent arming and login-item registration.
The app can resume permitted work in a login session; a cold boot with FileVault
still needs the initial OS login. This is not the same as requiring screen unlock
for every job. The Phase 4 shared-copy rules also exclude shared Login items from
unattended copies: do not promise all company website logins work unattended.

[ADR-0043](../decisions/0043-unattended-access-on-headless-hosts.md) is still
proposed, not implemented at the investigated revision. Its introductory summary
of ADR-0042 predates the latter's implementation amendments; use ADR-0042's
current decisions for the shipped macOS behavior.

For everyday interactive use, the person's usual Mac can be enrolled separately
in the shared vault. Always-on-host operation is a separate requirement and
should use the unattended/headless design, not repeated remote unlocking of the
personal vault. Neither enrollment nor unattended access was changed here.

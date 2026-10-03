# ADR-0038: Releasing a secret from the unlocked app needs a fresh presence proof

- **Status:** Implemented — phase 1 (Rust and FFI) and phase 2 (the Swift app, and the removal of
  the ungated calls) are both built; see "Implementation status" at the end. Windows implements
  the gate with Windows Hello across the C ABI — see "Windows" below (written, not yet built or
  run on Windows). What remains is
  recorded there under "Not done": the Swift unit and UI tests are written and compiled but have
  not been run (they occupy the GUI), and two refinements are left for later.
- **Date:** 2026-09-25
- **Deciders:** the owner, closing the gap [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md)
  explicitly left out of scope, in the same design pass
- **Refines:** [ADR-0008](0008-ffi-secret-crossings.md) crossings 2 and 5,
  [ADR-0016](0016-totp-field-storage.md), [ADR-0017](0017-quick-access-hotkey-and-pasteboard.md)
  §3, [ui-spec.md](../ui-spec.md) §4.2, §4.3, §7, §11, [threat-model.md](../threat-model.md)
- **Depends on:** [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md) for the
  one-prompt-at-a-time guard this ADR extends rather than duplicates (now the app-wide
  `PresenceCoordinator`), and for the precedent this ADR follows almost exactly, one boundary
  over; and on the transactional vault writes of
  [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md), whose audit path the release
  entries reuse. Both landed on the same branch before this ADR's implementation.
- **Amended 2026-10-03:** a release inside ADR-0037's app-wide grace window asks nothing, and a
  successful release check opens or extends that window. See the amendment at the end.

## Context: the vault's own front door has no lock on it

ADR-0037 closed a gap in the browser extension: a live fill lease let a second, third or
hundredth fill through on nothing but `event.isTrusted`, which an OS-level automation agent can
forge as easily as a real click. That ADR is explicit about what it did not touch:

> Gating **reveal** and **copy** in the app itself is a separate decision, ADR-0038, not this one.

The gap it left is the same shape, one boundary closer to the vault. Once the vault is unlocked,
the FFI calls that hand a value to the native app — `reveal_field`, `totp_code`,
`item_totp_code` (`crates/kagisecure-ffi/src/session.rs:355-411`) — release it unconditionally.
There is no biometric, no confirmation, nothing between "the vault happens to be unlocked right
now" and "here is the plaintext" beyond ordinary SwiftUI dispatch. `VaultStore.session`
(`apps/macos/Kagisecure/Models/VaultStore.swift:50`) is a plain, ungated property, and
`QuickAccessView`, `TotpFieldView`, `ItemDetailView` and `ItemListView` all call through it
directly. Anything that can drive the app's own UI — a human, or an OS-level automation agent
using the same accessibility surface the app's own test suite uses — gets every secret in the
vault for free, one field at a time, for as long as the vault stays unlocked. For most users that
is most of the working day.

### Inventory: eleven surfaces release a secret on nothing but "the vault is unlocked"

Every line number below is verified against `main` at `a58ed41`.

| # | Surface | Path |
| --- | --- | --- |
| 1 | Reveal (⌘R, advertised in the row's tooltip but bound to no key in code) | `ItemDetailView.swift:305-313` → `VaultStore.swift:179-182` → `session.rs:355-368` |
| 2 | The revealed value itself | `ItemDetailView.swift:349-353`. `.textSelection(.enabled)` on the rendered text lets ⌘C, drag and the Services menu bypass the concealed marker and the app's own clear entirely. |
| 3 | Copy (the "copy without revealing" button) | `ItemDetailView.swift:316-327` → `VaultStore.swift:192-201` |
| 4 | Edit prefill (⌘E) | `ItemDetailView.swift:254-279` → `ItemEditView.swift:197`. Every concealed field is fetched and prefilled in one pass, including a TOTP seed, so a single keystroke with no further intent releases the whole item. |
| 5 | TOTP setup sheet reopened for an existing field | `ItemEditView.swift:232-233` → `TotpFieldView.swift:211-213` prefills the stored seed |
| 6 | The live TOTP code, and its accessibility label | `TotpFieldView.swift:87-100` (recomputed every second), `:52-58` (rendered); the code is repeated in the `accessibilityLabel` at `:79-80` |
| 7 | TOTP copy | `TotpFieldView.swift:43-49` (ring tap), `:69-76` (⌥⌘C), `:102-106` → `VaultStore.swift:193-197` |
| 8 | List-row TOTP copy (hover action) | `ItemListView.swift:63-73` → `VaultStore.swift:204-213` |
| 9 | Quick Access password copy (⏎) | `QuickAccessView.swift:206-223`, with the `reveal_field` call itself at `:217`. This is the exact mechanism ADR-0037 gated on the browser side; the app's own Quick Access panel never got the equivalent. |
| 10 | Quick Access TOTP copy (⌥⏎) | `QuickAccessView.swift:241-257`, with the `itemTotpCode` call at `:244` |
| 11 | Notes, including everything typed into a Secure Note | `ItemDetailView.swift:146-161`. `Item.notes` (`crates/kagisecure-core/src/model/mod.rs:300`) is `Option<String>`, not `Secret` — there is no field-kind boundary here, only a UI convention, and `kagisecure item show` prints it unconditionally (`crates/kagisecure-cli/src/commands/item.rs:139`), `--reveal` or not. |

Two more facts anchor the mechanism decided below:

- **Locking today is implicit.** There is no `VaultSession::lock()`. `AppModel.lock`
  (`AppModel.swift:246-265`) sets `store = nil`, which drops the app's last strong reference to
  the `VaultSession`; that object's `Drop` impl (`session.rs:97-103`) is what actually calls
  `self.handle.take()`, zeroizing the key and running the lock hook. The effect is correct today,
  but it is a side effect of reference counting, not a call a new component — the presence gate —
  can hook to learn "the vault just locked" before the key is gone.
- **`FieldDraft.value` is a plain `String`** (`apps/macos/KagisecureFFI/Sources/KagisecureFFI/kagisecure_ffi.swift:3773`, generated from the FFI record), with no way to say "leave this field's stored value alone." Every edit prefill in #4 exists partly because there is no other way to submit an edit that keeps nine fields and changes one.

Out of scope for this ADR, recorded rather than silently dropped: public fields, the recovery
code, the password generator's own preview, extension fills (ADR-0037's territory), and the CLI's
`item show --reveal` for concealed *fields* (the CLI already asks for the master password on every
invocation — see "The CLI's stance" below). The clipboard already has a timed, concealed-type
clear (ADR-0017 §3); this ADR gates what reaches it, not the clear itself.

## The adversary: an OS-level automation agent driving the native app

The capability assumption is deliberately the same one ADR-0037 states for the browser, applied to
the app's own window instead of a page: something that can drive AppKit/SwiftUI through
Accessibility (`AXUIElement`), synthetic `CGEvent`s, AppleScript's GUI scripting, or an external
UI-testing harness attached without a debugger entitlement. It can find any button, menu item or
text field by the same accessibility identifiers the app's own test suite is built on (`ks.*`),
and it can invoke them exactly as a human would — click Reveal, press ⌘R, choose Copy, press ⏎ in
Quick Access. Nothing at the event-handling layer distinguishes this from a real gesture, which is
precisely why `event.isTrusted` failed as a gate on the browser side and why "the app received a
button-tap event" is not evidence of a human decision here either.

**What it can do.** Everything in the inventory table above, as fast as the UI will dispatch it,
for as long as the vault is unlocked. It can also read anything already on screen —
`AXValue`/`AXLabel` — including a value a legitimate reveal put there for a real person to read
(this is the residual risk stated plainly below, W-19).

**What it cannot do.** It cannot itself satisfy `LocalAuthentication`. Pressing a fingerprint
sensor, presenting an enrolled face to the camera, or carrying an unlocked Apple Watch within
range are physical events the Secure Enclave and the passcode subsystem attest to; no `CGEvent`,
no accessibility call and no synthetic click produces that attestation, and cancelling or timing
out the system sheet never yields `Confirmed` (the same property `BiometricGate.swift` gives
ADR-0037's fill lease). It also cannot type the vault's master password unless it already knows
it — a genuinely separate compromise, which the fallback in user decision 7 accepts honestly
rather than pretending the presence gate has closed it.

## Options considered

| # | Option | Verdict |
| --- | --- | --- |
| 1 | Leave reveal, copy and notes exactly as they are; treat "the vault is unlocked" as the only gate | Rejected — this is the vulnerability itself. Nothing in the inventory table above has anything to check beyond ordinary SwiftUI dispatch, which any UI-driving process reaches as easily as a person. |
| 2 | A Settings toggle to turn the presence requirement off | Rejected — user decision 6. A password manager whose strongest protection is opt-in protects nobody who did not already know to opt in, which is the same argument ADR-0008 and ADR-0017 already make for not asking for weaker permissions than the product needs. |
| 3 | One touch unlocks the whole item — every field, for N minutes — rather than one field | Rejected — user decision 1. ADR-0008 crossing 2 built `reveal_field` at one-field granularity specifically so a UI bug could leak one field and not nine; a coarse per-item or per-session grant would spend that granularity at the exact boundary meant to use it. |
| 4 | Keep prefilling every concealed field in edit mode (status quo) | Rejected — user decision 4. Surface #4 is the largest single item in the inventory: one keystroke, nine values, no confirmation of intent to see any of them beyond wanting to fix a title or a tag. |
| 5 | Leave item notes as plain, ungated text | Rejected — user decision 3. Secure Notes and free-text notes routinely hold recovery codes, security-question answers and PINs; the vault format never drew a line here, only a UI convention did, so "notes are public" was an oversight, not a considered decision. |
| 6 | Fail closed with no fallback when `LocalAuthentication` is unavailable | Rejected — user decision 7. A vault a user cannot get into because a sensor is dirty, disabled, or absent on that Mac is a worse failure than falling back to the master password the user already typed once to unlock the vault this session. |
| 7 | A second, app-side lease store mirroring the browser's fill lease (ADR-0020), minted on first touch and consumed by later reveals/copies | Rejected — user decision 1's "one touch, same field, no second touch" already grants the one exemption worth having. A lease store would reopen exactly the reuse window ADR-0037's whole design exists to close on the browser side, one boundary over. |
| 8 | A synchronous callback into Swift on a Rust worker thread, instead of an async foreign trait | Evaluated as the fallback if uniffi 0.32 could not support an async foreign trait cleanly. It can — see "Spike result" — so this is not adopted, but the fallback and its trade-offs are recorded there in case a future uniffi upgrade regresses it. |

## Decision

### 1. The mechanism

A new module, `crates/kagisecure-ffi/src/presence.rs`, defines:

```rust
#[uniffi::export(with_foreign)]
trait PresenceGate: Send + Sync {
    async fn confirm(&self, reason: String) -> PresenceOutcome; // Confirmed | Cancelled | Unavailable | Busy
}
```

installed once via `VaultSession::set_presence_gate` — a second call is refused, and **with no
gate installed, every release fails closed**. Rust builds the prompt's text from vault facts (the
item's title, the field's label, the action being taken), sanitised the way `ApprovalSheet.safe`
already sanitises fill-approval text, worded "…only if you just asked kagisecure to…" — the same
framing ADR-0037 chose for its own prompt, because the sentence that defeats an automation agent
tricking a real human into pressing the sensor is the one that names what is about to happen.

Three new async FFI calls replace the three unconditional ones:

- `release_field(item, field, purpose) -> FieldRelease`, where `purpose` is `Reveal`, `Copy`,
  `QuickAccessCopy` or `EditReveal`;
- `release_totp(item, field?, purpose) -> TotpRelease`, with a `code_at(at)` method so the ring and
  the digits stay derived from the caller's clock exactly as `TotpCodeView` does today;
- `release_notes(item) -> NotesRelease`, new — notes have no existing release call to replace,
  because notes were never gated at all (see user decision 3).

Release objects **re-read the vault on each use** and fail after the vault locks, after the
5-minute cap (user decisions 2 and 5), or after the object's `close()`. A release is a live
capability tied to the still-unlocked vault, not a copy of a string that outlives its truth.

`reveal_field`, `totp_code` and `item_totp_code` are removed in the same commit, which is why
ADR-0008 crossings 2 and 5 carry a pointer to this ADR rather than being rewritten: the crossing —
one field, one call, in or out — is unchanged, only the fail-closed check in front of it and the
function names are.

### 2. The invariant

**Every value the app's UI shows or copies, once the vault is unlocked, comes from a release that
a granted `PresenceGate::confirm` produced.** Paired with ADR-0037's invariant for the browser
extension ("every response carrying a secret value came from a granted `queue.ask`, and every
grant went through `gate.authenticate`"), the two ADRs together close both places a secret leaves
kagisecure's control after MCP already refuses to (ADR-0002) and the FFI boundary already
enumerates what may cross at all (ADR-0008): a value now needs a fresh, physical human decision at
the moment it is released, regardless of which door it leaves through.

### 3. Locking discipline — and why it is not just a review rule

**The VaultHandle mutex is never held across the prompt.** A release reads the vault facts it
needs, releases the lock, awaits the gate, re-acquires the lock, and only then checks the vault is
still unlocked and the field still exists before handing back a value. Holding a lock across an
`await` that can take an arbitrary, human-paced amount of time (a biometric prompt the user may
ignore for a minute) would stall every other vault operation — the agent's poll loop, another
window's render — for exactly as long as a human takes to look at their laptop.

This is not asserted as a discipline reviewers have to keep re-checking: it is enforced by the
type system, verified empirically for this ADR (see "Spike result"). `VaultRef`
(`session.rs:56`) wraps a `std::sync::MutexGuard`, which is not `Send`. `uniffi::export`'s async
support requires the returned future to be `Send + 'static` (`UniffiCompatibleFuture`, checked at
the `rust_future_new` call site the macro expands into). Holding a `VaultRef` across the `.await`
that calls into `PresenceGate::confirm` therefore does not compile — not a lint, not a test, a
build failure with the guard named in the diagnostic. A future refactor that tried to simplify a
release function by holding the guard across the prompt would be caught before it could ship.

### 4. Locking, made explicit

**A new `VaultSession::lock()`** calls `handle.take()` explicitly, rather than relying on the last
`Arc` reference dropping. `AppModel.lock` (`AppModel.swift:246-265`) calls it before `store = nil`,
so the moment the vault locks is a call the Swift side can hook rather than an implicit
consequence of reference counting — which is what lets the presence gate invalidate its current
`LAContext` at exactly that moment (the same `gate.cancelInFlight()` mechanism ADR-0037 uses on its
own lock path), rather than guessing from `store` going `nil`.

### 5. Edit mode stops prefilling

`FieldDraft.value` becomes `Option<String>` — `None` means "keep the stored value." Turning a
concealed field public without supplying a new value is refused (`Invalid`), which closes the
degenerate case where "unconceal" would otherwise be a free reveal with no new value in sight.
`TotpSetupSheet` no longer prefills the seed when reopened over an existing field (surface #5);
seeing it again is a `release_field` call like any other.

### 6. Swift

- `LocalAuthenticationGate` implements `PresenceGate`, with a **fresh `LAContext` every call and
  no reuse duration** — the same rule ADR-0037 states for fills, for the same reason: a bound
  session on `LAContext` is exactly the shortcut that would let one touch cover an unrelated later
  release.
- The **same `presencePrompt` guard ADR-0037** builds is extended to cover the app's own
  reveal/copy surfaces, not only the extension's fill approvals: one prompt at a time, and a
  second concurrent request is refused rather than queued, so a background automation attempt
  cannot pile requests up behind a legitimate one.
- The scripted/fake gate used in tests stays `#if DEBUG`, as ADR-0037's does.
- `.textSelection` is removed from every rendered secret and TOTP code (closing the ⌘C/drag/
  Services bypass surface #2 records).
- A shown value conceals itself on deselect, on lock, and at the 5-minute cap (user decisions 2
  and 5).
- Quick Access's copy actions move into a model object so they can be gated the same way the
  detail pane's are, and ⌘R — advertised in the tooltip today but bound to nothing — is wired to
  the new `release_field` call as part of the same change.

### User decisions (2026-09-25)

1. **One touch, one field.** The shown field stays shown, and copying that same shown value needs
   no new touch. A different field — the TOTP code after the password, say — needs another touch.
2. **TOTP in the detail pane** is masked until one touch, then live for at most five minutes (use
   does not extend the window). Deselecting the field or locking the vault ends it early.
3. **All notes are secret.** They are masked in memory as `Secret`, gated by `release_notes`.
   `ItemView` carries only `has_notes`, never the text. The CLI shows notes only with `--reveal`.
4. **Edit mode prefills nothing.** Concealed values stay masked; each one gets its own gated reveal
   if the user asks to see it while editing.
5. **Shown values auto-hide after five minutes**, and also on deselect and on lock.
6. **No setting to switch the protection off.**
7. **If `LocalAuthentication` is unavailable, fall back to the vault master password**, entered in
   the app.

## Accessibility

The system `LocalAuthentication` sheet is standard OS UI and is accessible on its own terms —
VoiceOver already announces it, and nothing here changes that. Three things this ADR changes do
need their own accessibility care:

- **A masked field's accessibility label must say it is concealed, not embed a placeholder that
  reads like a value.** The visual mask is already a fixed run of dots specifically so its length
  does not leak the value's length (ADR-0008 §2); the accessibility label has the same obligation,
  and today it does not exist at all for a masked field, only for the reveal button's own label.
- **The live TOTP code's accessibility label at `TotpFieldView.swift:79-80` already speaks the
  code aloud once shown** — correct and necessary for a VoiceOver user to use the feature at all,
  and unavoidably also readable by anything else walking the accessibility tree at that moment.
  This is the same value already on screen for sighted use; the gate governs *whether* the code is
  live, not who among screen-reader and screen users can perceive it once it is (see W-19).
- **⌘R was advertised but bound to nothing** (surface #1). Wiring it as part of this change is a
  keyboard-accessibility fix that happens to fall out of touching the same call site, not a new
  scope item — a keyboard-only user gets a working shortcut that already appears in the UI's own
  tooltip.

Quick Access's ⏎ and ⌥⏎ remain keyboard-driven; the presence prompt they now trigger is the same
system sheet, reachable and dismissable the same way from the keyboard as any other
`LocalAuthentication` prompt in the app.

## The CLI's stance

The CLI is unaffected for concealed *fields*: `kagisecure item show --reveal` already exists,
already requires the master password on every invocation to open the vault at all
(`crates/kagisecure-cli/src/main.rs:1-6` states this plainly — "the one place where a secret value
legitimately reaches a process the user asked for... or, on explicit request, their own
terminal"), and a presence gate on top of a tool that already demands the master password adds
friction with no matching security gain. `cli.rs:532-535`'s doc comment is explicit that `--reveal`
"has no equivalent over MCP and never will" — this ADR does not touch that line.

**Notes are the one real CLI change.** Because user decision 3 makes every note `Secret`,
`kagisecure item show`'s unconditional `if let Some(note) = &item.notes { println!(...) }`
(`crates/kagisecure-cli/src/commands/item.rs:139`) has to move behind `--reveal`, the same gate
concealed fields already sit behind. This is a small, mechanical change and is called out in the
implementation plan below so it is not missed as "just a docs ADR about the app."

## Audit semantics

Best-effort, and never blocking a release on a failed write — the same posture the audit log
already has for everything else (`crates/kagisecure-core/src/audit.rs`, and the unsaved-entry
tracking `threat-model.md` W-11 describes).

- **On release:** actor `app`, tool one of `reveal_field`, `copy_field`, `edit_reveal`,
  `quick_access_copy`, `totp_show`, `totp_copy`, `notes_show`, carrying the item id and the field
  label; detail `PRESENCE_CONFIRMED`.
- **On refusal:** `Denied`, with detail `PRESENCE_CANCELLED`, `PRESENCE_UNAVAILABLE`,
  `PRESENCE_BUSY` or `VAULT_LOCKED` — the same style of distinguishable detail string ADR-0030
  uses for `FILL_USERNAME_ONLY` and ADR-0037 for `FILL_CONFIRMED`, so a reader of the log sees
  *why* nothing was returned, not just that nothing was.
- **A copy of a value already shown** (surface #1's exemption in user decision 1) is audited with
  detail `SHOWN_EARLIER` rather than `PRESENCE_CONFIRMED`, so the log shows honestly that no new
  touch happened for that entry.
- One purpose enum is shared with the vault-transactions work's own audit entries, rather than
  each feature growing its own parallel vocabulary.

## Residual risks, stated plainly

This ADR does not claim to make reveal and copy safe against everything; it closes one specific
gap. What is left, honestly:

- **A value the gate legitimately released is still just pixels and a clipboard entry
  afterwards** (W-19). The gate proves a human asked for *this* release; it cannot retroactively
  protect the screen or the clipboard once the value is there. This is the same shape of residual
  risk ADR-0037 records for a filled password being readable by the page's own script (W-7) — the
  boundary this ADR defends is *whether* a value is released, not what happens to the pixels after.
- **The `LocalAuthentication`-unavailable fallback is the master password, which defeats nothing
  against an adversary who already knows it** (W-20, user decision 7). The presence gate raises the
  bar to "you need a fingerprint, a face, a watch, or the password" — for a Mac with no biometric
  hardware available at the moment, it is only the password, which is exactly as strong as the
  vault's existing front door and no stronger.
- **A shoulder-surfing adversary who is present for the biometric prompt itself is not defended
  against** — the same limitation T-7 already records, unchanged by this ADR. What changes is that
  every release, not just unlocking the vault once, now needs that physical presence.
- **An adversary that knows the master password and can also drive the UI degrades to the
  fallback case above.** This ADR does not claim otherwise; user decision 7 accepts it explicitly
  rather than pretending the gate is unconditional.

## Consequences

**Positive**

- Closes the app-side twin of the gap ADR-0037 closed on the browser side, using the same
  mechanism shape (a fresh `LocalAuthentication` check, no reuse duration, one prompt at a time)
  and the same `presencePrompt` guard, so the two do not drift into two different security
  postures a reviewer has to reconcile.
- The largest single surface in the inventory — edit-mode prefill of every concealed field on one
  keystroke — is closed rather than gated per field, which is both the simpler implementation and
  the one user decision 4 asked for.
- Notes, which had no security boundary at all beyond a UI convention, get the same `Secret`
  treatment every other concealed value already has.
- The "no lock held across the prompt" invariant is a compile-time property of the existing
  `VaultRef`/`std::sync::MutexGuard` pairing, not a new discipline to maintain by review — verified
  empirically for this ADR rather than assumed.
- Reuses the async foreign-trait pattern the spike confirms uniffi 0.32 supports natively, so
  neither this ADR nor ADR-0037 needs a bespoke polling or worker-thread mechanism for something
  the binding generator already does correctly.

**Negative — accepted**

- **A biometric prompt on every distinct field a user wants to see**, which is more friction than
  today's zero-prompt reveal. User decision 1's "one touch, same field, no second touch for a
  repeat copy" is the one concession made to usability, and it was a deliberate, narrow one rather
  than a broad session grant.
- **The master-password fallback (W-20) is only as strong as the vault's existing front door.**
  Recorded rather than hidden; see "Residual risks."
- **A screen-reader user's TOTP code is, unavoidably, also readable by anything else on the
  accessibility tree at that moment** (W-19) — the same trade-off every screen-reader-accessible
  secret display makes, not one this ADR introduces.
- **`async-trait` becomes a new dependency of `kagisecure-ffi`** (see "Spike result"): the
  `PresenceGate` trait is not dyn-compatible as a native `async fn` trait without it, because
  `Arc<dyn PresenceGate>` needs the trait to build a vtable, which the current, un-boxed shape of
  `async fn` in traits does not permit.

**Neutral**

- The CLI's `--reveal` behaviour for concealed fields is unchanged; only notes move behind it,
  which is a small, mechanical fix rather than a new stance.
- `VaultSession::lock()` is a new explicit call replacing an implicit `Drop`-triggered one; the
  effect on the vault (key zeroized, leases dropped) is unchanged, only the moment Swift can
  observe it moves earlier and becomes deliberate.

## Implementation plan

1. **Rust.**
   - `crates/kagisecure-ffi/src/presence.rs`: `PresenceGate` (foreign, async, `with_foreign`),
     `PresenceOutcome`, `set_presence_gate` (refuses a second install), prompt-text construction
     from vault facts, sanitised like `ApprovalSheet.safe`.
   - Add `async-trait` to `crates/kagisecure-ffi/Cargo.toml` (see "Spike result" for why).
   - `release_field`, `release_totp` (with `code_at`), `release_notes` on `VaultSession`; remove
     `reveal_field`, `totp_code`, `item_totp_code`, updating ADR-0008 and ADR-0016 in the same
     commit (the pointers this ADR added to both are the forward half of that edit).
   - `VaultSession::lock()`, called by `AppModel.lock` before `store = nil`.
   - `FieldDraft.value: Option<String>`; `save_item` treats `None` as "unchanged" and refuses an
     unconceal with no new value.
   - Regenerate bindings (`make bindgen`) once the FFI surface is final.
2. **Rust tests** — `crates/kagisecure-ffi/tests/release_presence_adversarial.rs`, with a fake
   gate and a canary value:
   - no gate installed means no release, for every one of the three release calls;
   - a cancelled or unavailable outcome never lets the canary reach a return value or any error's
     `Debug` output;
   - exactly one gate call per release, and a repeat copy of an already-shown value calls it zero
     times;
   - the prompt text is built from vault facts and is sanitised;
   - locking while the gate is awaiting answers the pending release `VAULT_LOCKED`;
   - `TotpRelease` fails after its TTL, after lock, and after `close()`;
   - a `save_item` that keeps a field's value (`None`) calls the gate zero times; an unconceal with
     no new value is `Invalid`;
   - nothing deadlocks while the gate is awaiting (exercised with a gate that never resolves,
     dropped after a bounded wait);
   - audit entries match §"Audit semantics" exactly, including `SHOWN_EARLIER`.
3. **Swift.**
   - `LocalAuthenticationGate: PresenceGate`, fresh `LAContext` per call, no reuse duration.
   - Extend ADR-0037's `presencePrompt` guard to serve both call sites; a concurrent second
     request is refused, not queued.
   - Remove `.textSelection` from every rendered secret and TOTP code.
   - Wire ⌘R to `release_field`; move Quick Access's copy actions into a model object gated the
     same way; auto-hide a shown value on deselect, on lock, and at the five-minute cap.
   - `TotpSetupSheet` stops prefilling the seed when reopened over an existing field.
   - Tests: a cancelled reveal or copy leaves visible state unchanged; Quick Access asks the gate
     exactly once per action; a source scan asserts no `touchIDAuthenticationAllowableReuseDuration`
     and no `.textSelection` on a released value (compile-and-scan only, run under user consent per
     this project's GUI-test policy).
4. **CLI.** Gate `item show`'s note line (`commands/item.rs:139`) behind `--reveal`, matching the
   existing concealed-field behaviour.
5. **Docs.** This ADR; the pointers already added to ADR-0008 and ADR-0016; the amendment already
   added to ADR-0017 §3; `ui-spec.md` §4.2, §4.3, §7, §11 wherever they describe unconditional
   reveal/copy; `threat-model.md` T-16, M-30, W-19, W-20 and the matrix rows (already added,
   marked pending this ADR's implementation).

**Order.** Land after `fix/fill-presence` (ADR-0037), since the `presencePrompt` guard is shared,
and after the vault-transactions work's audit path merges, since release audit entries go through
it.

## Numbering

Checked against every branch that exists at the time of writing, not just `main`:

- `main` (`a58ed41`): T-1 through T-7 in its own body, T-8…T-11 referenced from
  `threat-model-browser-extension.md`; M-1…M-21; W-1…W-11; N-1…N-9.
- `design/agent-requested-fill` (ADR-0036, proposed): T-12, T-13; M-22; W-12; N unchanged.
- `design/shared-vaults` (ADR-0035, proposed): T-12, T-13, T-14; M-22…M-28; W-12…W-17; N unchanged.
- `fix/fill-presence` (ADR-0037, accepted, unmerged): `docs/threat-model.md` on disk is still
  identical to `main` as of this writing — it has not yet added the T-15/M-29/W-18/N-10 the
  ADR-0038 design reserved for it.

The highest number in use anywhere, per prefix, is T-14, M-28, W-17, N-9. ADR-0038 uses the next
free numbers **above** the block the ADR-0038 design already reserved for ADR-0037 (T-15, M-29,
W-18, N-10), so the two sibling ADRs do not collide whichever merges first:

- **T-16** — OS-level automation agent driving the native app (no existing "OS automation"
  adversary row was found to reuse: ADR-0037's own row is T-15, reserved but not yet committed
  anywhere, so reusing it here would create a forward reference to a row that does not exist on
  this branch).
- **M-30** — the presence-gate mitigation itself.
- **W-19, W-20** — the two residual risks stated above.
- No new non-goal (`N-`) number: this ADR's residual risks are bounded weaknesses (`W-`), not
  blanket non-goals.

When the two design branches merged (2026-09-26), they turned out to collide with each other: both
had drafted T-12, M-22 and W-12, and ADR-0036's draft also used T-13. ADR-0035 kept T-12 … T-14,
M-22 … M-28 and W-12 … W-17; ADR-0036's entries became **T-17**, **M-31** and **W-21**, and its T-13
was folded into T-15, the same adversary. R-8 … R-12 stayed ADR-0036's. W-18, reserved above for
ADR-0037, was never used and stays unassigned.

## Spike result

**Question:** does the workspace's uniffi version support an async foreign (callback) trait
implemented in Swift and awaited from Rust, as `PresenceGate` needs?

**Answer: yes**, cleanly, in the exact version this workspace pins.
`crates/kagisecure-ffi/Cargo.toml` depends on `uniffi = "0.32"`, and `Cargo.lock` resolves it to
**0.32.0** exactly. A throwaway crate outside the repo, pinned to `uniffi = "=0.32.0"` (matching
the workspace precisely, not just the latest 0.32.x), defined:

```rust
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PresenceGate: Send + Sync {
    async fn confirm(&self, reason: String) -> PresenceOutcome;
}

#[uniffi::export]
pub async fn ask_gate(gate: Arc<dyn PresenceGate>, reason: String) -> PresenceOutcome {
    gate.confirm(reason).await
}
```

`cargo build` produced a working `cdylib`/`staticlib`. Generating Swift bindings from it
(`uniffi::generate_swift_bindings`, the same API `xtask/src/bindgen.rs` already calls) produced a
real `async` protocol method and a proper VTable-based async bridge
(`uniffiTraitInterfaceCallAsync`, with a foreign-future completion callback and a dropped-callback
for cancellation) — not a polling loop or a busy-wait. A Swift file implementing `PresenceGate`
with a stub `confirm` that does `try? await Task.sleep(nanoseconds: 300_000_000)` and returns
`.confirmed` was compiled with `swiftc` against the generated bindings and the static library, and
**run**: it printed the expected sequence and returned the expected value end to end, with no GUI
and no `LocalAuthentication` call, confirming the FFI/async plumbing itself rather than the
biometric prompt.

**Gotcha found.** A native `async fn` in the trait, without `#[async_trait::async_trait]`, fails
to compile: `Arc<dyn PresenceGate>` requires the trait to be dyn-compatible, and a plain `async fn`
in a trait is not dyn-compatible on stable Rust (confirmed by trying it — the compiler's own
suggestion is to box the future, which is exactly what `async_trait` does). **`async-trait`
therefore becomes a new dependency of `kagisecure-ffi`**, recorded in the implementation plan and
in Consequences above, and used by the `PresenceGate` trait definition.

**Second gotcha, a positive one.** The "never hold the VaultHandle mutex across the prompt"
invariant (§3 of the Decision) is not merely a discipline — it is enforced by the compiler.
Adding a second spike function that held a `std::sync::MutexGuard` across the `.await` into the
gate failed to compile outright:

```
error: future cannot be sent between threads safely
  = help: within `{async block}`, the trait `Send` is not implemented for `std::sync::MutexGuard<'_, u32>`
note: required by a bound in `rust_future_new`
```

`kagisecure-ffi`'s own `VaultRef` (`session.rs:56`) wraps exactly this kind of guard
(`std::sync::MutexGuard<'_, Option<Vault>>`), so a release function that accidentally held it
across the presence-gate await would fail the same way, at build time, with the offending guard
named in the diagnostic — not something a reviewer has to notice by reading.

**Fallback not needed.** Because the async path works cleanly, the sync-callback-on-a-worker-
thread fallback (option 8 above) is not adopted. It remains the documented fallback if a future
uniffi upgrade regresses async foreign traits: a synchronous `PresenceGate::confirm` called via
`uniffi::export(callback_interface)` (the older, stable mechanism), with Rust blocking a dedicated
worker thread on it rather than the async runtime, at the cost of one thread parked per in-flight
prompt and a callback interface that cannot itself use `await` on the Swift side (it would have to
bridge into a `Task` and block the calling thread on a semaphore until that task finishes).

The spike crate and its generated bindings live only under this session's scratch directory
(`/private/tmp/.../scratchpad/uniffi-spike/`) and are not part of this commit.

## Windows (added 2026-09-26, when `main`'s Windows port was merged)

The Windows app reaches the same Rust through a hand-written C ABI (ADR-0003's fallback), and an
async foreign trait does not cross a C ABI. So on Windows the gate is **one C callback**, and
everything else is the same code the Swift app runs:

- **The gate.** `kgs_session_set_presence_gate(session, confirm, context)` installs
  `confirm(context, reason) -> u32` behind `PresenceGate` (`crates/kagisecure-ffi/src/capi/presence.rs`).
  Rust calls it **synchronously, on the thread that asked for the release**, inside that call —
  never from a thread of its own and never after the call returns — and runs the async release to
  completion there. Rust still builds and sanitises the sentence, allows one release in flight,
  re-reads the vault after the answer, refuses a release whose prompt was up when the vault
  locked, and audits every outcome; C# answers one question.
- **Fail closed.** No gate installed: every `kgs_session_release_*` answers `NoPresenceGate`
  without asking anyone. A null `confirm` installs nothing. A second install is refused and the
  first stays. Any return value that is not the `Confirmed` tag is read as `Cancelled`. On the C#
  side, an exception in the gate is answered `Cancelled`, a gate key that no longer resolves (a
  release that raced the session's disposal) is answered `Cancelled`, and a gate called on the UI
  thread (which would deadlock) refuses rather than blocks.
- **The implementation.** `WindowsHelloPresenceGate` (`apps/windows/Kagisecure.App/Services/`)
  asks Windows Hello (`UserConsentVerifier`, parented to the app window) with the sentence as the
  prompt; every call is a fresh verification. Only when Hello reports itself **unavailable**
  does it ask for the vault master password, which Rust checks on the same session while the
  release waits (`VerifyMasterPassword`, rate limited and audited, marking the grant
  `PRESENCE_CONFIRMED_MASTER_PASSWORD`) — user decision 7, unchanged. Cancelled, failed or busy is
  never a grant. It is installed on every session before the session is published, so there is no
  window in which an unlocked vault has no gate.
- **One prompt at a time.** `PresencePromptGuard` is shared by the release gate and the approval
  sheet's Windows Hello consent, so a second prompt anywhere in the app is refused, not queued.
- **The app.** Reveal, Copy, the one-time code ("Show code") and the notes ("Show notes") each go
  through a release; a copy of a shown value uses `copy_shown_*` with no new prompt; a shown value
  hides on deselect, at the five-minute cap and when the shell is left (the lock); the editor
  prefills nothing concealed and sends `null` to keep a stored secret or note; permanent delete
  carries the Trash row's revision. The ungated `RevealField`, `TotpCode` and `ItemTotpCode` are
  gone from the interop layer, as their Rust functions are gone from the FFI.

**Weaker than macOS, and said so.** A Windows Hello verification is scoped to the Windows account
and the device, not to this app, and Hello always accepts the account PIN (threat-model W-1,
ADR-0033 §5) — it proves that someone who can sign in to this Windows account answered this app's
prompt, which is weaker evidence of a person than Touch ID. And on Windows a same-user process can
read the unlocked app's memory (threat-model T-3), which no gate addresses.

**Verified, and not.** The C ABI's gate and releases are tested in Rust (`capi::tests`: no gate,
a null gate, every refusal and an out-of-range answer, a second gate refused, the sentence shown,
a release ending at lock, the master-password fallback run from inside the callback and audited
as such, a kept secret, a stale delete), and the whole workspace is cross-checked for
`x86_64-pc-windows-msvc`. The C# interop, the WinUI app and their tests were written against the
regenerated declarations but **not compiled or run**: the machine that did the merge has no .NET
SDK. Not built on Windows yet either: the presence-only approval path (ADR-0037) — the Windows
sheet shows the full sheet for a presence-only request, which still requires Windows Hello, so it
is safe but asks more than macOS does — the edit sheet's per-field `EditReveal`, and a UI for the
vault-conflict flow (the calls cross the ABI; the app shows the error's sentence).

## Implementation status

### Phase 1 — Rust and the FFI surface (done, on `feat/vault-transactions`)

**The API.**

| Call | What it does |
| --- | --- |
| `PresenceGate::confirm(reason) -> PresenceOutcome` | The foreign trait (`#[uniffi::export(with_foreign)]` + `#[async_trait]`), `Confirmed` / `Cancelled` / `Unavailable` / `Busy`. |
| `VaultSession::set_presence_gate(gate)` | Installs it; a second call is refused (`Invalid`) and the first gate stays. |
| `async VaultSession::release_field(item, field, purpose) -> FieldRelease` | `purpose` is `Reveal`, `Copy`, `QuickAccessCopy` or `EditReveal`. `value()`, `copy_shown_value()`, `close()`, `is_live()`, `seconds_remaining()`. |
| `async VaultSession::release_totp(item, field?, purpose) -> TotpRelease` | `code_at(at)`, `copy_shown_code_at(at)`, and the same lifecycle calls. `EditReveal` is refused: editing a TOTP setup is `release_field` on the field. |
| `async VaultSession::release_notes(item, purpose) -> NotesRelease` | `text()`, `copy_shown_text()`, and the same lifecycle calls. Takes a `purpose` — which the ADR's sketch above does not — so a copy, a show and an edit are worded and audited apart; `QuickAccessCopy` is refused. |
| `VaultSession::lock()`, `is_unlocked()` | Explicit lock (§4). |
| `VaultSession::verify_master_password(password) -> MasterPasswordCheck` | The fallback (user decision 7). Returns `Verified`, `Wrong { retry_after_ms }` or `Throttled { retry_after_ms }` rather than a bare `bool`, because "not checked because of the back-off" is a third answer a `bool` would have to lie about. |
| `FfiError::{VaultLocked, NoPresenceGate, PresenceCancelled, PresenceUnavailable, PresenceBusy, ReleaseEnded}` | The refusals, distinguishable. |

**How the invariants are held, structurally rather than by review.**

- *No gate, no release.* The gate lives in a `OnceLock` on the session; every release path reads
  it before registering, and with none installed answers `NoPresenceGate` (audited
  `PRESENCE_UNAVAILABLE`) without asking anything.
- *The mutex is never held across the prompt* (§3). Each release is three steps —
  `begin_release` (sync: read facts, register), the one `.await` on the gate, `settle_release`
  (sync: borrow again, decide) — and the vault borrow wraps a `std::sync::MutexGuard`. This was
  re-verified on this code, not just the spike: holding the borrow across the `.await` in
  `release_notes` fails to build with `future cannot be sent between threads safely … required by
  a bound in rust_future_new`.
- *One touch, one field* (user decision 1). A release is bound at `begin_release` to the item and
  field **ids** (never a label), and each release call asks the gate exactly once. A `Copy` or
  `QuickAccessCopy` release is spent by its one use; only a `Reveal`/`EditReveal` release can be
  re-read or copied again (`SHOWN_EARLIER`) without a new touch.
- *One prompt at a time, in Rust too.* A per-session registry admits one release awaiting the gate;
  a second is refused `PresenceBusy` (audited) without reaching the gate. This is in addition to,
  not instead of, the Swift `presencePrompt` guard phase 2 extends, which also serialises against
  the extension's fill prompts.
- *A lock during the prompt answers `VAULT_LOCKED`* (§4). `lock()` takes the handle mutex, closes
  the registry and queues the in-flight release's `Denied`/`VAULT_LOCKED` entry on the vault while
  it still exists (written by the lock's own final flush), then takes the vault. A release whose
  prompt answers afterwards finds itself gone from the registry and hands nothing out, whatever the
  prompt said. Lock order is always the handle mutex, then the registry.
- *A release is a capability, not a copy.* Release objects hold no value; every use re-reads the
  vault through the shared handle, and fails after the lock, after the 5-minute cap (measured from
  the touch, not extended by use, on an injectable monotonic clock), and after `close()`.
- *An abandoned prompt leaves the log honest.* If the app's task is cancelled with the prompt up,
  the dropped future takes itself out of the registry and queues `PRESENCE_CANCELLED`.
- *A locked session never panics.* `VaultRef` used to `expect` that only `Drop` empties the handle;
  with `lock()` that stopped being true. It is now built only over a guard that holds a vault:
  fallible calls answer `VaultLocked`, infallible ones answer what an empty vault would.

**Prompt text.** Built in Rust from vault facts — "copy the password “password” of “GitHub”.
Continue only if you just asked Kagisecure to copy it" (the system prefixes "“Kagisecure” is trying
to") — with every title and label run through a port of `ApprovalSheet.safe`: quote glyphs become
`'`, Unicode format characters (bidi embeddings, overrides, isolates and marks, zero-width
characters, tag characters) and private-use scalars are dropped, control characters and whitespace
runs collapse to one space, and each run is capped at 64 characters with `…`.

The word before the quoted label says what the field **is**, from facts the edit sheet cannot change
without presence: "password" for the item's primary secret (designated by field id, vault-format
§5), "card number" and "one-time password setup" by kind, and "concealed field" for any other
secret. The title and the label are text anything driving the UI can rewrite for free; the noun is
not, so a PIN relabelled "password" is announced as "the concealed field “password”". The kind is
kept trustworthy by `save_item` refusing to change a stored secret's kind without its value.

**Audit** (ADR-0040 step 10), best-effort through the pending queue, actor `app`, item id, the
field's label (`notes` for notes): tools `reveal_field`, `copy_field`, `edit_reveal`,
`quick_access_copy`, `totp_show`, `totp_copy`, `notes_show`; details `PRESENCE_CONFIRMED`,
`PRESENCE_CANCELLED`, `PRESENCE_UNAVAILABLE`, `PRESENCE_BUSY`, `VAULT_LOCKED`, `SHOWN_EARLIER`. A
failed save never withholds the value (tested by replacing the vault file with a directory, so
no write can succeed, while a release settles).
The three refusals (`PRESENCE_CANCELLED`, `PRESENCE_UNAVAILABLE`, `PRESENCE_BUSY`) are throttled
the way wrong master passwords are: each entry rewrites the whole vault file and a refusal costs
its caller nothing, so only the first refusal of each reason in a minute is written, and the rest
of that minute are counted into one `<detail>_REPEATED:<n>` entry (keeping the tool, item and
label only where every counted refusal agreed), written when the minute has passed and the next
refusal arrives, just before the next grant, or on the lock's final flush — a burst stays visible
as evidence without being a way to rewrite the vault at will.
The other step-10 events are recorded too: `change_master_password` (app, and the CLI's `recover`
with detail `RECOVERY_CODE`), `reissue_recovery_code` (CLI), `touch_id_enrol` and
`touch_id_remove` — each inside the transaction that makes the change — and `vault_key_export`,
best-effort, since that call is a read with no transaction of its own.

**Notes are secret** (user decision 3). `Item::notes` is `Option<SecretText>` — a `Secret` that can
only be built from a `String`, so it is always UTF-8. On disk nothing changed: a crate-private
adapter writes exactly what `Option<String>` wrote, and two golden vectors written by the code
*before* this change pin it — `item-with-notes-v1.cbor` / `item-without-notes-v1.cbor` (byte-for-byte
encoding) and `v1-notes-argon2id-64k.kagivault` (an existing vault with a note still opens and
releases it). `ItemView` carries `has_notes`, never the text. `ItemDraft.notes` now means `None` =
keep, `""` = remove, anything else = replace, the same rule `FieldDraft.value` already follows — so
a sheet that never saw the note cannot erase it. The import IR holds notes as `SecretText` too, and
the import canary test now treats the note marker as secret (it previously allowed it in `Debug`).

**Search.** Notes are **not** searchable — by agents (they never were: the agent's `list_items`
matches title and tags, and the notes are in no metadata view) or in the app (`list_items` matches
title, tags and URLs). Recommended to stay that way: a search over note text is an oracle anything
that can type into the search field can query one guess at a time ("does any note contain
`1234`?"), watching which rows remain, with no prompt ever shown — exactly the adversary this ADR
is about. It is the same reason field values are not searched (ui-spec §3). If note search is ever
wanted, it has to happen behind a release (search the one item whose notes were just released), not
over the whole vault.

**Deviations from the text above, and why.**

- `reveal_field`, `totp_code` and `item_totp_code` are **kept**, not removed in the same commit,
  and a transitional `reveal_notes` is added: the Swift app still calls them, and phase 2 removes
  all four when it adopts the release calls. Each carries a "to be removed in phase 2" doc
  comment. They are ungated and unaudited, exactly as before.
- `FieldDraft.value: Option<String>` (§5) was already done before this phase.
- The generated Swift for an async *foreign* trait does not compile under Swift 6's region-based
  isolation checking (`passing closure as a 'sending' parameter risks causing data races`, in
  UniFFI 0.32's `uniffiTraitInterfaceCallAsync`); the spike's bare `swiftc` build did not surface
  it. The `KagisecureFFI` package target — the checked-in generated glue only — is
  compiled in Swift 5 language mode; the app's own code keeps Swift 6 and complete checking.

**The Swift shim until phase 2.** No gate is installed, so every new release call fails closed; the
app keeps working through the old calls. The only Swift that changed is what compiling needed: the
new `FfiError` cases in `ffiErrorMessage`; the detail pane and edit sheet read notes through
`revealNotes` (because `ItemView.notes` is gone); the edit sheet sends `""` rather than `nil` for a
cleared note (because `nil` now means keep); and three test call sites.

**Verified**: `crates/kagisecure-ffi/tests/release_presence_adversarial.rs` (20 tests, canary-based,
with a scripted and a held Rust gate, a manual clock, and a real agent on a real socket for the
no-deadlock case), core unit tests for `SecretText` and the constant-time comparison, and the CLI
`recover` audit assertion; `make macos` and `xcodebuild build-for-testing` build. **Not run**: the
Swift unit and UI tests (GUI-occupying).

### Phase 2 — the Swift app (done, on `feat/vault-transactions`)

**The gate.** `AppPresenceGate` (`Services/AppPresenceGate.swift`) is the app's `PresenceGate`,
installed on every session in `AppModel.adopt` before anything can ask for a value — so a session
never runs without one, and Rust's refusal of a second install means nothing later can swap it. It
asks through **`PresenceCoordinator`** (`Services/PresenceCoordinator.swift`), which is ADR-0037's
`presencePrompt` guard lifted out of `AgentService` and made app-wide:

- The coordinator owns the one `BiometricGate` (`LocalAuthenticationGate`: `.deviceOwnerAuthentication`,
  a fresh `LAContext` per call, no reuse duration — unchanged from ADR-0037) and **one prompt
  slot**. Every prompt in the app takes a `PresenceTicket` from it synchronously before asking: the
  approval sheet's Allow, a presence-only fill, and every release. A second request while the slot
  is taken is **refused, not queued** — a release answers `PresenceOutcome::Busy` (Rust records
  `PRESENCE_BUSY`), the sheet's Allow gets `BiometricOutcome.busy` and says another confirmation is
  on screen. The one thing that waits is a presence-only fill already at the head of the Rust
  approval queue: it is not a second prompt but a question with its own 60-second expiry, raised
  when the slot frees (`addIdleObserver`).
- The slot is freed only when the prompt's own call returns, never by a lock: ADR-0037's rule
  against a second sheet stacking beside one the system is still dismissing now holds for every
  prompt, not one kind.
- **When `LocalAuthentication` cannot run** (the gate answers `.unavailable`), the gate keeps the
  slot and puts up `MasterPasswordFallback`'s panel (`Services/MasterPasswordFallback.swift`) — a
  floating `NSPanel`, not a sheet, because a release can come from Quick Access with the main
  window closed, and a sheet nobody can see would hold the slot forever. The panel sends the
  password to `verify_master_password` off the main thread and honours its answer: `Wrong` and
  `Throttled` show "Try again in *n* seconds" and keep Confirm disabled until then; only `Verified`
  confirms. Rust, not the gate, decides the audit detail for a grant reached this way (see
  "Audit" below).

**Lock** (`AppModel.lock`), in this order, all synchronous: every shown value is hidden and its
release closed (`ItemReleases.hideAll`); **`session.lock()`** — the vault key goes, the lock hooks
deny approvals and drop leases, and a release waiting on its prompt is recorded `VAULT_LOCKED` and
can hand nothing out; then **`PresenceCoordinator.cancelInFlight()`** invalidates the `LAContext`
that is up (and closes the fallback panel); then the listeners stop and the store goes. The session
is locked explicitly because a release future waiting on its prompt holds a reference to it, so
dropping the store alone would have kept the vault open for as long as the prompt stayed up. An
answer that arrives after the lock is also reported as `.cancelled` by the gate (the coordinator's
`cancelGeneration`), belt and braces.

**The surfaces.** Every inventory row, re-verified against the code on this branch before it was
changed (line numbers in the table above are from `a58ed41` and had moved, but every surface was
still there, plus the two phase 1 added — the detail pane's and the edit sheet's `revealNotes`):

| # | Surface | Now |
| --- | --- | --- |
| 1 | Reveal, ⌘R | `ItemReleases.toggleReveal` → `release_field(Reveal)`, one prompt for that field. ⌘R is bound (Item ▸ Reveal or Conceal Field): the focused concealed row, else the item's password (its primary secret, designated by field id — the field ⇧⌘C and Quick Access ⏎ copy), else its one-time password, whose code it starts or stops. |
| 2 | The revealed value | Rendered without `.textSelection`; hidden on deselect, lock and at the release's five-minute cap. The only `.textSelection` left in the item views is `PublicFieldText`, for public values. |
| 3 | Copy without revealing | A shown value: `copy_shown_value`, no prompt (`SHOWN_EARLIER`). Otherwise a one-use `release_field(Copy)`. A public field copies its public value, no release. |
| 4 | Edit prefill | Nothing is prefilled (notes included, which phase 1 still prefilled). A masked field has **Show** — `release_field(EditReveal)`, read once and closed — and **Change**, which starts a new value and releases nothing. A value shown to edit — a field, the notes, a one-time password's setup (`EditReveal`) — that is untouched five minutes later is masked again, which keeps it as stored. |
| 5 | TOTP setup sheet | Opens blank over an existing field, with **Show current setup** → `release_field(EditReveal)` on the TOTP field (its URI). |
| 6 | Live TOTP code | Masked (`••• •••`) until **Show** → `release_totp(Reveal)`; then live via `TotpRelease::code_at` each second until five minutes after the touch, a deselect or a lock. Its accessibility label speaks the code only while it is live. |
| 7 | TOTP copy (ring, button, ⌥⌘C) | A running code: `copy_shown_code_at`, no prompt. A masked one: one-use `release_totp(Copy)`. |
| 8 | List-row TOTP copy | `ItemReleases.copyFirstTotp` — the running code if that item's is live in the detail pane, else `release_totp(field: None, Copy)`. |
| 9 | Quick Access ⏎ | `QuickAccessModel.copyPassword` → `release_field(QuickAccessCopy)`, exactly one prompt, closed after the one read. |
| 10 | Quick Access ⌥⏎ | `QuickAccessModel.copyTotp` → `release_totp(field: None, QuickAccessCopy)`, exactly one prompt. ⌘⏎ copies the public username and asks nothing. |
| 11 | Notes | Masked, with show and copy buttons → `release_notes(Reveal / Copy)`; `copy_shown_text` when shown. In edit mode **Show** / **Replace** / **Remove**. |

Quick Access's actions live in `QuickAccessModel` (made fresh per panel open, dropped on close,
holding no value); the detail pane's in `ItemReleases`, owned by `VaultStore`. Both go through the
same rule: nothing has a value until Rust hands one over from a release, a result that comes back
after a deselect or lock is closed unread, and a second action while a prompt is up does nothing.

**Accessibility.** A masked value's label says what it is and what revealing asks for —
"Password, concealed. Reveal asks for Touch ID or your Mac password." — never a placeholder and
never a length. Showing, hiding (including the five-minute and lock cases) and copying are
announced to VoiceOver, a copy with the clipboard's clear policy. Nothing inspects the input
source: whether an action came from a pointer, the keyboard, VoiceOver or an automation agent is
exactly what cannot be known, and the prompt is what decides.

**The ungated calls are gone.** `reveal_field`, `reveal_notes`, `totp_code` and `item_totp_code`
are removed from the FFI and the bindings regenerated; the app and both test targets building
against them is the proof that nothing calls them, and a unit test scans the bindings and every
Swift source for the names. ADR-0008 crossings 2 and 5 were amended in the same commit.

**Audit, completed.** Three gaps phase 1 left are closed in Rust:

- A grant through the master-password fallback is recorded **`PRESENCE_CONFIRMED_MASTER_PASSWORD`**,
  not `PRESENCE_CONFIRMED`. Rust decides it: `verify_master_password` answering `Verified` while a
  release is waiting marks that release, and only that one, so the gate cannot claim it and a
  password verified earlier cannot leak onto a later biometric grant. The name keeps the
  `PRESENCE_CONFIRMED` prefix so both grants read together, and says *master* because
  `LocalAuthentication` itself accepts the Mac's login password, and that answer is plain
  `PRESENCE_CONFIRMED` — the two prove different things (W-20).
- A wrong master password is recorded best-effort as `verify_master_password` / `denied` /
  `MASTER_PASSWORD_WRONG`, naming the item and label of the release it was typed for; a throttled
  attempt as `MASTER_PASSWORD_THROTTLED`, **once per back-off window** rather than per attempt, so
  pressing Return in a loop cannot rewrite the vault file at will. A burst is evidence of an agent
  guessing through the UI, and the log is where a person would look.
- A confirmed release whose item, field or notes were deleted while the prompt was up is recorded
  `failed` / `GONE_DURING_PROMPT` rather than leaving no entry.

**Deviations from the text above, and why.**

- **"Change" asks for nothing.** It replaces a value without showing the old one, so nothing is
  released; putting a prompt in front of it would add friction with no confidentiality gain, and
  an agent that can edit an item could already change its title the same way. Showing the old
  value to edit it (**Show**) is the gated path.
- **⌘R with no row focused** acts on the item's password — its primary secret, the one field
  ⇧⌘C, Quick Access ⏎, a browser fill and the prompt's "password" all mean, designated by field id
  so a relabel or reorder cannot move it — rather than doing nothing; a keyboard-only user reaches
  a row with Tab (rows with a secret are focusable), and ⌘R alone still does the obvious thing on
  a login.
- **A one-time-password field whose stored URI no longer parses** used to show an inline error
  (`ks.totp.error`); `release_totp` now refuses it before any prompt, and the app shows that as its
  ordinary error alert.
- **The five-minute cap in edit mode** re-masks an untouched shown value instead of hiding it
  outright, since the value is in an editable field: once typed into, it is the person's new value,
  not a released one.

**Also fixed alongside, found while doing this** (not part of this ADR's decision):
`change_master_password` ran Argon2id inside the handle's mutex — the doc said "before any lock is
taken", true only of the file lock — so a password change stalled the agent, the extension and the
UI for the whole derivation. It now runs in three steps around the slow one
(`Vault::plan_master_password`, `MasterPasswordPlan::derive` with no lock, `Vault::wrap_master_password`),
with a test that reads, writes and the agent's handle proceed mid-derivation. The FFI has no
recovery-code reissue or KDF-upgrade path to fix the same way (both are CLI-only, and the CLI owns
its vault outright).

**Verified**: `cargo test --workspace` (Rust release, audit and password-change tests), `make
bindgen`, `make macos`, and `xcodebuild build-for-testing` for both the `Kagisecure` scheme (app +
unit tests, including `ReleasePresenceTests`: a cancelled reveal shows nothing, a cancelled copy
leaves `NSPasteboard.changeCount` unchanged, Quick Access ⏎ and ⌥⏎ each ask exactly once and ⌘⏎
not at all, a lock during a prompt releases nothing, a second prompt is refused, the fallback
honours the back-off and is audited as such, and source scans for reuse windows, `.textSelection`
on released values and the removed calls) and the `KagisecureUITests` scheme (D, F, G, H and L
updated to launch with `-KSUITestBiometrics allow` and press Show where a value now waits for a
touch, plus a new D scenario launched with `cancel`).

### Not done

- **The Swift unit and UI tests have not been run** — only compiled. Both occupy the GUI (the
  unit tests touch `NSPasteboard.general` and run hosted in the app), and this project runs them
  only with the owner's go-ahead.
- ~~**Touch ID enrolment's own prompt** (`PlatformKeyService`, the Secure Enclave) does not go
  through the coordinator, so it could in principle be raised while a release prompt is up.~~
  Folded in: `AppModel.enrollTouchID` now takes `PresenceCoordinator`'s slot (a new
  `PresenceOwner.enrolment`) around the whole `PlatformKeyService.enroll` call and registers its
  `LAContext` for `cancelInFlight()` to invalidate on a lock, even though the Secure Enclave's own
  key-creation prompt (ADR-0011) is not one the coordinator's `gate.authenticate` can drive
  directly — it can only serialise against it. A release or an approval refuses (`PresenceBusy`)
  while enrolment holds the slot, and enrolment itself refuses, not queues, while one of them
  holds it. It still releases no vault value.
- **A card number's last four digits** still ride on the item list's subtitle (ui-spec §3, by
  design before this ADR). Four digits, not the number, but a value nonetheless, shown without a
  touch.

## Amendment 2026-10-03 — releases ride the grace window

At the owner's direction (convenience over security), `AppPresenceGate` confirms a reveal, copy,
Quick Access, one-time code or any other release without a prompt while ADR-0037's
[app-wide grace window](0037-every-fill-needs-a-fresh-presence-proof.md#amendment-2026-10-03-app-wide-sliding-grace-window)
is open, extending it; a check that succeeds (including the master-password fallback) opens or
extends it. Rust still records each release; the window is cleared on every lock.

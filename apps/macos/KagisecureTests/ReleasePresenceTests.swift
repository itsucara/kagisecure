import AppKit
import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// ADR-0038 phase 2, the app's half: every value the app shows or copies comes from a release a
/// granted presence check produced, one touch reveals one field, and nothing is shown, copied or
/// kept when the check is refused or the vault locks under it.
///
/// Through the real FFI and a real vault, with a Swift `PresenceGate` double where the person
/// would be. Compiled with the suite; run under the project's GUI-test consent rule like the rest
/// of `KagisecureTests` (these touch `NSPasteboard.general`).
@MainActor
struct ReleasePresenceTests {
    // MARK: - The detail pane

    @Test func aCancelledRevealLeavesNothingShown() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.cancelled]))
        let releases = fx.store.releases
        releases.announce = { _ in }

        #expect(await refusal {
            try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        } == "PresenceCancelled")
        #expect(gate.calls == 1, "one reveal, one prompt")
        #expect(releases.fields.isEmpty, "a cancelled reveal shows nothing")
        #expect(releases.shownValue(fx.passwordField) == nil)
        #expect(releases.pending == nil, "and leaves the pane free for the next attempt")
    }

    @Test func oneTouchShowsOneFieldAndCopyingItNeedsNoSecondTouch() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        let releases = fx.store.releases
        var spoken: [String] = []
        releases.announce = { spoken.append($0) }
        var copied: [String] = []
        releases.copyToPasteboard = { value, _ in copied.append(value) }

        try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        #expect(releases.shownValue(fx.passwordField) == ReleaseFixture.password)
        #expect(spoken.last == "Password shown")

        // The shown value is copied from its own release: no new prompt (user decision 1).
        try await releases.copy(item: fx.item, field: fx.passwordField)
        #expect(copied == [ReleaseFixture.password])
        #expect(gate.calls == 1, "copying a shown value asks nobody")

        // A different field is a different touch — and the script has no second yes.
        #expect(await refusal {
            try await releases.showTotp(item: fx.item, field: fx.totpField)
        } == "PresenceCancelled")
        #expect(gate.calls == 2)
        #expect(!releases.isLive(totp: fx.totpField))

        // Toggling again hides it, and says so.
        try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        #expect(releases.fields.isEmpty)
        #expect(spoken.last == "Password hidden")
        #expect(gate.calls == 2, "hiding asks nobody")
    }

    @Test func aCancelledCopyLeavesThePasteboardUntouched() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([]))
        let releases = fx.store.releases
        releases.announce = { _ in }
        let stamp = NSPasteboard.general.changeCount

        #expect(await refusal {
            try await releases.copy(item: fx.item, field: fx.passwordField)
        } == "PresenceCancelled")
        #expect(await refusal {
            try await releases.copyTotp(item: fx.item, field: fx.totpField)
        } == "PresenceCancelled")
        #expect(await refusal {
            try await releases.copyFirstTotp(of: fx.item)
        } == "PresenceCancelled")
        #expect(await refusal {
            try await releases.copyNotes(item: fx.item)
        } == "PresenceCancelled")
        #expect(gate.calls == 4, "each copy asked once")
        #expect(
            NSPasteboard.general.changeCount == stamp,
            "a refused copy must not have written to the pasteboard at all")
    }

    @Test func theLiveCodeIsMaskedUntilTouchedThenCopiesWithoutASecondTouch() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        let releases = fx.store.releases
        releases.announce = { _ in }
        var copied: [String] = []
        releases.copyToPasteboard = { value, _ in copied.append(value) }

        #expect(releases.totpCode(fx.totpField, at: 1_700_000_000) == nil, "masked until touched")
        try await releases.showTotp(item: fx.item, field: fx.totpField)
        let code = try #require(releases.totpCode(fx.totpField, at: TotpCountdown.unixNow()))
        #expect(code.code.count == 6)

        // ⌥⌘C, the ring and the list row all copy the running code from its release.
        try await releases.copyTotp(item: fx.item, field: fx.totpField)
        try await releases.copyFirstTotp(of: fx.item)
        #expect(copied.count == 2)
        #expect(copied.allSatisfy { $0.count == 6 && !$0.contains("otpauth") })
        #expect(gate.calls == 1, "one touch started it; copying it asked nobody")
    }

    @Test func aDeselectHidesEverythingAndEndsItsRelease() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        try fx.install(ScriptedPresenceGate([.confirmed, .confirmed, .confirmed]))
        let releases = fx.store.releases
        releases.announce = { _ in }

        try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        try await releases.toggleNotes(item: fx.item)
        try await releases.showTotp(item: fx.item, field: fx.totpField)
        let shown = try #require(releases.fields[fx.passwordField.id])
        #expect(releases.notesText == ReleaseFixture.notes)

        fx.store.selectedItemId = nil
        #expect(releases.fields.isEmpty && releases.notes == nil && releases.totps.isEmpty)
        let release = try #require(shown.release as? FieldRelease)
        #expect(!release.isLive(), "the capability ends with the pixels")
        #expect(throws: FfiError.self) { try release.copyShownValue() }
    }

    @Test func anAnswerThatArrivesAfterTheItemWasLeftShowsNothing() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(HeldPresenceGate())
        let releases = fx.store.releases
        releases.announce = { _ in }

        let reveal = Task { try await releases.toggleReveal(item: fx.item, field: fx.passwordField) }
        #expect(await eventually { gate.isAsking })
        fx.store.selectedItemId = nil
        gate.answer(.confirmed)
        _ = try? await reveal.value
        #expect(releases.fields.isEmpty, "a touch for an item the person left shows nothing")
    }

    // MARK: - ⇧⌘C, "Copy Password"

    @Test func shiftCommandCCopiesTheUnshownPasswordWithOneTouch() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        let releases = fx.store.releases
        releases.announce = { _ in }
        var copied: [String] = []
        releases.copyToPasteboard = { value, _ in copied.append(value) }

        fx.store.copyPasswordForShortcut()
        #expect(await eventually { !copied.isEmpty })
        #expect(copied == [ReleaseFixture.password])
        #expect(gate.calls == 1, "⇧⌘C on an unshown password asks exactly once")
    }

    @Test func shiftCommandCCopiesAnAlreadyShownPasswordWithNoNewTouch() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        let releases = fx.store.releases
        releases.announce = { _ in }
        var copied: [String] = []
        releases.copyToPasteboard = { value, _ in copied.append(value) }

        try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        #expect(gate.calls == 1, "showing it first is its own touch")

        fx.store.copyPasswordForShortcut()
        #expect(await eventually { !copied.isEmpty })
        #expect(copied == [ReleaseFixture.password])
        #expect(gate.calls == 1, "⇧⌘C on a shown password asks zero additional times")
    }

    // MARK: - Quick Access

    @Test func quickAccessReturnAsksTheGateExactlyOnce() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        var copied: [(String, String)] = []
        let model = QuickAccessModel(session: fx.session, onDismiss: {})
        model.copyToPasteboard = { copied.append(($0, $1)) }
        model.toastDuration = { _ in .zero }
        model.query = "GitHub"

        await model.copyPassword()
        #expect(gate.calls == 1, "⏎ is one prompt")
        #expect(copied.map(\.0) == [ReleaseFixture.password])
        #expect(gate.reasons.first?.contains("from Quick Access") == true)
    }

    @Test func quickAccessOptionReturnAsksTheGateExactlyOnce() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        var copied: [String] = []
        let model = QuickAccessModel(session: fx.session, onDismiss: {})
        model.copyToPasteboard = { value, _ in copied.append(value) }
        model.toastDuration = { _ in .zero }
        model.query = "GitHub"

        await model.copyTotp()
        #expect(gate.calls == 1, "⌥⏎ is one prompt")
        #expect(copied.count == 1 && copied[0].count == 6, "the code, never the seed")
    }

    @Test func quickAccessCommandReturnAsksNothingAndACancelCopiesNothing() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let gate = try fx.install(ScriptedPresenceGate([.cancelled, .cancelled]))
        var copied: [String] = []
        let model = QuickAccessModel(session: fx.session, onDismiss: {})
        model.copyToPasteboard = { value, _ in copied.append(value) }
        model.toastDuration = { _ in .zero }
        model.query = "GitHub"

        model.copyUsername()
        #expect(gate.calls == 0, "⌘⏎ copies a public value: nothing to release")
        #expect(copied == ["ada"])

        await model.copyPassword()
        await model.copyTotp()
        #expect(gate.calls == 2)
        #expect(copied == ["ada"], "a cancelled ⏎ or ⌥⏎ copies nothing")
        #expect(model.toast == "Not confirmed — nothing copied")
    }

    /// ⏎, ⇧⌘C and ⌘R's unfocused fallback copy or show the field the vault designates as the
    /// password — by id — so a PIN relabelled "password" and moved first is never what they pick.
    @Test func aRelabelledAndReorderedPinIsNeverThePassword() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        // Add a PIN, then relabel it "password", rename the real one, and move the PIN first —
        // none of which asks for presence.
        let withPin = try fx.session.saveItem(draft: ItemDraft(
            id: fx.item.id, category: fx.item.category, title: fx.item.title,
            fields: fx.item.fields.map(Self.kept) + [
                FieldDraft(
                    id: nil, label: "PIN", kind: .concealed, concealed: true, value: "4321",
                    section: nil, agentVisible: false)
            ],
            tags: fx.item.tags, urls: fx.item.urls, notes: nil, revision: fx.item.revision))
        let pin = try #require(withPin.fields.first { $0.label == "PIN" })
        var fields = withPin.fields.map(Self.kept)
        for index in fields.indices {
            if fields[index].id == pin.id { fields[index].label = "password" }
            if fields[index].id == fx.passwordField.id { fields[index].label = "old" }
        }
        let moved = fields.remove(at: try #require(fields.firstIndex { $0.id == pin.id }))
        fields.insert(moved, at: 0)
        let hostile = try fx.session.saveItem(draft: ItemDraft(
            id: withPin.id, category: withPin.category, title: withPin.title, fields: fields,
            tags: withPin.tags, urls: withPin.urls, notes: nil, revision: withPin.revision))
        #expect(hostile.passwordField?.id == fx.passwordField.id)

        let gate = try fx.install(ScriptedPresenceGate([.confirmed]))
        var copied: [String] = []
        let model = QuickAccessModel(session: fx.session, onDismiss: {})
        model.copyToPasteboard = { value, _ in copied.append(value) }
        model.toastDuration = { _ in .zero }
        model.query = "GitHub"
        await model.copyPassword()
        #expect(copied == [ReleaseFixture.password], "⏎ copies the password, not the PIN")
        #expect(gate.reasons.first?.hasPrefix("copy the password “old”") == true)
    }

    /// ⌘⏎ copies a real username field and nothing else — with none, not the subtitle.
    @Test func commandReturnWithNoUsernameCopiesNothing() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        _ = try fx.session.saveItem(draft: ItemDraft(
            id: fx.item.id, category: fx.item.category, title: fx.item.title,
            fields: fx.item.fields.map(Self.kept).filter { $0.label != "username" },
            tags: fx.item.tags, urls: fx.item.urls, notes: nil, revision: fx.item.revision))
        var copied: [String] = []
        let model = QuickAccessModel(session: fx.session, onDismiss: {})
        model.copyToPasteboard = { value, _ in copied.append(value) }
        model.toastDuration = { _ in .zero }
        model.query = "GitHub"
        #expect(model.selectedItem?.subtitle == "https://github.com")
        model.copyUsername()
        #expect(copied.isEmpty, "the website in the subtitle is not a username")
        #expect(model.toast == "No username on this item")
    }

    /// A field draft that keeps the stored value.
    private static func kept(_ field: FieldView) -> FieldDraft {
        FieldDraft(
            id: field.id, label: field.label, kind: field.kind, concealed: field.concealed,
            value: field.concealed ? nil : field.value, section: field.section,
            agentVisible: field.agentVisible)
    }

    // MARK: - A lock while the prompt is up

    @Test func aLockDuringThePromptReleasesNothing() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        // The whole app chain: Rust → `AppPresenceGate` → `PresenceCoordinator` → a biometric
        // that stays up until the test answers it, the way a Touch ID sheet does.
        let biometric = BiometricGateAdversarialTests.HeldGate()
        let coordinator = PresenceCoordinator(gate: biometric)
        let fallback = MasterPasswordFallback()
        try fx.session.setPresenceGate(
            gate: AppPresenceGate(coordinator: coordinator, fallback: fallback, session: fx.session))
        let releases = fx.store.releases
        releases.announce = { _ in }
        let stamp = NSPasteboard.general.changeCount

        let reveal = Task { try await releases.toggleReveal(item: fx.item, field: fx.passwordField) }
        let copy = Task { try await releases.copy(item: fx.item, field: fx.totpField) }
        #expect(await eventually { biometric.parked == 1 }, "the prompt is up")

        // What `AppModel.lock` does, in its order.
        releases.hideAll(because: .locked)
        fx.session.lock()
        coordinator.cancelInFlight()
        #expect(biometric.cancels == 1, "the lock reaches the LAContext that is up")

        // The person touches the sensor anyway, a moment too late.
        biometric.release(.authenticated)
        #expect(await refusal { try await reveal.value } == "VaultLocked")
        _ = try? await copy.value
        #expect(releases.fields.isEmpty, "nothing shown")
        #expect(NSPasteboard.general.changeCount == stamp, "nothing copied")
        #expect(biometric.calls == 1, "one prompt, never two")
        #expect(await eventually { !coordinator.isBusy }, "the slot frees once the prompt is gone")
    }

    // MARK: - One prompt at a time, app-wide

    @Test func aSecondPromptIsRefusedNotQueued() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let biometric = TestBiometricGate(.authenticated)
        let coordinator = PresenceCoordinator(gate: biometric)
        try fx.session.setPresenceGate(
            gate: AppPresenceGate(
                coordinator: coordinator, fallback: MasterPasswordFallback(), session: fx.session))

        // An approval's prompt holds the slot — the sheet's Allow, or a presence-only fill.
        let held = try #require(coordinator.begin(.approval("ks-approval")))
        #expect(coordinator.begin(.release) == nil, "no second slot")

        let releases = fx.store.releases
        releases.announce = { _ in }
        #expect(await refusal {
            try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        } == "PresenceBusy")
        #expect(biometric.reasons.isEmpty, "refused before anything was raised, not queued")

        coordinator.end(held)
        try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        #expect(biometric.reasons.count == 1)
        #expect(releases.shownValue(fx.passwordField) == ReleaseFixture.password)
    }

    /// Touch ID enrolment (`AppModel.enrollTouchID`, ADR-0004/ADR-0011) takes the same slot a
    /// release or an approval does, even though it never calls `gate.authenticate` — the Secure
    /// Enclave can raise its own prompt at key creation, which the coordinator has no way to drive
    /// directly, only to serialise against. Both directions: a release refuses while enrolment
    /// holds the slot, and enrolment refuses while a release holds it.
    @Test func enrolmentAndAReleaseRefuseEachOtherRatherThanStack() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let biometric = TestBiometricGate(.authenticated)
        let coordinator = PresenceCoordinator(gate: biometric)
        try fx.session.setPresenceGate(
            gate: AppPresenceGate(
                coordinator: coordinator, fallback: MasterPasswordFallback(), session: fx.session))
        let releases = fx.store.releases
        releases.announce = { _ in }

        // Enrolment holds the slot: a release is refused, not queued behind it.
        let enrolling = try #require(coordinator.begin(.enrolment))
        #expect(await refusal {
            try await releases.toggleReveal(item: fx.item, field: fx.passwordField)
        } == "PresenceBusy")
        coordinator.end(enrolling)

        // A release holds the slot: enrolment's own `begin` is refused too.
        let releasing = try #require(coordinator.begin(.release))
        #expect(coordinator.begin(.enrolment) == nil, "enrolment does not queue behind a release")
        coordinator.end(releasing)

        // With the slot free again, enrolment can take it.
        #expect(coordinator.begin(.enrolment) != nil)
    }

    // MARK: - The master-password fallback (user decision 7)

    @Test func theMasterPasswordFallbackHonoursTheBackOffAndIsAuditedAsSuch() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let coordinator = PresenceCoordinator(
            gate: TestBiometricGate(.unavailable("no authentication method available")))
        let fallback = MasterPasswordFallback()
        var presented = 0
        fallback.present = { _ in presented += 1 }
        try fx.session.setPresenceGate(
            gate: AppPresenceGate(coordinator: coordinator, fallback: fallback, session: fx.session))
        let releases = fx.store.releases
        releases.announce = { _ in }

        let reveal = Task { try await releases.toggleReveal(item: fx.item, field: fx.passwordField) }
        #expect(await eventually { fallback.request != nil }, "the panel is up")
        #expect(presented == 1)
        #expect(coordinator.isBusy, "the fallback holds the one prompt slot")

        fallback.submit("not the master password")
        #expect(await eventually { fallback.message != nil })
        #expect(fallback.message?.contains("Try again in 1 second") == true)
        #expect(fallback.isWaiting(at: .now), "Confirm waits out Rust's back-off")

        // Inside the back-off nothing is checked, not even the right password.
        fallback.submit(ReleaseFixture.master)
        #expect(fallback.request != nil)

        try await Task.sleep(for: .milliseconds(1_100))
        #expect(!fallback.isWaiting(at: .now))
        fallback.submit(ReleaseFixture.master)
        try await reveal.value
        #expect(releases.shownValue(fx.passwordField) == ReleaseFixture.password)
        #expect(fallback.request == nil, "the panel is gone")
        #expect(!coordinator.isBusy)

        let rows = fx.session.auditPage(limit: 2, offset: 0)
        #expect(rows.first?.detail == "PRESENCE_CONFIRMED_MASTER_PASSWORD")
        #expect(rows.last?.detail == "MASTER_PASSWORD_WRONG")
    }

    @Test func aLockClosesTheFallbackAndConfirmsNothing() async throws {
        let fx = try ReleaseFixture()
        defer { fx.remove() }
        let coordinator = PresenceCoordinator(gate: TestBiometricGate(.unavailable("none")))
        let fallback = MasterPasswordFallback()
        var dismissed = 0
        fallback.dismiss = { dismissed += 1 }
        coordinator.addCancelHandler { fallback.cancel() }
        try fx.session.setPresenceGate(
            gate: AppPresenceGate(coordinator: coordinator, fallback: fallback, session: fx.session))
        let releases = fx.store.releases
        releases.announce = { _ in }

        let reveal = Task { try await releases.toggleReveal(item: fx.item, field: fx.passwordField) }
        #expect(await eventually { fallback.request != nil })
        fx.session.lock()
        coordinator.cancelInFlight()
        #expect(await refusal { try await reveal.value } == "VaultLocked")
        #expect(dismissed == 1)
        #expect(fallback.request == nil)
        #expect(releases.fields.isEmpty)
    }

    // MARK: - Source scans

    @Test func noAuthenticationContextIsGivenAReuseWindow() throws {
        for file in AppSources.swiftFiles(in: "Kagisecure") {
            let code = try AppSources.code(of: file)
            #expect(
                !code.contains("touchIDAuthenticationAllowableReuseDuration"),
                "\(file.lastPathComponent) sets a Touch ID reuse window: one touch would pay for later releases")
        }
    }

    @Test func noReleasedValueIsSelectable() throws {
        // Every view that renders a released value, and every model that holds one. The one
        // legitimate `.textSelection` in the item views is `PublicFieldText`, for public values.
        let rendersReleases = [
            "Views/ItemDetailView.swift", "Views/TotpFieldView.swift", "Views/ItemEditView.swift",
            "Views/ItemListView.swift", "Views/QuickAccessView.swift",
            "Models/ItemReleases.swift", "Models/QuickAccessModel.swift",
            "Services/MasterPasswordFallback.swift",
        ]
        for relative in rendersReleases {
            let url = AppSources.root.appendingPathComponent("Kagisecure/\(relative)")
            let code = try AppSources.code(of: url)
            #expect(
                !code.contains(".textSelection"),
                "\(relative) makes text selectable: ⌘C, a drag or Services would bypass the concealed pasteboard (ADR-0038 surface #2)")
        }
        let publicText = try AppSources.code(
            of: AppSources.root.appendingPathComponent("Kagisecure/Views/PublicFieldText.swift"))
        #expect(!publicText.contains("Release"), "PublicFieldText is for public values only")
    }

    @Test func nothingCallsTheRemovedUngatedCalls() throws {
        // ADR-0038 phase 2 removed `reveal_field`, `reveal_notes`, `totp_code` and
        // `item_totp_code` from the FFI, so a caller left anywhere is a compile error. This pins
        // it from the other side: the generated bindings no longer declare them, and nothing in
        // the app or its tests names them — a reintroduction has to delete this test to land.
        let removed = ["revealField(", "revealNotes(", "totpCode(itemId", "itemTotpCode("]
        let bindings = AppSources.root.appendingPathComponent(
            "KagisecureFFI/Sources/KagisecureFFI/kagisecure_ffi.swift")
        let generated = try String(contentsOf: bindings, encoding: .utf8)
        for name in removed {
            #expect(!generated.contains("func \(name)"), "the bindings still declare \(name)")
        }
        let scanned = AppSources.swiftFiles(in: "Kagisecure")
            + AppSources.swiftFiles(in: "KagisecureTests")
            + AppSources.swiftFiles(in: "KagisecureUITests")
        for file in scanned where file.lastPathComponent != "ReleasePresenceTests.swift" {
            let code = try AppSources.code(of: file)
            for name in removed {
                #expect(
                    !code.contains(".\(name)"),
                    "\(file.lastPathComponent) calls the removed, ungated \(name)")
            }
        }
    }
}

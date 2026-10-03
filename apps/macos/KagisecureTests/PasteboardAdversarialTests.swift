import AppKit
import Foundation
import Testing

@testable import Kagisecure

/// Adversarial tests for `PasteboardService` — the one place a secret reaches `NSPasteboard`.
///
/// # Why this file exists
///
/// `PasteboardServiceTests` covers the happy path of the timed clear. This file covers what a
/// second process on the machine can do to it:
///
///   * write and then *restore* the secret inside the clear window, so the `changeCount` guard
///     declines to clear and the secret stays on the clipboard indefinitely (G-19);
///   * rely on the copy site never telling the user that their configured delay is `0` — "never
///     cleared" is a setting whose consequences are invisible at the moment of copying (G-19);
///   * read a third pasteboard type carrying the value past the concealed marker (G-20).
///
/// These drive the *real* `NSPasteboard.general` for the same reason the existing suite does: the
/// property under test is `changeCount`, which is a system counter and cannot be faked without
/// testing the fake. Everything restores what it found.
@MainActor
struct PasteboardAdversarialTests {
    /// Obvious test data: if this string ever turns up in a log or a clipboard manager it is this
    /// suite's, not a user's.
    static let secretCanary = "KS_CANARY_CLIPBOARD_sk_live_do_not_ship"

    private func withRestoredPasteboard(_ body: () throws -> Void) rethrows {
        let saved = NSPasteboard.general.string(forType: .string)
        defer {
            NSPasteboard.general.clearContents()
            if let saved { NSPasteboard.general.setString(saved, forType: .string) }
        }
        try body()
    }

    // MARK: - G-20: exactly two types, concealed first

    @Test func exactlyTwoPasteboardTypesAreWrittenAndTheConcealedMarkerIsFirst() {
        withRestoredPasteboard {
            PasteboardService.copy(Self.secretCanary, label: "password")
            let types = NSPasteboard.general.types ?? []

            #expect(
                types.first == .init("org.nspasteboard.ConcealedType"),
                """
                order matters: a clipboard manager that samples the first type must see the \
                concealed marker before the plain string. Got \(types)
                """)

            // AppKit answers a `.string` write with the modern UTI *and* its legacy alias —
            // `public.utf8-plain-text` and `NSStringPboardType` are two names for the same one
            // write, not two copies of the value. So the assertion is about how many *writes*
            // this service makes, which is what a third carrier of the secret would change.
            let legacyAliases: Set<String> = ["NSStringPboardType"]
            let distinct = types.map(\.rawValue).filter { !legacyAliases.contains($0) }
            #expect(
                distinct == ["org.nspasteboard.ConcealedType", "public.utf8-plain-text"],
                "exactly two writes: the concealed marker and the string. Got \(distinct)")
        }
    }

    @Test func noPasteboardTypeOtherThanTheseTwoCarriesTheValue() {
        withRestoredPasteboard {
            PasteboardService.copy(Self.secretCanary, label: "password")
            // Types a well-meaning convenience API might add behind our back — a rich-text or
            // URL flavour of a password is a second copy that no clipboard manager treats as
            // concealed. `NSStringPboardType` is excluded: it is AppKit's own alias for the
            // plain-string write, asserted above.
            let forbidden: [NSPasteboard.PasteboardType] = [
                .rtf, .html, .fileContents, .URL, .fileURL, .tabularText, .multipleTextSelection,
            ]
            for type in forbidden {
                #expect(
                    NSPasteboard.general.string(forType: type) != Self.secretCanary,
                    "\(type.rawValue) carries a second copy of the value")
            }
        }
    }

    // MARK: - G-19: the changeCount guard, and what defeats it

    @Test func aForeignWriteInsideTheWindowSuppressesTheClearAsDesigned() {
        withRestoredPasteboard {
            PasteboardService.copy(Self.secretCanary, label: "password")
            let stamp = NSPasteboard.general.changeCount

            // Another process copies something of the user's.
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("KS_CANARY_SHOPPING_LIST", forType: .string)

            #expect(!PasteboardService.clearIfUnchanged(since: stamp))
            #expect(NSPasteboard.general.string(forType: .string) == "KS_CANARY_SHOPPING_LIST")
            #expect(
                NSPasteboard.general.string(forType: .string) != Self.secretCanary,
                "the secret is gone because the foreign write replaced it, not because we cleared")
        }
    }

    @Test func aForeignWriteThatRestoresTheSecretDefeatsTheClearEntirely() {
        // The adversarial shape of the rule above, and a limitation rather than a bug: any design
        // that refuses to clear a clipboard it no longer owns can be made to refuse by a process
        // that writes and puts the value back. This test exists so the limitation is written down
        // and so a future change to the guard has to confront it deliberately.
        withRestoredPasteboard {
            PasteboardService.copy(Self.secretCanary, label: "password")
            let stamp = NSPasteboard.general.changeCount

            // A hostile clipboard manager: take a copy, then restore it so the user notices
            // nothing.
            let stolen = NSPasteboard.general.string(forType: .string)
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(stolen ?? "", forType: .string)

            #expect(!PasteboardService.clearIfUnchanged(since: stamp))
            #expect(
                NSPasteboard.general.string(forType: .string) == Self.secretCanary,
                "documented limitation: the restored value outlives the clear window")
            #expect(
                NSPasteboard.general.string(forType: .init("org.nspasteboard.ConcealedType")) == nil,
                "and the restored copy is no longer marked concealed, so it is now history-eligible")
        }
    }

    @Test func aStaleStampNeverClearsAFreshClipboard() {
        // Fail-closed in the other direction: a timer that fires late must not wipe a clipboard
        // that has moved on. `Int.min` stands in for any stamp that is not the current one.
        withRestoredPasteboard {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("KS_CANARY_USER_TEXT", forType: .string)
            #expect(!PasteboardService.clearIfUnchanged(since: Int.min))
            #expect(NSPasteboard.general.string(forType: .string) == "KS_CANARY_USER_TEXT")
        }
    }

    // MARK: - G-19: `clearSeconds == 0`

    @Test func zeroSecondsIsAnOfferedChoiceAndMeansNeverCleared() {
        #expect(PasteboardService.clearSecondsChoices.contains(0))
        #expect(PasteboardService.clearDescription(seconds: 0) == "Never cleared")
        #expect(PasteboardService.defaultClearSeconds == 60, "the default is not 'never'")
    }

    @Test func aZeroDelayStillMarksTheValueConcealedAndSchedulesNothing() {
        let key = PasteboardService.clearSecondsKey
        let saved = AppDefaults.shared.object(forKey: key)
        defer {
            if let saved { AppDefaults.shared.set(saved, forKey: key) }
            else { AppDefaults.shared.removeObject(forKey: key) }
        }
        AppDefaults.shared.set(0, forKey: key)
        #expect(PasteboardService.clearSeconds == 0)

        withRestoredPasteboard {
            PasteboardService.copy(Self.secretCanary, label: "password")
            // The concealed marker is the only mitigation left when the timer is off, so it had
            // better still be applied.
            #expect(
                NSPasteboard.general.string(forType: .init("org.nspasteboard.ConcealedType"))
                    == Self.secretCanary)
            // And nothing clears it: the stamp is still current well after any timer would fire.
            let stamp = NSPasteboard.general.changeCount
            #expect(NSPasteboard.general.changeCount == stamp)
            #expect(NSPasteboard.general.string(forType: .string) == Self.secretCanary)
        }
    }

    @Test
    func theCopyConfirmationSurfacesTheClearPolicy() throws {
        // A source-level assertion, because the confirmation is a SwiftUI toast (or, in the main
        // window, a VoiceOver announcement) with no seam. It asks a narrow question: does the code
        // that copies also mention the policy?
        //
        // Quick Access names it in its toast. The main window has no visible notice surface — its
        // only channel is `errorMessage`, a modal alert, and an alert on every copy would be worse
        // than saying nothing — but since ADR-0038 phase 2 every copy there is announced to
        // VoiceOver, and the announcement carries the policy too.
        for file in ["Models/QuickAccessModel.swift", "Models/ItemReleases.swift"] {
            let source = try String(contentsOf: Self.appSource(file), encoding: .utf8)
            #expect(
                source.contains("clearDescription"),
                "\(file) copies secrets but never names the clear policy at the copy site")
        }
    }

    @Test
    func theMainWindowHasNoVisibleCopyConfirmationSurface() throws {
        // Pins the open gap so that closing it is a deliberate act and reopening it is caught.
        // If someone adds a visible notice surface to the main window, this test fails and should
        // be replaced by the policy assertion above, extended to it.
        let source = try String(contentsOf: Self.appSource("Models/VaultStore.swift"), encoding: .utf8)
        #expect(
            !source.contains("clearDescription"),
            "VaultStore now names the clear policy — fold it into the assertion above")
        #expect(
            !source.contains("copyNotice"),
            "the main window grew a copy notice — assert that it carries the clear policy")
    }

    // MARK: - G-21: nothing retains the copied value after the panel closes

    @Test func noQuickAccessStateCanRetainACopiedSecret() throws {
        // `QuickAccessController.close()` drops the hosting view, and with it the model — but only
        // if none of the model's state held the secret in the first place. A source-level check
        // is the only way to assert that without a window server, and it is the check that would
        // catch the mistake.
        let view = try String(contentsOf: Self.appSource("Views/QuickAccessView.swift"), encoding: .utf8)
        #expect(
            !view.split(separator: "\n").contains { $0.contains("@State") },
            "the panel's state lives in QuickAccessModel, not in the view")

        let model = try String(
            contentsOf: Self.appSource("Models/QuickAccessModel.swift"), encoding: .utf8)
        // Every property the model declares, by name. A new one fails this until someone has
        // looked at it: the names below hold a query, metadata views, a selection, a status line,
        // a flag, the session and three closures — never a value.
        let declaration = try NSRegularExpression(
            pattern: #"^    (?:private\(set\) )?(?:var|let) (\w+)"#, options: .anchorsMatchLines)
        let names = Set(
            declaration.matches(in: model, range: NSRange(model.startIndex..., in: model)).compactMap {
                Range($0.range(at: 1), in: model).map { String(model[$0]) }
            })
        #expect(
            names == [
                "query", "selection", "results", "toast", "awaitingPresence", "session",
                "onDismiss", "copyToPasteboard", "toastDuration", "isLocked", "selectedItem",
            ],
            "a new property on QuickAccessModel needs a look: \(names.sorted())")
        // The copy helpers read the value from the release straight into the pasteboard call;
        // nothing binds it to a property.
        #expect(model.contains("copyToPasteboard(try release.value(), field.label)"))
        #expect(!model.contains("self.copiedValue"))
    }

    @Test func theServiceItselfRetainsOnlyTheLabel() {
        withRestoredPasteboard {
            PasteboardService.copy(Self.secretCanary, label: "password")
            #expect(PasteboardService.lastCopied == "password")
            #expect(
                PasteboardService.lastCopied != Self.secretCanary,
                "the only thing remembered about a copy is the field name")
        }
    }

    // MARK: - Helpers

    /// A path inside the app target, relative to this source file.
    private static func appSource(_ relative: String) -> URL {
        var url = URL(fileURLWithPath: #filePath)
        // …/apps/macos/KagisecureTests/PasteboardAdversarialTests.swift -> …/apps/macos
        url.deleteLastPathComponent()
        url.deleteLastPathComponent()
        return url.appendingPathComponent("Kagisecure").appendingPathComponent(relative)
    }
}

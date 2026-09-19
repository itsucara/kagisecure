import AppKit
import Foundation
import Testing

@testable import Kagisecure

/// The timed clipboard clear (ui-spec.md §11's copy actions, ADR-0017).
///
/// These touch the *real* `NSPasteboard.general`, because a fake one would only prove the fake
/// works — and the whole property under test is about `changeCount`, which is a system counter.
/// They restore what they found, so running the suite does not silently eat whatever the person
/// running it had on their clipboard.
@MainActor
struct PasteboardServiceTests {
    private func withRestoredPasteboard(_ body: () throws -> Void) rethrows {
        let saved = NSPasteboard.general.string(forType: .string)
        defer {
            NSPasteboard.general.clearContents()
            if let saved {
                NSPasteboard.general.setString(saved, forType: .string)
            }
        }
        try body()
    }

    @Test func copyingMarksTheValueConcealedForClipboardManagers() throws {
        withRestoredPasteboard {
            PasteboardService.copy("hunter2", label: "password")
            #expect(NSPasteboard.general.string(forType: .string) == "hunter2")
            #expect(
                NSPasteboard.general.string(forType: .init("org.nspasteboard.ConcealedType"))
                    == "hunter2",
                "without this marker the value lands in clipboard-manager history")
            #expect(PasteboardService.lastCopied == "password", "the label is metadata")
        }
    }

    @Test func theClearHappensWhenNothingElseHasWritten() throws {
        withRestoredPasteboard {
            PasteboardService.copy("ephemeral", label: "password")
            let stamp = NSPasteboard.general.changeCount
            #expect(PasteboardService.clearIfUnchanged(since: stamp))
            #expect(NSPasteboard.general.string(forType: .string) == nil)
        }
    }

    @Test func theClearIsSkippedWhenSomethingElseHasWritten() throws {
        withRestoredPasteboard {
            PasteboardService.copy("ephemeral", label: "password")
            let stamp = NSPasteboard.general.changeCount

            // Somebody else — the user, another app — copies afterwards.
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("a shopping list", forType: .string)

            #expect(!PasteboardService.clearIfUnchanged(since: stamp))
            #expect(
                NSPasteboard.general.string(forType: .string) == "a shopping list",
                "clearing unconditionally would throw away the user's own clipboard")
        }
    }

    @Test func theDelayIsConfigurableAndDescribesItself() {
        #expect(PasteboardService.defaultClearSeconds == 60)
        #expect(PasteboardService.clearSecondsChoices.contains(0), "off must be offered")
        #expect(PasteboardService.clearDescription(seconds: 0) == "Never cleared")
        #expect(PasteboardService.clearDescription(seconds: 60) == "Cleared after 1 minute")
        #expect(PasteboardService.clearDescription(seconds: 300) == "Cleared after 5 minutes")
        #expect(PasteboardService.clearDescription(seconds: 15) == "Cleared after 15 seconds")
    }
}

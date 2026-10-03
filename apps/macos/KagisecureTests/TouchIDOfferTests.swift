import Foundation
import Testing

@testable import Kagisecure

/// Touch ID on by default (ADR-0004 amendment 2026-10-04): what follows a password unlock.
struct TouchIDOfferTests {
    @Test func autoEnrolsWhenAvailableAndNeverTurnedOff() {
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, explicitlyOff: false, dontAskAgain: false) == .autoEnrol)
        // "Don't show again" only silences the prompt; it never blocks the default.
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, explicitlyOff: false, dontAskAgain: true) == .autoEnrol)
    }

    @Test func promptsWhenTurnedOffExplicitly() {
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, explicitlyOff: true, dontAskAgain: false) == .prompt)
    }

    @Test func nothingWhenTurnedOffAndDontAskAgain() {
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, explicitlyOff: true, dontAskAgain: true) == .nothing)
    }

    @Test func nothingWhenAlreadyEnrolledOrUnavailable() {
        for off in [false, true] {
            for dont in [false, true] {
                #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: true, explicitlyOff: off, dontAskAgain: dont) == .nothing)
                #expect(TouchIDOffer.decide(available: false, hasPlatformSlot: false, explicitlyOff: off, dontAskAgain: dont) == .nothing)
            }
        }
    }

    @Test func failedAutoEnrolFallsBackToPrompt() {
        #expect(TouchIDOffer.afterFailedAutoEnrol(dontAskAgain: false) == .prompt)
        #expect(TouchIDOffer.afterFailedAutoEnrol(dontAskAgain: true) == .nothing)
    }

    @Test func readsPersistedFlagsFromDefaults() throws {
        let name = "ks.test.touchIdOffer.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, defaults: defaults) == .autoEnrol)
        defaults.set(true, forKey: TouchIDOffer.explicitlyOffKey)
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, defaults: defaults) == .prompt)
        defaults.set(true, forKey: TouchIDOffer.dontAskAgainKey)
        #expect(TouchIDOffer.decide(available: true, hasPlatformSlot: false, defaults: defaults) == .nothing)
    }
}

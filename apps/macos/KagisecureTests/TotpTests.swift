import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The countdown arithmetic and the app-side TOTP path (ui-spec.md §4.2, §9).
///
/// The roadmap's acceptance criterion is that the ring "regenerates the code exactly at period
/// boundaries, with no visible drift after a 10-minute soak test". A ten-minute soak is not a
/// unit test, so the property it is really about — that every render is computed from the wall
/// clock rather than from a count of ticks — is asserted here by sweeping ten minutes of
/// timestamps in a loop and checking the code changes exactly at the boundaries.
@MainActor
struct TotpTests {
    static let uri = "otpauth://totp/ACME:ada@example.com"
        + "?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30"

    private static func newVault() throws -> VaultSession {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-totp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return try VaultSession.create(
            path: directory.appendingPathComponent("t.kagivault").path,
            masterPassword: "correct horse battery staple",
            vaultName: "Personal", kdfMKib: 8, kdfT: 1)
    }

    // MARK: - Countdown arithmetic

    @Test func theRingEmptiesOverThePeriodAndNeverQuiteReachesZero() {
        #expect(TotpCountdown.fraction(secondsRemaining: 30, period: 30) == 1.0)
        #expect(TotpCountdown.fraction(secondsRemaining: 15, period: 30) == 0.5)
        #expect(TotpCountdown.fraction(secondsRemaining: 1, period: 30) > 0)
        // A code with one second left is still usable, so the ring is not empty.
        #expect(TotpCountdown.fraction(secondsRemaining: 1, period: 30) == 1.0 / 30.0)
    }

    @Test func theFractionIsClampedRatherThanTrusted() {
        #expect(TotpCountdown.fraction(secondsRemaining: 99, period: 30) == 1.0)
        #expect(TotpCountdown.fraction(secondsRemaining: 5, period: 0) == 0)
    }

    @Test func theWarningStateTurnsOnInTheLastFiveSeconds() {
        #expect(!TotpCountdown.isExpiring(secondsRemaining: 6))
        #expect(TotpCountdown.isExpiring(secondsRemaining: 5))
        #expect(TotpCountdown.isExpiring(secondsRemaining: 1))
    }

    @Test func codesAreGroupedForReading() {
        #expect(TotpCountdown.grouped("123456") == "123 456")
        #expect(TotpCountdown.grouped("12345678") == "1234 5678")
        #expect(TotpCountdown.grouped("1234567") == "123 456 7")
    }

    // MARK: - The code itself

    @Test func aPreviewIsStableInsideAWindowAndChangesAtTheBoundary() throws {
        // 1_700_000_000 % 30 == 20, so this window runs 1_699_999_980...1_700_000_009.
        let start = try totpPreview(uri: Self.uri, at: 1_699_999_980)
        let end = try totpPreview(uri: Self.uri, at: 1_700_000_009)
        let next = try totpPreview(uri: Self.uri, at: 1_700_000_010)
        #expect(start.code == end.code)
        #expect(end.code != next.code)
        #expect(start.secondsRemaining == 30)
        #expect(end.secondsRemaining == 1)
        #expect(next.secondsRemaining == 30)
    }

    /// Ten minutes of one-second renders, with no drift, in a few milliseconds.
    @Test func tenMinutesOfRendersChangeOnlyAtPeriodBoundaries() throws {
        let base: UInt64 = 1_700_000_010  // the top of a window
        var previous = try totpPreview(uri: Self.uri, at: base).code
        var changes = 0
        for offset in 1...600 {
            let at = base + UInt64(offset)
            let view = try totpPreview(uri: Self.uri, at: at)
            let snapshot = TotpSnapshot(view)
            let isBoundary = at % 30 == 0
            if view.code != previous {
                changes += 1
                #expect(isBoundary, "the code changed at \(at), which is not a boundary")
            }
            #expect(
                isBoundary ? snapshot.secondsRemaining == 30 : snapshot.secondsRemaining < 30,
                "seconds remaining was \(snapshot.secondsRemaining) at \(at)")
            #expect(snapshot.fraction > 0 && snapshot.fraction <= 1)
            previous = view.code
        }
        #expect(changes == 20, "ten minutes at 30 s per window is 20 rollovers, saw \(changes)")
    }

    @Test func aSnapshotDerivesEverythingTheRingNeeds() throws {
        let snapshot = TotpSnapshot(try totpPreview(uri: Self.uri, at: 1_700_000_005))
        #expect(snapshot.period == 30)
        #expect(snapshot.secondsRemaining == 5)
        #expect(snapshot.isExpiring)
        #expect(snapshot.caption == "ACME · ada@example.com")
        #expect(snapshot.grouped.contains(" "))
        #expect(snapshot.code.count == 6)
    }

    // MARK: - Setup and storage

    @Test func manualEntryAndAPastedUriProduceTheSameCode() throws {
        let manual = try totpUriFromParts(
            secretBase32: "jbsw y3dp ehpk 3pxp",
            params: TotpParamsView(
                algorithm: .sha1, digits: 6, period: 30, issuer: "ACME",
                account: "ada@example.com", caption: nil))
        #expect(
            try totpPreview(uri: manual, at: 1_700_000_000).code
                == totpPreview(uri: Self.uri, at: 1_700_000_000).code)
    }

    @Test func aBadUriIsRejectedBeforeAnythingIsStored() {
        #expect(!totpUriIsValid(uri: ""))
        #expect(!totpUriIsValid(uri: "otpauth://totp/x?secret=!!!!"))
        #expect(!totpUriIsValid(uri: "https://example.com"))
        #expect(totpUriIsValid(uri: Self.uri))
    }

    @Test func aStoredTotpFieldIsSecretAndStillProducesACode() throws {
        let session = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let item = try #require(store.selectedItem)
        let totpField = try #require(item.fields.first { $0.kind == FieldKind.totp })

        var draft = ItemDraft(
            id: item.id, category: item.category, title: item.title,
            fields: item.fields.map {
                FieldDraft(
                    id: $0.id, label: $0.label, kind: $0.kind, concealed: $0.concealed,
                    value: $0.id == totpField.id ? Self.uri : ($0.value ?? ""),
                    section: $0.section, agentVisible: $0.agentVisible)
            },
            tags: [], urls: [], notes: nil)
        draft.title = "GitHub"
        try store.save(draft: draft)

        let saved = try #require(store.selectedItem)
        let field = try #require(saved.fields.first { $0.kind == FieldKind.totp })
        #expect(field.concealed, "a TOTP seed is secret material")
        #expect(field.hasValue)
        #expect(field.value == nil, "the seed must not ride along on a rendered field list")

        let code = try session.totpCode(itemId: saved.id, fieldId: field.id, at: 1_700_000_000)
        #expect(code.code.count == 6)
        #expect(code.params.issuer == "ACME")

        // The item-level lookup — what Quick Access's ⌥⏎ and the list's hover action use.
        let byItem = try #require(try session.itemTotpCode(itemId: saved.id, at: 1_700_000_000))
        #expect(byItem.code == code.code)
    }

    @Test func anItemWithNoOneTimePasswordReportsNothingRatherThanFailing() throws {
        let session = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "secure-note")
        let item = try #require(store.selectedItem)
        #expect(try session.itemTotpCode(itemId: item.id, at: 0) == nil)
    }
}

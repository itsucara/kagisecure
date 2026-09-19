import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The import sheet's state machine (import.md §8), against a real vault and the real FFI.
///
/// Nothing here fakes a session or a plan. What the sheet renders is whatever
/// `kagisecure-import` produced, and a double would only prove that Swift agrees with Swift.
///
/// Note what these cannot cover yet: the 1PUX and CSV parsers are stubs that refuse every file
/// (WP1 and WP2 of the import plan), so the *successful* paths — a preview with counts, a commit,
/// the shred prompt — are exercised on the Rust side in `kagisecure-ffi`'s own tests, which build
/// a plan directly. Here that is the refusal path, plus the parts of the model that do not need a
/// parser.
@MainActor
struct ImportModelTests {
    private static func newVault() throws -> (VaultSession, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-import-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("test.kagivault")
        let session = try VaultSession.create(
            path: path.path, masterPassword: "correct horse battery staple",
            vaultName: "Personal", kdfMKib: 8, kdfT: 1)
        return (session, directory)
    }

    @Test func startsIdleAndNamesTheFileItWasGiven() throws {
        let (session, directory) = try Self.newVault()
        let model = ImportModel(
            session: session, sourcePath: directory.appendingPathComponent("export.1pux").path)

        guard case .idle = model.phase else {
            Issue.record("a model that has not been asked to load anything is idle")
            return
        }
        #expect(model.sourceName == "export.1pux")
        #expect(!model.canImport, "there is nothing to import before a file has been read")
        #expect(!model.hasCommitted)
        #expect(model.report == nil)
        #expect(model.outcome == nil)
    }

    @Test func offersEveryFormatTheCoreKnows() throws {
        let (session, directory) = try Self.newVault()
        let model = ImportModel(session: session, sourcePath: directory.path)
        // The picker is built from the core's list, so this is the list `--format` accepts.
        #expect(model.formats.map(\.id) == ["1pux", "apple-csv", "chromium-csv", "firefox-csv", "1password-csv"])
        #expect(model.formats.allSatisfy { !$0.displayName.isEmpty })
    }

    @Test func aFileThatCannotBeReadFailsWithAMessageAndNoPlan() throws {
        let (session, directory) = try Self.newVault()
        let missing = directory.appendingPathComponent("nowhere.csv").path
        let model = ImportModel(session: session, sourcePath: missing)

        model.load()

        guard case .failed(let message) = model.phase else {
            Issue.record("a missing file must leave the sheet in its error state")
            return
        }
        #expect(!message.isEmpty)
        #expect(model.plan == nil)
        #expect(!model.canImport, "the Import button stays disabled after a failure")
        #expect(model.report == nil)
    }

    @Test func theShredWarningIsOnTheModelBeforeAnythingIsDeleted() throws {
        let (session, directory) = try Self.newVault()
        let model = ImportModel(session: session, sourcePath: directory.path)
        // The prompt shows this *before* the button exists to press, so the offer is never made
        // as though it were a secure erase (import.md §9).
        #expect(model.shredWarning.lowercased().contains("best effort"))
        #expect(!model.shredWarning.lowercased().contains("secure erase"))
    }

    @Test func shreddingIsIgnoredUnlessTheSheetIsActuallyAskingAboutIt() throws {
        let (session, directory) = try Self.newVault()
        let file = directory.appendingPathComponent("export.csv")
        try "title,url,username,password\n".write(to: file, atomically: true, encoding: .utf8)
        let model = ImportModel(session: session, sourcePath: file.path)

        // No commit has happened, so there is no prompt and nothing to act on. A model that
        // deleted the file here would delete an export nobody had imported.
        model.shredSource()
        model.keepSource()
        #expect(FileManager.default.fileExists(atPath: file.path))
    }

    @Test func changingThePolicyWithNoPlanIsHarmless() throws {
        let (session, directory) = try Self.newVault()
        let model = ImportModel(session: session, sourcePath: directory.path)
        model.policy = .update
        model.policy = .keepBoth
        #expect(model.report == nil)
    }
}

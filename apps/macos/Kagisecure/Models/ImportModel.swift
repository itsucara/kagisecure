import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

import KagisecureFFI

/// Where an import has got to (import.md §8).
///
/// One linear path — choose a file, look at what it would do, do it, decide what happens to the
/// file — with a failure that can arrive at any point along it. The plan itself is not in here:
/// it lives on `ImportModel`, because it is a handle to an object on the Rust side and moving it
/// between cases would say something about its lifetime that is not true.
enum ImportPhase {
    /// Nothing has been chosen yet.
    case idle
    /// The file is being parsed. Nothing has been written and nothing can be, yet.
    case choosing
    /// Parsed. The report is what the sheet renders; the values it came from never left Rust.
    case previewing(ImportReportView)
    /// `import_commit` is running.
    case committing
    /// Committed and saved, with nothing left to ask about — the source file is already gone.
    case done(ImportOutcomeView)
    /// Committed and saved, and the source file is still on disk (import.md §9).
    case shredPrompt(ImportOutcomeView)
    /// Over. The string says what happened to the source file.
    case finished(ImportOutcomeView, String)
    /// Something failed. The string is a message; `FfiError`'s messages are metadata, never a
    /// value.
    case failed(String)
}

/// The state behind the import sheet (import.md §8, ui-spec.md §15).
///
/// # What this class may hold
///
/// Counts and names. The parsed plan is an `ImportPlanHandle` — a reference to an object that
/// stays in Rust — and the only thing this class can ask it for is a report, which by
/// construction holds no values (`crates/kagisecure-ffi/src/import.rs`). So there is no path by
/// which a password from someone's 1Password export reaches a SwiftUI view, and this class does
/// not have to be careful about one: it is not given the option.
///
/// # Why the file is chosen before the sheet
///
/// `AppModel.openImport()` runs the `NSOpenPanel` and only then presents the sheet, which is the
/// order import.md §8 describes. Cancelling the panel therefore leaves no sheet behind, rather
/// than opening an empty one that has to explain itself.
@MainActor
@Observable
final class ImportModel {
    /// The unlocked vault. Import is a vault operation, so there is no import without one — the
    /// menu item is disabled while locked and this class cannot be built without a session.
    private let session: VaultSession

    /// The file being imported, in full. The sheet shows it; the shred prompt needs it.
    let sourcePath: String

    /// Where we are.
    private(set) var phase: ImportPhase = .idle

    /// The parsed plan, while there is one. Spent by a successful commit.
    private(set) var plan: ImportPlanHandle?

    /// The formats the picker offers, read from the core rather than listed again here.
    let formats: [ImportFormatInfo] = importFormats()

    /// The sentence the "Delete the source file?" prompt shows *before* the user agrees.
    let shredWarning: String = shredCaveat()

    /// The format override, or `nil` to let the parser detect one. Changing it re-parses.
    var formatOverride: ImportFormat? {
        didSet {
            guard formatOverride != oldValue else { return }
            load()
        }
    }

    /// What to do about items the vault already has. Changing it re-previews, because the policy
    /// is what decides the per-item action column.
    var policy: DuplicatePolicyView = .skip {
        didSet {
            guard policy != oldValue else { return }
            refreshPreview()
        }
    }

    /// `-KSUITestImportFile <path>` — the file the XCUITest suite imports, instead of an
    /// `NSOpenPanel` nothing in a test can drive.
    ///
    /// A launch argument rather than an environment variable, and `#if DEBUG` only, for the
    /// reasons `UITestSupport` gives at length: an argument is written once by whoever spawned
    /// the process and is visible in `ps`, and none of this exists in a Release build. It
    /// replaces the file *chooser*, not any part of the import: the sheet, the preview, the
    /// Import button and the shred prompt are all the real ones.
    static let uiTestSourceArgument = "-KSUITestImportFile"

    init(session: VaultSession, sourcePath: String) {
        self.session = session
        self.sourcePath = sourcePath
    }

    // MARK: - Choosing a file

    /// Ask for the export to read, or return `nil` if the user cancelled.
    ///
    /// `.commaSeparatedText` plus a type derived from the `1pux` extension: 1PUX has no declared
    /// UTI on macOS, and declaring one in this app's `Info.plist` would be claiming a file format
    /// that is 1Password's. A type derived from the extension filters the panel without claiming
    /// anything.
    static func chooseSourceFile() -> String? {
        #if DEBUG
            if let scripted = UITestSupport.value(for: uiTestSourceArgument) {
                return scripted
            }
        #endif
        let panel = NSOpenPanel()
        panel.title = "Import into kagisecure"
        panel.message =
            "Choose a 1Password .1pux archive or a CSV exported from Apple Passwords, Chrome, "
            + "Edge or Firefox."
        panel.prompt = "Choose"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        var types: [UTType] = [.commaSeparatedText, .plainText]
        if let onepux = UTType(filenameExtension: "1pux") {
            types.append(onepux)
        }
        panel.allowedContentTypes = types
        // An export is usually in ~/Downloads, and the panel remembering the last directory is
        // not something this sheet should decide; `directoryURL` is left alone.
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return url.path
    }

    // MARK: - The flow

    /// Parse the file and show what importing it would do.
    func load() {
        phase = .choosing
        plan = nil
        do {
            let parsed = try session.importPreview(path: sourcePath, format: formatOverride)
            plan = parsed
            refreshPreview()
        } catch {
            fail(error)
        }
    }

    /// Re-ask for the preview against the open vault under the current policy.
    ///
    /// This — not `ImportPlanHandle.report()` — is what the sheet shows: only a report built
    /// against the vault knows how many of these items the vault already has.
    func refreshPreview() {
        guard let plan else { return }
        do {
            phase = .previewing(try session.importPreviewAgainst(plan: plan, policy: policy))
        } catch {
            fail(error)
        }
    }

    /// Apply the plan and save.
    ///
    /// `targetVault: nil` — every item goes where the source said it should, creating logical
    /// vaults as needed. Collapsing an import into one vault is a CLI flag (`--logical-vault`)
    /// and not a control on this sheet; the sheet shows which vault each item is headed for
    /// instead.
    func commit() {
        guard let plan else { return }
        phase = .committing
        do {
            let outcome = try session.importCommit(plan: plan, policy: policy, targetVault: nil)
            self.plan = nil
            phase =
                FileManager.default.fileExists(atPath: sourcePath)
                ? .shredPrompt(outcome) : .done(outcome)
        } catch {
            fail(error)
        }
    }

    /// Overwrite and delete the file the import was read from (import.md §9).
    ///
    /// Only ever from the button, and only after `shredWarning` has been on screen: this is best
    /// effort, and the UI must never have implied otherwise.
    func shredSource() {
        guard case .shredPrompt(let outcome) = phase else { return }
        do {
            let result = try shredSourceFile(path: sourcePath)
            let sentence =
                result.removed
                ? "The source file was deleted. \(result.caveat)"
                : "The source file is still there. \(result.caveat)"
            phase = .finished(outcome, sentence)
        } catch {
            fail(error)
        }
    }

    /// Keep the source file, and say plainly what that means.
    func keepSource() {
        guard case .shredPrompt(let outcome) = phase else { return }
        phase = .finished(
            outcome,
            "The source file was left where it is. It is a complete, unencrypted copy of "
                + "everything you just imported — delete it yourself when you are done with it.")
    }

    /// Go back to the file that was chosen and parse it again, after a failure.
    func retry() {
        load()
    }

    // MARK: - What the sheet reads

    /// The report on screen, if there is one.
    var report: ImportReportView? {
        switch phase {
        case .previewing(let report): report
        case .done(let outcome), .shredPrompt(let outcome), .finished(let outcome, _):
            outcome.report
        default: nil
        }
    }

    /// The outcome, once there is one.
    var outcome: ImportOutcomeView? {
        switch phase {
        case .done(let outcome), .shredPrompt(let outcome), .finished(let outcome, _): outcome
        default: nil
        }
    }

    /// Whether the Import button can be pressed.
    var canImport: Bool {
        if case .previewing(let report) = phase { return report.totals.items > 0 }
        return false
    }

    /// Whether the items are in the vault and on disk.
    ///
    /// True from the moment the commit succeeds — including while the "Delete the source file?"
    /// prompt is still up, which is why the sheet's button says "Done" there rather than offering
    /// a Cancel for something that has already happened. Closing the sheet without answering the
    /// prompt keeps the file, which is the safe half of that question.
    var hasCommitted: Bool {
        switch phase {
        case .done, .shredPrompt, .finished: true
        default: false
        }
    }

    /// The file's name on its own, for the sheet's header.
    var sourceName: String {
        (sourcePath as NSString).lastPathComponent
    }

    /// How many of one kind of thing the current report says will be left behind.
    func dropped(_ kind: ImportDropKindView) -> DropNoteView? {
        report?.dropped.first { $0.kind == kind }
    }

    // MARK: - Errors

    private func fail(_ error: Error) {
        phase = .failed(Self.message(for: error))
    }

    /// The same mapping `AppModel` uses: `FfiError`'s messages are metadata — a path, a missing
    /// column, a limit — and are safe to show. Nothing else is inspected.
    static func message(for error: Error) -> String {
        if let ffi = error as? FfiError {
            switch ffi {
            case .WrongCredential:
                return "That did not unlock the vault."
            case .NotFound(let message), .AlreadyExists(let message), .NoSuchSlot(let message),
                .NotPresent(let message), .Invalid(let message), .Io(let message):
                return message
            }
        }
        return error.localizedDescription
    }
}

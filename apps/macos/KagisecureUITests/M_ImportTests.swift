import XCTest

/// File ▸ Import… (import.md §8, ui-spec.md §15).
///
/// # Written, compiled, not yet run
///
/// e2e-harness.md §7.2 says so explicitly, and the reason is in the import crate: the 1PUX and CSV
/// parsers are still stubs that refuse with "that import format is not supported by this build"
/// (WP1 and WP2 of the import plan). Until they land, the happy-path scenario below reaches the
/// error pane rather than the preview, so `make e2e SUITE=app` does not run this file. It is here
/// now because the sheet, the FFI surface and the identifiers are here now, and a scenario written
/// against a screen while the screen is being built is a scenario that matches it.
///
/// # How the file gets chosen
///
/// Not through the `NSOpenPanel`, which is an AppKit modal a UI test cannot drive and which would
/// be reaching outside the scenario's scratch world anyway. `-KSUITestImportFile <path>` replaces
/// the *chooser* and nothing else: the sheet, the preview, the Import button, the duplicate policy
/// and the shred prompt are all the real ones. Same discipline as `-KSUITestBiometrics` — a launch
/// argument, `#if DEBUG` only, nothing persisted (see `UITestSupport`).
final class M_ImportTests: UITestCase {

    // MARK: - Scenarios

    func testImportingACsvShowsAPreviewThenImportsAndOffersToDeleteTheSource() throws {
        try Harness.seedVault(at: vaultPath)
        let source = try writeFixture(
            named: "apple-passwords.csv",
            contents: """
                Title,URL,Username,Password,Notes,OTPAuth
                Hosting,https://hosting.test,ada@example.test,hunter2-hosting,,
                Newsletter,https://news.test,ada@example.test,hunter2-news,,

                """)
        launch(importing: source)
        unlock()

        step("⇧⌘I opens the import sheet on the file that was chosen") {
            app.typeKey("i", modifierFlags: [.command, .shift])
            waitFor("ks.import.sheet")
            XCTAssertTrue(
                text("ks.import.sourcePath").contains("apple-passwords.csv"),
                "the sheet must name the file it is reading")
            capture("import-preview", "The import preview, before anything is written")
        }

        step("the preview counts what is coming and what is not") {
            waitFor("ks.import.totalItems")
            waitFor("ks.import.duplicates")
            waitFor("ks.import.duplicatePolicy")
            waitFor("ks.import.detailTable")
            // The three counters of import.md §8, each with its sentence beside it.
            for identifier in [
                "ks.import.droppedAttachments", "ks.import.droppedPasskeys",
                "ks.import.droppedHistory",
            ] {
                let said = text(identifier)
                XCTAssertFalse(
                    said.isEmpty, "\(identifier) must pair its number with an explanation")
            }
            waitFor("ks.import.category.login")
        }

        step("no value from the file is anywhere in the sheet") {
            // The canary the report crate asserts on byte by byte, asserted again at the only
            // place a user could actually read one.
            let onScreen = app.descendants(matching: .any).allElementsBoundByIndex
                .map { "\($0.label) \(($0.value as? String) ?? "")" }
                .joined(separator: " ")
            for value in ["hunter2-hosting", "hunter2-news"] {
                XCTAssertFalse(
                    onScreen.contains(value),
                    "a password from the import reached the screen; the preview is names and "
                        + "counts only (import.md §1.1)")
            }
        }

        step("Import writes the items and the list picks them up") {
            click("ks.import.confirm")
            waitFor("ks.import.result")
            capture("import-result", "What the import did")
        }

        step("the source file is offered up for deletion, with the caveat on screen first") {
            waitFor("ks.import.shredPrompt")
            let warning = text("ks.import.shredPrompt")
            XCTAssertFalse(warning.isEmpty)
            click("ks.import.shredConfirm")
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: source),
                "the source export is still on disk after the user asked for it to be deleted")
        }

        step("Done closes the sheet and the imported items are in the list") {
            click("ks.import.confirm")
            waitForDisappearance("ks.import.sheet")
            let titles = itemListTitles()
            XCTAssertTrue(titles.contains("Hosting"), "imported items: \(titles)")
            XCTAssertTrue(titles.contains("Newsletter"), "imported items: \(titles)")
        }
    }

    func testAFileThatCannotBeParsedIsRefusedWithTheVaultUntouched() throws {
        try Harness.seedVault(at: vaultPath)
        let source = try writeFixture(named: "not-an-export.csv", contents: "nonsense\n")
        launch(importing: source)
        unlock()

        let before = itemListTitles()

        step("the sheet explains the refusal rather than an empty preview") {
            app.typeKey("i", modifierFlags: [.command, .shift])
            waitFor("ks.import.sheet")
            waitFor("ks.import.error")
            XCTAssertFalse(text("ks.import.error").isEmpty)
            capture("import-error", "A file the importer will not read")
        }

        step("keeping the source file is the other half of the offer") {
            // Nothing was imported, so there is nothing to offer: the prompt is not up.
            XCTAssertFalse(
                element("ks.import.shredPrompt").exists,
                "a failed import must never offer to delete the file it could not read")
            click("ks.import.cancel")
            waitForDisappearance("ks.import.sheet")
            XCTAssertTrue(
                FileManager.default.fileExists(atPath: source),
                "the file the importer refused must still be there")
            XCTAssertEqual(itemListTitles(), before, "a refused import must change nothing")
        }
    }

    // MARK: - The scenario's world

    /// Write an export into this scenario's scratch directory and return its path.
    private func writeFixture(named name: String, contents: String) throws -> String {
        let url = scratch.appendingPathComponent(name)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }

    /// `UITestCase.launch()` plus the one argument this suite needs, which no other scenario does.
    ///
    /// Written here rather than added to `UITestCase` for that reason: the base class sets the
    /// three things every scenario must not forget, and a per-suite fixture choice belongs to the
    /// suite that makes it.
    @discardableResult
    private func launchWithImportFile(_ path: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["KAGISECURE_HOME"] = scratch.path
        app.launchEnvironment["KAGISECURE_SOCKET"] = socketPath
        app.launchEnvironment["KAGISECURE_UITEST"] = "1"
        app.launchArguments = [
            "-KSUITestDefaultsSuite", defaultsSuite!,
            "-KSUITestBiometrics", "allow",
            "-KSUITestImportFile", path,
        ]

        let defaults = UserDefaults(suiteName: defaultsSuite!)
        defaults?.set(0, forKey: "autoLockIdleMinutes")
        defaults?.set(60, forKey: "pasteboardClearSeconds")

        terminateApp(XCUIApplication())
        app.launch()
        self.app = app
        return app
    }

    /// Reads better at the call site than the verb-first name does.
    @discardableResult
    private func launch(importing path: String) -> XCUIApplication {
        launchWithImportFile(path)
    }

    /// Seed-and-unlock, as every other scenario in this suite spells it out for itself.
    private func unlock(file: StaticString = #filePath, line: UInt = #line) {
        waitFor("ks.lock.title", file: file, line: line)
        type(Harness.password, into: "ks.lock.password", file: file, line: line)
        click("ks.lock.unlock", file: file, line: line)
        waitFor("ks.sidebar.all", file: file, line: line)
    }
}

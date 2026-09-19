import AppKit
import XCTest

/// The Quick Access panel (ui-spec.md §7).
///
/// The panel's whole claim is that it is a keyboard-only way at a password without the three-pane
/// window: search, arrows, one of three Returns, gone. Both scenarios here are about that claim —
/// the second one about what it says when it cannot keep it, because the vault is locked and Quick
/// Access deliberately does not unlock anything in v1.
final class H_QuickAccessTests: UITestCase {
    /// The password `Harness.seedVault` stores on the GitHub fixture.
    private static let githubPassword = "g1thub-p4ssw0rd"
    /// Its username field.
    private static let githubUsername = "alice@example.test"

    /// Distinguishes the evidence file each `openQuickAccess()` writes, since a scenario opens the
    /// panel more than once and the second record must not overwrite the first.
    private var openCount = 0

    // MARK: - Scenarios

    func testQuickAccessSearchesAndCopiesWithoutTheMainWindow() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()

        step("the panel comes up, and says what its three shortcuts do") {
            let path = openQuickAccess()
            waitFor("ks.quickAccess.search")
            capture("quick-access-open", "Quick Access, opened over the main window (via \(path))")

            // One identifier per entry, not one for the row: an identifier on the row's `HStack`
            // is stamped over both `Text`s inside it, which is how the legend stopped being
            // readable at all the first time this was written.
            for promised in ["Copy password", "Copy username", "Copy one-time password"] {
                XCTAssertTrue(
                    element("ks.quickAccess.legend.\(promised)").exists,
                    "ui-spec.md §7 makes ⌥⏎ discoverable by printing all three copy actions along "
                        + "the bottom; \"\(promised)\" is not among them")
            }
        }

        step("typing filters the list down to the matching item") {
            type("git", into: "ks.quickAccess.search")
            let row = waitForRowTitled("GitHub")
            XCTAssertNotNil(
                row,
                "\"git\" should find the GitHub fixture; the panel listed "
                    + "\(itemListTitles().joined(separator: ", "))")
            capture("quick-access-search", "Quick Access, filtered to one match")
        }

        step("a query that matches nothing says so rather than showing everything") {
            type("zzzzz", into: "ks.quickAccess.search")
            waitFor("ks.quickAccess.empty")
            XCTAssertFalse(
                element("ks.quickAccess.list").exists,
                "a no-match query must replace the list, not sit above a stale one")
            capture("quick-access-no-match", "Quick Access with a query nothing matches")

            clearSearch()
            waitFor("ks.quickAccess.list")
            XCTAssertGreaterThan(
                itemListTitles().count, 1,
                "clearing the query must bring the whole vault back (ui-spec §7 lists every item)")
        }

        step("↑ and ↓ move the selection without taking focus off the field") {
            // Back to one match first: with an empty query the selection sits on the alphabetically
            // first item, and the ⏎ assertion below is about GitHub.
            type("git", into: "ks.quickAccess.search")
            waitForRowTitled("GitHub")

            app.typeKey(XCUIKeyboardKey.downArrow, modifierFlags: [])
            app.typeKey(XCUIKeyboardKey.upArrow, modifierFlags: [])

            XCTAssertTrue(
                element("ks.quickAccess.search").exists,
                "the arrow keys closed the panel; ui-spec §7 gives them to the selection, not to "
                    + "dismissal")
            // `hasKeyboardFocus` is a KVC-only attribute on `XCUIElement` and is not guaranteed
            // across Xcode versions, so it is probed before it is read — an unguarded
            // `value(forKey:)` against a missing key raises rather than returning nil. Same shape
            // as E_SearchTests. When it is not exposed, the next step is the proof that cannot be
            // faked: ⏎ still copies, which it could not do if the field had lost the keystrokes.
            let focusKey = "hasKeyboardFocus"
            if XCUIElement.instancesRespond(to: NSSelectorFromString(focusKey)) {
                let focused = element("ks.quickAccess.search").value(forKey: focusKey) as? Bool
                XCTAssertEqual(
                    focused, true,
                    "the panel's whole design is that ↑/↓ move the selection while the search "
                        + "field keeps focus, so the user can keep typing (ui-spec.md §7)")
                record(
                    "quick-access-focus-probe", "\(focusKey) = \(String(describing: focused))",
                    "Whether the search field still held focus after ↑/↓")
            } else {
                record(
                    "quick-access-focus-probe",
                    "\(focusKey) is not exposed by this XCTest build; that ↑/↓ did not steal the "
                        + "keystrokes is proved by the copy in the next step.",
                    "Whether the search field still held focus after ↑/↓")
            }
            capture("quick-access-before-return", "Quick Access, one match selected, about to copy")
        }

        step("⏎ copies the password and the panel goes away") {
            app.typeKey(XCUIKeyboardKey.return, modifierFlags: [])
            waitForDisappearance("ks.quickAccess.search")

            let copied = waitForPasteboard(where: { $0 == Self.githubPassword })
            XCTAssertEqual(
                copied, Self.githubPassword,
                "ui-spec §7: ⏎ copies the selected item's password. The clipboard held "
                    + "\(NSPasteboard.general.string(forType: .string) ?? "nothing")")
        }

        step("⌘⏎ copies the username instead") {
            openQuickAccess()
            type("git", into: "ks.quickAccess.search")
            waitForRowTitled("GitHub")

            app.typeKey(XCUIKeyboardKey.return, modifierFlags: .command)
            waitForDisappearance("ks.quickAccess.search")

            let copied = waitForPasteboard(where: { $0 == Self.githubUsername })
            XCTAssertEqual(
                copied, Self.githubUsername,
                "ui-spec §7: ⌘⏎ copies the username. The clipboard held "
                    + "\(NSPasteboard.general.string(forType: .string) ?? "nothing")")
        }
    }

    func testQuickAccessSaysSoWhenTheVaultIsLocked() throws {
        try Harness.seedVault(at: vaultPath)
        launch()

        step("the app is locked, and stays locked") {
            waitFor("ks.lock.title")
            capture("quick-access-locked-app", "The lock screen, before Quick Access is asked for")
        }

        step("the panel still opens, because a dead shortcut is a worse answer") {
            let path = openQuickAccess()
            waitFor("ks.quickAccess.search")
            record(
                "quick-access-locked-open-path", path,
                "How Quick Access was opened with the vault locked")
        }

        step("it offers the unlock window rather than a list it cannot have") {
            waitFor("ks.quickAccess.locked")
            XCTAssertFalse(
                element("ks.quickAccess.list").exists,
                "with no unlocked store there is nothing to search; ui-spec §7 says Quick Access "
                    + "shows a \"Vault is locked\" state, not an empty or stale list")
            XCTAssertTrue(
                element("ks.quickAccess.openMainWindow").exists,
                "the locked state's job is to point at where unlocking lives (ui-spec §7)")
            capture("quick-access-locked-panel", "Quick Access with the vault locked")
        }

        step("Esc closes it") {
            app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
            waitForDisappearance("ks.quickAccess.search")
            XCTAssertTrue(
                element("ks.lock.title").exists,
                "closing the panel should leave the app exactly where it was — locked")
            capture("quick-access-locked-dismissed", "Back to the lock screen after Esc")
        }
    }

    // MARK: - Getting to an unlocked vault

    private func unlock(file: StaticString = #filePath, line: UInt = #line) {
        waitFor("ks.lock.title", file: file, line: line)
        type(Harness.password, into: "ks.lock.password", file: file, line: line)
        click("ks.lock.unlock", file: file, line: line)
        waitFor("ks.sidebar.all", file: file, line: line)
    }

    // MARK: - Opening the panel

    /// Open Quick Access, by whichever of its three documented routes works, and say which.
    ///
    /// ⇧⌘Space is a *global* shortcut registered with `RegisterEventHotKey` (ADR-0017 §1). Carbon
    /// hot keys are dispatched from the event target rather than the responder chain, and whether a
    /// synthetic key event from XCUITest reaches that target is not something the suite gets to
    /// decide — so it is tried first and not relied on. The other two ways in are the ones
    /// ui-spec §7 promises still work when the shortcut is unavailable: the toolbar button, and the
    /// Item menu. Neither is a lesser test of the panel, so a hot key that does not fire is not a
    /// reason to skip the scenario.
    @discardableResult
    private func openQuickAccess(file: StaticString = #filePath, line: UInt = #line) -> String {
        openCount += 1
        if element("ks.quickAccess.search").exists { return "already open" }
        var tried: [String] = []

        app.typeKey(" ", modifierFlags: [.command, .shift])
        if panelAppeared() { return recordOpenPath("the ⇧⌘Space global hot key") }
        tried.append("⇧⌘Space did not open the panel")

        let toolbar = element("ks.toolbar.quickAccess")
        if toolbar.exists, toolbar.isHittable {
            toolbar.click()
            if panelAppeared() { return recordOpenPath("the ks.toolbar.quickAccess button") }
            tried.append("ks.toolbar.quickAccess was clicked and no panel appeared")
        } else {
            tried.append("ks.toolbar.quickAccess is not on screen (it is a main-window toolbar "
                + "item, so it is absent while the vault is locked)")
        }

        let itemMenu = app.menuBarItems["Item"]
        if itemMenu.exists {
            itemMenu.click()
            let entry = app.menuItems["Quick Access"]
            if entry.waitForExistence(timeout: Self.shortTimeout) {
                entry.click()
                if panelAppeared() { return recordOpenPath("the Item ▸ Quick Access menu command") }
                tried.append("Item ▸ Quick Access was chosen and no panel appeared")
            } else {
                tried.append("the Item menu has no Quick Access command")
                // Leave no menu hanging open over the next step's screenshot.
                app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
            }
        } else {
            tried.append("there is no Item menu in the menu bar")
        }

        XCTFail(
            "Quick Access would not open by any of the three routes ui-spec §7 documents:\n"
                + tried.joined(separator: "\n")
                + "\nOn screen: \(onScreenIdentifiers().joined(separator: ", "))",
            file: file, line: line)
        return "none"
    }

    private func panelAppeared() -> Bool {
        element("ks.quickAccess.search").waitForExistence(timeout: Self.shortTimeout)
    }

    private func recordOpenPath(_ path: String) -> String {
        record(
            "quick-access-open-path-\(openCount)", path,
            "Which of ui-spec §7's three routes opened Quick Access")
        return path
    }

    // MARK: - Reading the panel

    /// Wait for a row with exactly this title, and hand it back if it arrives.
    @discardableResult
    private func waitForRowTitled(_ title: String) -> XCUIElement? {
        let row = elements("ks.quickAccess.rowTitle")
            .matching(NSPredicate(format: "label == %@", title)).firstMatch
        return row.waitForExistence(timeout: Self.shortTimeout) ? row : nil
    }

    /// Empty the search field.
    ///
    /// Not `type("", into:)`: the base helper selects all and then types, and typing an empty
    /// string leaves the selection sitting there instead of removing it.
    private func clearSearch() {
        let search = waitFor("ks.quickAccess.search")
        search.click()
        search.typeKey("a", modifierFlags: .command)
        search.typeKey(XCUIKeyboardKey.delete, modifierFlags: [])
    }

    /// Wait for the system pasteboard to hold something `matches` accepts.
    ///
    /// Polled, because the copy happens in the app's process and the clipboard is not part of the
    /// accessibility tree — there is no XCUITest expectation that can be attached to it.
    private func waitForPasteboard(
        where matches: (String) -> Bool, timeout: TimeInterval = UITestCase.shortTimeout
    ) -> String? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let contents = NSPasteboard.general.string(forType: .string), matches(contents) {
                return contents
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        return nil
    }
}

import XCTest

/// The Settings scene (⌘,): the Security pane's three preferences (ui-spec.md §6.2 auto-lock,
/// §11's copy actions, §6.1 Touch ID) and the Vault pane that says which file is open.
///
/// This is also the suite's own safety net. `-KSUITestDefaultsSuite` exists so that a scenario
/// which turns auto-lock off and clipboard clearing down to fifteen seconds is changing a throwaway
/// preferences suite rather than the security posture of whoever's Mac is running the tests; the
/// second scenario below is the one that proves the redirection actually holds, by reading the
/// suite back after clicking the pane.
final class I_SettingsTests: UITestCase {
    /// The Settings tabs, by the names they show. See `tab(_:)` for why not by identifier.
    private static let securityTab = "Security"
    private static let vaultTab = "Vault"
    /// `PasteboardService.clearSecondsKey`. Hardcoded because the UI-test bundle links against
    /// XCTest and the app's *bundle*, not the app's module — there is no `import Kagisecure` to be
    /// had from a UI test, so the key travels as a string and this comment is the reference back to
    /// its one definition.
    private static let clipboardSecondsKey = "pasteboardClearSeconds"

    /// `AutoLockCoordinator.idleMinutesKey`, hardcoded for the same reason.
    private static let autoLockMinutesKey = "autoLockIdleMinutes"

    // MARK: - Scenarios

    func testEverySettingsTabIsReachableAndSaysWhatItShould() throws {
        try openSeededVault()

        step("the main window is up before Settings is asked for") {
            capture("settings-before", "The main window, before ⌘, opens Settings")
        }

        step("⌘, opens Settings on the Security tab") {
            openSettings()
            // By name, not by identifier. `.tabItem` hands AppKit a title and an image and builds
            // its own tab item; a view modifier on the label reaches nothing, so the tabs have no
            // identifiers to find. Their names are what a user reads and what VoiceOver says.
            XCTAssertTrue(tab(Self.securityTab).exists, "Settings should offer a Security tab")
            XCTAssertTrue(tab(Self.vaultTab).exists, "Settings should offer a Vault tab")
            XCTAssertTrue(
                element("ks.settings.clipboardInterval").exists,
                "the Security tab carries the clipboard interval (ui-spec.md §11's copy actions)")
            capture("settings-security", "Settings: the Security tab")
        }

        step("the Quick Access section says either its shortcut or why it has none") {
            // ⇧⌘Space is a system-wide hot key and another application on the machine running this
            // may already own it, in which case `QuickAccessController` reports the failure instead
            // of the shortcut. Both are correct behaviour, so the disjunction is the assertion and
            // which branch was taken is evidence rather than a verdict.
            let shortcut = element("ks.settings.quickAccessShortcut")
            let failure = element("ks.settings.quickAccessError")
            let registered = shortcut.waitForExistence(timeout: Self.shortTimeout)

            if registered {
                XCTAssertEqual(
                    text(of: shortcut), "⇧⌘Space",
                    "ui-spec.md §7's Quick Access shortcut is ⇧⌘Space")
                record(
                    "settings-quick-access", "shortcut: \(text(of: shortcut))",
                    "What the Quick Access section says")
            } else {
                XCTAssertTrue(
                    failure.exists,
                    "the Quick Access section should show either the ⇧⌘Space shortcut or the "
                        + "reason it could not be registered; it showed neither")
                record(
                    "settings-quick-access", "hot key unavailable: \(text(of: failure))",
                    "What the Quick Access section says")
            }
        }

        step("the Touch ID section resolves to an answer rather than a spinner") {
            // Three states in `SecuritySettings`: available (a toggle), unavailable (an
            // explanation) and unknown (a `ProgressView` with no identifier at all). The third is
            // a transient, so this waits for one of the first two rather than sampling once.
            let toggle = element("ks.settings.touchIdToggle")
            let unavailable = element("ks.settings.touchIdUnavailable")
            XCTAssertTrue(
                waitUntil("the Touch ID section stops saying 'unknown'") {
                    toggle.exists || unavailable.exists
                },
                "the Touch ID section never left its loading state; ui-spec.md §6.1 wants it to "
                    + "resolve to an offer or to a reason")
            record(
                "settings-touch-id",
                toggle.exists
                    ? "Touch ID is offered: ks.settings.touchIdToggle is present"
                    : "Touch ID is unavailable: \(text(of: unavailable))",
                "Which of the two Touch ID states this machine is in")
        }

        step("the Vault tab names the file that is actually open") {
            selectSettingsTab(Self.vaultTab, thenWaitFor: "ks.settings.vaultPath")

            let path = text("ks.settings.vaultPath")
            XCTAssertTrue(
                path.contains(scratch.path),
                "THE SUITE IS POINTED AT THE WRONG VAULT. This scenario's throwaway vault lives "
                    + "under \(scratch.path), and Settings says the open vault is \(path). If "
                    + "that is the real user's file at "
                    + "~/Library/Application Support/kagisecure/, then KAGISECURE_HOME did not "
                    + "reach the app and every scenario in this suite has been writing to "
                    + "somebody's actual password vault.")

            XCTAssertEqual(
                text("ks.settings.auditState"), "Chain intact",
                "a vault the CLI has just written should have an unbroken audit chain")
            XCTAssertTrue(
                text("ks.settings.wordlist").contains("7776"),
                "the generator's word list is the EFF long list, which is 7776 words; Settings "
                    + "said \(text("ks.settings.wordlist"))")

            capture("settings-vault", "Settings: the Vault tab, naming the scratch vault")
        }
    }

    func testTheAutoLockAndClipboardIntervalsAreWritableFromTheSettingsPane() throws {
        // Started from the two values this scenario is about to move, so that reading the suite
        // back proves a change rather than restating a default.
        try openSeededVault(autoLockMinutes: 0, pasteboardSeconds: 60)

        step("Settings opens on Security") {
            openSettings()
            waitFor("ks.settings.clipboardInterval")
            capture("settings-intervals-before", "Security, before either interval is changed")
        }

        step("the clipboard interval can be moved to fifteen seconds") {
            // "15 seconds" is what the picker shows for 15: `SecuritySettings` renders each choice
            // as `PasteboardService.clearDescription(seconds:)` with the leading "Cleared after "
            // stripped, so "Cleared after 15 seconds" becomes "15 seconds".
            chooseFromPicker("ks.settings.clipboardInterval", "15 seconds")
            assertPreference(
                Self.clipboardSecondsKey, becomes: 15,
                "choosing \"15 seconds\" in Settings should write 15 to "
                    + "\(Self.clipboardSecondsKey) (PasteboardService.clearSecondsKey)")
            capture("settings-clipboard-15s", "The clipboard interval, moved to fifteen seconds")
        }

        step("the auto-lock interval can be moved to one minute") {
            // ui-spec.md §6.2: the idle timeout is the one auto-lock trigger that is a preference.
            chooseFromPicker("ks.settings.autoLockInterval", "1 minute")
            assertPreference(
                Self.autoLockMinutesKey, becomes: 1,
                "choosing \"1 minute\" in Settings should write 1 to "
                    + "\(Self.autoLockMinutesKey) (AutoLockCoordinator.idleMinutesKey)")
            capture("settings-autolock-1m", "The auto-lock interval, moved to one minute")
        }

        step("and is put back to Never before it can lock this scenario out") {
            // The idle timer is measured against system-wide input idleness, so a scenario that
            // leaves it at one minute while a later step waits on a subprocess would be locked out
            // from under itself. `UITestCase.launch` defaults every scenario to Never for exactly
            // this reason; this one turned it on and so this one turns it off again.
            chooseFromPicker("ks.settings.autoLockInterval", "Never")
            assertPreference(
                Self.autoLockMinutesKey, becomes: 0,
                "choosing \"Never\" should write 0 to \(Self.autoLockMinutesKey)")
            capture("settings-autolock-never", "The auto-lock interval, back at Never")
        }

        step("all of it landed in the throwaway suite and nowhere else") {
            // The point of the whole file. `AppDefaults` sends every `@AppStorage` write to the
            // suite named by `-KSUITestDefaultsSuite`, which `tearDown` deletes. If the redirection
            // were broken these two values would have gone to the real `com.kagisecure.app`
            // preferences — a suite run would have quietly turned a stranger's clipboard clearing
            // down to fifteen seconds — and the reads above, which only ever look at the throwaway
            // suite, would have found nothing.
            let suite = UserDefaults(suiteName: defaultsSuite)
            record(
                "settings-defaults-suite",
                "suite: \(defaultsSuite!)\n"
                    + "\(Self.clipboardSecondsKey): "
                    + "\(String(describing: suite?.object(forKey: Self.clipboardSecondsKey)))\n"
                    + "\(Self.autoLockMinutesKey): "
                    + "\(String(describing: suite?.object(forKey: Self.autoLockMinutesKey)))",
                "The preferences the Settings pane wrote, read back out of the throwaway suite")
        }
    }

    // MARK: - Getting to the main window

    /// Seed a vault through the CLI, launch against it and get past the lock screen.
    private func openSeededVault(autoLockMinutes: Int = 0, pasteboardSeconds: Int = 60) throws {
        try Harness.seedVault(at: vaultPath)
        launch(autoLockMinutes: autoLockMinutes, pasteboardSeconds: pasteboardSeconds)
        waitFor("ks.lock.title")
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
    }

    // MARK: - Driving Settings

    /// Open Settings with ⌘, and wait for the pane rather than for a window.
    ///
    /// `Settings { }` is a separate scene with a title AppKit localises and decorates ("Kagisecure
    /// Settings", "…Preferences" on older systems), so the window title is the wrong thing to wait
    /// on. The first control on the Security tab is unambiguous and is not on the main window.
    private func openSettings(file: StaticString = #filePath, line: UInt = #line) {
        app.typeKey(",", modifierFlags: .command)
        waitFor("ks.settings.autoLockInterval", file: file, line: line)
    }

    /// Switch Settings tabs, and wait for something that is only on the destination tab.
    ///
    /// The fallback is by visible title: a `.tabItem`'s `accessibilityIdentifier` sits on the
    /// `Label` inside the modifier, and AppKit rebuilds that label into a toolbar or segmented
    /// control item, which does not always carry the identifier across. The tab is still there and
    /// still named, so the scenario falls back to its name rather than stopping at a detail of how
    /// SwiftUI lowered it.
    private func selectSettingsTab(
        _ name: String, thenWaitFor destination: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let target = tab(name)
        XCTAssertTrue(
            target.waitForExistence(timeout: Self.shortTimeout),
            "no tab named \(name) in the Settings window", file: file, line: line)
        target.click()
        waitFor(destination, file: file, line: line)
    }

    /// The Settings tab called `name`.
    private func tab(_ name: String) -> XCUIElement {
        let radio = app.radioButtons[name]
        if radio.exists { return radio }
        return app.descendants(matching: .any).matching(
            NSPredicate(format: "label == %@ OR title == %@", name, name)
        ).firstMatch
    }

    /// Choose `option` from the `.menu`-style `Picker` with `identifier`.
    ///
    /// A `Picker` inside a `Form` is an `NSPopUpButton`, and XCUITest reaches its choices as menu
    /// items rather than as descendants of the picker. Hittability, not existence, is what is
    /// waited on: both Security pickers offer a choice worded "1 minute", and only the open menu's
    /// copy of it can be clicked.
    private func chooseFromPicker(
        _ identifier: String, _ option: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let picker = waitFor(identifier, file: file, line: line)
        picker.click()

        let choice = app.menuItems[option].firstMatch
        if !waitUntil("the \(identifier) menu offers \(option)", { choice.exists && choice.isHittable }
        ) {
            // A pop-up button clicked while its window was still taking key focus swallows the
            // click and stays shut. Escape first, so the retry cannot land inside a menu that did
            // open but has not settled.
            app.typeKey(XCUIKeyboardKey.escape.rawValue, modifierFlags: [])
            picker.click()
            XCTAssertTrue(
                waitUntil("the \(identifier) menu offers \(option)") {
                    choice.exists && choice.isHittable
                },
                "\(identifier) never opened a menu containing \(option)",
                file: file, line: line)
        }
        choice.click()
    }

    // MARK: - Reading preferences back

    /// Assert that the Settings pane actually wrote `key`.
    ///
    /// Read out of a freshly made `UserDefaults` on every poll: the app writes the suite through
    /// `cfprefsd` from another process, and a long-lived instance in this one can keep handing back
    /// the value it cached before that write landed.
    private func assertPreference(
        _ key: String, becomes expected: Int, _ message: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let landed = waitUntil("\(key) becomes \(expected)") {
            UserDefaults(suiteName: self.defaultsSuite)?.object(forKey: key) as? Int == expected
        }
        let actual = UserDefaults(suiteName: defaultsSuite)?.object(forKey: key)
        XCTAssertTrue(
            landed,
            "\(message). The suite \(defaultsSuite!) holds \(String(describing: actual)) instead.",
            file: file, line: line)
    }

    /// Wait until `condition` holds. Predicate-driven rather than a sleep loop, so it returns the
    /// moment the preference lands.
    private func waitUntil(
        _ description: String, timeout: TimeInterval = UITestCase.shortTimeout,
        _ condition: @escaping () -> Bool
    ) -> Bool {
        if condition() { return true }
        let expectation = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in condition() }, object: nil)
        expectation.expectationDescription = description
        return XCTWaiter().wait(for: [expectation], timeout: timeout) == .completed
    }
}

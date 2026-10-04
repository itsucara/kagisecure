import XCTest

/// What happens around an unlock: the Touch ID offer (ADR-0004 amendment of 2026-10-04), the
/// "Connect your browsers" prompt (ui-spec.md §6.5), and a manual lock that must stay locked.
///
/// Touch ID itself cannot be automated. The Secure Enclave is replaced by `ScriptedPlatformKey`
/// (`-KSUITestTouchID`, `#if DEBUG` only), which keeps the vault key in memory, so everything
/// around the sensor — the slot written into the vault, the lock screen's button, the offer
/// sheet — runs for real. The browser list is injected the same way (`-KSUITestBrowsers`).
///
/// Native AutoFill (the credential provider switched on in System Settings) is deliberately not
/// here: System Settings is another process and cannot be driven from this suite.
final class N_UnlockPromptsTests: UITestCase {
    /// `TouchIDOffer.explicitlyOffKey` / `dontAskAgainKey`, hardcoded because the UI-test bundle
    /// cannot import the app's module (see I_SettingsTests).
    private static let touchIDExplicitlyOffKey = "touchID.explicitlyOff"
    private static let touchIDDontAskAgainKey = "touchID.dontAskAgain"
    /// `BrowserConnectPrompt.silencedKey` / `snoozedUntilKey`.
    private static let browserSilencedKey = "browserPrompt.silenced"
    private static let browserSnoozedKey = "browserPrompt.snoozedUntil"

    private static let chrome = "googlechrome=Google Chrome"
    private static let edge = "microsoftedge=Microsoft Edge"

    private var touchIDLogPath: String {
        scratch.appendingPathComponent("touchid-unwraps.log").path
    }

    private func touchID(_ mode: String) -> [String] {
        ["-KSUITestTouchID", mode, "-KSUITestTouchIDLog", touchIDLogPath]
    }

    /// How many Touch ID unlocks the double has performed.
    private func unwrapCount() -> Int {
        let text = (try? String(contentsOfFile: touchIDLogPath, encoding: .utf8)) ?? ""
        return text.split(separator: "\n").filter { $0 == "unwrap" }.count
    }

    // MARK: - Touch ID offer

    /// Available, never turned off: the first password unlock enrols silently, with no sheet,
    /// and the next lock screen offers Touch ID.
    func testAPasswordUnlockEnrolsTouchIDSilently() throws {
        try Harness.seedVault(at: vaultPath)
        launch(extraArguments: touchID("works"))

        step("a password unlock raises no offer sheet") {
            unlockWithPassword()
            XCTAssertFalse(
                element("ks.touchIdOffer.title").waitForExistence(timeout: 3),
                "Touch ID is on by default: an available, never-disabled sensor enrols silently")
            capture("touchid-auto-enrolled", "Unlocked; Touch ID was enrolled without asking")
        }

        step("the next lock screen offers Touch ID") {
            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            waitFor("ks.lock.touchId")
            capture("touchid-lock-button", "The lock screen after auto-enrolment")
        }
    }

    /// Enrolment fails (cancelled at the sensor): the offer sheet follows; "Don't show this
    /// again" + "Not Now" is remembered and the next unlock asks nothing.
    func testAFailedAutoEnrolmentFallsBackToTheOfferSheet() throws {
        try Harness.seedVault(at: vaultPath)
        launch(extraArguments: touchID("enrolFails"))

        step("the offer sheet appears after the password unlock") {
            unlockWithPassword()
            waitFor("ks.touchIdOffer.title")
            XCTAssertTrue(element("ks.touchIdOffer.turnOn").exists)
            XCTAssertTrue(element("ks.touchIdOffer.notNow").exists)
            capture("touchid-offer-sheet", "Turn on Touch ID unlock? after a failed auto-enrolment")
        }

        step("Don't show this again + Not Now is remembered") {
            click("ks.touchIdOffer.dontAskAgain")
            click("ks.touchIdOffer.notNow")
            waitForDisappearance("ks.touchIdOffer.title")
            XCTAssertTrue(
                waitUntil("touchID.dontAskAgain is written") {
                    UserDefaults(suiteName: self.defaultsSuite)?
                        .bool(forKey: Self.touchIDDontAskAgainKey) == true
                },
                "\"Don't show this again\" should write \(Self.touchIDDontAskAgainKey)")
        }

        step("the next unlock asks nothing") {
            app.typeKey("\\", modifierFlags: .command)
            unlockWithPassword()
            XCTAssertFalse(
                element("ks.touchIdOffer.title").waitForExistence(timeout: 3),
                "the offer came back after \"Don't show this again\"")
        }
    }

    /// Turned off earlier: no silent enrolment, the sheet asks, and Turn On enrols.
    func testTurnedOffTouchIDIsOfferedAndTurnOnEnrols() throws {
        try Harness.seedVault(at: vaultPath)
        launch(
            extraArguments: touchID("works"),
            seedDefaults: [Self.touchIDExplicitlyOffKey: true])

        step("the offer sheet asks instead of enrolling") {
            unlockWithPassword()
            waitFor("ks.touchIdOffer.title")
            capture("touchid-offer-after-off", "The offer, for someone who turned Touch ID off")
        }

        step("Turn On enrols, and the lock screen then offers Touch ID") {
            click("ks.touchIdOffer.turnOn")
            waitForDisappearance("ks.touchIdOffer.title")
            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            waitFor("ks.lock.touchId")
        }
    }

    /// No sensor: nothing is offered at all.
    func testNoOfferWhenTouchIDIsUnavailable() throws {
        try Harness.seedVault(at: vaultPath)
        launch(extraArguments: touchID("unavailable"))
        unlockWithPassword()
        XCTAssertFalse(
            element("ks.touchIdOffer.title").waitForExistence(timeout: 3),
            "Touch ID cannot be offered on a Mac without it")
    }

    // MARK: - Manual lock

    /// ⌘\ is "lock now": the lock screen must not immediately raise Touch ID and undo it.
    func testAManualLockDoesNotAutoPromptTouchID() throws {
        try Harness.seedVault(at: vaultPath)
        launch(extraArguments: touchID("works"))
        unlockWithPassword()
        XCTAssertFalse(element("ks.touchIdOffer.title").waitForExistence(timeout: 2))

        step("after ⌘\\ the lock screen stays, and no unlock was attempted") {
            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            waitFor("ks.lock.touchId")
            // Long enough for an onAppear unlock (scripted sensor answers in well under a second).
            Thread.sleep(forTimeInterval: 4)
            XCTAssertTrue(element("ks.lock.title").exists, "the vault unlocked itself after ⌘\\")
            XCTAssertFalse(element("ks.sidebar.all").exists)
            XCTAssertEqual(
                unwrapCount(), 0,
                "a manual lock must not prompt Touch ID (LockView.onAppear skips .manual)")
            capture("manual-lock-stays", "Locked with ⌘\\: Touch ID offered, not raised")
        }

        step("control: the Touch ID button does unlock") {
            click("ks.lock.touchId")
            waitFor("ks.sidebar.all")
            XCTAssertEqual(unwrapCount(), 1)
        }
    }

    // MARK: - Browser connect prompt

    func testTheBrowserPromptAppearsAfterUnlockAndLaterSnoozesIt() throws {
        try Harness.seedVault(at: vaultPath)
        launch(extraArguments: ["-KSUITestBrowsers", Self.chrome])

        step("an unconnected browser is offered after the unlock") {
            unlockWithPassword()
            waitFor("ks.browserPrompt.title")
            XCTAssertTrue(element("ks.browserPrompt.connect.googlechrome").exists)
            XCTAssertTrue(element("ks.browserPrompt.later").exists)
            capture("browser-prompt", "Connect your browsers, after unlock")
        }

        step("Later closes it and snoozes the browser") {
            click("ks.browserPrompt.later")
            waitForDisappearance("ks.browserPrompt.title")
            XCTAssertTrue(
                waitUntil("the snooze is written") {
                    let table = UserDefaults(suiteName: self.defaultsSuite)?
                        .dictionary(forKey: Self.browserSnoozedKey) as? [String: Double]
                    return (table?["googlechrome"] ?? 0) > Date().timeIntervalSince1970
                },
                "Later should snooze googlechrome in \(Self.browserSnoozedKey)")
        }

        step("a relaunch inside the snooze does not ask again") {
            launch(extraArguments: ["-KSUITestBrowsers", Self.chrome])
            unlockWithPassword()
            XCTAssertFalse(
                element("ks.browserPrompt.title").waitForExistence(timeout: 4),
                "a snoozed browser was offered again")
        }
    }

    func testDontAskAgainSilencesOneBrowserForGood() throws {
        try Harness.seedVault(at: vaultPath)
        let both = ["-KSUITestBrowsers", "\(Self.chrome),\(Self.edge)"]
        launch(extraArguments: both)

        step("both browsers are listed") {
            unlockWithPassword()
            waitFor("ks.browserPrompt.title")
            waitFor("ks.browserPrompt.connect.googlechrome")
            waitFor("ks.browserPrompt.connect.microsoftedge")
        }

        step("Don't ask about Chrome again disables its Connect, then Later") {
            click("ks.browserPrompt.dontAsk.googlechrome")
            XCTAssertTrue(
                waitUntil("Connect is disabled") {
                    !self.element("ks.browserPrompt.connect.googlechrome").isEnabled
                })
            capture("browser-prompt-dont-ask", "Don't ask about Google Chrome again, checked")
            click("ks.browserPrompt.later")
            waitForDisappearance("ks.browserPrompt.title")
            XCTAssertTrue(
                waitUntil("googlechrome is silenced") {
                    UserDefaults(suiteName: self.defaultsSuite)?
                        .stringArray(forKey: Self.browserSilencedKey) == ["googlechrome"]
                })
        }

        step("with the snooze expired, only Edge comes back") {
            UserDefaults(suiteName: defaultsSuite)?.removeObject(forKey: Self.browserSnoozedKey)
            launch(extraArguments: both)
            unlockWithPassword()
            waitFor("ks.browserPrompt.title")
            waitFor("ks.browserPrompt.connect.microsoftedge")
            XCTAssertFalse(
                element("ks.browserPrompt.connect.googlechrome").exists,
                "a silenced browser was offered again")
            capture("browser-prompt-silenced", "Only the browser that was not silenced")
            click("ks.browserPrompt.later")
        }
    }

    // MARK: - Helpers

    private func unlockWithPassword(file: StaticString = #filePath, line: UInt = #line) {
        waitFor("ks.lock.title", file: file, line: line)
        type(Harness.password, into: "ks.lock.password", file: file, line: line)
        click("ks.lock.unlock", file: file, line: line)
        waitFor("ks.sidebar.all", file: file, line: line)
    }
}

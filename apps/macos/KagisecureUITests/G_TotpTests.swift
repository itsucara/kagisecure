import AppKit
import XCTest

/// One-time passwords: adding one (ui-spec.md §9) and living with one (ui-spec.md §4.2).
///
/// # The fixture secret
///
/// `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` is the Base32 form of the ASCII string
/// `12345678901234567890`, the shared key RFC 6238 publishes as its own test vector. It is safe to
/// commit for exactly that reason: it is the most widely published TOTP seed in existence and
/// protects nothing anywhere.
final class G_TotpTests: UITestCase {
    private static let fixtureUri =
        "otpauth://totp/Kagisecure:e2e@example.test"
        + "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Kagisecure"
        + "&algorithm=SHA1&digits=6&period=30"

    // MARK: - Scenarios

    func testAOneTimePasswordIsAddedThroughTheSetupSheetAndRunsLive() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()
        selectItem("GitHub")

        step("a one-time-password field is added from the Add field menu") {
            app.typeKey("e", modifierFlags: .command)
            waitFor("ks.edit.addField")
            click("ks.edit.addField")

            let entry = app.menuItems["One-time password"]
            XCTAssertTrue(
                entry.waitForExistence(timeout: Self.shortTimeout),
                "ui-spec §9 reaches the setup flow from \"+ Add field\"; the menu offered: "
                    + app.menuItems.allElementsBoundByIndex.map { $0.title }.joined(separator: ", "))
            entry.click()

            // ItemEditView.addField names a new TOTP row "one-time password", and every control in
            // an edit row is identified by that label, because a draft row has no id yet.
            click("ks.edit.fieldTotpSetup.one-time password")
            waitFor("ks.totpSetup.mode")
            capture("totp-setup-opened", "The one-time-password setup sheet, before anything is typed")
        }

        step("the preview says it has nothing to show yet") {
            XCTAssertTrue(
                element("ks.totpSetup.previewEmpty").exists,
                "ui-spec §9 puts a live preview in this sheet; with no URI it must say so rather "
                    + "than show a stale or invented code")
            XCTAssertFalse(
                element("ks.totpSetup.previewCode").exists,
                "there is no secret yet, so there is nothing a code could be derived from")
        }

        step("pasting the URI produces a live code before anything is saved") {
            type(Self.fixtureUri, into: "ks.totpSetup.uri")
            waitFor("ks.totpSetup.previewCode")
            let preview = textOf("ks.totpSetup.previewCode")
            XCTAssertTrue(
                isGroupedSixDigitCode(preview),
                "ui-spec §4.2 renders a six-digit code grouped as \"123 456\"; the preview showed "
                    + "\"\(preview)\"")
            capture("totp-setup-preview", "The live preview, confirming the secret before it is saved")
        }

        step("saving the sheet and the item puts a running code on the detail pane") {
            click("ks.totpSetup.save")
            waitForDisappearance("ks.totpSetup.mode")
            click("ks.edit.save")

            waitFor("ks.totp.code")
            let code = textOf("ks.totp.code")
            XCTAssertTrue(
                isGroupedSixDigitCode(code),
                "the detail pane must render the code grouped (ui-spec §4.2); it showed \"\(code)\"")

            let caption = textOf("ks.totp.caption")
            XCTAssertTrue(
                caption.contains("Kagisecure") || caption.contains("e2e@example.test"),
                "ui-spec §4.2 shows issuer and account beneath the code, so a user with two "
                    + "second factors can tell them apart; the caption read \"\(caption)\"")
            capture("totp-detail-live", "The saved one-time password, running on the detail pane")
        }

        try step("the app and the CLI agree about what the code is right now") {
            var shown = digitsOf(textOf("ks.totp.code"))
            var fromCli = try codeFromCli()

            if shown != fromCli {
                // A TOTP window can roll over between two reads that are milliseconds apart, and
                // that is not a defect — it is the feature. One re-read is the whole allowance:
                // twice in a row is two independent implementations disagreeing.
                shown = digitsOf(textOf("ks.totp.code"))
                fromCli = try codeFromCli()
            }

            record(
                "totp-app-versus-cli",
                "app: \(shown)\ncli: \(fromCli)\nequal: \(shown == fromCli)",
                "The app's code and `kagisecure totp GitHub`, read in the same window")
            XCTAssertEqual(
                shown, fromCli,
                "the app and the CLI derive from the same seed through the same core, so within "
                    + "one window they must produce the same code")
        }

        try step("copying yields the code, never the seed") {
            // Read before and after the click: a window can roll over between pressing the button
            // and reading the screen back, and either side of that boundary is a correct answer.
            let before = digitsOf(textOf("ks.totp.code"))
            click("ks.totp.copy")
            let copied = try XCTUnwrap(
                waitForPasteboard(where: { $0.range(of: "^\\d{6}$", options: .regularExpression) != nil }),
                "ui-spec §4.2 promises the copy button puts the code on the clipboard; it held "
                    + "\(NSPasteboard.general.string(forType: .string) ?? "nothing")")
            let after = digitsOf(textOf("ks.totp.code"))

            XCTAssertTrue(
                copied == before || copied == after,
                "ui-spec §4.2: the copy button yields the code that is on screen. It copied "
                    + "\(copied) while the field showed \(before) and then \(after)")
            XCTAssertFalse(
                copied.contains("otpauth"),
                "the field stores an otpauth:// URI carrying the shared seed; copying that out "
                    + "would hand the second factor to whatever the user pastes into (ui-spec §4.2)")
            XCTAssertFalse(
                copied.contains(" "),
                "the grouping is for reading, not for pasting — a service's form does not want the "
                    + "space")
        }
    }

    func testTheRingCountsDownAndTheCodeRegenerates() throws {
        try Harness.seedVault(at: vaultPath)
        // Seeded through the CLI rather than the setup sheet: the sheet is the subject of the
        // scenario above, and this one is about what the ring does afterwards. `--value-stdin`
        // reads the concealed values and then the one-time-password URIs, one per line, in flag
        // order (crates/kagisecure-cli/src/cli.rs, AddArgs); Harness.cli writes the master
        // password first, so the URI is the only other line needed.
        try Harness.cliOk(
            [
                "item", "add", "--title", "TOTP fixture", "--category", "login",
                "--totp", "one-time password", "--value-stdin",
            ],
            vault: vaultPath, stdin: [Self.fixtureUri])

        launch()
        unlock()
        selectItem("TOTP fixture")

        var first = ""
        step("the field arrives already running") {
            waitFor("ks.totp.code")
            first = textOf("ks.totp.code")
            XCTAssertTrue(
                isGroupedSixDigitCode(first),
                "a configured one-time password renders as a grouped code, not as its stored URI "
                    + "(ui-spec §4.2); it showed \"\(first)\"")
            capture("totp-fixture-running", "The CLI-seeded one-time password, on the detail pane")
        }

        step("the countdown is alive") {
            let before = secondsRemaining()
            // Two seconds of real time, deliberately. What is under test is that the view keeps
            // recomputing from the wall clock — there is no element appearing or disappearing to
            // wait on, and the only way to observe a clock is to let some of it pass. Two seconds
            // is short enough that it cannot straddle a whole 30-second window.
            Thread.sleep(forTimeInterval: 2)

            let after = textOf("ks.totp.code")
            XCTAssertTrue(
                element("ks.totp.code").exists,
                "the one-time password disappeared while it was being watched")
            XCTAssertTrue(
                isGroupedSixDigitCode(after),
                "two seconds later the field must still be showing a grouped code — a tick that "
                    + "throws is how drift becomes a blank field; it showed \"\(after)\"")

            let remaining = secondsRemaining()
            record(
                "totp-countdown",
                "code before: \(first)\ncode after 2s: \(after)\n"
                    + "seconds remaining before: \(before.map { String($0) } ?? "not exposed")\n"
                    + "seconds remaining after: \(remaining.map { String($0) } ?? "not exposed")",
                "The countdown, sampled two seconds apart")
            if let before, let remaining, before > 3 {
                XCTAssertLessThan(
                    remaining, before,
                    "the ring counts down (ui-spec §4.2); it reported \(before)s and then "
                        + "\(remaining)s")
            }
            capture("totp-ring-countdown", "The countdown ring, two seconds on")
        }

        step("the ring is itself a copy button") {
            let ring = waitFor("ks.totp.ring")
            XCTAssertEqual(
                ring.elementType, .button,
                "ui-spec §4.2 says a click on the ring copies, so the ring has to be a control "
                    + "rather than decoration; it is element type \(ring.elementType.rawValue)")

            let before = digitsOf(textOf("ks.totp.code"))
            ring.click()
            let copied = waitForPasteboard(where: { $0.range(of: "^\\d{6}$", options: .regularExpression) != nil })
            XCTAssertNotNil(
                copied,
                "clicking the ring put no six-digit code on the clipboard; it held "
                    + "\((NSPasteboard.general.string(forType: .string) ?? "nothing").prefix(40))")
            let after = digitsOf(textOf("ks.totp.code"))
            XCTAssertTrue(
                copied == before || copied == after,
                "the ring and the copy button are the same action on the same code; the ring "
                    + "copied \(copied ?? "nothing") while the field showed \(before) then \(after)")
            capture("totp-ring-copied", "After a click on the ring, which copies the code")
        }
    }

    // MARK: - Getting to an unlocked vault

    private func unlock(file: StaticString = #filePath, line: UInt = #line) {
        waitFor("ks.lock.title", file: file, line: line)
        type(Harness.password, into: "ks.lock.password", file: file, line: line)
        click("ks.lock.unlock", file: file, line: line)
        waitFor("ks.sidebar.all", file: file, line: line)
    }

    // MARK: - Reading codes

    /// The text an element is showing, whichever half of the accessibility record it landed in.
    private func textOf(_ identifier: String) -> String {
        let found = element(identifier)
        if let value = found.value as? String, !value.isEmpty { return value }
        return text(of: found)
    }

    /// ui-spec §4.2: a six-digit code is rendered `123 456`.
    private func isGroupedSixDigitCode(_ text: String) -> Bool {
        text.range(of: "^\\d{3} \\d{3}$", options: .regularExpression) != nil
    }

    private func digitsOf(_ text: String) -> String {
        String(text.filter(\.isNumber))
    }

    /// What `kagisecure totp` says the code is, right now.
    ///
    /// The CLI prints the code on stdout and "valid for Ns" on stderr, so stdout is the whole
    /// answer (crates/kagisecure-cli/src/commands/generate.rs).
    private func codeFromCli(file: StaticString = #filePath, line: UInt = #line) throws -> String {
        let result = try Harness.cliOk(["totp", "GitHub"], vault: vaultPath, file: file, line: line)
        let printed = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertTrue(
            printed.range(of: "^\\d{6}$", options: .regularExpression) != nil,
            "`kagisecure totp GitHub` should print six digits and nothing else; it printed "
                + "\"\(printed)\"",
            file: file, line: line)
        return printed
    }

    /// How many seconds the view says are left, or `nil` when it does not say.
    ///
    /// The ring's own digits are `.accessibilityHidden(true)` and the button wrapping it is labeled
    /// "Copy the one-time password", so the number is not on `ks.totp.ring`. It *is* in the label
    /// of the containing `ks.totp.field`, which reads "One-time password 123 456, 17 seconds left".
    /// Both are tried, and `nil` is a legitimate answer — the countdown assertion is conditional on
    /// getting one.
    private func secondsRemaining() -> UInt32? {
        for identifier in ["ks.totp.ring", "ks.totp.field"] {
            let found = element(identifier)
            guard found.exists else { continue }
            for text in [text(of: found), (found.value as? String) ?? ""] {
                guard
                    let match = text.range(
                        of: "\\d+(?= seconds? left)", options: .regularExpression)
                else { continue }
                if let seconds = UInt32(text[match]) { return seconds }
            }
        }
        return nil
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

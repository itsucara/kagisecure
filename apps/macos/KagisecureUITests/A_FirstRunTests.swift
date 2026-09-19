import XCTest

/// First run and the lock screen (ui-spec.md §6, §12).
///
/// Named with an `A_` prefix because XCTest runs classes in alphabetical order and the report reads
/// better in the order a person meets the app: there is no vault, then there is one, then it locks.
/// Nothing depends on that order — every scenario builds its own world.
final class A_FirstRunTests: UITestCase {
    /// The one scenario that creates a vault through the app rather than through the CLI.
    ///
    /// It therefore pays the real KDF cost, which is the point: the first-run screen is where a
    /// user's actual vault is made, and a first run that took a second longer than the released
    /// parameters allow would be a real defect.
    func testFirstRunCreatesAVaultAndShowsTheRecoveryCodeOnce() throws {
        launch()

        step("the empty state offers to create a vault") {
            waitFor("ks.createVault.title")
            XCTAssertTrue(element("ks.createVault.title").exists)
            capture("first-run-empty", "First run: no vault yet")
        }

        step("a short password is refused, and says so") {
            type("short", into: "ks.createVault.password")
            type("short", into: "ks.createVault.confirmation")
            XCTAssertTrue(
                element("ks.createVault.tooShort").waitForExistence(timeout: Self.shortTimeout),
                "a password under eight characters should be called out")
            XCTAssertFalse(
                element("ks.createVault.create").isEnabled,
                "Create Vault must stay disabled while the password is too short")
        }

        step("two different passwords are refused") {
            type(Harness.password, into: "ks.createVault.password")
            type("something else entirely", into: "ks.createVault.confirmation")
            XCTAssertTrue(
                element("ks.createVault.mismatch").waitForExistence(timeout: Self.shortTimeout))
            capture("first-run-mismatch", "First run: the two passwords do not match")
        }

        step("a matching password creates the vault") {
            type(Harness.password, into: "ks.createVault.confirmation")
            XCTAssertTrue(element("ks.createVault.create").isEnabled)
            click("ks.createVault.create")
        }

        var code = ""
        step("the recovery code is shown, once, in Base32 groups") {
            waitFor("ks.recoveryCode.title", timeout: Self.timeout)
            let codeElement = waitFor("ks.recoveryCode.code")
            let shown = codeElement.value as? String ?? codeElement.label
            code = shown
            capture("first-run-recovery-code", "The recovery code, shown once")

            XCTAssertFalse(shown.isEmpty, "the recovery code must actually be on screen")
            // vault-format.md §3.2: RFC 4648 Base32 without padding, in hyphen-separated groups.
            let groups = shown.split(separator: "-")
            XCTAssertGreaterThanOrEqual(
                groups.count, 4, "the code should be grouped for transcription, got \(shown)")
            let alphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
            for group in groups {
                XCTAssertTrue(
                    CharacterSet(charactersIn: String(group)).isSubset(of: alphabet),
                    "\(group) is not Base32 — the whole code was \(shown)")
            }

            XCTAssertFalse(
                element("ks.recoveryCode.done").isEnabled,
                "Done should stay disabled until the user says they have written it down")
        }

        step("acknowledging it dismisses the sheet for good") {
            click("ks.recoveryCode.acknowledge")
            XCTAssertTrue(element("ks.recoveryCode.done").isEnabled)
            click("ks.recoveryCode.done")
            waitForDisappearance("ks.recoveryCode.title")
        }

        step("the main window is there, with the vault the user named") {
            waitFor("ks.sidebar.all")
            XCTAssertTrue(element("ks.sidebar.vaultName").exists)
            capture("first-run-main-window", "The main window, on a brand-new vault")
        }

        step("the code is not shown a second time") {
            // Locking and unlocking is the only way back to a fresh root view, and the sheet must
            // not come with it: "shown once and not stored anywhere" is a claim the file format
            // makes, and this is the only place a user could catch it being false.
            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            type(Harness.password, into: "ks.lock.password")
            click("ks.lock.unlock")
            waitFor("ks.sidebar.all")
            XCTAssertFalse(
                element("ks.recoveryCode.title").exists,
                "the recovery code sheet came back after an unlock")
        }

        record(
            "first-run-recovery-code-shape",
            "groups: \(code.split(separator: "-").count)\n"
                + "characters per group: \(Set(code.split(separator: "-").map(\.count)).sorted())",
            "The shape of the recovery code (never its value in the report)")
    }

    func testTheLockScreenUnlocksWithAPasswordAndRefusesAWrongOne() throws {
        try Harness.seedVault(at: vaultPath)
        launch()

        step("the app opens locked") {
            waitFor("ks.lock.title")
            XCTAssertTrue(element("ks.lock.title").exists)
            XCTAssertEqual(
                text("ks.lock.vaultFile"), "default.kagivault",
                "the lock screen should name the file it is about to open")
            capture("lock-screen", "The lock screen")
        }

        step("a wrong password is refused without saying why") {
            type("not the password", into: "ks.lock.password")
            click("ks.lock.unlock")
            // The alert's *button* carries an identifier; its message does not, because SwiftUI
            // hands an alert's message to AppKit as a string. So the message is read the way a
            // VoiceOver user would meet it — off the dialog itself.
            waitFor("ks.alert.ok")
            // Not `app.dialogs`: SwiftUI presents this as a sheet on the window, and which
            // collection AppKit files it under has moved. The message is a static text somewhere
            // in the app, so that is what is looked for.
            let message = "That did not unlock the vault."
            let found = app.descendants(matching: .staticText)
                .matching(NSPredicate(format: "value == %@ OR label == %@", message, message))
                .firstMatch
            XCTAssertTrue(
                found.waitForExistence(timeout: Self.shortTimeout),
                "the message must not distinguish a wrong password from a damaged file, and must "
                    + "say that much; on screen instead: "
                    + app.descendants(matching: .staticText).allElementsBoundByIndex
                    .prefix(30).map { text(of: $0) }.joined(separator: " | "))
            capture("lock-wrong-password", "A wrong password is refused")
            click("ks.alert.ok")
        }

        step("the right one opens it") {
            type(Harness.password, into: "ks.lock.password")
            click("ks.lock.unlock")
            waitFor("ks.sidebar.all")
            capture("lock-unlocked", "Unlocked")
        }

        step("⌘\\ locks it again, and says who locked it") {
            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            XCTAssertEqual(text("ks.lock.reason"), "Locked.")
            capture("lock-after-manual-lock", "Locked manually, with the reason shown")
        }
    }

    /// Open the "Use recovery code instead" disclosure.
    ///
    /// One click on the whole row. That is worth a helper only because it did not used to be true:
    /// the row was a `DisclosureGroup`, nothing could open it, and the fix — a real `Button` with
    /// the row as its hit area — is what this asserts stayed fixed.
    private func expandRecoveryDisclosure(file: StaticString = #filePath, line: UInt = #line) {
        let disclosure = waitFor("ks.lock.recoveryDisclosure", file: file, line: line)
        activate()

        disclosure.click()
        if element("ks.lock.recoveryCode").waitForExistence(timeout: Self.shortTimeout) { return }

        XCTFail(
            "\"Use recovery code instead\" would not open — the disclosure reported "
                + "value \(String(describing: disclosure.value)) and frame \(disclosure.frame); "
                + "the lock screen showed \(onScreenIdentifiers().joined(separator: ", "))",
            file: file, line: line)
    }

    func testTheRecoveryCodePathUnlocksAVaultWhosePasswordIsForgotten() throws {
        // The code comes from the CLI's own `vault init`, which prints it — the same code the
        // app's sheet would have shown. Reading it out of the app would mean creating the vault
        // through the UI again, and this scenario is about the *unlock* path.
        let created = try Harness.cliOk(
            ["vault", "init", "--name", "Personal"] + Harness.cheapKdf, vault: vaultPath)
        let code = try XCTUnwrap(
            created.stdout
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .first(where: { line in
                    let groups = line.split(separator: "-")
                    return groups.count >= 4
                        && groups.allSatisfy { group in
                            CharacterSet(charactersIn: String(group)).isSubset(
                                of: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))
                        }
                }),
            "`vault init` should print a recovery code; it printed:\n\(created.stdout)")

        launch()

        step("the recovery path is behind a disclosure, not in the way") {
            waitFor("ks.lock.title")
            XCTAssertFalse(
                element("ks.lock.recoveryCode").exists,
                "the recovery field should be collapsed until it is asked for")
            expandRecoveryDisclosure()
            capture("lock-recovery-disclosure", "\"Use recovery code instead\", expanded")
        }

        step("the code opens the vault") {
            type(code, into: "ks.lock.recoveryCode")
            click("ks.lock.recoveryUnlock")
            waitFor("ks.sidebar.all")
            capture("lock-recovery-unlocked", "Unlocked with the recovery code")
        }
    }
}

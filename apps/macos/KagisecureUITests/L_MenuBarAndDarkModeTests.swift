import XCTest

/// The menu-bar status item (ui-spec.md §6.3) and the dark-mode captures (§13).
final class L_MenuBarAndDarkModeTests: UITestCase {
    private var sidecar: Sidecar?
    private var project: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        project = scratch.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        sidecar?.stop()
        sidecar = nil
        try super.tearDownWithError()
    }

    // MARK: - The menu bar

    func testTheMenuBarItemShowsTheLockStateAndCanLockTheVault() throws {
        try Harness.seedVault(at: vaultPath)
        launch()

        try step("the status item is there before anything is unlocked") {
            let icon = try XCTUnwrap(
                statusItem(), "the status item was not reachable — see `statusItem()`")
            // The *state* is asserted from the menu, not from the icon. `MenuBarExtra`'s label is
            // an `Image`, and the `.accessibilityLabel` the app puts on it does not survive into
            // the `NSStatusItem` AppKit builds — the element is in the tree with its identifier and
            // an empty label. Recorded rather than asserted, because the icon carrying its state in
            // words is a VoiceOver improvement worth having and not a promise this suite can hold
            // SwiftUI to today.
            record(
                "menu-bar-icon-label",
                "identifier: \(icon.identifier)\nlabel: \(icon.label)\n"
                    + "value: \(String(describing: icon.value))",
                "What the status item exposes to the accessibility tree")
            capture("menu-bar-locked", "The menu-bar item while the vault is locked")
        }

        try step("and it offers the way in, not the way round") {
            let icon = try XCTUnwrap(statusItem())
            icon.click()
            XCTAssertTrue(
                text("ks.menuBar.lockState") == "Vault locked",
                "the menu should say the same thing the icon does")
            XCTAssertTrue(
                element("ks.menuBar.openMainWindow").exists,
                "the only action a locked vault offers is opening the window that unlocks it")
            XCTAssertFalse(
                element("ks.menuBar.lockNow").exists,
                "there is nothing to lock")
            capture("menu-bar-locked-menu", "The menu-bar menu while locked")
            app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        }

        try step("unlocking flips it, and the menu grows the things a key makes possible") {
            type(Harness.password, into: "ks.lock.password")
            click("ks.lock.unlock")
            waitFor("ks.sidebar.all")

            let icon = try XCTUnwrap(statusItem())
            icon.click()
            XCTAssertEqual(text("ks.menuBar.lockState"), "Vault unlocked")
            XCTAssertTrue(element("ks.menuBar.quickAccess").exists)
            XCTAssertTrue(text("ks.menuBar.agentState").contains("Serving agents"))
            XCTAssertFalse(
                element("ks.menuBar.revokeAll").isEnabled,
                "Revoke All is disabled while nothing is granted")
            capture("menu-bar-unlocked-menu", "The menu-bar menu while unlocked")
        }

        step("Lock Vault Now does") {
            click("ks.menuBar.lockNow")
            waitFor("ks.lock.title")
            capture("menu-bar-after-lock", "Locked from the menu bar")
        }
    }

    func testTheMenuBarItemBadgesAWaitingApproval() throws {
        try seedAgentVault()
        launch()
        unlock()

        let sidecar = try Sidecar(socket: socketPath, cwd: project)
        self.sidecar = sidecar
        XCTAssertNotNil(sidecar.initialize())

        let pending = PendingCall()
        DispatchQueue.global().async {
            pending.finish(
                sidecar.call(
                    "create_environment", ["name": "asked for by an agent"], timeout: 120))
        }

        try step("a waiting approval is counted in the menu-bar menu") {
            waitFor("ks.approval.sentence", timeout: Self.timeout)
            // The icon's symbol changes too (ui-spec.md §6.3), but the status item exposes no
            // label to assert that on — see the note in the previous scenario. The menu is where
            // the count is in words, and it is the same `pendingApprovals` the symbol is chosen
            // from, so this holds the app to the same fact through the surface that can be read.
            let icon = try XCTUnwrap(statusItem())
            icon.click()
            let waiting = waitFor("ks.menuBar.pendingApprovals", timeout: Self.shortTimeout)
            XCTAssertTrue(
                text(of: waiting).contains("waiting"),
                "the menu should offer the way to the sheet: \(text(of: waiting))")
            capture("menu-bar-pending", "The menu-bar menu with an approval waiting")
            app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        }

        step("answering it clears the badge") {
            click("ks.approval.deny")
            waitForDisappearance("ks.approval.sentence")
            _ = pending.wait()

            let icon = statusItem()
            icon?.click()
            let deadline = Date().addingTimeInterval(Self.shortTimeout)
            while Date() < deadline {
                if !element("ks.menuBar.pendingApprovals").exists {
                    capture("menu-bar-after-answer", "The count, gone")
                    app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
                    return
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            XCTFail("the waiting-approval entry outlived the request it was about")
        }
    }

    // MARK: - Dark mode

    func testTheMainWindowAndTheApprovalSheetRenderInDarkMode() throws {
        try seedAgentVault()
        try Harness.cliOk(
            [
                "item", "add", "--title", "GitHub", "--category", "login",
                "--field", "username=alice@example.test", "--secret", "password", "--value-stdin",
            ],
            vault: vaultPath, stdin: ["g1thub-p4ssw0rd"])

        // `NSApp.appearance`, set from a `#if DEBUG` launch argument. Not the *system* appearance:
        // a test that flipped the Mac into dark mode would be changing the machine it ran on, and
        // ui-spec.md §13 is about this application's palette, which is what this pins.
        launch(appearance: "dark")

        step("the lock screen, in the dark") {
            waitFor("ks.lock.title")
            capture("dark-lock", "The lock screen in dark mode")
        }

        unlock()

        step("the three-pane window, in the dark") {
            waitFor("ks.sidebar.all")
            capture("dark-main-window", "The main window in dark mode")
        }

        step("an item's detail, where the concealed and revealed states differ most") {
            let row = elements("ks.itemList.rowTitle").allElementsBoundByIndex
                .first { text(of: $0) == "GitHub" }
            row?.click()
            if element("ks.item.fieldReveal.password").waitForExistence(timeout: Self.shortTimeout) {
                click("ks.item.fieldReveal.password")
            }
            capture("dark-item-detail", "An item's detail in dark mode, one field revealed")
        }

        try step("and the approval sheet, which is the surface that has to read at a glance") {
            let sidecar = try Sidecar(socket: socketPath, cwd: project)
            self.sidecar = sidecar
            XCTAssertNotNil(sidecar.initialize())
            let pending = PendingCall()
            DispatchQueue.global().async {
                pending.finish(
                    sidecar.call("create_environment", ["name": "dark mode"], timeout: 120))
            }
            waitFor("ks.approval.sentence", timeout: Self.timeout)
            capture("dark-approval-sheet", "The approval sheet in dark mode")

            // The verdict and the warnings pair colour with an icon and text, so that the sheet
            // still says "unverified" to somebody who cannot see the red (ui-spec.md §13).
            XCTAssertTrue(
                text("ks.approval.verdict").lowercased().contains("unverified"),
                "colour is never the only signal: the verdict is in the text too")

            click("ks.approval.deny")
            _ = pending.wait()
        }
    }

    // MARK: - Helpers

    /// The app's status item, if XCUITest can see it.
    ///
    /// A `MenuBarExtra` is an `NSStatusItem` in the system menu bar. It belongs to this application,
    /// so it is somewhere in this application's element tree — but *where* has moved between macOS
    /// releases (an extra `menuBars` element, a `statusItems` collection, or a plain
    /// `menuBarItem`). Rather than pick one and be wrong on the next release, this looks for the
    /// identifier the app sets, in each of the places it has been known to live.
    private func statusItem() -> XCUIElement? {
        let byIdentifier = element("ks.menuBar.icon")
        if byIdentifier.exists { return byIdentifier }

        for bar in app.menuBars.allElementsBoundByIndex {
            let candidate = bar.descendants(matching: .any)
                .matching(identifier: "ks.menuBar.icon").firstMatch
            if candidate.exists { return candidate }
        }
        let statusItems = app.descendants(matching: .statusItem)
        if statusItems.count > 0 { return statusItems.firstMatch }
        return nil
    }

    private func unlock() {
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
        let deadline = Date().addingTimeInterval(Self.timeout)
        while Date() < deadline {
            if text("ks.sidebar.listenerState") == "Serving agents" { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    private func seedAgentVault() throws {
        try Harness.cliOk(["vault", "init", "--name", "Personal"] + Harness.cheapKdf, vault: vaultPath)
        try Harness.cliOk(
            ["env", "agent-access", "--allow", "--logical-vault", "Personal"], vault: vaultPath)
    }
}

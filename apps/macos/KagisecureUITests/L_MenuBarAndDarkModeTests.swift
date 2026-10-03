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

        try step("the status item is there before anything is unlocked, and says it is locked") {
            let icon = try XCTUnwrap(
                statusItem(), "the status item was not reachable — see `statusItem()`")
            // The icon's `.accessibilityLabel` is the status item's *title* (`AXTitle`), not its
            // `label` (`AXDescription`, empty) — measured; see "Reading the status item" below.
            // It is what VoiceOver says for the icon, so the lock state is asserted on it.
            XCTAssertEqual(
                icon.title, "Kagisecure, vault locked",
                "the icon says the lock state in words, not only as a padlock symbol")
            capture("menu-bar-locked", "The menu-bar item while the vault is locked")
        }

        try step("and its menu offers the way in, not the way round") {
            XCTAssertNotNil(
                statusMenuItem("Vault locked"),
                "the menu says the lock state; it lists \(statusMenuTitles())")
            XCTAssertNotNil(
                statusMenuItem("Open Kagisecure"),
                "the only action a locked vault offers is opening the window that unlocks it")
            XCTAssertNil(statusMenuItem("Lock Vault Now"), "there is nothing to lock")

            try openStatusMenu()
            capture("menu-bar-locked-menu", "The menu-bar menu while locked")
            closeStatusMenu()
        }

        try step("unlocking flips it, and the menu grows the things a key makes possible") {
            type(Harness.password, into: "ks.lock.password")
            click("ks.lock.unlock")
            waitFor("ks.sidebar.all")

            let icon = try XCTUnwrap(statusItem())
            XCTAssertTrue(
                waitUntil("the icon says unlocked") { icon.title == "Kagisecure, vault unlocked" },
                "the icon follows the lock state; it says \(icon.title)")
            XCTAssertNotNil(
                statusMenuItem("Vault unlocked"),
                "the menu says the lock state; it lists \(statusMenuTitles())")
            XCTAssertNotNil(statusMenuItem("Quick Access"))
            XCTAssertTrue(
                waitUntil("the menu says the listener is up") {
                    self.statusMenuItem(containing: "Serving agents") != nil
                },
                "the menu says the listener is up; it lists \(statusMenuTitles())")
            let revokeAll = try XCTUnwrap(statusMenuItem("Revoke All Leases"))
            XCTAssertFalse(revokeAll.isEnabled, "Revoke All is disabled while nothing is granted")

            try openStatusMenu()
            capture("menu-bar-unlocked-menu", "The menu-bar menu while unlocked")
        }

        try step("Lock Vault Now does") {
            // The menu is still open from the previous step, so the item has a frame to click.
            try XCTUnwrap(statusMenuItem("Lock Vault Now")).click()
            waitFor("ks.lock.title")
            let icon = try XCTUnwrap(statusItem())
            XCTAssertTrue(
                waitUntil("the icon says locked") { icon.title == "Kagisecure, vault locked" },
                "the icon follows the lock state; it says \(icon.title)")
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

        try step("a waiting approval is counted on the icon and in the menu") {
            waitFor("ks.approval.sentence", timeout: Self.timeout)
            let icon = try XCTUnwrap(statusItem())
            // The icon's symbol changes too (ui-spec.md §6.3); its title is that state in words,
            // chosen from the same `pendingApprovals` the symbol is.
            XCTAssertTrue(
                waitUntil("the icon counts the approval") {
                    icon.title == "Kagisecure, vault unlocked, 1 approval(s) waiting"
                },
                "the icon says an approval is waiting; it says \(icon.title)")
            XCTAssertNotNil(
                statusMenuItem(containing: "1 approval(s) waiting"),
                "the menu should offer the way to the sheet; it lists \(statusMenuTitles())")

            try openStatusMenu()
            capture("menu-bar-pending", "The menu-bar menu with an approval waiting")
            closeStatusMenu()
        }

        try step("answering it clears the badge") {
            click("ks.approval.deny")
            waitForDisappearance("ks.approval.sentence")
            _ = pending.wait()

            // The count follows the agent's status poll, so it can take a moment to catch up.
            // The menu's entries follow the app's state whether it is open or not (measured), so
            // this waits on them directly rather than reopening the menu to look.
            let icon = try XCTUnwrap(statusItem())
            XCTAssertTrue(
                waitUntil("the icon stops counting") { icon.title == "Kagisecure, vault unlocked" },
                "the badge outlived the request it was about; the icon says \(icon.title)")
            XCTAssertTrue(
                waitUntil("the menu entry goes") {
                    self.statusMenuItem(containing: "approval(s) waiting") == nil
                },
                "the waiting-approval entry outlived the request it was about; the menu lists "
                    + "\(statusMenuTitles())")

            try openStatusMenu()
            capture("menu-bar-after-answer", "The count, gone")
            closeStatusMenu()
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
                // A presence-gated release (ADR-0038): the value arrives after the scripted
                // prompt answers.
                waitForValue("ks.item.fieldValue.password", equals: "g1thub-p4ssw0rd")
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
    /// A `MenuBarExtra` is an `NSStatusItem`. It belongs to this application, so it is in this
    /// application's element tree — a `statusItem` in the second of its `menuBars`
    /// (`AXExtrasMenuBar`). Found by the identifier the app sets, the one `ks.menuBar.*`
    /// identifier that survives into the tree.
    private func statusItem() -> XCUIElement? {
        let byIdentifier = element("ks.menuBar.icon")
        if byIdentifier.exists { return byIdentifier }
        let statusItems = app.descendants(matching: .statusItem)
        if statusItems.count > 0 { return statusItems.firstMatch }
        return nil
    }

    // MARK: Reading the status item
    //
    // What a menu-style `MenuBarExtra` puts in the accessibility tree — measured on macOS 27 with a
    // probe app read back through `AXUIElement` (docs/e2e-harness.md §7.2):
    //
    // - The status item's `AXTitle` is the icon's `.accessibilityLabel`, and follows it live. Its
    //   `AXDescription`, which XCUITest calls `label`, is empty. So `icon.title` is the lock state.
    // - Its menu is an `AXMenu` child of the status item **whether it is open or not**, with one
    //   `AXMenuItem` per entry: the entry's title and enabled state, and no
    //   `.accessibilityIdentifier` (a button's comes out as `menuAction:`). The entries follow the
    //   app's state while the menu is closed, too. So what the menu says is read from the status
    //   item's own subtree, by title — which also keeps it apart from the main menu bar, where
    //   "Lock Vault Now" and "Quick Access" are commands as well.
    // - Closed, the menu and its entries have a zero-size frame; open, a real one. That, not
    //   `isHittable`, is how a scenario knows the menu is open.
    // - The status item's frame is where the app was told the item is, which is not necessarily
    //   where it can be clicked. A menu-bar manager that collapses status items (BetterTouchTool's,
    //   on the Mac this was measured on) leaves a collapsed item reporting a frame under its own
    //   chevron, and the first click there expands the hidden items instead of opening this menu;
    //   after it, the frame is the real one. That is why `openStatusMenu` may click twice.

    /// The titles of every entry in the status item's menu, for failure messages.
    private func statusMenuTitles() -> [String] {
        statusItem()?.menuItems.allElementsBoundByIndex.map(\.title) ?? []
    }

    /// The status item's menu entry titled exactly `title`, or `nil`.
    private func statusMenuItem(_ title: String) -> XCUIElement? {
        guard let icon = statusItem() else { return nil }
        let match = icon.menuItems.matching(NSPredicate(format: "title == %@", title)).firstMatch
        return match.exists ? match : nil
    }

    /// The status item's menu entry whose title contains `fragment` — for the entries that carry
    /// a count.
    private func statusMenuItem(containing fragment: String) -> XCUIElement? {
        guard let icon = statusItem() else { return nil }
        let match = icon.menuItems.matching(NSPredicate(format: "title CONTAINS %@", fragment))
            .firstMatch
        return match.exists ? match : nil
    }

    /// Whether the status item's menu is open: on screen, with a frame.
    private func statusMenuIsOpen() -> Bool {
        guard let menu = statusItem()?.menus.firstMatch, menu.exists else { return false }
        return menu.frame.width > 0 && menu.frame.height > 0
    }

    /// Click the status item until its menu is open.
    ///
    /// More than once only when a click did not open it — the collapsed-status-item case above,
    /// where the click revealed the item instead. Each try re-reads the item, so the next click
    /// goes where the item now is.
    private func openStatusMenu(file: StaticString = #filePath, line: UInt = #line) throws {
        var frames: [CGRect] = []
        for _ in 0..<3 {
            let icon = try XCTUnwrap(
                statusItem(), "the status item was not reachable — see `statusItem()`",
                file: file, line: line)
            frames.append(icon.frame)
            activate()
            icon.click()
            if waitUntil("the status menu is open", timeout: 3, { self.statusMenuIsOpen() }) {
                return
            }
        }
        XCTFail(
            "the status item's menu did not open after three clicks, at \(frames). An item a "
                + "menu-bar manager keeps hidden cannot be clicked; allow it in that manager.",
            file: file, line: line)
    }

    /// Close the status item's menu, and wait until it has.
    private func closeStatusMenu() {
        guard statusMenuIsOpen() else { return }
        app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        waitUntil("the status menu has closed") { !self.statusMenuIsOpen() }
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

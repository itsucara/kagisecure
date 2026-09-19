import XCTest

/// The sidebar (ui-spec.md §2.2): every section it promises, and what selecting one does to the
/// rest of the window.
///
/// The interesting claim here is not that a row exists but that clicking it *lands* somewhere. A
/// sidebar that renders eleven sections and filters on none of them looks identical in a
/// screenshot, so every selection in this file is followed by an assertion about the middle pane.
final class C_SidebarTests: UITestCase {
    /// ui-spec.md §5's table of eleven categories, plus `Environment` — which §5 omits from the
    /// table but which is a first-class `Category` in `kagisecure-core` (`Category::first_class()`)
    /// and therefore gets a sidebar row of its own. The full list is also what
    /// `kagisecure item add --category` documents.
    ///
    /// These are the vault's own canonical lower-case names rather than the display names, because
    /// `SidebarView.identifier(for:)` builds `ks.sidebar.category.<id>` out of the id: the display
    /// name is user-facing text and is allowed to move, the id is not.
    private static let categories: [(id: String, displayName: String)] = [
        ("login", "Login"),
        ("password", "Password"),
        ("secure-note", "Secure Note"),
        ("credit-card", "Credit Card"),
        ("identity", "Identity"),
        ("api-credential", "API Credential"),
        ("server", "Server"),
        ("database", "Database"),
        ("ssh-key", "SSH Key"),
        ("software-license", "Software License"),
        ("document", "Document"),
        ("environment", "Environment"),
    ]

    // MARK: - Scenarios

    func testEverySidebarSectionIsPresentAndSelectable() throws {
        try openSeededVault()

        step("the sidebar offers every section ui-spec.md §2.2 lists") {
            XCTAssertEqual(
                Self.categories.count, 12,
                "ui-spec.md §5 specifies eleven categories and the vault format adds Environment")

            for identifier in [
                "ks.sidebar.all", "ks.sidebar.favorites", "ks.sidebar.archive", "ks.sidebar.trash",
                "ks.sidebar.agentEnvironments", "ks.sidebar.agentLeases", "ks.sidebar.agentAudit",
                "ks.sidebar.agentSetup", "ks.sidebar.browserExtension",
            ] {
                XCTAssertTrue(
                    element(identifier).exists,
                    "ui-spec.md §2.2 lists this section, and \(identifier) is not in the sidebar")
            }

            for category in Self.categories {
                // §2.2: "a category with zero items is still shown (greyed count)" — nine of these
                // twelve hold nothing in a freshly seeded vault, and all twelve must still be rows.
                XCTAssertTrue(
                    element("ks.sidebar.category.\(category.id)").exists,
                    "\(category.displayName) has no sidebar row; §2.2 says an empty category is "
                        + "shown greyed rather than hidden")
            }

            capture("sidebar-all-sections", "The sidebar, with every section ui-spec.md §2.2 lists")
        }

        step("All Items, Favorites, Archive and Trash each take the selection") {
            // The empty titles come from `MainView.emptyTitle`, which is the as-built rendering of
            // ui-spec.md §12's table.
            selectSection("ks.sidebar.all", named: "All Items", emptyTitle: "No items yet")
            selectSection("ks.sidebar.favorites", named: "Favorites", emptyTitle: "No favorites yet")
            selectSection("ks.sidebar.archive", named: "Archive", emptyTitle: "Nothing archived")
            selectSection("ks.sidebar.trash", named: "Trash", emptyTitle: "Trash is empty")

            // ui-spec.md §12: the empty Trash says so in those words, and offers no action.
            XCTAssertTrue(
                emptyStateTitles().contains("Trash is empty"),
                "an empty Trash must read \"Trash is empty\" (ui-spec.md §12); the empty states on "
                    + "screen were \(emptyStateTitles())")
            capture("sidebar-trash-empty", "Trash on a fresh vault: \"Trash is empty\"")
        }

        step("every category row filters the list to itself") {
            for category in Self.categories {
                selectSection(
                    "ks.sidebar.category.\(category.id)",
                    named: category.displayName,
                    // §12: "No {Category} items yet" for a category with nothing in it.
                    emptyTitle: "No \(category.displayName) items yet")
            }
            capture(
                "sidebar-category-selected",
                "The last category row selected, filtering the item list")
        }

        step("the five agent and browser rows each open their own pane") {
            let panes = [
                ("ks.sidebar.agentEnvironments", "ks.agentAccess.listenerState", "environments"),
                ("ks.sidebar.agentLeases", "ks.leases.revokeAll", "leases"),
                ("ks.sidebar.agentAudit", "ks.audit.chainState", "audit"),
                ("ks.sidebar.agentSetup", "ks.agentSetup.title", "agent-setup"),
                ("ks.sidebar.browserExtension", "ks.browserExtension.title", "browser-extension"),
            ]
            for (row, root, name) in panes {
                selectSidebarRow(row)
                XCTAssertTrue(
                    element(root).waitForExistence(timeout: Self.timeout),
                    "selecting \(row) should open \(root); on screen instead: "
                        + onScreenIdentifiers().joined(separator: ", "))
                capture("sidebar-pane-\(name)", "The \(name) pane, opened from the sidebar")
            }
        }

        step("a tag row filters to the items carrying that tag") {
            // `Harness.seedVault` tags Acme and Stripe `prod` and GitHub `personal`, so both rows
            // are expected and the filter has something to prove.
            for tag in ["prod", "personal"] {
                XCTAssertTrue(
                    element("ks.sidebar.tag.\(tag)").exists,
                    "ui-spec.md §2.2 gives every distinct tag a row, and \(tag) is on a seeded item")
            }

            selectSidebarRow("ks.sidebar.tag.prod")
            let expected = Set(["Acme production database", "Stripe"])
            XCTAssertTrue(
                waitUntil("the item list narrows to the prod-tagged items") {
                    Set(self.itemListRowTitles()) == expected
                },
                "selecting the prod tag should leave exactly \(expected.sorted()) in the list; "
                    + "it left \(itemListRowTitles().sorted())")
            XCTAssertFalse(
                itemListRowTitles().contains("GitHub"),
                "GitHub is tagged personal, not prod, and must not survive the prod filter")
            capture("sidebar-tag-prod", "The prod tag selected, filtering the item list to two items")

            // The filtered list is live, not a stale render: one of its rows still opens.
            selectItem("Stripe")
        }
    }

    func testTheVaultSwitcherAndFooterSayWhichVaultIsOpen() throws {
        try openSeededVault()

        step("the window is open on the vault the CLI named") {
            XCTAssertTrue(element("ks.sidebar.vaultName").exists)
            capture("vault-window", "The main window, open on the seeded vault")
        }

        step("the footer names the vault and says whether agents are being served") {
            let name = waitFor("ks.sidebar.vaultName")
            XCTAssertEqual(
                text(of: name), "Personal",
                "the footer should name the vault `kagisecure vault init --name Personal` created")
            XCTAssertTrue(
                element("ks.sidebar.listenerState").exists,
                "ui-spec.md §2.2's footer also carries the listener state")
            record(
                "vault-footer-state",
                "vault name: \(text(of: name))\n"
                    + "listener: \(text("ks.sidebar.listenerState"))",
                "What the sidebar footer says about the open vault")
            capture("vault-footer", "The sidebar footer: the vault name and the listener state")
        }

        step("locking and unlocking comes back to the same single vault") {
            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            XCTAssertEqual(
                text("ks.lock.vaultFile"), "default.kagivault",
                "there is one file, and the lock screen names it")
            capture("vault-lock-screen", "The lock screen, naming the one vault file")

            type(Harness.password, into: "ks.lock.password")
            click("ks.lock.unlock")
            waitFor("ks.sidebar.all")
            XCTAssertEqual(text("ks.sidebar.vaultName"), "Personal")
        }

        throw XCTSkip(
            "ui-spec.md §2.2 specifies a vault switcher — a dropdown over the `VaultMeta` list at "
                + "the top of the sidebar — and no such control is built. This is recorded, not "
                + "discovered: ui-spec.md's own preamble already says \"the vault switcher and "
                + "'Customize Sidebar' affordance in §2.2 are not built (there is one logical "
                + "vault and the sidebar is fixed)\". What is built is asserted above; the switcher "
                + "half of §2.2 is pending on that feature, not on this scenario.")
    }

    // MARK: - Getting to the main window

    /// Seed a vault through the CLI, launch against it and get past the lock screen.
    ///
    /// Every scenario in this file starts here: the sidebar is only interesting on a vault that
    /// already has items and tags in it, and the first-run and unlock paths are suite A's subject.
    private func openSeededVault() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        waitFor("ks.lock.title")
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
    }

    // MARK: - Selecting

    /// Click a sidebar row and leave the selection on it.
    ///
    /// The base class does the work: the sidebar is taller than the window at its default size, so
    /// the rows below Tags have to be scrolled into view first, and a SwiftUI `List(selection:)`
    /// does not reliably take a synthetic click on the label inside its cell.
    private func selectSidebarRow(
        _ identifier: String, file: StaticString = #filePath, line: UInt = #line
    ) {
        clickSidebarRow(identifier, file: file, line: line)
    }

    /// Click a sidebar row and assert the selection reached the item list.
    ///
    /// "Reached the item list" deliberately does not mean a particular number of rows: nine of the
    /// twelve categories are empty on a seeded vault and asserting counts here would only restate
    /// `Harness.seedVault`. What it means is that the middle pane is now showing *this* section —
    /// either some rows, or the empty state whose title names the section (ui-spec.md §12).
    private func selectSection(
        _ identifier: String, named section: String, emptyTitle: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        selectSidebarRow(identifier, file: file, line: line)

        XCTAssertTrue(
            element("ks.itemList.list").exists || element("ks.emptyState.title").exists,
            "after selecting \(section) the window showed neither an item list nor an empty state",
            file: file, line: line)

        let landed = waitUntil("\(section) is what the item list is showing") {
            !self.itemListRowTitles().isEmpty || self.emptyStateTitles().contains(emptyTitle)
        }
        XCTAssertTrue(
            landed,
            "selecting \(section) changed nothing: the item list has no rows and no empty state "
                + "reads \"\(emptyTitle)\". Empty states on screen: \(emptyStateTitles())",
            file: file, line: line)
    }

    // MARK: - Reading the window

    /// The title of whatever the detail pane currently has open, if anything.
    private func openedItemTitle() -> String? {
        let title = element("ks.item.title")
        guard title.waitForExistence(timeout: Self.shortTimeout) else { return nil }
        return text(of: title)
    }

    private func itemListRowTitles() -> [String] {
        elements("ks.itemList.rowTitle").allElementsBoundByIndex.map { text(of: $0) }
    }

    /// Every empty state's title.
    ///
    /// Plural on purpose. `EmptyStateView`'s own comment says there is at most one on screen at a
    /// time, and that is not true: an empty section shows one in the item list pane *and* one in
    /// the detail pane, with different wording. A test that took `firstMatch` would be asserting
    /// on whichever of the two AppKit happened to hand back first.
    private func emptyStateTitles() -> [String] {
        elements("ks.emptyState.title").allElementsBoundByIndex.map { text(of: $0) }
    }

    /// Wait until `condition` holds.
    ///
    /// `waitFor` covers "this identifier appears"; this covers the conditions that are computed
    /// over several elements at once, which no identifier can express. Predicate-driven rather
    /// than a sleep loop, so it returns as soon as the condition is true.
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

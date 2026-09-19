import AppKit
import XCTest

/// Items: creating one per category, editing, concealed fields, and the archive/trash lifecycle
/// (ui-spec.md §3–§5).
final class D_ItemTests: UITestCase {
    /// The twelve first-class categories and the fields their "+ New" flow pre-populates
    /// (ui-spec.md §5, `Category::default_fields` in `kagisecure-core`).
    ///
    /// Written out here rather than read from the app, on purpose. A test that asks the app what
    /// the template is and then asserts the app produced it asserts nothing; this table is the
    /// second opinion, and it is the thing that fails when somebody quietly drops `CVV` from the
    /// credit-card template.
    static let templates: [(id: String, display: String, fields: [String])] = [
        ("login", "Login", ["username", "password", "one-time password"]),
        ("password", "Password", ["password"]),
        ("secure-note", "Secure Note", []),
        (
            "credit-card", "Credit Card",
            ["cardholder name", "number", "expiry", "CVV", "PIN", "issuer"]
        ),
        ("identity", "Identity", ["first name", "last name", "email", "phone", "address"]),
        ("api-credential", "API Credential", ["key", "endpoint"]),
        ("server", "Server", ["hostname", "username", "password"]),
        ("database", "Database", ["hostname", "port", "username", "password"]),
        ("ssh-key", "SSH Key", ["private key", "public key", "fingerprint", "passphrase"]),
        (
            "software-license", "Software License",
            ["license key", "licensed to", "version", "email"]
        ),
        ("document", "Document", []),
        ("environment", "Environment", []),
    ]

    // MARK: - Scenarios

    func testOneItemPerCategoryArrivesWithItsTemplateFields() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()

        for template in Self.templates {
            step("a new \(template.display) carries its template") {
                click("ks.toolbar.newItem")
                click("ks.toolbar.newItem.\(template.id)")

                // `VaultStore.createItem` titles a new item "New <display name>" and selects it.
                let title = waitFor("ks.item.title")
                XCTAssertEqual(
                    text(of: title), "New \(template.display)",
                    "a new item should be titled after its category so it is findable before it "
                        + "is named")
                XCTAssertEqual(text("ks.item.category"), template.display)

                if template.fields.isEmpty {
                    XCTAssertTrue(
                        element("ks.item.noFields").waitForExistence(timeout: Self.shortTimeout),
                        "\(template.display) has no template fields (ui-spec.md §5), so the pane "
                            + "should say so rather than render an empty box")
                } else {
                    for field in template.fields {
                        XCTAssertTrue(
                            element("ks.item.fieldLabel.\(field)")
                                .waitForExistence(timeout: Self.shortTimeout),
                            "\(template.display) should start with a \(field) field")
                    }
                }
            }
        }

        capture("items-every-category", "One item created per category, the last one open")
        record(
            "items-every-category",
            Self.templates
                .map { "\($0.display): \($0.fields.joined(separator: ", "))" }
                .joined(separator: "\n"),
            "The template each category's + New flow produced")
    }

    func testAnItemIsEditedTaggedFavouritedAndGrowsACustomField() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()
        selectItem("GitHub")

        step("edit mode opens on ⌘E") {
            app.typeKey("e", modifierFlags: .command)
            waitFor("ks.edit.title")
            capture("item-edit-mode", "Edit mode, with the concealed value shown for correction")
        }

        step("a concealed field shows its real value while being edited") {
            // ui-spec.md §4.3: fixing a typo must not need a separate reveal step.
            let value = waitFor("ks.edit.fieldValue.password")
            XCTAssertEqual(
                value.value as? String, "g1thub-p4ssw0rd",
                "edit mode should show the concealed value it is about to let you change")
        }

        step("the title, a tag and a custom field all change together") {
            type("GitHub (work)", into: "ks.edit.title")
            type("personal, work", into: "ks.edit.tags")

            click("ks.edit.addField")
            app.menuItems["Text"].click()
            // A new row starts life labelled "New field"; renaming it is what makes the custom
            // field a custom field.
            type("recovery email", into: "ks.edit.fieldLabel.New field")
            type("alice+recovery@example.test", into: "ks.edit.fieldValue.recovery email")
            capture("item-edit-custom-field", "A custom field added in edit mode")

            click("ks.edit.save")
            waitForDisappearance("ks.edit.title")
        }

        step("all three changes are on the item, and in the file") {
            XCTAssertEqual(text("ks.item.title"), "GitHub (work)")
            XCTAssertTrue(element("ks.item.tag.work").exists, "the new tag should be on the item")
            XCTAssertTrue(element("ks.item.tag.personal").exists, "the old tag should survive")
            XCTAssertEqual(
                text("ks.item.fieldValue.recovery email"),
                "alice+recovery@example.test")
            capture("item-edited", "The item after editing")

            // The sidebar is built from the vault, not from the view, so a new tag appearing there
            // is the evidence that the edit reached the file rather than the screen.
            XCTAssertTrue(
                element("ks.sidebar.tag.work").waitForExistence(timeout: Self.shortTimeout),
                "a tag added to an item should appear in the sidebar's Tags section")
        }

        step("the favourite star round-trips") {
            click("ks.item.favorite")
            XCTAssertTrue(
                element("ks.sidebar.favorites").waitForExistence(timeout: Self.shortTimeout))
            clickSidebarRow("ks.sidebar.favorites")
            XCTAssertTrue(
                itemListTitles().contains("GitHub (work)"),
                "a favourited item should be in Favorites; saw \(itemListTitles())")
            capture("item-favorited", "Favorites, with the item just starred")
        }
    }

    func testAConcealedFieldRevealsCopiesAndIsTakenBackOffTheClipboard() throws {
        try Harness.seedVault(at: vaultPath)
        // Fifteen seconds is the shortest interval the Settings pane offers, which makes it the
        // shortest one a user can actually choose — so it is the one worth waiting out.
        launch(pasteboardSeconds: 15)
        unlock()
        selectItem("GitHub")

        step("a concealed value is masked at a fixed width, and says so out loud") {
            let masked = waitFor("ks.item.fieldValue.password")
            // The dots are the *value*; the `label` is what VoiceOver reads, and ui-spec.md §13
            // asks it to announce the field rather than recite ten bullets. Two different
            // promises, asserted separately.
            XCTAssertEqual(
                masked.value as? String, "••••••••••",
                "the mask must be length-independent — ten dots for any password (ui-spec.md §4.2)")
            XCTAssertEqual(
                masked.label, "password, concealed, activate to reveal",
                "a concealed field announces itself rather than reading the mask (ui-spec.md §13)")
            capture("item-concealed", "A concealed field, masked")
        }

        step("the eye reveals it") {
            click("ks.item.fieldReveal.password")
            let revealed = waitFor("ks.item.fieldValue.password")
            XCTAssertEqual(revealed.value as? String, "g1thub-p4ssw0rd")
            capture("item-revealed", "The same field, revealed")
            click("ks.item.fieldReveal.password")
            XCTAssertEqual(
                waitFor("ks.item.fieldValue.password").value as? String, "••••••••••",
                "the eye should conceal again")
        }

        let stamp = NSPasteboard.general.changeCount
        step("copying puts the value on the clipboard, marked concealed") {
            click("ks.item.fieldCopy.password")
            XCTAssertTrue(
                waitForPasteboard("g1thub-p4ssw0rd"),
                "the copy button should put the value on the clipboard without revealing it")
            // The marker clipboard managers honour, so a password does not land in a searchable
            // history (PasteboardService's whole reason for existing).
            XCTAssertNotNil(
                NSPasteboard.general.string(forType: .init("org.nspasteboard.ConcealedType")),
                "a copied secret must carry org.nspasteboard.ConcealedType")
            XCTAssertGreaterThan(NSPasteboard.general.changeCount, stamp)
        }

        step("and it is gone again after the configured interval") {
            // 15 seconds configured, plus slack for the timer's own scheduling. `Thread.sleep` and
            // not a polling wait: the assertion is that the value is *still there* right up until
            // the interval, and a poll that returned early would pass a clipboard cleared too soon.
            Thread.sleep(forTimeInterval: 8)
            XCTAssertEqual(
                NSPasteboard.general.string(forType: .string), "g1thub-p4ssw0rd",
                "the clipboard should not be cleared before the interval the user chose")
            XCTAssertTrue(
                waitForPasteboardToNotContain("g1thub-p4ssw0rd", timeout: 20),
                "PasteboardService should take the value back off the clipboard after 15 seconds")
            capture("item-clipboard-cleared", "The item after the clipboard cleared itself")
        }
    }

    func testAnItemGoesToTheArchiveComesBackAndIsFinallyDeletedForGood() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()
        selectItem("Stripe")

        step("archiving moves it out of All Items") {
            click("ks.toolbar.more")
            click("ks.item.menu.archive")

            // The detail pane does not stay on it: archiving takes the item out of All Items, the
            // list re-reads the vault, and the selection moves to whatever is still there. That is
            // the behaviour ui-spec.md §2.2 asks for, so the badge is asserted where the item now
            // lives rather than where it used to be.
            XCTAssertFalse(
                itemListTitles().contains("Stripe"),
                "All Items shows non-archived items only (ui-spec.md §2.2); saw \(itemListTitles())")

            clickSidebarRow("ks.sidebar.archive")
            XCTAssertTrue(itemListTitles().contains("Stripe"), "it should be in Archive")
            selectItem("Stripe")
            XCTAssertTrue(
                element("ks.item.archivedBadge").waitForExistence(timeout: Self.shortTimeout),
                "an archived item should say so on its own detail pane")
            capture("item-archive-section", "The Archive section, with the archived item open")
        }

        step("and unarchiving brings it back") {
            click("ks.toolbar.more")
            click("ks.item.menu.archive")
            clickSidebarRow("ks.sidebar.all")
            XCTAssertTrue(
                itemListTitles().contains("Stripe"), "saw \(itemListTitles())")
        }

        step("trashing is a different, reversible thing") {
            selectItem("Stripe")
            click("ks.toolbar.more")
            click("ks.item.menu.trash")
            clickSidebarRow("ks.sidebar.trash")
            XCTAssertTrue(itemListTitles().contains("Stripe"))
            selectItem("Stripe")
            XCTAssertTrue(
                element("ks.item.trashedBadge").waitForExistence(timeout: Self.shortTimeout))
            capture("item-trash", "The Trash")

            click("ks.toolbar.more")
            click("ks.item.menu.restore")
            clickSidebarRow("ks.sidebar.all")
            XCTAssertTrue(itemListTitles().contains("Stripe"), "Restore should undo a trashing")
        }

        try step("permanent delete is permanent") {
            selectItem("Stripe")
            click("ks.toolbar.more")
            click("ks.item.menu.trash")
            clickSidebarRow("ks.sidebar.trash")
            selectItem("Stripe")
            click("ks.toolbar.more")
            click("ks.item.menu.deleteForever")

            XCTAssertTrue(
                element("ks.emptyState.title").waitForExistence(timeout: Self.shortTimeout),
                "the last item left the Trash, so the Trash should show its empty state")
            XCTAssertEqual(text("ks.emptyState.title"), "Trash is empty")
            capture("item-trash-empty", "The Trash, emptied")

            // The file is the record, not the screen. A CLI listing is the independent check that
            // "delete permanently" reached it.
            let listing = try Harness.cliOk(["item", "list"], vault: vaultPath)
            XCTAssertFalse(
                listing.stdout.contains("Stripe"),
                "a permanently deleted item must be gone from the vault file, not just hidden:\n"
                    + listing.stdout)
            record("item-after-delete", listing.stdout, "`kagisecure item list` after the delete")
        }
    }

    func testTheAgentAccessPanelDefaultsToOffOnEveryItem() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()
        selectItem("Acme production database")

        step("visible-to-agents is off, and there are no per-field toggles yet") {
            waitFor("ks.item.agentVisible")
            let toggle = waitFor("ks.item.agentVisible")
            XCTAssertEqual(
                toggle.value as? Int ?? (toggle.value as? String).map { $0 == "1" ? 1 : 0 }, 0,
                "every item is invisible to agents by default — the outermost of the three "
                    + "default-deny gates (ui-spec.md §4.4)")
            XCTAssertFalse(
                element("ks.item.fieldAgentVisible.password").exists,
                "per-field toggles only appear once the item itself is exposed")
            capture("item-agent-access-off", "Agent access, off by default")
        }

        step("turning it on reveals a toggle per field") {
            click("ks.item.agentVisible")
            for field in ["hostname", "username", "password"] {
                XCTAssertTrue(
                    element("ks.item.fieldAgentVisible.\(field)")
                        .waitForExistence(timeout: Self.shortTimeout),
                    "every field should get its own agent-visibility toggle")
            }
            capture("item-agent-access-on", "Agent access, with the per-field toggles")
        }

        try step("a field can be excluded even while the item is exposed") {
            click("ks.item.fieldAgentVisible.password")
            let listing = try Harness.cliOk(["item", "show", "Acme production database"], vault: vaultPath)
            record("item-agent-visibility", listing.stdout, "The item after the toggles")
        }
    }

    // MARK: - Helpers

    private func unlock() {
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
    }

    /// Wait for the general pasteboard to hold exactly `value`.
    private func waitForPasteboard(_ value: String, timeout: TimeInterval = 10) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if NSPasteboard.general.string(forType: .string) == value { return true }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }

    /// Wait for the general pasteboard to stop holding `value`.
    private func waitForPasteboardToNotContain(_ value: String, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if NSPasteboard.general.string(forType: .string) != value { return true }
            Thread.sleep(forTimeInterval: 0.1)
        }
        return false
    }
}

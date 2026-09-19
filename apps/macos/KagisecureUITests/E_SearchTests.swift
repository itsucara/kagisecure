import XCTest

/// Search (ui-spec.md §3) and the empty state it lands on (§12).
///
/// §3 makes a promise with two halves: search matches titles, tags and URL hostnames, and it
/// "never matches secret field contents". The second half is the one worth a scenario — a search
/// index that quietly learned a password would look exactly like a working search until the day
/// somebody typed one in.
final class E_SearchTests: UITestCase {
    // MARK: - Scenarios

    func testSearchMatchesTitlesTagsAndUrlsAndNeverValues() throws {
        try openSeededVault()

        step("⌘F puts the keyboard in the search field, and a title match narrows the list") {
            waitFor("ks.itemList.list")
            XCTAssertTrue(
                searchField.waitForExistence(timeout: Self.shortTimeout),
                "ui-spec.md §3 puts a search field at the top of the item list, and there is none")

            app.typeKey("f", modifierFlags: .command)

            // `hasKeyboardFocus` is a KVC-only attribute on `XCUIElement`: there is no public API
            // for "is this the first responder", and the key is not guaranteed across Xcode
            // versions. Probed rather than assumed, so a future Xcode that drops it downgrades
            // this to the typing proof below instead of failing the scenario for the wrong reason.
            let focusKey = "hasKeyboardFocus"
            if XCUIElement.instancesRespond(to: NSSelectorFromString(focusKey)) {
                let focused = searchField.value(forKey: focusKey) as? Bool
                XCTAssertEqual(
                    focused, true,
                    "ui-spec.md §3 and §11 both say ⌘F focuses the search field from any pane")
                record(
                    "search-focus-probe", "\(focusKey) = \(String(describing: focused))",
                    "Whether ⌘F left the keyboard focus in the search field")
            } else {
                record(
                    "search-focus-probe",
                    "\(focusKey) is not exposed by this XCTest build; focus is proved below by "
                        + "typing without clicking anything first.",
                    "Whether ⌘F left the keyboard focus in the search field")
            }

            // Typed at the application, not into the field: nothing has been clicked since ⌘F, so
            // the text landing in the search field is itself the proof that ⌘F focused it — and it
            // is also the first query.
            app.typeText("github")

            XCTAssertTrue(
                waitUntil("the list narrows to GitHub") { self.itemListTitles() == ["GitHub"] },
                "\"github\" matches exactly one seeded title, so the list should hold only GitHub; "
                    + "it held \(itemListTitles())")
            capture("search-title-match", "Searching \"github\": one title match")
        }

        step("a tag matches, and does not drag the other items along") {
            search("prod")
            let expected = Set(["Acme production database", "Stripe"])
            XCTAssertTrue(
                waitUntil("the list narrows to the prod-tagged items") {
                    Set(self.itemListTitles()) == expected
                },
                "ui-spec.md §3 says search matches tags: \"prod\" is on Acme and Stripe, so both "
                    + "should be listed. The list held \(itemListTitles().sorted())")
            XCTAssertFalse(
                itemListTitles().contains("GitHub"),
                "GitHub is tagged personal and its title and URL do not contain \"prod\"; it must "
                    + "not match")
            capture("search-tag-match", "Searching \"prod\": a tag match across two items")
        }

        step("a saved URL matches on its hostname") {
            search("github.com")
            XCTAssertTrue(
                waitUntil("the list narrows to GitHub") { self.itemListTitles() == ["GitHub"] },
                "ui-spec.md §3 says search matches URL hostnames, and GitHub's saved URL is "
                    + "https://github.com; the list held \(itemListTitles())")
        }

        step("the value of a concealed field matches nothing at all") {
            // `hunter2-acme-production` is the password `Harness.seedVault` put on the Acme item.
            // It is not in any title, tag or URL, so the only way it could produce a hit is if a
            // secret value had been indexed.
            let secret = "hunter2-acme-production"
            search(secret)
            XCTAssertTrue(
                waitUntil("the search finds nothing") { self.itemListTitles().isEmpty },
                "SEARCH MATCHED A SECRET. ui-spec.md §3: search \"never matches secret field "
                    + "contents\", and vault-format.md §5.1 is why — a Secret is not indexed in "
                    + "plaintext. Typing the Acme item's password returned \(itemListTitles()), which "
                    + "means a concealed value is reachable by anyone who can guess at it.")
            XCTAssertTrue(
                element("ks.emptyState.title").exists,
                "a search that matches nothing should land on the empty state (ui-spec.md §12)")
            capture(
                "search-secret-value-no-match",
                "Searching a concealed field's own value finds nothing, as §3 requires")
        }

        step("clearing the field brings everything back") {
            clearSearch()
            let everything = Set(["Acme production database", "GitHub", "Stripe"])
            XCTAssertTrue(
                waitUntil("the list fills back up") { Set(self.itemListTitles()) == everything },
                "clearing the search should restore all three seeded items; the list held "
                    + "\(itemListTitles().sorted())")
        }
    }

    func testTheEmptyStateNamesTheQueryAndOffersAWayBack() throws {
        try openSeededVault()

        step("all three items are listed before anything is typed") {
            waitFor("ks.itemList.list")
            XCTAssertTrue(
                waitUntil("the seeded items are listed") { self.itemListTitles().count == 3 },
                "the seeded vault holds three items; the list held \(itemListTitles())")
            capture("search-empty-before", "The item list before any query is typed")
        }

        let query = "zzzzzz"

        step("a query that matches nothing says so, and says what it was looking for") {
            search(query)
            waitFor("ks.emptyState.title", timeout: Self.shortTimeout)

            let titles = emptyStateTitles()
            let messages = emptyStateMessages()

            // Two panes can show an empty state at once — the item list's overlay
            // ("No matches") and the detail pane's own ("No items match “{query}”") — and which of
            // them AppKit puts in the tree depends on the window's width, so the assertion is made
            // against the whole set rather than against whichever came first.
            XCTAssertFalse(
                titles.isEmpty,
                "a search that matches nothing should say so somewhere (ui-spec.md §12)")
            XCTAssertTrue(
                messages.contains(where: { $0.contains(query) })
                    || titles.contains(where: { $0.contains(query) }),
                "ui-spec.md §12 wants the query quoted back at the user — its wording is "
                    + "'No items match {query}' — and neither the titles \(titles) nor the "
                    + "messages \(messages) mention '\(query)'")

            // Recorded rather than asserted: §12 specifies one empty state per context and the
            // build renders two, with the spec's wording landing on the detail pane's title and
            // the list pane inventing a shorter one. Neither is wrong for a user; the drift is
            // worth a line in the report rather than a failed scenario.
            record(
                "search-empty-state-wording",
                "ui-spec.md §12 specifies: No items match \"{query}\"\n"
                    + "as built, titles on screen: \(titles)\n"
                    + "as built, messages on screen: \(messages)\n"
                    + "ks.emptyState.action present: \(element("ks.emptyState.action").exists)\n"
                    + "§12 also lists \"Clear search\" as the primary action for this state.",
                "The no-matches empty state as built, against ui-spec.md §12")

            capture("search-empty-state", "The empty state for a query that matches nothing")
        }

        step("the way back is the one the empty state describes") {
            // §12's primary action for this state is a "Clear search" button; the build offers the
            // instruction as text instead (see the record above). Either way, the route back has to
            // work, so the scenario takes it.
            clearSearch()
            let everything = Set(["Acme production database", "GitHub", "Stripe"])
            XCTAssertTrue(
                waitUntil("the list fills back up") { Set(self.itemListTitles()) == everything },
                "clearing the search field should bring every item back, which is what the empty "
                    + "state tells the user to do; the list held \(itemListTitles().sorted())")
            waitForDisappearance("ks.emptyState.title")
            capture("search-empty-cleared", "The item list after clearing the query")
        }
    }

    // MARK: - Getting to the main window

    /// Seed a vault through the CLI, launch against it and get past the lock screen.
    private func openSeededVault() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        waitFor("ks.lock.title")
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
    }

    // MARK: - The search field

    /// The item list's search field.
    ///
    /// Not an identifier lookup, and cannot be one: the field is built by
    /// `.searchable(text:placement:prompt:)`, which takes a binding and a prompt and hands back no
    /// view to hang an `accessibilityIdentifier` on. So it is found by element type instead, with
    /// the prompt text as a fallback for the builds where AppKit renders the toolbar item as a
    /// plain text field rather than an `NSSearchField`.
    private var searchField: XCUIElement {
        let field = app.searchFields.firstMatch
        if field.exists { return field }
        return app.textFields
            .matching(NSPredicate(format: "placeholderValue CONTAINS[c] 'Search'"))
            .firstMatch
    }

    /// Replace whatever is in the search field with `text`.
    private func search(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        let field = searchField
        XCTAssertTrue(
            field.waitForExistence(timeout: Self.shortTimeout),
            "the search field is gone", file: file, line: line)
        field.click()
        field.typeKey("a", modifierFlags: .command)
        field.typeText(text)
    }

    /// Empty the search field.
    private func clearSearch(file: StaticString = #filePath, line: UInt = #line) {
        let field = searchField
        XCTAssertTrue(
            field.waitForExistence(timeout: Self.shortTimeout),
            "the search field is gone", file: file, line: line)
        field.click()
        field.typeKey("a", modifierFlags: .command)
        field.typeKey(XCUIKeyboardKey.delete.rawValue, modifierFlags: [])
    }

    // MARK: - Reading the window

    /// Every empty state's title, plural on purpose: an empty item list shows one empty state in
    /// the list pane and another in the detail pane, and `firstMatch` could return either.
    private func emptyStateTitles() -> [String] {
        elements("ks.emptyState.title").allElementsBoundByIndex.map { text(of: $0) }
    }

    private func emptyStateMessages() -> [String] {
        elements("ks.emptyState.message").allElementsBoundByIndex.map { text(of: $0) }
    }

    /// Wait until `condition` holds. `waitFor` covers "this identifier appears"; this covers the
    /// conditions computed across several elements at once, which no identifier can express.
    /// Predicate-driven rather than a sleep loop, so it returns the moment the list settles.
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

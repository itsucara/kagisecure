import XCTest

/// The password generator sheet (ui-spec.md §8), standalone and filling a field.
///
/// Two scenarios, because the sheet is genuinely two features wearing one face. Standalone it is a
/// tool — there is nothing to fill, so it offers Copy and nothing else. Opened from a concealed
/// field in edit mode it is a step in an edit, and the thing that matters is that the password the
/// user looked at is the password that ends up in the vault.
final class F_GeneratorTests: UITestCase {

    // MARK: - Scenarios

    func testTheGeneratorSheetProducesACandidateInBothModes() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()

        step("⇧⌘G opens the generator with a candidate already drawn") {
            // ui-spec.md §11 binds the standalone generator to ⇧⌘G; the sheet is presented by
            // RootView, so it is reachable with no item selected.
            app.typeKey("g", modifierFlags: [.command, .shift])
            waitFor("ks.generator.candidate")
            capture("generator-opened", "The generator, opened standalone with ⇧⌘G")
        }

        var candidate = ""
        step("the candidate is a real password, not the empty placeholder") {
            candidate = readCandidate()
            XCTAssertFalse(
                candidate.isEmpty,
                "the sheet must open with a candidate already generated, not an empty box")
            XCTAssertNotEqual(
                candidate, "—",
                "“—” is the placeholder the sheet shows when generation failed; the sheet opened "
                    + "without a password")
            // The default recipe is 20 characters (GeneratorRecipe.standard, ui-spec.md §8).
            XCTAssertEqual(
                candidate.count, 20,
                "the generator should open at its documented default of 20 characters")
        }

        step("the strength meter names a bucket and says what it is worth in bits") {
            let strength = waitFor("ks.generator.strength")
            // `ks.generator.strengthLabel` and `ks.generator.bits` live inside an
            // `.accessibilityElement(children: .combine)` container, so AppKit fuses them into one
            // element and neither is separately addressable. The combined element's label is the
            // sentence the meter says out loud, so that is what is asserted on.
            let said = text(of: strength)
            let buckets = ["Very weak", "Weak", "Fair", "Good", "Excellent"]
            XCTAssertTrue(
                buckets.contains(where: { said.contains($0) }),
                "ui-spec §8 gives the meter five labels — \(buckets.joined(separator: " / ")) — "
                    + "and the meter said \"\(said)\"")
            XCTAssertTrue(
                said.contains("bits of entropy"),
                "the meter must quantify the estimate, not just colour it; it said \"\(said)\"")
            record("generator-strength", said, "What the strength meter says at the default recipe")
        }

        step("regenerating draws a different password") {
            click("ks.generator.regenerate")
            let second = waitForCandidateToChange(from: candidate)
            XCTAssertNotEqual(
                second, candidate,
                "Regenerate must draw a new candidate; the box still reads the old one")
            candidate = second
            capture("generator-regenerated", "A second candidate, after Regenerate")
        }

        step("the length slider reaches the documented ceiling of 128") {
            let path = driveLengthSliderToMaximum()
            record(
                "generator-length-slider-path", path,
                "How the scenario got the length slider to its maximum")
            XCTAssertEqual(
                textOf("ks.generator.lengthValue"), "128",
                "ui-spec §8 records the as-built upper bound as 128 characters")

            click("ks.generator.regenerate")
            let long = waitForCandidate(where: { $0.count == 128 })
            XCTAssertEqual(
                long.count, 128,
                "a 128-character recipe must produce a 128-character password, got \(long.count)")
            candidate = long
            capture("generator-max-length", "The generator at its 128-character maximum")
        }

        step("turning digits and symbols off leaves letters and nothing else") {
            // Each toggle mutates the recipe, which regenerates on its own; the explicit
            // Regenerate afterwards is what the assertion is actually about.
            click("ks.generator.toggle.symbols")
            click("ks.generator.toggle.digits")
            click("ks.generator.regenerate")

            let letters = waitForCandidate(where: { !$0.isEmpty && $0.allSatisfy(\.isLetter) })
            XCTAssertTrue(
                letters.allSatisfy(\.isLetter),
                "with both digits and symbols switched off the alphabet is letters only "
                    + "(ui-spec §8), but the candidate contained "
                    + "\(String(letters.filter { !$0.isLetter }))")
            XCTAssertFalse(
                letters.isEmpty,
                "ui-spec §8 keeps at least one letter class on, so a letters-only recipe is still "
                    + "satisfiable and must not blank the candidate")
        }

        step("Memorable words gives a separated passphrase") {
            selectSegment("Memorable words", in: "ks.generator.mode")
            let phrase = waitForCandidate(where: { $0.contains("-") })
            XCTAssertTrue(
                phrase.contains("-"),
                "the default separator is a hyphen (ui-spec §8), so the passphrase should read "
                    + "like correct-horse-battery; it was \"\(phrase)\"")
            XCTAssertEqual(
                textOf("ks.generator.wordsValue"), "4",
                "words mode defaults to four words (ui-spec §8)")
            capture("generator-words-mode", "Memorable words mode, at its four-word default")
        }

        step("with no field to fill, the sheet offers Copy and nothing else") {
            XCTAssertTrue(
                element("ks.generator.copy").exists,
                "the standalone generator's only way out with a password is Copy")
            XCTAssertFalse(
                element("ks.generator.use").exists,
                "ui-spec §8: opened standalone there is no field to fill, so \"Use this password\" "
                    + "must not be offered")
        }

        step("Cancel closes it") {
            click("ks.generator.cancel")
            waitForDisappearance("ks.generator.candidate")
        }
    }

    func testTheGeneratorFillsAPasswordFieldFromEditMode() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()
        selectItem("GitHub")

        step("edit mode offers to generate the password field's value") {
            app.typeKey("e", modifierFlags: .command)
            waitFor("ks.edit.fieldValue.password")
            click("ks.edit.fieldGenerate.password")
            waitFor("ks.generator.candidate")
            capture("generator-from-field", "The generator, opened from the password field")
        }

        var generated = ""
        step("\"Use this password\" puts the candidate into the field") {
            generated = readCandidate()
            XCTAssertFalse(generated.isEmpty, "there was no candidate to use")
            XCTAssertTrue(
                element("ks.generator.use").exists,
                "opened from a field the sheet must offer \"Use this password\" (ui-spec §8)")
            click("ks.generator.use")
            waitForDisappearance("ks.generator.candidate")

            let field = waitFor("ks.edit.fieldValue.password")
            XCTAssertEqual(
                field.value as? String, generated,
                "the password the user looked at is the password that must land in the field")
            capture("generator-filled-field", "The generated password, in the edit field")
        }

        step("saving keeps it, and revealing shows the same string") {
            click("ks.edit.save")
            waitFor("ks.item.fieldReveal.password")
            click("ks.item.fieldReveal.password")

            let shown = waitFor("ks.item.fieldValue.password")
            XCTAssertEqual(
                textOf("ks.item.fieldValue.password"), generated,
                "the vault must hold the generated password, not a truncated or re-generated one; "
                    + "the detail pane showed \"\(text(of: shown))\"")
            capture("generator-saved-and-revealed", "The saved password, revealed on the detail pane")
        }
    }

    // MARK: - Getting to an unlocked vault

    /// Seed-and-unlock is the preamble of nearly every scenario in the suite, and `UITestCase` is
    /// deliberately not the place for it: it is a fixture choice, not a harness one.
    private func unlock(file: StaticString = #filePath, line: UInt = #line) {
        waitFor("ks.lock.title", file: file, line: line)
        type(Harness.password, into: "ks.lock.password", file: file, line: line)
        click("ks.lock.unlock", file: file, line: line)
        waitFor("ks.sidebar.all", file: file, line: line)
    }

    // MARK: - Reading the sheet

    /// The text an element is showing, whichever half of the accessibility record it landed in.
    ///
    /// SwiftUI puts a plain `Text`'s content in the label and a selectable or editable one's in the
    /// value, and which of the two a given control gets is an AppKit implementation detail that has
    /// moved between releases. A test should not have to care.
    private func textOf(_ identifier: String) -> String {
        let found = element(identifier)
        if let value = found.value as? String, !value.isEmpty { return value }
        return text(of: found)
    }

    /// The candidate currently on show.
    ///
    /// `ks.generator.candidate` carries an explicit `.accessibilityLabel("Generated password")`, so
    /// the password itself is only in the value. Falling back to the label would silently compare
    /// two copies of that constant and pass, which is why the constant is asserted against.
    private func readCandidate(file: StaticString = #filePath, line: UInt = #line) -> String {
        let shown = textOf("ks.generator.candidate")
        XCTAssertNotEqual(
            shown, "Generated password",
            "ks.generator.candidate exposed only its accessibility label — the generated password "
                + "is not readable from the accessibility tree",
            file: file, line: line)
        return shown
    }

    /// Poll the candidate until `matches` is happy with it.
    ///
    /// The sheet regenerates on a state change rather than in response to the click, so there is no
    /// element appearing or disappearing to wait on — only a value settling.
    @discardableResult
    private func waitForCandidate(
        where matches: (String) -> Bool, timeout: TimeInterval = UITestCase.shortTimeout
    ) -> String {
        var latest = textOf("ks.generator.candidate")
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            latest = textOf("ks.generator.candidate")
            if matches(latest) { return latest }
        }
        return latest
    }

    private func waitForCandidateToChange(from previous: String) -> String {
        waitForCandidate(where: { $0 != previous && !$0.isEmpty })
    }

    /// Push the length slider to 128, and say which way it got there.
    ///
    /// `adjust(toNormalizedSliderPosition:)` is the direct route, but it only applies to an element
    /// AppKit actually exposed as a slider, and it raises rather than returns when it does not — so
    /// the element type is checked first instead of the call being attempted and caught. The
    /// arrow-key route works either way: a focused `Slider` steps by the recipe's step of 1.
    private func driveLengthSliderToMaximum() -> String {
        let slider = waitFor("ks.generator.length")
        var path: String

        if slider.elementType == .slider {
            slider.adjust(toNormalizedSliderPosition: 1.0)
            path = "adjust(toNormalizedSliderPosition: 1.0)"
        } else {
            path = "element type \(slider.elementType.rawValue) is not a slider"
        }

        if textOf("ks.generator.lengthValue") != "128" {
            path += " + right-arrow steps"
            slider.click()
            // 8…128 is 120 steps; the batches keep this to a handful of accessibility reads rather
            // than one per key press.
            for _ in 0..<9 {
                if textOf("ks.generator.lengthValue") == "128" { break }
                for _ in 0..<20 {
                    app.typeKey(XCUIKeyboardKey.rightArrow, modifierFlags: [])
                }
            }
        }
        return path
    }

    /// Click one segment of a segmented `Picker` by its title.
    ///
    /// A segmented picker is not a single clickable control: `click("ks.generator.mode")` lands on
    /// the group and changes nothing. The segments themselves are buttons or radio buttons
    /// depending on the AppKit version, and they may or may not be reported as descendants of the
    /// element carrying the picker's identifier, so all four shapes are tried before giving up.
    private func selectSegment(
        _ title: String, in identifier: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let picker = element(identifier)
        let candidates = [
            picker.buttons[title],
            picker.radioButtons[title],
            app.radioButtons[title],
            app.buttons[title],
        ]
        for candidate in candidates where candidate.exists && candidate.isHittable {
            candidate.click()
            return
        }

        let seen = app.descendants(matching: .any).allElementsBoundByIndex
            .filter { $0.elementType == .button || $0.elementType == .radioButton }
            .map { "\($0.elementType.rawValue):\(text(of: $0))" }
            .prefix(40)
            .joined(separator: ", ")
        XCTFail(
            "no segment titled \"\(title)\" under \(identifier). Buttons and radio buttons on "
                + "screen: \(seen)",
            file: file, line: line)
    }
}

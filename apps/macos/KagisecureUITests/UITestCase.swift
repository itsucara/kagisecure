import AppKit
import XCTest

/// The base every scenario in suite D is built on (docs/e2e-harness.md §7).
///
/// # What a scenario owns
///
/// Its whole world. Each test gets a fresh `KAGISECURE_HOME`, a fresh socket path, a fresh
/// `UserDefaults` suite and a fresh launch of the app, and tears all of it down afterwards. Nothing
/// is shared between scenarios, which is the same rule suites A–C follow and for the same reason:
/// a suite whose scenarios only pass in one order hides bugs.
///
/// # What it must never touch
///
/// `~/Library/Application Support/kagisecure/` and `~/Library/Preferences/com.kagisecure.app.plist`.
/// The app under test is the real bundle with the real bundle identifier, so both are one forgotten
/// environment variable away. `KAGISECURE_HOME` moves the vault, `KAGISECURE_SOCKET` moves the
/// listener, and `-KSUITestDefaultsSuite` moves the preferences; all three are set on every launch,
/// by this class, so no individual scenario can forget one.
///
/// `@MainActor` on the class rather than on the handful of members that need it. Every one of these
/// helpers touches `XCUIApplication` or `XCTContext`, both of which are main-actor isolated, and
/// pinning the base class means a subclass's scenarios inherit the isolation instead of each one
/// rediscovering it.
@MainActor
class UITestCase: XCTestCase {
    /// The app under test, once `launch()` has run.
    var app: XCUIApplication!

    /// This scenario's scratch directory. Everything it writes lives here.
    private(set) var scratch: URL!

    /// The `UserDefaults` suite the app writes preferences into, deleted in `tearDown`.
    private(set) var defaultsSuite: String!

    /// Where the app's IPC listener binds. Short, because `sun_path` is 104 bytes on macOS.
    private(set) var socketPath: String!

    /// How long to wait for something that involves the vault or a subprocess.
    static let timeout: TimeInterval = 30

    /// A shorter wait, for something that is either on screen already or is a bug.
    static let shortTimeout: TimeInterval = 8

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = false

        let id = UUID().uuidString.prefix(8)
        scratch = URL(fileURLWithPath: "/tmp/ksui-\(id)")
        try FileManager.default.createDirectory(
            at: scratch, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        socketPath = "/tmp/ksui-\(id)/agent.sock"
        defaultsSuite = "com.kagisecure.app.uitest.\(id)"
    }

    override func tearDownWithError() throws {
        // Inline rather than through `terminateApp`, because `tearDownWithError` is not isolated
        // to the main actor and handing it a non-`Sendable` `XCUIApplication` is exactly the kind
        // of hop Swift 6 refuses.
        if let app, app.state != .notRunning {
            app.terminate()
            let deadline = Date().addingTimeInterval(Self.shortTimeout)
            while Date() < deadline, app.state != .notRunning {
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        app = nil
        Self.killStrayApps()
        // The preferences suite is a plist in ~/Library/Preferences. It is not the user's, but it
        // is in the user's directory, so it goes.
        if let defaultsSuite {
            UserDefaults.standard.removePersistentDomain(forName: defaultsSuite)
            let plist = FileManager.default
                .homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Preferences/\(defaultsSuite).plist")
            try? FileManager.default.removeItem(at: plist)
        }
        if let scratch, ProcessInfo.processInfo.environment["E2E_KEEP"] != "1" {
            try? FileManager.default.removeItem(at: scratch)
        }
        try super.tearDownWithError()
    }

    /// Kill anything left of the app under test.
    ///
    /// `XCUIApplication.terminate()` goes through the test runner, and on a machine that has
    /// refused the runner permission to drive another process it fails — leaving a live app behind
    /// for the next scenario to trip over, and a suite that leaks one process per scenario.
    ///
    /// The pattern is the **built product's** path, not the bundle identifier: it matches only a
    /// binary inside a `Build/Products/…/Kagisecure.app`, so a copy of kagisecure the person at
    /// this Mac installed and is using cannot be caught by it.
    static func killStrayApps() {
        let kill = Process()
        kill.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        kill.arguments = ["-f", "Build/Products/.*/Kagisecure.app/Contents/MacOS/Kagisecure"]
        kill.standardOutput = FileHandle.nullDevice
        kill.standardError = FileHandle.nullDevice
        try? kill.run()
        kill.waitUntilExit()
    }

    // MARK: - Launching

    /// The vault file this scenario's app opens.
    var vaultPath: String {
        scratch.appendingPathComponent("default.kagivault").path
    }

    /// Launch the app against this scenario's scratch world.
    ///
    /// - Parameters:
    ///   - biometrics: what the injected `BiometricGate` answers, or `nil` to leave the real one.
    ///     `nil` is only useful for asserting that the app *asks*; every scenario that has to get
    ///     past the gate passes `"allow"`.
    ///   - appearance: `"dark"` or `"light"` to pin `NSApp.appearance`, for the dark-mode captures.
    ///   - autoLockMinutes: 0 means never. Every scenario wants 0: the idle timer is measured
    ///     against *system-wide* input idleness, so a test that types nothing for eleven minutes
    ///     while a subprocess works would lock the vault underneath itself.
    ///   - pasteboardSeconds: how long a copied value stays on the clipboard.
    @discardableResult
    func launch(
        biometrics: String? = "allow",
        appearance: String? = nil,
        autoLockMinutes: Int = 0,
        pasteboardSeconds: Int = 60
    ) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["KAGISECURE_HOME"] = scratch.path
        app.launchEnvironment["KAGISECURE_SOCKET"] = socketPath
        // Inherited by the app, and by anything it spawns. Nothing here may reach a real browser
        // or a real agent.
        app.launchEnvironment["KAGISECURE_UITEST"] = "1"

        var arguments = ["-KSUITestDefaultsSuite", defaultsSuite!]
        if let biometrics {
            arguments += ["-KSUITestBiometrics", biometrics]
        }
        if let appearance {
            arguments += ["-KSUITestAppearance", appearance]
        }
        app.launchArguments = arguments

        // The two preferences the suite needs a known value for, seeded into the scratch suite
        // *before* launch rather than clicked into the Settings pane by every scenario that
        // depends on them. The Settings scenario is the one that exercises the pane.
        let defaults = UserDefaults(suiteName: defaultsSuite!)
        defaults?.set(autoLockMinutes, forKey: "autoLockIdleMinutes")
        defaults?.set(pasteboardSeconds, forKey: "pasteboardClearSeconds")

        // Anything left over from the previous scenario goes first, and this waits for it to be
        // gone. `terminate()` returns before the process does, and the app keeps a `MenuBarExtra`
        // — so an early relaunch attaches to a half-dead instance whose accessibility tree is the
        // status item and nothing else. That failure reads as "the window never appeared", which
        // is the most misleading message this suite could produce.
        terminateApp(XCUIApplication())

        app.launch()
        self.app = app
        return app
    }

    /// Terminate `candidate` and wait for it to actually be gone.
    func terminateApp(_ candidate: XCUIApplication?) {
        guard let candidate, candidate.state != .notRunning else { return }
        candidate.terminate()
        let deadline = Date().addingTimeInterval(Self.shortTimeout)
        while Date() < deadline, candidate.state != .notRunning {
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    // MARK: - Finding things

    /// The element carrying `identifier`, wherever it is — window, sheet, panel or menu.
    ///
    /// `descendants(matching: .any)` rather than a typed query because the same logical control is
    /// a different element type in different places: a SwiftUI `Toggle` is a checkbox in a form and
    /// a switch in a row, and a `Text` inside a `Table` column is a cell rather than a static text.
    /// A test should say *which control*, not *what AppKit made of it*.
    func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }

    /// Every element carrying `identifier`. Used where an identifier is deliberately shared by the
    /// rows of a list.
    func elements(_ identifier: String) -> XCUIElementQuery {
        app.descendants(matching: .any).matching(identifier: identifier)
    }

    /// Wait for `identifier` to exist, failing the scenario with a readable message if it does not.
    @discardableResult
    func waitFor(
        _ identifier: String, timeout: TimeInterval = UITestCase.timeout,
        file: StaticString = #filePath, line: UInt = #line
    ) -> XCUIElement {
        let found = element(identifier)
        XCTAssertTrue(
            found.waitForExistence(timeout: timeout),
            "\(identifier) never appeared. On screen: \(onScreenIdentifiers().joined(separator: ", "))",
            file: file, line: line)
        return found
    }

    /// Wait for `identifier` to go away.
    func waitForDisappearance(
        _ identifier: String, timeout: TimeInterval = UITestCase.shortTimeout,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let gone = expectation(
            for: NSPredicate(format: "exists == false"), evaluatedWith: element(identifier))
        let result = XCTWaiter().wait(for: [gone], timeout: timeout)
        XCTAssertEqual(result, .completed, "\(identifier) was still there", file: file, line: line)
    }

    /// Click the element with `identifier`, waiting for it first.
    func click(
        _ identifier: String, timeout: TimeInterval = UITestCase.timeout,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        activate()
        let target = waitFor(identifier, timeout: timeout, file: file, line: line)
        XCTAssertTrue(
            target.isHittable,
            "\(identifier) is in the accessibility tree but not clickable, and scrolling did not "
                + "bring it into view — its frame is \(target.frame)",
            file: file, line: line)
        target.click()
    }

    /// Click a sidebar row, scrolling the sidebar first if the row is below the fold.
    ///
    /// The sidebar is taller than the window at its default size — twelve categories, the tags, the
    /// five agent-access and browser rows, Archive and Trash — so the bottom of it is in the
    /// accessibility tree and off the screen, where a click cannot land. XCUITest has no
    /// "scroll this into view" on macOS, so the list is nudged until the row is reachable.
    ///
    /// Only the sidebar, and only from here: an earlier version scrolled every scrollable thing it
    /// could find from inside `click`, which moved panes that were not the point and broke
    /// scenarios that had nothing to do with the sidebar.
    func clickSidebarRow(
        _ identifier: String, file: StaticString = #filePath, line: UInt = #line
    ) {
        activate()
        waitFor(identifier, file: file, line: line)

        // Scroll, click, check, repeat. Every query is rebuilt inside the loop: a scroll moves the
        // rows, and an element resolved before one is a stale remote reference that XCUITest
        // reports as "Failed to resolve remote element" rather than as a wrong click.
        //
        // The **cell** is what gets clicked, not the label inside it. SwiftUI puts the identifier
        // on the `Label`, which lowers to a static text inside an `AXCell`; a click on the text is
        // a click on a piece of text, and `List(selection:)` does not reliably take it.
        for attempt in 0..<4 {
            if !element(identifier).isHittable {
                let sidebar = element("ks.sidebar.list")
                guard sidebar.exists else { break }
                for delta in [-80.0, -80.0, -80.0, -80.0, 320.0, 80.0, 80.0, 80.0, 80.0] {
                    if element(identifier).isHittable { break }
                    sidebar.scroll(byDeltaX: 0, deltaY: CGFloat(delta))
                }
            }
            guard element(identifier).isHittable else { continue }

            let cell = app.cells.containing(.staticText, identifier: identifier).firstMatch
            if cell.exists, cell.isHittable {
                cell.click()
            } else {
                element(identifier).click()
            }

            // A row that took the click reports itself selected — on its *cell*, not on the
            // static text the identifier sits on. `Selected` is an attribute of the
            // `AXOutlineRow`/`AXCell`; the label inside it never carries one, so asking the
            // element with the identifier would be asking the wrong object and always getting no.
            let deadline = Date().addingTimeInterval(0.6)
            while Date() < deadline {
                if sidebarRowIsSelected(identifier) { return }
                Thread.sleep(forTimeInterval: 0.05)
            }
            if attempt >= 1 { break }
        }

        // The keyboard, which is where a `List(selection:)` is least ambiguous: the arrow keys go
        // through the table's own responder and move the binding, whatever a synthetic click did
        // or did not land on. This is the documented quirk the whole helper exists for — it is
        // rare, but "Set up your agent" hits it reproducibly.
        if !sidebarRowIsSelected(identifier) {
            for _ in 0..<40 {
                if sidebarRowIsSelected(identifier) { return }
                app.typeKey(XCUIKeyboardKey.downArrow, modifierFlags: [])
            }
            for _ in 0..<40 {
                if sidebarRowIsSelected(identifier) { return }
                app.typeKey(XCUIKeyboardKey.upArrow, modifierFlags: [])
            }
        }

        XCTAssertTrue(
            sidebarRowIsSelected(identifier),
            "\(identifier) would not take a selection, by click or by keyboard; its frame is "
                + "\(element(identifier).frame)",
            file: file, line: line)
    }

    /// Select the item called `title` in the middle pane, and wait for the detail pane to show it.
    ///
    /// By title rather than by identifier because a row's identifier is the item's id, which the
    /// test never learns — and the title is what a user clicks anyway. Two things make this more
    /// than one line:
    ///
    /// * a `Text`'s string is its **value**, not its label, so a predicate on `label` matches
    ///   nothing;
    /// * `List(selection:)` does not reliably take a synthetic click on the static text inside its
    ///   cell, which is why the cell is clicked and why the keyboard is the last resort.
    func selectItem(_ title: String, file: StaticString = #filePath, line: UInt = #line) {
        waitFor("ks.itemList.list", file: file, line: line)
        activate()
        var tried: [String] = []

        let byTitle = elements("ks.itemList.rowTitle")
            .matching(NSPredicate(format: "value == %@ OR label == %@", title, title))
            .firstMatch
        if byTitle.waitForExistence(timeout: Self.shortTimeout) {
            let cell = app.cells.containing(
                NSPredicate(format: "value == %@ OR label == %@", title, title)
            ).firstMatch
            if cell.exists, cell.isHittable {
                cell.click()
            } else {
                byTitle.click()
            }
            if detailShows(title) { return }
            tried.append("a click on the row highlighted it but did not move the selection")
        } else {
            tried.append(
                "no row reads \"\(title)\"; the list showed \(itemListTitles())")
        }

        element("ks.itemList.list").click()
        for _ in 0..<25 {
            app.typeKey(XCUIKeyboardKey.downArrow, modifierFlags: [])
            if detailShows(title, timeout: 0.5) { return }
        }
        tried.append("walking the list with the down arrow never reached it")

        XCTFail(
            "could not select the item titled \"\(title)\":\n" + tried.joined(separator: "\n"),
            file: file, line: line)
    }

    /// Every title currently in the middle pane.
    func itemListTitles() -> [String] {
        elements("ks.itemList.rowTitle").allElementsBoundByIndex.map { text(of: $0) }
    }

    /// Whether the detail pane is showing the item called `title`.
    func detailShows(_ title: String, timeout: TimeInterval = UITestCase.shortTimeout) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if element("ks.item.title").exists, text("ks.item.title") == title { return true }
            Thread.sleep(forTimeInterval: 0.05)
        } while Date() < deadline
        return false
    }

    /// Whether the sidebar row carrying `identifier` is the selected one.
    ///
    /// Resolved fresh every call: the cell is a remote reference and a scroll invalidates it.
    func sidebarRowIsSelected(_ identifier: String) -> Bool {
        let cell = app.cells.containing(.staticText, identifier: identifier).firstMatch
        guard cell.exists else { return false }
        return cell.isSelected
    }

    /// Type `text` into the field with `identifier`, replacing whatever is in it.
    ///
    /// Every keystroke goes to the frontmost application, so this makes sure that is the app under
    /// test first. Without it a scenario fails with "Timed out while synthesizing event" whenever
    /// something else — the terminal running `xcodebuild`, a notification, the previous scenario's
    /// app still on its way out — has the keyboard.
    func type(
        _ text: String, into identifier: String,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        activate()
        let field = waitFor(identifier, file: file, line: line)
        field.click()
        // Select-all then type: a `SecureField` has no readable value to clear character by
        // character, and a scenario that appends to a leftover value fails in a way that reads as
        // a product bug rather than a test one.
        field.typeKey("a", modifierFlags: .command)
        field.typeText(text)
    }

    /// Bring the app under test to the front, and wait until it is actually there.
    ///
    /// `XCUIApplication.activate()` returns before the activation has landed. Typing into a window
    /// that is not yet frontmost is the single most common cause of a flaky macOS UI test, so this
    /// waits for the state to change rather than hoping.
    func activate() {
        guard app.state != .runningForeground else { return }
        app.activate()
        let deadline = Date().addingTimeInterval(Self.shortTimeout)
        while Date() < deadline, app.state != .runningForeground {
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    /// The text a view is showing.
    ///
    /// SwiftUI lowers a `Text` to an `AXStaticText` whose **value** is the string; the `label` is
    /// empty unless the view also carries an `.accessibilityLabel`. Reading `.label` and getting
    /// `""` is therefore the normal case rather than a bug, and every assertion about what is on
    /// screen goes through here instead of guessing which of the two a given view populated.
    func text(_ identifier: String, file: StaticString = #filePath, line: UInt = #line) -> String {
        text(of: waitFor(identifier, file: file, line: line))
    }

    /// The text an element is showing, from whichever attribute carries it.
    ///
    /// `label` first: a view that sets `.accessibilityLabel` is saying "this is what I am", and
    /// that is what an assertion should read. A plain `Text` sets no label, and its string is in
    /// `value`. The one shape this cannot serve is a view whose label and value are *both*
    /// meaningful and different — the generator's candidate, say, which is labelled "Generated
    /// password" and valued with the password — and those call sites read `.value` directly.
    func text(of element: XCUIElement) -> String {
        if !element.label.isEmpty { return element.label }
        return element.value as? String ?? ""
    }

    /// What is on screen, for a failure message. Truncated: the whole tree is thousands of lines
    /// and the first fifty identifiers are what tells you whether you are on the wrong screen.
    func onScreenIdentifiers() -> [String] {
        var seen: [String] = []
        for element in app.descendants(matching: .any).allElementsBoundByIndex {
            let id = element.identifier
            if id.hasPrefix("ks."), !seen.contains(id) {
                seen.append(id)
                if seen.count >= 50 { break }
            }
        }
        return seen
    }

    // MARK: - Steps

    /// Run `body` as a named sub-step, so the `.xcresult` and the HTML report both show where a
    /// long scenario got to.
    ///
    /// Returns nothing, deliberately. A generic `-> T` would be more convenient at two call sites
    /// and would mean handing a non-`Sendable` value out of a main-actor-isolated closure, which
    /// Swift 6 refuses; a scenario that needs a value out of a step captures a `var` instead.
    func step(_ name: String, _ body: () throws -> Void) rethrows {
        try XCTContext.runActivity(named: name) { _ in try body() }
    }

    // MARK: - Evidence

    /// Where the phase-1 runner wants evidence, or `nil` when running from Xcode.
    private var artifactDirectory: URL? {
        guard let path = ProcessInfo.processInfo.environment["E2E_ARTIFACTS"] else { return nil }
        return URL(fileURLWithPath: path)
    }

    /// The name this scenario is reported under.
    ///
    /// `XCTestCase.name` is `-[KagisecureUITests.ItemTests testSomething]` on some Xcode versions
    /// and `testSomething()` on others, while `xcresulttool` always reports `testSomething()`. The
    /// adapter joins the manifest to the JUnit document on this string, so it is normalised here
    /// rather than hoped about.
    var scenarioKey: String {
        var token = name
        if let space = token.lastIndex(of: " ") {
            token = String(token[token.index(after: space)...])
        }
        token = token.replacingOccurrences(of: "]", with: "")
        return token.hasSuffix("()") ? token : token + "()"
    }

    /// Screenshot the app, attach it to the `.xcresult`, and drop a PNG into `$E2E_ARTIFACTS` with
    /// a manifest line, so the phase-1 HTML report shows it.
    ///
    /// Both, deliberately. The attachment is what somebody opening the result bundle in Xcode
    /// looks at; the PNG is what the report embeds. Extracting attachments back out of an
    /// `.xcresult` is possible and is a moving target across Xcode versions, so the suite writes
    /// the file it wants rather than asking for it back.
    func capture(_ name: String, _ label: String) {
        let screenshot = app.state == .runningForeground || app.state == .runningBackground
            ? app.screenshot()
            : XCUIScreen.main.screenshot()

        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = label
        attachment.lifetime = .keepAlways
        add(attachment)

        guard let directory = artifactDirectory else { return }
        let file = "\(name).png"
        do {
            try Self.downscaled(screenshot).write(to: directory.appendingPathComponent(file))
            appendManifest(file: file, label: label, kind: "image")
        } catch {
            XCTFail("could not write the screenshot \(file): \(error)")
        }
    }

    /// A screenshot, scaled down to something a report can carry.
    ///
    /// The phase-1 report is one self-contained HTML file with every image inlined as a data URI,
    /// which is what makes it possible to hand somebody a single artifact. A full-resolution Retina
    /// capture of a 5K display is well over a megabyte, and ninety-odd of them made a 45 MB file
    /// that a browser struggles to open and CI has to upload. Sixteen hundred pixels wide is enough
    /// to read every label on these screens and roughly an eighth of the bytes.
    ///
    /// The attachment on the `.xcresult` keeps the original: somebody debugging in Xcode wants the
    /// pixels, and that bundle is not embedded in anything.
    static func downscaled(_ screenshot: XCUIScreenshot, maxWidth: CGFloat = 1600) -> Data {
        let image = screenshot.image
        guard image.size.width > maxWidth else { return screenshot.pngRepresentation }

        let scale = maxWidth / image.size.width
        let size = NSSize(
            width: maxWidth, height: (image.size.height * scale).rounded())
        guard
            let bitmap = NSBitmapImageRep(
                bitmapDataPlanes: nil,
                pixelsWide: Int(size.width), pixelsHigh: Int(size.height),
                bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
        else { return screenshot.pngRepresentation }
        bitmap.size = size

        NSGraphicsContext.saveGraphicsState()
        defer { NSGraphicsContext.restoreGraphicsState() }
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        image.draw(in: NSRect(origin: .zero, size: size))
        NSGraphicsContext.current?.flushGraphics()

        return bitmap.representation(using: .png, properties: [:]) ?? screenshot.pngRepresentation
    }

    /// Record a piece of text as evidence, the way `recordText` does in the Node suites.
    func record(_ name: String, _ text: String, _ label: String) {
        let attachment = XCTAttachment(string: text)
        attachment.name = label
        attachment.lifetime = .keepAlways
        add(attachment)

        guard let directory = artifactDirectory else { return }
        let file = "\(name).txt"
        do {
            try text.write(to: directory.appendingPathComponent(file), atomically: true, encoding: .utf8)
            appendManifest(file: file, label: label, kind: "log")
        } catch {
            XCTFail("could not write \(file): \(error)")
        }
    }

    /// One JSON Lines entry per piece of evidence — the contract in docs/e2e-harness.md §3.
    ///
    /// Appended rather than rewritten, and opened per line: scenarios in the same bundle run one
    /// after another, but the adapter and a future parallel run must not be able to lose an entry
    /// in a read-modify-write window.
    private func appendManifest(file: String, label: String, kind: String) {
        guard let directory = artifactDirectory else { return }
        let entry: [String: String] = [
            "test": scenarioKey, "file": file, "label": label, "kind": kind,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: entry, options: [.sortedKeys]),
            var line = String(data: data, encoding: .utf8)
        else { return }
        line += "\n"

        let manifest = directory.appendingPathComponent("manifest.jsonl")
        if let handle = try? FileHandle(forWritingTo: manifest) {
            defer { try? handle.close() }
            try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
        } else {
            try? line.write(to: manifest, atomically: false, encoding: .utf8)
        }
    }
}

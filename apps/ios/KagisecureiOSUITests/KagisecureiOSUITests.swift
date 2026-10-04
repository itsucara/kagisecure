import XCTest

/// First run → create vault → add login → see it → edit → delete, with password unlock only
/// (Face ID is off and presence is scripted via DEBUG launch arguments).
final class KagisecureiOSUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    func testFirstRunAddEditDelete() throws {
        let dir = NSTemporaryDirectory() + "ks-ui-" + UUID().uuidString
        let app = XCUIApplication()
        app.launchArguments = [
            "-KSVaultDir", dir, "-KSFastKDF", "-KSUITestPresence", "allow", "-KSNoBiometrics",
        ]
        app.launch()
        let password = "ui-" + UUID().uuidString

        // First run
        let pw = app.secureTextFields["setup.password"]
        XCTAssertTrue(pw.waitForExistence(timeout: 10))
        pw.tap(); pw.typeText(password)
        let confirm = app.secureTextFields["setup.confirm"]
        confirm.tap(); confirm.typeText(password)
        app.buttons["setup.create"].tap()

        // Recovery code shown once
        XCTAssertTrue(app.staticTexts["recovery.code"].waitForExistence(timeout: 20))
        app.switches["recovery.saved"].switches.firstMatch.tap()
        app.buttons["recovery.continue"].tap()

        // Add a login
        let add = app.buttons["list.add"]
        XCTAssertTrue(add.waitForExistence(timeout: 10))
        add.tap()
        let title = app.textFields["add.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        title.tap(); title.typeText("Example Login")
        app.buttons["add.next"].tap()
        XCTAssertTrue(app.buttons["edit.save"].waitForExistence(timeout: 5))
        app.buttons["edit.save"].tap()

        // In the list
        let row = app.buttons["item.Example Login"]
        XCTAssertTrue(row.waitForExistence(timeout: 5))

        // Edit
        row.tap()
        let edit = app.buttons["detail.edit"]
        XCTAssertTrue(edit.waitForExistence(timeout: 5))
        edit.tap()
        let editTitle = app.textFields["edit.title"]
        XCTAssertTrue(editTitle.waitForExistence(timeout: 5))
        editTitle.tap()
        editTitle.typeText(" Renamed")
        app.buttons["edit.save"].tap()
        XCTAssertTrue(app.navigationBars["Example Login Renamed"].waitForExistence(timeout: 5))

        // Delete
        app.buttons["detail.delete"].tap()
        let confirmDelete = app.buttons.matching(identifier: "detail.confirmDelete").firstMatch
        XCTAssertTrue(confirmDelete.waitForExistence(timeout: 5))
        confirmDelete.tap()
        XCTAssertTrue(add.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["item.Example Login Renamed"].waitForExistence(timeout: 2))

        // Lock from settings, unlock with password
        app.buttons["list.settings"].tap()
        app.buttons["settings.lock"].tap()
        let lockField = app.secureTextFields["lock.password"]
        XCTAssertTrue(lockField.waitForExistence(timeout: 5))
        lockField.tap(); lockField.typeText(password)
        app.buttons["lock.unlock"].tap()
        XCTAssertTrue(add.waitForExistence(timeout: 20))
    }
}

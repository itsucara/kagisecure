import AppKit
import XCTest

@testable import Kagisecure

/// Settings › General: the appearance and language choices (ui-spec.md §17).
@MainActor
final class AppearanceAndLanguageTests: XCTestCase {
    func testAppearanceMapsToAppKitNames() {
        XCTAssertNil(AppAppearance.system.appearanceName)
        XCTAssertEqual(AppAppearance.light.appearanceName, .aqua)
        XCTAssertEqual(AppAppearance.dark.appearanceName, .darkAqua)
    }

    func testUnknownOrMissingAppearanceReadsAsSystem() {
        XCTAssertEqual(AppAppearance.choice(from: nil), .system)
        XCTAssertEqual(AppAppearance.choice(from: "sepia"), .system)
        XCTAssertEqual(AppAppearance.choice(from: "dark"), .dark)
    }

    func testAppearanceRoundTripsThroughDefaults() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ks-appearance-\(UUID())"))
        XCTAssertEqual(AppAppearance.stored(in: defaults), .system)
        defaults.set(AppAppearance.light.rawValue, forKey: AppAppearance.defaultsKey)
        XCTAssertEqual(AppAppearance.stored(in: defaults), .light)
    }

    func testAvailableLanguagesPutDevelopmentFirstAndDropBase() {
        XCTAssertEqual(
            AppLanguage.available(localizations: ["ja", "Base", "en", "de"], development: "en"),
            ["en", "de", "ja"])
    }

    func testBundleShipsEnglishAndJapanese() {
        let codes = AppLanguage.available(in: Bundle(for: AppModel.self))
        XCTAssertTrue(codes.contains("en"))
        XCTAssertTrue(codes.contains("ja"))
    }

    func testLanguagesAreNamedInThemselves() {
        XCTAssertEqual(AppLanguage.nativeName(of: "en"), "English")
        XCTAssertEqual(AppLanguage.nativeName(of: "ja"), "日本語")
    }

    func testOnlyASingleLanguageListIsAnOverride() {
        XCTAssertNil(AppLanguage.selection(from: nil))
        XCTAssertNil(AppLanguage.selection(from: ["ja", "en"]))
        XCTAssertNil(AppLanguage.selection(from: "ja"))
        XCTAssertEqual(AppLanguage.selection(from: ["ja"]), "ja")
    }

    func testLanguageStoreWritesListOrRemovesKey() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ks-language-\(UUID())"))
        AppLanguage.store("ja", in: defaults)
        XCTAssertEqual(defaults.array(forKey: AppLanguage.defaultsKey) as? [String], ["ja"])
        XCTAssertEqual(AppLanguage.stored(in: defaults), "ja")
        AppLanguage.store(nil, in: defaults)
        XCTAssertNil(defaults.persistentDomain(forName: "unused")?[AppLanguage.defaultsKey])
        XCTAssertNil(AppLanguage.storedValue(for: nil))
    }
}

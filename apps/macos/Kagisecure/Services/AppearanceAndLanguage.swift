import AppKit
import Foundation
import SwiftUI

/// The app's own light/dark choice, independent of the Mac's.
///
/// Applied through `NSApp.appearance`, which every window inherits — the main window, Settings,
/// the Quick Access panel and any sheet — so one assignment changes all of them at once.
enum AppAppearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    static let defaultsKey = "appearance"

    var id: String { rawValue }

    /// The `NSAppearance` name to pin, or `nil` to follow the system.
    var appearanceName: NSAppearance.Name? {
        switch self {
        case .system: nil
        case .light: .aqua
        case .dark: .darkAqua
        }
    }

    var symbol: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max"
        case .dark: "moon"
        }
    }

    /// A key rather than a resolved string, so the view's `\.locale` decides the language.
    var title: LocalizedStringKey {
        switch self {
        case .system: "System"
        case .light: "Light"
        case .dark: "Dark"
        }
    }

    /// A stored raw value as a choice; anything missing or unrecognised reads as `.system`.
    static func choice(from raw: String?) -> AppAppearance {
        raw.flatMap(AppAppearance.init(rawValue:)) ?? .system
    }

    static func stored(in defaults: UserDefaults = AppDefaults.shared) -> AppAppearance {
        choice(from: defaults.string(forKey: defaultsKey))
    }

    /// Pin (or release) the whole application's appearance.
    @MainActor
    func apply() {
        NSApplication.shared.appearance = appearanceName.flatMap { NSAppearance(named: $0) }
    }

    /// Apply the stored choice at launch. Scheduled for the next main-actor turn because this is
    /// reached from `AppModel.init`, before `NSApp` exists (see `UITestSupport.applyAppearance`).
    @MainActor
    static func applyStoredAtLaunch() {
        let choice = stored()
        guard choice != .system else { return }
        Task { @MainActor in choice.apply() }
    }
}

/// The app's own language choice.
///
/// Stored the way macOS stores a per-app language from System Settings: an `AppleLanguages` array
/// in the app's defaults domain, or no key at all for "follow the system". Bundle localisation is
/// resolved at launch, so a change takes effect on the next launch.
enum AppLanguage {
    static let defaultsKey = "AppleLanguages"

    /// The languages the app ships, from the bundle itself — a new `.lproj` shows up here with no
    /// code change. `Base` is not a language. Development language first, the rest sorted.
    static func available(localizations: [String], development: String?) -> [String] {
        let codes = Array(Set(localizations.filter { $0 != "Base" }))
        return codes.sorted { lhs, rhs in
            if lhs == development { return true }
            if rhs == development { return false }
            return lhs < rhs
        }
    }

    static func available(in bundle: Bundle = .main) -> [String] {
        available(localizations: bundle.localizations, development: bundle.developmentLocalization)
    }

    /// A language's name in that language: "English", "日本語".
    static func nativeName(of code: String) -> String {
        let name = Locale(identifier: code).localizedString(forIdentifier: code) ?? code
        return name.prefix(1).uppercased() + name.dropFirst()
    }

    /// The override an `AppleLanguages` value represents, or `nil` for "follow the system". Only a
    /// single-language list — what this pane writes — counts as an override.
    static func selection(from value: Any?) -> String? {
        guard let list = value as? [String], list.count == 1 else { return nil }
        return list.first
    }

    /// The value to write for a selection: `[code]`, or `nil` (remove the key) for the system.
    static func storedValue(for code: String?) -> [String]? {
        code.map { [$0] }
    }

    /// The current override. For the standard store, only the app's own domain is read —
    /// `object(forKey:)` would also see the Mac-wide language list in the global domain.
    static func stored(in defaults: UserDefaults = AppDefaults.shared) -> String? {
        if defaults === UserDefaults.standard, let id = Bundle.main.bundleIdentifier {
            return selection(from: defaults.persistentDomain(forName: id)?[defaultsKey])
        }
        return selection(from: defaults.object(forKey: defaultsKey))
    }

    static func store(_ code: String?, in defaults: UserDefaults = AppDefaults.shared) {
        if let value = storedValue(for: code) {
            defaults.set(value, forKey: defaultsKey)
        } else {
            defaults.removeObject(forKey: defaultsKey)
        }
    }

    /// Lock the vault, start a fresh copy of the app, and quit this one.
    @MainActor
    static func relaunch(model: AppModel) {
        model.lock(reason: .manual)
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: config) { _, error in
            guard error == nil else { return }
            Task { @MainActor in NSApplication.shared.terminate(nil) }
        }
    }
}

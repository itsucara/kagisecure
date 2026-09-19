import Foundation
import Observation

import KagisecureFFI

/// The state behind the password generator sheet (ui-spec.md §8).
///
/// Holds knobs and candidates; owns no randomness and no strength arithmetic. Every value it
/// shows comes from `kagisecure-core` through the FFI, so the sheet, `kagisecure generate` and
/// any later browser extension cannot disagree about what a 20-character password is worth.
///
/// It touches no vault, which is what makes it testable on its own: the tests in
/// `KagisecureTests/GeneratorModelTests.swift` drive this class with no unlocked session anywhere.
@MainActor
@Observable
final class GeneratorModel {
    /// The bounds the sliders obey, read from the core rather than written twice.
    let limits: GeneratorLimits = generatorLimits()

    /// The current settings. Every mutation regenerates, so the candidate always matches what the
    /// meter is describing.
    var recipe: GeneratorRecipe {
        didSet {
            guard recipe != oldValue else { return }
            enforceLetterClassRule(previous: oldValue)
            regenerate()
        }
    }

    /// The candidate on screen. Empty only before the first generation, or after a failure.
    private(set) var candidate = ""

    /// Earlier candidates from this sheet, newest first (ui-spec.md §8's history dropdown).
    ///
    /// In memory and nowhere else. The sheet is the lifetime: closing it releases this object,
    /// and nothing writes a candidate to disk, to the audit log or to `UserDefaults`.
    private(set) var history: [String] = []

    /// The last generation failure, if the recipe could not be satisfied.
    private(set) var errorMessage: String?

    /// How many candidates the history keeps. Enough to undo a few regenerations, few enough that
    /// a sheet left open does not accumulate a list of live passwords.
    static let historyLimit = 8

    init(recipe: GeneratorRecipe = GeneratorRecipe.standard) {
        self.recipe = recipe
        regenerate()
    }

    /// What the strength meter draws. A property of the recipe, not of the candidate, so the bar
    /// moves monotonically as the slider does instead of jittering on every regeneration.
    var strength: StrengthView {
        recipeStrength(recipe: recipe)
    }

    /// Draw a new candidate (⌘R in the sheet).
    func regenerate() {
        do {
            let fresh = try generatePassword(recipe: recipe)
            if !candidate.isEmpty {
                history.insert(candidate, at: 0)
                if history.count > Self.historyLimit {
                    history.removeLast(history.count - Self.historyLimit)
                }
            }
            candidate = fresh
            errorMessage = nil
        } catch {
            candidate = ""
            errorMessage = VaultStore.message(for: error)
        }
    }

    /// Bring an earlier candidate back without regenerating.
    func restore(_ earlier: String) {
        guard earlier != candidate, history.contains(earlier) else { return }
        history.removeAll { $0 == earlier }
        if !candidate.isEmpty {
            history.insert(candidate, at: 0)
        }
        candidate = earlier
    }

    /// Whether this recipe can produce anything at all.
    var isSatisfiable: Bool {
        recipe.mode == .words || recipe.lowercase || recipe.uppercase || recipe.digits
            || recipe.symbols
    }

    /// ui-spec.md §8: "at least one letter class must stay on".
    ///
    /// Turning off the last enabled letter class turns the *other* one on rather than refusing
    /// the click. A toggle that silently does nothing is worse than one that visibly moves its
    /// neighbour, and a password of digits and symbols only is not what anyone meant to ask for.
    private func enforceLetterClassRule(previous: GeneratorRecipe) {
        guard recipe.mode == .characters, !recipe.lowercase, !recipe.uppercase else { return }
        if previous.lowercase {
            recipe.uppercase = true
        } else {
            recipe.lowercase = true
        }
    }
}

extension GeneratorRecipe {
    /// The default the sheet opens with: 20 characters, every class, ambiguous characters allowed.
    ///
    /// Spelled out here rather than taken from a Rust `Default` because UniFFI records arrive in
    /// Swift without one, and one place has to say what "open the generator" means.
    static var standard: GeneratorRecipe {
        GeneratorRecipe(
            mode: .characters,
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoidAmbiguous: false,
            words: 4,
            separator: .hyphen,
            capitalize: false,
            includeDigit: false)
    }
}

extension WordSeparator {
    /// Every separator the sheet offers, in menu order.
    static let all: [WordSeparator] = [.hyphen, .underscore, .period, .space, .none]

    /// What the menu row says.
    var label: String {
        switch self {
        case .hyphen: "Hyphen  -"
        case .underscore: "Underscore  _"
        case .period: "Period  ."
        case .space: "Space"
        case .none: "None"
        }
    }
}

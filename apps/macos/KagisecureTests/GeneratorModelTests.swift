import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The generator sheet's view model (ui-spec.md §8, roadmap M5).
///
/// No vault anywhere: `GeneratorModel` talks to free functions in `kagisecure-core`, which is
/// what makes the sheet openable from the `+` menu before an item exists — and what makes these
/// tests run in microseconds.
@MainActor
struct GeneratorModelTests {
    @Test func opensWithACandidateAndAnExcellentDefault() {
        let model = GeneratorModel()
        #expect(model.candidate.count == 20)
        #expect(model.history.isEmpty, "the first candidate is not its own history")
        #expect(model.strength.bucket == .excellent)
        #expect(model.errorMessage == nil)
    }

    @Test func regeneratingPushesTheOldCandidateOntoTheHistory() {
        let model = GeneratorModel()
        let first = model.candidate
        model.regenerate()
        #expect(model.candidate != first, "two draws from a 128-bit space must differ")
        #expect(model.history.first == first)
    }

    @Test func theHistoryIsBounded() {
        let model = GeneratorModel()
        for _ in 0..<(GeneratorModel.historyLimit + 6) {
            model.regenerate()
        }
        #expect(model.history.count == GeneratorModel.historyLimit)
    }

    @Test func restoringBringsAnEarlierCandidateBackWithoutGenerating() {
        let model = GeneratorModel()
        let first = model.candidate
        model.regenerate()
        let second = model.candidate
        model.restore(first)
        #expect(model.candidate == first)
        #expect(model.history.contains(second), "the one it replaced is now the history")
        #expect(!model.history.contains(first), "and the restored one has left it")
    }

    @Test func changingTheLengthRegeneratesAtTheNewLength() {
        let model = GeneratorModel()
        model.recipe.length = 42
        #expect(model.candidate.count == 42)
        model.recipe.length = 8
        #expect(model.candidate.count == 8)
    }

    @Test func theMeterMovesMonotonicallyWithTheSlider() {
        let model = GeneratorModel()
        var previous = 0.0
        for length in model.limits.minLength...model.limits.maxLength {
            model.recipe.length = length
            let bits = model.strength.bits
            #expect(bits > previous, "\(length) characters scored \(bits) after \(previous)")
            previous = bits
        }
    }

    @Test func turningOffTheLastLetterClassTurnsTheOtherOn() {
        let model = GeneratorModel()
        model.recipe.uppercase = false
        #expect(model.recipe.lowercase, "lower case was already on and stays on")

        // Now switch the remaining one off: the rule brings the other back rather than leaving a
        // digits-and-symbols password (ui-spec.md §8).
        model.recipe.lowercase = false
        #expect(model.recipe.uppercase)
        #expect(model.isSatisfiable)
        #expect(!model.candidate.isEmpty)
        #expect(model.candidate.allSatisfy { !$0.isLowercase })
    }

    @Test func disabledClassesDoNotAppearInTheCandidate() {
        let model = GeneratorModel()
        model.recipe = GeneratorRecipe(
            mode: .characters, length: 64, lowercase: true, uppercase: false, digits: false,
            symbols: false, avoidAmbiguous: true, words: 4, separator: .hyphen, capitalize: false,
            includeDigit: false)
        #expect(model.candidate.count == 64)
        #expect(model.candidate.allSatisfy { $0.isLowercase && $0.isLetter })
        #expect(!model.candidate.contains("l"), "l is excluded as ambiguous")
    }

    @Test func wordModeUsesItsOwnKnobs() {
        let model = GeneratorModel()
        model.recipe.mode = .words
        #expect(model.candidate.split(separator: "-").count == 4)

        model.recipe.words = 7
        model.recipe.separator = .period
        model.recipe.capitalize = true
        let parts = model.candidate.split(separator: ".")
        #expect(parts.count == 7)
        #expect(parts.allSatisfy { $0.first?.isUppercase == true })
        #expect(model.strength.bits > 80)
    }

    @Test func theWordlistSizeComesFromTheCore() {
        #expect(GeneratorModel().limits.wordlistSize == 7_776)
    }

    @Test func estimatingAnExistingPasswordIsNotTheSameAsGeneratingOne() {
        #expect(passwordStrength(password: "password").bucket == .veryWeak)
        #expect(passwordStrength(password: "").bits == 0)
        let generated = GeneratorModel().candidate
        #expect(passwordStrength(password: generated).bucket == .excellent)
    }
}

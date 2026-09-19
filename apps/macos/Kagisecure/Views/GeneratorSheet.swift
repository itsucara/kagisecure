import SwiftUI

import KagisecureFFI

/// The password generator sheet (ui-spec.md §8).
///
/// Opened from a concealed field's "Generate" button in edit mode, from the toolbar's `+` menu
/// and from the Item menu. `onUse` is `nil` for the standalone case — there is no field to fill,
/// so the sheet offers Copy and nothing else.
struct GeneratorSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model = GeneratorModel()
    @State private var copied = false

    /// Where the password goes when the user presses "Use this password". `nil` when the sheet
    /// was opened standalone.
    var onUse: ((String) -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            candidateBox
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    modePicker
                    switch model.recipe.mode {
                    case .characters: characterControls
                    case .words: wordControls
                    }
                }
                .padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 460)
        .frame(minHeight: 470)
    }

    // MARK: - The candidate and its meter

    private var candidateBox: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Text(model.candidate.isEmpty ? "—" : model.candidate)
                    .font(.system(.title3, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel("Generated password")
                    // …and the password itself as the *value*. Without this the label replaces the
                    // text, and a VoiceOver user is told only that there is a generated password —
                    // never what it is, on the sheet whose whole purpose is to show them one.
                    .accessibilityValue(model.candidate)
                    .accessibilityIdentifier("ks.generator.candidate")

                Button {
                    model.regenerate()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .keyboardShortcut("r", modifiers: .command)
                .help("Generate a new one (⌘R)")
                .accessibilityLabel("Regenerate")
                .accessibilityIdentifier("ks.generator.regenerate")

                if !model.history.isEmpty {
                    Menu {
                        ForEach(model.history, id: \.self) { earlier in
                            Button(earlier) { model.restore(earlier) }
                        }
                    } label: {
                        Image(systemName: "clock.arrow.circlepath")
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .help("Earlier candidates from this session")
                    .accessibilityIdentifier("ks.generator.history")
                }
            }

            if let message = model.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.generator.error")
            } else {
                meter
            }
        }
        .padding(20)
    }

    private var meter: some View {
        let strength = model.strength
        return VStack(alignment: .leading, spacing: 5) {
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    Capsule().fill(.quaternary)
                    Capsule()
                        .fill(color(for: strength.bucket))
                        .frame(width: max(4, geometry.size.width * strength.fraction))
                }
            }
            .frame(height: 6)
            HStack {
                Text(strength.label)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(color(for: strength.bucket))
                    .accessibilityIdentifier("ks.generator.strengthLabel")
                Spacer()
                Text("\(Int(strength.bits.rounded())) bits of entropy")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .accessibilityIdentifier("ks.generator.bits")
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "Strength \(strength.label), \(Int(strength.bits.rounded())) bits of entropy")
        .accessibilityIdentifier("ks.generator.strength")
    }

    private func color(for bucket: StrengthBucket) -> Color {
        switch bucket {
        case .veryWeak: .red
        case .weak: .orange
        case .fair: .yellow
        case .good: .mint
        case .excellent: .green
        }
    }

    // MARK: - Controls

    private var modePicker: some View {
        Picker("Mode", selection: Binding(
            get: { model.recipe.mode },
            set: { model.recipe.mode = $0 })
        ) {
            Text("Random characters").tag(GeneratorMode.characters)
            Text("Memorable words").tag(GeneratorMode.words)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .accessibilityIdentifier("ks.generator.mode")
    }

    private var characterControls: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Length")
                Spacer()
                Text("\(model.recipe.length)")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.generator.lengthValue")
            }
            Slider(
                value: Binding(
                    get: { Double(model.recipe.length) },
                    set: { model.recipe.length = UInt32($0.rounded()) }),
                in: Double(model.limits.minLength)...Double(model.limits.maxLength),
                step: 1
            )
            .accessibilityLabel("Length")
            .accessibilityValue("\(model.recipe.length) characters")
            .accessibilityIdentifier("ks.generator.length")

            Toggle("Lower-case letters  a–z", isOn: binding(\.lowercase))
                .accessibilityIdentifier("ks.generator.toggle.lowercase")
            Toggle("Upper-case letters  A–Z", isOn: binding(\.uppercase))
                .accessibilityIdentifier("ks.generator.toggle.uppercase")
            Toggle("Digits  0–9", isOn: binding(\.digits))
                .accessibilityIdentifier("ks.generator.toggle.digits")
            Toggle("Symbols  ! # $ % …", isOn: binding(\.symbols))
                .accessibilityIdentifier("ks.generator.toggle.symbols")
            Toggle("Avoid ambiguous characters  0 O 1 l I", isOn: binding(\.avoidAmbiguous))
                .accessibilityIdentifier("ks.generator.toggle.avoidAmbiguous")

            Text("At least one letter class stays on; turning both off switches the other back.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var wordControls: some View {
        VStack(alignment: .leading, spacing: 14) {
            Stepper(
                value: Binding(
                    get: { model.recipe.words },
                    set: { model.recipe.words = $0 }),
                in: model.limits.minWords...model.limits.maxWords
            ) {
                HStack {
                    Text("Words")
                    Spacer()
                    Text("\(model.recipe.words)")
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("ks.generator.wordsValue")
                }
            }
            .accessibilityIdentifier("ks.generator.words")

            Picker("Separator", selection: Binding(
                get: { model.recipe.separator },
                set: { model.recipe.separator = $0 })
            ) {
                ForEach(WordSeparator.all, id: \.self) { separator in
                    Text(separator.label).tag(separator)
                }
            }
            .accessibilityIdentifier("ks.generator.separator")

            Toggle("Capitalize each word", isOn: binding(\.capitalize))
                .accessibilityIdentifier("ks.generator.toggle.capitalize")
            Toggle("Include a digit", isOn: binding(\.includeDigit))
                .accessibilityIdentifier("ks.generator.toggle.includeDigit")

            Text(
                "Words are drawn from the EFF long list — \(model.limits.wordlistSize) words, "
                    + "so each one is worth 12.9 bits."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func binding(_ path: WritableKeyPath<GeneratorRecipe, Bool>) -> Binding<Bool> {
        Binding(
            get: { model.recipe[keyPath: path] },
            set: { model.recipe[keyPath: path] = $0 })
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button {
                PasteboardService.copy(model.candidate, label: "Generated password")
                copied = true
            } label: {
                Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .disabled(model.candidate.isEmpty)
            .help(PasteboardService.clearDescription(seconds: PasteboardService.clearSeconds))
            .accessibilityIdentifier("ks.generator.copy")

            Spacer()

            Button("Cancel", role: .cancel) { dismiss() }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("ks.generator.cancel")

            if let onUse {
                Button("Use this password") {
                    onUse(model.candidate)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(model.candidate.isEmpty)
                .accessibilityIdentifier("ks.generator.use")
            }
        }
        .padding(16)
        .onChange(of: model.candidate) { _, _ in copied = false }
    }
}

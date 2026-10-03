import SwiftUI

/// A whole number the user can set exactly: a text field and a stepper, bound to one value.
///
/// It goes beside a `Slider`, not instead of it. The slider is the quick, coarse control; this is
/// the precise one, and the one the keyboard can reach. A macOS `NSSlider` takes key focus only
/// with Full Keyboard Access turned on, and so does an `NSStepper`, so a slider on its own leaves
/// someone who uses the keyboard with no way to set the value at all (ui-spec.md §13). A text field
/// is in the Tab order on every Mac. The pairing is the one the macOS HIG recommends for a slider
/// whose range is wide enough that an exact value matters — a text field for typing the value, a
/// stepper for nudging it by one — and both of this app's sliders are that: the generator's 8–128
/// characters and the approval sheet's 1–1,440 minutes.
///
/// A number typed in is taken **as it is typed**, whenever what is in the field is a value in
/// `range`. It has to be: both sheets have a button whose meaning depends on the value — "Use this
/// password", "Allow for this session" — and neither Return (a default button's key equivalent is
/// dispatched before the field sees the key) nor a click on a button (which does not take focus)
/// ends the edit first. A value that only arrived on commit would lose that race, and the password
/// used or the lease granted would be the one from before the typing.
///
/// On Return, Tab or a click elsewhere the field is committed: digits only, clamped into `range`.
/// Out-of-range input is not an error, it is a request for the nearest value that exists, and the
/// field then shows the value that was taken — so typing 500 into a 128-character ceiling reads
/// back as 128, never as a 500 that was quietly not applied. Anything with no digits in it puts
/// the field back to the current value.
///
/// Identifiers: `<identifier>Field` on the text field and `<identifier>Stepper` on the stepper —
/// set on the leaves, because an identifier on the `HStack` would be stamped onto both
/// (ui-spec.md §15).
struct ExactNumberField: View {
    /// What the number is, for VoiceOver — "Length in characters", "Access expires after, in
    /// minutes". Both controls carry it (the text field's `AXDescription`, the stepper's title).
    let label: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    var step = 1
    let identifier: String

    @State private var text = ""
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 4) {
            TextField(label, text: $text)
                .labelsHidden()
                .multilineTextAlignment(.trailing)
                .monospacedDigit()
                .frame(width: 52)
                .focused($focused)
                .onSubmit(commit)
                .onChange(of: text) { _, typed in
                    if let number = Self.number(in: typed), range.contains(number), number != value {
                        value = number
                    }
                }
                .onChange(of: focused) { _, isFocused in
                    if !isFocused { commit() }
                }
                .accessibilityLabel(label)
                .accessibilityIdentifier("\(identifier)Field")
            // The title is its accessibility label already; `.accessibilityLabel` on top of it
            // reads the label twice ("Length in characters, Length in characters" — measured).
            Stepper(label, value: $value, in: range, step: step)
                .labelsHidden()
                .accessibilityIdentifier("\(identifier)Stepper")
        }
        .onAppear { text = String(value) }
        // The slider and the stepper move the value without going through the field. Nothing
        // typed is lost by following them: an in-range number is already the value by the time
        // this runs, and only a partial one — the "1" of "128" — is not.
        .onChange(of: value) { _, newValue in text = String(newValue) }
    }

    private func commit() {
        if let typed = Self.number(in: text) {
            value = min(max(typed, range.lowerBound), range.upperBound)
        }
        // Set even when `value` did not change — 500 clamped to a 128 that was already 128 — so
        // the field never keeps showing a number that is not the value.
        text = String(value)
    }

    /// The digits in `text` as a number, or `nil` if there are none. Nine digits at most, which
    /// no range here comes near and no `Int` overflows on.
    private static func number(in text: String) -> Int? {
        Int(text.filter(\.isASCIIDigit).prefix(9))
    }
}

private extension Character {
    var isASCIIDigit: Bool { ("0"..."9").contains(self) }
}

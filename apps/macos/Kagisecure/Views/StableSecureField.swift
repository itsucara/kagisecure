import AppKit
import SwiftUI

/// A native macOS password field whose in-progress input is never rewritten by SwiftUI.
///
/// On macOS 26, `SwiftUI.SecureField` can feed an IME's marked text back through its binding
/// while the input method is still composing it. With Japanese input enabled, one physical key
/// press can consequently appear as two bullets. `NSSecureTextField` already owns the correct
/// field editor for secret input, so this wrapper lets AppKit finish composition and only mirrors
/// committed changes into the SwiftUI binding.
struct StableSecureField: NSViewRepresentable {
    @Binding var text: String
    let placeholder: String
    var autofocus = false
    var onSubmit: () -> Void = {}

    init(
        _ placeholder: String,
        text: Binding<String>,
        autofocus: Bool = false,
        onSubmit: @escaping () -> Void = {}
    ) {
        self.placeholder = placeholder
        _text = text
        self.autofocus = autofocus
        self.onSubmit = onSubmit
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeNSView(context: Context) -> NSSecureTextField {
        let field = NSSecureTextField(string: text)
        field.placeholderString = placeholder
        field.delegate = context.coordinator
        field.bezelStyle = .roundedBezel
        field.isBordered = true
        field.drawsBackground = true
        field.focusRingType = .default
        field.font = .systemFont(ofSize: NSFont.systemFontSize)
        field.lineBreakMode = .byClipping
        field.usesSingleLineMode = true
        Self.configureAgainstAutoFill(field)
        return field
    }

    /// Every use of this field is a Kagisecure secret (the master password, an agent secret
    /// value) — never a website login. Without an explicit content type, macOS Passwords AutoFill
    /// treats any secure field as a login password and offers its suggestions over the lock
    /// screen. An empty content type opts the field out of that heuristic.
    static func configureAgainstAutoFill(_ field: NSSecureTextField) {
        field.contentType = NSTextContentType(rawValue: "")
        field.isAutomaticTextCompletionEnabled = false
    }

    /// Reports this field's real size back to SwiftUI, so the `NSSecureTextField`'s own frame —
    /// what AppKit actually hit-tests mouse clicks against — matches what SwiftUI lays other
    /// views out around, rather than an ambiguous size `NSViewRepresentable` would otherwise
    /// guess from Auto Layout. Without this, a sibling in the same `HStack` (an "Add" button,
    /// say) could end up drawn where this field's real, smaller hit area does not reach: the
    /// field looks clickable across its whole visible width but only part of it focuses on
    /// click, and the rest silently does nothing (Tab still reaches it, since that does not go
    /// through hit-testing).
    func sizeThatFits(
        _ proposal: ProposedViewSize, nsView: NSSecureTextField, context: Context
    ) -> CGSize? {
        // Width follows the proposal; height is always the field's own single line. Taking the
        // proposed height too stretched the lock screen's password field over the whole card.
        let fitting = nsView.fittingSize
        return CGSize(width: proposal.width ?? fitting.width, height: fitting.height)
    }

    func updateNSView(_ field: NSSecureTextField, context: Context) {
        context.coordinator.parent = self

        // Writing `stringValue` while an input method owns marked text commits that text and can
        // make the same keystroke arrive again. AppKit will call `controlTextDidChange` with the
        // committed value; until then the field editor remains the source of truth.
        let isComposing = (field.currentEditor() as? NSTextView)?.hasMarkedText() ?? false
        if !isComposing, field.stringValue != text {
            field.stringValue = text
        }

        guard autofocus, !context.coordinator.didRequestFocus else { return }
        context.coordinator.didRequestFocus = true
        DispatchQueue.main.async { [weak field] in
            guard let field, let window = field.window else { return }
            window.makeFirstResponder(field)
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: StableSecureField
        var didRequestFocus = false

        init(_ parent: StableSecureField) {
            self.parent = parent
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSecureTextField else { return }
            parent.text = field.stringValue
        }

        func control(
            _ control: NSControl,
            textView: NSTextView,
            doCommandBy commandSelector: Selector
        ) -> Bool {
            guard commandSelector == #selector(NSResponder.insertNewline(_:)) else { return false }
            // Return commits an active IME composition first. Submitting at that point would use
            // the marked (not final) password and could clear the field underneath the input
            // method; AppKit will offer Return again after the composition is committed.
            guard !textView.hasMarkedText() else { return false }
            parent.onSubmit()
            return true
        }
    }
}

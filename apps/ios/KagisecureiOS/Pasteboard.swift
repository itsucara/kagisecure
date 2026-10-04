import UIKit

/// Copy a secret: this device only (no Universal Clipboard) and gone after 60 seconds — the
/// macOS default clear interval (PasteboardService.defaultClearSeconds).
@MainActor
enum Pasteboard {
    static let expirySeconds: TimeInterval = 60

    static func copy(_ value: String) {
        UIPasteboard.general.setItems(
            [["public.utf8-plain-text": value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(expirySeconds),
            ])
    }
}

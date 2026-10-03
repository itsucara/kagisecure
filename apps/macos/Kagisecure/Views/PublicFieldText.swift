import SwiftUI

/// A **public** field's value in the detail pane — a username, a hostname, a phone number —
/// which the vault already hands out in every `ItemView` and which a person may select and copy
/// as ordinary text.
///
/// Its own file, and the only place in the item views that enables `.textSelection`, on purpose:
/// no released secret may ever be selectable (ADR-0038 surface #2), and a unit test scans the
/// views that render released values for `.textSelection`. Keeping the one legitimate use here
/// keeps that scan exact rather than a list of exceptions. Nothing released may be passed to it.
struct PublicFieldText: View {
    let value: String

    var body: some View {
        Text(value)
            .textSelection(.enabled)
    }
}

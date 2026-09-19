import Foundation

import KagisecureFFI

/// `Identifiable` conformances for the generated FFI records.
///
/// UniFFI emits plain records — it has no way to know which field a SwiftUI `Table` or `ForEach`
/// should key rows by, and teaching it would put a UI concern in the Rust surface. Declaring the
/// conformances here keeps `kagisecure-ffi` about the vault and this file about SwiftUI.
extension LeaseView: @retroactive Identifiable {}

extension AuditRowView: @retroactive Identifiable {
    /// The chain position. Unique by construction: it *is* the entry's index in the hash chain.
    public var id: UInt64 { seq }
}

extension EnvironmentView: @retroactive Identifiable {}

extension EnvVarView: @retroactive Identifiable {
    /// Variable names are unique within an environment — `Environment::set_var` replaces rather
    /// than appends — so the name is the identity.
    public var id: String { name }
}

extension FillLeaseView: @retroactive Identifiable {
    /// The pair the store keys on. A fill lease is scoped to one item at one origin, and the store
    /// holds at most one per pair, so the two together are the identity.
    public var id: String { "\(origin)\u{0000}\(itemId)" }
}

extension BrowserManifestView: @retroactive Identifiable {
    /// The absolute path of the file. One manifest per browser, one path per manifest.
    public var id: String { path }
}

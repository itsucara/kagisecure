import Foundation

import KagisecureFFI

/// An item `EnvironmentEditor`'s "Add a variable" may bind a shared environment's variable to
/// (ui-spec.md §16.6): a shared vault's own items, never another vault's — the same rule
/// `kagisecure-core`'s `resolve_injections` enforces server-side ("references stay inside the
/// vault", `crates/kagisecure-ffi/src/shared.rs` module documentation).
struct EnvironmentBindableItem: Identifiable {
    /// One field an environment's variable may point at.
    struct Field: Identifiable, Hashable {
        let id: String
        let label: String
    }

    let id: String
    let title: String
    let fields: [Field]
}

/// What `EnvironmentEditor` (ui-spec.md §10.4, §16.6) needs in order to act on one environment —
/// extracted so the same editor renders and behaves identically for the personal vault's
/// environments (`VaultStore`) and a shared vault's (`SharedVaultSession` plus
/// `SharedVaultsModel`'s bookkeeping); only what a mutation does, and whether a given one is even
/// offered, differs between the two.
///
/// A struct of closures rather than a protocol: the two backings need no shared base type of
/// their own (`VaultStore` is not an environment source; a shared vault's calls go through
/// `SharedVaultSession` plus a vault id `SharedVaultsModel` needs for `didChangeLocally`), and a
/// closure adapts either without inventing one.
@MainActor
struct EnvironmentEditing {
    /// Whether this device may change the environment's shape at all: always for the personal
    /// vault; a shared vault's reader may view but not edit (ui-spec.md §16.6's item rule, applied
    /// here). Agent visibility is unaffected by this flag — it is this device's own setting
    /// either way, like an item's (decision 22), and never a shared vault's own record.
    let canEdit: Bool
    let setShareWithAgents: (EnvironmentView, Bool) -> Void
    let setVariableValue: (EnvironmentView, String, String) -> Void
    let bindVariable: (EnvironmentView, String, String, String) -> Void
    let removeVariable: (EnvironmentView, String) -> Void
    /// Renaming: only a shared vault's environments offer it from this pane (the personal
    /// editor's name is fixed once created, unchanged from before this type existed). `nil` hides
    /// the affordance entirely.
    let rename: ((EnvironmentView, String) -> Void)?
    /// Items "Add a variable" may bind a new variable to, alongside a literal value. `nil` keeps
    /// the personal editor's original, literal-only Add UI exactly as it was; a shared vault's
    /// editor supplies its own items here (ui-spec.md §16.6).
    let bindableItems: [EnvironmentBindableItem]?
}

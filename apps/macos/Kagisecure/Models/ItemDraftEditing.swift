import Foundation
import KagisecureFFI

/// One field row in the edit sheet (`ItemEditView`), paired with a UI-only stable identity.
///
/// `FieldDraft.id` cannot serve as `ForEach`'s identity: it is `nil` for a field the vault has not
/// minted one for yet, which is exactly the "two rows are indistinguishable" problem
/// `ItemDraft.removingField(at:)` above already documents for *deletion*. The same problem shows
/// up a second time, one layer up, for SwiftUI's own view identity — and there it is worse than a
/// wrong deletion, because it is silent. `ForEach` used to be keyed by array *index*
/// (`Array(draft.fields.indices), id: \.self`): deleting row 1 shifts row 2's *content* up to
/// index 1, but SwiftUI had no way to know that — it saw "the view at index 1" as unchanged and
/// "the view at index 2" as removed, so row 2's own `FieldEditRow` (a sheet left open, "Change"
/// pressed on a masked concealed field) kept the *previous* row 2's on-screen state rather than
/// following row 2's *content* to its new position. `uiId`, generated once when a row is created
/// and carried along by every operation that changes the array's shape, is what lets `ForEach`
/// key on the row itself instead of on wherever it currently sits.
struct EditableField: Identifiable, Equatable {
    let uiId: UUID
    var draft: FieldDraft

    var id: UUID { uiId }

    init(uiId: UUID = UUID(), draft: FieldDraft) {
        self.uiId = uiId
        self.draft = draft
    }
}

extension Array where Element == EditableField {
    /// The row at `index` removed, and nothing else — the same contract as
    /// `ItemDraft.removingField(at:)` below, applied to this wrapper array instead of a bare
    /// `[FieldDraft]`. Deletion still goes by *position*: `uiId` exists to give `ForEach` and each
    /// row's own `@State` something stable to track, not to change what "delete the row the user
    /// is pointing at" means, which was already solved correctly by position (see that function's
    /// own doc for why identity — `FieldDraft.id` there, `uiId` here — is the wrong key for a
    /// delete two otherwise-identical new rows can both trigger).
    ///
    /// Out of range is a no-op, matching `ItemDraft.removingField(at:)`: a caller that resolves
    /// `index` from a captured `uiId` immediately before calling this should never see one, but a
    /// stale index must not crash rather than simply doing nothing.
    func removingField(at index: Int) -> [EditableField] {
        guard indices.contains(index) else { return self }
        var edited = self
        edited.remove(at: index)
        return edited
    }
}

extension ItemDraft {
    /// The draft with the field at `index` removed, and nothing else.
    ///
    /// # Why by position
    ///
    /// The edit form used to delete with a predicate — `removeAll { $0.id == field.id && $0.label
    /// == field.label }` — and that is wrong for exactly the rows a user is most likely to delete.
    /// A field that has never been saved has **no id** (`FieldDraft.id` is `nil` until the vault
    /// mints one) and starts life labelled "New field", so two freshly added rows match each other
    /// on both halves of that predicate. Adding two fields and pressing the minus on one of them
    /// deleted both, silently, with no undo — the draft is local state and Cancel is the only way
    /// back, so the user's other new field was simply gone.
    ///
    /// Position is the only thing that distinguishes two otherwise identical draft rows, and it is
    /// what the user is pointing at when they press the button next to one.
    ///
    /// Out of range is a no-op rather than a crash: the caller is a SwiftUI closure capturing an
    /// index, and a closure that outlives its row by one frame must not take the app down.
    func removingField(at index: Int) -> ItemDraft {
        guard fields.indices.contains(index) else { return self }
        var edited = self
        edited.fields.remove(at: index)
        return edited
    }
}

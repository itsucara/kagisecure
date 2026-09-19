import KagisecureFFI

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

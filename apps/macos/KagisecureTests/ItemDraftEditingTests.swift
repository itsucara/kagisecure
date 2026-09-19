import Testing

@testable import Kagisecure

import KagisecureFFI

/// Deleting one field from a draft deletes one field.
///
/// This exists because it did not. The edit form removed a row with
/// `removeAll { $0.id == field.id && $0.label == field.label }`, and a field that has never been
/// saved has `id == nil` and the default label `"New field"` — so two freshly added rows satisfied
/// both halves of that predicate for each other. Adding two fields and pressing the minus on one
/// removed both, with no undo: a draft is local state and Cancel is the only way back, so the row
/// the user meant to keep was gone along with the one they meant to lose.
struct ItemDraftEditingTests {
    private static func draft(fields: [FieldDraft]) -> ItemDraft {
        ItemDraft(
            id: "item-1",
            category: "login",
            title: "Example",
            fields: fields,
            tags: [],
            urls: [],
            notes: nil)
    }

    private static func newField(label: String = "New field") -> FieldDraft {
        FieldDraft(
            id: nil, label: label, kind: .text, concealed: false, value: "", section: nil,
            agentVisible: false)
    }

    @Test func removingOneOfTwoIdenticalNewFieldsLeavesTheOther() {
        let draft = Self.draft(fields: [Self.newField(), Self.newField()])
        let edited = draft.removingField(at: 0)
        // Two unsaved fields are indistinguishable by id and label; deleting one must still
        // delete one.
        #expect(edited.fields.count == 1)
    }

    @Test func removingKeepsTheFieldsEitherSideOfIt() {
        let draft = Self.draft(
            fields: [
                Self.newField(label: "first"), Self.newField(label: "middle"),
                Self.newField(label: "last"),
            ])
        let edited = draft.removingField(at: 1)
        #expect(edited.fields.map(\.label) == ["first", "last"])
    }

    @Test func removingASavedFieldLeavesTheDraftsAlone() {
        let saved = FieldDraft(
            id: "field-1", label: "password", kind: .concealed, concealed: true, value: "secret",
            section: nil, agentVisible: false)
        let draft = Self.draft(fields: [saved, Self.newField(), Self.newField()])
        let edited = draft.removingField(at: 0)
        #expect(edited.fields.count == 2)
        #expect(edited.fields.allSatisfy { $0.id == nil })
    }

    @Test func anIndexPastTheEndChangesNothing() {
        // A SwiftUI closure captures the index its row had when the body was built, and can outlive
        // that row by a frame. Crashing there would be the worst possible outcome of a delete.
        let draft = Self.draft(fields: [Self.newField()])
        #expect(draft.removingField(at: 7).fields.count == 1)
        #expect(draft.removingField(at: -1).fields.count == 1)
    }
}

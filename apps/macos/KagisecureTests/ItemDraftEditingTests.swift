import Foundation
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
            notes: nil,
            revision: "test-revision")
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
        // that row by a frame. Crashing there must not take the app down.
        let draft = Self.draft(fields: [Self.newField()])
        #expect(draft.removingField(at: 7).fields.count == 1)
        #expect(draft.removingField(at: -1).fields.count == 1)
    }
}

/// `EditableField`, `ItemEditView`'s per-row wrapper: a stable `uiId` alongside each `FieldDraft`,
/// because `FieldDraft.id` cannot serve as `ForEach`'s view identity any more than it could serve
/// `removingField(at:)`'s deletion above — it is `nil` for a field the vault has not minted one
/// for yet, so two new rows are indistinguishable by it.
///
/// This exists because `ForEach` used to be keyed by array *index*
/// (`Array(draft.fields.indices), id: \.self`). Deleting row 1 shifts row 2's *content* up to
/// index 1, but SwiftUI has no way to know that from the index alone — it sees "the view at index
/// 1" as unchanged, so row 2's own `@State` inside `FieldEditRow` (a sheet left open, "Change"
/// pressed on a masked concealed field so it is showing a text field instead of a mask) stayed
/// behind at the old index rather than following row 2's content to its new position. Two rows
/// down, the wrong row's view could end up wearing the state that belonged to a row that no longer
/// exists. Keying by `uiId` instead — generated once when a row is created, carried along by every
/// add and delete — is what lets `ForEach` (and the `@State` inside each row it produces) track
/// content instead of position.
@MainActor
struct EditableFieldTests {
    /// Three rows, deliberately built as three *separate* calls rather than `Array(repeating:)`,
    /// the same way three real "+ Add field" presses would produce them: content-identical,
    /// `uiId`-distinct.
    private static func newRows(count: Int, label: String = "New field") -> [EditableField] {
        (0..<count).map { _ in
            EditableField(
                draft: FieldDraft(
                    id: nil, label: label, kind: .text, concealed: false, value: "", section: nil,
                    agentVisible: false))
        }
    }

    @Test func twoContentIdenticalNewRowsStillGetDistinctIds() {
        // The whole reason `uiId` exists rather than deriving an identity from the field's own
        // content: two rows a person cannot tell apart by content must still be two different rows
        // as far as `ForEach` is concerned.
        let rows = Self.newRows(count: 2)
        #expect(rows[0].draft == rows[1].draft, "the rows are content-identical, by construction")
        #expect(rows[0].uiId != rows[1].uiId, "but never share an identity")
    }

    /// Deleting the middle row of three leaves the other two rows' `uiId`s exactly as they were —
    /// each still paired with its own original content, not shifted onto a neighbor. This is the
    /// data-level guarantee `ForEach($fieldRows)` relies on to keep each row's on-screen `@State`
    /// attached to the row it actually belongs to across a deletion.
    @Test func removingARowLeavesEveryOtherRowsIdentityAndContentPairedCorrectly() {
        var rows = Self.newRows(count: 1, label: "first")
        rows += Self.newRows(count: 1, label: "middle")
        rows += Self.newRows(count: 1, label: "last")
        let (firstId, middleId, lastId) = (rows[0].uiId, rows[1].uiId, rows[2].uiId)

        let edited = rows.removingField(at: 1)

        #expect(edited.map(\.draft.label) == ["first", "last"])
        #expect(edited.map(\.uiId) == [firstId, lastId], "the surviving rows keep their own ids")
        #expect(!edited.map(\.uiId).contains(middleId), "the deleted row's id is gone, not reused")
    }

    /// The scenario this whole type exists to prevent, stated as directly as the wrapper array
    /// allows: a field the user is actively "entering a new value" into (modeled here as any
    /// distinguishing content on that row, since the real `enteringNewValue` flag lives inside
    /// `FieldEditRow`'s own `@State`, not in `FieldDraft`) must not have its row's identity
    /// reassigned to a different field merely because an unrelated row before it was deleted.
    @Test func aRowsIdentityDoesNotMigrateToADifferentFieldAfterAnEarlierDeletion() {
        let untouched = EditableField(
            draft: FieldDraft(
                id: "kept-field", label: "password", kind: .concealed, concealed: true,
                value: nil, section: nil, agentVisible: false))
        var rows = [
            EditableField(
                draft: FieldDraft(
                    id: nil, label: "doomed", kind: .text, concealed: false, value: "",
                    section: nil, agentVisible: false)),
            untouched,
        ]
        let untouchedId = untouched.uiId

        rows = rows.removingField(at: 0)

        #expect(rows.count == 1)
        #expect(rows[0].uiId == untouchedId, "the untouched field's row identity is unchanged")
        #expect(
            rows[0].draft.value == nil,
            "and its draft is exactly what it was — nothing rode in on the deletion")
    }

    @Test func anIndexPastTheEndChangesNothing() {
        let rows = Self.newRows(count: 1)
        #expect(rows.removingField(at: 7).count == 1)
        #expect(rows.removingField(at: -1).count == 1)
    }

    /// End to end, through a real vault: the exact shape of edit session `EditableField` exists
    /// for — adding a throwaway field ahead of a concealed one, then deleting it again — must
    /// leave the concealed field's draft `nil` (untouched) all the way to `save`, and the stored
    /// secret unchanged afterwards. Before the identity fix, the deletion above could leave the
    /// *view* backing the password row wearing state that belonged to the deleted row; this test
    /// instead asserts the data-level guarantee that view correctness is built on, and that the
    /// save this produces never turns the kept secret into `""`.
    @Test func deletingAnUnrelatedRowNeverTurnsAKeptConcealedFieldIntoAnEmptySave() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-editablefield-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("test.kagivault")
        let session = try VaultSession.create(
            path: path.path, masterPassword: "correct horse battery staple",
            vaultName: "Personal", kdfMKib: 64, kdfT: 1)
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let created = try #require(store.selectedItem)
        let passwordField = try #require(created.fields.first { $0.kind == .concealed })

        // Give the password a real value first, the same way a first setup would.
        try store.save(
            draft: ItemDraft(
                id: created.id, category: created.category, title: created.title,
                fields: created.fields.map { f in
                    FieldDraft(
                        id: f.id, label: f.label, kind: f.kind, concealed: f.concealed,
                        value: f.id == passwordField.id ? "s3cr3t-value" : nil,
                        section: f.section, agentVisible: f.agentVisible)
                },
                tags: [], urls: [], notes: nil, revision: created.revision))

        // The edit sheet's own view of the item: concealed fields never prefilled, exactly as
        // `ItemDetailView.beginEditing` builds it.
        let toEdit = try #require(store.selectedItem)
        var rows = toEdit.fields.map { f in
            EditableField(
                draft: FieldDraft(
                    id: f.id, label: f.label, kind: f.kind, concealed: f.concealed,
                    value: f.concealed ? nil : f.value, section: f.section,
                    agentVisible: f.agentVisible))
        }

        // A field added, then immediately deleted, ahead of the password row — the shape
        // `ItemEditView.addField`/`removeField(withId:)` produces.
        rows.insert(
            EditableField(
                draft: FieldDraft(
                    id: nil, label: "New field", kind: .text, concealed: false, value: "",
                    section: nil, agentVisible: false)),
            at: 0)
        rows = rows.removingField(at: 0)

        let passwordRow = try #require(rows.first { $0.draft.id == passwordField.id })
        #expect(
            passwordRow.draft.value == nil,
            "the untouched concealed field's draft must still be nil after an unrelated row was added and removed"
        )

        try store.save(
            draft: ItemDraft(
                id: toEdit.id, category: toEdit.category, title: toEdit.title,
                fields: rows.map(\.draft), tags: toEdit.tags, urls: toEdit.urls,
                notes: nil, revision: toEdit.revision))

        #expect(
            try await releasedValue(session, itemId: created.id, fieldId: passwordField.id)
                == "s3cr3t-value",
            "the stored secret must survive byte for byte, never having passed through \"\"")
    }
}

/// ADR-0038 user decision 5 in edit mode: a value shown to edit — a field, the notes, a one-time
/// password's setup — is masked again at five minutes if it is still exactly what "Show" put there,
/// and kept if the person has edited it.
struct EditRevealTests {
    @Test func theCapIsFiveMinutes() {
        #expect(EditReveal.lifetime == .seconds(300))
    }

    @Test func anUntouchedShownValueIsMaskedAgainAndAnEditedOneIsKept() {
        #expect(EditReveal.shouldRemask(shown: "recovery codes", current: "recovery codes"))
        #expect(!EditReveal.shouldRemask(shown: "recovery codes", current: "recovery codes!"))
        #expect(!EditReveal.shouldRemask(shown: "otpauth://totp/x", current: ""))
        #expect(!EditReveal.shouldRemask(shown: nil, current: "never shown"))
        #expect(!EditReveal.shouldRemask(shown: "notes", current: nil))
    }
}

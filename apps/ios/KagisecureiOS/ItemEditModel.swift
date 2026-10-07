import Foundation
import KagisecureFFI

/// One row of the edit sheet. Concealed fields are never prefilled (ADR-0038 step 3): an empty
/// `newValue` keeps the stored secret.
struct EditableField: Identifiable, Equatable {
    let id = UUID()
    var fieldId: String?
    var label: String
    var kind: FieldKind
    var concealed: Bool
    var section: String?
    var agentVisible: Bool
    /// Public fields: the current value. Concealed fields: a replacement, empty = keep.
    var newValue: String
    var hasStoredValue: Bool
}

/// The add/edit sheet's state, built from an `ItemView` and turned back into an `ItemDraft`.
struct ItemEditModel: Equatable {
    let itemId: String
    let category: String
    let revision: String
    var title: String
    var fields: [EditableField]
    var tags: String
    var urls: String
    var hasStoredNotes: Bool
    /// Empty = keep the stored note.
    var newNotes: String
    /// Remove the stored note on save (the FFI's `notes: Some("")`).
    private(set) var removeNotes = false

    /// Switching "Remove Note" on would throw away a note typed in this edit: ask first.
    var removeNotesNeedsConfirmation: Bool { !removeNotes && !newNotes.isEmpty }

    /// Turn "Remove Note" on or off. Turning it on clears the note typed in this edit, so what is
    /// saved is exactly what the sheet shows (the editor is replaced by "will be removed").
    mutating func setRemoveNotes(_ on: Bool) {
        removeNotes = on
        if on { newNotes = "" }
    }

    init(item: ItemView) {
        itemId = item.id
        category = item.category
        revision = item.revision
        title = item.title
        fields = item.fields.map {
            EditableField(
                fieldId: $0.id, label: $0.label, kind: $0.kind, concealed: $0.concealed,
                section: $0.section, agentVisible: $0.agentVisible,
                newValue: $0.concealed ? "" : ($0.value ?? ""), hasStoredValue: $0.hasValue)
        }
        tags = item.tags.joined(separator: ", ")
        urls = item.urls.joined(separator: "\n")
        hasStoredNotes = item.hasNotes
        newNotes = ""
    }

    mutating func addField(concealed: Bool) {
        fields.append(
            EditableField(
                fieldId: nil, label: concealed ? "password" : "text",
                kind: concealed ? .concealed : .text, concealed: concealed, section: nil,
                agentVisible: false, newValue: "", hasStoredValue: false))
    }

    /// A one-time-password field, labelled and concealed as the Mac's editor makes it.
    mutating func addTotpField() {
        fields.append(
            EditableField(
                fieldId: nil, label: "one-time password", kind: .totp, concealed: true,
                section: nil, agentVisible: false, newValue: "", hasStoredValue: false))
    }

    var hasTotpField: Bool { fields.contains { $0.kind == .totp } }

    /// Put a scanned QR code into the one-time-password field (adding the field if there is
    /// none). Throws `TotpScanError` for anything but a usable `otpauth://` URI; the field is
    /// left untouched then.
    mutating func applyScannedTotp(_ payload: String) throws {
        let uri = try Self.scannedTotpURI(payload)
        if !hasTotpField { addTotpField() }
        guard let index = fields.firstIndex(where: { $0.kind == .totp }) else { return }
        fields[index].newValue = uri
    }

    /// The `otpauth://` URI a QR code carries. Google Authenticator's export
    /// (`otpauth-migration://`) packs several accounts in a format we do not read: say so rather
    /// than fail quietly.
    nonisolated static func scannedTotpURI(_ payload: String) throws -> String {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if lower.hasPrefix("otpauth-migration:") { throw TotpScanError.migrationExport }
        guard lower.hasPrefix("otpauth://"), totpUriIsValid(uri: trimmed) else {
            throw TotpScanError.notOneTimePassword
        }
        return trimmed
    }

    /// The draft to save, with every typed one-time-password setup turned into the
    /// `otpauth://` URI the vault stores. Throws `FfiError.Invalid` for a setup that is neither a
    /// usable URI nor a Base32 secret.
    func validatedDraft() throws -> ItemDraft {
        var draft = self.draft
        for index in draft.fields.indices where draft.fields[index].kind == .totp {
            guard let value = draft.fields[index].value, !value.isEmpty else { continue }
            draft.fields[index].value = try Self.totpURI(from: value, issuer: title)
        }
        return draft
    }

    /// An `otpauth://` URI as pasted, or a hand-typed Base32 secret (spaces and case ignored)
    /// with the usual SHA-1 / 6 digits / 30 seconds, named after the item.
    nonisolated static func totpURI(from input: String, issuer: String) throws -> String {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") {
            guard totpUriIsValid(uri: trimmed) else {
                throw FfiError.Invalid(message: "not a usable otpauth:// URI")
            }
            return trimmed
        }
        let secret = trimmed.filter { !$0.isWhitespace && $0 != "-" }.uppercased()
        let name = issuer.trimmingCharacters(in: .whitespaces)
        return try totpUriFromParts(
            secretBase32: secret,
            params: TotpParamsView(
                algorithm: .sha1, digits: 6, period: 30, issuer: name.isEmpty ? nil : name,
                account: nil, caption: nil))
    }

    var draft: ItemDraft {
        ItemDraft(
            id: itemId, category: category, title: title,
            // A one-time-password field that was added but never filled in is not saved.
            fields: fields.filter { !($0.kind == .totp && $0.fieldId == nil && $0.newValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) }
            .map { field in
                let value: String?
                if field.concealed && field.fieldId != nil && field.newValue.isEmpty {
                    value = nil  // keep the stored secret
                } else {
                    value = field.newValue
                }
                return FieldDraft(
                    id: field.fieldId, label: field.label, kind: field.kind,
                    concealed: field.concealed, value: value, section: field.section,
                    agentVisible: field.agentVisible)
            },
            tags: tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty },
            urls: urls.split(whereSeparator: \.isNewline).map {
                $0.trimmingCharacters(in: .whitespaces)
            }.filter { !$0.isEmpty },
            notes: removeNotes ? "" : (newNotes.isEmpty ? nil : newNotes),
            revision: revision)
    }

    static func generatedPassword() -> String {
        (try? generatePassword(
            recipe: GeneratorRecipe(
                mode: .characters, length: 20, lowercase: true, uppercase: true, digits: true,
                symbols: true, avoidAmbiguous: false, words: 4, separator: .hyphen,
                capitalize: false, includeDigit: false))) ?? ""
    }
}

/// Why a scanned QR code could not become a one-time password.
enum TotpScanError: Error, Equatable, LocalizedError {
    /// Google Authenticator's "Transfer accounts" export.
    case migrationExport
    /// Anything that is not a usable `otpauth://` URI.
    case notOneTimePassword

    var errorDescription: String? {
        switch self {
        case .migrationExport:
            String(localized: "This format (a Google Authenticator export) cannot be read. Scan the QR code the website shows instead.")
        case .notOneTimePassword:
            String(localized: "This QR code is not a one-time password setup.")
        }
    }
}

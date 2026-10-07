import KagisecureFFI
import SwiftUI

struct ItemEditSheet: View {
    let store: VaultStore
    @State var model: ItemEditModel
    let done: () -> Void
    @State private var message: String?
    @State private var stale = false
    @State private var scanning = false
    @State private var confirmingRemoveNotes = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $model.title).accessibilityIdentifier("edit.title")
                }
                Section("Fields") {
                    ForEach($model.fields) { $field in
                        VStack(alignment: .leading) {
                            TextField("Label", text: $field.label).font(.caption)
                            if field.kind == .totp {
                                SecureField(
                                    field.hasStoredValue ? "Unchanged" : "otpauth:// URI or Base32 secret",
                                    text: $field.newValue
                                )
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .accessibilityIdentifier("edit.totp")
                                if QRScannerView.canScan {
                                    Button {
                                        scanning = true
                                    } label: {
                                        Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                                    }
                                    .buttonStyle(.borderless)
                                    .accessibilityIdentifier("edit.totp.scan")
                                }
                            } else if field.concealed {
                                HStack {
                                    SecureField(
                                        field.hasStoredValue ? "Unchanged" : "Value",
                                        text: $field.newValue
                                    )
                                    .accessibilityIdentifier("edit.field.\(field.label)")
                                    Button {
                                        field.newValue = ItemEditModel.generatedPassword()
                                    } label: { Image(systemName: "wand.and.stars") }
                                        .buttonStyle(.borderless)
                                        .accessibilityLabel("Generate password")
                                }
                            } else {
                                TextField("Value", text: $field.newValue)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                                    .accessibilityIdentifier("edit.field.\(field.label)")
                            }
                        }
                    }
                    .onDelete { model.fields.remove(atOffsets: $0) }
                    Menu("Add Field") {
                        Button("Text") { model.addField(concealed: false) }
                        Button("Password") { model.addField(concealed: true) }
                        Button("One-Time Password") { model.addTotpField() }
                            .disabled(model.hasTotpField)
                    }
                }
                Section("Websites (one per line)") {
                    TextField("https://example.com", text: $model.urls, axis: .vertical)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("edit.urls")
                }
                Section("Tags (comma separated)") {
                    TextField("Tags", text: $model.tags).textInputAutocapitalization(.never)
                }
                Section {
                    if model.removeNotes {
                        Text("The note will be removed when you save.").foregroundStyle(.secondary)
                    } else {
                        TextField("Notes", text: $model.newNotes, axis: .vertical)
                            .accessibilityIdentifier("edit.notes")
                    }
                    if model.hasStoredNotes {
                        Toggle("Remove Note", isOn: Binding(
                            get: { model.removeNotes },
                            set: { on in
                                if on && model.removeNotesNeedsConfirmation {
                                    confirmingRemoveNotes = true
                                } else {
                                    model.setRemoveNotes(on)
                                }
                            }))
                            .accessibilityIdentifier("edit.removeNotes")
                    }
                } header: {
                    Text(model.hasStoredNotes ? "Notes (leave empty to keep)" : "Notes")
                }
            }
            .navigationTitle("Edit")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel", action: done) }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save).accessibilityIdentifier("edit.save")
                }
            }
            .confirmationDialog(
                "Discard the note you typed?", isPresented: $confirmingRemoveNotes, titleVisibility: .visible
            ) {
                Button("Discard and Remove Note", role: .destructive) { model.setRemoveNotes(true) }
                    .accessibilityIdentifier("edit.confirmRemoveNotes")
            } message: {
                Text("Removing the note also discards what you typed here.")
            }
            .alert("Changed elsewhere – reload", isPresented: $stale) {
                Button("Reload") {
                    if let fresh = store.item(id: model.itemId) {
                        model = ItemEditModel(item: fresh)
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This item was saved somewhere else after you started editing. Reload it and make your edit again.")
            }
            .alert("Error", isPresented: .constant(message != nil)) {
                Button("OK") { message = nil }
            } message: { Text(message ?? "") }
        }
        .sheet(isPresented: $scanning) {
            NavigationStack {
                QRScannerView { payload in
                    scanning = false
                    do {
                        try model.applyScannedTotp(payload)
                    } catch {
                        message = error.localizedDescription
                    }
                }
                .ignoresSafeArea()
                .navigationTitle("Scan QR Code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { scanning = false }
                    }
                }
            }
        }
        .interactiveDismissDisabled()
    }

    private func save() {
        do {
            try store.save(model.validatedDraft())
            done()
        } catch FfiError.ItemChangedElsewhere {
            stale = true
        } catch FfiError.Invalid where model.hasTotpField {
            message = String(localized: "The one-time password setup is neither a usable otpauth:// URI nor a Base32 secret.")
        } catch {
            message = AppModel.message(for: error)
        }
    }
}

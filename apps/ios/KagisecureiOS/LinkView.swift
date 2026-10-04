import KagisecureFFI
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// "Link with Mac" (ui-spec §16.3 for iPhone): choose the shared vault's folder in iCloud Drive,
/// join with the invitation the Mac saved there and its six words, then see the sync status.
///
/// The Mac makes the invitation (its members pane → your row → Invite Another Computer…, saved
/// into the vault's folder). The device key is generated on the Mac (ADR-0035 decision 86), so
/// the iPhone has no fingerprint before it joins; once joined it shows its fingerprint, to
/// compare with the one the Mac's members pane lists.
struct LinkView: View {
    @Bindable var link: LinkModel
    @State private var picking = false
    @State private var importing = false
    @State private var invitation: URL?
    @State private var words = ""
    @State private var joining = false
    @State private var joinProblem: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Folder", value: link.folderName ?? String(localized: "Not chosen"))
                    .accessibilityIdentifier("link.folder")
                Button(link.folderName == nil ? "Choose Folder in iCloud Drive…" : "Change Folder…") {
                    picking = true
                }
                .accessibilityIdentifier("link.chooseFolder")
            } header: {
                Text("1. Shared vault folder")
            } footer: {
                Text("Choose the folder your Mac's shared vault syncs through (its members pane shows it).")
            }

            if !link.isLinked {
                joinSection
            } else {
                statusSection
            }
        }
        .navigationTitle("Link with Mac")
        .sheet(isPresented: $picking) {
            FolderPicker { url in
                picking = false
                if let url { Task { await link.choose(folder: url) } }
            }
            .ignoresSafeArea()
        }
        .fileImporter(
            isPresented: $importing,
            allowedContentTypes: [UTType(filenameExtension: ExchangeMirror.invitationExtension) ?? .data]
        ) { result in
            if case .success(let url) = result { invitation = importInvitation(url) }
        }
        .task { await link.sync() }
    }

    private var joinSection: some View {
        Section {
            if link.invitations.isEmpty {
                Text("No invitation in the folder yet. On the Mac: the shared vault's Members → your row's ⋯ → Invite Another Computer…, and save it in the folder.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button("Check Again") { Task { await link.sync() } }
                    .disabled(link.syncing)
            } else {
                Picker("Invitation", selection: $invitation) {
                    Text("Choose…").tag(URL?.none)
                    ForEach(link.invitations, id: \.self) { url in
                        Text(url.deletingPathExtension().lastPathComponent).tag(Optional(url))
                    }
                }
                .accessibilityIdentifier("link.invitation")
            }
            Button("Open Invitation from Files or AirDrop…") { importing = true }
            TextField("The six words", text: $words)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .font(.system(.body, design: .monospaced))
                .accessibilityIdentifier("link.words")
            if let joinProblem {
                Text(joinProblem).foregroundStyle(.red).font(.footnote)
            }
            Button {
                Task { await join() }
            } label: {
                if joining { ProgressView() } else { Text("Join") }
            }
            .disabled(invitation == nil || words.trimmingCharacters(in: .whitespaces).isEmpty || joining)
            .accessibilityIdentifier("link.join")
        } header: {
            Text("2. Join")
        } footer: {
            Text("The Mac shows six words with the invitation. Type them here; they are never saved.")
        }
        .onAppear { if invitation == nil { invitation = link.invitations.last } }
    }

    private var statusSection: some View {
        Group {
            Section("Shared vaults") {
                ForEach(link.summaries, id: \.id) { summary in
                    LabeledContent(summary.name, value: String(localized: "\(summary.itemCount) items · \(summary.memberCount) members"))
                }
            }
            Section {
                ForEach(link.myFingerprints(), id: \.self) { fingerprint in
                    Text(fingerprint).font(.system(.footnote, design: .monospaced))
                        .accessibilityIdentifier("link.fingerprint")
                }
            } header: {
                Text("This iPhone's fingerprint")
            } footer: {
                Text("The Mac's members pane lists the same digits for this iPhone.")
            }
            Section("Sync") {
                LabeledContent("Status", value: statusLine).accessibilityIdentifier("link.status")
                if let report = link.lastReport, report.pending > 0 {
                    Text("Waiting for iCloud to download \(report.pending) file(s).")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if let problem = link.problem {
                    Text(problem).foregroundStyle(.red).font(.footnote)
                }
                Button("Sync Now") { Task { await link.sync() } }
                    .disabled(link.syncing)
                    .accessibilityIdentifier("link.syncNow")
            }
        }
    }

    private var statusLine: String {
        if link.syncing { return String(localized: "Syncing…") }
        guard let date = link.lastSynced else { return String(localized: "Not synced yet") }
        return String(localized: "Synced \(date.formatted(.relative(presentation: .named)))")
    }

    private func join() async {
        guard let invitation else { return }
        joining = true
        defer { joining = false }
        do {
            try await link.join(invitation: invitation, words: words)
            words = ""
            joinProblem = nil
        } catch FfiError.WrongCredential {
            joinProblem = String(localized: "Those words do not open this invitation.")
        } catch {
            joinProblem = AppModel.message(for: error)
        }
    }

    /// An invitation from Files or AirDrop: copied into the mirror so Rust reads a local file.
    private func importInvitation(_ url: URL) -> URL? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { return nil }
        let dir = link.folders.mirrorDirectory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let destination = dir.appendingPathComponent(url.lastPathComponent)
        try? ExchangeMirror.writeNew(data, to: destination, replacing: true)
        link.reload()
        return destination
    }
}

/// The system folder picker; hands back a security-scoped folder URL, or `nil` if cancelled.
struct FolderPicker: UIViewControllerRepresentable {
    let picked: (URL?) -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder])
        picker.allowsMultipleSelection = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(picked: picked) }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let picked: (URL?) -> Void
        init(picked: @escaping (URL?) -> Void) { self.picked = picked }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            picked(urls.first)
        }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { picked(nil) }
    }
}

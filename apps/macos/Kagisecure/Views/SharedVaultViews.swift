import AppKit
import SwiftUI

import KagisecureFFI

// MARK: - Sheets

/// The shared-vault sheet on screen, if any (ui-spec.md §16). Presented by `MainView`, which
/// outlives the sidebar's rebuilds.
enum SharedSheet: Identifiable, Hashable {
    /// "New Shared Vault…": a name and, optionally, a folder.
    case create
    /// "Join Shared Vault…": an invitation file, its passphrase and a folder.
    case join
    /// "Invite…": a name and a role, then the file and the passphrase.
    case invite(vaultId: String)
    /// "Invite Another Computer…" for an existing member.
    case inviteDevice(vaultId: String, memberId: String, name: String)

    var id: Self { self }
}

/// The body of whichever `SharedSheet` is up.
struct SharedSheetView: View {
    @Bindable var store: VaultStore
    let sheet: SharedSheet

    var body: some View {
        switch sheet {
        case .create:
            CreateSharedVaultSheet(store: store)
        case .join:
            JoinSharedVaultSheet(store: store)
        case .invite(let vaultId):
            InviteSheet(store: store, vaultId: vaultId, existingMember: nil)
        case .inviteDevice(let vaultId, let memberId, let name):
            InviteSheet(store: store, vaultId: vaultId, existingMember: (memberId, name))
        }
    }
}

/// The open and save panels the sheets use. Nothing here reads or writes a file itself.
@MainActor
enum SharedPanels {
    /// A folder the members share — in iCloud Drive or Dropbox, say.
    static func chooseFolder(message: String, starting: URL? = nil) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = String(localized: "Use Folder")
        panel.message = message
        panel.directoryURL = starting
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// An invitation file someone sent.
    static func chooseInvitation() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.prompt = String(localized: "Choose")
        panel.message = String(localized: "Choose the invitation file you were sent.")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Where to save a new invitation: by default the vault's folder, so a member who shares it
    /// finds the file there.
    static func saveInvitation(named name: String, in folder: URL?) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(name).\(invitationExtension)"
        panel.directoryURL = folder
        panel.canCreateDirectories = true
        panel.prompt = String(localized: "Save Invitation")
        panel.message = String(localized: "Save the invitation where the person you invite can open it.")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// An invitation file's extension. Informational: joining reads the file's own magic.
    static let invitationExtension = "kagisecure-invite"

    /// The folder to sync through when joining with `invitation`: the invitation's own folder,
    /// if that folder already holds a shared vault's records — which is where an admin saving it
    /// into the shared folder leaves it.
    static func folder(besides invitation: URL) -> URL? {
        let folder = invitation.deletingLastPathComponent()
        var isDirectory: ObjCBool = false
        let records = folder.appendingPathComponent("records").path
        guard FileManager.default.fileExists(atPath: records, isDirectory: &isDirectory),
            isDirectory.boolValue
        else { return nil }
        return folder
    }
}

/// "New Shared Vault…" (ui-spec.md §16.2): a name and a folder. Two fields, one button.
struct CreateSharedVaultSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: VaultStore
    @State private var name = ""
    @State private var folder: URL?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New Shared Vault")
                .font(.title2.weight(.semibold))
            Text(
                "Items in a shared vault sync to everyone you invite, through a folder you all can open — in iCloud Drive or Dropbox, for example."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Form {
                TextField("Name", text: $name, prompt: Text("Team"))
                    .accessibilityIdentifier("ks.shared.create.name")
                LabeledContent("Folder") {
                    FolderChoice(folder: folder) {
                        folder = SharedPanels.chooseFolder(
                            message: String(localized: "Choose or create an empty folder everyone you invite can open, in iCloud Drive or Dropbox."))
                            ?? folder
                    }
                }
            }
            if folder == nil {
                Text("Without a folder the vault stays on this Mac until you choose one.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ErrorText(error)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create") { create() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("ks.shared.create.confirm")
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    private func create() {
        do {
            let id = try store.shared.create(name: name, folder: folder)
            dismiss()
            store.selection = .sharedVault(id)
        } catch {
            self.error = describeAnyError(error)
        }
    }
}

/// "Join Shared Vault…" (ui-spec.md §16.3): the invitation file, the words that came with it,
/// and — usually already filled in — the folder.
struct JoinSharedVaultSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: VaultStore
    @State private var invitation: URL?
    @State private var passphrase = ""
    @State private var folder: URL?
    @State private var error: String?
    @State private var joining = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Join a Shared Vault")
                .font(.title2.weight(.semibold))
            Text(
                "Open the invitation file you were sent, and type the six words the person who invited you told you."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Form {
                LabeledContent("Invitation") {
                    HStack {
                        Text(invitation?.lastPathComponent ?? String(localized: "None chosen"))
                            .foregroundStyle(invitation == nil ? .secondary : .primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button("Choose…") { chooseInvitation() }
                            .accessibilityIdentifier("ks.shared.join.chooseFile")
                    }
                }
                TextField("Words", text: $passphrase, prompt: Text("six words"))
                    .font(.body.monospaced())
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("ks.shared.join.passphrase")
                LabeledContent("Folder") {
                    FolderChoice(folder: folder) {
                        folder = SharedPanels.chooseFolder(
                            message: String(localized: "Choose the folder the vault is shared through."),
                            starting: invitation?.deletingLastPathComponent())
                            ?? folder
                    }
                }
            }
            ErrorText(error)
            HStack {
                if joining { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Join") { join() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        invitation == nil || joining
                            || passphrase.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("ks.shared.join.confirm")
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    private func chooseInvitation() {
        guard let url = SharedPanels.chooseInvitation() else { return }
        invitation = url
        if folder == nil { folder = SharedPanels.folder(besides: url) }
    }

    private func join() {
        guard let invitation else { return }
        joining = true
        error = nil
        Task { @MainActor in
            defer { joining = false }
            do {
                let id = try await store.shared.join(
                    invitation: invitation, passphrase: passphrase, folder: folder)
                passphrase = ""
                dismiss()
                store.selection = .sharedVault(id)
            } catch FfiError.WrongCredential {
                error = String(localized: "Those words do not open this invitation. Check them with the person who invited you.")
            } catch {
                self.error = describeAnyError(error)
            }
        }
    }
}

/// "Invite…" (ui-spec.md §16.4): a name and a role, then a file to save and six words to say.
/// The words are shown here once and never again.
struct InviteSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: VaultStore
    let vaultId: String
    /// Set for "Invite Another Computer…": the member, by id and name.
    let existingMember: (id: String, name: String)?

    @State private var name = ""
    @State private var role: SharedRole = .writer
    @State private var invitation: SharedInvitation?
    @State private var error: String?
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let invitation {
                done(invitation)
            } else {
                form
            }
        }
        .padding(24)
        .frame(width: 480)
        // The words leave memory with the sheet.
        .onDisappear { invitation = nil }
    }

    private var who: String {
        existingMember?.name ?? name.trimmingCharacters(in: .whitespaces)
    }

    @ViewBuilder
    private var form: some View {
        (existingMember == nil ? Text("Invite Someone") : Text("Invite Another Computer"))
            .font(.title2.weight(.semibold))
        (existingMember == nil
            ? Text("You will save an invitation file and get six words. Send the file, and tell the words another way — in person or on a call.")
            : Text("An invitation for another computer of \(existingMember?.name ?? String(localized: "this member")), with the same role."))
        .font(.callout)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
        if existingMember == nil {
            Form {
                TextField("Name", text: $name, prompt: Text("Their name"))
                    .accessibilityIdentifier("ks.shared.invite.name")
                Picker("Role", selection: $role) {
                    Text("Can view").tag(SharedRole.reader)
                    Text("Can edit").tag(SharedRole.writer)
                    Text("Admin").tag(SharedRole.admin)
                }
                .accessibilityIdentifier("ks.shared.invite.role")
            }
            Text(SharedRoleText.help(role))
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        ErrorText(error)
        HStack {
            if working { ProgressView().controlSize(.small) }
            Spacer()
            Button("Cancel", role: .cancel) { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button("Save Invitation…") { invite() }
                .keyboardShortcut(.defaultAction)
                .disabled(who.isEmpty || working)
                .accessibilityIdentifier("ks.shared.invite.save")
        }
    }

    @ViewBuilder
    private func done(_ invitation: SharedInvitation) -> some View {
        Label("Invitation saved", systemImage: "checkmark.circle.fill")
            .font(.title2.weight(.semibold))
            .foregroundStyle(.green)
        Text("Send \(who) the file, and tell them these six words another way:")
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)
        HStack {
            Text(invitation.passphrase)
                .font(.title3.monospaced())
                // Not selectable: ⌘C would put the words on the pasteboard unmarked and
                // uncleared. The Copy button goes through `PasteboardService`.
                .accessibilityIdentifier("ks.shared.invite.passphrase")
            Spacer()
            Button {
                PasteboardService.copy(invitation.passphrase, label: String(localized: "Invitation words"))
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .accessibilityIdentifier("ks.shared.invite.copy")
        }
        .padding(12)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
        Text("These words are not shown again. Anyone with the file and the words can join.")
            .font(.footnote)
            .foregroundStyle(.secondary)
        HStack {
            Button("Show File in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([
                    URL(fileURLWithPath: invitation.path)
                ])
            }
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("ks.shared.invite.done")
        }
    }

    private func invite() {
        guard let vault = store.shared.session(for: vaultId) else { return }
        let folder = store.shared.summary(for: vaultId)?.folder.map { URL(fileURLWithPath: $0) }
        let vaultName = store.shared.summary(for: vaultId)?.name ?? String(localized: "Shared vault")
        guard
            let url = SharedPanels.saveInvitation(named: "\(who) – \(vaultName)", in: folder)
        else { return }
        working = true
        error = nil
        Task { @MainActor in
            defer { working = false }
            do {
                // Off the main thread: the passphrase is stretched with Argon2id.
                let (member, name, role) = (existingMember, who, role)
                invitation = try await Task.detached(priority: .userInitiated) {
                    if let member {
                        try vault.inviteDevice(
                            memberId: member.id, outPath: url.path, kdfMKib: nil, kdfT: nil)
                    } else {
                        try vault.inviteMember(
                            name: name, role: role, outPath: url.path, kdfMKib: nil, kdfT: nil)
                    }
                }.value
                store.shared.didChangeLocally(vaultId)
            } catch {
                self.error = describeAnyError(error)
            }
        }
    }
}

// MARK: - Members pane

/// A shared vault's members (ui-spec.md §16.4): who is in it and with which role, its folder
/// and how it last synced, and what removed members could have seen.
struct SharedMembersView: View {
    @Bindable var store: VaultStore
    let vaultId: String

    @State private var renaming: RenameTarget?
    @State private var newName = ""
    @State private var removing: SharedMemberView?

    private enum RenameTarget: Identifiable {
        case vault
        case member(SharedMemberView)
        var id: String {
            switch self {
            case .vault: "vault"
            case .member(let member): member.id
            }
        }
    }

    private var shared: SharedVaultsModel { store.shared }
    private var summary: SharedVaultSummary? { shared.summary(for: vaultId) }
    private var isAdmin: Bool { shared.isAdmin(vaultId) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                if let problem = summary?.problem {
                    problemBanner(problem)
                } else {
                    warningsSection
                    folderSection
                    membersSection
                    exposureSection
                }
            }
            .padding(24)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .accessibilityIdentifier("ks.shared.members.root")
        .onAppear { shared.refresh() }
        .alert(
            renamingTitle,
            isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })
        ) {
            TextField("Name", text: $newName)
            Button("Rename") { rename() }
            Button("Cancel", role: .cancel) { renaming = nil }
        } message: {
            Text("The name is kept on this Mac only.")
        }
        .confirmationDialog(
            "Remove \(removing?.name ?? String(localized: "this member"))?",
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) { remove() }
        } message: {
            Text(
                "They keep what they could already see, but nothing changed from now on reaches them. Consider changing the passwords they had.")
        }
    }

    private var renamingTitle: String {
        switch renaming {
        case .vault: String(localized: "Rename Shared Vault")
        case .member: String(localized: "Rename Member")
        case nil: ""
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "person.2.fill")
                .font(.title)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(summary?.name ?? String(localized: "Shared vault"))
                    .font(.title2.weight(.semibold))
                    .accessibilityIdentifier("ks.shared.members.title")
                Text(roleLine)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                newName = summary?.name ?? ""
                renaming = .vault
            } label: {
                Label("Rename", systemImage: "pencil")
            }
            .accessibilityIdentifier("ks.shared.members.rename")
            if isAdmin {
                Button {
                    store.sharedSheet = .invite(vaultId: vaultId)
                } label: {
                    Label("Invite…", systemImage: "person.badge.plus")
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("ks.shared.members.invite")
            }
        }
    }

    private var roleLine: String {
        let count = summary?.memberCount ?? 0
        let members = count == 1 ? String(localized: "1 member") : String(localized: "\(Int(count)) members")
        guard let role = summary?.myRole else { return String(localized: "\(members) · You were removed") }
        return String(localized: "\(members) · You \(SharedRoleText.youCan(role))")
    }

    /// Roster warnings (ui-spec.md §16.4): the same ones `kagisecure shared status` prints, so
    /// they are not something only the CLI's admin ever sees.
    @ViewBuilder
    private var warningsSection: some View {
        ForEach(Array((summary?.warnings ?? []).enumerated()), id: \.offset) { _, warning in
            Label(SharedRosterWarningText.name(warning), systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.shared.members.warning")
        }
    }

    private func problemBanner(_ problem: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(problem, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            Button("Rebuild from Folder…") {
                guard
                    let folder = SharedPanels.chooseFolder(
                        message: String(localized: "Choose the folder this vault is shared through."))
                else { return }
                store.attempt { try shared.rebuild(vaultId, from: folder) }
            }
            .accessibilityIdentifier("ks.shared.members.rebuild")
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: Folder

    private var folderSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SYNC")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            HStack {
                if let folder = summary?.folder {
                    Label(folder, systemImage: "folder")
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(folder)
                        .accessibilityIdentifier("ks.shared.members.folder")
                } else {
                    Label("Not syncing: no folder chosen", systemImage: "folder.badge.questionmark")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(summary?.folder == nil ? String(localized: "Choose Folder…") : String(localized: "Change…")) { chooseFolder() }
                    .accessibilityIdentifier("ks.shared.members.chooseFolder")
                if summary?.folder != nil {
                    Button("Sync Now") { shared.sync(vaultId) }
                        .accessibilityIdentifier("ks.shared.members.syncNow")
                }
            }
            syncStatus
        }
    }

    @ViewBuilder
    private var syncStatus: some View {
        if let problem = shared.syncProblems[vaultId] {
            Label(problem, systemImage: "exclamationmark.triangle")
                .font(.footnote)
                .foregroundStyle(.orange)
                .accessibilityIdentifier("ks.shared.members.syncProblem")
        } else if let date = shared.lastSynced[vaultId] {
            Text("Synced \(date.formatted(.relative(presentation: .named))). Changes sync by themselves while kagisecure is open.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func chooseFolder() {
        let current = summary?.folder.map { URL(fileURLWithPath: $0) }
        guard
            let folder = SharedPanels.chooseFolder(
                message: String(localized: "Choose a folder everyone in this vault can open."), starting: current)
        else { return }
        store.attempt { try shared.setFolder(vaultId, folder) }
    }

    // MARK: Members

    private var membersSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MEMBERS")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(shared.members[vaultId] ?? [], id: \.id) { member in
                memberRow(member)
                Divider()
            }
        }
    }

    private func memberRow(_ member: SharedMemberView) -> some View {
        HStack(spacing: 10) {
            Image(systemName: member.isYou ? "person.crop.circle.fill" : "person.crop.circle")
                .font(.title2)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(member.name)
                        .accessibilityIdentifier("ks.shared.member.name")
                    if member.isYou {
                        Text("You")
                            .font(.caption)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(.quaternary, in: Capsule())
                    }
                }
                (member.devices.count == 1
                    ? Text("1 computer") : Text("\(member.devices.count) computers"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .help(member.devices.map(\.fingerprint).joined(separator: "\n"))
            }
            Spacer()
            if isAdmin && !member.isYou {
                Picker(
                    "Role",
                    selection: Binding(
                        get: { member.role },
                        set: { role in
                            store.attempt {
                                guard let vault = shared.session(for: vaultId) else { return }
                                try vault.setRole(memberId: member.id, role: role)
                                shared.didChangeLocally(vaultId)
                            }
                        })
                ) {
                    Text("Can view").tag(SharedRole.reader)
                    Text("Can edit").tag(SharedRole.writer)
                    Text("Admin").tag(SharedRole.admin)
                }
                .labelsHidden()
                .fixedSize()
                .accessibilityIdentifier("ks.shared.member.role")
            } else {
                Text(SharedRoleText.name(member.role))
                    .foregroundStyle(.secondary)
            }
            Menu {
                Button("Rename…") {
                    newName = member.name
                    renaming = .member(member)
                }
                if isAdmin {
                    Button("Invite Another Computer…") {
                        store.sharedSheet = .inviteDevice(
                            vaultId: vaultId, memberId: member.id, name: member.name)
                    }
                    if !member.isYou {
                        Divider()
                        Button("Remove…", role: .destructive) { removing = member }
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .accessibilityLabel("More for \(member.name)")
            .accessibilityIdentifier("ks.shared.member.menu")
        }
        .padding(.vertical, 2)
    }

    // MARK: What removed members could have seen

    @ViewBuilder
    private var exposureSection: some View {
        let exposures = shared.session(for: vaultId)?.rotationList() ?? []
        if !exposures.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text("REMOVED MEMBERS COULD HAVE SEEN")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(
                    "Nothing changed after a removal reaches the removed member. What they could already see, they may have kept: change these where they are used if that matters.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(Array(exposures.enumerated()), id: \.offset) { _, exposure in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(exposure.memberName).font(.callout.weight(.medium))
                        Text(exposure.itemTitles.joined(separator: ", "))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .accessibilityIdentifier("ks.shared.members.exposures")
        }
    }

    // MARK: Actions

    private func rename() {
        let target = renaming
        renaming = nil
        guard let vault = shared.session(for: vaultId) else { return }
        store.attempt {
            switch target {
            case .vault: try vault.rename(name: newName)
            case .member(let member): try vault.setMemberName(memberId: member.id, name: newName)
            case nil: return
            }
            shared.refresh()
        }
    }

    private func remove() {
        guard let member = removing, let vault = shared.session(for: vaultId) else { return }
        removing = nil
        store.attempt {
            try vault.removeMember(memberId: member.id)
            shared.didChangeLocally(vaultId)
        }
    }
}

// MARK: - Small pieces

/// A role, in the words the app uses for it.
enum SharedRoleText {
    static func name(_ role: SharedRole) -> String {
        switch role {
        case .reader: String(localized: "Can view")
        case .writer: String(localized: "Can edit")
        case .admin: String(localized: "Admin")
        }
    }

    static func youCan(_ role: SharedRole) -> String {
        switch role {
        case .reader: String(localized: "can view")
        case .writer: String(localized: "can edit")
        case .admin: String(localized: "are an admin")
        }
    }

    static func help(_ role: SharedRole) -> String {
        switch role {
        case .reader: String(localized: "Sees and copies every item; changes nothing.")
        case .writer: String(localized: "Also adds, edits and deletes items.")
        case .admin: String(localized: "Also invites and removes people and changes roles.")
        }
    }
}

/// What each roster warning says (ui-spec.md §16.4) — the same words the CLI's `shared status`
/// already prints (`kagisecure_cli::commands::shared::warning_text`).
enum SharedRosterWarningText {
    static func name(_ warning: SharedRosterWarning) -> String {
        switch warning {
        case .fewAdmins:
            String(localized: "Fewer than two admins are left; losing the last one would freeze the roster.")
        case .frozen:
            String(localized: "No admin is left; the roster is frozen and cannot change.")
        }
    }
}

/// A chosen folder, or none, with a button to choose one.
private struct FolderChoice: View {
    let folder: URL?
    let choose: () -> Void

    var body: some View {
        HStack {
            Text(folder?.path ?? String(localized: "None"))
                .foregroundStyle(folder == nil ? .secondary : .primary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(folder?.path ?? "")
            Spacer()
            Button("Choose…", action: choose)
                .accessibilityIdentifier("ks.shared.chooseFolder")
        }
    }
}

/// An error line under a sheet's form, or nothing.
private struct ErrorText: View {
    let message: String?
    init(_ message: String?) { self.message = message }

    var body: some View {
        if let message {
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.shared.error")
        }
    }
}

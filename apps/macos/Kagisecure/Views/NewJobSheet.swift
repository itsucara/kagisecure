import AppKit
import SwiftUI

import KagisecureFFI

/// What the "New job" sheet holds, and the one draft it becomes. A value type so the rules can be
/// tested without a sheet.
struct NewJobForm: Equatable {
    var name = ""
    var program = ""
    var argumentsText = ""
    var folder = ""
    /// `nil` for every day; 0 = Monday … 6 = Sunday.
    var weekday: UInt8?
    var hour: UInt8 = 2
    var minute: UInt8 = 0
    var environmentId = ""
    /// Whether the job may run its own program with the variables — the common case, and one
    /// click fewer.
    var sameCommand = true
    var command = ""
    var commandArgumentsText = ""
    var expiresInDays: UInt32 = 30
    /// The machine login the job signs in with, or empty (ADR-0042 §12).
    var loginItemId = ""
    /// The one exact https origin it signs in at.
    var loginOrigin = ""
    /// The one-time-code switch, off by default (ADR-0042 §12.5).
    var oneTimeCodes = false
    /// The job's own browser, by full path.
    var runBrowser = ""

    /// Whether the job signs in.
    var signsIn: Bool { !loginItemId.isEmpty }

    /// The executable the grant names.
    var grantedCommand: String { sameCommand ? program : command }

    /// Why there is no draft yet, in a sentence for the sheet.
    struct Missing: Error, Equatable {
        let message: String
    }

    /// The draft, or why there is none yet.
    func draft() -> Result<UnattendedJobDraft, Missing> {
        let name = name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return .failure(Missing(message: String(localized: "Give the job a name."))) }
        guard program.hasPrefix("/") else { return .failure(Missing(message: String(localized: "Choose the program the job starts."))) }
        guard folder.hasPrefix("/") else { return .failure(Missing(message: String(localized: "Choose the folder it runs in."))) }
        guard !environmentId.isEmpty || signsIn else {
            return .failure(Missing(message: String(localized: "Choose the environment it may use, or a login it signs in with.")))
        }
        guard environmentId.isEmpty || sameCommand || command.hasPrefix("/") else {
            return .failure(Missing(message: String(localized: "Choose the command it may run with the environment.")))
        }
        if signsIn {
            guard loginOrigin.hasPrefix("https://") else {
                return .failure(Missing(message: String(localized: "Choose the site it signs in to.")))
            }
            guard runBrowser.hasPrefix("/") else {
                return .failure(Missing(message: String(localized: "Choose the browser it signs in with.")))
            }
        }
        return .success(
            UnattendedJobDraft(
                name: name,
                program: program,
                arguments: UnattendedText.arguments(argumentsText),
                workingDir: folder,
                schedule: [UnattendedTimeView(weekday: weekday, hour: hour, minute: minute)],
                environmentId: environmentId,
                variables: [],
                command: sameCommand ? nil : command,
                commandArguments: sameCommand ? nil : UnattendedText.arguments(commandArgumentsText),
                expiresInDays: expiresInDays,
                runBrowser: signsIn ? runBrowser : nil,
                logins: signsIn
                    ? [
                        UnattendedLoginDraft(
                            itemId: loginItemId, origin: loginOrigin, followOnOrigins: [],
                            oneTimeCodes: oneTimeCodes)
                    ] : []))
    }
}

/// New job: a program, a schedule and an environment or a login, in one sheet; the grants come
/// with it (ui-spec.md §10.8). Creating it asks for Touch ID.
struct NewJobSheet: View {
    @Environment(UnattendedService.self) private var unattended
    @Environment(\.dismiss) private var dismiss
    let store: VaultStore
    let environments: [MachineEnvironmentView]
    var logins: [MachineLoginView] = []

    @State private var form = NewJobForm()
    @State private var time = Calendar.current.date(from: DateComponents(hour: 2, minute: 0)) ?? .now

    /// The sheet's text fields. A click focuses the field it lands on explicitly: in a macOS
    /// `Form`, a field in a row with a button, or a vertical-axis field, did not take focus from a
    /// click (only from Tab) — the owner's GUI check, item 8.
    enum Field: Hashable {
        case name, program, arguments, folder, command, commandArguments, runBrowser
    }

    @FocusState private var focus: Field?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New unattended job").font(.title3.weight(.semibold))
            Form {
                TextField("Name", text: $form.name)
                    .clickFocused($focus, .name)
                    .accessibilityIdentifier("ks.unattended.form.name")
                pathRow("Program", path: $form.program, directory: false, field: .program)
                TextField("Arguments, one per line", text: $form.argumentsText, axis: .vertical)
                    .lineLimit(1...4)
                    .clickFocused($focus, .arguments)
                    .accessibilityIdentifier("ks.unattended.form.arguments")
                pathRow("Runs in", path: $form.folder, directory: true, field: .folder)
                Picker("When", selection: $form.weekday) {
                    Text("Every day").tag(UInt8?.none)
                    ForEach(0..<7, id: \.self) { day in
                        Text("Every \(UnattendedText.weekdays[day])").tag(UInt8?.some(UInt8(day)))
                    }
                }
                DatePicker("At", selection: $time, displayedComponents: .hourAndMinute)
                Picker("Environment", selection: $form.environmentId) {
                    (logins.isEmpty ? Text("Choose…") : Text("None")).tag("")
                    ForEach(environments, id: \.id) { env in
                        Text("\(env.name) (\(env.variableNames.joined(separator: ", ")))").tag(env.id)
                    }
                }
                .accessibilityIdentifier("ks.unattended.form.environment")
                if !form.environmentId.isEmpty {
                    Toggle("It may run its own program with the environment", isOn: $form.sameCommand)
                        .help(
                            "On: the program starts with the environment's variables already set. Off: name the one command that may run with them.")
                }
                if !form.environmentId.isEmpty && !form.sameCommand {
                    pathRow("Command", path: $form.command, directory: false, field: .command)
                    TextField(
                        "Its arguments, one per line", text: $form.commandArgumentsText,
                        axis: .vertical
                    )
                    .lineLimit(1...4)
                    .clickFocused($focus, .commandArguments)
                }
                if !logins.isEmpty { signInRows }
                Stepper("Expires in \(Int(form.expiresInDays)) days", value: $form.expiresInDays, in: 1...90)
            }
            warnings
            if form.signsIn { signInWarnings }
            HStack {
                if case .failure(let why) = form.draft() {
                    Text(why.message).font(.caption).foregroundStyle(.secondary)
                }
                if let problem = unattended.problem {
                    Text(problem).font(.caption).foregroundStyle(.red)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create") {
                    guard case .success(let draft) = form.draft() else { return }
                    Task {
                        if await unattended.create(draft, session: store.session) { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled((try? form.draft().get()) == nil || unattended.confirming)
                .accessibilityIdentifier("ks.unattended.form.create")
            }
        }
        .padding(20)
        .frame(width: 560)
        .onAppear {
            if environments.count == 1 { form.environmentId = environments[0].id }
            if form.runBrowser.isEmpty { form.runBrowser = unattended.defaultRunBrowser() ?? "" }
        }
        .onChange(of: form.loginItemId) { _, new in
            let login = logins.first { $0.id == new }
            form.loginOrigin = login?.origins.first ?? ""
            if login?.hasOneTimeCode != true { form.oneTimeCodes = false }
        }
        .onChange(of: time) { _, new in
            let parts = Calendar.current.dateComponents([.hour, .minute], from: new)
            form.hour = UInt8(parts.hour ?? 0)
            form.minute = UInt8(parts.minute ?? 0)
        }
    }

    /// The login grant's rows (ADR-0042 §12.2): which login, at which one site, in which browser,
    /// and the one-time-code switch.
    @ViewBuilder
    private var signInRows: some View {
        Picker("Signs in with", selection: $form.loginItemId) {
            Text("No login").tag("")
            ForEach(logins, id: \.id) { login in
                Text(login.username.map { "\(login.title) (\($0))" } ?? login.title).tag(login.id)
            }
        }
        .accessibilityIdentifier("ks.unattended.form.login")
        if let login = logins.first(where: { $0.id == form.loginItemId }) {
            Picker("At", selection: $form.loginOrigin) {
                ForEach(login.origins, id: \.self) { origin in
                    Text(origin).tag(origin)
                }
            }
            .accessibilityIdentifier("ks.unattended.form.loginOrigin")
            pathRow(
                "In its own browser", path: $form.runBrowser, directory: false, field: .runBrowser)
            Toggle("Also fill one-time codes", isOn: $form.oneTimeCodes)
                .disabled(!login.hasOneTimeCode)
                .help(
                    login.hasOneTimeCode
                        ? String(localized: "Off by default. Read the warning below first.")
                        : String(localized: "This login has no one-time password."))
                .accessibilityIdentifier("ks.unattended.form.oneTimeCodes")
        }
    }

    /// The sentences ADR-0042 §12.2 and §12.5 make mandatory for a login grant.
    private var signInWarnings: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(UnattendedText.loginCost).font(.caption).foregroundStyle(.secondary)
            Text(UnattendedText.loginAdvice).font(.caption)
            // Always laid out, shown only with the switch on, so turning it on moves nothing.
            Text(UnattendedText.oneTimeCodeCost)
                .font(.caption)
                .padding(8)
                .background(.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
                .reserved(shown: form.oneTimeCodes)
                .accessibilityIdentifier("ks.unattended.form.oneTimeCodeWarning")
        }
    }

    /// The sentences ADR-0042 §5 makes mandatory on this sheet.
    @ViewBuilder
    private var warnings: some View {
        if !form.environmentId.isEmpty { commandWarnings }
    }

    private var commandWarnings: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(UnattendedText.commandCost).font(.caption).foregroundStyle(.secondary)
            // Both lines below are always laid out and only shown when they apply, so typing a
            // program path that turns out to be an interpreter moves nothing on the sheet.
            (form.folder.isEmpty
                ? Text("Not pinned: anything else this command reads.")
                : Text("Not pinned: anything else this command reads in \(form.folder)."))
            .font(.caption)
            .lineLimit(1)
            .truncationMode(.middle)
            .reserved(shown: !form.grantedCommand.isEmpty)
            Text(UnattendedText.interpreterCost)
                .font(.caption)
                .padding(8)
                .background(.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
                .reserved(shown: UnattendedText.isInterpreter(form.grantedCommand))
                .accessibilityIdentifier("ks.unattended.form.interpreterWarning")
        }
    }

    private func pathRow(
        _ label: LocalizedStringKey, path: Binding<String>, directory: Bool, field: Field
    ) -> some View {
        HStack {
            TextField(label, text: path)
                .clickFocused($focus, field)
            Button("Choose…") {
                let panel = NSOpenPanel()
                panel.canChooseFiles = !directory
                panel.canChooseDirectories = directory
                panel.allowsMultipleSelection = false
                if panel.runModal() == .OK, let url = panel.url {
                    path.wrappedValue = url.path
                }
            }
        }
    }
}

// File-private: the environment editor is being fixed separately, and a helper of the same name
// there must not collide with this one.
fileprivate extension View {
    /// Focus `field` when this text field is clicked, as well as by Tab. The tap is simultaneous,
    /// so the field's own handling of the click (placing the caret, selecting) still happens.
    func clickFocused<Field: Hashable>(_ focus: FocusState<Field?>.Binding, _ field: Field)
        -> some View
    {
        self.focused(focus, equals: field)
            .simultaneousGesture(TapGesture().onEnded { focus.wrappedValue = field })
    }

    /// Lay this view out whether or not it is `shown`, so showing it moves nothing around it;
    /// hidden, it is invisible, takes no clicks and is left out of accessibility.
    func reserved(shown: Bool) -> some View {
        self.opacity(shown ? 1 : 0)
            .allowsHitTesting(shown)
            .accessibilityHidden(!shown)
    }
}

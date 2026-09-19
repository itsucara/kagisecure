import SwiftUI

import KagisecureFFI

/// Agent access → Environments (ui-spec.md §2.2, §10.4).
///
/// Lists every environment with its variable count and agent-visibility state, and opens an
/// editor for one: name, description, each variable with its binding, and a **Pending** badge for
/// a variable an agent declared through `add_variables` and could not supply a value for
/// (mcp-server.md §2.6).
///
/// That pending flow is completed here, in the app, with the keyboard — which is the whole point:
/// the agent named `STRIPE_SECRET_KEY`, the schema gave it nowhere to put a value, and the value
/// goes into a `SecureField` in this window rather than into a chat transcript.
struct AgentAccessView: View {
    @Environment(AgentService.self) private var agent
    @Bindable var store: VaultStore

    @State private var selected: String?
    @State private var creating = false
    @State private var newName = ""

    var body: some View {
        VStack(spacing: 0) {
            if let error = agent.startupError {
                listenerProblem(error)
            } else {
                listenerState
            }
            Divider()
            content
        }
        .navigationTitle("Agent access")
        .toolbar {
            Button {
                creating = true
            } label: {
                Label("New Environment", systemImage: "plus")
            }
            .help("Create an environment")
            .accessibilityIdentifier("ks.agentAccess.newEnvironment")
        }
        .sheet(isPresented: $creating) { newEnvironmentSheet }
    }

    // MARK: - Listener banner

    private var listenerState: some View {
        HStack(spacing: 8) {
            Image(systemName: agent.status.running ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash")
                .foregroundStyle(agent.status.running ? .green : .secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(agent.status.running ? "Serving agents" : "Not serving agents")
                    .font(.callout.weight(.medium))
                    .accessibilityIdentifier("ks.agentAccess.listenerState")
                if agent.status.running {
                    Text(agent.status.endpoint)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("ks.agentAccess.endpoint")
                }
            }
            Spacer()
            // The outermost of the three gates (threat-model M-9). With this off nothing inside
            // the vault is reachable however an individual environment is flagged, so it belongs
            // where a user looking at agent access will find it.
            Toggle(
                "Share this vault",
                isOn: Binding(
                    get: { store.vaultAgentVisible },
                    set: { store.setVaultAgentVisible($0) })
            )
            .toggleStyle(.switch)
            .help("Agents cannot see anything in a vault that is not shared")
            .accessibilityIdentifier("ks.agentAccess.shareVault")
            if agent.status.activeLeases > 0 {
                Label("\(agent.status.activeLeases) active", systemImage: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.agentAccess.activeLeases")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    /// The app-versus-daemon collision, said out loud (architecture.md §4.2).
    private func listenerProblem(_ error: String) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text("Agents cannot reach this app")
                    .font(.callout.weight(.semibold))
                Text(error)
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .foregroundStyle(.red)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .accessibilityIdentifier("ks.agentAccess.listenerError")
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if store.environments.isEmpty {
            EmptyStateView(
                symbol: "list.bullet.rectangle",
                title: "No environments yet",
                message:
                    "An environment is a named set of variables an agent can ask to have written "
                    + "into a project. Create one, or let an agent create it for you.",
                action: ("New Environment", { creating = true }))
            .accessibilityIdentifier("ks.agentAccess.empty")
        } else {
            HSplitView {
                List(selection: $selected) {
                    ForEach(store.environments, id: \.id) { environment in
                        environmentRow(environment)
                            .tag(environment.id)
                    }
                }
                .frame(minWidth: 220, idealWidth: 280)
                .accessibilityIdentifier("ks.agentAccess.list")

                if let id = selected,
                    let environment = store.environments.first(where: { $0.id == id })
                {
                    EnvironmentEditor(store: store, environment: environment)
                } else {
                    EmptyStateView(
                        symbol: "sidebar.right",
                        title: "Select an environment",
                        message: "Its variables, their bindings, and anything waiting for you.")
                }
            }
        }
    }

    private func environmentRow(_ environment: EnvironmentView) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(environment.name)
                    .font(.headline)
                    .accessibilityIdentifier("ks.agentAccess.row.\(environment.name)")
                Spacer()
                if environment.pendingCount > 0 {
                    Text("\(environment.pendingCount) pending")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.orange.opacity(0.2), in: Capsule())
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier(
                            "ks.agentAccess.pendingBadge.\(environment.name)")
                }
            }
            HStack(spacing: 6) {
                Image(systemName: environment.agentVisible ? "eye" : "eye.slash")
                    .accessibilityHidden(true)
                Text(
                    environment.variableNames.isEmpty
                        ? "No variables"
                        : "\(environment.variableNames.count) variable\(environment.variableNames.count == 1 ? "" : "s")"
                )
            }
            .font(.caption)
            .foregroundStyle(environment.agentVisible ? .secondary : .tertiary)
        }
        .padding(.vertical, 3)
    }

    private var newEnvironmentSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New environment")
                .font(.title3.weight(.semibold))
            TextField("Name, e.g. acme-api / staging", text: $newName)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("ks.newEnvironment.name")
            Text(
                "New environments are not shared with agents. Turn sharing on once you have put "
                + "something in it."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel") { creating = false; newName = "" }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.newEnvironment.cancel")
                Button("Create") {
                    store.createEnvironment(name: newName)
                    selected = store.environments.last?.id
                    creating = false
                    newName = ""
                }
                .keyboardShortcut(.defaultAction)
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
                .accessibilityIdentifier("ks.newEnvironment.create")
            }
        }
        .padding(24)
        .frame(width: 420)
    }
}

/// One environment, editable (ui-spec.md §10.4).
struct EnvironmentEditor: View {
    @Bindable var store: VaultStore
    let environment: EnvironmentView

    @State private var pendingValues: [String: String] = [:]
    @State private var newName = ""
    @State private var newValue = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Divider()
                variableList
                Divider()
                addVariable
            }
            .padding(20)
        }
        .frame(minWidth: 380)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(environment.name)
                .font(.title3.weight(.semibold))
                .accessibilityIdentifier("ks.environment.name")
            if let description = environment.description {
                Text(description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.environment.description")
            }
            Toggle(
                "Share with agents",
                isOn: Binding(
                    get: { environment.agentVisible },
                    set: { store.setEnvironmentAgentVisible(environment, $0) })
            )
            .toggleStyle(.switch)
            .accessibilityIdentifier("ks.environment.share")
            Text(
                environment.agentVisible
                    ? "Agents can see this environment's name and its variable names. Never a value."
                    : "Hidden from agents entirely — they cannot see that it exists."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var variableList: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Variables")
                .font(.subheadline.weight(.semibold))
            if environment.variables.isEmpty {
                Text("Nothing here yet.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.environment.noVariables")
            }
            ForEach(environment.variables, id: \.name) { variable in
                variableRow(variable)
            }
        }
    }

    @ViewBuilder
    private func variableRow(_ variable: EnvVarView) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(variable.name)
                    .font(.system(.callout, design: .monospaced))
                    .accessibilityIdentifier("ks.environment.variable.\(variable.name)")
                Spacer()
                badge(for: variable)
                    .accessibilityIdentifier("ks.environment.binding.\(variable.name)")
                Button {
                    store.removeVariable(environment, name: variable.name)
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .help("Remove \(variable.name)")
                .accessibilityIdentifier("ks.environment.removeVariable.\(variable.name)")
            }
            if variable.binding == .pending {
                if let hint = variable.hint {
                    Text("The agent says: “\(hint)”")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.environment.hint.\(variable.name)")
                }
                HStack {
                    SecureField(
                        "Paste the value for \(variable.name)",
                        text: Binding(
                            get: { pendingValues[variable.name] ?? "" },
                            set: { pendingValues[variable.name] = $0 })
                    )
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("ks.environment.pendingValue.\(variable.name)")
                    Button("Save") {
                        store.setVariableValue(
                            environment, name: variable.name,
                            value: pendingValues[variable.name] ?? "")
                        pendingValues[variable.name] = ""
                    }
                    .disabled((pendingValues[variable.name] ?? "").isEmpty)
                    .accessibilityIdentifier("ks.environment.pendingSave.\(variable.name)")
                }
                Text("Typed here, in kagisecure. The agent that asked for it never sees it.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            variable.binding == .pending ? AnyShapeStyle(.orange.opacity(0.08)) : AnyShapeStyle(.quaternary.opacity(0.3)),
            in: RoundedRectangle(cornerRadius: 8))
    }

    private func badge(for variable: EnvVarView) -> some View {
        let (text, color): (String, Color) =
            switch variable.binding {
            case .pending: ("Pending", .orange)
            case .itemField: ("Linked to an item", .blue)
            case .literal: ("Stored here", .secondary)
            }
        return Text(text)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private var addVariable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Add a variable")
                .font(.subheadline.weight(.semibold))
            HStack {
                TextField("NAME", text: $newName)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 180)
                    .accessibilityIdentifier("ks.environment.newVariableName")
                SecureField("Value", text: $newValue)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("ks.environment.newVariableValue")
                Button("Add") {
                    store.setVariableValue(environment, name: newName, value: newValue)
                    newName = ""
                    newValue = ""
                }
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty || newValue.isEmpty)
                .accessibilityIdentifier("ks.environment.addVariable")
            }
            Text("Values stay in the vault. Nothing here is ever returned to an agent.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

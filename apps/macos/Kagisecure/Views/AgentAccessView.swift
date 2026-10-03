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
///
/// Between the listener banner and the environments sits **Agent fills** (`AgentFillSection`):
/// the switch for agent-requested browser fills, the agents blocked from asking, and the notices
/// about requests that raised no sheet (ADR-0036).
struct AgentAccessView: View {
    @Environment(AgentService.self) private var agent
    @Bindable var store: VaultStore

    @State private var selected: String?
    @State private var creating = false
    @State private var newName = ""
    /// How tall the agent-fills section wants to be, and how tall the whole pane is. Measured
    /// rather than left to the stack, because the section is not bounded: every block and every
    /// notice adds a row.
    @State private var agentFillHeight: CGFloat = 0
    @State private var paneHeight: CGFloat = 0

    /// The most of the pane the agent-fills section may take before it scrolls. The rest belongs
    /// to the environments, which are what this pane is for.
    private static let agentFillShare: CGFloat = 0.4

    var body: some View {
        VStack(spacing: 0) {
            if let error = agent.startupError {
                listenerProblem(error)
            } else {
                listenerState
            }
            Divider()
            // ADR-0036 §2, §9: the switch, the blocks list and the recent notices. Above the
            // environments, beside the other vault-wide gate ("Share this vault").
            agentFill
            Divider()
            content
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { paneHeight = $0 }
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

    // MARK: - Agent fills

    /// `AgentFillSection` at its own height while that is small, and scrolling inside at most
    /// `agentFillShare` of the pane once it is not.
    ///
    /// Stacked straight into this `VStack`, the section's height was a floor under the pane's:
    /// a few wrapped lines, blocks and notices made the pane taller than the window, and the
    /// window pushed the environment list and editor off the bottom of the screen, where nothing
    /// could click them.
    private var agentFill: some View {
        ScrollView {
            AgentFillSection()
                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: {
                    agentFillHeight = $0
                }
        }
        .scrollBounceBehavior(.basedOnSize)
        .frame(
            height: min(
                agentFillHeight,
                paneHeight > 0 ? paneHeight * Self.agentFillShare : agentFillHeight))
    }

    // MARK: - Listener banner

    private var listenerState: some View {
        HStack(spacing: 8) {
            Image(systemName: agent.status.running ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash")
                .foregroundStyle(agent.status.running ? .green : .secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                (agent.status.running ? Text("Serving agents") : Text("Not serving agents"))
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
                Label("\(Int(agent.status.activeLeases)) active", systemImage: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.agentAccess.activeLeases")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    /// The app-versus-daemon collision, said out loud (architecture.md §4.2).
    ///
    /// `error` is a startup-error string from the daemon, not something this view controls the
    /// length of — an unbounded `fixedSize(vertical:)` here once made the pane taller than the
    /// window (the same overflow §10.4's other panes were fixed for). Capped to a few lines with
    /// the full text still reachable, by selection or by hovering.
    private func listenerProblem(_ error: String) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text("Agents cannot reach this app")
                    .font(.callout.weight(.semibold))
                Text(error)
                    .font(.caption)
                    .lineLimit(4)
                    .truncationMode(.tail)
                    .textSelection(.enabled)
                    .help(error)
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
                title: String(localized: "No environments yet"),
                message: String(
                    localized: "An environment is a named set of variables an agent can ask to have written into a project. Create one, or let an agent create it for you."),
                action: (String(localized: "New Environment"), { creating = true }))
            .accessibilityIdentifier("ks.agentAccess.empty")
        } else {
            // The detail column is narrow: the item list stays beside it in every section, so a
            // 1040-point window leaves this pane about 460. The two minimums below must add up to
            // less than that, or the split overflows the window and the editor's right-hand edge
            // — the Add button — is off the screen.
            HSplitView {
                List(selection: $selected) {
                    ForEach(store.environments, id: \.id) { environment in
                        environmentRow(environment)
                            .tag(environment.id)
                    }
                }
                .frame(minWidth: 160, idealWidth: 200)
                .accessibilityIdentifier("ks.agentAccess.list")

                if let id = selected,
                    let environment = store.environments.first(where: { $0.id == id })
                {
                    EnvironmentEditor(environment: environment, editing: editing)
                } else {
                    EmptyStateView(
                        symbol: "sidebar.right",
                        title: String(localized: "Select an environment"),
                        message: String(localized: "Its variables, their bindings, and anything waiting for you."))
                }
            }
        }
    }

    /// The personal vault's own environments are always editable, have no rename affordance
    /// from this pane (unchanged from before `EnvironmentEditing` existed), and bind only through
    /// the pending-value flow and this file's own `store` calls — never through "Add a variable",
    /// which stays literal-only here.
    private var editing: EnvironmentEditing {
        EnvironmentEditing(
            canEdit: true,
            setShareWithAgents: { env, visible in
                store.setEnvironmentAgentVisible(env, visible)
            },
            setVariableValue: { env, name, value in
                store.setVariableValue(env, name: name, value: value)
            },
            bindVariable: { env, name, itemId, fieldId in
                store.bindVariable(env, name: name, itemId: itemId, fieldId: fieldId)
            },
            removeVariable: { env, name in
                store.removeVariable(env, name: name)
            },
            rename: nil,
            bindableItems: nil)
    }

    private func environmentRow(_ environment: EnvironmentView) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(environment.name)
                    .font(.headline)
                    .accessibilityIdentifier("ks.agentAccess.row.\(environment.name)")
                Spacer()
                if environment.pendingCount > 0 {
                    Text("\(Int(environment.pendingCount)) pending")
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
                (environment.variableNames.isEmpty
                    ? Text("No variables")
                    : (environment.variableNames.count == 1
                        ? Text("\(environment.variableNames.count) variable")
                        : Text("\(environment.variableNames.count) variables")))
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
                "New environments are not shared with agents. Turn sharing on once you have put something in it."
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

/// One environment, editable (ui-spec.md §10.4, §16.6) — the personal vault's own, or a shared
/// vault's, driven by `editing` (`EnvironmentEditing`) so the two render and behave identically
/// wherever they do not have to differ.
struct EnvironmentEditor: View {
    let environment: EnvironmentView
    let editing: EnvironmentEditing

    @State private var pendingValues: [String: String] = [:]
    @State private var newName = ""
    @State private var newValue = ""
    @State private var addMode: AddMode = .literal
    @State private var bindItemId = ""
    @State private var bindFieldId = ""
    @State private var renaming = false
    @State private var renameText = ""

    private enum AddMode: Hashable {
        case literal
        case bound
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Divider()
                variableList
                if editing.canEdit {
                    Divider()
                    addVariable
                }
            }
            .padding(20)
        }
        .frame(minWidth: 260)
        .alert("Rename Environment", isPresented: $renaming) {
            TextField("Name", text: $renameText)
            Button("Rename") { editing.rename?(environment, renameText) }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(environment.name)
                    .font(.title3.weight(.semibold))
                    .accessibilityIdentifier("ks.environment.name")
                if editing.rename != nil, editing.canEdit {
                    Button {
                        renameText = environment.name
                        renaming = true
                    } label: {
                        Image(systemName: "pencil")
                    }
                    .buttonStyle(.borderless)
                    .help("Rename this environment")
                    .accessibilityIdentifier("ks.environment.renameButton")
                }
            }
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
                    set: { editing.setShareWithAgents(environment, $0) })
            )
            .toggleStyle(.switch)
            .accessibilityIdentifier("ks.environment.share")
            (environment.agentVisible
                ? Text("Agents can see this environment's name and its variable names. Never a value.")
                : Text("Hidden from agents entirely — they cannot see that it exists."))
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
                if editing.canEdit {
                    Button {
                        editing.removeVariable(environment, variable.name)
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove \(variable.name)")
                    .accessibilityIdentifier("ks.environment.removeVariable.\(variable.name)")
                }
            }
            if variable.binding == .pending {
                if let hint = variable.hint {
                    Text("The agent says: “\(hint)”")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.environment.hint.\(variable.name)")
                }
                if editing.canEdit {
                    HStack {
                        StableSecureField(
                            String(localized: "Paste the value for \(variable.name)"),
                            text: Binding(
                                get: { pendingValues[variable.name] ?? "" },
                                set: { pendingValues[variable.name] = $0 })
                        )
                        .accessibilityIdentifier("ks.environment.pendingValue.\(variable.name)")
                        Button("Save") {
                            editing.setVariableValue(
                                environment, variable.name, pendingValues[variable.name] ?? "")
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
            case .pending: (String(localized: "Pending"), .orange)
            case .itemField: (String(localized: "Linked to an item"), .blue)
            case .literal: (String(localized: "Stored here"), .secondary)
            }
        return Text(text)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    // MARK: Add a variable

    private var addVariable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Add a variable")
                .font(.subheadline.weight(.semibold))
            if let items = editing.bindableItems, !items.isEmpty {
                Picker("Kind", selection: $addMode) {
                    Text("Literal value").tag(AddMode.literal)
                    Text("Bind to an item").tag(AddMode.bound)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityIdentifier("ks.environment.addVariableMode")
            }
            TextField("NAME", text: $newName)
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 80, idealWidth: 180, maxWidth: 220)
                .accessibilityIdentifier("ks.environment.newVariableName")
            if addMode == .bound, let items = editing.bindableItems, !items.isEmpty {
                bindPickers(items)
            } else {
                literalValue
            }
            Text("Values stay in the vault. Nothing here is ever returned to an agent.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var literalValue: some View {
        HStack {
            StableSecureField(String(localized: "Value"), text: $newValue)
                .frame(minWidth: 60, minHeight: 22)
                .accessibilityIdentifier("ks.environment.newVariableValue")
            Button("Add") {
                editing.setVariableValue(environment, newName, newValue)
                newName = ""
                newValue = ""
            }
            .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty || newValue.isEmpty)
            .accessibilityIdentifier("ks.environment.addVariable")
        }
    }

    /// The item and field pickers for a bound variable, and its own Add button — a second one for
    /// `literalValue`'s would either share a name two very different actions both need
    /// identified by, or force a mode check into `addVariable` that belongs here instead.
    @ViewBuilder
    private func bindPickers(_ items: [EnvironmentBindableItem]) -> some View {
        let fields = items.first(where: { $0.id == bindItemId })?.fields ?? []
        VStack(alignment: .leading, spacing: 6) {
            Picker("Item", selection: $bindItemId) {
                Text("Choose an item…").tag("")
                ForEach(items) { item in
                    Text(item.title).tag(item.id)
                }
            }
            .labelsHidden()
            .accessibilityIdentifier("ks.environment.bindItem")
            Picker("Field", selection: $bindFieldId) {
                Text("Choose a field…").tag("")
                ForEach(fields) { field in
                    Text(field.label).tag(field.id)
                }
            }
            .labelsHidden()
            .disabled(fields.isEmpty)
            .accessibilityIdentifier("ks.environment.bindField")
            HStack {
                Spacer()
                Button("Add") {
                    editing.bindVariable(environment, newName, bindItemId, bindFieldId)
                    newName = ""
                    bindItemId = ""
                    bindFieldId = ""
                }
                .disabled(
                    newName.trimmingCharacters(in: .whitespaces).isEmpty || bindItemId.isEmpty
                        || bindFieldId.isEmpty
                )
                .accessibilityIdentifier("ks.environment.addVariable")
            }
        }
        .onChange(of: bindItemId) { _, _ in bindFieldId = "" }
    }
}

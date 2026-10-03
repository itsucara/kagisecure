import AppKit
import SwiftUI

import KagisecureFFI

/// Agent access → Unattended jobs (ui-spec.md §10.8, ADR-0042 Phase 3).
///
/// Top to bottom: whether jobs are armed, with **Arm…** or **Pause**; the jobs, each with its
/// schedule, what it runs and its grant — uses, expiry, and a suspension with **Re-enable**, plus
/// **Run Now** and **Revoke**; and the environments jobs may use, each a copy of a personal
/// environment with **Update** (which re-approves the grants over it) and **Remove**.
///
/// The fewest clicks on purpose: **New Job…** is one sheet — a program, a schedule and an
/// environment — and the grant is created with the job. Names, paths and schedules only; no value
/// is anywhere here.
struct UnattendedView: View {
    @Environment(UnattendedService.self) private var unattended
    @Bindable var store: VaultStore

    @State private var creatingJob = false

    var body: some View {
        VStack(spacing: 0) {
            banner
            if let problem = unattended.problem {
                Text(problem)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("ks.unattended.problem")
            }
            Divider()
            List {
                jobsSection
                environmentsSection
                loginsSection
                if !store.shared.vaults.isEmpty { sharedSection }
                if !unattended.recentNotices.isEmpty { noticesSection }
            }
        }
        .navigationTitle("Unattended jobs")
        .toolbar {
            Button {
                creatingJob = true
            } label: {
                Label("New Job", systemImage: "plus")
            }
            .help("Define a job that runs on a schedule and may use one environment or sign in with one login")
            .disabled((unattended.overview?.environments.isEmpty ?? true) && unattended.logins.isEmpty)
            .accessibilityIdentifier("ks.unattended.newJob")
        }
        .sheet(isPresented: $creatingJob) {
            NewJobSheet(
                store: store, environments: unattended.overview?.environments ?? [],
                logins: unattended.logins)
        }
        .sheet(
            isPresented: Binding(
                get: { unattended.armSheetShown },
                set: { if !$0 { unattended.armSheetShown = false } })
        ) {
            ArmSheet(store: store)
        }
        .onAppear {
            unattended.refresh(session: store.session)
            unattended.markSeen()
        }
    }

    // MARK: - Armed or not

    private var banner: some View {
        HStack(spacing: 10) {
            Image(systemName: unattended.status.armed ? "clock.badge.checkmark.fill" : "pause.circle")
                .foregroundStyle(unattended.status.armed ? .green : .secondary)
                .font(.title2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(armedTitle)
                    .font(.callout.weight(.medium))
                    .accessibilityIdentifier("ks.unattended.state")
                (unattended.status.armed
                    ? Text("Jobs run on schedule with nobody present, even after a restart, until you pause them.")
                    : Text("No job runs and nothing is released unattended."))
                .font(.caption)
                .foregroundStyle(.secondary)
                Toggle(
                    "Open Kagisecure at login, so armed jobs run after a restart",
                    isOn: Binding(
                        get: { unattended.loginItemEnabled },
                        set: { unattended.setLoginItem($0) })
                )
                .toggleStyle(.checkbox)
                .font(.caption)
                .accessibilityIdentifier("ks.unattended.loginItem")
                if !unattended.status.runs.isEmpty {
                    Text("Running now: \(unattended.status.runs.map(\.job).joined(separator: ", "))")
                        .font(.caption)
                        .accessibilityIdentifier("ks.unattended.running")
                }
            }
            Spacer()
            if unattended.status.armed {
                Button("Pause") { unattended.pause(session: store.session) }
                    .accessibilityIdentifier("ks.unattended.pause")
            } else {
                Button("Arm…") { unattended.requestArm() }
                    .disabled(unattended.confirming || unattended.arming || !unattended.status.running)
                    .accessibilityIdentifier("ks.unattended.arm")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var armedTitle: String {
        guard unattended.status.running else { return String(localized: "Unattended jobs are not available") }
        guard unattended.status.armed else { return String(localized: "Unattended jobs are paused") }
        guard let at = unattended.status.armedAt else { return String(localized: "Unattended jobs are armed") }
        return String(localized: "Armed since \(AuditView.timestamp(at))")
    }

    // MARK: - Jobs

    private var jobsSection: some View {
        Section("Jobs") {
            let jobs = unattended.overview?.jobs ?? []
            if jobs.isEmpty {
                ((unattended.overview?.environments.isEmpty ?? true) && unattended.logins.isEmpty
                    ? Text("Add an environment or a login below, then create a job that uses it.")
                    : Text("No jobs yet. New Job… defines one and its grant in one step."))
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.unattended.noJobs")
            }
            ForEach(jobs, id: \.id) { job in
                JobRow(job: job, store: store)
            }
        }
    }

    // MARK: - Environments

    private var environmentsSection: some View {
        Section("Environments jobs may use") {
            ForEach(unattended.overview?.environments ?? [], id: \.id) { env in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(env.name).font(.callout.weight(.medium))
                        Text(env.variableNames.joined(separator: ", "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if unattended.staleCopies.contains(env.id) {
                            Label(
                                "Changed at its source since it was copied — Update to copy it again",
                                systemImage: "arrow.triangle.2.circlepath"
                            )
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityIdentifier("ks.unattended.env.stale")
                        }
                        Text("Copied \(AuditView.timestamp(env.updatedAt))")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                    if unattended.canUpdate(env, personal: store.environments) {
                        Button("Update") {
                            Task { await unattended.update(env, session: store.session) }
                        }
                        .help("Copy the current values again. Jobs using it keep their grants.")
                        .accessibilityIdentifier("ks.unattended.env.update")
                    }
                    Button("Remove", role: .destructive) {
                        unattended.remove(env, session: store.session)
                    }
                    .help("Remove the copy, and every job that uses it")
                    .accessibilityIdentifier("ks.unattended.env.remove")
                }
            }
            Menu("Add an Environment…") {
                if !store.environments.isEmpty {
                    Section("Personal vault") {
                        ForEach(store.environments, id: \.id) { env in
                            Button(env.name) {
                                Task {
                                    await unattended.copy(environmentId: env.id, session: store.session)
                                }
                            }
                        }
                    }
                }
                ForEach(sharedVaults, id: \.id) { entry in
                    sharedChoices(entry.session)
                }
            }
            .disabled(store.environments.isEmpty && store.shared.vaults.isEmpty)
            .help(
                "Copies the environment's current values into the machine vault. Only jobs you create can use the copy unattended.")
            .accessibilityIdentifier("ks.unattended.addEnvironment")
        }
    }

    /// One shared vault's environments in the Add menu: refused ones say why.
    @ViewBuilder
    private func sharedChoices(_ vault: SharedVaultSession) -> some View {
        let id = vault.vaultId()
        let name = store.shared.summary(for: id)?.name ?? String(localized: "Shared vault")
        Section(name) {
            if unattended.sharedCopiesAllowed[id] == false {
                Text("An admin does not allow unattended copies")
            } else {
                ForEach(unattended.choices(in: vault), id: \.id) { choice in
                    Button(choice.loginBound ? String(localized: "\(choice.name) (a login: never copied)") : choice.name) {
                        Task {
                            await unattended.copyShared(
                                environmentId: choice.id, from: vault, session: store.session)
                        }
                    }
                    .disabled(choice.loginBound)
                }
            }
        }
    }

    // MARK: - Logins (ADR-0042 §12)

    /// The personal logins that could be copied in.
    private var personalLogins: [ItemView] {
        store.session.listItems(filter: .category(category: "login"), query: nil, sort: .title)
    }

    private var loginsSection: some View {
        Section("Logins jobs may sign in with") {
            ForEach(unattended.logins, id: \.id) { login in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(login.title).font(.callout.weight(.medium))
                        Text(([login.username].compactMap { $0 } + login.origins).joined(separator: " · "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Copied \(AuditView.timestamp(login.updatedAt))")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                    if let source = login.copiedFrom {
                        Button("Update") {
                            Task { await unattended.copyLogin(itemId: source, session: store.session) }
                        }
                        .help("Copy the login again. Jobs signing in with it keep their grants.")
                        .accessibilityIdentifier("ks.unattended.login.update")
                    }
                }
            }
            Menu("Add a Login…") {
                ForEach(personalLogins, id: \.id) { item in
                    Button(item.title) {
                        Task { await unattended.copyLogin(itemId: item.id, session: store.session) }
                    }
                }
            }
            .help(
                "Copies a service account's login into the machine vault, so a job you create can sign in with it in its own browser. The job's agent can read the password.")
            .accessibilityIdentifier("ks.unattended.addLogin")
        }
    }

    // MARK: - Shared vaults

    /// The open shared vaults, by id.
    private var sharedVaults: [(id: String, session: SharedVaultSession)] {
        store.shared.vaults.map { (id: $0.vaultId(), session: $0) }
    }

    /// Every open shared vault: whether it allows unattended copies (an admin may change it), and
    /// which devices hold one — a removed device's flagged, since its copy stays on it.
    private var sharedSection: some View {
        Section("Unattended copies of shared vaults") {
            ForEach(sharedVaults, id: \.id) { entry in
                let vault = entry.session
                let id = entry.id
                let name = store.shared.summary(for: id)?.name ?? String(localized: "Shared vault")
                VStack(alignment: .leading, spacing: 4) {
                    if store.shared.isAdmin(id) {
                        Toggle(
                            "\(name): members may copy values for unattended jobs",
                            isOn: Binding(
                                get: { unattended.sharedCopiesAllowed[id] ?? true },
                                set: {
                                    unattended.setCopiesAllowed($0, in: vault, session: store.session)
                                })
                        )
                        .accessibilityIdentifier("ks.unattended.shared.allowCopies")
                    } else {
                        ((unattended.sharedCopiesAllowed[id] ?? true)
                            ? Text("\(name): unattended copies allowed")
                            : Text("\(name): unattended copies not allowed"))
                        .font(.callout.weight(.medium))
                    }
                    let copies = unattended.sharedCopies[id] ?? []
                    if copies.isEmpty {
                        Text("No device holds an unattended copy.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(Array(copies.enumerated()), id: \.offset) { _, copy in
                        (copy.holderActive
                            ? Text("\(copy.holder) holds “\(copy.environmentName)” (\(copy.variables.joined(separator: ", ")))")
                            : Text("\(copy.holder) holds “\(copy.environmentName)” (\(copy.variables.joined(separator: ", "))) — removed from the vault: rotate these values at their service first"))
                        .font(.caption)
                        .foregroundStyle(copy.holderActive ? Color.secondary : Color.orange)
                    }
                }
            }
        }
    }

    // MARK: - Notices

    private var noticesSection: some View {
        Section("Recent") {
            ForEach(Array(unattended.recentNotices.enumerated()), id: \.offset) { _, notice in
                let (title, body) = UnattendedText.notification(notice)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.callout.weight(.medium))
                    Text(body).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// One job, with its grant.
private struct JobRow: View {
    @Environment(UnattendedService.self) private var unattended
    let job: UnattendedJobView
    let store: VaultStore

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text(job.name).font(.callout.weight(.semibold))
                Text(UnattendedText.schedule(job.schedule))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Run Now") { unattended.runNow(jobId: job.id) }
                    .disabled(!unattended.status.armed)
                    .help("Start it once now; its grant applies as on schedule")
                    .accessibilityIdentifier("ks.unattended.job.runNow")
                Button("Revoke", role: .destructive) {
                    unattended.revoke(jobId: job.id, session: store.session)
                }
                .help("Remove the job and its grant")
                .accessibilityIdentifier("ks.unattended.job.revoke")
            }
            Text(([job.program] + job.arguments).joined(separator: " "))
                .font(.system(.caption, design: .monospaced))
                .lineLimit(2)
                .textSelection(.enabled)
            ForEach(job.grants, id: \.id) { grant in
                GrantLine(grant: grant, store: store)
            }
            ForEach(unattended.loginGrants(ofJob: job.id), id: \.id) { grant in
                LoginGrantLine(grant: grant, store: store)
            }
        }
        .padding(.vertical, 4)
    }
}

/// A grant's scope, use and state.
private struct GrantLine: View {
    @Environment(UnattendedService.self) private var unattended
    let grant: UnattendedGrantView
    let store: VaultStore

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(
                "May run \(([grant.command] + grant.arguments).joined(separator: " ")) with \(grant.variables.joined(separator: ", ")) from “\(grant.environmentName)”"
            )
            .font(.caption)
            Text(
                "Used \(Int(grant.uses)) of \(Int(grant.totalUses)) · \(Int(grant.perRun)) per run · expires \(AuditView.timestamp(grant.expiresAt))"
            )
            .font(.caption2)
            .foregroundStyle(.secondary)
            if let reason = grant.suspendedReason {
                HStack {
                    Label(
                        "Suspended: \(UnattendedText.suspension(reason))",
                        systemImage: "exclamationmark.octagon.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                    Button("Re-enable…") {
                        Task { await unattended.reenable(grantId: grant.id, session: store.session) }
                    }
                    .help("Let the job use this grant again, after Touch ID")
                    .accessibilityIdentifier("ks.unattended.grant.reenable")
                }
            }
        }
    }
}

/// A login grant's scope, use and state (ADR-0042 §12.2).
private struct LoginGrantLine: View {
    @Environment(UnattendedService.self) private var unattended
    let grant: UnattendedLoginGrantView
    let store: VaultStore

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            (grant.oneTimeCodes
                ? Text("May sign in as “\(grant.itemTitle)” at \(grant.origin), in its own browser, with one-time codes")
                : Text("May sign in as “\(grant.itemTitle)” at \(grant.origin), in its own browser"))
            .font(.caption)
            Text(
                "Signed in \(Int(grant.uses)) of \(Int(grant.totalUses)) · \(Int(grant.perRun)) per run · expires \(AuditView.timestamp(grant.expiresAt))"
            )
            .font(.caption2)
            .foregroundStyle(.secondary)
            if let reason = grant.suspendedReason {
                HStack {
                    Label(
                        "Suspended: \(UnattendedText.suspension(reason))",
                        systemImage: "exclamationmark.octagon.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                    Button("Re-enable…") {
                        Task { await unattended.reenable(grantId: grant.id, session: store.session) }
                    }
                    .help("Let the job sign in again, after Touch ID")
                    .accessibilityIdentifier("ks.unattended.loginGrant.reenable")
                }
            }
        }
    }
}

/// Arm, with what it means said first (ui-spec.md §10.8).
///
/// The sheet is `UnattendedService.armSheetShown`, and **Arm** closes it before the presence
/// prompt rather than after: nothing is left behind the prompt, and nothing dismisses a sheet
/// that is already gone.
struct ArmSheet: View {
    @Environment(UnattendedService.self) private var unattended
    let store: VaultStore

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Arm unattended jobs?").font(.title3.weight(.semibold))
            Text(UnattendedText.armCost)
            Text(UnattendedText.commandCost)
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { unattended.armSheetShown = false }
                    .keyboardShortcut(.cancelAction)
                Button("Arm") {
                    let session = store.session
                    unattended.armSheetShown = false
                    Task { await unattended.arm(session: session) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(unattended.arming)
                .accessibilityIdentifier("ks.unattended.arm.confirm")
            }
        }
        .padding(20)
        .frame(width: 480)
    }
}

/// "While you were away" (ADR-0042 §9): what the machine log recorded since the last look.
struct WhileAwaySheet: View {
    @Environment(UnattendedService.self) private var unattended
    let store: VaultStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("While you were away").font(.title3.weight(.semibold))
            if let summary = unattended.summary {
                Text(
                    "\(Int(summary.runs)) run(s), \(Int(summary.releases)) release(s), \(Int(summary.refusals)) refusal(s), \(Int(summary.suspensions)) suspension(s)."
                )
                .accessibilityIdentifier("ks.unattended.whileAway.counts")
                if summary.suspensions > 0 {
                    Text(
                        "A suspended job may have been steered. If it signs in to anything, reset that account's password at the service."
                    )
                    .font(.callout)
                    .foregroundStyle(.orange)
                }
                List(summary.rows, id: \.seq) { row in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(row.detail ?? row.tool).font(.callout)
                        Text(
                            "\(AuditView.timestamp(row.timestamp)) · \(row.actor)"
                                + (row.variables.isEmpty ? "" : " · \(row.variables.joined(separator: ", "))")
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    }
                }
                .frame(minHeight: 220)
            }
            HStack {
                Spacer()
                Button("Done") { unattended.acknowledge(session: store.session) }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("ks.unattended.whileAway.done")
            }
        }
        .padding(20)
        .frame(width: 560, height: 460)
    }
}

import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Unattended jobs in the app (ADR-0042 Phase 3; ui-spec.md §10.8).
///
/// # What is under test
///
/// * arming asks for presence and only then stores the key in the Keychain; a cancelled check
///   arms nothing and stores nothing;
/// * pausing asks for nothing and deletes the Keychain item; so does a `DISARMED` notice;
/// * at launch the Keychain's bytes re-arm, and an item the engine no longer accepts is deleted;
/// * creating a job, copying an environment and re-enabling a grant each need presence first;
/// * "While you were away" is offered after an unlock only when there is something in it;
/// * the new-job form's rules, the mandatory interpreter warning, the schedule text, and the Audit
///   view's Unattended filter.
///
/// Every FFI and system call goes through `UnattendedService`'s seams: nothing here starts an
/// engine, opens a machine vault or touches the real Keychain.
@MainActor
struct UnattendedTests {
    typealias ScriptedGate = BiometricGateAdversarialTests.ScriptedGate
    typealias RecordingNotifier = AgentFillSwitchAndNoticesTests.RecordingNotifier

    /// An in-memory Keychain.
    final class MemoryKeyStore: ArmKeyStore {
        var stored: Data?
        var deletes = 0
        func read() -> Data? { stored }
        func save(_ bytes: Data) throws { stored = bytes }
        func delete() {
            deletes += 1
            stored = nil
        }
    }

    /// What crossed the seams.
    final class Calls {
        var armed = 0
        var disarmed = 0
        var resumed: [Data] = []
        var resumeAnswer = true
        var created: [UnattendedJobDraft] = []
        var copied: [String] = []
        var reenabled: [String] = []
        var notices: [UnattendedNoticeView] = []
        var summaryTotal: UInt32 = 0
        var loginRegistered = 0
        var loginUnregistered = 0
        var stale: [String] = []
        var copiedLogins: [String] = []
    }

    static let key = Data((0..<48).map { UInt8($0) })

    static func session() throws -> VaultSession {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ks-unattended-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return try VaultSession.create(
            path: dir.appendingPathComponent("p.kagivault").path, masterPassword: "pw",
            vaultName: "Personal", kdfMKib: 64, kdfT: 1)
    }

    static func scratchDefaults() -> UserDefaults {
        let name = "ks-unattended-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

    static func service(
        gate: BiometricGate, store: MemoryKeyStore, calls: Calls,
        notifier: RecordingNotifier = RecordingNotifier(),
        defaults: UserDefaults = scratchDefaults()
    ) -> UnattendedService {
        let service = UnattendedService(
            presence: PresenceCoordinator(gate: gate), keyStore: store, notifier: notifier,
            defaults: defaults)
        service.registerLoginItem = { calls.loginRegistered += 1 }
        service.unregisterLoginItem = { calls.loginUnregistered += 1 }
        service.loginItemStatus = { calls.loginRegistered > calls.loginUnregistered }
        service.fetchStale = { _, _ in calls.stale }
        service.startEngine = { _ in }
        service.resumeEngine = {
            calls.resumed.append($0)
            return calls.resumeAnswer
        }
        service.armEngine = { _ in
            calls.armed += 1
            return Self.key
        }
        service.disarmEngine = { _ in
            calls.disarmed += 1
            return true
        }
        service.fetchStatus = {
            UnattendedStatusView(
                running: true, armed: calls.armed > calls.disarmed, armedAt: nil, endpoint: "",
                runs: [])
        }
        service.takeNotices = {
            defer { calls.notices = [] }
            return calls.notices
        }
        service.fetchOverview = { _ in
            UnattendedOverviewView(hasMachineVault: true, environments: [], jobs: [])
        }
        service.fetchSummary = { _ in
            UnattendedSummaryView(
                rows: [], total: calls.summaryTotal, runs: 0, releases: 0, refusals: 0,
                suspensions: 0)
        }
        service.acknowledgeSummary = { _ in calls.summaryTotal = 0 }
        service.copyEnvironment = { _, id in
            calls.copied.append(id)
            return "machine-env"
        }
        service.createJob = { _, draft in
            calls.created.append(draft)
            return "job"
        }
        service.reenableGrant = { _, id in
            calls.reenabled.append(id)
            return true
        }
        service.attachToAgent = { _ in }
        service.fetchLogins = { _ in [] }
        service.fetchLoginGrants = { _ in [] }
        service.copyLoginItem = { _, id in
            calls.copiedLogins.append(id)
            return "machine-login"
        }
        service.defaultRunBrowser = { "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" }
        return service
    }

    // MARK: - Arming and the Keychain

    @Test func armingAsksForPresenceAndThenKeepsTheKeyInTheKeychain() async throws {
        let gate = ScriptedGate(.authenticated)
        let store = MemoryKeyStore()
        let calls = Calls()
        let notifier = RecordingNotifier()
        let service = Self.service(gate: gate, store: store, calls: calls, notifier: notifier)

        await service.arm(session: try Self.session())

        #expect(gate.reasons == [UnattendedService.armReason])
        #expect(calls.armed == 1)
        #expect(store.stored == Self.key)
        #expect(service.status.armed)
        #expect(notifier.authorizationRequests == 1, "notifications are asked for when arming")
    }

    @Test func oneArmShowsTheSheetOnceAndClosesItBeforeThePrompt() async throws {
        let session = try Self.session()
        let calls = Calls()
        let service = Self.service(
            gate: ScriptedGate(.authenticated), store: MemoryKeyStore(), calls: calls)
        service.requestArm()
        service.requestArm()
        #expect(service.armSheetShown)

        // Two presses of Arm (a double click, Return twice): one arm, and no sheet left behind.
        async let first: Void = service.arm(session: session)
        async let second: Void = service.arm(session: session)
        _ = await (first, second)
        #expect(calls.armed == 1)
        #expect(!service.armSheetShown)
        #expect(!service.arming)

        // Armed: Arm… shows nothing.
        service.requestArm()
        #expect(!service.armSheetShown)
    }

    @Test func aCancelledCheckArmsNothingAndStoresNothing() async throws {
        let store = MemoryKeyStore()
        let calls = Calls()
        let service = Self.service(gate: ScriptedGate(.cancelled), store: store, calls: calls)

        await service.arm(session: try Self.session())

        #expect(calls.armed == 0)
        #expect(store.stored == nil)
        #expect(service.problem != nil)
    }

    @Test func pausingAsksNothingAndForgetsTheKey() {
        let gate = ScriptedGate(.cancelled)
        let store = MemoryKeyStore()
        store.stored = Self.key
        let calls = Calls()
        let service = Self.service(gate: gate, store: store, calls: calls)

        service.pause(session: nil)

        #expect(gate.reasons.isEmpty, "narrowing asks for nothing")
        #expect(calls.disarmed == 1)
        #expect(store.stored == nil)
    }

    @Test func launchReArmsFromTheKeychainAndForgetsAKeyTheEngineRefuses() {
        let store = MemoryKeyStore()
        store.stored = Self.key
        let calls = Calls()
        let service = Self.service(gate: ScriptedGate(.cancelled), store: store, calls: calls)

        service.launch(vaultPath: "/tmp/p.kagivault", tick: false)
        #expect(calls.resumed == [Self.key])
        #expect(store.stored == Self.key, "still armed: the item stays")

        calls.resumeAnswer = false
        service.launch(vaultPath: "/tmp/p.kagivault", tick: false)
        #expect(store.stored == nil, "disarmed elsewhere: the item goes")
    }

    @Test func anEngineDisarmDeletesTheKeyAndIsAnnounced() async {
        let store = MemoryKeyStore()
        store.stored = Self.key
        let calls = Calls()
        let notifier = RecordingNotifier()
        let service = Self.service(
            gate: ScriptedGate(.cancelled), store: store, calls: calls, notifier: notifier)
        calls.notices = [
            UnattendedNoticeView(kind: "DISARMED", job: nil, reason: "LOCK_REQUEST"),
            UnattendedNoticeView(kind: "SUSPENDED", job: "nightly", reason: "NO_GRANT"),
        ]

        service.tick()
        try? await Task.sleep(for: .milliseconds(50))

        #expect(store.stored == nil)
        #expect(service.unseenNotices == 2)
        #expect(service.attention == 2)
        #expect(service.recentNotices.first?.kind == "SUSPENDED")
        #expect(notifier.posts.count == 2)
        #expect(notifier.posts.contains { $0.body.contains("nightly") })
        service.markSeen()
        #expect(service.attention == 0)
    }

    // MARK: - The login item

    @Test func theFirstArmOpensTheAppAtLoginAndOnlyTheToggleChangesItAfter() async throws {
        let calls = Calls()
        let defaults = Self.scratchDefaults()
        let service = Self.service(
            gate: ScriptedGate(.authenticated), store: MemoryKeyStore(), calls: calls,
            defaults: defaults)
        let session = try Self.session()

        await service.arm(session: session)
        #expect(calls.loginRegistered == 1)
        #expect(service.loginItemEnabled)

        service.setLoginItem(false)
        #expect(calls.loginUnregistered == 1)
        #expect(!service.loginItemEnabled)

        // Pausing and arming again does not put it back: the person turned it off.
        service.pause(session: session)
        await service.arm(session: session)
        #expect(calls.loginRegistered == 1)
        #expect(!service.loginItemEnabled)

        service.setLoginItem(true)
        #expect(calls.loginRegistered == 2)
        #expect(service.loginItemEnabled)
    }

    // MARK: - Copies

    @Test func sharedSourcesAreReadFromTheirKey() {
        #expect(
            UnattendedService.sharedSource("shared:0a1b:6f1c1f0e-0000-4000-8000-000000000000")?.0
                == "0a1b")
        #expect(
            UnattendedService.sharedSource("shared:0a1b:6f1c1f0e-0000-4000-8000-000000000000")?.1
                == "6f1c1f0e-0000-4000-8000-000000000000")
        #expect(UnattendedService.sharedSource("6f1c1f0e-0000-4000-8000-000000000000") == nil)
        #expect(UnattendedService.sharedSource("shared::x") == nil)
    }

    @Test func staleCopiesAreReadOnRefreshAndForgottenOnLock() throws {
        let calls = Calls()
        calls.stale = ["machine-env"]
        let service = Self.service(
            gate: ScriptedGate(.cancelled), store: MemoryKeyStore(), calls: calls)
        service.refresh(session: try Self.session())
        #expect(service.staleCopies == ["machine-env"])
        service.vaultLocked()
        #expect(service.staleCopies.isEmpty)
    }

    // MARK: - Decisions

    @Test func creatingAJobNeedsPresenceFirst() async throws {
        let session = try Self.session()
        var form = NewJobForm()
        form.name = "Nightly"
        form.program = "/bin/sh"
        form.folder = "/tmp"
        form.environmentId = "env"
        let draft = try form.draft().get()

        let refused = Calls()
        let cancelled = Self.service(
            gate: ScriptedGate(.cancelled), store: MemoryKeyStore(), calls: refused)
        #expect(await cancelled.create(draft, session: session) == false)
        #expect(refused.created.isEmpty)

        let calls = Calls()
        let service = Self.service(
            gate: ScriptedGate(.authenticated), store: MemoryKeyStore(), calls: calls)
        #expect(await service.create(draft, session: session))
        #expect(calls.created == [draft])
    }

    @Test func copyingAndReenablingNeedPresenceFirst() async throws {
        let session = try Self.session()
        let calls = Calls()
        let service = Self.service(
            gate: ScriptedGate(.cancelled), store: MemoryKeyStore(), calls: calls)
        await service.copy(environmentId: "e", session: session)
        await service.reenable(grantId: "g", session: session)
        #expect(calls.copied.isEmpty)
        #expect(calls.reenabled.isEmpty)

        let allowed = Self.service(
            gate: ScriptedGate(.authenticated), store: MemoryKeyStore(), calls: calls)
        await allowed.copy(environmentId: "e", session: session)
        await allowed.reenable(grantId: "g", session: session)
        #expect(calls.copied == ["e"])
        #expect(calls.reenabled == ["g"])
    }

    @Test func whileYouWereAwayIsOfferedOnlyWhenThereIsSomething() throws {
        let session = try Self.session()
        let calls = Calls()
        let service = Self.service(
            gate: ScriptedGate(.cancelled), store: MemoryKeyStore(), calls: calls)

        service.vaultUnlocked(session: session)
        #expect(!service.showWhileAway)

        calls.summaryTotal = 4
        service.vaultUnlocked(session: session)
        #expect(service.showWhileAway)
        #expect(service.attention == 4)

        service.acknowledge(session: session)
        #expect(!service.showWhileAway)
        #expect(service.attention == 0)

        service.vaultLocked()
        #expect(service.summary == nil)
        #expect(service.overview == nil)
    }

    // MARK: - The form and the words

    @Test func theFormNamesWhatIsMissingAndDefaultsTheGrantToTheProgram() throws {
        var form = NewJobForm()
        guard case .failure = form.draft() else {
            Issue.record("an empty form must not make a draft")
            return
        }
        form.name = "  Deploy  "
        form.program = "/usr/local/bin/agent"
        form.argumentsText = "--prompt\n\n  /opt/jobs/deploy.md  \n"
        form.folder = "/opt/jobs"
        form.environmentId = "env-1"
        form.weekday = 6
        form.hour = 23
        form.minute = 45
        let draft = try form.draft().get()
        #expect(draft.name == "Deploy")
        #expect(draft.arguments == ["--prompt", "/opt/jobs/deploy.md"])
        #expect(draft.command == nil, "the program itself is the granted command")
        #expect(draft.commandArguments == nil)
        #expect(draft.schedule == [UnattendedTimeView(weekday: 6, hour: 23, minute: 45)])
        #expect(draft.variables.isEmpty, "every variable of the environment")

        form.sameCommand = false
        guard case .failure = form.draft() else {
            Issue.record("a separate command needs a full path")
            return
        }
        form.command = "/usr/local/bin/deploy"
        form.commandArgumentsText = "--prod"
        let separate = try form.draft().get()
        #expect(separate.command == "/usr/local/bin/deploy")
        #expect(separate.commandArguments == ["--prod"])
    }

    // MARK: - Unattended sign-ins (ADR-0042 §12)

    @Test func aJobThatOnlySignsInNeedsASiteAndABrowserAndCarriesOneLoginGrant() throws {
        var form = NewJobForm()
        form.name = "Post"
        form.program = "/usr/local/bin/agent"
        form.folder = "/opt/jobs"
        guard case .failure(let none) = form.draft() else {
            Issue.record("neither an environment nor a login")
            return
        }
        #expect(none.message.contains("or a login"))
        form.loginItemId = "login-1"
        guard case .failure(let site) = form.draft() else {
            Issue.record("a login needs its site")
            return
        }
        #expect(site.message == "Choose the site it signs in to.")
        form.loginOrigin = "https://service.example"
        guard case .failure(let browser) = form.draft() else {
            Issue.record("a login needs a browser")
            return
        }
        #expect(browser.message == "Choose the browser it signs in with.")
        form.runBrowser = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
        let draft = try form.draft().get()
        #expect(draft.environmentId.isEmpty, "no command grant")
        #expect(draft.runBrowser == form.runBrowser)
        #expect(
            draft.logins == [
                UnattendedLoginDraft(
                    itemId: "login-1", origin: "https://service.example", followOnOrigins: [],
                    oneTimeCodes: false)
            ])
        // The one-time-code switch is carried only when turned on.
        form.oneTimeCodes = true
        #expect(try form.draft().get().logins.first?.oneTimeCodes == true)
        // A job with an environment and no login has no run browser.
        var plain = NewJobForm()
        plain.name = "Deploy"
        plain.program = "/bin/sh"
        plain.folder = "/tmp"
        plain.environmentId = "env"
        plain.runBrowser = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
        let command = try plain.draft().get()
        #expect(command.runBrowser == nil)
        #expect(command.logins.isEmpty)
    }

    @Test func copyingALoginNeedsPresenceFirst() async throws {
        let session = try Self.session()
        let calls = Calls()
        let refused = Self.service(gate: ScriptedGate(.cancelled), store: MemoryKeyStore(), calls: calls)
        await refused.copyLogin(itemId: "item", session: session)
        #expect(calls.copiedLogins.isEmpty)
        #expect(refused.problem != nil)

        let allowed = Self.service(gate: ScriptedGate(.authenticated), store: MemoryKeyStore(), calls: calls)
        await allowed.copyLogin(itemId: "item", session: session)
        #expect(calls.copiedLogins == ["item"])
    }

    @Test func loginGrantsAreReadOnRefreshListedByJobAndForgottenOnLock() throws {
        let session = try Self.session()
        let calls = Calls()
        let service = Self.service(gate: ScriptedGate(.cancelled), store: MemoryKeyStore(), calls: calls)
        let grant = UnattendedLoginGrantView(
            id: "g", jobId: "job-1", itemId: "i", itemTitle: "Service bot",
            origin: "https://service.example", followOnOrigins: [], fields: ["username", "password"],
            oneTimeCodes: false, uses: 0, totalUses: 60, perRun: 1, expiresAt: 0,
            suspendedReason: "OTHER_ORIGIN")
        service.fetchLoginGrants = { _ in [grant] }
        service.refresh(session: session)
        #expect(service.loginGrants(ofJob: "job-1") == [grant])
        #expect(service.loginGrants(ofJob: "job-2").isEmpty)
        #expect(UnattendedText.suspension("OTHER_ORIGIN").contains("Reset this account's password"))
        service.vaultLocked()
        #expect(service.loginGrants.isEmpty)
        #expect(service.logins.isEmpty)
    }

    @Test func theLoginSheetCarriesTheADRSentencesVerbatim() {
        #expect(UnattendedText.loginCost.hasPrefix("Under a login grant, kagisecure types"))
        #expect(UnattendedText.loginAdvice.hasPrefix("The job's agent can read this password."))
        #expect(UnattendedText.oneTimeCodeCost.contains("second factor no longer protects it"))
    }

    @Test func theInterpreterBoxCarriesTheADRSentence() {
        #expect(UnattendedText.interpreterCost.hasPrefix("A grant for an interpreter is a grant for whatever it reads."))
        #expect(UnattendedText.interpreterCost.hasSuffix("and nothing will be suspended."))
    }

    @Test func interpretersAreRecognizedForTheWarning() {
        for path in ["/bin/sh", "/bin/zsh", "/usr/bin/env", "/opt/homebrew/bin/node",
            "/usr/bin/python3", "/usr/local/bin/python3.12", "/opt/homebrew/bin/npx",
        ] {
            #expect(UnattendedText.isInterpreter(path), "\(path)")
        }
        for path in ["/usr/local/bin/deploy", "/usr/local/bin/claude", "/usr/bin/shasum"] {
            #expect(!UnattendedText.isInterpreter(path), "\(path)")
        }
    }

    @Test func schedulesReadAsWords() {
        #expect(
            UnattendedText.schedule([UnattendedTimeView(weekday: nil, hour: 2, minute: 5)])
                == "Every day at 02:05")
        #expect(
            UnattendedText.schedule([UnattendedTimeView(weekday: 0, hour: 12, minute: 0)])
                == "Mondays at 12:00")
        #expect(UnattendedText.schedule([]) == "Never")
    }

    @Test func theAuditFilterFindsUnattendedEntries() {
        #expect(AuditView.actorMatches("mcp unattended \"nightly\" run 1 pid 4 /bin/sh", "unattended"))
        #expect(AuditView.actorMatches("unattended", "unattended"))
        #expect(!AuditView.actorMatches("mcp", "unattended"))
        #expect(!AuditView.actorMatches("app", "unattended"))
        #expect(AuditView.actorMatches("mcp unattended \"x\" run 1", "mcp"), "still an agent")
    }
}

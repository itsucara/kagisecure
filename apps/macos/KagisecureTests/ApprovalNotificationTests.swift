import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Records approval notices instead of posting them.
@MainActor
final class RecordingApprovalNotifier: AgentFillNotifier {
    var posted: [(id: String, title: String, body: String)] = []
    var withdrawn: [String] = []
    func requestAuthorization() async {}
    func post(title: String, body: String) async {}
    func postApproval(id: String, title: String, body: String) {
        posted.append((id, title, body))
    }
    func withdrawApproval(id: String) { withdrawn.append(id) }
}

/// An approval sheet raises exactly one notification, a sheet-less grant none, and the
/// notification is withdrawn when the sheet is answered or times out.
@MainActor
struct ApprovalNotificationTests {
    private static func service() -> (AgentService, RecordingApprovalNotifier, Counter) {
        let service = AgentService()
        let notifier = RecordingApprovalNotifier()
        let counter = Counter()
        service.approvalNotifier = notifier
        service.bringApprovalForward = { counter.n += 1 }
        service.resolver = { _, _, _ in true }
        return (service, notifier, counter)
    }

    final class Counter { var n = 0 }

    @Test func aSheetRaisesOneNotificationNamingTheAgentAndBringsTheAppForward() {
        let (service, notifier, counter) = Self.service()
        let request = StoreCommandOutputApprovalTests.request()
        service.enqueue(request)
        #expect(notifier.posted.count == 1)
        #expect(notifier.posted[0].id == request.id)
        #expect(notifier.posted[0].body == ApprovalSheet.sentence(for: request))
        #expect(notifier.posted[0].body.contains("Claude Code"))
        #expect(counter.n == 1)
        // A tick-driven refresh does not post the same sheet twice.
        service.dropExpired()
        #expect(notifier.posted.count == 1)
    }

    @Test func answeringTheSheetWithdrawsTheNotification() {
        let (service, notifier, _) = Self.service()
        let request = StoreCommandOutputApprovalTests.request()
        service.enqueue(request)
        service.deny(request)
        #expect(notifier.withdrawn == [request.id])
    }

    @Test func aTimedOutSheetWithdrawsTheNotification() {
        let (service, notifier, _) = Self.service()
        let now = UInt64(Date.now.timeIntervalSince1970)
        let base = StoreCommandOutputApprovalTests.request()
        var expired = base
        expired.expiresAt = now - 1
        service.enqueue(expired)
        #expect(notifier.posted.count == 1)
        service.dropExpired()
        #expect(notifier.withdrawn == [expired.id])
    }

    @Test func stoppingWithdrawsTheNotification() {
        let (service, notifier, _) = Self.service()
        let request = StoreCommandOutputApprovalTests.request()
        service.enqueue(request)
        service.stop()
        #expect(notifier.withdrawn == [request.id])
    }

    @Test func aSheetlessRequestRaisesNothing() {
        let (service, notifier, counter) = Self.service()
        var request = ApprovalRenderingAdversarialTests.fillRequest(itemTitle: "Example", origin: "https://example.com", presenceOnly: true)
        request.expiresAt = UInt64(Date.now.timeIntervalSince1970) + 60
        service.enqueue(request)
        #expect(notifier.posted.isEmpty)
        #expect(counter.n == 0)
        service.stop()
    }
}

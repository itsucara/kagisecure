import AppKit
import SwiftUI

/// A small floating panel in the top-right corner that never takes focus or blocks the app:
/// “Updating Kagisecure…” while an update installs at launch, and an offer to relaunch when one
/// is ready while the app runs.
@MainActor
final class UpdateIndicator {
    private var panel: NSPanel?

    func showInstalling() {
        show(UpdateIndicatorView(state: .installing))
    }

    func showReady(relaunch: @escaping @MainActor () -> Void) {
        show(UpdateIndicatorView(state: .ready(relaunch: relaunch, later: { [weak self] in self?.hide() })))
    }

    func hide() {
        panel?.orderOut(nil)
        panel = nil
    }

    private func show(_ view: UpdateIndicatorView) {
        hide()
        let hosting = NSHostingView(rootView: view)
        hosting.frame.size = hosting.fittingSize
        let panel = NSPanel(
            contentRect: NSRect(origin: .zero, size: hosting.fittingSize),
            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false
        )
        panel.contentView = hosting
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        if let screen = NSScreen.main?.visibleFrame {
            let margin: CGFloat = 16
            panel.setFrameOrigin(
                NSPoint(
                    x: screen.maxX - hosting.fittingSize.width - margin,
                    y: screen.maxY - hosting.fittingSize.height - margin))
        }
        panel.orderFrontRegardless()
        self.panel = panel
    }
}

private struct UpdateIndicatorView: View {
    enum State {
        case installing
        case ready(relaunch: @MainActor () -> Void, later: @MainActor () -> Void)
    }

    let state: State

    var body: some View {
        content
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .fixedSize()
    }

    @ViewBuilder private var content: some View {
        switch state {
        case .installing:
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text("Updating Kagisecure…")
            }
        case .ready(let relaunch, let later):
            VStack(alignment: .leading, spacing: 8) {
                Text("A new version is ready.")
                Text("It installs when you quit.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Later", action: later)
                    Button("Relaunch to Update", action: relaunch)
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
    }
}

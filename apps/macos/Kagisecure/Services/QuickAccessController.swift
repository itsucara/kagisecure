import AppKit
import SwiftUI

/// The floating Quick Access panel (ui-spec.md §7) and the global shortcut that summons it.
///
/// # Why an `NSPanel` and not a SwiftUI `Window` scene
///
/// The requirement is "does not raise the main window". A SwiftUI `Window` scene is an ordinary
/// `NSWindow`: showing it means activating the app, and activating the app brings every one of
/// its windows forward — including the three-pane one the user deliberately left behind. An
/// `NSPanel` with `.nonactivatingPanel` can take key focus *without* the app becoming active, so
/// the main window stays exactly where it was. That behaviour has no SwiftUI scene equivalent, so
/// this is one of the few places the app reaches for AppKit directly.
///
/// The panel is created lazily and destroyed on close: it holds a SwiftUI view over the unlocked
/// store, and a panel kept alive across a lock would be holding a reference to a session that is
/// supposed to be gone.
///
/// See `open()` for the one place reality did not match the specification: a non-activating panel
/// in an app that has a Dock icon cannot take keyboard focus, so the app is activated as a
/// fallback.
@MainActor
final class QuickAccessController {
    private var panel: NSPanel?
    private var hotKey: GlobalHotKey?

    /// Why the shortcut is not working, if it is not. Shown in Settings rather than swallowed.
    private(set) var hotKeyError: String?

    /// Whether the panel is on screen.
    private(set) var isOpen = false

    /// What the panel renders. Set by `AppModel` whenever the phase changes, so that a panel
    /// opened while locked shows the locked state rather than a stale list.
    private var content: (() -> AnyView)?

    /// Register ⇧⌘Space. Safe to call more than once.
    func registerHotKey(_ action: @escaping () -> Void) {
        guard hotKey == nil else { return }
        do {
            hotKey = try GlobalHotKey(
                keyCode: GlobalHotKey.quickAccess.keyCode,
                modifiers: GlobalHotKey.quickAccess.modifiers,
                action: action)
            hotKeyError = nil
        } catch {
            // Not fatal, and not silent: the menu-bar item and the Item menu still open Quick
            // Access, so the feature works — the shortcut is what is unavailable, and the user is
            // the only one who can free it up.
            hotKeyError = "⇧⌘Space is unavailable — \(error)."
        }
    }

    /// Supply the view the panel shows.
    func setContent<Content: View>(@ViewBuilder _ content: @escaping () -> Content) {
        self.content = { AnyView(content()) }
    }

    /// Show the panel, or hide it if it is already up: a shortcut that only opens is a shortcut
    /// that cannot be taken back.
    func toggle() {
        if isOpen {
            close()
        } else {
            open()
        }
    }

    func open() {
        guard let content else { return }
        let panel = self.panel ?? makePanel()
        self.panel = panel
        panel.contentView = NSHostingView(rootView: content())
        panel.center()
        // A panel positioned dead centre sits low; nudging it up puts it where Spotlight and
        // 1Password's own Quick Access appear, which is where the eye already is.
        if let screen = panel.screen ?? NSScreen.main {
            var frame = panel.frame
            frame.origin.y = screen.visibleFrame.midY + screen.visibleFrame.height * 0.08
            panel.setFrameOrigin(frame.origin)
        }
        // A `.nonactivatingPanel` is *supposed* to take keyboard focus while its app is in the
        // background. On macOS 26, for an app that has a Dock icon, it gets half of that: the
        // panel becomes the app's key window and its search field becomes the app's focused
        // element — `AXFocusedUIElement` says so — but the keystrokes still go to whichever app
        // is frontmost. A search panel you cannot type into is not a feature, so the app is
        // activated.
        //
        // What that costs, precisely: kagisecure becomes the frontmost application, so its main
        // window is drawn above other applications' windows. What it does *not* do is raise the
        // main window *within* the app — `makeKeyAndOrderFront` is never called on it, it never
        // becomes key, the panel stays in front of it, and a minimized or hidden main window
        // stays minimized or hidden. That is the part of ui-spec.md §7 this keeps and the part it
        // misses; ADR-0017 and the roadmap record the difference. An accessory (menu-bar-only)
        // app would not need this, which is a decision about whether kagisecure keeps a Dock
        // icon, not about Quick Access.
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        // Activation is asynchronous. Asking for key status before it lands gets it handed to the
        // main window the moment the app actually becomes active, which is how a panel ends up
        // visible, focused-looking, and swallowing nothing. One hop past the activation fixes it.
        DispatchQueue.main.async { panel.makeKeyAndOrderFront(nil) }
        isOpen = true
    }

    func close() {
        panel?.orderOut(nil)
        // The hosting view goes with it, so nothing keeps a reference to the unlocked store while
        // the panel is not on screen.
        panel?.contentView = nil
        isOpen = false
    }

    private func makePanel() -> NSPanel {
        let panel = KeyablePanel(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 420),
            styleMask: [.titled, .fullSizeContentView],
            backing: .buffered,
            defer: false)
        // `becomesKeyOnlyIfNeeded` is what stops a panel taking keyboard focus when the app
        // thinks nothing in it wants any; a search field wants it the moment the panel opens.
        panel.becomesKeyOnlyIfNeeded = false
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        // `.titled` is what gives the panel rounded corners and a shadow; the buttons that come
        // with it are not wanted, because Esc is the way out and a Spotlight-style panel with a
        // close button reads as a window the user is supposed to keep.
        for button in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] {
            panel.standardWindowButton(button)?.isHidden = true
        }
        // Transparent, so the view's own `.regularMaterial` is what the user sees rather than a
        // flat grey behind it.
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        // NOT `hidesOnDeactivate`. The whole point of a non-activating panel is that it opens
        // while another app is frontmost, so "hide when this app is not active" would close it in
        // the same breath as opening it. Esc and a second ⇧⌘Space are the ways out.
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.animationBehavior = .utilityWindow
        return panel
    }
}

/// `NSPanel` refuses key status by default unless it is a utility panel; Quick Access is a search
/// field and is useless without it.
private final class KeyablePanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

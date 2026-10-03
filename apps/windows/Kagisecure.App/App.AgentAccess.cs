using System;
using Kagisecure.App.Services;
using Kagisecure.App.Views;
using Microsoft.UI.Dispatching;

namespace Kagisecure.App;

/// <summary>
/// The agent side of the composition root: the listeners' host and approval sheet (ui-spec.md
/// §10), and Windows Hello unlock (ADR-0004, ADR-0033). Kept out of <c>App.xaml.cs</c> so the
/// item side of the app and this side do not edit the same lines.
/// </summary>
public partial class App
{
    private ApprovalPresenter? approvalPresenter;

    /// <summary>The vault's agent-facing half (environments, the Locking hook, the session for the listeners).</summary>
    internal IAgentVaultAccess AgentVault => (IAgentVaultAccess)VaultService;

    /// <summary>The two process-global listeners.</summary>
    internal IAgentRuntime AgentRuntime { get; private set; } = null!;

    /// <summary>Starts/stops the listeners with the vault and owns the approval queue.</summary>
    internal AgentHostService AgentHost { get; private set; } = null!;

    /// <summary>Windows Hello unlock.</summary>
    internal WindowsHelloService WindowsHello { get; private set; } = null!;

    /// <summary>The main window's HWND, for the release prompt's Windows Hello dialog to come up in front of.</summary>
    private static IntPtr WindowForPrompts() =>
        CurrentWindow is { } window ? WinRT.Interop.WindowNative.GetWindowHandle(window) : IntPtr.Zero;

    /// <summary>
    /// Build the agent side. Call on the UI thread before the first window is created: the lock
    /// screen asks <see cref="WindowsHello"/> whether to offer Hello as soon as it exists.
    /// </summary>
    private void InitializeAgentAccess()
    {
        WindowsHello = new WindowsHelloService(
            new WindowsHelloKeys(),
            new DpapiWindowsHelloSecretStore(),
            (IWindowsHelloVault)VaultService,
            // Fixed strings and exception type names only; see WindowsHelloService.Log.
            line => System.Diagnostics.Debug.WriteLine($"kagisecure: {line}"));

        // One prompt at a time, app-wide: the approval sheet's Windows Hello and the release
        // gate's (ADR-0037 §3, ADR-0038 §6) take the same slot, and a second is refused.
        var promptGuard = new PresencePromptGuard();
        DispatcherQueue uiQueue = DispatcherQueue.GetForCurrentThread();

        // ADR-0038: every unlocked session gets a presence gate before it is published, so no
        // concealed value, one-time code or note leaves the vault without a fresh Windows Hello
        // verification (or, only where Hello cannot run, the master password).
        var releaseHello = new WindowsHelloConsentGate(WindowForPrompts);
        var passwordPrompt = new ContentDialogMasterPasswordPrompt(() => CurrentWindow?.Content?.XamlRoot);
        ((VaultService)VaultService).PresenceGateFactory =
            session => new WindowsHelloPresenceGate(session, releaseHello, promptGuard, uiQueue, passwordPrompt);

        AgentRuntime = new AgentRuntime(() => AgentVault.SessionForListeners);
        AgentHost = new AgentHostService(
            AgentRuntime,
            new SerializedConsentGate(
                new WindowsHelloConsentGate(() => approvalPresenter?.OwnerWindowHandle() ?? IntPtr.Zero),
                promptGuard),
            AgentVault,
            new DispatcherQueueAgentDispatcher(uiQueue));
        approvalPresenter = new ApprovalPresenter(AgentHost, () => CurrentWindow);

        // Start on unlock, stop on lock — before the session is released — and lock when
        // `kagisecure lock` asks over IPC.
        AgentHost.Bind(VaultService);
    }
}

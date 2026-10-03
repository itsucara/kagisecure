using Kagisecure.App.Services;
using Microsoft.UI.Xaml;

namespace Kagisecure.App;

/// <summary>
/// The composition root. No DI container: the app is small enough that field assignment here is
/// clearer than a container's indirection, and it keeps <c>Kagisecure.App.Tests</c> from needing
/// one either — tests construct view models directly against a fake <see cref="IVaultService"/>.
/// </summary>
public partial class App : Application
{
    private Window? window;

    /// <summary>
    /// The composition root, for pages to pull their services from in their constructor — before
    /// <c>InitializeComponent</c>, the same way <see cref="Views.GeneratorView"/> already does —
    /// rather than through a <c>Frame.Navigate</c> parameter read in <c>OnNavigatedTo</c>. There is
    /// exactly one of each service for the process's lifetime, so a navigation parameter buys
    /// nothing here; constructing the view model before <c>InitializeComponent</c> means every
    /// x:Bind resolves on first layout and no page needs <c>Bindings.Update()</c>.
    /// </summary>
    internal static App Instance => (App)Application.Current;

    /// <summary>The single top-level window, for the rare bit of code (file/folder pickers) that needs an HWND.</summary>
    internal static Window? CurrentWindow { get; private set; }

    /// <summary>The one <see cref="IVaultService"/> instance for the process's lifetime.</summary>
    internal IVaultService VaultService { get; } = new VaultService();

    /// <summary>The one <see cref="IClipboardService"/> instance for the process's lifetime.</summary>
    internal IClipboardService ClipboardService { get; } = new ClipboardService();

    /// <summary>The one <see cref="ISettingsService"/> instance for the process's lifetime.</summary>
    internal ISettingsService SettingsService { get; } = new SettingsService();

    private AutoLockService? autoLockService;

    public App()
    {
        // As early as possible: an exception thrown from inside a data-bound property or an
        // event handler and left unhandled brings the whole process down with a native fail-fast
        // (Microsoft.UI.Xaml.dll, exit 0xc000027b) that carries no managed stack trace of its
        // own — this is the only way to have one on disk afterwards. See
        // Services.CrashLogger and apps/windows/README.md's "Run the app" section.
        CrashLogger.Install();
        UnhandledException += (_, e) =>
        {
            CrashLogger.Write("Application.UnhandledException", e.Exception, isTerminating: true);
            // Deliberately not setting e.Handled = true: swallowing an exception the XAML
            // framework itself doesn't understand how to recover from would leave the app in an
            // unknown state. The point of this handler is to get the log written before the
            // process goes down, not to keep running.
        };

        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        ClipboardService.ClearAfterSeconds = SettingsService.ClipboardClearSeconds;

        autoLockService = new AutoLockService(VaultService, SettingsService);
        InitializeAgentAccess(); // App.AgentAccess.cs — before the window, whose lock screen asks about Windows Hello.

        window = new MainWindow(VaultService, ClipboardService);
        CurrentWindow = window;
        autoLockService.WatchWindow(window);
        window.Closed += (_, _) =>
        {
            // ui-spec.md §6.2: unconditional lock on app quit.
            VaultService.Lock();
            autoLockService?.Dispose();
        };
        window.Activate();
    }
}

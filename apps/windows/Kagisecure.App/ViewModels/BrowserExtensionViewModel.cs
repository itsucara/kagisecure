using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Agent access › Browser extension — the macOS <c>BrowserExtensionView</c> minus Safari: the
/// listener's state, the native host binary, the pinned extension id, and for each browser the
/// manifest file and the <c>HKEY_CURRENT_USER</c> key that points the browser at it, with Set up /
/// Remove buttons. What the button writes is exactly the record on screen.
/// </summary>
public sealed class BrowserExtensionViewModel : ObservableObject, IDisposable
{
    private readonly IAgentRuntime runtime;
    private readonly AgentHostService host;
    private ExtensionSetup? setup;
    private string? lastError;
    private bool isBusy;

    public BrowserExtensionViewModel(IAgentRuntime runtime, AgentHostService host, Action<string> copyText)
    {
        this.runtime = runtime;
        this.host = host;
        CopyHostPathCommand = new RelayCommand(() => copyText(NmhostPath ?? string.Empty), () => NmhostPath is not null);
        CopyExtensionIdCommand = new RelayCommand(() => copyText(ExtensionId ?? string.Empty), () => ExtensionId is not null);
        host.PropertyChanged += OnHostPropertyChanged;
    }

    public ObservableCollection<BrowserManifestRowViewModel> Browsers { get; } = new();

    public string? NmhostPath => setup?.NmhostPath;

    public bool HostMissing => setup is not null && setup.NmhostPath is null;

    public string? ExtensionId => setup?.ExtensionId;

    public string? HostName => setup?.HostName;

    public const string Intro =
        "The extension asks this app which of your items apply to the page you are on, and gets back "
        + "titles and usernames. A password crosses only when you click to fill it and approve it "
        + "here — once per website, per unlock. Nothing is stored in the browser.";

    public const string HostMissingText =
        "kagisecure-nmhost.exe was not found next to this app, on your PATH, or at KAGISECURE_NMHOST. "
        + "Build it with `cargo build -p kagisecure-nmhost` and point KAGISECURE_NMHOST at it, or "
        + "install the released app.";

    public const string ExtensionIdHelp =
        "Check this against the ID your browser shows on its Extensions page. It is fixed by a key "
        + "committed in the extension's manifest, so it is the same whether the extension is loaded "
        + "unpacked or installed from a store — and any other extension is refused.";

    public string ListenerTitle => host.ExtensionStartupError is not null
        ? "The extension cannot reach this app"
        : host.ExtensionStatus.Running ? "Listening for browsers" : "Not listening";

    public string ListenerDetail => host.ExtensionStartupError
        ?? (host.ExtensionStatus.Running
            ? $"{host.ExtensionStatus.Endpoint} · {host.ExtensionStatus.ConnectedHosts} connected"
            : "The extension cannot reach this app while the vault is locked.");

    public bool HasListenerError => host.ExtensionStartupError is not null;

    public string? LastError
    {
        get => lastError;
        private set => SetProperty(ref lastError, value);
    }

    public bool IsBusy
    {
        get => isBusy;
        private set => SetProperty(ref isBusy, value);
    }

    public RelayCommand CopyHostPathCommand { get; }

    public RelayCommand CopyExtensionIdCommand { get; }

    /// <summary>Re-read the setup table (and the "installed" ticks). Off the UI thread.</summary>
    public async Task RefreshAsync()
    {
        try
        {
            ExtensionSetup fresh = await Task.Run(runtime.ExtensionSetup).ConfigureAwait(true);
            setup = fresh;
            Browsers.Clear();
            foreach (BrowserManifest manifest in fresh.Manifests)
            {
                Browsers.Add(new BrowserManifestRowViewModel(this, manifest));
            }

            OnPropertyChanged(nameof(NmhostPath));
            OnPropertyChanged(nameof(HostMissing));
            OnPropertyChanged(nameof(ExtensionId));
            OnPropertyChanged(nameof(HostName));
            CopyHostPathCommand.NotifyCanExecuteChanged();
            CopyExtensionIdCommand.NotifyCanExecuteChanged();
        }
        catch (KagisecureException ex)
        {
            LastError = ex.Message;
        }
    }

    /// <summary>Write the manifest and its registry value — exactly the record the row is showing.</summary>
    internal Task InstallAsync(BrowserManifest manifest) => Change(() => runtime.InstallManifest(manifest));

    /// <summary>Remove the manifest and its registry value. Missing is success.</summary>
    internal Task UninstallAsync(BrowserManifest manifest) => Change(() => runtime.UninstallManifest(manifest));

    private async Task Change(Action change)
    {
        IsBusy = true;
        LastError = null;
        try
        {
            await Task.Run(change).ConfigureAwait(true);
        }
        catch (KagisecureException ex)
        {
            LastError = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }

        await RefreshAsync().ConfigureAwait(true);
    }

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AgentHostService.ExtensionStatus) or nameof(AgentHostService.ExtensionStartupError))
        {
            OnPropertyChanged(nameof(ListenerTitle));
            OnPropertyChanged(nameof(ListenerDetail));
            OnPropertyChanged(nameof(HasListenerError));
        }
    }

    public void Dispose() => host.PropertyChanged -= OnHostPropertyChanged;
}

/// <summary>One browser: whether it is installed, whether it is set up, and what the button writes.</summary>
public sealed class BrowserManifestRowViewModel
{
    public BrowserManifestRowViewModel(BrowserExtensionViewModel owner, BrowserManifest manifest)
    {
        Manifest = manifest;
        InstallCommand = new AsyncRelayCommand(() => owner.InstallAsync(manifest));
        UninstallCommand = new AsyncRelayCommand(() => owner.UninstallAsync(manifest));
    }

    public BrowserManifest Manifest { get; }

    public string Browser => Manifest.Browser;

    public bool Installed => Manifest.Installed;

    public bool NotInstalled => !Manifest.Installed;

    public string StateText => Manifest.Installed
        ? "Set up"
        : Manifest.BrowserInstalled ? "Not set up yet" : "Not installed on this PC";

    public string ManifestPath => Manifest.Path;

    /// <summary>The <c>HKEY_CURRENT_USER</c> key the button also sets, in full.</summary>
    public string RegistryKeyText => Manifest.RegistryKey is { } key
        ? $@"HKEY_CURRENT_USER\{key}"
        : "No registry key: this browser is not pointed at the manifest through the registry.";

    public string Body => Manifest.Body;

    public AsyncRelayCommand InstallCommand { get; }

    public AsyncRelayCommand UninstallCommand { get; }
}

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
/// Agent access › Set up your agent (mcp-server.md §9) — the macOS <c>AgentSetupView</c>: where the
/// sidecar is for this install, whether this app is listening, and the exact snippet for each MCP
/// client with a copy button. The snippets come from <c>kagisecure-agent::setup</c>, the table the
/// CLI's <c>mcp install --print</c> reads, so the app and the CLI cannot drift.
/// </summary>
public sealed class McpSetupViewModel : ObservableObject, IDisposable
{
    private readonly IAgentRuntime runtime;
    private readonly AgentHostService host;
    private readonly Action<string> copyText;
    private string? sidecarPath;
    private bool loaded;
    private string? errorMessage;

    /// <param name="copyText">
    /// Straight to the clipboard, not through the auto-clearing secret path: a configuration snippet
    /// is not secret, and clearing it after a minute would break the one thing the user is about to
    /// do with it — paste it into an editor.
    /// </param>
    public McpSetupViewModel(IAgentRuntime runtime, AgentHostService host, Action<string> copyText)
    {
        this.runtime = runtime;
        this.host = host;
        this.copyText = copyText;
        CopySidecarCommand = new RelayCommand(() => Copy(SidecarPath ?? string.Empty), () => SidecarPath is not null);
        host.PropertyChanged += OnHostPropertyChanged;
    }

    public ObservableCollection<McpSnippetRowViewModel> Snippets { get; } = new();

    public string? SidecarPath
    {
        get => sidecarPath;
        private set
        {
            if (SetProperty(ref sidecarPath, value))
            {
                OnPropertyChanged(nameof(SidecarMissing));
                CopySidecarCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool SidecarMissing => loaded && SidecarPath is null;

    public const string SidecarMissingText =
        "kagisecure-mcp.exe was not found next to this app, on your PATH, or at KAGISECURE_MCP. The "
        + "snippets below show where a normal install puts it; build it with `cargo build -p "
        + "kagisecure-mcp` if you are running from source, and set KAGISECURE_MCP to the result.";

    public const string Intro =
        "kagisecure ships a small MCP server. Your agent spawns it; it talks to this app over a local "
        + "named pipe; and every injection raises the approval sheet you confirm with Windows Hello. "
        + "The agent never receives a value — only names.";

    public const string Footer =
        "The vault must be unlocked for any of this to work. A locked vault answers VAULT_LOCKED and "
        + "kills every lease it had granted.";

    public string ListenerText => host.StartupError is { } error
        ? $"This app cannot listen: {error}"
        : host.AgentStatus.Running
            ? $"This app is listening on {host.AgentStatus.Endpoint}"
            : "This app is not listening. Agents will get APP_NOT_RUNNING.";

    public bool IsListening => host.AgentStatus.Running;

    public string? ErrorMessage
    {
        get => errorMessage;
        private set => SetProperty(ref errorMessage, value);
    }

    public RelayCommand CopySidecarCommand { get; }

    /// <summary>Read the setup table. Off the UI thread: it searches the disk for the sidecar.</summary>
    public async Task LoadAsync()
    {
        try
        {
            McpSetup setup = await Task.Run(runtime.McpSetup).ConfigureAwait(true);
            loaded = true;
            SidecarPath = setup.SidecarPath;
            OnPropertyChanged(nameof(SidecarMissing));
            Snippets.Clear();
            foreach (McpSnippet snippet in setup.Snippets)
            {
                Snippets.Add(new McpSnippetRowViewModel(snippet, Copy));
            }
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    private void Copy(string text) => copyText(text);

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AgentHostService.AgentStatus) or nameof(AgentHostService.StartupError))
        {
            OnPropertyChanged(nameof(ListenerText));
            OnPropertyChanged(nameof(IsListening));
        }
    }

    public void Dispose() => host.PropertyChanged -= OnHostPropertyChanged;
}

/// <summary>One MCP client's snippet.</summary>
public sealed class McpSnippetRowViewModel
{
    public McpSnippetRowViewModel(McpSnippet snippet, Action<string> copy)
    {
        Snippet = snippet;
        CopyCommand = new RelayCommand(() => copy(snippet.Body));
    }

    public McpSnippet Snippet { get; }

    public string Title => Snippet.Title;

    public string Language => Snippet.Language;

    public string Body => Snippet.Body;

    public string WhereText => Snippet.ConfigPath is { } path
        ? $"Put it in {path}"
        : "This client keeps its own registry — run the command instead of editing a file.";

    public RelayCommand CopyCommand { get; }
}

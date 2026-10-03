using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Agent access › Environments (ui-spec.md §10.4) — the macOS <c>AgentAccessView</c> and
/// <c>EnvironmentEditor</c>: the listener banner and the vault-level "Share this vault" gate, the
/// environment list, and an editor for one — share toggle, each variable with its binding, the
/// pending flow (an agent named a variable and the value is typed <i>here</i>, never in the chat),
/// add a literal variable, remove one, create and delete environments.
/// </summary>
public sealed class EnvironmentsViewModel : ObservableObject, IDisposable
{
    private readonly IAgentVaultAccess vault;
    private readonly AgentHostService host;
    private VaultEnvironment? selected;
    private bool vaultShared;
    private string newEnvironmentName = string.Empty;
    private string newVariableName = string.Empty;
    private string newVariableValue = string.Empty;
    private string? errorMessage;
    private bool isBusy;
    private bool suppressShareWrites;

    public EnvironmentsViewModel(IAgentVaultAccess vault, AgentHostService host)
    {
        this.vault = vault;
        this.host = host;
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        CreateCommand = new AsyncRelayCommand(CreateAsync, () => !IsBusy && NewEnvironmentName.Trim().Length > 0);
        AddVariableCommand = new AsyncRelayCommand(AddVariableAsync, () => !IsBusy && Selected is not null && NewVariableName.Trim().Length > 0 && NewVariableValue.Length > 0);
        DeleteCommand = new AsyncRelayCommand(DeleteAsync, () => !IsBusy && Selected is not null);
        host.PropertyChanged += OnHostPropertyChanged;
    }

    public ObservableCollection<VaultEnvironment> Environments { get; } = new();

    public ObservableCollection<EnvironmentVariableRowViewModel> Variables { get; } = new();

    public AsyncRelayCommand RefreshCommand { get; }

    public AsyncRelayCommand CreateCommand { get; }

    public AsyncRelayCommand AddVariableCommand { get; }

    public AsyncRelayCommand DeleteCommand { get; }

    public bool IsEmpty => Environments.Count == 0;

    public const string EmptyMessage =
        "An environment is a named set of variables an agent can ask to have written into a project. "
        + "Create one, or let an agent create it for you.";

    public const string NewEnvironmentNote =
        "New environments are not shared with agents. Turn sharing on once you have put something in it.";

    // --- Listener banner ------------------------------------------------------------------------

    public bool ListenerRunning => host.AgentStatus.Running;

    public string ListenerTitle => host.StartupError is not null
        ? "Agents cannot reach this app"
        : host.AgentStatus.Running ? "Serving agents" : "Not serving agents";

    public string ListenerDetail => host.StartupError ?? (host.AgentStatus.Running ? host.AgentStatus.Endpoint : string.Empty);

    public bool HasListenerError => host.StartupError is not null;

    public string ActiveLeasesText => host.AgentStatus.ActiveLeases > 0 ? $"{host.AgentStatus.ActiveLeases} active" : string.Empty;

    /// <summary>The vault-level gate (threat-model M-9): with this off nothing in the vault is reachable, however an environment is flagged.</summary>
    public bool VaultShared
    {
        get => vaultShared;
        set
        {
            if (SetProperty(ref vaultShared, value) && !suppressShareWrites)
            {
                _ = RunAsync(() => vault.SetVaultAgentVisibleAsync(value));
            }
        }
    }

    // --- Selection and editor -------------------------------------------------------------------

    public VaultEnvironment? Selected
    {
        get => selected;
        set
        {
            if (SetProperty(ref selected, value))
            {
                RebuildVariables();
                OnPropertyChanged(nameof(HasSelection));
                OnPropertyChanged(nameof(SelectedShared));
                OnPropertyChanged(nameof(SelectedShareNote));
                AddVariableCommand.NotifyCanExecuteChanged();
                DeleteCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool HasSelection => Selected is not null;

    /// <summary>The selected environment's "Share with agents" switch.</summary>
    public bool SelectedShared
    {
        get => Selected?.AgentVisible ?? false;
        set
        {
            if (Selected is { } env && env.AgentVisible != value && !suppressShareWrites)
            {
                _ = RunAsync(async () => ReplaceSelected(await vault.SetEnvironmentAgentVisibleAsync(env.Id, value).ConfigureAwait(true)));
            }
        }
    }

    public string SelectedShareNote => Selected?.AgentVisible == true
        ? "Agents can see this environment's name and its variable names. Never a value."
        : "Hidden from agents entirely — they cannot see that it exists.";

    public string NewEnvironmentName
    {
        get => newEnvironmentName;
        set
        {
            if (SetProperty(ref newEnvironmentName, value ?? string.Empty))
            {
                CreateCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string NewVariableName
    {
        get => newVariableName;
        set
        {
            if (SetProperty(ref newVariableName, value ?? string.Empty))
            {
                AddVariableCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>A value typed into the app, going straight into the vault. Cleared once saved.</summary>
    public string NewVariableValue
    {
        get => newVariableValue;
        set
        {
            if (SetProperty(ref newVariableValue, value ?? string.Empty))
            {
                AddVariableCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string? ErrorMessage
    {
        get => errorMessage;
        private set => SetProperty(ref errorMessage, value);
    }

    public bool IsBusy
    {
        get => isBusy;
        private set
        {
            if (SetProperty(ref isBusy, value))
            {
                CreateCommand.NotifyCanExecuteChanged();
                AddVariableCommand.NotifyCanExecuteChanged();
                DeleteCommand.NotifyCanExecuteChanged();
            }
        }
    }

    // --- Operations -----------------------------------------------------------------------------

    public async Task RefreshAsync()
    {
        await RunAsync(async () =>
        {
            string? keep = Selected?.Id;
            var environments = await vault.EnvironmentsAsync().ConfigureAwait(true);
            bool shared = await vault.VaultAgentVisibleAsync().ConfigureAwait(true);
            Environments.Clear();
            foreach (VaultEnvironment env in environments)
            {
                Environments.Add(env);
            }

            suppressShareWrites = true;
            try
            {
                VaultShared = shared;
                Selected = Environments.FirstOrDefault(e => e.Id == keep) ?? Environments.FirstOrDefault();
            }
            finally
            {
                suppressShareWrites = false;
            }

            OnPropertyChanged(nameof(IsEmpty));
        }).ConfigureAwait(true);
    }

    private Task CreateAsync() => RunAsync(async () =>
    {
        VaultEnvironment created = await vault.CreateEnvironmentAsync(NewEnvironmentName.Trim(), null).ConfigureAwait(true);
        NewEnvironmentName = string.Empty;
        Environments.Add(created);
        Selected = created;
        OnPropertyChanged(nameof(IsEmpty));
    });

    private Task AddVariableAsync()
    {
        if (Selected is not { } env)
        {
            return Task.CompletedTask;
        }

        string name = NewVariableName.Trim();
        string value = NewVariableValue;
        NewVariableValue = string.Empty;
        return RunAsync(async () =>
        {
            ReplaceSelected(await vault.SetVariableValueAsync(env.Id, name, value).ConfigureAwait(true));
            NewVariableName = string.Empty;
        });
    }

    private Task DeleteAsync()
    {
        if (Selected is not { } env)
        {
            return Task.CompletedTask;
        }

        return RunAsync(async () =>
        {
            await vault.DeleteEnvironmentAsync(env.Id).ConfigureAwait(true);
            Environments.Remove(env);
            Selected = Environments.FirstOrDefault();
            OnPropertyChanged(nameof(IsEmpty));
        });
    }

    internal Task SavePendingAsync(EnvironmentVariableRowViewModel row)
    {
        if (Selected is not { } env || row.PendingValue.Length == 0)
        {
            return Task.CompletedTask;
        }

        string value = row.PendingValue;
        row.PendingValue = string.Empty;
        return RunAsync(async () => ReplaceSelected(await vault.SetVariableValueAsync(env.Id, row.Name, value).ConfigureAwait(true)));
    }

    internal Task RemoveAsync(EnvironmentVariableRowViewModel row)
    {
        if (Selected is not { } env)
        {
            return Task.CompletedTask;
        }

        return RunAsync(async () => ReplaceSelected(await vault.RemoveVariableAsync(env.Id, row.Name).ConfigureAwait(true)));
    }

    private void ReplaceSelected(VaultEnvironment updated)
    {
        int index = Environments.ToList().FindIndex(e => e.Id == updated.Id);
        suppressShareWrites = true;
        try
        {
            if (index >= 0)
            {
                Environments[index] = updated;
            }

            selected = null; // force the setter to rebuild even though the id is the same
            Selected = updated;
        }
        finally
        {
            suppressShareWrites = false;
        }
    }

    private void RebuildVariables()
    {
        foreach (EnvironmentVariableRowViewModel row in Variables)
        {
            row.PendingValue = string.Empty;
        }

        Variables.Clear();
        if (Selected is null)
        {
            return;
        }

        foreach (EnvironmentVariable variable in Selected.Variables)
        {
            Variables.Add(new EnvironmentVariableRowViewModel(this, variable));
        }
    }

    private async Task RunAsync(Func<Task> body)
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            await body().ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AgentHostService.AgentStatus) or nameof(AgentHostService.StartupError))
        {
            OnPropertyChanged(nameof(ListenerRunning));
            OnPropertyChanged(nameof(ListenerTitle));
            OnPropertyChanged(nameof(ListenerDetail));
            OnPropertyChanged(nameof(HasListenerError));
            OnPropertyChanged(nameof(ActiveLeasesText));
        }
    }

    public void Dispose()
    {
        host.PropertyChanged -= OnHostPropertyChanged;
        foreach (EnvironmentVariableRowViewModel row in Variables)
        {
            row.PendingValue = string.Empty;
        }

        NewVariableValue = string.Empty;
    }
}

/// <summary>One variable in the environment editor: name, binding badge, and for a pending one the agent's hint and a box to type the value into.</summary>
public sealed class EnvironmentVariableRowViewModel : ObservableObject
{
    private string pendingValue = string.Empty;

    public EnvironmentVariableRowViewModel(EnvironmentsViewModel owner, EnvironmentVariable variable)
    {
        Variable = variable;
        SaveCommand = new AsyncRelayCommand(() => owner.SavePendingAsync(this), () => PendingValue.Length > 0);
        RemoveCommand = new AsyncRelayCommand(() => owner.RemoveAsync(this));
    }

    public EnvironmentVariable Variable { get; }

    public string Name => Variable.Name;

    public bool IsPending => Variable.Binding == VarBinding.Pending;

    public string BindingText => Variable.Binding switch
    {
        VarBinding.Pending => "Pending",
        VarBinding.ItemField => "Linked to an item",
        _ => "Stored here",
    };

    /// <summary>The agent's hint, quoted — it is what the agent said, not what the app says.</summary>
    public string? HintLine => IsPending && Variable.Hint is { } hint ? $"The agent says: “{ApprovalText.Safe(hint, 200)}”" : null;

    public string PendingPlaceholder => $"Paste the value for {Name}";

    /// <summary>Typed here, in kagisecure. The agent that asked for it never sees it.</summary>
    public string PendingValue
    {
        get => pendingValue;
        set
        {
            if (SetProperty(ref pendingValue, value ?? string.Empty))
            {
                SaveCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public AsyncRelayCommand SaveCommand { get; }

    public AsyncRelayCommand RemoveCommand { get; }
}

/// <summary>Row text for the environment list, for x:Bind function bindings.</summary>
public static class EnvironmentsFormat
{
    /// <summary>"3 variables · 1 pending · shared with agents" / "No variables · hidden from agents".</summary>
    public static string RowDetail(int variableCount, uint pendingCount, bool agentVisible)
    {
        string variables = variableCount == 0 ? "No variables" : $"{variableCount} variable{(variableCount == 1 ? string.Empty : "s")}";
        string pending = pendingCount > 0 ? $" · {pendingCount} pending" : string.Empty;
        return $"{variables}{pending} · {(agentVisible ? "shared with agents" : "hidden from agents")}";
    }
}

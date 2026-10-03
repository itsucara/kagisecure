using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Agent access › Leases (ui-spec.md §10.4): every live lease and every live fill lease, with a
/// live countdown and Revoke per row, and Revoke all. Leases are memory-only; this is the only
/// place they are visible.
/// </summary>
public sealed class LeasesViewModel : ObservableObject, IDisposable
{
    private readonly AgentHostService host;

    public LeasesViewModel(AgentHostService host)
    {
        this.host = host;
        RevokeAllCommand = new RelayCommand(host.RevokeAll, () => HasAny);
        host.Leases.CollectionChanged += OnLeasesChanged;
        host.FillLeases.CollectionChanged += OnLeasesChanged;
        host.PropertyChanged += OnHostPropertyChanged;
        Rebuild();
    }

    public ObservableCollection<LeaseRowViewModel> Leases { get; } = new();

    public ObservableCollection<FillLeaseRowViewModel> FillLeases { get; } = new();

    public bool HasAny => Leases.Count > 0 || FillLeases.Count > 0;

    public bool IsEmpty => !HasAny;

    public bool HasLeases => Leases.Count > 0;

    public bool HasFillLeases => FillLeases.Count > 0;

    /// <summary>Drop every lease, shred every file they wrote, and make the next browser fill ask again.</summary>
    public RelayCommand RevokeAllCommand { get; }

    public const string EmptyMessage =
        "A lease is minted when you approve an injection or a browser fill, and dies on expiry, use "
        + "exhaustion, or when the vault locks. Nothing is granted right now.";

    private void OnLeasesChanged(object? sender, NotifyCollectionChangedEventArgs e) => Rebuild();

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AgentHostService.Now))
        {
            foreach (LeaseRowViewModel row in Leases)
            {
                row.Tick(host.Now);
            }

            foreach (FillLeaseRowViewModel row in FillLeases)
            {
                row.Tick(host.Now);
            }
        }
    }

    private void Rebuild()
    {
        Leases.Clear();
        foreach (Lease lease in host.Leases)
        {
            Leases.Add(new LeaseRowViewModel(lease, host.Now, () => host.Revoke(lease)));
        }

        FillLeases.Clear();
        foreach (FillLease lease in host.FillLeases)
        {
            FillLeases.Add(new FillLeaseRowViewModel(lease, host.Now, () => host.Revoke(lease)));
        }

        OnPropertyChanged(nameof(HasAny));
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasLeases));
        OnPropertyChanged(nameof(HasFillLeases));
        RevokeAllCommand.NotifyCanExecuteChanged();
    }

    public void Dispose()
    {
        host.Leases.CollectionChanged -= OnLeasesChanged;
        host.FillLeases.CollectionChanged -= OnLeasesChanged;
        host.PropertyChanged -= OnHostPropertyChanged;
    }

    /// <summary>"12 minutes", "45 s", or "expired" — the same wording as the sheet.</summary>
    public static string Remaining(ulong expiresAt, DateTimeOffset now)
    {
        long seconds = (long)expiresAt - now.ToUnixTimeSeconds();
        return seconds <= 0 ? "expired" : ApprovalText.Duration((ulong)seconds);
    }
}

/// <summary>One env/run lease row.</summary>
public sealed class LeaseRowViewModel : ObservableObject
{
    private string remaining;
    private bool isUrgent;

    public LeaseRowViewModel(Lease lease, DateTimeOffset now, Action revoke)
    {
        Lease = lease;
        RevokeCommand = new RelayCommand(revoke);
        remaining = LeasesViewModel.Remaining(lease.ExpiresAt, now);
        isUrgent = (long)lease.ExpiresAt - now.ToUnixTimeSeconds() < 60;
    }

    public Lease Lease { get; }

    public string Caller => Lease.ClientIdentity;

    public string KindText => Lease.Kind == "env-file" ? ".env file" : "command";

    public string Directory => Lease.Directory;

    public string Variables => string.Join(", ", Lease.Variables);

    public string UsesLeft => Lease.UsesRemaining.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public string Remaining
    {
        get => remaining;
        private set => SetProperty(ref remaining, value);
    }

    public bool IsUrgent
    {
        get => isUrgent;
        private set => SetProperty(ref isUrgent, value);
    }

    public RelayCommand RevokeCommand { get; }

    public void Tick(DateTimeOffset now)
    {
        Remaining = LeasesViewModel.Remaining(Lease.ExpiresAt, now);
        IsUrgent = (long)Lease.ExpiresAt - now.ToUnixTimeSeconds() < 60;
    }
}

/// <summary>One browser-fill lease row.</summary>
public sealed class FillLeaseRowViewModel : ObservableObject
{
    private string remaining;
    private bool isUrgent;

    public FillLeaseRowViewModel(FillLease lease, DateTimeOffset now, Action revoke)
    {
        Lease = lease;
        RevokeCommand = new RelayCommand(revoke);
        remaining = LeasesViewModel.Remaining(lease.ExpiresAt, now);
        isUrgent = (long)lease.ExpiresAt - now.ToUnixTimeSeconds() < 60;
    }

    public FillLease Lease { get; }

    public string Website => Lease.Origin;

    public string Item => Lease.ItemTitle;

    public string Browser => Lease.ClientIdentity;

    public string Fields => string.Join(", ", Lease.Fields);

    public string Remaining
    {
        get => remaining;
        private set => SetProperty(ref remaining, value);
    }

    public bool IsUrgent
    {
        get => isUrgent;
        private set => SetProperty(ref isUrgent, value);
    }

    public RelayCommand RevokeCommand { get; }

    public void Tick(DateTimeOffset now)
    {
        Remaining = LeasesViewModel.Remaining(Lease.ExpiresAt, now);
        IsUrgent = (long)Lease.ExpiresAt - now.ToUnixTimeSeconds() < 60;
    }
}

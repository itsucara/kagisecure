using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;
using Microsoft.UI.Dispatching;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// One field row in the item detail pane (ui-spec.md §4.2). Nothing concealed is on it until the
/// person asks and confirms with Windows Hello (ADR-0038): Reveal, Copy and a one-time code each
/// go through a presence-gated release, and a shown value hides itself after five minutes, when
/// the selection moves on, and when the vault locks. A TOTP row shows its live code only after
/// "Show code", recomputed from the wall clock every second rather than counted down, for at most
/// five minutes.
/// </summary>
public sealed partial class FieldRowViewModel : ObservableObject, IDisposable
{
    private const string Mask = "••••••••••"; // ui-spec.md §4.2: length-independent — does not leak length.
    private const string TotpMask = "••• •••";

    private readonly IVaultService vaultService;
    private readonly IClipboardService clipboardService;
    private readonly string itemId;
    private readonly DispatcherQueueTimer? timer;
    private IFieldRelease? shownField;
    private ITotpRelease? shownTotp;
    private bool disposed;

    public FieldRowViewModel(IVaultService vaultService, IClipboardService clipboardService, string itemId, Field field)
    {
        this.vaultService = vaultService;
        this.clipboardService = clipboardService;
        this.itemId = itemId;
        Field = field;

        // One tick a second: the live code's refresh, and the check that ends a shown value at its
        // five-minute cap. Guarded rather than assumed: outside a live WinUI message loop (a
        // view-model test host) there is no DispatcherQueue for the current thread, and depending
        // on the host this can throw rather than return null. Without it a shown value still ends
        // in Rust at the cap; only the on-screen hide waits for the next interaction.
        if (field.Concealed)
        {
            try
            {
                DispatcherQueue? queue = DispatcherQueue.GetForCurrentThread();
                timer = queue?.CreateTimer();
                if (timer is not null)
                {
                    timer.Interval = TimeSpan.FromSeconds(1);
                    timer.IsRepeating = true;
                    timer.Tick += (_, _) => _ = TickAsync();
                }
            }
            catch (Exception)
            {
                timer = null;
            }
        }
    }

    public Field Field { get; }

    public bool IsTotp => Field.Kind == FieldKind.Totp;

    [ObservableProperty]
    private string? revealedValue;

    [ObservableProperty]
    private bool isRevealing;

    [ObservableProperty]
    private string? copiedNotice;

    [ObservableProperty]
    private TotpCode? totpCode;

    [ObservableProperty]
    private string? totpError;

    /// <summary>What the row shows: the plain value, the revealed value, or a length-independent mask.</summary>
    public string DisplayValue
    {
        get
        {
            if (!Field.Concealed)
            {
                return Field.Value ?? string.Empty;
            }

            return RevealedValue ?? Mask;
        }
    }

    public bool CanReveal => !IsTotp && Field.Concealed && Field.HasValue && RevealedValue is null && !IsRevealing;

    /// <summary>
    /// Whether the reveal button should be shown at all: concealed fields, but not a one-time
    /// password, whose row shows the code (behind "Show code") rather than its setup seed.
    /// </summary>
    public bool ShowRevealButton => !IsTotp && Field.Concealed && Field.HasValue;

    /// <summary>Whether the plain copy button applies — not for TOTP, which has its own copy affordance.</summary>
    public bool ShowCopyButton => !IsTotp && (Field.HasValue || !Field.Concealed);

    /// <summary>Whether a TOTP row's "Show code" button applies: a one-time password whose code is not showing.</summary>
    public bool ShowTotpButton => IsTotp && Field.HasValue && TotpCode is null;

    /// <summary>"123 456" — grouped for readability, matching TotpFieldView's presentation; masked until shown.</summary>
    public string TotpGrouped => TotpCode is null ? TotpMask : Group(TotpCode.Code);

    public string? TotpCaption => TotpCode?.Params.Caption;

    public double TotpFraction =>
        TotpCode is null || TotpCode.Params.Period == 0 ? 0 : (double)TotpCode.SecondsRemaining / TotpCode.Params.Period;

    public bool TotpExpiring => TotpCode is not null && TotpCode.SecondsRemaining <= 5;

    public string TotpSecondsText => TotpCode is null ? string.Empty : TotpCode.SecondsRemaining.ToString();

    [RelayCommand]
    private async Task RevealAsync()
    {
        if (!CanReveal)
        {
            return;
        }

        IsRevealing = true;
        OnPropertyChanged(nameof(CanReveal));
        try
        {
            IFieldRelease release = await vaultService.ReleaseFieldAsync(itemId, Field.Id, ReleasePurpose.Reveal).ConfigureAwait(true);
            string value;
            try
            {
                value = await Task.Run(release.Value).ConfigureAwait(true);
            }
            catch
            {
                release.Dispose();
                throw;
            }

            if (disposed)
            {
                release.Dispose();
                return;
            }

            HideField();
            shownField = release;
            RevealedValue = value;
            timer?.Start();
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            // Cancelled, unavailable, busy or locked: leave it masked. Nothing was released.
        }
        finally
        {
            IsRevealing = false;
            RefreshFieldState();
        }
    }

    /// <summary>
    /// Copy. A value already shown under a live release is copied with no new touch (ADR-0038 user
    /// decision 1); anything else is its own one-use release, with its own Windows Hello prompt.
    /// </summary>
    [RelayCommand]
    private async Task CopyAsync()
    {
        try
        {
            if (!Field.Concealed)
            {
                string plain = Field.Value ?? string.Empty;
                if (plain.Length > 0)
                {
                    Copied(plain);
                }

                return;
            }

            byte[] utf8;
            if (shownField is { } shown && await StillLiveAsync(shown.State).ConfigureAwait(true))
            {
                utf8 = await Task.Run(shown.CopyShownValueUtf8).ConfigureAwait(true);
            }
            else
            {
                using IFieldRelease release = await vaultService.ReleaseFieldAsync(itemId, Field.Id, ReleasePurpose.Copy).ConfigureAwait(true);
                utf8 = await Task.Run(release.ValueUtf8).ConfigureAwait(true);
            }

            try
            {
                if (utf8.Length > 0)
                {
                    Copied(System.Text.Encoding.UTF8.GetString(utf8));
                }
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(utf8);
            }
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            // Not confirmed, or nothing to copy. Nothing was released.
        }
    }

    /// <summary>"Show code": one Windows Hello prompt, then the live code for at most five minutes.</summary>
    [RelayCommand]
    private async Task ShowTotpAsync()
    {
        if (!ShowTotpButton)
        {
            return;
        }

        try
        {
            ITotpRelease release = await vaultService.ReleaseTotpAsync(itemId, Field.Id, ReleasePurpose.Reveal).ConfigureAwait(true);
            if (disposed)
            {
                release.Dispose();
                return;
            }

            HideTotp();
            shownTotp = release;
            await TickAsync().ConfigureAwait(true);
            timer?.Start();
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            TotpError = ex is KagisecureException.PresenceCancelled ? null : ex.Message;
        }
    }

    [RelayCommand]
    private async Task CopyTotpAsync()
    {
        try
        {
            ulong now = Now();
            TotpCode code;
            if (shownTotp is { } shown && await StillLiveAsync(shown.State).ConfigureAwait(true))
            {
                code = await Task.Run(() => shown.CopyShownCodeAt(now)).ConfigureAwait(true);
            }
            else
            {
                using ITotpRelease release = await vaultService.ReleaseTotpAsync(itemId, Field.Id, ReleasePurpose.Copy).ConfigureAwait(true);
                code = await Task.Run(() => release.CodeAt(now)).ConfigureAwait(true);
            }

            Copied(code.Code);
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            // Not confirmed, or the release ended. Nothing was released.
        }
    }

    private void Copied(string value)
    {
        clipboardService.CopySecret(value, Field.Label);
        CopiedNotice = $"Copied — clears in {clipboardService.ClearAfterSeconds}s";
    }

    /// <summary>Once a second while something is shown: refresh the code, and hide whatever has ended.</summary>
    private async Task TickAsync()
    {
        if (shownField is { } field && !await StillLiveAsync(field.State).ConfigureAwait(true))
        {
            HideField();
        }

        if (shownTotp is { } totp)
        {
            try
            {
                ulong now = Now();
                TotpCode = await Task.Run(() => totp.CodeAt(now)).ConfigureAwait(true);
                TotpError = null;
            }
            catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
            {
                // Ended: five minutes, a lock, or the field went. Back to the mask.
                HideTotp();
            }

            RefreshTotpState();
        }

        if (shownField is null && shownTotp is null)
        {
            timer?.Stop();
        }
    }

    private static async Task<bool> StillLiveAsync(Func<ReleaseState> state)
    {
        try
        {
            return (await Task.Run(state).ConfigureAwait(true)).IsLive;
        }
        catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
        {
            return false;
        }
    }

    private void HideField()
    {
        shownField?.Dispose();
        shownField = null;
        if (RevealedValue is not null)
        {
            RevealedValue = null;
            RefreshFieldState();
        }
    }

    private void HideTotp()
    {
        shownTotp?.Dispose();
        shownTotp = null;
        TotpCode = null;
        RefreshTotpState();
    }

    private void RefreshFieldState()
    {
        OnPropertyChanged(nameof(DisplayValue));
        // ShellPage.xaml binds the Reveal button's IsEnabled straight to CanReveal; that binding
        // only refreshes on its own PropertyChanged, which [ObservableProperty] never raises for a
        // hand-written computed property.
        OnPropertyChanged(nameof(CanReveal));
    }

    private void RefreshTotpState()
    {
        OnPropertyChanged(nameof(TotpGrouped));
        OnPropertyChanged(nameof(TotpCaption));
        OnPropertyChanged(nameof(TotpFraction));
        OnPropertyChanged(nameof(TotpExpiring));
        OnPropertyChanged(nameof(TotpSecondsText));
        OnPropertyChanged(nameof(ShowTotpButton));
    }

    private static ulong Now() => (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static string Group(string code)
    {
        // "123456" -> "123 456"; an odd-length code (7 digits) groups as "123 4567" — there is no
        // clean halfway split, and leading digits are the ones a glance reads first.
        int half = code.Length / 2;
        return half == 0 ? code : $"{code[..half]} {code[half..]}";
    }

    /// <summary>
    /// Hide and end whatever this row released, and stop its tick. Called when the detail pane's
    /// selection moves on, and when the shell is torn down at lock.
    /// </summary>
    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        timer?.Stop();
        shownField?.Dispose();
        shownField = null;
        shownTotp?.Dispose();
        shownTotp = null;
    }
}

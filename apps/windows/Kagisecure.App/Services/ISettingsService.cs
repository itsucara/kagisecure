namespace Kagisecure.App.Services;

/// <summary>
/// The app's own settings — auto-lock timeout, lock-on-minimize/sleep, clipboard clear timeout
/// (ui-spec.md §6.2, §settings.*) — read once at startup and written back on every change.
/// </summary>
public interface ISettingsService
{
    /// <summary>Idle minutes before auto-lock; 0 means "never" (ui-spec.md §6.2's picker choices).</summary>
    int AutoLockIdleMinutes { get; set; }

    /// <summary>Lock immediately when the main window is minimized, in addition to the unconditional sleep/screen-lock/quit rules <see cref="AutoLockService"/> already enforces.</summary>
    bool LockOnMinimize { get; set; }

    /// <summary>Seconds before a copied secret is cleared from the clipboard; 0 disables the clear.</summary>
    int ClipboardClearSeconds { get; set; }

    /// <summary>Persist the current values. Called after every setter above; exposed so a caller can force a flush.</summary>
    void Save();
}

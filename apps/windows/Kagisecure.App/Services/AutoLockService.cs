using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.Win32;

namespace Kagisecure.App.Services;

/// <summary>
/// Locks the vault, unconditionally, on system sleep and on the workstation being locked —
/// the Windows equivalents of the macOS app's "unconditional lock on system sleep, screen lock,
/// and app quit" rule (ui-spec.md §6.2; ADR-0004's "Common rules"). App-quit is handled
/// separately, at the window's <c>Closed</c> event, since that is a WinUI concern rather than a
/// system one; this service only owns the two OS-level notifications, plus the two
/// <see cref="ISettingsService"/>-configurable rules: idle timeout and lock-on-minimize.
/// </summary>
public sealed class AutoLockService : IDisposable
{
    private const int PollIntervalMilliseconds = 5000;

    private readonly IVaultService vaultService;
    private readonly ISettingsService settingsService;
    private readonly DispatcherQueueTimer? idleTimer;
    private AppWindow? appWindow;
    private bool subscribed;
    private bool wasMinimized;

    public AutoLockService(IVaultService vaultService, ISettingsService settingsService)
    {
        this.vaultService = vaultService;
        this.settingsService = settingsService;

        // SystemEvents marshals its callbacks onto a hidden message-only window's thread, not
        // necessarily the UI thread; VaultService.Lock() is thread-safe (internally locked), so
        // that's fine without an explicit dispatch back to the UI thread.
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        subscribed = true;

        // The idle timer runs on the UI thread (DispatcherQueueTimer), because GetLastInputInfo is
        // a cheap, thread-agnostic Win32 read — no need for a background thread for a 5-second poll.
        DispatcherQueue? queue = DispatcherQueue.GetForCurrentThread();
        idleTimer = queue?.CreateTimer();
        if (idleTimer is not null)
        {
            idleTimer.Interval = TimeSpan.FromMilliseconds(PollIntervalMilliseconds);
            idleTimer.IsRepeating = true;
            idleTimer.Tick += (_, _) => CheckIdle();
            idleTimer.Start();
        }
    }

    /// <summary>
    /// Watch the main window for minimize (ui-spec.md §6.2's lock-on-minimize, settings-gated —
    /// unlike sleep/screen-lock/quit, 1Password-style apps treat this as optional). Call once,
    /// after the window exists.
    /// </summary>
    public void WatchWindow(Microsoft.UI.Xaml.Window window)
    {
        appWindow = window.AppWindow;
        if (appWindow is not null)
        {
            appWindow.Changed += OnAppWindowChanged;
        }
    }

    private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (!args.DidPresenterChange || sender.Presenter is not OverlappedPresenter presenter)
        {
            return;
        }

        bool isMinimized = presenter.State == OverlappedPresenterState.Minimized;
        if (isMinimized && !wasMinimized && settingsService.LockOnMinimize)
        {
            vaultService.Lock();
        }

        wasMinimized = isMinimized;
    }

    private void CheckIdle()
    {
        int minutes = settingsService.AutoLockIdleMinutes;
        if (minutes <= 0 || !vaultService.IsUnlocked)
        {
            return; // 0 means "never", per ui-spec.md §6.2's picker.
        }

        uint idleMs = GetIdleMilliseconds();
        if (idleMs >= (uint)minutes * 60_000)
        {
            vaultService.Lock();
        }
    }

    private static uint GetIdleMilliseconds()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref info))
        {
            return 0; // Can't tell — never lock on a signal we couldn't read.
        }

        uint tickCount = (uint)Environment.TickCount;
        return tickCount - info.dwTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        // SessionLock: the workstation was locked (Win+L or idle policy). SessionLogoff: the
        // user is signing out. Both mean "nobody is looking at this session anymore."
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff)
        {
            vaultService.Lock();
        }
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend)
        {
            vaultService.Lock();
        }
    }

    public void Dispose()
    {
        idleTimer?.Stop();

        if (appWindow is not null)
        {
            appWindow.Changed -= OnAppWindowChanged;
            appWindow = null;
        }

        if (!subscribed)
        {
            return;
        }

        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        subscribed = false;
    }
}

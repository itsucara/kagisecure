using System;
using System.Runtime.InteropServices;
using Kagisecure.App.Services;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using WinRT.Interop;

namespace Kagisecure.App.Views;

/// <summary>
/// Shows the approval sheet (ui-spec.md §10.1) in its own always-on-top window, brought to the
/// front and flashed in the taskbar when a request arrives — rendered by this app, in its own
/// window, never by the agent's UI. One window, whose content is swapped when the head of the
/// queue changes, and which closes itself when the queue empties: answered, expired (the 60-second
/// window), or the vault locked. Closing it by hand is a Deny.
/// </summary>
/// <remarks>
/// A dedicated window rather than a <c>ContentDialog</c> on the main window: a XAML root can show
/// one <c>ContentDialog</c> at a time, and the sheet must be able to appear over whatever else the
/// app is showing, including when the main window is minimised or behind another app.
/// </remarks>
public sealed class ApprovalPresenter
{
    private readonly AgentHostService host;
    private readonly Func<Window?> mainWindow;
    private Window? window;
    private ApprovalViewModel? current;
    private bool closingProgrammatically;
    private bool closingByUser;

    public ApprovalPresenter(AgentHostService host, Func<Window?> mainWindow)
    {
        this.host = host;
        this.mainWindow = mainWindow;
        host.CurrentChanged += (_, _) => Update();
        host.AttentionRequested += (_, _) => RequestAttention();
    }

    /// <summary>The HWND the Windows Hello consent prompt is parented to: the sheet, else the main window.</summary>
    public IntPtr OwnerWindowHandle()
    {
        Window? target = window ?? mainWindow();
        return target is null ? IntPtr.Zero : WindowNative.GetWindowHandle(target);
    }

    private void Update()
    {
        if (closingByUser)
        {
            return; // Closed runs Update again once the window is gone.
        }

        ApprovalRequest? head = host.Current;
        if (head is null)
        {
            Close();
            return;
        }

        if (current?.Request.Id == head.Id)
        {
            return;
        }

        current?.Dispose();
        current = new ApprovalViewModel(host, head);
        EnsureWindow();
        window!.Content = new ApprovalView(current);
        window.Activate();
        RequestAttention();
    }

    private void EnsureWindow()
    {
        if (window is not null)
        {
            return;
        }

        var created = new Window { Title = "kagisecure — approval request" };
        if (Microsoft.UI.Composition.SystemBackdrops.MicaController.IsSupported())
        {
            created.SystemBackdrop = new MicaBackdrop();
        }

        AppWindow appWindow = created.AppWindow;
        PlaceOnScreen(created, appWindow);
        if (appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsAlwaysOnTop = true;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
        }

        appWindow.Closing += (_, _) =>
        {
            if (!closingProgrammatically)
            {
                // Saying no is always allowed; a sheet that vanished without an answer would leave
                // the caller waiting out its minute. The Deny advances the queue, and Update must
                // not put the next request into a window that is on its way out — it is shown
                // once this one has closed.
                closingByUser = true;
                current?.DenyIfStillPending();
            }
        };
        created.Closed += (_, _) =>
        {
            bool reopen = closingByUser;
            closingByUser = false;
            window = null;
            current?.Dispose();
            current = null;
            if (reopen)
            {
                // Another request may have been waiting behind the one just refused.
                Update();
            }
        };
        window = created;
    }

    /// <summary>
    /// 620 × 860 effective pixels, scaled for the monitor's DPI (AppWindow sizes are physical
    /// pixels), clamped to the work area and centred on it.
    /// </summary>
    private static void PlaceOnScreen(Window window, AppWindow appWindow)
    {
        double scale = Math.Max(1.0, GetDpiForWindow(WindowNative.GetWindowHandle(window)) / 96.0);
        Windows.Graphics.RectInt32 work = DisplayArea.GetFromWindowId(appWindow.Id, DisplayAreaFallback.Nearest).WorkArea;
        int width = Math.Min((int)(620 * scale), work.Width);
        int height = Math.Min((int)(860 * scale), work.Height);
        appWindow.MoveAndResize(new Windows.Graphics.RectInt32(
            work.X + ((work.Width - width) / 2), work.Y + ((work.Height - height) / 2), width, height));
    }

    private void Close()
    {
        current?.Dispose();
        current = null;
        if (window is null)
        {
            return;
        }

        closingProgrammatically = true;
        try
        {
            window.Close();
        }
        finally
        {
            closingProgrammatically = false;
            window = null;
        }
    }

    /// <summary>The Windows counterpart of <c>NSApp.requestUserAttention(.criticalRequest)</c>.</summary>
    private void RequestAttention()
    {
        if (window is not null)
        {
            IntPtr hwnd = WindowNative.GetWindowHandle(window);
            SetForegroundWindow(hwnd);
            Flash(hwnd);
        }

        if (mainWindow() is { } main)
        {
            Flash(WindowNative.GetWindowHandle(main));
        }
    }

    private static void Flash(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero)
        {
            return;
        }

        var info = new FlashWInfo
        {
            Size = (uint)Marshal.SizeOf<FlashWInfo>(),
            Hwnd = hwnd,
            Flags = FlashwAll | FlashwTimerNoFg,
            Count = 3,
            Timeout = 0,
        };
        FlashWindowEx(ref info);
    }

    private const uint FlashwAll = 0x3;
    private const uint FlashwTimerNoFg = 0xC;

    [StructLayout(LayoutKind.Sequential)]
    private struct FlashWInfo
    {
        public uint Size;
        public IntPtr Hwnd;
        public uint Flags;
        public uint Count;
        public uint Timeout;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlashWindowEx(ref FlashWInfo info);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hWnd);
}

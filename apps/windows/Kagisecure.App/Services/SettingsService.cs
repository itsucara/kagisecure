using System;
using System.IO;
using System.Text.Json;

namespace Kagisecure.App.Services;

/// <summary>
/// The real <see cref="ISettingsService"/>, a small JSON file under
/// <c>%LOCALAPPDATA%\Kagisecure</c> (same directory <see cref="CrashLogger"/> uses). Not
/// <c>Windows.Storage.ApplicationData</c>: this app is unpackaged
/// (<c>WindowsPackageType=None</c>, apps/windows/README.md), and <c>ApplicationData.Current</c>
/// throws with no package identity to hang settings off — a JSON file needs none of that and is
/// still a single, greppable place to look during support.
/// </summary>
public sealed class SettingsService : ISettingsService
{
    private const int DefaultAutoLockIdleMinutes = 10; // ui-spec.md §6.2's stated default.

    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kagisecure", "settings.json");

    private Model model;

    public SettingsService()
    {
        model = Load();
    }

    /// <inheritdoc />
    public int AutoLockIdleMinutes
    {
        get => model.AutoLockIdleMinutes;
        set
        {
            model.AutoLockIdleMinutes = value;
            Save();
        }
    }

    /// <inheritdoc />
    public bool LockOnMinimize
    {
        get => model.LockOnMinimize;
        set
        {
            model.LockOnMinimize = value;
            Save();
        }
    }

    /// <inheritdoc />
    public int ClipboardClearSeconds
    {
        get => model.ClipboardClearSeconds;
        set
        {
            model.ClipboardClearSeconds = value;
            Save();
        }
    }

    /// <inheritdoc />
    public void Save()
    {
        try
        {
            string? directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(model));
        }
        catch (Exception)
        {
            // Settings are a convenience, not vault data; a failed write (e.g. a locked-down
            // profile directory) should not take the app down. The in-memory values still apply
            // for this run — only persistence across launches is lost.
        }
    }

    private static Model Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                string json = File.ReadAllText(SettingsPath);
                Model? loaded = JsonSerializer.Deserialize<Model>(json);
                if (loaded is not null)
                {
                    return loaded;
                }
            }
        }
        catch (Exception)
        {
            // Corrupt or unreadable settings file — fall through to defaults rather than fail startup.
        }

        return new Model
        {
            AutoLockIdleMinutes = DefaultAutoLockIdleMinutes,
            LockOnMinimize = false,
            ClipboardClearSeconds = ClipboardService.DefaultClearAfterSeconds,
        };
    }

    private sealed class Model
    {
        public int AutoLockIdleMinutes { get; set; } = DefaultAutoLockIdleMinutes;

        public bool LockOnMinimize { get; set; }

        public int ClipboardClearSeconds { get; set; } = ClipboardService.DefaultClearAfterSeconds;
    }
}

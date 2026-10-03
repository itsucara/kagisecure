using Kagisecure.App.Services;

namespace Kagisecure.App.Tests;

/// <summary>An in-memory <see cref="ISettingsService"/> for view-model tests — no disk I/O.</summary>
internal sealed class FakeSettingsService : ISettingsService
{
    public int AutoLockIdleMinutes { get; set; } = 10;

    public bool LockOnMinimize { get; set; }

    public int ClipboardClearSeconds { get; set; } = 60;

    public int SaveCount { get; private set; }

    public void Save() => SaveCount++;
}

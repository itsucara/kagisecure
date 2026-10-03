using System.Collections.Generic;
using Kagisecure.App.Services;

namespace Kagisecure.App.Tests;

/// <summary>Records copies instead of touching the real Windows clipboard.</summary>
internal sealed class FakeClipboardService : IClipboardService
{
    public int ClearAfterSeconds { get; set; } = 60;

    public List<(string Value, string Label)> Copies { get; } = new();

    public void CopySecret(string value, string label) => Copies.Add((value, label));
}

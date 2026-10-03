using System.Threading.Tasks;
using Kagisecure.App.Services;
using Windows.Storage.Streams;

namespace Kagisecure.App.Tests;

/// <summary>A scriptable <see cref="IQrCodeReader"/> — never touches a real image codec.</summary>
internal sealed class FakeQrCodeReader : IQrCodeReader
{
    /// <summary>What <see cref="DecodeAsync"/> hands back; <c>null</c> means "no code found", matching the real reader.</summary>
    public string? ResultToReturn { get; set; }

    /// <summary>The stream <see cref="DecodeAsync"/> was called with, for asserting the right one was passed through.</summary>
    public IRandomAccessStream? LastStream { get; private set; }

    public Task<string?> DecodeAsync(IRandomAccessStream imageStream)
    {
        LastStream = imageStream;
        return Task.FromResult(ResultToReturn);
    }
}

/// <summary>A scriptable <see cref="IImageFilePicker"/> — never shows a real file picker.</summary>
internal sealed class FakeImageFilePicker : IImageFilePicker
{
    /// <summary>What <see cref="PickImageAsync"/> hands back; <c>null</c> means "the user cancelled".</summary>
    public IRandomAccessStream? StreamToReturn { get; set; }

    public int CallCount { get; private set; }

    public Task<IRandomAccessStream?> PickImageAsync()
    {
        CallCount++;
        return Task.FromResult(StreamToReturn);
    }
}

/// <summary>A scriptable <see cref="IClipboardImageSource"/> — never touches the real clipboard (ui-spec.md §9's brief: "no real clipboard in unit tests").</summary>
internal sealed class FakeClipboardImageSource : IClipboardImageSource
{
    /// <summary>What <see cref="GetImageAsync"/> hands back; <c>null</c> means "the clipboard has no image".</summary>
    public IRandomAccessStream? StreamToReturn { get; set; }

    public int CallCount { get; private set; }

    public Task<IRandomAccessStream?> GetImageAsync()
    {
        CallCount++;
        return Task.FromResult(StreamToReturn);
    }
}

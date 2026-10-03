using CommunityToolkit.Mvvm.ComponentModel;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>One row in the sidebar (ui-spec.md §2.2) that the shell can show a live count for.</summary>
public sealed partial class SidebarNodeViewModel : ObservableObject
{
    public SidebarNodeViewModel(string displayName, ItemFilter filter, string glyph)
    {
        DisplayName = displayName;
        Filter = filter;
        Glyph = glyph;
    }

    public string DisplayName { get; }

    public ItemFilter Filter { get; }

    /// <summary>A Segoe Fluent Icons glyph standing in for ui-spec.md's SF Symbol per row.</summary>
    public string Glyph { get; }

    [ObservableProperty]
    private uint? count;

    [ObservableProperty]
    private bool isLoading;
}

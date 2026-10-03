using System;
using Kagisecure.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>
/// Shows the characters-mode panel when <see cref="GeneratorMode.Characters"/> is selected
/// (or the words-mode panel when <see cref="Invert"/> is set), hiding the other.
/// </summary>
public sealed class ModeToVisibilityConverter : IValueConverter
{
    /// <summary>When true, show for <see cref="GeneratorMode.Words"/> instead of <see cref="GeneratorMode.Characters"/>.</summary>
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        bool isCharacters = value is GeneratorMode.Characters;
        bool visible = Invert ? !isCharacters : isCharacters;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

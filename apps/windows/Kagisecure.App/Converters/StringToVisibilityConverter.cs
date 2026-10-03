using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>
/// Non-null, non-empty string → <see cref="Visibility.Visible"/>, otherwise
/// <see cref="Visibility.Collapsed"/>. <see cref="StringToBoolConverter"/> exists for the same
/// question asked of a <c>bool</c> property (<c>InfoBar.IsOpen</c>); this is the <c>Visibility</c>
/// counterpart — the two are not interchangeable since x:Bind assigns the converter's return value
/// straight into the target property with no further coercion, and a <c>bool</c> boxed into a
/// <c>Visibility</c> property throws <see cref="InvalidCastException"/> rather than converting.
/// </summary>
public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        string.IsNullOrEmpty(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

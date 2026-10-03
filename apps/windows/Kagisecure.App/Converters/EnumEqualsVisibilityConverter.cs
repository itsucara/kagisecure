using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>
/// <see cref="Visibility.Visible"/> when the bound enum value's <see cref="object.ToString"/>
/// equals <c>ConverterParameter</c> (comma-separated for "any of"), <see cref="Visibility.Collapsed"/>
/// otherwise. General-purpose stand-in for a dedicated converter per enum (ui-spec.md's wizard-style
/// screens — <see cref="ViewModels.ImportPhase"/> here — switch a lot of panels on one state enum).
/// </summary>
public sealed class EnumEqualsVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        string? current = value?.ToString();
        string wanted = parameter as string ?? string.Empty;
        foreach (string candidate in wanted.Split(','))
        {
            if (string.Equals(candidate.Trim(), current, StringComparison.Ordinal))
            {
                return Visibility.Visible;
            }
        }

        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

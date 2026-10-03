using System;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>Non-null, non-empty string → <c>true</c>. Used to drive an <c>InfoBar.IsOpen</c> from an error message.</summary>
public sealed class StringToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        !string.IsNullOrEmpty(value as string);

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

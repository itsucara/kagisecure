using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>A count greater than zero → <see cref="Visibility.Visible"/>; zero → <see cref="Visibility.Collapsed"/>.</summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is int count && count > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

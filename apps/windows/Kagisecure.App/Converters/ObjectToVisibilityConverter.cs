using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>Non-null → <see cref="Visibility.Visible"/> (or <see cref="Visibility.Collapsed"/> when <see cref="Invert"/> is set), null → the other.</summary>
public sealed class ObjectToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        bool present = value is not null;
        bool visible = Invert ? !present : present;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

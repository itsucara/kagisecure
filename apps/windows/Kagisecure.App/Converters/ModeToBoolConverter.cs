using System;
using Kagisecure.Interop;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>
/// <see cref="GeneratorMode"/> ↔ <see cref="bool"/> for the generator's mode
/// <c>ToggleSwitch</c> (<see cref="GeneratorMode.Words"/> is "on").
/// </summary>
public sealed class ModeToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is GeneratorMode.Words;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        value is true ? GeneratorMode.Words : GeneratorMode.Characters;
}

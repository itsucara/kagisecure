using System;
using Kagisecure.Interop;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>
/// An <see cref="ImportItemAction"/>? to the word the import wizard's per-item table shows —
/// the same wording as the macOS sheet's <c>ImportSheet.actionName</c>. <c>null</c> (a report
/// built with no vault) reads as "—".
/// </summary>
public sealed class ImportActionToDisplayNameConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) => value switch
    {
        ImportItemAction.Create => "Add",
        ImportItemAction.Update => "Update",
        ImportItemAction.Skip => "Skip",
        ImportItemAction.KeepBoth => "Keep both",
        _ => "—",
    };

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

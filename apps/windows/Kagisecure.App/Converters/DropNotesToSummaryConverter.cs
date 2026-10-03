using System;
using System.Collections.Generic;
using System.Linq;
using Kagisecure.Interop;
using Microsoft.UI.Xaml.Data;

namespace Kagisecure.App.Converters;

/// <summary>
/// One item row's <see cref="DropNote"/> list to "Name ×Count, Name ×Count", or "—" when
/// nothing was dropped — the same wording as the macOS sheet's <c>ImportSheet.droppedSummary</c>.
/// Names and counts only, never a value: the source list already carries no more than that
/// (import.md §1.1).
/// </summary>
public sealed class DropNotesToSummaryConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not IEnumerable<DropNote> notes)
        {
            return "—";
        }

        DropNote[] list = notes.ToArray();
        return list.Length == 0
            ? "—"
            : string.Join(", ", list.Select(n => $"{n.Name} ×{n.Count}"));
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException();
}

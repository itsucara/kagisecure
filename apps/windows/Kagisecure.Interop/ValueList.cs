using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Kagisecure.Interop;

/// <summary>
/// An immutable list with value equality, so a record holding one — an <see cref="Item"/> and its
/// fields, say — compares by content the way the rest of the record does. Every list this assembly
/// returns is one.
/// </summary>
/// <typeparam name="T">The element type.</typeparam>
public sealed class ValueList<T> : IReadOnlyList<T>, IEquatable<ValueList<T>>
{
    private readonly T[] items;

    /// <summary>Wrap a copy of <paramref name="items"/>.</summary>
    public ValueList(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        this.items = items.ToArray();
    }

    /// <summary>The empty list.</summary>
    public static ValueList<T> Empty { get; } = new(Array.Empty<T>());

    /// <inheritdoc />
    public int Count => items.Length;

    /// <inheritdoc />
    public T this[int index] => items[index];

    /// <inheritdoc />
    public IEnumerator<T> GetEnumerator() => ((IEnumerable<T>)items).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => items.GetEnumerator();

    /// <inheritdoc />
    public bool Equals(ValueList<T>? other) =>
        other is not null && items.SequenceEqual(other.items);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as ValueList<T>);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (T item in items)
        {
            hash.Add(item);
        }
        return hash.ToHashCode();
    }

    /// <inheritdoc />
    public override string ToString() => $"[{string.Join(", ", items)}]";
}

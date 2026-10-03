using System;
using System.Reflection;
using Kagisecure.Interop;

namespace Kagisecure.App.Tests;

/// <summary>
/// Builds a <see cref="KagisecureException"/> subtype for tests, via its non-public constructor.
/// </summary>
/// <remarks>
/// Every <see cref="KagisecureException"/> nested type has an <c>internal</c> constructor —
/// deliberately: only <c>Kagisecure.Interop</c> itself is meant to raise these, from a real FFI
/// status code (see <c>KagisecureException.From</c>). This project isn't granted
/// <c>InternalsVisibleTo</c> (and per this task's scope, <c>Kagisecure.Interop</c> is not to be
/// edited to add one — another agent owns it concurrently), so a fake <see cref="Services.IVaultService"/>
/// that needs to hand a view model a <see cref="KagisecureException.WrongCredential"/> or similar
/// has no public way to construct one. Reflection is the least invasive way around that from
/// outside the assembly, and it only runs in tests.
/// </remarks>
internal static class KagisecureExceptionFactory
{
    public static T Create<T>(string message)
        where T : KagisecureException
    {
        ConstructorInfo? ctor = typeof(T).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance, binder: null, new[] { typeof(string) }, modifiers: null);
        if (ctor is null)
        {
            throw new InvalidOperationException($"{typeof(T)} has no (string) constructor to reflect into.");
        }

        return (T)ctor.Invoke(new object[] { message });
    }
}

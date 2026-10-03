using System;
using System.Collections.Generic;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>The extension listener's state. (The Safari members of Rust's record are macOS-only and not carried.)</summary>
/// <param name="Running">Whether the extension endpoint is bound and being accepted on.</param>
/// <param name="Endpoint">Where it is listening; empty when it is not.</param>
/// <param name="ConnectedHosts">How many native hosts are connected — in practice, browsers.</param>
/// <param name="FillLeases">How many fill leases are alive.</param>
/// <param name="VaultUnlocked">Whether the vault behind it is still unlocked.</param>
public sealed record ExtensionStatus(bool Running, string Endpoint, uint ConnectedHosts, uint FillLeases, bool VaultUnlocked);

/// <summary>One live fill lease.</summary>
/// <param name="Origin">The origin it covers.</param>
/// <param name="ItemId">The item it covers.</param>
/// <param name="ItemTitle">That item's title.</param>
/// <param name="Fields">Which fields it covers. Names.</param>
/// <param name="ClientIdentity">The browser it was minted for.</param>
/// <param name="ExpiresAt">Unix seconds it dies at.</param>
public sealed record FillLease(
    string Origin,
    string ItemId,
    string ItemTitle,
    ValueList<string> Fields,
    string ClientIdentity,
    ulong ExpiresAt)
{
    internal static FillLease From(in KgsFillLease n) => new(
        Str(n.origin), Str(n.item_id), Str(n.item_title), Strings(n.fields), Str(n.client_identity), n.expires_at);
}

/// <summary>One browser's native-messaging manifest, as the setup screen shows it.</summary>
/// <param name="Browser">The browser's display name.</param>
/// <param name="Path">The file the button would write.</param>
/// <param name="Body">Exactly what would be written there.</param>
/// <param name="BrowserInstalled">Whether that browser appears to be installed.</param>
/// <param name="Installed">Whether that exact file is already in place.</param>
/// <param name="RegistryKey">The <c>HKEY_CURRENT_USER</c> subkey the install button also sets, pointing that browser at the file.</param>
public sealed record BrowserManifest(string Browser, string Path, string Body, bool BrowserInstalled, bool Installed, string? RegistryKey)
{
    internal static BrowserManifest From(in KgsBrowserManifest n) =>
        new(Str(n.browser), Str(n.path), Str(n.body), n.browser_installed != 0, n.installed != 0, Str(n.registry_key));
}

/// <summary>Everything the Browser extension screen needs. (No Safari section: macOS-only.)</summary>
/// <param name="NmhostPath">The absolute path to <c>kagisecure-nmhost</c>, or <c>null</c> if not found.</param>
/// <param name="ExtensionId">The pinned extension id.</param>
/// <param name="HostName">The native messaging host name the manifests are filed under.</param>
/// <param name="Manifests">One entry per browser, installed browsers first.</param>
public sealed record ExtensionSetup(string? NmhostPath, string ExtensionId, string HostName, ValueList<BrowserManifest> Manifests);

/// <summary>
/// The browser-extension listener: a process global, so a static class. Its fill approvals arrive
/// on the same queue <see cref="Agent.NextRequest"/> polls — one loop serves both.
/// </summary>
public static unsafe class BrowserExtension
{
    /// <summary>
    /// Bind the extension endpoint and start serving browsers from <paramref name="session"/>'s
    /// vault. <paramref name="socketPath"/> means what <see cref="Agent.Start"/>'s does.
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">Another kagisecure holds the endpoint, or this process already runs a listener.</exception>
    public static string Start(VaultSession session, string? socketPath = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        EnsureAbi();
        using var s = session.Handle.Borrow();
        using var p = PinnedUtf8.Optional(socketPath);
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_extension_start(s.Ptr, p.OptSlice, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>Stop serving browsers and drop every fill lease. Idempotent.</summary>
    public static void Stop()
    {
        EnsureAbi();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_extension_stop(&error), ref error);
    }

    /// <summary>Whether the listener is running, and what it is holding.</summary>
    public static ExtensionStatus Status()
    {
        EnsureAbi();
        KgsExtensionStatus output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_extension_status(&output, &error), ref error);
            return new ExtensionStatus(
                output.running != 0, Str(output.endpoint), output.connected_hosts, output.fill_leases, output.vault_unlocked != 0);
        }
        finally
        {
            NativeMethods.kgs_extension_status_free(&output);
        }
    }

    /// <summary>Live fill leases.</summary>
    public static IReadOnlyList<FillLease> FillLeases()
    {
        EnsureAbi();
        KgsFillLeaseArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_extension_fill_leases(&output, &error), ref error);
            return List<KgsFillLease, FillLease>(output.ptr, output.len, FillLease.From);
        }
        finally
        {
            NativeMethods.kgs_fill_lease_array_free(&output);
        }
    }

    /// <summary>Revoke one fill lease. Returns whether there was such a live lease.</summary>
    public static bool RevokeFillLease(string origin, string itemId)
    {
        EnsureAbi();
        using var o = new PinnedUtf8(origin);
        using var id = new PinnedUtf8(itemId);
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_extension_revoke_fill_lease(o.Slice, id.Slice, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>Revoke every fill lease, so the next fill at every origin asks again.</summary>
    public static void RevokeAllFillLeases()
    {
        EnsureAbi();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_extension_revoke_all_fill_leases(&error), ref error);
    }

    /// <summary>
    /// Where the native host is, the pinned extension id, and what each browser needs written.
    /// <paramref name="helpersDirectory"/> is where the app installed <c>kagisecure-nmhost.exe</c>.
    /// </summary>
    public static ExtensionSetup Setup(string? helpersDirectory = null)
    {
        EnsureAbi();
        using var dir = PinnedUtf8.Optional(helpersDirectory);
        KgsExtensionSetup output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_extension_setup(dir.OptSlice, &output, &error), ref error);
            return new ExtensionSetup(
                Str(output.nmhost_path),
                Str(output.extension_id),
                Str(output.host_name),
                List<KgsBrowserManifest, BrowserManifest>(output.manifests.ptr, output.manifests.len, BrowserManifest.From));
        }
        finally
        {
            NativeMethods.kgs_extension_setup_free(&output);
        }
    }

    /// <summary>Write one browser's manifest — exactly the record the screen is showing.</summary>
    /// <exception cref="KagisecureException.Io">The file could not be written.</exception>
    public static void InstallManifest(BrowserManifest manifest) =>
        WithManifest(manifest, &NativeMethods.kgs_extension_install_manifest);

    /// <summary>Remove one browser's manifest. A file that was not there is success.</summary>
    /// <exception cref="KagisecureException.Io">The file could not be removed.</exception>
    public static void UninstallManifest(BrowserManifest manifest) =>
        WithManifest(manifest, &NativeMethods.kgs_extension_uninstall_manifest);

    private static void WithManifest(
        BrowserManifest manifest, delegate*<KgsBrowserManifestRef*, KgsBuffer*, KgsStatus> call)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        EnsureAbi();
        using var browser = new PinnedUtf8(manifest.Browser);
        using var path = new PinnedUtf8(manifest.Path);
        using var body = new PinnedUtf8(manifest.Body);
        using var registryKey = PinnedUtf8.Optional(manifest.RegistryKey);
        var native = new KgsBrowserManifestRef
        {
            browser = browser.Slice,
            path = path.Slice,
            body = body.Slice,
            browser_installed = Byte(manifest.BrowserInstalled),
            installed = Byte(manifest.Installed),
            registry_key = registryKey.OptSlice,
        };
        KgsBuffer error = default;
        Check(call(&native, &error), ref error);
    }
}

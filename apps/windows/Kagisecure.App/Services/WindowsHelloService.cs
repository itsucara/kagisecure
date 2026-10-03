using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>How a Windows Hello unlock attempt ended.</summary>
public enum HelloUnlockStatus
{
    /// <summary>The vault is unlocked.</summary>
    Unlocked,

    /// <summary>The user cancelled. Not an error: the password field is right there.</summary>
    Cancelled,

    /// <summary>This vault has no Windows Hello slot enrolled on this PC.</summary>
    NotEnrolled,

    /// <summary>Hello is not available on this PC right now.</summary>
    Unavailable,

    /// <summary>
    /// The slot can never unlock again: its Hello key was deleted or replaced, its DPAPI secret is
    /// gone, or the unwrapped key does not open the vault. Use the password, then re-enrol.
    /// </summary>
    NeedsReEnroll,

    /// <summary>The unlock finished after the vault was told to lock (screen lock, sleep); it stays locked.</summary>
    LockedMeanwhile,

    /// <summary>Anything else; the message says what.</summary>
    Failed,
}

/// <summary>The outcome of an unlock, enrol or disable, with a sentence for the user.</summary>
public sealed record HelloResult(HelloUnlockStatus Status, string? Message = null);

/// <summary>What the vault's one platform slot is, as far as this PC can tell (for the Security page).</summary>
public enum PlatformSlotKind
{
    /// <summary>No platform slot.</summary>
    None,

    /// <summary>A Windows Hello slot enrolled on this PC, in this Windows profile.</summary>
    ThisPc,

    /// <summary>A Windows Hello slot this PC cannot use: enrolled on another PC or profile, or in an older format.</summary>
    OtherWindowsHello,

    /// <summary>A Mac's Touch ID (Secure Enclave) slot.</summary>
    MacTouchId,

    /// <summary>A platform slot this app does not recognise.</summary>
    Unknown,
}

/// <summary>
/// Windows Hello unlock (ADR-0004 Windows section, ADR-0033): enrol, unlock, disable. The macOS
/// <c>PlatformKeyService</c> plus the parts of <c>AppModel</c> that drive it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Stated plainly (threat-model W-1, ADR-0033 §5):</b> turning this on lowers the vault's
/// protection on this PC to "anyone who can sign in to this Windows account". Windows Hello keys
/// belong to the Windows user and the device, not to this app; Windows Hello always accepts the
/// account's PIN, and adding a fingerprint or face does not invalidate the key. A program running as
/// you can ask Windows Hello to use this app's key; the DPAPI half of the construction is readable by
/// that same program; and a single such signature, with the vault file, opens the vault offline until
/// Hello is turned off and on again.
/// </para>
/// <para>
/// Every byte array holding the vault key, the signature, the app secret or the KEK is allocated on
/// the pinned heap and cleared with <see cref="CryptographicOperations.ZeroMemory"/> in a
/// <c>finally</c>. None of them, nor the wrapped blob, is ever written to the diagnostics or put in
/// a message.
/// </para>
/// </remarks>
public sealed partial class WindowsHelloService : ObservableObject
{
    /// <summary>The help text every Hello surface shows (W-1, ADR-0033 §5).</summary>
    public const string ScopeNotice =
        "Windows Hello unlock lowers this vault's protection on this PC to \"anyone who can sign in to "
        + "this Windows account\": Windows Hello always accepts your Windows PIN, adding a fingerprint "
        + "does not reset it, and its keys belong to your account, not to kagisecure. A program running "
        + "as you can ask Windows Hello to use kagisecure's key — one approved prompt is enough for it to "
        + "open the vault — so only confirm a Windows Hello prompt you asked for. This is much weaker "
        + "than Touch ID on a Mac. Your master password is unaffected and always works.";

    private readonly IWindowsHelloKeys keys;
    private readonly IWindowsHelloSecretStore secrets;
    private readonly IWindowsHelloVault vault;
    private readonly Action<string>? diagnostics;

    public WindowsHelloService(IWindowsHelloKeys keys, IWindowsHelloSecretStore secrets, IWindowsHelloVault vault, Action<string>? diagnostics = null)
    {
        this.keys = keys;
        this.secrets = secrets;
        this.vault = vault;
        this.diagnostics = diagnostics;
    }

    private HelloAvailability availability = HelloAvailability.Unknown;
    private bool needsReEnroll;

    /// <summary>Whether Hello can be offered on this PC. Refreshed by <see cref="RefreshAvailabilityAsync"/>.</summary>
    public HelloAvailability Availability
    {
        get => availability;
        private set => SetProperty(ref availability, value);
    }

    /// <summary>
    /// Set when an unlock found the slot dead (<see cref="HelloUnlockStatus.NeedsReEnroll"/>); the
    /// Security page offers to enrol again once the vault is unlocked with the password.
    /// </summary>
    public bool NeedsReEnroll
    {
        get => needsReEnroll;
        private set => SetProperty(ref needsReEnroll, value);
    }

    /// <summary>Re-check availability. Never prompts.</summary>
    public async Task<HelloAvailability> RefreshAvailabilityAsync()
    {
        Availability = await keys.AvailabilityAsync().ConfigureAwait(true);
        return Availability;
    }

    /// <summary>
    /// Whether the vault file at <paramref name="path"/> has a Windows Hello slot that <i>this</i> PC
    /// can use (read from the header, no unlock): the right format, and this profile holds its
    /// secret. A slot enrolled on another PC is not offered — it could only fail.
    /// </summary>
    public bool IsEnrolledAt(string path)
    {
        try
        {
            string? slotId = vault.PlatformSlotInfoOf(path).SlotId;
            return WindowsHelloCrypto.IsWindowsHelloSlot(slotId) && secrets.Exists(slotId!);
        }
        catch (KagisecureException)
        {
            return false;
        }
    }

    /// <summary>The unlocked vault's platform slot id, whoever wrote it (a Mac's Touch ID slot included).</summary>
    public string? CurrentSlotId()
    {
        try
        {
            return vault.CurrentPlatformSlotId();
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>What the unlocked vault's platform slot is, as far as this PC can tell.</summary>
    public PlatformSlotKind CurrentSlotKind() => Classify(CurrentSlotId());

    /// <summary>What a platform slot id is, as far as this PC can tell.</summary>
    public PlatformSlotKind Classify(string? slotId)
    {
        if (slotId is null)
        {
            return PlatformSlotKind.None;
        }

        if (WindowsHelloCrypto.IsWindowsHelloSlot(slotId) && secrets.Exists(slotId))
        {
            return PlatformSlotKind.ThisPc;
        }

        if (WindowsHelloCrypto.IsAnyWindowsHelloSlot(slotId))
        {
            return PlatformSlotKind.OtherWindowsHello;
        }

        return slotId.StartsWith("macos-", StringComparison.Ordinal) ? PlatformSlotKind.MacTouchId : PlatformSlotKind.Unknown;
    }

    /// <summary>Whether the unlocked vault is enrolled for Windows Hello on this PC.</summary>
    public bool IsEnrolled => CurrentSlotKind() == PlatformSlotKind.ThisPc;

    /// <summary>
    /// Unlock the vault at <paramref name="path"/> with Windows Hello: one read of the header, one
    /// Hello prompt (the signature), the DPAPI secret, the KEK, the unwrap, and the vault key
    /// straight into <see cref="IWindowsHelloVault.UnlockWithVaultKeyAsync"/>.
    /// </summary>
    public async Task<HelloResult> UnlockAsync(string path)
    {
        PlatformSlotInfo info;
        try
        {
            // One read: the slot id, the blob and the vault-file id cannot come from two different
            // versions of a file replaced in between. (The unlock itself reads the file again; a
            // different file there fails the key check, and the blob is bound to this vault id.)
            info = vault.PlatformSlotInfoOf(path);
        }
        catch (KagisecureException ex)
        {
            return new HelloResult(HelloUnlockStatus.Failed, ex.Message);
        }

        string? slotId = info.SlotId;
        if (!WindowsHelloCrypto.IsWindowsHelloSlot(slotId) || info.WrappedKey is not { } blob)
        {
            return new HelloResult(HelloUnlockStatus.NotEnrolled);
        }

        HelloAvailability available = await RefreshAvailabilityAsync().ConfigureAwait(true);
        if (!available.Available)
        {
            return new HelloResult(HelloUnlockStatus.Unavailable, available.Reason);
        }

        byte[]? signature = null;
        byte[]? appSecret = null;
        byte[]? kek = null;
        byte[]? vaultKey = null;
        try
        {
            HelloSignResult signed = await keys.SignAsync(WindowsHelloCrypto.CredentialName(slotId!), WindowsHelloCrypto.Challenge(slotId!)).ConfigureAwait(true);
            signature = signed.Signature;
            switch (signed.Status)
            {
                case HelloKeyStatus.Success when signature is not null:
                    break;
                case HelloKeyStatus.Cancelled:
                    return new HelloResult(HelloUnlockStatus.Cancelled);
                case HelloKeyStatus.NotFound:
                    return Dead("its Windows Hello key was removed from this PC");
                case HelloKeyStatus.Unavailable:
                    return new HelloResult(HelloUnlockStatus.Unavailable, signed.Message);
                default:
                    Log($"Windows Hello sign failed: {signed.Status}");
                    return new HelloResult(HelloUnlockStatus.Failed, signed.Message ?? "Windows Hello did not sign.");
            }

            appSecret = secrets.Load(slotId!);
            if (appSecret is null)
            {
                return Dead("kagisecure's protected secret for it is missing on this PC");
            }

            kek = WindowsHelloCrypto.DeriveKek(signature, appSecret, slotId!);
            vaultKey = WindowsHelloCrypto.Unwrap(kek, blob, slotId!, info.VaultId);
            if (vaultKey is null)
            {
                // A different Hello key under the same name, a replaced secret, a blob from another
                // vault file, or a tampered header.
                Log("Windows Hello unwrap failed: authentication tag mismatch");
                return Dead("its key no longer matches");
            }

            try
            {
                await vault.UnlockWithVaultKeyAsync(path, vaultKey).ConfigureAwait(true);
            }
            catch (KagisecureException.WrongCredential)
            {
                Log("Windows Hello unwrap produced a key the vault rejected");
                return Dead("the key it holds no longer opens this vault");
            }
            catch (VaultLockedDuringUnlockException ex)
            {
                return new HelloResult(HelloUnlockStatus.LockedMeanwhile, ex.Message);
            }

            NeedsReEnroll = false;
            return new HelloResult(HelloUnlockStatus.Unlocked);
        }
        catch (Exception ex) when (ex is KagisecureException or CryptographicException or ArgumentException)
        {
            Log($"Windows Hello unlock failed: {ex.GetType().Name}");
            return new HelloResult(HelloUnlockStatus.Failed, ex.Message);
        }
        finally
        {
            Clear(signature);
            Clear(appSecret);
            Clear(kek);
            Clear(vaultKey);
        }
    }

    /// <summary>
    /// Turn Windows Hello on for the unlocked vault: create a Hello key, require its TPM attestation,
    /// sign the new slot's challenge (two prompts), create the DPAPI secret, export and wrap the
    /// vault key, and install the slot — replacing any platform slot (v1 keeps one per vault, so a
    /// Mac's Touch ID slot or another PC's Hello slot is replaced too; the Security page asks first).
    /// </summary>
    public async Task<HelloResult> EnableAsync()
    {
        HelloAvailability available = await RefreshAvailabilityAsync().ConfigureAwait(true);
        if (!available.Available)
        {
            return new HelloResult(HelloUnlockStatus.Unavailable, available.Reason);
        }

        string? previous = CurrentSlotId();
        string slotId = WindowsHelloCrypto.NewSlotId();
        string credential = WindowsHelloCrypto.CredentialName(slotId);
        byte[]? vaultKey = null;
        byte[]? signature = null;
        byte[]? appSecret = null;
        byte[]? kek = null;
        bool installed = false;
        try
        {
            HelloSignResult signed = await keys.CreateAndSignAsync(credential, WindowsHelloCrypto.Challenge(slotId)).ConfigureAwait(true);
            signature = signed.Signature;
            if (signed.Status == HelloKeyStatus.Cancelled)
            {
                return new HelloResult(HelloUnlockStatus.Cancelled);
            }

            if (signed.Status != HelloKeyStatus.Success || signature is null)
            {
                return new HelloResult(
                    signed.Status is HelloKeyStatus.Unavailable or HelloKeyStatus.NotHardwareBacked ? HelloUnlockStatus.Unavailable : HelloUnlockStatus.Failed,
                    signed.Message ?? "Windows Hello did not create a key.");
            }

            appSecret = secrets.Create(slotId);
            kek = WindowsHelloCrypto.DeriveKek(signature, appSecret, slotId);
            byte[] vaultId = vault.CurrentVaultFileId();
            vaultKey = await vault.ExportVaultKeyForPlatformWrappingAsync().ConfigureAwait(true);
            byte[] blob = WindowsHelloCrypto.Wrap(kek, vaultKey, slotId, vaultId);
            await vault.InstallPlatformSlotAsync(slotId, $"Windows Hello on {Environment.MachineName}", blob).ConfigureAwait(true);
            installed = true;
            NeedsReEnroll = false;
        }
        catch (Exception ex) when (ex is KagisecureException or CryptographicException or InvalidOperationException or System.IO.IOException or UnauthorizedAccessException)
        {
            Log($"Windows Hello enrolment failed: {ex.GetType().Name}");
            return new HelloResult(HelloUnlockStatus.Failed, ex.Message);
        }
        finally
        {
            Clear(vaultKey);
            Clear(signature);
            Clear(appSecret);
            Clear(kek);
            if (!installed)
            {
                secrets.Delete(slotId);
                await keys.DeleteAsync(credential).ConfigureAwait(true);
            }
        }

        // Only after the new slot is on disk: the old one's key and secret are now dead weight.
        if (WindowsHelloCrypto.IsAnyWindowsHelloSlot(previous) && previous != slotId)
        {
            await Forget(previous!).ConfigureAwait(true);
        }

        return new HelloResult(HelloUnlockStatus.Unlocked);
    }

    /// <summary>Turn Windows Hello off: remove the slot from the vault, delete the Hello key and the DPAPI secret.</summary>
    public async Task<HelloResult> DisableAsync()
    {
        string? slotId = CurrentSlotId();
        try
        {
            await vault.RemovePlatformSlotAsync().ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            return new HelloResult(HelloUnlockStatus.Failed, ex.Message);
        }

        if (WindowsHelloCrypto.IsAnyWindowsHelloSlot(slotId))
        {
            await Forget(slotId!).ConfigureAwait(true);
        }

        NeedsReEnroll = false;
        return new HelloResult(HelloUnlockStatus.NotEnrolled);
    }

    private async Task Forget(string slotId)
    {
        secrets.Delete(slotId);
        await keys.DeleteAsync(WindowsHelloCrypto.CredentialName(slotId)).ConfigureAwait(true);
    }

    private HelloResult Dead(string why)
    {
        NeedsReEnroll = true;
        return new HelloResult(
            HelloUnlockStatus.NeedsReEnroll,
            $"Windows Hello no longer unlocks this vault — {why}. Unlock with your master password, "
            + "then turn Windows Hello back on under Security.");
    }

    /// <summary>Diagnostics only ever get fixed strings and exception type names — never a key, a blob, or a message that might quote one.</summary>
    private void Log(string line) => diagnostics?.Invoke(line);

    private static void Clear(byte[]? buffer)
    {
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}

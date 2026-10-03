using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace Kagisecure.App.Services;

/// <summary>Whether Windows Hello unlock can be offered on this PC, and why not.</summary>
/// <param name="Available">Hello is set up and a TPM 2.0 is present to hold its keys.</param>
/// <param name="Reason">When not available: a sentence for the user.</param>
public sealed record HelloAvailability(bool Available, string? Reason)
{
    /// <summary>Not checked yet.</summary>
    public static HelloAvailability Unknown { get; } = new(false, null);
}

/// <summary>How a Hello key operation ended.</summary>
public enum HelloKeyStatus
{
    /// <summary>Signed.</summary>
    Success,

    /// <summary>No credential by that name — it was deleted (or Hello was reset), so the slot can never unlock again.</summary>
    NotFound,

    /// <summary>The user cancelled, or chose "use password".</summary>
    Cancelled,

    /// <summary>Hello is not available (not set up, locked TPM, …).</summary>
    Unavailable,

    /// <summary>
    /// The key exists but its TPM attestation did not succeed, so nothing proves it is held in a
    /// TPM rather than in software. Enrolment refuses it.
    /// </summary>
    NotHardwareBacked,

    /// <summary>Anything else.</summary>
    Failed,
}

/// <summary>
/// One Hello key operation's outcome. <see cref="Signature"/> is on the pinned heap and is the
/// caller's to clear.
/// </summary>
public sealed record HelloSignResult(HelloKeyStatus Status, byte[]? Signature = null, string? Message = null);

/// <summary>
/// The <c>KeyCredentialManager</c> half of ADR-0033: a Hello-gated, TPM-backed RSA key per
/// enrolment, used only to sign the slot's challenge. A seam so the unlock/enrol logic is tested
/// against a fake.
/// </summary>
public interface IWindowsHelloKeys
{
    /// <summary>Whether Hello is set up and a TPM 2.0 is present. Never prompts.</summary>
    Task<HelloAvailability> AvailabilityAsync();

    /// <summary>
    /// Create a credential named <paramref name="credentialName"/> (replacing one of that name),
    /// require a successful TPM attestation of it (<see cref="HelloKeyStatus.NotHardwareBacked"/>
    /// otherwise, and the credential is deleted), then sign <paramref name="challenge"/>. Two Hello
    /// prompts. Fails unless the signature verifies as RSASSA-PKCS1-v1_5 under the credential's
    /// public key — the property that makes it deterministic.
    /// </summary>
    Task<HelloSignResult> CreateAndSignAsync(string credentialName, byte[] challenge);

    /// <summary>Open the credential and sign <paramref name="challenge"/>. One Hello prompt.</summary>
    Task<HelloSignResult> SignAsync(string credentialName, byte[] challenge);

    /// <summary>Delete the credential. A credential that does not exist is success.</summary>
    Task DeleteAsync(string credentialName);
}

/// <summary>
/// The DPAPI half of ADR-0033: a random per-slot app secret, protected with
/// <c>CryptProtectData</c> (current-user scope) and stored in this app's own directory under
/// <c>%LOCALAPPDATA%</c>. Returned arrays are pinned and the caller's to clear.
/// </summary>
public interface IWindowsHelloSecretStore
{
    /// <summary>Generate, protect and persist a new secret for <paramref name="slotId"/>, replacing any.</summary>
    byte[] Create(string slotId);

    /// <summary>The secret for <paramref name="slotId"/>, or <c>null</c> when there is none or it no longer unprotects.</summary>
    byte[]? Load(string slotId);

    /// <summary>Whether this PC's profile holds a secret for <paramref name="slotId"/> — i.e. whether the slot was enrolled here. Never decrypts.</summary>
    bool Exists(string slotId);

    /// <summary>Forget the secret. Missing is success.</summary>
    void Delete(string slotId);
}

/// <summary>The real <see cref="IWindowsHelloKeys"/>, over <see cref="KeyCredentialManager"/>.</summary>
/// <remarks>
/// W-1, stated plainly: the credential is scoped to this Windows user on this device, not to this
/// app. Any process running as the same user can open a credential by name (the name is derived
/// from the slot id in the vault header) and ask the user to sign with it; and Windows Hello always
/// accepts the account's PIN, so "sign" means "anyone who can sign in to this Windows account" —
/// not "this fingerprint", and not invalidated when fingerprints change (ADR-0033 §5).
/// </remarks>
public sealed class WindowsHelloKeys : IWindowsHelloKeys
{
    /// <inheritdoc />
    public async Task<HelloAvailability> AvailabilityAsync()
    {
        try
        {
            if (TpmVersion() is not uint version)
            {
                // ADR-0004: on a machine with no TPM, say so — never a silent downgrade to a
                // software-held Hello key.
                return new HelloAvailability(false, "This PC has no TPM, so Windows Hello cannot hold kagisecure's key in hardware. Unlock with your master password.");
            }

            if (version != TpmVersion20)
            {
                return new HelloAvailability(false, "This PC's TPM is not a TPM 2.0, which kagisecure requires for a Windows Hello key. Unlock with your master password.");
            }

            if (!await KeyCredentialManager.IsSupportedAsync())
            {
                return new HelloAvailability(false, "Windows Hello is not set up for this account. Set up a PIN, fingerprint or face in Windows Settings › Accounts › Sign-in options.");
            }

            return new HelloAvailability(true, null);
        }
        catch (Exception ex)
        {
            return new HelloAvailability(false, $"Windows Hello could not be checked: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async Task<HelloSignResult> CreateAndSignAsync(string credentialName, byte[] challenge)
    {
        try
        {
            HelloDialogFocus.BringToFrontSoon();
            KeyCredentialRetrievalResult created =
                await KeyCredentialManager.RequestCreateAsync(credentialName, KeyCredentialCreationOption.ReplaceExisting);
            if (created.Status != KeyCredentialStatus.Success)
            {
                return FromStatus(created.Status);
            }

            // Presence of a TPM (AvailabilityAsync) does not prove that *this* key is in it: Hello
            // can fall back to a software key. Attestation is the TPM vouching for this key; no
            // attestation, no enrolment. It does not prompt.
            KeyCredentialAttestationResult attestation = await created.Credential.GetAttestationAsync();
            if (attestation.Status != KeyCredentialAttestationStatus.Success)
            {
                await DeleteAsync(credentialName).ConfigureAwait(true);
                return new HelloSignResult(HelloKeyStatus.NotHardwareBacked, Message: AttestationMessage(attestation.Status));
            }

            HelloSignResult signed = await SignWith(created.Credential, challenge).ConfigureAwait(true);
            if (signed.Status != HelloKeyStatus.Success || signed.Signature is null)
            {
                await DeleteAsync(credentialName).ConfigureAwait(true);
                return signed;
            }

            if (!VerifiesAsPkcs1(created.Credential, challenge, signed.Signature))
            {
                CryptographicOperations.ZeroMemory(signed.Signature);
                await DeleteAsync(credentialName).ConfigureAwait(true);
                return new HelloSignResult(
                    HelloKeyStatus.Failed,
                    Message: "This PC's Windows Hello key does not sign deterministically (RSASSA-PKCS1-v1_5), so kagisecure cannot derive a stable key from it.");
            }

            return signed;
        }
        catch (Exception ex)
        {
            return new HelloSignResult(HelloKeyStatus.Failed, Message: ex.Message);
        }
    }

    /// <summary>What an attestation status that is not Success tells the user.</summary>
    public static string AttestationMessage(KeyCredentialAttestationStatus status) => status switch
    {
        KeyCredentialAttestationStatus.NotSupported =>
            "Windows could not prove that the Windows Hello key is held in this PC's TPM (attestation is not supported here — a TPM 1.2, a software key, or a virtual machine), so kagisecure will not use it. Unlock with your master password.",
        KeyCredentialAttestationStatus.TemporaryFailure =>
            "Windows could not attest the Windows Hello key right now (a temporary TPM failure). Try again later.",
        _ =>
            $"Windows could not prove that the Windows Hello key is held in this PC's TPM ({status}), so kagisecure will not use it.",
    };

    /// <inheritdoc />
    public async Task<HelloSignResult> SignAsync(string credentialName, byte[] challenge)
    {
        try
        {
            KeyCredentialRetrievalResult opened = await KeyCredentialManager.OpenAsync(credentialName);
            if (opened.Status != KeyCredentialStatus.Success)
            {
                return FromStatus(opened.Status);
            }

            HelloDialogFocus.BringToFrontSoon();
            return await SignWith(opened.Credential, challenge).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            return new HelloSignResult(HelloKeyStatus.Failed, Message: ex.Message);
        }
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string credentialName)
    {
        try
        {
            await KeyCredentialManager.DeleteAsync(credentialName);
        }
        catch (Exception)
        {
            // Not there, or Hello went away: either way there is nothing left to delete.
        }
    }

    private static async Task<HelloSignResult> SignWith(KeyCredential credential, byte[] challenge)
    {
        KeyCredentialOperationResult result = await credential.RequestSignAsync(challenge.AsBuffer());
        if (result.Status != KeyCredentialStatus.Success)
        {
            return FromStatus(result.Status);
        }

        IBuffer buffer = result.Result;
        int length = checked((int)buffer.Length);
        byte[] signature = WindowsHelloCrypto.PinnedBuffer(length);
        buffer.CopyTo(0, signature, 0, length);
        // Overwrite the WinRT buffer in place, so the signature does not outlive this call in the
        // runtime's heap either. Best effort: a buffer that refuses writes is left to its owner.
        try
        {
            new byte[length].CopyTo(0, buffer, 0, length);
        }
        catch (Exception)
        {
        }

        return new HelloSignResult(HelloKeyStatus.Success, signature);
    }

    private static bool VerifiesAsPkcs1(KeyCredential credential, byte[] challenge, byte[] signature)
    {
        try
        {
            IBuffer spki = credential.RetrievePublicKey(CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki.ToArray(), out _);
            return rsa.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static HelloSignResult FromStatus(KeyCredentialStatus status) => status switch
    {
        KeyCredentialStatus.NotFound => new(HelloKeyStatus.NotFound, Message: "The Windows Hello key for this vault no longer exists."),
        KeyCredentialStatus.UserCanceled => new(HelloKeyStatus.Cancelled),
        KeyCredentialStatus.UserPrefersPassword => new(HelloKeyStatus.Cancelled),
        KeyCredentialStatus.SecurityDeviceLocked => new(HelloKeyStatus.Unavailable, Message: "The security device (TPM) is locked out. Try again later."),
        _ => new(HelloKeyStatus.Failed, Message: $"Windows Hello refused the operation ({status})."),
    };

    private const uint TpmVersion20 = 2;

    /// <summary>The TPM's version (1 = 1.2, 2 = 2.0), or <c>null</c> when there is none.</summary>
    private static uint? TpmVersion()
    {
        var info = new TpmDeviceInfo { StructVersion = 1 };
        try
        {
            return NativeMethods.Tbsi_GetDeviceInfo((uint)Marshal.SizeOf<TpmDeviceInfo>(), ref info) == 0 ? info.TpmVersion : null;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TpmDeviceInfo
    {
        public uint StructVersion;
        public uint TpmVersion;
        public uint TpmInterfaceType;
        public uint TpmImpRevision;
    }

    private static class NativeMethods
    {
        [DllImport("tbs.dll")]
        public static extern uint Tbsi_GetDeviceInfo(uint size, ref TpmDeviceInfo info);
    }
}

/// <summary>
/// An unpackaged desktop app has no CoreWindow for the Hello dialog to attach to, and
/// <c>KeyCredentialManager</c> has no window-parented variant, so the dialog can open behind this
/// app's window. This brings the system's Hello dialog forward for a few seconds after a request.
/// </summary>
/// <remarks>
/// A window class name is not an identity: any same-user program can register a window called
/// "Credential Dialog Xaml Host", and foregrounding the first one found would put a fake Hello
/// prompt in front of the user at exactly the moment they expect a real one. So every window of
/// that class is considered, and only one whose process image is
/// <c>%SystemRoot%\System32\CredentialUIBroker.exe</c> — read from the process, not from anything
/// the window says — is ever activated. No match, no foregrounding: the dialog may open behind the
/// app, which is cosmetic.
/// </remarks>
public static class HelloDialogFocus
{
    private const string DialogClass = "Credential Dialog Xaml Host";

    /// <summary>The only image whose window this app will bring forward, for this Windows installation.</summary>
    public static string ExpectedBrokerPath(string systemRoot) =>
        Path.Combine(systemRoot, "System32", "CredentialUIBroker.exe");

    /// <summary>
    /// Whether <paramref name="imagePath"/> — the full Win32 path of a window's owning process — is
    /// the system credential broker. Exact path comparison (case-insensitive, as NTFS names are),
    /// never "ends with".
    /// </summary>
    public static bool IsSystemCredentialBroker(string? imagePath, string systemRoot) =>
        !string.IsNullOrEmpty(imagePath)
        && !string.IsNullOrEmpty(systemRoot)
        && string.Equals(
            Path.GetFullPath(imagePath),
            Path.GetFullPath(ExpectedBrokerPath(systemRoot)),
            StringComparison.OrdinalIgnoreCase);

    public static void BringToFrontSoon()
    {
        string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _ = Task.Run(async () =>
        {
            for (int i = 0; i < 30; i++)
            {
                IntPtr hwnd = IntPtr.Zero;
                while ((hwnd = FindWindowEx(IntPtr.Zero, hwnd, DialogClass, null)) != IntPtr.Zero)
                {
                    if (IsSystemCredentialBroker(ImagePathOf(hwnd), systemRoot))
                    {
                        SetForegroundWindow(hwnd);
                        return;
                    }
                }

                await Task.Delay(100).ConfigureAwait(false);
            }
        });
    }

    private static string? ImagePathOf(IntPtr hwnd)
    {
        if (GetWindowThreadProcessId(hwnd, out uint pid) == 0 || pid == 0)
        {
            return null;
        }

        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new StringBuilder(1024);
            int size = buffer.Capacity;
            return QueryFullProcessImageName(process, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr FindWindowEx(IntPtr parent, IntPtr childAfter, string className, string? windowName);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>The real <see cref="IWindowsHelloSecretStore"/>: DPAPI (current user) files under <c>%LOCALAPPDATA%\Kagisecure\windows-hello</c>.</summary>
public sealed class DpapiWindowsHelloSecretStore : IWindowsHelloSecretStore
{
    private readonly string directory;

    /// <param name="directory">Where the protected secrets live; the default is <c>%LOCALAPPDATA%\Kagisecure\windows-hello</c>.</param>
    public DpapiWindowsHelloSecretStore(string? directory = null)
    {
        this.directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kagisecure", "windows-hello");
    }

    /// <inheritdoc />
    public byte[] Create(string slotId)
    {
        byte[] secret = WindowsHelloCrypto.PinnedBuffer(WindowsHelloCrypto.AppSecretLength);
        RandomNumberGenerator.Fill(secret);
        byte[] protectedBlob = Dpapi.Protect(secret, WindowsHelloCrypto.DpapiEntropy(slotId));
        Directory.CreateDirectory(directory);
        string target = PathFor(slotId);
        string temp = target + ".tmp";
        File.WriteAllBytes(temp, protectedBlob);
        File.Move(temp, target, overwrite: true);
        return secret;
    }

    /// <inheritdoc />
    public byte[]? Load(string slotId)
    {
        string path = PathFor(slotId);
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            byte[] secret = Dpapi.Unprotect(File.ReadAllBytes(path), WindowsHelloCrypto.DpapiEntropy(slotId));
            if (secret.Length != WindowsHelloCrypto.AppSecretLength)
            {
                CryptographicOperations.ZeroMemory(secret);
                return null;
            }

            return secret;
        }
        catch (CryptographicException)
        {
            // A different Windows user's file, a profile reset that lost the DPAPI master key, or
            // a file that is not ours: all mean "no secret".
            return null;
        }
    }

    /// <inheritdoc />
    public bool Exists(string slotId) => File.Exists(PathFor(slotId));

    /// <inheritdoc />
    public void Delete(string slotId)
    {
        try
        {
            File.Delete(PathFor(slotId));
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private string PathFor(string slotId)
    {
        if (!WindowsHelloCrypto.IsAnyWindowsHelloSlot(slotId) || slotId.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException("not a Windows Hello slot id", nameof(slotId));
        }

        return Path.Combine(directory, slotId + ".dpapi");
    }
}

/// <summary><c>CryptProtectData</c>/<c>CryptUnprotectData</c> with current-user scope, clearing every unmanaged copy it makes.</summary>
internal static class Dpapi
{
    private const int CryptProtectUiForbidden = 0x1;

    public static byte[] Protect(byte[] plaintext, byte[] entropy) => Transform(plaintext, entropy, protect: true);

    /// <summary>The plaintext, in a pinned array the caller clears.</summary>
    public static byte[] Unprotect(byte[] ciphertext, byte[] entropy) => Transform(ciphertext, entropy, protect: false);

    private static byte[] Transform(byte[] input, byte[] entropy, bool protect)
    {
        DataBlob inBlob = Alloc(input);
        DataBlob entropyBlob = Alloc(entropy);
        DataBlob outBlob = default;
        try
        {
            bool ok = protect
                ? CryptProtectData(ref inBlob, null, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outBlob);
            if (!ok)
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            byte[] output = protect ? new byte[outBlob.Length] : WindowsHelloCrypto.PinnedBuffer(outBlob.Length);
            Marshal.Copy(outBlob.Data, output, 0, outBlob.Length);
            return output;
        }
        finally
        {
            Free(ref inBlob);
            Free(ref entropyBlob);
            if (outBlob.Data != IntPtr.Zero)
            {
                Marshal.Copy(new byte[outBlob.Length], 0, outBlob.Data, outBlob.Length);
                LocalFree(outBlob.Data);
            }
        }
    }

    private static DataBlob Alloc(byte[] bytes)
    {
        IntPtr p = Marshal.AllocHGlobal(Math.Max(1, bytes.Length));
        Marshal.Copy(bytes, 0, p, bytes.Length);
        return new DataBlob { Length = bytes.Length, Data = p };
    }

    private static void Free(ref DataBlob blob)
    {
        if (blob.Data != IntPtr.Zero)
        {
            Marshal.Copy(new byte[blob.Length], 0, blob.Data, blob.Length);
            Marshal.FreeHGlobal(blob.Data);
            blob.Data = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Length;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn, string? description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
}

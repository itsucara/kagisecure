using System;
using System.Security.Cryptography;
using System.Text;

namespace Kagisecure.App.Services;

/// <summary>
/// The key construction behind Windows Hello unlock — ADR-0033, which fixes the derivation
/// ADR-0004's Windows section leaves open. Pure functions over byte arrays, so every step is
/// tested without Hello, DPAPI or a vault.
/// </summary>
/// <remarks>
/// <code>
/// challenge = SHA-256("kagisecure/windows-hello/v2/challenge" || 0x00 || slotId)
/// signature = KeyCredential(credentialName).RequestSignAsync(challenge)      // Hello-gated, TPM-held RSA key,
///                                                                            // RSASSA-PKCS1-v1_5: deterministic
/// appSecret = 32 random bytes, stored CryptProtectData(CurrentUser) in %LOCALAPPDATA%\Kagisecure
/// KEK       = HKDF-SHA256(ikm = signature || appSecret,
///                         salt = "kagisecure/windows-hello/v2",
///                         info = "kagisecure/windows-hello/v2/kek" || 0x00 || slotId, L = 32)
/// blob      = "KGH2" || nonce(12) || AES-256-GCM(KEK, nonce, VK, aad) || tag(16)
/// aad       = "KGH2" || len(vaultId) || vaultId || slotId
/// </code>
/// The blob is the platform slot's opaque wrapped key in the vault header, bound by its associated
/// data to that slot <i>and</i> to that vault file. Neither input alone reconstructs the KEK. Read
/// ADR-0033 §5 before believing that is worth much: both inputs are reachable by a process running
/// as the same Windows user.
/// <para>
/// Every buffer holding a secret is allocated on the pinned object heap
/// (<see cref="GC.AllocateUninitializedArray{T}(int, bool)"/> with <c>pinned: true</c>), so the
/// garbage collector cannot leave an unzeroed copy behind by moving it — including across the
/// awaits of the Hello flow — and is cleared by its owner in a <c>finally</c>.
/// </para>
/// </remarks>
public static class WindowsHelloCrypto
{
    /// <summary>The platform-slot id prefix that marks a slot as this construction's.</summary>
    public const string SlotIdPrefix = "windows-hello-v2-";

    /// <summary>The prefix any Windows Hello slot carries, of any version — for telling one from a Mac's.</summary>
    public const string AnyVersionPrefix = "windows-hello-";

    /// <summary>The blob's first four bytes, and part of its associated data.</summary>
    public static ReadOnlySpan<byte> Magic => "KGH2"u8;

    /// <summary>The vault key's length (vault-format §3).</summary>
    public const int VaultKeyLength = 32;

    /// <summary>The app secret's length.</summary>
    public const int AppSecretLength = 32;

    private const int NonceLength = 12;
    private const int TagLength = 16;

    /// <summary>The whole blob's length.</summary>
    public const int BlobLength = 4 + NonceLength + VaultKeyLength + TagLength;

    /// <summary>A fresh slot id: the prefix and 16 random bytes in hex.</summary>
    public static string NewSlotId() => SlotIdPrefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>Whether <paramref name="slotId"/> is one this construction (this version) wrote.</summary>
    public static bool IsWindowsHelloSlot(string? slotId) =>
        slotId is not null && slotId.StartsWith(SlotIdPrefix, StringComparison.Ordinal) && slotId.Length > SlotIdPrefix.Length;

    /// <summary>Whether <paramref name="slotId"/> is any Windows Hello slot, this version or an earlier one.</summary>
    public static bool IsAnyWindowsHelloSlot(string? slotId) =>
        slotId is not null && slotId.StartsWith(AnyVersionPrefix, StringComparison.Ordinal);

    /// <summary>The name of the <c>KeyCredential</c> for a slot. One credential per enrolment, deleted when Hello is turned off.</summary>
    public static string CredentialName(string slotId) => "Kagisecure vault unlock " + slotId;

    /// <summary>A byte array on the pinned object heap: the GC never moves it, so clearing it clears the only copy.</summary>
    public static byte[] PinnedBuffer(int length) => GC.AllocateUninitializedArray<byte>(length, pinned: true);

    /// <summary>A pinned copy of <paramref name="source"/>.</summary>
    public static byte[] PinnedCopy(ReadOnlySpan<byte> source)
    {
        byte[] copy = PinnedBuffer(source.Length);
        source.CopyTo(copy);
        return copy;
    }

    /// <summary>The fixed per-slot challenge the Hello key signs.</summary>
    public static byte[] Challenge(string slotId) =>
        SHA256.HashData(Concat(Encoding.UTF8.GetBytes("kagisecure/windows-hello/v2/challenge"), new byte[] { 0 }, Encoding.UTF8.GetBytes(slotId)));

    /// <summary>
    /// Derive the key-encryption key from the Hello signature and the DPAPI-held app secret. The
    /// returned (pinned) array is the caller's to clear.
    /// </summary>
    public static byte[] DeriveKek(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> appSecret, string slotId)
    {
        if (signature.Length == 0)
        {
            throw new ArgumentException("empty signature", nameof(signature));
        }

        if (appSecret.Length != AppSecretLength)
        {
            throw new ArgumentException("the app secret has the wrong length", nameof(appSecret));
        }

        byte[] ikm = PinnedBuffer(signature.Length + appSecret.Length);
        byte[] kek = PinnedBuffer(32);
        try
        {
            signature.CopyTo(ikm);
            appSecret.CopyTo(ikm.AsSpan(signature.Length));
            byte[] salt = Encoding.UTF8.GetBytes("kagisecure/windows-hello/v2");
            byte[] info = Concat(Encoding.UTF8.GetBytes("kagisecure/windows-hello/v2/kek"), new byte[] { 0 }, Encoding.UTF8.GetBytes(slotId));
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, kek, salt, info);
            return kek;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(kek);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>Wrap the vault key under <paramref name="kek"/>, bound to the slot and the vault file. The blob is not secret.</summary>
    public static byte[] Wrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> vaultKey, string slotId, ReadOnlySpan<byte> vaultId)
    {
        if (vaultKey.Length != VaultKeyLength)
        {
            throw new ArgumentException("the vault key has the wrong length", nameof(vaultKey));
        }

        byte[] blob = new byte[BlobLength];
        Magic.CopyTo(blob);
        Span<byte> nonce = blob.AsSpan(4, NonceLength);
        RandomNumberGenerator.Fill(nonce);
        Span<byte> ciphertext = blob.AsSpan(4 + NonceLength, VaultKeyLength);
        Span<byte> tag = blob.AsSpan(4 + NonceLength + VaultKeyLength, TagLength);
        using var aes = new AesGcm(kek, TagLength);
        aes.Encrypt(nonce, vaultKey, ciphertext, tag, AssociatedData(slotId, vaultId));
        return blob;
    }

    /// <summary>
    /// Unwrap. Returns the vault key in a pinned array (the caller's to clear), or <c>null</c> when
    /// the blob is not this construction's or does not authenticate under <paramref name="kek"/> for
    /// this slot and this vault file — a different Hello key, a different app secret, a blob copied
    /// from another vault, or a tampered one all look the same, deliberately.
    /// </summary>
    public static byte[]? Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> blob, string slotId, ReadOnlySpan<byte> vaultId)
    {
        if (blob.Length != BlobLength || !blob[..4].SequenceEqual(Magic))
        {
            return null;
        }

        byte[] vaultKey = PinnedBuffer(VaultKeyLength);
        try
        {
            using var aes = new AesGcm(kek, TagLength);
            aes.Decrypt(
                blob.Slice(4, NonceLength),
                blob.Slice(4 + NonceLength, VaultKeyLength),
                blob.Slice(4 + NonceLength + VaultKeyLength, TagLength),
                vaultKey,
                AssociatedData(slotId, vaultId));
            return vaultKey;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(vaultKey);
            return null;
        }
    }

    /// <summary>
    /// The DPAPI optional entropy for a slot's app secret: binds the protected blob to the slot, so
    /// one slot's file copied over another's does not unprotect into it.
    /// </summary>
    public static byte[] DpapiEntropy(string slotId) =>
        Concat(Encoding.UTF8.GetBytes("kagisecure/windows-hello/v2/app-secret"), new byte[] { 0 }, Encoding.UTF8.GetBytes(slotId));

    private static byte[] AssociatedData(string slotId, ReadOnlySpan<byte> vaultId)
    {
        if (vaultId.Length == 0 || vaultId.Length > 255)
        {
            throw new ArgumentException("a vault-file id is 1 to 255 bytes", nameof(vaultId));
        }

        return Concat(Magic.ToArray(), new[] { (byte)vaultId.Length }, vaultId.ToArray(), Encoding.UTF8.GetBytes(slotId));
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach (byte[] p in parts)
        {
            length += p.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            p.CopyTo(result, offset);
            offset += p.Length;
        }

        return result;
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>
/// An unlocked vault. <see cref="Dispose"/> is the lock: it calls <see cref="Lock"/>, which zeroizes
/// the vault key, ends every release and kills every agent lease whoever else still holds a
/// reference, and then releases this reference to the Rust <c>VaultSession</c>.
/// </summary>
/// <remarks>
/// <para>
/// Hold one in <c>using</c>. The finalizer behind the handle will eventually lock a forgotten
/// session, but "eventually" is not a lock (ADR-0003 C4). After <see cref="Dispose"/>, every method
/// throws <see cref="ObjectDisposedException"/>. Call <see cref="Agent.Stop"/> and
/// <see cref="BrowserExtension.Stop"/> first: each holds its own reference to the session.
/// </para>
/// <para>
/// <b>Threading.</b> Every method is synchronous and thread-safe, and none belongs on the UI
/// thread: <see cref="Create"/>, the <c>Unlock*</c> constructors and
/// <see cref="ChangeMasterPassword"/> run Argon2id (about a second at the desktop profile), and
/// every mutating method re-encrypts and saves the whole file before it returns. Use
/// <c>Task.Run</c>.
/// </para>
/// <para>
/// <b>Secrets.</b> Secrets going in are <see cref="ReadOnlySpan{T}"/> so a caller can hold them in
/// a buffer it clears; the UTF-8 copy made for the call is pinned and zeroed as soon as it returns.
/// Secrets coming out as <see cref="string"/> (<see cref="FieldRelease.Value"/>, <see cref="TakeRecoveryCode"/>,
/// a <see cref="TotpCode"/>) cannot be zeroized — the same limit a Swift <c>String</c> has, accepted
/// because showing them is the feature. <see cref="FieldRelease.ValueUtf8"/> and
/// <see cref="ExportVaultKeyForPlatformWrapping"/> return a <c>byte[]</c> the caller must clear.
/// </para>
/// <para>
/// <b>Presence (ADR-0038).</b> Nothing concealed leaves the vault except through
/// <see cref="ReleaseField"/>, <see cref="ReleaseTotp"/> and <see cref="ReleaseNotes"/>, and each
/// asks the <see cref="IPresenceGate"/> installed with <see cref="SetPresenceGate"/> first — with
/// none installed, each fails closed with <see cref="KagisecureException.NoPresenceGate"/>.
/// </para>
/// </remarks>
public sealed unsafe class VaultSession : IDisposable
{
    private readonly SessionHandle handle;
    private nint presenceGateKey;

    private VaultSession(SessionHandle handle)
    {
        this.handle = handle;
    }

    /// <summary>Whether this session has been disposed — that is, locked.</summary>
    public bool IsDisposed => handle.IsClosed;

    /// <summary>The handle, for the agent and the extension listener to take their own reference.</summary>
    internal SessionHandle Handle => handle;

    // -------------------------------------------------------------------------------------------
    // Vault files (no session needed)
    // -------------------------------------------------------------------------------------------

    /// <summary>Whether a vault file exists at <paramref name="path"/>: the empty state or the unlock card.</summary>
    public static bool Exists(string path)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_vault_exists(p.Slice, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>
    /// Where the user's vault lives by default — <c>KAGISECURE_VAULT</c>, else
    /// <c>KAGISECURE_HOME</c>, else the per-user data directory — the same answer the CLI gives.
    /// </summary>
    public static string DefaultPath()
    {
        EnsureAbi();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_default_vault_path(&output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>
    /// The platform slot's identifier, read from the header without unlocking — whether to offer
    /// Windows Hello before the password field. <c>null</c> when the vault has no platform slot.
    /// </summary>
    /// <exception cref="KagisecureException.NotFound">No file there.</exception>
    /// <exception cref="KagisecureException.WrongCredential">The file is not a kagisecure vault.</exception>
    public static string? PlatformSlotIdOf(string path)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        KgsOptBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_platform_slot_id(p.Slice, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>
    /// The platform slot's wrapped key: opaque keystore ciphertext, raw bytes, for Windows Hello to
    /// unwrap and hand back through <see cref="UnlockWithVaultKey"/>. <c>null</c> when there is no
    /// platform slot.
    /// </summary>
    /// <exception cref="KagisecureException.NotFound">No file there.</exception>
    public static byte[]? PlatformWrappedKeyOf(string path)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        KgsOptBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_platform_wrapped_key(p.Slice, &output, &error), ref error);
        return TakeBytes(ref output);
    }

    /// <summary>
    /// The vault-file id and the platform slot, from <b>one</b> read of the header — so the slot
    /// id and the wrapped key cannot come from two versions of a file replaced in between.
    /// </summary>
    /// <exception cref="KagisecureException.NotFound">No file there.</exception>
    /// <exception cref="KagisecureException.WrongCredential">The file is not a kagisecure vault.</exception>
    public static PlatformSlotInfo PlatformSlotInfoOf(string path)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        KgsPlatformSlotInfo output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_platform_slot_info(p.Slice, &output, &error), ref error);
            return new PlatformSlotInfo(
                CopyBytes(output.vault_id),
                Str(output.slot_id),
                output.wrapped_key.present != 0 ? CopyBytes(output.wrapped_key.value) : null);
        }
        finally
        {
            NativeMethods.kgs_platform_slot_info_free(&output);
        }
    }

    private static byte[] CopyBytes(in KgsBuffer buffer)
    {
        if (buffer.len == 0 || buffer.ptr == null)
        {
            return Array.Empty<byte>();
        }

        return new ReadOnlySpan<byte>(buffer.ptr, checked((int)buffer.len)).ToArray();
    }

    // -------------------------------------------------------------------------------------------
    // Constructors and the lock
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Create a vault file and unlock it. <paramref name="kdfMKib"/> and <paramref name="kdfT"/>
    /// override the Argon2id cost; leave them <c>null</c> for the desktop profile. Tests pass tiny
    /// values so a vault takes milliseconds, the same escape hatch the CLI has. Show
    /// <see cref="TakeRecoveryCode"/> before the user goes any further.
    /// </summary>
    /// <exception cref="KagisecureException.AlreadyExists">There is already a file at <paramref name="path"/>.</exception>
    public static VaultSession Create(
        string path, ReadOnlySpan<char> masterPassword, string vaultName, uint? kdfMKib = null, uint? kdfT = null)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        using var pw = new PinnedUtf8(masterPassword);
        using var name = new PinnedUtf8(vaultName);
        KgsSession* output = null;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_create(
            p.Slice, pw.Slice, name.Slice, KgsOptU32.From(kdfMKib), KgsOptU32.From(kdfT), &output, &error);
        return Adopt(status, output, ref error);
    }

    /// <summary>Unlock with the master password. ADR-0008 crossing 1.</summary>
    /// <exception cref="KagisecureException.NotFound">No vault at <paramref name="path"/>.</exception>
    /// <exception cref="KagisecureException.WrongCredential">The password does not open it.</exception>
    public static VaultSession UnlockWithPassword(string path, ReadOnlySpan<char> masterPassword)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        using var pw = new PinnedUtf8(masterPassword);
        KgsSession* output = null;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_unlock_with_password(p.Slice, pw.Slice, &output, &error);
        return Adopt(status, output, ref error);
    }

    /// <summary>
    /// Unlock with the printable recovery code. ADR-0008 crossing 1. Ask for a new master password
    /// afterwards (<see cref="UnlockedBy"/> is <see cref="UnlockKind.RecoveryCode"/>).
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">The code does not parse or its checksum fails.</exception>
    /// <exception cref="KagisecureException.WrongCredential">It parses but does not open this vault.</exception>
    public static VaultSession UnlockWithRecoveryCode(string path, ReadOnlySpan<char> recoveryCode)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        using var code = new PinnedUtf8(recoveryCode);
        KgsSession* output = null;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_unlock_with_recovery_code(p.Slice, code.Slice, &output, &error);
        return Adopt(status, output, ref error);
    }

    /// <summary>
    /// Unlock with a vault key the platform keystore has unwrapped. ADR-0008 crossing 4: the key
    /// is raw bytes end to end and is never decoded as text. Clear your copy when this returns.
    /// </summary>
    /// <exception cref="KagisecureException.WrongCredential">The key does not open this vault.</exception>
    public static VaultSession UnlockWithVaultKey(string path, ReadOnlySpan<byte> vaultKey)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        KgsSession* output = null;
        KgsBuffer error = default;
        KgsStatus status;
        fixed (byte* key = vaultKey)
        {
            status = NativeMethods.kgs_session_unlock_with_vault_key(
                p.Slice, new KgsSlice(key, vaultKey.Length), &output, &error);
        }
        return Adopt(status, output, ref error);
    }

    /// <summary>
    /// Lock now: zeroize the vault key, end every release, and answer a release whose prompt is
    /// still up "vault locked" whatever the prompt then says (ADR-0038 §4). Idempotent; the object
    /// stays usable only for reading <see cref="IsUnlocked"/> until it is disposed.
    /// </summary>
    public void Lock()
    {
        using var s = handle.Borrow();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_lock(s.Ptr, &error), ref error);
    }

    /// <summary>Whether the vault is still unlocked.</summary>
    public bool IsUnlocked
    {
        get
        {
            if (handle.IsClosed)
            {
                return false;
            }

            using var s = handle.Borrow();
            byte output = 0;
            KgsBuffer error = default;
            Check(NativeMethods.kgs_session_is_unlocked(s.Ptr, &output, &error), ref error);
            return output != 0;
        }
    }

    /// <summary>
    /// Re-read the vault file if another writer (the CLI, the MCP daemon) changed it. Returns
    /// whether anything was picked up.
    /// </summary>
    public bool Sync()
    {
        using var s = handle.Borrow();
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_sync(s.Ptr, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>
    /// Lock (<see cref="Lock"/>), then release this reference. The presence gate is forgotten
    /// last: a release that raced the lock to the gate is answered "cancelled", never with a
    /// dangling callback.
    /// </summary>
    public void Dispose()
    {
        if (!handle.IsClosed)
        {
            try
            {
                Lock();
            }
            catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
            {
                // Already locked or already disposed: the handle below is all that is left.
            }
        }

        handle.Dispose();
        nint key = Interlocked.Exchange(ref presenceGateKey, 0);
        if (key != 0)
        {
            PresenceBridge.Unregister(key);
        }
    }

    /// <summary>Wrap a freshly minted pointer, or throw on failure.</summary>
    private static VaultSession Adopt(KgsStatus status, KgsSession* output, ref KgsBuffer error)
    {
        Check(status, ref error);
        return new VaultSession(new SessionHandle(output));
    }

    // -------------------------------------------------------------------------------------------
    // Session state
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The one-time recovery code, if this session created the vault — once, then <c>null</c>.
    /// A managed string that cannot be zeroized; show it, then drop every reference.
    /// </summary>
    public string? TakeRecoveryCode()
    {
        using var s = handle.Borrow();
        KgsOptBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_take_recovery_code(s.Ptr, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>Where this vault lives.</summary>
    public string Path
    {
        get
        {
            using var s = handle.Borrow();
            KgsBuffer output = default;
            KgsBuffer error = default;
            Check(NativeMethods.kgs_session_path(s.Ptr, &output, &error), ref error);
            return TakeString(ref output);
        }
    }

    /// <summary>How this session unlocked.</summary>
    public UnlockKind UnlockedBy
    {
        get
        {
            using var s = handle.Borrow();
            uint output = 0;
            KgsBuffer error = default;
            Check(NativeMethods.kgs_session_unlocked_by(s.Ptr, &output, &error), ref error);
            return (UnlockKind)output;
        }
    }

    /// <summary>The logical vaults inside the file, for the vault switcher.</summary>
    public IReadOnlyList<LogicalVault> Vaults()
    {
        using var s = handle.Borrow();
        KgsVaultViewArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_vaults(s.Ptr, &output, &error), ref error);
            return List<KgsVaultView, LogicalVault>(output.ptr, output.len, LogicalVault.From);
        }
        finally
        {
            NativeMethods.kgs_vault_view_array_free(&output);
        }
    }

    /// <summary>
    /// Share a logical vault with agents, or stop — the outermost of the agent's three gates.
    /// Returns the core's "the logical vault was found", which is always <c>true</c> here because
    /// an unknown id throws first.
    /// </summary>
    /// <exception cref="KagisecureException.NotPresent">No such logical vault.</exception>
    public bool SetVaultAgentVisible(string vaultId, bool visible)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(vaultId);
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_set_vault_agent_visible(s.Ptr, id.Slice, Byte(visible), &output, &error), ref error);
        return output != 0;
    }

    /// <summary>The logical vault new items go into.</summary>
    public string DefaultVaultId()
    {
        using var s = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_default_vault_id(s.Ptr, &output, &error), ref error);
        return TakeString(ref output);
    }

    // -------------------------------------------------------------------------------------------
    // Items
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The item list for one sidebar section, optionally searched. <paramref name="query"/> matches
    /// title, tags and URLs — never field values.
    /// </summary>
    public IReadOnlyList<Item> ListItems(ItemFilter filter, string? query = null, ItemSort sort = ItemSort.Title)
    {
        ArgumentNullException.ThrowIfNull(filter);
        using var s = handle.Borrow();
        (KgsItemFilterTag tag, string? value) = filter.ToNative();
        using var v = new PinnedUtf8(value ?? string.Empty);
        using var q = PinnedUtf8.Optional(query);
        var native = new KgsItemFilter { tag = (uint)tag, value = v.Slice };
        KgsItemViewArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_list_items(s.Ptr, &native, q.OptSlice, (uint)sort, &output, &error), ref error);
            return List<KgsItemView, Item>(output.ptr, output.len, Interop.Item.From);
        }
        finally
        {
            NativeMethods.kgs_item_view_array_free(&output);
        }
    }

    /// <summary>One item by id.</summary>
    /// <exception cref="KagisecureException.NotPresent">No item with that id.</exception>
    public Item Item(string itemId)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(itemId);
        KgsItemView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_item(s.Ptr, id.Slice, &output, &error);
        return TakeItem(status, ref output, ref error);
    }

    /// <summary>The counts the sidebar shows.</summary>
    public SidebarCounts SidebarCounts()
    {
        using var s = handle.Borrow();
        KgsSidebarCounts output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_sidebar_counts(s.Ptr, &output, &error), ref error);
            return Interop.SidebarCounts.From(output);
        }
        finally
        {
            NativeMethods.kgs_sidebar_counts_free(&output);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Presence-gated releases (ADR-0038)
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Install the app's presence check. Once per session: a second call is refused and the first
    /// gate stays, so nothing that runs later can swap in a gate that always says yes.
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">A gate is already installed.</exception>
    public void SetPresenceGate(IPresenceGate gate)
    {
        ArgumentNullException.ThrowIfNull(gate);
        using var s = handle.Borrow();
        nint key = PresenceBridge.Register(gate);
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_set_presence_gate(s.Ptr, PresenceBridge.Confirm, (void*)key, &error);
        if (status != KgsStatus.Ok)
        {
            PresenceBridge.Unregister(key);
            Check(status, ref error);
        }

        presenceGateKey = key;
    }

    /// <summary>
    /// Ask the presence gate, then hand out a release that can read one concealed field. Blocks for
    /// as long as the prompt is up: call it from a background thread. ADR-0008 crossing 2.
    /// </summary>
    /// <exception cref="KagisecureException.NoPresenceGate">No gate is installed.</exception>
    /// <exception cref="KagisecureException.PresenceCancelled">The person said no.</exception>
    /// <exception cref="KagisecureException.PresenceUnavailable">No check could run.</exception>
    /// <exception cref="KagisecureException.PresenceBusy">Another prompt is up.</exception>
    /// <exception cref="KagisecureException.NotPresent">Unknown item or field.</exception>
    /// <exception cref="KagisecureException.Invalid">The field is not concealed, or its value is not text.</exception>
    public FieldRelease ReleaseField(string itemId, string fieldId, ReleasePurpose purpose)
    {
        using var s = handle.Borrow();
        using var item = new PinnedUtf8(itemId);
        using var field = new PinnedUtf8(fieldId);
        KgsFieldRelease* output = null;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_release_field(s.Ptr, item.Slice, field.Slice, (uint)purpose, &output, &error), ref error);
        return new FieldRelease(output, itemId, fieldId);
    }

    /// <summary>
    /// Ask the presence gate, then hand out a release that derives an item's one-time code — the
    /// named TOTP field's, or with <paramref name="fieldId"/> <c>null</c> the item's first. Blocks
    /// while the prompt is up. <see cref="ReleasePurpose.EditReveal"/> is refused.
    /// </summary>
    /// <exception cref="KagisecureException.NotPresent">Unknown item, or it has no one-time password.</exception>
    public TotpRelease ReleaseTotp(string itemId, string? fieldId, ReleasePurpose purpose)
    {
        using var s = handle.Borrow();
        using var item = new PinnedUtf8(itemId);
        using var field = PinnedUtf8.Optional(fieldId);
        KgsTotpRelease* output = null;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_release_totp(s.Ptr, item.Slice, field.OptSlice, (uint)purpose, &output, &error), ref error);
        return new TotpRelease(output, itemId);
    }

    /// <summary>
    /// Ask the presence gate, then hand out a release that can read an item's notes (every note is
    /// secret, ADR-0038 user decision 3). Blocks while the prompt is up.
    /// <see cref="ReleasePurpose.QuickAccessCopy"/> is refused.
    /// </summary>
    /// <exception cref="KagisecureException.NotPresent">Unknown item, or it has no notes.</exception>
    public NotesRelease ReleaseNotes(string itemId, ReleasePurpose purpose)
    {
        using var s = handle.Borrow();
        using var item = new PinnedUtf8(itemId);
        KgsNotesRelease* output = null;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_release_notes(s.Ptr, item.Slice, (uint)purpose, &output, &error), ref error);
        return new NotesRelease(output, itemId);
    }

    /// <summary>
    /// Create an item pre-populated with its category's default fields, saved at once.
    /// <paramref name="vaultId"/> <c>null</c> is the default logical vault.
    /// </summary>
    /// <exception cref="KagisecureException.NotPresent">No such logical vault.</exception>
    public Item CreateItem(string category, string title, string? vaultId = null)
    {
        using var s = handle.Borrow();
        using var v = PinnedUtf8.Optional(vaultId);
        using var c = new PinnedUtf8(category);
        using var t = new PinnedUtf8(title);
        KgsItemView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_create_item(s.Ptr, v.OptSlice, c.Slice, t.Slice, &output, &error);
        return TakeItem(status, ref output, ref error);
    }

    /// <summary>
    /// Replace an item's editable content with what the edit sheet produced. Fields keep their ids;
    /// fields the draft omits are deleted; agent visibility is never taken from the draft; a
    /// <see cref="FieldDraft.Value"/> or <see cref="ItemDraft.Notes"/> of <c>null</c> keeps what is
    /// stored. ADR-0008 crossing 2, inbound: every non-null <see cref="FieldDraft.Value"/>.
    /// </summary>
    /// <exception cref="KagisecureException.NotPresent">Unknown item.</exception>
    /// <exception cref="KagisecureException.ItemChangedElsewhere">The item changed since <see cref="ItemDraft.Revision"/> was read.</exception>
    public Item SaveItem(ItemDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        using var s = handle.Borrow();
        using var pins = new DraftPins(draft);
        KgsItemDraft native = pins.Native;
        KgsItemView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_save_item(s.Ptr, &native, &output, &error);
        return TakeItem(status, ref output, ref error);
    }

    /// <summary>Toggle the favourite star.</summary>
    public Item SetFavorite(string itemId, bool favorite) =>
        SetFlag(itemId, favorite, &NativeMethods.kgs_session_set_favorite);

    /// <summary>Move an item to the archive, or bring it back.</summary>
    public Item SetArchived(string itemId, bool archived) =>
        SetFlag(itemId, archived, &NativeMethods.kgs_session_set_archived);

    /// <summary>Move an item to the trash, or restore it. A soft delete.</summary>
    public Item SetTrashed(string itemId, bool trashed) =>
        SetFlag(itemId, trashed, &NativeMethods.kgs_session_set_trashed);

    /// <summary>The item-level "Visible to agents" toggle. Turning it off turns every field off too.</summary>
    public Item SetAgentVisible(string itemId, bool visible) =>
        SetFlag(itemId, visible, &NativeMethods.kgs_session_set_agent_visible);

    private Item SetFlag(
        string itemId,
        bool value,
        delegate*<KgsSession*, KgsSlice, byte, KgsItemView*, KgsBuffer*, KgsStatus> call)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(itemId);
        KgsItemView output = default;
        KgsBuffer error = default;
        KgsStatus status = call(s.Ptr, id.Slice, Byte(value), &output, &error);
        return TakeItem(status, ref output, ref error);
    }

    /// <summary>One field's agent-visibility override.</summary>
    /// <exception cref="KagisecureException.NotPresent">Unknown item or field.</exception>
    public Item SetFieldAgentVisible(string itemId, string fieldId, bool visible)
    {
        using var s = handle.Borrow();
        using var item = new PinnedUtf8(itemId);
        using var field = new PinnedUtf8(fieldId);
        KgsItemView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_set_field_agent_visible(
            s.Ptr, item.Slice, field.Slice, Byte(visible), &output, &error);
        return TakeItem(status, ref output, ref error);
    }

    /// <summary>
    /// Delete an item for good — only if it is still in the Trash and still at
    /// <paramref name="revision"/>, the <see cref="Item.Revision"/> of the row the person chose.
    /// </summary>
    /// <exception cref="KagisecureException.NotPresent">Unknown item.</exception>
    /// <exception cref="KagisecureException.ItemChangedElsewhere">It was restored or changed meanwhile.</exception>
    public void DeleteItem(string itemId, string revision)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(itemId);
        using var rev = new PinnedUtf8(revision);
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_delete_item(s.Ptr, id.Slice, rev.Slice, &error), ref error);
    }

    /// <summary>One field of one item, freshly read.</summary>
    /// <exception cref="KagisecureException.NotPresent">Unknown item or field.</exception>
    public Field Field(string itemId, string fieldId)
    {
        using var s = handle.Borrow();
        using var item = new PinnedUtf8(itemId);
        using var field = new PinnedUtf8(fieldId);
        KgsFieldView output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_field(s.Ptr, item.Slice, field.Slice, &output, &error), ref error);
            return Interop.Field.From(output);
        }
        finally
        {
            NativeMethods.kgs_field_view_free(&output);
        }
    }

    private static Item TakeItem(KgsStatus status, ref KgsItemView output, ref KgsBuffer error)
    {
        Check(status, ref error);
        return Interop.Item.Take(ref output);
    }

    // -------------------------------------------------------------------------------------------
    // Environments
    // -------------------------------------------------------------------------------------------

    /// <summary>Every environment, names and bindings only.</summary>
    public IReadOnlyList<VaultEnvironment> Environments()
    {
        using var s = handle.Borrow();
        KgsEnvironmentViewArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_environments(s.Ptr, &output, &error), ref error);
            return List<KgsEnvironmentView, VaultEnvironment>(output.ptr, output.len, VaultEnvironment.From);
        }
        finally
        {
            NativeMethods.kgs_environment_view_array_free(&output);
        }
    }

    /// <summary>One environment, by id or name.</summary>
    /// <exception cref="KagisecureException.NotPresent">No such environment.</exception>
    public VaultEnvironment Environment(string environmentId)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(environmentId);
        KgsEnvironmentView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_environment(s.Ptr, id.Slice, &output, &error);
        return TakeEnvironment(status, ref output, ref error);
    }

    /// <summary>Create an empty environment, invisible to agents until the user says otherwise.</summary>
    /// <exception cref="KagisecureException.Invalid">An empty name.</exception>
    public VaultEnvironment CreateEnvironment(string name, string? description = null)
    {
        using var s = handle.Borrow();
        using var n = new PinnedUtf8(name);
        using var d = PinnedUtf8.Optional(description);
        KgsEnvironmentView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_create_environment(s.Ptr, n.Slice, d.OptSlice, &output, &error);
        return TakeEnvironment(status, ref output, ref error);
    }

    /// <summary>Share an environment with agents, or stop sharing it.</summary>
    public VaultEnvironment SetEnvironmentAgentVisible(string environmentId, bool visible)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(environmentId);
        KgsEnvironmentView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_set_environment_agent_visible(
            s.Ptr, id.Slice, Byte(visible), &output, &error);
        return TakeEnvironment(status, ref output, ref error);
    }

    /// <summary>
    /// Supply a variable's value, typed by the user. ADR-0008 crossing 2, inbound: take it from a
    /// clearable buffer and clear it after.
    /// </summary>
    public VaultEnvironment SetVariableValue(string environmentId, string name, ReadOnlySpan<char> value)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(environmentId);
        using var n = new PinnedUtf8(name);
        using var v = new PinnedUtf8(value);
        KgsEnvironmentView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_set_variable_value(s.Ptr, id.Slice, n.Slice, v.Slice, &output, &error);
        return TakeEnvironment(status, ref output, ref error);
    }

    /// <summary>Bind a variable to an item's field instead of a literal.</summary>
    /// <exception cref="KagisecureException.NotPresent">The environment, item or field does not exist.</exception>
    public VaultEnvironment BindVariable(string environmentId, string name, string itemId, string fieldId)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(environmentId);
        using var n = new PinnedUtf8(name);
        using var item = new PinnedUtf8(itemId);
        using var field = new PinnedUtf8(fieldId);
        KgsEnvironmentView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_bind_variable(
            s.Ptr, id.Slice, n.Slice, item.Slice, field.Slice, &output, &error);
        return TakeEnvironment(status, ref output, ref error);
    }

    /// <summary>Remove one variable from an environment.</summary>
    public VaultEnvironment RemoveVariable(string environmentId, string name)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(environmentId);
        using var n = new PinnedUtf8(name);
        KgsEnvironmentView output = default;
        KgsBuffer error = default;
        KgsStatus status = NativeMethods.kgs_session_remove_variable(s.Ptr, id.Slice, n.Slice, &output, &error);
        return TakeEnvironment(status, ref output, ref error);
    }

    /// <summary>Delete an environment.</summary>
    /// <exception cref="KagisecureException.NotPresent">No such environment.</exception>
    public void DeleteEnvironment(string environmentId)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(environmentId);
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_delete_environment(s.Ptr, id.Slice, &error), ref error);
    }

    private static VaultEnvironment TakeEnvironment(KgsStatus status, ref KgsEnvironmentView output, ref KgsBuffer error)
    {
        Check(status, ref error);
        return VaultEnvironment.Take(ref output);
    }

    // -------------------------------------------------------------------------------------------
    // Audit
    // -------------------------------------------------------------------------------------------

    /// <summary>A page of the audit log, newest first.</summary>
    public IReadOnlyList<AuditRow> AuditPage(uint limit, uint offset)
    {
        using var s = handle.Borrow();
        KgsAuditRowArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_audit_page(s.Ptr, limit, offset, &output, &error), ref error);
            return List<KgsAuditRow, AuditRow>(output.ptr, output.len, AuditRow.From);
        }
        finally
        {
            NativeMethods.kgs_audit_row_array_free(&output);
        }
    }

    /// <summary>How many entries the audit log has.</summary>
    public uint AuditCount()
    {
        using var s = handle.Borrow();
        uint output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_audit_count(s.Ptr, &output, &error), ref error);
        return output;
    }

    /// <summary>Whether the audit hash chain verifies.</summary>
    public bool AuditIntact()
    {
        using var s = handle.Borrow();
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_audit_intact(s.Ptr, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>
    /// Whether every appended audit entry has reached disk — a different question from
    /// <see cref="AuditIntact"/>. Nonzero <see cref="AuditDurability.UnsavedEntries"/> means a save
    /// has been failing and the UI should say so.
    /// </summary>
    public AuditDurability AuditDurability()
    {
        using var s = handle.Borrow();
        KgsAuditDurability output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_audit_durability(s.Ptr, &output, &error), ref error);
            return new AuditDurability(output.unsaved_entries, Str(output.last_error));
        }
        finally
        {
            NativeMethods.kgs_audit_durability_free(&output);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Credentials and the platform slot (Windows Hello)
    // -------------------------------------------------------------------------------------------

    /// <summary>Replace the master password — required after a recovery-code unlock. ADR-0008 crossing 1.</summary>
    public void ChangeMasterPassword(ReadOnlySpan<char> newPassword)
    {
        using var s = handle.Borrow();
        using var pw = new PinnedUtf8(newPassword);
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_change_master_password(s.Ptr, pw.Slice, &error), ref error);
    }

    /// <summary>
    /// Whether <paramref name="masterPassword"/> opens <b>this</b> unlocked vault — checked in
    /// memory against the header the session holds, never against the file on disk, so a file
    /// swapped underneath (a known password, enormous KDF parameters) changes nothing. Runs
    /// Argon2id: not on the UI thread. ADR-0008 crossing 1.
    /// </summary>
    /// <remarks>
    /// The one master-password check the app has — the approval sheet's fallback and the presence
    /// gate's (ADR-0038 user decision 7) alike. Rate limited per session, and a wrong or throttled
    /// attempt is audited; a right one while a release waits on its prompt marks that release as
    /// granted by the master password rather than by Windows Hello.
    /// </remarks>
    public MasterPasswordCheck VerifyMasterPassword(ReadOnlySpan<char> masterPassword)
    {
        using var s = handle.Borrow();
        using var pw = new PinnedUtf8(masterPassword);
        KgsMasterPasswordCheck output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_verify_master_password(s.Ptr, pw.Slice, &output, &error), ref error);
        return MasterPasswordCheck.From(output);
    }

    /// <summary>The vault file's random id, from the header in memory. Not secret.</summary>
    public byte[] VaultFileId()
    {
        using var s = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_vault_file_id_bytes(s.Ptr, &output, &error), ref error);
        return TakeBytes(ref output);
    }

    /// <summary>Whether this vault has a platform (Windows Hello) slot.</summary>
    public bool HasPlatformSlot()
    {
        using var s = handle.Borrow();
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_has_platform_slot(s.Ptr, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>The platform slot's identifier, if there is one.</summary>
    public string? PlatformSlotId()
    {
        using var s = handle.Borrow();
        KgsOptBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_platform_slot_id(s.Ptr, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>
    /// The raw vault key, for the platform keystore to wrap. ADR-0008 crossing 3. The returned
    /// array is yours: clear it with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/> as soon as the
    /// keystore has consumed it. Rust has already zeroized its own copy.
    /// </summary>
    public byte[] ExportVaultKeyForPlatformWrapping()
    {
        using var s = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_export_vault_key(s.Ptr, &output, &error), ref error);
        return TakeBytes(ref output);
    }

    /// <summary>Store the keystore's wrapped copy of the vault key, replacing any platform slot.</summary>
    /// <exception cref="KagisecureException.Invalid">An empty <paramref name="wrappedKey"/>.</exception>
    public void InstallPlatformSlot(string slotId, string label, ReadOnlySpan<byte> wrappedKey)
    {
        using var s = handle.Borrow();
        using var id = new PinnedUtf8(slotId);
        using var l = new PinnedUtf8(label);
        KgsBuffer error = default;
        KgsStatus status;
        fixed (byte* key = wrappedKey)
        {
            status = NativeMethods.kgs_session_install_platform_slot(
                s.Ptr, id.Slice, l.Slice, new KgsSlice(key, wrappedKey.Length), &error);
        }
        Check(status, ref error);
    }

    /// <summary>Forget the platform slot. Returns whether there was one.</summary>
    public bool RemovePlatformSlot()
    {
        using var s = handle.Borrow();
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_remove_platform_slot(s.Ptr, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>Write the vault to disk. Every mutating method already does.</summary>
    public void Save()
    {
        using var s = handle.Borrow();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_save(s.Ptr, &error), ref error);
    }

    // -------------------------------------------------------------------------------------------
    // Import
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Parse an export into a plan. Nothing is written; the parsed values stay in Rust behind the
    /// returned <see cref="ImportPlan"/>, which must be disposed. <paramref name="format"/>
    /// <c>null</c> detects it from the file.
    /// </summary>
    /// <exception cref="KagisecureException.NotFound">No file there.</exception>
    /// <exception cref="KagisecureException.Invalid">It cannot be parsed.</exception>
    public ImportPlan ImportPreview(string path, ImportFormat? format = null)
    {
        using var s = handle.Borrow();
        using var p = new PinnedUtf8(path);
        KgsImportPlan* output = null;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_session_import_preview(s.Ptr, p.Slice, KgsOptU32.From((uint?)format), &output, &error), ref error);
        return new ImportPlan(new ImportPlanHandle(output));
    }

    /// <summary>The plan previewed against this vault under <paramref name="policy"/>: duplicates known.</summary>
    /// <exception cref="KagisecureException.Invalid">The plan has been committed.</exception>
    public ImportReport ImportPreviewAgainst(ImportPlan plan, DuplicatePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(plan);
        using var s = handle.Borrow();
        using var p = plan.Handle.Borrow();
        KgsImportReport output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_import_preview_against(s.Ptr, p.Ptr, (uint)policy, &output, &error), ref error);
            return ImportReport.From(output);
        }
        finally
        {
            NativeMethods.kgs_import_report_free(&output);
        }
    }

    /// <summary>
    /// Apply the plan and save. The plan is spent afterwards. <paramref name="targetVault"/> names
    /// one logical vault for everything (created if missing); <c>null</c> follows the source.
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">The plan is already spent.</exception>
    public ImportOutcome ImportCommit(ImportPlan plan, DuplicatePolicy policy, string? targetVault = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        using var s = handle.Borrow();
        using var p = plan.Handle.Borrow();
        using var target = PinnedUtf8.Optional(targetVault);
        KgsImportOutcome output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_session_import_commit(s.Ptr, p.Ptr, (uint)policy, target.OptSlice, &output, &error), ref error);
            return ImportOutcome.From(output);
        }
        finally
        {
            NativeMethods.kgs_import_outcome_free(&output);
        }
    }

    /// <summary>
    /// An <see cref="ItemDraft"/> pinned for one call: every string a <see cref="PinnedUtf8"/>, and
    /// the field and slice arrays on the pinned heap, so the native draft's pointers stay valid.
    /// </summary>
    private sealed class DraftPins : IDisposable
    {
        private readonly List<IDisposable> owned = new();
        private readonly KgsFieldDraft[] fields;
        private readonly PinnedUtf8 id;
        private readonly PinnedUtf8 category;
        private readonly PinnedUtf8 title;
        private readonly PinnedUtf8 notes;
        private readonly PinnedUtf8 revision;
        private readonly PinnedUtf8List tags;
        private readonly PinnedUtf8List urls;

        internal DraftPins(ItemDraft draft)
        {
            id = Own(new PinnedUtf8(draft.Id));
            category = Own(new PinnedUtf8(draft.Category));
            title = Own(new PinnedUtf8(draft.Title));
            notes = Own(PinnedUtf8.Optional(draft.Notes));
            revision = Own(new PinnedUtf8(draft.Revision));
            tags = Own(new PinnedUtf8List(draft.Tags ?? Array.Empty<string>()));
            urls = Own(new PinnedUtf8List(draft.Urls ?? Array.Empty<string>()));
            IReadOnlyList<FieldDraft> source = draft.Fields ?? Array.Empty<FieldDraft>();
            fields = GC.AllocateArray<KgsFieldDraft>(source.Count, pinned: true);
            for (int i = 0; i < source.Count; i++)
            {
                FieldDraft f = source[i] ?? throw new ArgumentException("a field draft was null", nameof(draft));
                fields[i] = new KgsFieldDraft
                {
                    id = Own(PinnedUtf8.Optional(f.Id)).OptSlice,
                    label = Own(new PinnedUtf8(f.Label)).Slice,
                    kind = (uint)f.Kind,
                    concealed = Byte(f.Concealed),
                    value = Own(PinnedUtf8.Optional(f.Value)).OptSlice,
                    section = Own(PinnedUtf8.Optional(f.Section)).OptSlice,
                    agent_visible = Byte(f.AgentVisible),
                };
            }
        }

        internal KgsItemDraft Native => new()
        {
            id = id.Slice,
            category = category.Slice,
            title = title.Slice,
            fields = new KgsFieldDraftList
            {
                ptr = fields.Length == 0
                    ? null
                    : (KgsFieldDraft*)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(fields)),
                len = (nuint)fields.Length,
            },
            tags = tags.List,
            urls = urls.List,
            notes = notes.OptSlice,
            revision = revision.Slice,
        };

        public void Dispose()
        {
            foreach (IDisposable d in owned.AsEnumerable().Reverse())
            {
                d.Dispose();
            }
        }

        private T Own<T>(T disposable)
            where T : IDisposable
        {
            owned.Add(disposable);
            return disposable;
        }
    }
}

using System;
using System.Collections.Generic;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>How a field's value is presented and edited. Values are the generated native tags.</summary>
public enum FieldKind : uint
{
    /// <summary>Plain text.</summary>
    Text = (uint)KgsFieldKind.Text,

    /// <summary>Password-like; rendered masked.</summary>
    Concealed = (uint)KgsFieldKind.Concealed,

    /// <summary>Email address.</summary>
    Email = (uint)KgsFieldKind.Email,

    /// <summary>URL.</summary>
    Url = (uint)KgsFieldKind.Url,

    /// <summary>Telephone number.</summary>
    Phone = (uint)KgsFieldKind.Phone,

    /// <summary>A date.</summary>
    Date = (uint)KgsFieldKind.Date,

    /// <summary>A month/year pair (card expiry).</summary>
    MonthYear = (uint)KgsFieldKind.MonthYear,

    /// <summary>A TOTP seed.</summary>
    Totp = (uint)KgsFieldKind.Totp,

    /// <summary>A choice from a fixed list.</summary>
    Menu = (uint)KgsFieldKind.Menu,

    /// <summary>Credit card number.</summary>
    CreditCardNumber = (uint)KgsFieldKind.CreditCardNumber,

    /// <summary>Credit card brand.</summary>
    CreditCardType = (uint)KgsFieldKind.CreditCardType,

    /// <summary>A postal address.</summary>
    Address = (uint)KgsFieldKind.Address,

    /// <summary>A reference to another item.</summary>
    Reference = (uint)KgsFieldKind.Reference,

    /// <summary>A file attachment.</summary>
    File = (uint)KgsFieldKind.File,
}

/// <summary>The item list's sort order.</summary>
public enum ItemSort : uint
{
    /// <summary>Title, A–Z, case-insensitive.</summary>
    Title = (uint)KgsItemSort.Title,

    /// <summary>Most recently modified first.</summary>
    DateModified = (uint)KgsItemSort.DateModified,

    /// <summary>Most recently created first.</summary>
    DateCreated = (uint)KgsItemSort.DateCreated,

    /// <summary>Category, then title.</summary>
    Category = (uint)KgsItemSort.Category,
}

/// <summary>How the current session unlocked the vault.</summary>
public enum UnlockKind : uint
{
    /// <summary>The master password.</summary>
    Password = (uint)KgsUnlockKind.Password,

    /// <summary>The printable recovery code; ask for a new master password afterwards.</summary>
    RecoveryCode = (uint)KgsUnlockKind.RecoveryCode,

    /// <summary>The platform keystore — Windows Hello here, Touch ID on macOS.</summary>
    PlatformKey = (uint)KgsUnlockKind.PlatformKey,
}

/// <summary>
/// Which sidebar section the item list is showing — the C# mirror of Rust's <c>ItemFilter</c>, an
/// enum with data. A closed hierarchy: the private constructor means these six are the only cases.
/// </summary>
public abstract record ItemFilter
{
    private ItemFilter()
    {
    }

    /// <summary>Every item that is neither archived nor trashed.</summary>
    public sealed record All : ItemFilter;

    /// <summary>Favourites, excluding archived and trashed.</summary>
    public sealed record Favorites : ItemFilter;

    /// <summary>One category, by canonical name (<c>"login"</c>, <c>"secure-note"</c>, …).</summary>
    /// <param name="Name">The category's canonical name.</param>
    public sealed record Category(string Name) : ItemFilter;

    /// <summary>One tag.</summary>
    /// <param name="Name">The tag.</param>
    public sealed record Tag(string Name) : ItemFilter;

    /// <summary>Archived items.</summary>
    public sealed record Archive : ItemFilter;

    /// <summary>Trashed items.</summary>
    public sealed record Trash : ItemFilter;

    /// <summary>The tag <c>KgsItemFilter</c> uses, and the payload if this case carries one.</summary>
    internal (KgsItemFilterTag Tag, string? Value) ToNative() => this switch
    {
        All => (KgsItemFilterTag.All, null),
        Favorites => (KgsItemFilterTag.Favorites, null),
        Category c => (KgsItemFilterTag.Category, c.Name),
        Tag t => (KgsItemFilterTag.Tag, t.Name),
        Archive => (KgsItemFilterTag.Archive, null),
        Trash => (KgsItemFilterTag.Trash, null),
        _ => throw new InvalidOperationException("unreachable: ItemFilter is closed"),
    };
}

/// <summary>A category, as a sidebar row or a "+ New item" menu entry needs it.</summary>
/// <param name="Id">Canonical name, e.g. <c>"credit-card"</c> — what the app sends back.</param>
/// <param name="DisplayName">Display name, e.g. <c>"Credit Card"</c>.</param>
/// <param name="SymbolName">The macOS SF Symbol name; the Windows app maps it to its own glyph.</param>
public sealed record CategoryInfo(string Id, string DisplayName, string SymbolName)
{
    internal static CategoryInfo From(in KgsCategoryInfo n) =>
        new(Str(n.id), Str(n.display_name), Str(n.symbol_name));
}

/// <summary>Every category the vault format knows about.</summary>
public static class Categories
{
    /// <summary>The "+ New item" menu, in catalogue order.</summary>
    public static unsafe IReadOnlyList<CategoryInfo> Catalog()
    {
        EnsureAbi();
        KgsCategoryInfoArray native = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_category_catalog(&native, &error), ref error);
            return List<KgsCategoryInfo, CategoryInfo>(native.ptr, native.len, CategoryInfo.From);
        }
        finally
        {
            NativeMethods.kgs_category_info_array_free(&native);
        }
    }
}

/// <summary>One field of an item, as the detail pane renders it.</summary>
/// <param name="Id">Field identifier.</param>
/// <param name="Label">Human label.</param>
/// <param name="Kind">How to present it.</param>
/// <param name="Concealed">The value is secret material and must be masked.</param>
/// <param name="HasValue">There is a value at all — for a concealed field, the only thing known until it is revealed.</param>
/// <param name="Value">The value for a field that is not concealed; <c>null</c> for a concealed one (use <see cref="VaultSession.ReleaseField"/>, behind a presence check).</param>
/// <param name="Section">Optional section name.</param>
/// <param name="AgentVisible">Per-field agent visibility.</param>
public sealed record Field(
    string Id,
    string Label,
    FieldKind Kind,
    bool Concealed,
    bool HasValue,
    string? Value,
    string? Section,
    bool AgentVisible)
{
    internal static Field From(in KgsFieldView n) => new(
        Str(n.id),
        Str(n.label),
        (FieldKind)n.kind,
        n.concealed != 0,
        n.has_value != 0,
        Str(n.value),
        Str(n.section),
        n.agent_visible != 0);
}

/// <summary>One item, as the list and detail panes render it.</summary>
/// <param name="Id">Item identifier.</param>
/// <param name="VaultId">The logical vault it lives in.</param>
/// <param name="Category">Canonical category name.</param>
/// <param name="CategoryDisplayName">Display name of the category.</param>
/// <param name="CategorySymbol">The macOS SF Symbol for the category.</param>
/// <param name="Title">Title.</param>
/// <param name="Fields">Fields, in display order.</param>
/// <param name="Tags">Tags.</param>
/// <param name="Urls">Associated URLs.</param>
/// <param name="HasNotes">Whether the item has a note. Never the note itself: that is <see cref="VaultSession.ReleaseNotes"/> (ADR-0038 user decision 3).</param>
/// <param name="Favorite">Favourited.</param>
/// <param name="Archived">Archived.</param>
/// <param name="Trashed">In the trash.</param>
/// <param name="AgentVisible">Visible to agents. <c>false</c> on every new item.</param>
/// <param name="CreatedAt">Unix seconds.</param>
/// <param name="UpdatedAt">Unix seconds.</param>
/// <param name="Subtitle">The item list's one-line subtitle. Never a secret.</param>
/// <param name="Username">The username, if the item has one. Never a secret.</param>
/// <param name="PrimarySecretFieldId">The field this item designates as its password, if any.</param>
/// <param name="Revision">
/// An opaque fingerprint of the item as read. Hand it back unchanged in <see cref="ItemDraft.Revision"/>
/// and to <see cref="VaultSession.DeleteItem"/>; a save or delete from a stale read is refused with
/// <see cref="KagisecureException.ItemChangedElsewhere"/>.
/// </param>
public sealed record Item(
    string Id,
    string VaultId,
    string Category,
    string CategoryDisplayName,
    string CategorySymbol,
    string Title,
    ValueList<Field> Fields,
    ValueList<string> Tags,
    ValueList<string> Urls,
    bool HasNotes,
    bool Favorite,
    bool Archived,
    bool Trashed,
    bool AgentVisible,
    ulong CreatedAt,
    ulong UpdatedAt,
    string? Subtitle,
    string? Username,
    string? PrimarySecretFieldId,
    string Revision)
{
    internal static unsafe Item From(in KgsItemView n) => new(
        Str(n.id),
        Str(n.vault_id),
        Str(n.category),
        Str(n.category_display_name),
        Str(n.category_symbol),
        Str(n.title),
        List<KgsFieldView, Field>(n.fields.ptr, n.fields.len, Field.From),
        Strings(n.tags),
        Strings(n.urls),
        n.has_notes != 0,
        n.favorite != 0,
        n.archived != 0,
        n.trashed != 0,
        n.agent_visible != 0,
        n.created_at,
        n.updated_at,
        Str(n.subtitle),
        Str(n.username),
        Str(n.primary_secret_field_id),
        Str(n.revision));

    /// <summary>Copy the native item out and free it, whatever happens.</summary>
    internal static unsafe Item Take(ref KgsItemView native)
    {
        try
        {
            return From(native);
        }
        finally
        {
            fixed (KgsItemView* p = &native)
            {
                NativeMethods.kgs_item_view_free(p);
            }
        }
    }
}

/// <summary>
/// A field as the edit sheet hands it back. ADR-0008 crossing 2: <see cref="Value"/> is the
/// plaintext the user typed, and a <see cref="string"/> — immutable and not zeroizable, the same
/// limit a Swift <c>String</c> has. The UTF-8 copy made for the call is cleared when it returns.
/// </summary>
/// <remarks>
/// The edit sheet is never handed a concealed value to send back (ADR-0038 user decision 4):
/// <see cref="Value"/> <c>null</c> keeps the stored value. Turning a concealed field public
/// without a new value is refused.
/// </remarks>
/// <param name="Id">Existing field identifier, or <c>null</c> for a new field.</param>
/// <param name="Label">Human label.</param>
/// <param name="Kind">How to present it.</param>
/// <param name="Concealed">The value is secret material.</param>
/// <param name="Value">The new value, or <c>null</c> to keep the stored one.</param>
/// <param name="Section">Optional section name.</param>
/// <param name="AgentVisible">Per-field agent visibility; ignored for existing fields, which keep theirs.</param>
public sealed record FieldDraft(
    string? Id,
    string Label,
    FieldKind Kind,
    bool Concealed,
    string? Value,
    string? Section,
    bool AgentVisible);

/// <summary>An item as the edit sheet hands it back.</summary>
/// <param name="Id">The item being edited.</param>
/// <param name="Category">Canonical category name.</param>
/// <param name="Title">Title.</param>
/// <param name="Fields">Fields, in the order they should be stored. Fields left out are deleted.</param>
/// <param name="Tags">Tags.</param>
/// <param name="Urls">Associated URLs.</param>
/// <param name="Notes">The note: <c>null</c> keeps the stored note, <c>""</c> removes it, anything else replaces it.</param>
/// <param name="Revision"><see cref="Item.Revision"/> as it stood when the edit began.</param>
public sealed record ItemDraft(
    string Id,
    string Category,
    string Title,
    IReadOnlyList<FieldDraft> Fields,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> Urls,
    string? Notes,
    string Revision);

/// <summary>A name and how many items carry it: a category or a tag.</summary>
/// <param name="Name">The category's canonical name, or the tag.</param>
/// <param name="Count">How many items.</param>
public sealed record TagCount(string Name, uint Count)
{
    internal static TagCount From(in KgsTagCount n) => new(Str(n.name), n.count);
}

/// <summary>The counts the sidebar shows next to its rows.</summary>
/// <param name="All">Items in "All Items".</param>
/// <param name="Favorites">Favourites.</param>
/// <param name="Archive">Archived items.</param>
/// <param name="Trash">Trashed items.</param>
/// <param name="Categories">Per-category counts, in catalogue order, zeros included.</param>
/// <param name="Tags">Per-tag counts, sorted by tag.</param>
public sealed record SidebarCounts(
    uint All,
    uint Favorites,
    uint Archive,
    uint Trash,
    ValueList<TagCount> Categories,
    ValueList<TagCount> Tags)
{
    internal static unsafe SidebarCounts From(in KgsSidebarCounts n) => new(
        n.all,
        n.favorites,
        n.archive,
        n.trash,
        List<KgsTagCount, TagCount>(n.categories.ptr, n.categories.len, TagCount.From),
        List<KgsTagCount, TagCount>(n.tags.ptr, n.tags.len, TagCount.From));
}

/// <summary>A logical vault inside the vault file.</summary>
/// <param name="Id">Identifier.</param>
/// <param name="Name">Display name.</param>
/// <param name="ItemCount">Items it holds, trashed and archived included.</param>
/// <param name="AgentVisible">Whether agents may see it at all.</param>
public sealed record LogicalVault(string Id, string Name, uint ItemCount, bool AgentVisible)
{
    internal static LogicalVault From(in KgsVaultView n) =>
        new(Str(n.id), Str(n.name), n.item_count, n.agent_visible != 0);
}

/// <summary>
/// What a platform keystore needs from a vault header before unlocking, read in one go
/// (<see cref="VaultSession.PlatformSlotInfoOf"/>). Nothing here is secret: the wrapped key is
/// opaque keystore ciphertext.
/// </summary>
/// <param name="VaultId">The header's random vault-file id.</param>
/// <param name="SlotId">The platform slot's id, or <c>null</c> when there is none.</param>
/// <param name="WrappedKey">The platform slot's wrapped key, or <c>null</c> when there is none.</param>
public sealed record PlatformSlotInfo(byte[] VaultId, string? SlotId, byte[]? WrappedKey);

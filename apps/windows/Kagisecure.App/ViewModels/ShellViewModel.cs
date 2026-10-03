using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// The main shell after unlock (ui-spec.md §2): sidebar with live counts (All/Favorites/Archive/
/// Trash, every category, every tag — all real, from <see cref="IVaultService.SidebarCountsAsync"/>
/// and <see cref="IVaultService.Categories"/>), a real item-list pane (filter/search/sort via
/// <see cref="IVaultService.ListItemsAsync"/>), and a detail pane for the selected item. The
/// sidebar's Agent access group is ShellPage's own (Views/ShellPage.AgentAccess.cs): its pages
/// have view models of their own over <see cref="AgentHostService"/>.
/// </summary>
public sealed partial class ShellViewModel : ObservableObject
{
    // Section management (add/rename/delete/reorder a section, move a field between sections) is
    // in ShellViewModel.Sections.cs, which also declares this class's IEditSectionActions.

    /// <summary>Segoe Fluent Icons glyphs for the categories ui-spec.md §5 names; a category the catalog adds later falls back to <see cref="DefaultCategoryGlyph"/>.</summary>
    private static readonly IReadOnlyDictionary<string, string> GlyphByCategoryId = new Dictionary<string, string>
    {
        ["login"] = "",
        ["password"] = "",
        ["secure-note"] = "",
        ["credit-card"] = "",
        ["identity"] = "",
        ["api-credential"] = "",
        ["server"] = "",
        ["database"] = "",
        ["ssh-key"] = "",
        ["software-license"] = "",
        ["document"] = "",
        ["environment"] = "",
    };

    private const string DefaultCategoryGlyph = ""; // generic tag glyph, for a category the catalog adds later.
    private const string TagGlyph = "";

    /// <summary>ui-spec.md §3's sort menu.</summary>
    public static readonly IReadOnlyList<ItemSort> SortChoices = new[]
    {
        ItemSort.Title, ItemSort.DateModified, ItemSort.DateCreated, ItemSort.Category,
    };

    /// <summary>Every <see cref="FieldKind"/> the "+ Add field" menu offers, matching the macOS editor's list (ui-spec.md §4.3).</summary>
    public static readonly IReadOnlyList<FieldKind> AddableFieldKindsList = new[]
    {
        FieldKind.Text, FieldKind.Concealed, FieldKind.Email, FieldKind.Url, FieldKind.Phone,
        FieldKind.Date, FieldKind.MonthYear, FieldKind.Totp, FieldKind.CreditCardNumber, FieldKind.Address,
    };

    private readonly IVaultService vaultService;
    private readonly IClipboardService clipboardService;

    /// <summary>Guards against an in-flight item-list request finishing after a newer one (e.g. search typed while a request from the previous keystroke is still out).</summary>
    private int itemsRequestGeneration;

    public ShellViewModel(IVaultService vaultService, IClipboardService clipboardService)
    {
        this.vaultService = vaultService;
        this.clipboardService = clipboardService;

        AllItems = new SidebarNodeViewModel("All Items", new ItemFilter.All(), "");
        Favorites = new SidebarNodeViewModel("Favorites", new ItemFilter.Favorites(), "");
        Archive = new SidebarNodeViewModel("Archive", new ItemFilter.Archive(), "");
        Trash = new SidebarNodeViewModel("Trash", new ItemFilter.Trash(), "");

        CategoryNodes = new ObservableCollection<SidebarNodeViewModel>(
            vaultService.Categories().Select(c =>
                new SidebarNodeViewModel(
                    c.DisplayName,
                    new ItemFilter.Category(c.Id),
                    GlyphByCategoryId.TryGetValue(c.Id, out string? g) ? g : DefaultCategoryGlyph)));

        TagNodes = new ObservableCollection<SidebarNodeViewModel>();

        Items = new ObservableCollection<Item>();
        DetailFields = new ObservableCollection<FieldRowViewModel>();
        EditFields = new ObservableCollection<FieldDraftRowViewModel>();
        Categories = vaultService.Categories();
        WireSectionTracking(); // ShellViewModel.Sections.cs: keeps EditSections/DetailSections in sync with EditFields/DetailFields.

        selectedNode = AllItems;
        sortOrder = ItemSort.Title;
    }

    /// <summary>Every category, for the "+ New item" menu's one entry per category (ui-spec.md §2.3/§5).</summary>
    public IReadOnlyList<CategoryInfo> Categories { get; }

    /// <summary>Instance wrapper around <see cref="AddableFieldKindsList"/>, for x:Bind.</summary>
    public IReadOnlyList<FieldKind> AddableFieldKinds => AddableFieldKindsList;

    public SidebarNodeViewModel AllItems { get; }

    public SidebarNodeViewModel Favorites { get; }

    public SidebarNodeViewModel Archive { get; }

    public SidebarNodeViewModel Trash { get; }

    public ObservableCollection<SidebarNodeViewModel> CategoryNodes { get; }

    /// <summary>Every distinct tag, with counts — real now (<see cref="SidebarCounts.Tags"/>), populated by <see cref="RefreshCountsAsync"/>.</summary>
    public ObservableCollection<SidebarNodeViewModel> TagNodes { get; }

    /// <summary>ui-spec.md §2.2's top group: All Items, Favorites.</summary>
    public IReadOnlyList<SidebarNodeViewModel> TopNodes => new[] { AllItems, Favorites };

    /// <summary>ui-spec.md §2.2's bottom group: Archive, Trash.</summary>
    public IReadOnlyList<SidebarNodeViewModel> BottomNodes => new[] { Archive, Trash };

    [ObservableProperty]
    private SidebarNodeViewModel selectedNode;

    [ObservableProperty]
    private string searchQuery = string.Empty;

    [ObservableProperty]
    private ItemSort sortOrder;

    [ObservableProperty]
    private bool isLoadingItems;

    /// <summary>The item-list pane's rows for the current filter/search/sort.</summary>
    public ObservableCollection<Item> Items { get; }

    [ObservableProperty]
    private Item? selectedItem;

    /// <summary>The detail pane's field rows for <see cref="SelectedItem"/>.</summary>
    public ObservableCollection<FieldRowViewModel> DetailFields { get; }

    /// <summary>Instance wrapper around <see cref="SortChoices"/>, for x:Bind (which needs an instance member).</summary>
    public IReadOnlyList<ItemSort> SortOptions => SortChoices;

    public string ItemListHeader => Items.Count switch
    {
        0 when IsLoadingItems => "Loading…",
        0 => $"{SelectedNode.DisplayName} — no items",
        1 => $"{SelectedNode.DisplayName} — 1 item",
        var n => $"{SelectedNode.DisplayName} — {n} items",
    };

    partial void OnSelectedNodeChanged(SidebarNodeViewModel value)
    {
        OnPropertyChanged(nameof(ItemListHeader));
        _ = RefreshItemsAsync();
    }

    partial void OnSearchQueryChanged(string value) => _ = RefreshItemsAsync();

    partial void OnSortOrderChanged(ItemSort value) => _ = RefreshItemsAsync();

    partial void OnSelectedItemChanged(Item? value)
    {
        IsEditingItem = false;
        ClearDetailFields();
        HideNotes();
        NotesText = value is { HasNotes: true } ? NotesMask : null;
        OnPropertyChanged(nameof(CanShowNotes));
        if (value is not null)
        {
            foreach (Field field in value.Fields)
            {
                DetailFields.Add(new FieldRowViewModel(vaultService, clipboardService, value.Id, field));
            }
        }

        RebuildDetailSections(); // ShellViewModel.Sections.cs
    }

    // -------------------------------------------------------------------------------------------
    // Notes (ADR-0038 user decision 3: every note is secret)
    // -------------------------------------------------------------------------------------------

    private const string NotesMask = "••••••••••";

    /// <summary>The live release behind the notes on screen, if they are showing.</summary>
    private INotesRelease? shownNotes;

    /// <summary>What the detail pane shows for the notes: nothing, the mask, or — after "Show notes" — the text.</summary>
    [ObservableProperty]
    private string? notesText;

    /// <summary>Whether "Show notes" applies: the item has notes and they are not showing.</summary>
    public bool CanShowNotes => SelectedItem is { HasNotes: true } && shownNotes is null;

    /// <summary>"Show notes": one Windows Hello confirmation, then the notes until deselect, lock or five minutes.</summary>
    [RelayCommand]
    private async Task ShowNotesAsync()
    {
        if (SelectedItem is not { HasNotes: true } item || shownNotes is not null)
        {
            return;
        }

        try
        {
            INotesRelease release = await vaultService.ReleaseNotesAsync(item.Id, ReleasePurpose.Reveal).ConfigureAwait(true);
            string text;
            try
            {
                text = await Task.Run(release.Text).ConfigureAwait(true);
            }
            catch
            {
                release.Dispose();
                throw;
            }

            if (SelectedItem?.Id != item.Id)
            {
                release.Dispose();
                return;
            }

            shownNotes = release;
            NotesText = text;
            OnPropertyChanged(nameof(CanShowNotes));
            _ = HideNotesAtCapAsync(release);
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            // Not confirmed, or locked: they stay masked. Nothing was released.
        }
    }

    /// <summary>Hide the notes when their release reaches its five-minute cap (user decision 5).</summary>
    private async Task HideNotesAtCapAsync(INotesRelease release)
    {
        try
        {
            ReleaseState state = await Task.Run(release.State).ConfigureAwait(true);
            await Task.Delay(TimeSpan.FromSeconds(state.SecondsRemaining)).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
        {
            // Already ended.
        }

        if (ReferenceEquals(shownNotes, release))
        {
            HideNotes();
            NotesText = SelectedItem is { HasNotes: true } ? NotesMask : null;
            OnPropertyChanged(nameof(CanShowNotes));
        }
    }

    private void HideNotes()
    {
        shownNotes?.Dispose();
        shownNotes = null;
    }

    /// <summary>
    /// End and hide everything the detail pane has released — for the lock, when the shell is torn
    /// down. (Rust has already ended every release by then; this takes the text off the screen.)
    /// </summary>
    public void HideReleasedValues()
    {
        ClearDetailFields();
        HideNotes();
        NotesText = null;
    }

    private void ClearDetailFields()
    {
        foreach (FieldRowViewModel row in DetailFields)
        {
            row.Dispose();
        }

        DetailFields.Clear();
        // The detail pane renders DetailSections, not DetailFields: drop the grouped view too, or a
        // disposed row — and whatever value it was showing — would stay on screen past the lock.
        DetailSections.Clear();
    }

    [RelayCommand]
    private async Task RefreshCountsAsync()
    {
        try
        {
            SidebarCounts counts = await vaultService.SidebarCountsAsync().ConfigureAwait(true);
            AllItems.Count = counts.All;
            Favorites.Count = counts.Favorites;
            Archive.Count = counts.Archive;
            Trash.Count = counts.Trash;

            foreach (SidebarNodeViewModel node in CategoryNodes)
            {
                string canonical = ((ItemFilter.Category)node.Filter).Name;
                node.Count = counts.Categories.FirstOrDefault(c => c.Name == canonical)?.Count ?? 0;
            }

            TagNodes.Clear();
            foreach (TagCount tag in counts.Tags)
            {
                TagNodes.Add(new SidebarNodeViewModel(tag.Name, new ItemFilter.Tag(tag.Name), TagGlyph) { Count = tag.Count });
            }
        }
        catch (KagisecureException)
        {
            // Locked mid-refresh (e.g. auto-lock fired) — the lock-screen navigation is already
            // under way; nothing useful to show here.
        }

        await RefreshItemsAsync().ConfigureAwait(true);
    }

    private async Task RefreshItemsAsync()
    {
        int generation = ++itemsRequestGeneration;
        IsLoadingItems = true;
        OnPropertyChanged(nameof(ItemListHeader));
        try
        {
            string? query = string.IsNullOrWhiteSpace(SearchQuery) ? null : SearchQuery;
            IReadOnlyList<Item> items = await vaultService.ListItemsAsync(SelectedNode.Filter, query, SortOrder).ConfigureAwait(true);
            if (generation != itemsRequestGeneration)
            {
                return; // a newer request has since started; drop this stale result.
            }

            Items.Clear();
            foreach (Item item in items)
            {
                Items.Add(item);
            }
        }
        catch (KagisecureException)
        {
            if (generation == itemsRequestGeneration)
            {
                Items.Clear();
            }
        }
        finally
        {
            if (generation == itemsRequestGeneration)
            {
                IsLoadingItems = false;
                OnPropertyChanged(nameof(ItemListHeader));
            }
        }
    }

    [RelayCommand]
    private void LockNow() => vaultService.Lock();

    // -------------------------------------------------------------------------------------------
    // Item create / edit / delete (ui-spec.md §4.3)
    // -------------------------------------------------------------------------------------------

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isEditingItem;

    [ObservableProperty]
    private string editTitle = string.Empty;

    [ObservableProperty]
    private string editTagsText = string.Empty;

    [ObservableProperty]
    private string editUrlsText = string.Empty;

    [ObservableProperty]
    private string editNotes = string.Empty;

    /// <summary>
    /// Whether anything was typed into the notes box. Untouched, the save sends no note and the
    /// stored one is kept (the editor prefills nothing secret, ADR-0038 user decision 4); touched,
    /// the box's text replaces it — empty removes it.
    /// </summary>
    private bool editNotesTouched;

    /// <summary>What the empty notes box says while the stored note is being kept.</summary>
    public string EditNotesPlaceholder =>
        SelectedItem is { HasNotes: true } && !editNotesTouched ? "Unchanged (hidden) — type to replace" : string.Empty;

    partial void OnEditNotesChanged(string value)
    {
        if (!editNotesTouched && IsEditingItem)
        {
            editNotesTouched = true;
            OnPropertyChanged(nameof(EditNotesPlaceholder));
        }
    }

    [ObservableProperty]
    private string? editError;

    [ObservableProperty]
    private bool isSavingEdit;

    /// <summary>The edit form's field rows — local state; nothing reaches the vault until Save (ui-spec.md §4.3).</summary>
    public ObservableCollection<FieldDraftRowViewModel> EditFields { get; }

    public bool CanSaveEdit => !IsSavingEdit && !string.IsNullOrWhiteSpace(EditTitle);

    /// <summary>"+ New item" (ui-spec.md §2.3): pre-populated from the category's default field template.</summary>
    [RelayCommand]
    private async Task NewItemAsync(string categoryId)
    {
        ErrorMessage = null;
        try
        {
            Item created = await vaultService.CreateItemAsync(categoryId, "New item").ConfigureAwait(true);
            SelectedNode = AllItems;
            await RefreshItemsAsync().ConfigureAwait(true);
            SelectedItem = Items.FirstOrDefault(i => i.Id == created.Id) ?? created;
            await BeginEditAsync().ConfigureAwait(true);
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    /// <summary>
    /// Enter edit mode (⌘E / ui-spec.md §4.3). Nothing concealed is prefilled (ADR-0038 user
    /// decision 4): a stored secret, and the notes, stay as they are unless something is typed over
    /// them, so editing a title never releases a value.
    /// </summary>
    [RelayCommand]
    private Task BeginEditAsync()
    {
        if (SelectedItem is not { } item)
        {
            return Task.CompletedTask;
        }

        EditError = null;
        EditTitle = item.Title;
        EditTagsText = string.Join(", ", item.Tags);
        EditUrlsText = string.Join(Environment.NewLine, item.Urls);
        EditNotes = string.Empty;
        editNotesTouched = false; // after the reset above, which is not the person typing
        OnPropertyChanged(nameof(EditNotesPlaceholder));
        ResetSectionState(); // ShellViewModel.Sections.cs: a fresh edit shouldn't remember another item's pending sections.

        EditFields.Clear();
        foreach (Field field in item.Fields)
        {
            EditFields.Add(new FieldDraftRowViewModel(field));
        }

        IsEditingItem = true;
        return Task.CompletedTask;
    }

    [RelayCommand]
    private void CancelEdit()
    {
        IsEditingItem = false;
        EditError = null;
        EditFields.Clear();
        ResetSectionState(); // ShellViewModel.Sections.cs
    }

    [RelayCommand]
    private void AddField(FieldKind kind) => EditFields.Add(new FieldDraftRowViewModel(kind));

    [RelayCommand]
    private void RemoveField(FieldDraftRowViewModel row) => EditFields.Remove(row);

    [RelayCommand]
    private void MoveFieldUp(FieldDraftRowViewModel row)
    {
        int index = EditFields.IndexOf(row);
        if (index > 0)
        {
            EditFields.Move(index, index - 1);
        }
    }

    [RelayCommand]
    private void MoveFieldDown(FieldDraftRowViewModel row)
    {
        int index = EditFields.IndexOf(row);
        if (index >= 0 && index < EditFields.Count - 1)
        {
            EditFields.Move(index, index + 1);
        }
    }

    [RelayCommand(CanExecute = nameof(CanSaveEdit))]
    private async Task SaveEditAsync()
    {
        if (SelectedItem is not { } item)
        {
            return;
        }

        IsSavingEdit = true;
        EditError = null;
        try
        {
            IReadOnlyList<string> tags = SplitList(EditTagsText, ',');
            IReadOnlyList<string> urls = SplitList(EditUrlsText, '\n');
            // Untouched: null keeps the stored note. Touched: the text replaces it, and an empty box
            // removes it ("" is the vault's "remove", distinct from "keep").
            string? notes = editNotesTouched ? (string.IsNullOrWhiteSpace(EditNotes) ? string.Empty : EditNotes) : null;
            var draft = new ItemDraft(
                item.Id, item.Category, EditTitle.Trim(), EditFields.Select(f => f.ToDraft()).ToList(), tags, urls, notes, item.Revision);
            Item saved = await vaultService.SaveItemAsync(draft).ConfigureAwait(true);
            IsEditingItem = false;
            EditFields.Clear();
            ResetSectionState(); // ShellViewModel.Sections.cs
            await RefreshCountsAsync().ConfigureAwait(true);
            SelectedItem = Items.FirstOrDefault(i => i.Id == saved.Id) ?? saved;
        }
        catch (KagisecureException ex)
        {
            EditError = ex.Message;
        }
        finally
        {
            IsSavingEdit = false;
        }
    }

    private static IReadOnlyList<string> SplitList(string text, char separator) =>
        text.Split(separator).Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

    partial void OnIsSavingEditChanged(bool value) => SaveEditCommand.NotifyCanExecuteChanged();

    partial void OnEditTitleChanged(string value) => SaveEditCommand.NotifyCanExecuteChanged();

    [RelayCommand]
    private async Task ToggleFavoriteAsync() =>
        await MutateSelectedAsync(i => vaultService.SetFavoriteAsync(i.Id, !i.Favorite)).ConfigureAwait(true);

    [RelayCommand]
    private async Task ToggleArchivedAsync() =>
        await MutateSelectedAsync(i => vaultService.SetArchivedAsync(i.Id, !i.Archived)).ConfigureAwait(true);

    /// <summary>Move to Trash, or restore — the same toggle, matching the "..." menu's single Trash/Restore entry (ui-spec.md §4.1).</summary>
    [RelayCommand]
    private async Task ToggleTrashedAsync() =>
        await MutateSelectedAsync(i => vaultService.SetTrashedAsync(i.Id, !i.Trashed)).ConfigureAwait(true);

    /// <summary>Delete permanently — only meaningful from the Trash (ui-spec.md §4.1's "Delete forever").</summary>
    [RelayCommand]
    private async Task DeleteForeverAsync()
    {
        if (SelectedItem is not { } item)
        {
            return;
        }

        ErrorMessage = null;
        try
        {
            await vaultService.DeleteItemAsync(item.Id, item.Revision).ConfigureAwait(true);
            SelectedItem = null;
            await RefreshCountsAsync().ConfigureAwait(true);
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
    }

    /// <summary>Apply a mutation to <see cref="SelectedItem"/>, then refresh counts and the list — the item may leave the current filter (e.g. archiving while viewing All Items).</summary>
    private async Task MutateSelectedAsync(Func<Item, Task<Item>> mutate)
    {
        if (SelectedItem is not { } item)
        {
            return;
        }

        ErrorMessage = null;
        try
        {
            Item updated = await mutate(item).ConfigureAwait(true);
            await RefreshCountsAsync().ConfigureAwait(true);
            SelectedItem = Items.FirstOrDefault(i => i.Id == updated.Id);
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
    }
}

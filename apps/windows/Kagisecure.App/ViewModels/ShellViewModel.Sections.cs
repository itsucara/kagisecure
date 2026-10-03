using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Section management for the item editor (ui-spec.md §4.3) — add/rename/delete/reorder a section,
/// and move a field between sections. See <see cref="EditSectionViewModel"/>'s doc comment for why
/// this is all just relabelling/reordering <see cref="FieldDraftRowViewModel.Section"/> strings:
/// neither the FFI nor macOS's own <c>ItemDraft</c> carries a section entity, only that string per
/// field.
///
/// <see cref="EditFields"/> stays the single source of truth — <see cref="EditSections"/> is a
/// grouped *view* of it, rebuilt whenever it changes (add/remove/move a field) or any field's
/// <see cref="FieldDraftRowViewModel.Section"/> changes, via <see cref="OnEditFieldsChanged"/> and
/// <see cref="OnEditFieldPropertyChanged"/>, which the constructor and <c>EditFields.Add/Remove/
/// Clear/Move</c> calls elsewhere in <c>ShellViewModel</c> already exercise — nothing there needed
/// to change.
/// </summary>
public sealed partial class ShellViewModel : IEditSectionActions
{
    /// <summary>
    /// Section names a user has started (via <see cref="AddSectionCommand"/>) that no field carries
    /// yet. A section is otherwise only as real as the fields in it, so this is the one bit of
    /// section state that doesn't fall out of <see cref="EditFields"/> by itself — everything else
    /// (order, membership) is derived fresh in <see cref="RebuildEditSections"/>.
    /// </summary>
    private readonly List<string> pendingSectionNames = new();

    /// <summary>Grouped view of <see cref="EditFields"/> for the edit form (ui-spec.md §4.3).</summary>
    public ObservableCollection<EditSectionViewModel> EditSections { get; } = new();

    /// <summary>Grouped view of <see cref="DetailFields"/> for the read-only detail pane (ui-spec.md §4.2).</summary>
    public ObservableCollection<DetailSectionViewModel> DetailSections { get; } = new();

    [ObservableProperty]
    private string newSectionName = string.Empty;

    /// <summary>Every <see cref="FieldDraftRowViewModel"/> currently subscribed to <see cref="OnEditFieldPropertyChanged"/> — reconciled against <see cref="EditFields"/> on every change, rather than trusted from the event args, because <c>ObservableCollection.Clear()</c> raises a <c>Reset</c> with no old-items list (BeginEditAsync/CancelEdit/SaveEditAsync all clear the whole collection between items).</summary>
    private readonly HashSet<FieldDraftRowViewModel> trackedEditFields = new();

    /// <summary>
    /// Call once, from the constructor, after <see cref="EditFields"/> is created. Every add/
    /// remove/move/clear of a row keeps <see cref="EditSections"/> in sync, and keeps this instance
    /// subscribed to each row's <see cref="FieldDraftRowViewModel.Section"/> changes.
    /// </summary>
    private void WireSectionTracking() => EditFields.CollectionChanged += OnEditFieldsChanged;

    private void OnEditFieldsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        var current = new HashSet<FieldDraftRowViewModel>(EditFields);
        foreach (FieldDraftRowViewModel stale in trackedEditFields.Where(f => !current.Contains(f)).ToList())
        {
            stale.PropertyChanged -= OnEditFieldPropertyChanged;
            trackedEditFields.Remove(stale);
        }

        foreach (FieldDraftRowViewModel added in current.Where(f => !trackedEditFields.Contains(f)).ToList())
        {
            added.PropertyChanged += OnEditFieldPropertyChanged;
            trackedEditFields.Add(added);
        }

        RebuildEditSections();
    }

    private void OnEditFieldPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(FieldDraftRowViewModel.Section) || sender is not FieldDraftRowViewModel field)
        {
            return;
        }

        // Typing an existing pending section's name into a field's own Section box is how that
        // section stops being "pending" and starts being real — there is no separate "move to
        // section" picker; the field's own box, plus this hook, is what moves it.
        string typed = field.Section ?? string.Empty;
        if (typed.Length > 0)
        {
            pendingSectionNames.RemoveAll(n => string.Equals(n, typed, StringComparison.Ordinal));
        }

        RebuildEditSections();
    }

    private void RebuildEditSections()
    {
        EditSections.Clear();
        (List<string> order, Dictionary<string, List<FieldDraftRowViewModel>> groups) = GroupBySection(EditFields, f => f.Section);

        foreach (string key in order)
        {
            var section = new EditSectionViewModel(key, this);
            foreach (FieldDraftRowViewModel field in groups[key])
            {
                section.Fields.Add(field);
            }

            EditSections.Add(section);
        }

        foreach (string pending in pendingSectionNames)
        {
            if (!order.Contains(pending, StringComparer.Ordinal))
            {
                EditSections.Add(new EditSectionViewModel(pending, this));
            }
        }
    }

    private void RebuildDetailSections()
    {
        DetailSections.Clear();
        (List<string> order, Dictionary<string, List<FieldRowViewModel>> groups) =
            GroupBySection(DetailFields, f => f.Field.Section);
        foreach (string key in order)
        {
            DetailSections.Add(new DetailSectionViewModel(key, groups[key]));
        }
    }

    /// <summary>First-appearance-order grouping by section, empty string for "no section" — matches macOS's <c>ItemDetailView.sections</c> algorithm.</summary>
    private static (List<string> Order, Dictionary<string, List<T>> Groups) GroupBySection<T>(
        IEnumerable<T> items, Func<T, string?> section)
    {
        var order = new List<string>();
        var groups = new Dictionary<string, List<T>>(StringComparer.Ordinal);
        foreach (T item in items)
        {
            string key = section(item) ?? string.Empty;
            if (!groups.TryGetValue(key, out List<T>? list))
            {
                list = new List<T>();
                groups[key] = list;
                order.Add(key);
            }

            list.Add(item);
        }

        return (order, groups);
    }

    /// <summary>Reset transient section state — a fresh edit session shouldn't remember another item's half-made (pending, fieldless) sections.</summary>
    private void ResetSectionState()
    {
        pendingSectionNames.Clear();
        NewSectionName = string.Empty;
        RebuildEditSections(); // drop any pending (fieldless) section EditSections was still showing.
    }

    /// <summary>"+ Add section" (ui-spec.md §4.3): a name with no fields yet, made real the moment a field's Section box names it.</summary>
    [RelayCommand]
    private void AddSection()
    {
        string trimmed = NewSectionName.Trim();
        NewSectionName = string.Empty;
        if (trimmed.Length == 0)
        {
            return;
        }

        bool exists = EditFields.Any(f => string.Equals(f.Section, trimmed, StringComparison.Ordinal))
            || pendingSectionNames.Contains(trimmed, StringComparer.Ordinal);
        if (!exists)
        {
            pendingSectionNames.Add(trimmed);
        }

        RebuildEditSections();
    }

    void IEditSectionActions.RenameSection(EditSectionViewModel section, string newName)
    {
        if (section.IsDefault)
        {
            return;
        }

        string trimmed = newName.Trim();
        string oldName = section.Name;
        string? assign = trimmed.Length == 0 ? null : trimmed;
        foreach (FieldDraftRowViewModel field in EditFields.Where(f => string.Equals(f.Section, oldName, StringComparison.Ordinal)))
        {
            field.Section = assign;
        }

        pendingSectionNames.RemoveAll(n => string.Equals(n, oldName, StringComparison.Ordinal));
        if (assign is not null && !EditFields.Any(f => string.Equals(f.Section, assign, StringComparison.Ordinal)))
        {
            // The section being renamed was itself still pending (no fields yet) — stays pending under its new name.
            pendingSectionNames.Add(assign);
        }

        RebuildEditSections();
    }

    /// <summary>
    /// Removes the section label, not the fields: every field in it moves to "no section" rather
    /// than being deleted along with it. Neither ui-spec.md nor the FFI models a section as
    /// anything more than that label, so there is no separate entity a delete could remove without
    /// also destroying the fields' own data — moving them out is the non-destructive reading of
    /// "sections ... can be removed" (ui-spec.md §4.3).
    /// </summary>
    void IEditSectionActions.DeleteSection(EditSectionViewModel section)
    {
        if (section.IsDefault)
        {
            return;
        }

        foreach (FieldDraftRowViewModel field in EditFields.Where(f => string.Equals(f.Section, section.Name, StringComparison.Ordinal)))
        {
            field.Section = null;
        }

        pendingSectionNames.RemoveAll(n => string.Equals(n, section.Name, StringComparison.Ordinal));
        RebuildEditSections();
    }

    void IEditSectionActions.MoveSectionUp(EditSectionViewModel section) => SwapAdjacentSections(section, -1);

    void IEditSectionActions.MoveSectionDown(EditSectionViewModel section) => SwapAdjacentSections(section, 1);

    /// <summary>
    /// Reorders sections by reordering the fields underneath them: a section's position is nothing
    /// but "where its fields fall in <see cref="EditFields"/>", so swapping two sections means
    /// concatenating their field blocks in the other order (which also makes every section's fields
    /// contiguous afterward, even if they weren't before). Only sections that currently hold at
    /// least one field participate — a still-pending, empty section has no position to swap, so
    /// moving it is a no-op rather than a crash.
    /// </summary>
    private void SwapAdjacentSections(EditSectionViewModel section, int direction)
    {
        List<EditSectionViewModel> real = EditSections.Where(s => s.Fields.Count > 0).ToList();
        int index = real.IndexOf(section);
        int otherIndex = index + direction;
        if (index < 0 || otherIndex < 0 || otherIndex >= real.Count)
        {
            return;
        }

        List<string> keyOrder = real.Select(s => s.Name).ToList();
        (keyOrder[index], keyOrder[otherIndex]) = (keyOrder[otherIndex], keyOrder[index]);

        Dictionary<string, List<FieldDraftRowViewModel>> byKey =
            real.ToDictionary(s => s.Name, s => s.Fields.ToList(), StringComparer.Ordinal);
        var reordered = new List<FieldDraftRowViewModel>();
        foreach (string key in keyOrder)
        {
            reordered.AddRange(byKey[key]);
        }

        // Rebuild EditFields' order without tearing down/recreating the rows themselves (identity
        // matters: e.g. an open TOTP setup dialog holds a reference to one row). The
        // CollectionChanged handler is detached for the swap itself, since interpreting a Clear
        // followed by N Adds as "every field changed" would unsubscribe/resubscribe every row's
        // PropertyChanged handler for no reason; one rebuild at the end is enough.
        EditFields.CollectionChanged -= OnEditFieldsChanged;
        try
        {
            EditFields.Clear();
            foreach (FieldDraftRowViewModel field in reordered)
            {
                EditFields.Add(field);
            }
        }
        finally
        {
            EditFields.CollectionChanged += OnEditFieldsChanged;
        }

        RebuildEditSections();
    }
}

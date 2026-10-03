using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Callbacks an <see cref="EditSectionViewModel"/>'s own commands reach back through — implemented
/// by <see cref="ShellViewModel"/>. A section has no identity of its own in the FFI
/// (<c>FieldDraft.Section</c> is just a string on each field — see
/// <c>crates/kagisecure-ffi/src/capi/items.rs</c>, unchanged for this feature), so every one of
/// these operations really means "relabel/reorder some fields". This interface is the seam that
/// lets <see cref="EditSectionViewModel"/> ask for that without holding a reference to the whole
/// edit form.
/// </summary>
public interface IEditSectionActions
{
    /// <summary>Relabel every field in <paramref name="section"/> to <paramref name="newName"/> (blank merges them into "no section").</summary>
    void RenameSection(EditSectionViewModel section, string newName);

    /// <summary>Move every field in <paramref name="section"/> out to "no section" — the section label is removed, the fields are not.</summary>
    void DeleteSection(EditSectionViewModel section);

    /// <summary>Swap this section's field block with the one before it.</summary>
    void MoveSectionUp(EditSectionViewModel section);

    /// <summary>Swap this section's field block with the one after it.</summary>
    void MoveSectionDown(EditSectionViewModel section);
}

/// <summary>
/// One section of the item editor (ui-spec.md §4.3: "sections can be added/renamed/reordered/
/// removed"), grouping some of <see cref="ShellViewModel.EditFields"/> by their shared
/// <see cref="FieldDraftRowViewModel.Section"/>.
///
/// # Why this has no macOS screen to mirror
///
/// macOS's <c>ItemEditView</c> (apps/macos/Kagisecure/Views/ItemEditView.swift) has no section UI
/// at all today: a new field's <c>section</c> is always set to <c>nil</c>, and nothing in that view
/// ever reads or writes an existing field's <c>section</c> — only the read-only
/// <c>ItemDetailView</c> groups by it, for display. So there is no macOS behavior to copy pixel for
/// pixel; this is built from ui-spec.md §4.2/§4.3's text (which does call for add/rename/reorder/
/// remove) and the FFI's actual shape — a per-field string and nothing else — rather than from a
/// macOS screen.
/// </summary>
public sealed partial class EditSectionViewModel : ObservableObject
{
    private readonly IEditSectionActions actions;

    public EditSectionViewModel(string name, IEditSectionActions actions)
    {
        this.name = name;
        this.actions = actions;
        renameText = name;
    }

    /// <summary>The section's current name. Empty for the "no section" bucket every unlabelled field falls into.</summary>
    [ObservableProperty]
    private string name;

    /// <summary>The rename box's live text — separate from <see cref="Name"/> so a half-typed edit isn't applied on every keystroke.</summary>
    [ObservableProperty]
    private string renameText;

    /// <summary>The fields currently labelled with this section, in their <see cref="ShellViewModel.EditFields"/> order.</summary>
    public ObservableCollection<FieldDraftRowViewModel> Fields { get; } = new();

    /// <summary>The "no section" bucket every field starts in — not renameable, deletable, or reorderable: it is not a section, it is the absence of one.</summary>
    public bool IsDefault => Name.Length == 0;

    public bool CanManage => !IsDefault;

    [RelayCommand(CanExecute = nameof(CanManage))]
    private void Rename() => actions.RenameSection(this, RenameText);

    [RelayCommand(CanExecute = nameof(CanManage))]
    private void Delete() => actions.DeleteSection(this);

    /// <summary>A no-op when this section is still pending (no fields yet) — there is nothing to swap positions with. See <see cref="ShellViewModel"/>'s section-reorder notes.</summary>
    [RelayCommand(CanExecute = nameof(CanManage))]
    private void MoveUp() => actions.MoveSectionUp(this);

    [RelayCommand(CanExecute = nameof(CanManage))]
    private void MoveDown() => actions.MoveSectionDown(this);

    partial void OnNameChanged(string value)
    {
        OnPropertyChanged(nameof(IsDefault));
        OnPropertyChanged(nameof(CanManage));
        RenameCommand.NotifyCanExecuteChanged();
        DeleteCommand.NotifyCanExecuteChanged();
        MoveUpCommand.NotifyCanExecuteChanged();
        MoveDownCommand.NotifyCanExecuteChanged();
    }
}

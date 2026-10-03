using System.Collections.Generic;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// One section of the read-only detail pane (ui-spec.md §4.2), grouping
/// <see cref="ShellViewModel.DetailFields"/> by <see cref="FieldRowViewModel.Field"/>'s
/// <c>Section</c> — matching macOS's <c>ItemDetailView.sections</c> (apps/macos/Kagisecure/Views/
/// ItemDetailView.swift), which merges every field sharing a section name into one group wherever
/// in the list it falls, not only when same-section fields happen to sit next to each other.
/// </summary>
/// <param name="Name">The section name, or empty for fields with no section.</param>
/// <param name="Fields">The fields in this section, in display order.</param>
public sealed record DetailSectionViewModel(string Name, IReadOnlyList<FieldRowViewModel> Fields);

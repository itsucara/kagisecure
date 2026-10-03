using System;
using System.Collections.Generic;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Views;

/// <summary>The main shell after unlock (ui-spec.md §2). See ShellViewModel for what's stubbed and why.</summary>
public sealed partial class ShellPage : Page
{
    /// <summary>Display names for the "+ Add field" menu (ui-spec.md §4.3), matching the macOS editor's list.</summary>
    private static readonly IReadOnlyList<(FieldKind Kind, string Name)> AddableFieldMenuEntries = new[]
    {
        (FieldKind.Text, "Text"),
        (FieldKind.Concealed, "Password"),
        (FieldKind.Email, "Email"),
        (FieldKind.Url, "URL"),
        (FieldKind.Phone, "Phone"),
        (FieldKind.Date, "Date"),
        (FieldKind.MonthYear, "Month / year"),
        (FieldKind.Totp, "One-time password"),
        (FieldKind.CreditCardNumber, "Card number"),
        (FieldKind.Address, "Address"),
    };

    public ShellViewModel ViewModel { get; }

    public ShellPage()
    {
        // Built before InitializeComponent, same as GeneratorView, so every x:Bind below resolves
        // on first layout — no Bindings.Update() needed.
        ViewModel = new ShellViewModel(App.Instance.VaultService, App.Instance.ClipboardService);
        InitializeComponent();

        foreach (CategoryInfo category in ViewModel.Categories)
        {
            var item = new MenuFlyoutItem { Text = category.DisplayName, Tag = category.Id };
            item.Click += OnNewItemClicked;
            NewItemMenu.Items.Add(item);
        }

        foreach ((FieldKind kind, string name) in AddableFieldMenuEntries)
        {
            var item = new MenuFlyoutItem { Text = name, Tag = kind };
            item.Click += OnAddFieldClicked;
            AddFieldMenu.Items.Add(item);
        }
    }

    protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        TopList.SelectedIndex = 0; // "All Items" selected by default, per ui-spec.md §2.2.
        _ = ViewModel.RefreshCountsCommand.ExecuteAsync(null);
    }

    /// <summary>
    /// Leaving the shell — the lock, above all — takes every released value off the page and ends
    /// its release (ADR-0038 user decision 5: a shown value hides on lock).
    /// </summary>
    protected override void OnNavigatedFrom(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
    {
        ViewModel.HideReleasedValues();
        base.OnNavigatedFrom(e);
    }

    private void OnTopListSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        SelectFrom(TopList, CategoryList, TagList, BottomList);

    private void OnCategoryListSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        SelectFrom(CategoryList, TopList, TagList, BottomList);

    private void OnTagListSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        SelectFrom(TagList, TopList, CategoryList, BottomList);

    private void OnBottomListSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        SelectFrom(BottomList, TopList, CategoryList, TagList);

    /// <summary>
    /// The sidebar groups are separate <see cref="ListView"/>s (so section headers like
    /// "CATEGORIES" can sit between them without becoming selectable rows), so a selection in one
    /// has to clear the other three by hand to keep exactly one row selected overall.
    /// </summary>
    private void SelectFrom(ListView selected, ListView other1, ListView other2, ListView other3)
    {
        if (selected.SelectedItem is SidebarNodeViewModel node)
        {
            other1.SelectedItem = null;
            other2.SelectedItem = null;
            other3.SelectedItem = null;
            HideAgentAccessPane();
            ViewModel.SelectedNode = node;
        }
    }

    private void OnItemsListSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        ViewModel.SelectedItem = ItemsList.SelectedItem as Item;

    private void OnGeneratePasswordClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var flyout = new Flyout
        {
            Content = new GeneratorView(App.Instance.VaultService, App.Instance.ClipboardService),
        };
        flyout.ShowAt(GeneratePasswordButton);
    }

    private void OnNewItemClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is Microsoft.UI.Xaml.Controls.MenuFlyoutItem { Tag: string categoryId })
        {
            _ = ViewModel.NewItemCommand.ExecuteAsync(categoryId);
        }
    }

    private void OnImportClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(ImportPage));

    private void OnSettingsClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(SettingsPage));

    private void OnAuditClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(AuditPage));

    private void OnAddFieldClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem { Tag: FieldKind kind })
        {
            ViewModel.AddFieldCommand.Execute(kind);
        }
    }

    private void OnMoveFieldUpClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: FieldDraftRowViewModel row })
        {
            ViewModel.MoveFieldUpCommand.Execute(row);
        }
    }

    private void OnMoveFieldDownClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: FieldDraftRowViewModel row })
        {
            ViewModel.MoveFieldDownCommand.Execute(row);
        }
    }

    private void OnRemoveFieldClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: FieldDraftRowViewModel row })
        {
            ViewModel.RemoveFieldCommand.Execute(row);
        }
    }

    /// <summary>"Set up"/"Change one-time password" (ui-spec.md §9) — opens <see cref="TotpSetupDialog"/> over the row it was clicked from, same trigger as macOS's <c>FieldEditRow</c>.</summary>
    private async void OnTotpSetupClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: FieldDraftRowViewModel row })
        {
            return;
        }

        // row.Value is only what was set up in this edit: a stored setup is never prefilled
        // (ADR-0038 §5), so over an existing field the dialog opens blank and replaces it unseen.
        var dialog = new TotpSetupDialog(App.Instance.VaultService, row.Value) { XamlRoot = XamlRoot };
        ContentDialogResult result;
        try
        {
            result = await dialog.ShowAsync();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            result = ContentDialogResult.None; // another dialog was already open — nothing changes.
        }

        if (result == ContentDialogResult.Primary && dialog.ViewModel.ComposedUri is { } uri)
        {
            row.Value = uri;
            // A one-time-password seed is always secret material, whatever the row's checkbox said
            // before the dialog opened — same rule macOS's TotpSetupSheet callback applies.
            row.Concealed = true;
        }
    }
}

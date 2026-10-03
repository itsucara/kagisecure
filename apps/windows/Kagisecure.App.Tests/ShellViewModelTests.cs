using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class ShellViewModelTests
{
    private static IReadOnlyList<CategoryInfo> TwelveCategories() => new[]
    {
        new CategoryInfo("login", "Logins", "person.crop.circle"),
        new CategoryInfo("password", "Passwords", "key"),
        new CategoryInfo("secure-note", "Secure Notes", "note.text"),
        new CategoryInfo("credit-card", "Credit Cards", "creditcard"),
        new CategoryInfo("identity", "Identities", "person.text.rectangle"),
        new CategoryInfo("api-credential", "API Credentials", "chevron.left.forwardslash.chevron.right"),
        new CategoryInfo("server", "Servers", "server.rack"),
        new CategoryInfo("database", "Databases", "cylinder.split.1x2"),
        new CategoryInfo("ssh-key", "SSH Keys", "terminal"),
        new CategoryInfo("software-license", "Software Licenses", "checkmark.seal"),
        new CategoryInfo("document", "Documents", "paperclip"),
        new CategoryInfo("environment", "Environments", "list.bullet.rectangle"),
    };

    private static Item MakeItem(
        string id, string title, string category = "login", bool favorite = false, bool archived = false, bool trashed = false) => new(
        id, "vault-1", category, category, "glyph", title,
        ValueList<Field>.Empty, ValueList<string>.Empty, ValueList<string>.Empty,
        false, favorite, archived, trashed, false, 0, 0, null, null, null, "rev-" + id);

    private static ShellViewModel MakeVm(FakeVaultService service, FakeClipboardService? clipboard = null) =>
        new(service, clipboard ?? new FakeClipboardService());

    [Fact]
    public void SidebarHasEveryCategoryFromTheService()
    {
        var service = new FakeVaultService { CategoriesToReturn = TwelveCategories() };
        var vm = MakeVm(service);

        Assert.Equal(12, vm.CategoryNodes.Count);
        Assert.Contains(vm.CategoryNodes, n => n.DisplayName == "Environments");
        Assert.Contains(vm.CategoryNodes, n => n.DisplayName == "Logins");
    }

    [Fact]
    public void SelectedNodeDefaultsToAllItems()
    {
        var vm = MakeVm(new FakeVaultService());
        Assert.Same(vm.AllItems, vm.SelectedNode);
    }

    [Fact]
    public async Task RefreshCountsAsync_PopulatesSidebarCountsFromService()
    {
        var service = new FakeVaultService
        {
            CategoriesToReturn = TwelveCategories(),
            SidebarCountsToReturn = new SidebarCounts(
                All: 42,
                Favorites: 3,
                Archive: 5,
                Trash: 1,
                Categories: new ValueList<TagCount>(new[] { new TagCount("login", 7) }),
                Tags: new ValueList<TagCount>(new[] { new TagCount("work", 2) })),
        };

        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);

        Assert.Equal(42u, vm.AllItems.Count);
        Assert.Equal(3u, vm.Favorites.Count);
        Assert.Equal(5u, vm.Archive.Count);
        Assert.Equal(1u, vm.Trash.Count);
        Assert.Equal(7u, vm.CategoryNodes.Single(n => n.DisplayName == "Logins").Count);
        Assert.Equal(0u, vm.CategoryNodes.Single(n => n.DisplayName == "Passwords").Count);
        Assert.Single(vm.TagNodes);
        Assert.Equal("work", vm.TagNodes[0].DisplayName);
        Assert.Equal(2u, vm.TagNodes[0].Count);
    }

    [Fact]
    public async Task RefreshCountsAsync_AlsoLoadsItemsForTheSelectedNode()
    {
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { MakeItem("1", "GitHub"), MakeItem("2", "GitLab") },
        };
        var vm = MakeVm(service);

        await vm.RefreshCountsCommand.ExecuteAsync(null);

        Assert.Equal(2, vm.Items.Count);
        Assert.Equal(new[] { "GitHub", "GitLab" }, vm.Items.Select(i => i.Title));
        Assert.False(vm.IsLoadingItems);
        Assert.IsType<ItemFilter.All>(service.LastListItemsArgs!.Value.Filter);
    }

    [Fact]
    public async Task SelectingANode_ReloadsItemsForThatFilter()
    {
        var service = new FakeVaultService();
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);

        service.ItemsToReturn = new[] { MakeItem("3", "Corp Amex", "credit-card") };
        vm.SelectedNode = vm.Favorites;
        await Task.Delay(50); // the selection handler fires the reload fire-and-forget

        Assert.IsType<ItemFilter.Favorites>(service.LastListItemsArgs!.Value.Filter);
        Assert.Single(vm.Items);
        Assert.Equal("Corp Amex", vm.Items[0].Title);
    }

    [Fact]
    public async Task SelectingAnItem_PopulatesDetailFields()
    {
        var field = new Field("f1", "password", FieldKind.Concealed, true, true, null, null, false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { field }) };
        var service = new FakeVaultService { ItemsToReturn = new[] { item } };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);

        vm.SelectedItem = vm.Items[0];

        Assert.Single(vm.DetailFields);
        Assert.Equal("password", vm.DetailFields[0].Field.Label);
        Assert.True(vm.DetailFields[0].ShowRevealButton);
    }

    [Fact]
    public async Task LockNow_LocksTheService()
    {
        var service = new FakeVaultService();
        service.ExistingPaths.Add(service.DefaultVaultPath);
        await service.UnlockAsync(service.DefaultVaultPath, "x");
        Assert.True(service.IsUnlocked);

        var vm = MakeVm(service);
        vm.LockNowCommand.Execute(null);

        Assert.False(service.IsUnlocked);
        Assert.Equal(1, service.LockCount);
    }

    // ---------------------------------------------------------------------------------------
    // Item create / edit / delete
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task NewItemAsync_CreatesViaService_ThenSelectsAndEnterEdit()
    {
        var created = MakeItem("new-1", "New item", "login");
        var service = new FakeVaultService
        {
            CreateItemHandler = (category, title, vaultId) => created,
            ItemsToReturn = new[] { created },
        };
        var vm = MakeVm(service);

        await vm.NewItemCommand.ExecuteAsync("login");

        Assert.NotNull(vm.SelectedItem);
        Assert.Equal("new-1", vm.SelectedItem!.Id);
        Assert.True(vm.IsEditingItem);
        Assert.Equal("New item", vm.EditTitle);
    }

    [Fact]
    public async Task BeginEditAsync_PrefillsNothingConcealed_AndAnUntouchedSecretIsKept()
    {
        // ADR-0038 user decision 4: editing a title must not release a single value.
        var field = new Field("f1", "password", FieldKind.Concealed, true, true, null, "Login", false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { field }), HasNotes = true };
        var service = new FakeVaultService { ItemsToReturn = new[] { item }, RevealedValue = "hunter2" };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];

        await vm.BeginEditCommand.ExecuteAsync(null);

        Assert.True(vm.IsEditingItem);
        Assert.Single(vm.EditFields);
        Assert.Equal(string.Empty, vm.EditFields[0].Value);
        Assert.Equal("Login", vm.EditFields[0].Section);
        Assert.Empty(service.ReleaseCalls);
        Assert.Null(vm.EditFields[0].ToDraft().Value); // null keeps the stored secret

        vm.EditFields[0].Value = "a new one";
        Assert.Equal("a new one", vm.EditFields[0].ToDraft().Value);
    }

    [Fact]
    public async Task SaveEditAsync_SendsADraft_ThenExitsEditMode()
    {
        var item = MakeItem("1", "GitHub");
        var saved = item with { Title = "GitHub (renamed)" };
        ItemDraft? sentDraft = null;
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            SaveItemHandler = draft => { sentDraft = draft; return saved; },
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];
        await vm.BeginEditCommand.ExecuteAsync(null);
        vm.EditTitle = "GitHub (renamed)";
        vm.EditTagsText = "work, prod";

        service.ItemsToReturn = new[] { saved };
        await vm.SaveEditCommand.ExecuteAsync(null);

        Assert.False(vm.IsEditingItem);
        Assert.NotNull(sentDraft);
        Assert.Equal("GitHub (renamed)", sentDraft!.Title);
        Assert.Equal(new[] { "work", "prod" }, sentDraft.Tags);
        Assert.Equal(item.Revision, sentDraft.Revision); // the save is refused if the item changed since
        Assert.Null(sentDraft.Notes); // untouched: the stored note is kept
        Assert.Equal("GitHub (renamed)", vm.SelectedItem!.Title);
    }

    [Fact]
    public async Task SaveEditAsync_OnFailure_SetsEditError_AndStaysInEditMode()
    {
        var item = MakeItem("1", "GitHub");
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            SaveItemThrows = KagisecureExceptionFactory.Create<KagisecureException.Invalid>("bad field"),
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];
        await vm.BeginEditCommand.ExecuteAsync(null);

        await vm.SaveEditCommand.ExecuteAsync(null);

        Assert.True(vm.IsEditingItem);
        Assert.Equal("bad field", vm.EditError);
    }

    [Fact]
    public void AddField_RemoveField_MoveField_MutateEditFieldsInOrder()
    {
        var vm = MakeVm(new FakeVaultService());
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.AddFieldCommand.Execute(FieldKind.Concealed);
        Assert.Equal(2, vm.EditFields.Count);
        Assert.True(vm.EditFields[1].Concealed); // Concealed field defaults to concealed = true

        vm.MoveFieldUpCommand.Execute(vm.EditFields[1]);
        Assert.True(vm.EditFields[0].Concealed);

        FieldDraftRowViewModel toRemove = vm.EditFields[0];
        vm.RemoveFieldCommand.Execute(toRemove);
        Assert.Single(vm.EditFields);
        Assert.DoesNotContain(toRemove, vm.EditFields);
    }

    [Fact]
    public void CancelEdit_ClearsFieldsAndExitsEditMode()
    {
        var vm = MakeVm(new FakeVaultService());
        vm.AddFieldCommand.Execute(FieldKind.Text);

        vm.CancelEditCommand.Execute(null);

        Assert.False(vm.IsEditingItem);
        Assert.Empty(vm.EditFields);
    }

    [Fact]
    public async Task ToggleFavoriteAsync_CallsService_AndRefreshesSelection()
    {
        var item = MakeItem("1", "GitHub", favorite: false);
        var favorited = item with { Favorite = true };
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            MutationResult = _ => favorited,
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];

        service.ItemsToReturn = new[] { favorited };
        await vm.ToggleFavoriteCommand.ExecuteAsync(null);

        Assert.Single(service.FavoriteCalls);
        Assert.Equal(("1", true), service.FavoriteCalls[0]);
        Assert.True(vm.SelectedItem!.Favorite);
    }

    [Fact]
    public async Task ToggleTrashedAsync_ItemLeavingTheFilter_ClearsSelection()
    {
        var item = MakeItem("1", "GitHub", trashed: false);
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            MutationResult = id => item with { Trashed = true },
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];

        service.ItemsToReturn = System.Array.Empty<Item>(); // trashed items drop out of "All Items"
        await vm.ToggleTrashedCommand.ExecuteAsync(null);

        Assert.Single(service.TrashedCalls);
        Assert.Null(vm.SelectedItem);
    }

    [Fact]
    public async Task DeleteForeverAsync_CallsService_AndClearsSelection()
    {
        var item = MakeItem("1", "GitHub", trashed: true);
        var service = new FakeVaultService { ItemsToReturn = new[] { item } };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];

        service.ItemsToReturn = System.Array.Empty<Item>();
        await vm.DeleteForeverCommand.ExecuteAsync(null);

        Assert.Contains("1", service.DeletedItemIds);
        Assert.Equal(new[] { item.Revision }, service.DeletedRevisions);
        Assert.Null(vm.SelectedItem);
    }

    // ---------------------------------------------------------------------------------------
    // TOTP (via FieldRowViewModel, exercised through ShellViewModel's DetailFields population)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task SelectingAnItem_WithATotpField_MarksTheRowAsTotp()
    {
        var field = new Field("f1", "one-time password", FieldKind.Totp, true, true, null, null, false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { field }) };
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            TotpCodeToReturn = new TotpCode("654321", 12, new TotpParams(TotpAlgorithm.Sha1, 6, 30, "GitHub", "ada", null)),
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);

        vm.SelectedItem = vm.Items[0];

        Assert.Single(vm.DetailFields);
        FieldRowViewModel row = vm.DetailFields[0];
        Assert.True(row.IsTotp);
        Assert.False(row.ShowCopyButton); // TOTP has its own copy affordance
        Assert.False(row.ShowRevealButton); // the row shows the code, never the setup seed
        // Masked until a presence-gated release (ADR-0038 user decision 2).
        Assert.Equal("••• •••", row.TotpGrouped);
        Assert.Empty(service.ReleaseCalls);

        await row.ShowTotpCommand.ExecuteAsync(null);

        Assert.Equal("654 321", row.TotpGrouped);
        var call = Assert.Single(service.ReleaseCalls);
        Assert.Equal(("totp", "1", (string?)"f1", ReleasePurpose.Reveal), call);
    }

    [Fact]
    public async Task Reveal_GoesThroughOneRelease_AndACancelledPromptRevealsNothing()
    {
        var field = new Field("f1", "password", FieldKind.Concealed, true, true, null, null, false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { field }) };
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            ReleaseThrows = KagisecureExceptionFactory.Create<KagisecureException.PresenceCancelled>("not confirmed"),
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];
        FieldRowViewModel row = vm.DetailFields[0];

        await row.RevealCommand.ExecuteAsync(null);
        Assert.Null(row.RevealedValue);
        Assert.Equal("••••••••••", row.DisplayValue);

        service.ReleaseThrows = null;
        service.RevealedValue = "hunter2";
        await row.RevealCommand.ExecuteAsync(null);
        Assert.Equal("hunter2", row.DisplayValue);
        Assert.Equal(2, service.ReleaseCalls.Count);
        Assert.All(service.ReleaseCalls, c => Assert.Equal(ReleasePurpose.Reveal, c.Purpose));
    }

    [Fact]
    public async Task Notes_AreMaskedUntilShown_ThroughTheirOwnRelease()
    {
        var item = MakeItem("1", "Wi-Fi") with { HasNotes = true };
        var service = new FakeVaultService { ItemsToReturn = new[] { item }, NotesText = "router: hunter2" };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);

        vm.SelectedItem = vm.Items[0];
        Assert.Equal("••••••••••", vm.NotesText);
        Assert.True(vm.CanShowNotes);
        Assert.Empty(service.ReleaseCalls);

        await vm.ShowNotesCommand.ExecuteAsync(null);

        Assert.Equal("router: hunter2", vm.NotesText);
        Assert.False(vm.CanShowNotes);
        Assert.Equal(("notes", "1", (string?)null, ReleasePurpose.Reveal), Assert.Single(service.ReleaseCalls));
    }
}

using System.Linq;
using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

/// <summary>
/// Section management in the item editor (ui-spec.md §4.3): add, rename, delete (moves fields out,
/// doesn't delete them), reorder, and move a field between sections — against a fake
/// <see cref="IVaultService"/>. See <see cref="EditSectionViewModel"/>'s doc comment for why there
/// is no macOS screen this mirrors: macOS's own <c>ItemEditView</c> has no section UI at all today.
/// </summary>
public class ShellViewModelSectionsTests
{
    private static ShellViewModel MakeVm(FakeVaultService? service = null) =>
        new(service ?? new FakeVaultService(), new FakeClipboardService());

    private static Item MakeItem(string id, string title, string category = "login") => new(
        id, "vault-1", category, category, "glyph", title,
        ValueList<Field>.Empty, ValueList<string>.Empty, ValueList<string>.Empty,
        false, false, false, false, false, 0, 0, null, null, null, "rev-" + id);

    [Fact]
    public void AddSection_CreatesAPendingSection_WithNoFieldsYet()
    {
        var vm = MakeVm();
        vm.NewSectionName = "Recovery";

        vm.AddSectionCommand.Execute(null);

        EditSectionViewModel section = Assert.Single(vm.EditSections);
        Assert.Equal("Recovery", section.Name);
        Assert.Empty(section.Fields);
        Assert.Equal(string.Empty, vm.NewSectionName); // the box clears once added
    }

    [Fact]
    public void AddSection_Blank_IsANoOp()
    {
        var vm = MakeVm();
        vm.NewSectionName = "   ";

        vm.AddSectionCommand.Execute(null);

        Assert.Empty(vm.EditSections);
    }

    [Fact]
    public void TypingAPendingSectionsName_IntoAFieldsSectionBox_MakesItReal()
    {
        var vm = MakeVm();
        vm.NewSectionName = "Recovery";
        vm.AddSectionCommand.Execute(null);
        vm.AddFieldCommand.Execute(FieldKind.Text);

        vm.EditFields[0].Section = "Recovery"; // the field's own Section box is the only "move to section" picker there is

        EditSectionViewModel section = Assert.Single(vm.EditSections);
        Assert.Equal("Recovery", section.Name);
        Assert.Single(section.Fields);
        Assert.Same(vm.EditFields[0], section.Fields[0]);
    }

    [Fact]
    public void RenameSection_RelabelsEveryFieldCurrentlyInIt()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.EditFields[0].Section = "Login";
        vm.EditFields[1].Section = "Login";

        EditSectionViewModel section = vm.EditSections.Single(s => s.Name == "Login");
        section.RenameText = "Sign-in";
        section.RenameCommand.Execute(null);

        Assert.All(vm.EditFields, f => Assert.Equal("Sign-in", f.Section));
        Assert.Contains(vm.EditSections, s => s.Name == "Sign-in");
        Assert.DoesNotContain(vm.EditSections, s => s.Name == "Login");
    }

    [Fact]
    public void RenameSection_ToBlank_MergesItsFieldsIntoNoSection()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.EditFields[0].Section = "Login";
        EditSectionViewModel section = vm.EditSections.Single(s => s.Name == "Login");

        section.RenameText = "   ";
        section.RenameCommand.Execute(null);

        Assert.Null(vm.EditFields[0].Section);
        Assert.DoesNotContain(vm.EditSections, s => s.Name == "Login");
    }

    [Fact]
    public void RenameSection_OnTheDefaultBucket_IsANoOp()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        EditSectionViewModel defaultSection = vm.EditSections.Single(s => s.IsDefault);

        defaultSection.RenameText = "Should not apply";
        defaultSection.RenameCommand.Execute(null);

        Assert.Null(vm.EditFields[0].Section);
        Assert.False(defaultSection.CanManage);
    }

    [Fact]
    public void DeleteSection_MovesItsFieldsOut_RatherThanDeletingThem()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.EditFields[0].Section = "Login";
        FieldDraftRowViewModel field = vm.EditFields[0];
        EditSectionViewModel section = vm.EditSections.Single(s => s.Name == "Login");

        section.DeleteCommand.Execute(null);

        Assert.Equal(2, vm.EditFields.Count);
        Assert.Contains(field, vm.EditFields); // still there
        Assert.Null(field.Section);
        Assert.DoesNotContain(vm.EditSections, s => s.Name == "Login");
    }

    [Fact]
    public void DeleteSection_OnTheDefaultBucket_IsANoOp()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        EditSectionViewModel defaultSection = vm.EditSections.Single(s => s.IsDefault);

        defaultSection.DeleteCommand.Execute(null);

        Assert.Single(vm.EditFields);
    }

    [Fact]
    public void MoveSectionUpAndDown_SwapsFieldBlocks()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.EditFields[0].Label = "a";
        vm.EditFields[1].Label = "b";
        vm.EditFields[2].Label = "c";
        vm.EditFields[0].Section = "First";
        vm.EditFields[1].Section = "Second";
        // vm.EditFields[2] ("c") stays in "no section".

        Assert.Equal(new[] { "First", "Second", string.Empty }, vm.EditSections.Select(s => s.Name));

        EditSectionViewModel second = vm.EditSections.Single(s => s.Name == "Second");
        second.MoveUpCommand.Execute(null);

        Assert.Equal(new[] { "Second", "First", string.Empty }, vm.EditSections.Select(s => s.Name));
        Assert.Equal(new[] { "b", "a", "c" }, vm.EditFields.Select(f => f.Label));

        EditSectionViewModel first = vm.EditSections.Single(s => s.Name == "First");
        first.MoveDownCommand.Execute(null); // swaps with the "no section" bucket, now its neighbor

        Assert.Equal(new[] { "Second", string.Empty, "First" }, vm.EditSections.Select(s => s.Name));
        Assert.Equal(new[] { "b", "c", "a" }, vm.EditFields.Select(f => f.Label));
    }

    [Fact]
    public void MoveSectionUp_AtTheTop_IsANoOp()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.EditFields[0].Section = "Only";

        vm.EditSections.Single(s => s.Name == "Only").MoveUpCommand.Execute(null);

        // Only one field exists at all, so there is no "no section" bucket to swap with either —
        // "Only" is the sole section, at index 0, with nowhere to move.
        Assert.Equal(new[] { "Only" }, vm.EditSections.Select(s => s.Name));
    }

    [Fact]
    public void MoveSection_OnAStillPendingEmptySection_IsANoOp()
    {
        var vm = MakeVm();
        vm.NewSectionName = "Recovery";
        vm.AddSectionCommand.Execute(null);
        EditSectionViewModel section = vm.EditSections.Single();

        section.MoveUpCommand.Execute(null);
        section.MoveDownCommand.Execute(null);

        Assert.Single(vm.EditSections);
        Assert.Equal("Recovery", vm.EditSections[0].Name);
    }

    [Fact]
    public async Task BeginEditAsync_GroupsNonContiguousFieldsOfTheSameSection()
    {
        // "Login" is not contiguous — a plain grouping by list position (as opposed to grouping by
        // key, matching macOS's ItemDetailView.sections) would produce two separate "Login" groups.
        var f1 = new Field("f1", "username", FieldKind.Text, false, true, "ada", "Login", false);
        var f2 = new Field("f2", "note", FieldKind.Text, false, true, "n/a", null, false);
        var f3 = new Field("f3", "password", FieldKind.Concealed, true, true, null, "Login", false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { f1, f2, f3 }) };
        var service = new FakeVaultService { ItemsToReturn = new[] { item } };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];

        await vm.BeginEditCommand.ExecuteAsync(null);

        Assert.Equal(new[] { "Login", string.Empty }, vm.EditSections.Select(s => s.Name));
        Assert.Equal(new[] { "username", "password" }, vm.EditSections[0].Fields.Select(f => f.Label));
        Assert.Equal(new[] { "note" }, vm.EditSections[1].Fields.Select(f => f.Label));
    }

    [Fact]
    public async Task CancelEdit_ForgetsPendingSections()
    {
        var vm = MakeVm();
        vm.AddFieldCommand.Execute(FieldKind.Text);
        vm.NewSectionName = "Recovery";
        vm.AddSectionCommand.Execute(null);
        Assert.Equal(2, vm.EditSections.Count); // "no section" bucket + pending "Recovery"

        vm.CancelEditCommand.Execute(null);

        // A fresh add-field afterward should not resurrect the discarded pending section.
        vm.AddFieldCommand.Execute(FieldKind.Text);
        Assert.DoesNotContain(vm.EditSections, s => s.Name == "Recovery");
        await Task.CompletedTask;
    }

    [Fact]
    public async Task SelectingAnItem_GroupsDetailFieldsIntoDetailSections_MatchingMacOssNonContiguousMerge()
    {
        var f1 = new Field("f1", "username", FieldKind.Text, false, true, "ada", "Login", false);
        var f2 = new Field("f2", "note", FieldKind.Text, false, true, "n/a", null, false);
        var f3 = new Field("f3", "code", FieldKind.Totp, true, true, null, "Login", false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { f1, f2, f3 }) };
        var service = new FakeVaultService { ItemsToReturn = new[] { item } };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);

        vm.SelectedItem = vm.Items[0];

        Assert.Equal(new[] { "Login", string.Empty }, vm.DetailSections.Select(s => s.Name));
        Assert.Equal(2, vm.DetailSections[0].Fields.Count);
        Assert.Single(vm.DetailSections[1].Fields);
        Assert.Equal("note", vm.DetailSections[1].Fields[0].Field.Label);
    }

    // -------------------------------------------------------------------------------------------
    // Sections over ADR-0038's presence gate: rearranging never releases, and the grouped detail
    // pane shows a one-time code only through a release.
    // -------------------------------------------------------------------------------------------

    [Fact]
    public async Task MovingAndRenamingSectionsOfStoredSecrets_KeepsTheirValues_AndReleasesNothing()
    {
        var pw = new Field("p1", "password", FieldKind.Concealed, true, true, null, null, false);
        var totp = new Field("t1", "one-time password", FieldKind.Totp, true, true, null, null, false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { pw, totp }) };
        ItemDraft? sent = null;
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            SaveItemHandler = d => { sent = d; return item; },
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];
        await vm.BeginEditCommand.ExecuteAsync(null);

        FieldDraftRowViewModel totpRow = vm.EditFields.Single(f => f.IsTotp);
        Assert.Equal(string.Empty, totpRow.Value); // nothing concealed is prefilled
        Assert.Equal("Change one-time password", totpRow.TotpSetupLabel); // a stored setup exists, unseen

        vm.NewSectionName = "Security";
        vm.AddSectionCommand.Execute(null);
        totpRow.Section = "Security";
        EditSectionViewModel security = vm.EditSections.Single(s => s.Name == "Security");
        security.RenameText = "Two-factor";
        security.RenameCommand.Execute(null);
        vm.EditSections.Single(s => s.Name == "Two-factor").MoveUpCommand.Execute(null);

        await vm.SaveEditCommand.ExecuteAsync(null);

        Assert.Empty(service.ReleaseCalls);
        Assert.NotNull(sent);
        Assert.Equal(new[] { "t1", "p1" }, sent!.Fields.Select(f => f.Id));
        Assert.All(sent.Fields, f => Assert.Null(f.Value)); // null keeps each stored secret
        Assert.Equal("Two-factor", sent.Fields[0].Section);
        Assert.Null(sent.Fields[1].Section);
    }

    [Fact]
    public async Task ATotpRowInTheGroupedDetailPane_IsMaskedUntilItsRelease_AndLeavesWithTheLock()
    {
        var totp = new Field("t1", "one-time password", FieldKind.Totp, true, true, null, "Login", false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { totp }) };
        var service = new FakeVaultService { ItemsToReturn = new[] { item } };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];

        FieldRowViewModel row = Assert.Single(Assert.Single(vm.DetailSections).Fields);
        Assert.Equal("••• •••", row.TotpGrouped);
        Assert.True(row.ShowTotpButton);
        Assert.Empty(service.ReleaseCalls);

        await row.ShowTotpCommand.ExecuteAsync(null);

        Assert.Equal(("totp", "1", (string?)"t1", ReleasePurpose.Reveal), Assert.Single(service.ReleaseCalls));
        Assert.Equal("123 456", row.TotpGrouped);

        vm.HideReleasedValues();

        Assert.Empty(vm.DetailSections); // nothing the lock ended is left on screen
    }

    [Fact]
    public async Task ATotpSetupTypedInThisEdit_IsSentAsTheNewValue()
    {
        var totp = new Field("t1", "one-time password", FieldKind.Totp, true, true, null, null, false);
        var item = MakeItem("1", "GitHub") with { Fields = new ValueList<Field>(new[] { totp }) };
        ItemDraft? sent = null;
        var service = new FakeVaultService
        {
            ItemsToReturn = new[] { item },
            SaveItemHandler = d => { sent = d; return item; },
        };
        var vm = MakeVm(service);
        await vm.RefreshCountsCommand.ExecuteAsync(null);
        vm.SelectedItem = vm.Items[0];
        await vm.BeginEditCommand.ExecuteAsync(null);

        vm.EditFields[0].Value = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"; // what the setup dialog hands back

        await vm.SaveEditCommand.ExecuteAsync(null);

        Assert.Equal("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", Assert.Single(sent!.Fields).Value);
        Assert.Empty(service.ReleaseCalls);
    }
}

using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Windows.Storage.Streams;
using Xunit;

namespace Kagisecure.App.Tests;

/// <summary>
/// <see cref="TotpSetupViewModel"/> against a fake <see cref="IVaultService"/> and fake QR/file/
/// clipboard sources — no real FFI, no real image codec, no real file picker, no real clipboard.
/// </summary>
public class TotpSetupViewModelTests
{
    private static TotpSetupViewModel MakeVm(
        FakeVaultService? service = null,
        FakeQrCodeReader? qr = null,
        FakeImageFilePicker? filePicker = null,
        FakeClipboardImageSource? clipboard = null,
        string existingUri = "") =>
        new(
            service ?? new FakeVaultService(),
            qr ?? new FakeQrCodeReader(),
            filePicker ?? new FakeImageFilePicker(),
            clipboard ?? new FakeClipboardImageSource(),
            existingUri);

    [Fact]
    public void Manual_WithNoSecret_CannotSave()
    {
        var vm = MakeVm();

        Assert.Equal(TotpSetupMode.Manual, vm.Mode); // manual is the default (ui-spec.md: raw URI is now "advanced")
        Assert.Null(vm.ComposedUri);
        Assert.False(vm.CanSave);
        Assert.False(vm.PreviewAvailable);
    }

    [Fact]
    public void Manual_WithASecret_ComposesViaTheService_AndShowsALivePreview()
    {
        var service = new FakeVaultService
        {
            TotpCodeToReturn = new TotpCode("654321", 12, new TotpParams(TotpAlgorithm.Sha1, 6, 30, "GitHub", "ada", "GitHub · ada")),
        };
        var vm = MakeVm(service);

        vm.SecretText = "JBSWY3DPEHPK3PXP";

        Assert.True(vm.CanSave);
        Assert.NotNull(vm.ComposedUri);
        Assert.StartsWith("otpauth://", vm.ComposedUri);
        Assert.Equal("654 321", vm.PreviewCode);
        Assert.Equal("GitHub · ada", vm.PreviewCaption);
        Assert.True(vm.PreviewAvailable);
    }

    [Fact]
    public void Uri_WithAnInvalidUri_CannotSave()
    {
        var vm = MakeVm();
        vm.Mode = TotpSetupMode.Uri;

        vm.UriText = "not a uri";

        Assert.Null(vm.ComposedUri);
        Assert.False(vm.CanSave);
    }

    [Fact]
    public void Uri_WithAValidUri_CanSave_AndComposedUriIsTheTrimmedText()
    {
        var vm = MakeVm();
        vm.Mode = TotpSetupMode.Uri;

        vm.UriText = "  otpauth://totp/GitHub:ada?secret=ABC  ";

        Assert.True(vm.CanSave);
        Assert.Equal("otpauth://totp/GitHub:ada?secret=ABC", vm.ComposedUri);
    }

    [Fact]
    public void ConstructingWithAnExistingUri_StartsOnTheUriTab()
    {
        var vm = MakeVm(existingUri: "otpauth://totp/GitHub:ada?secret=ABC");

        Assert.Equal(TotpSetupMode.Uri, vm.Mode);
        Assert.Equal("otpauth://totp/GitHub:ada?secret=ABC", vm.UriText);
        Assert.True(vm.CanSave);
    }

    [Fact]
    public void ModeIndex_MirrorsMode_BothWays()
    {
        var vm = MakeVm();

        vm.ModeIndex = 2;
        Assert.Equal(TotpSetupMode.Uri, vm.Mode);

        vm.Mode = TotpSetupMode.Qr;
        Assert.Equal(1, vm.ModeIndex);
    }

    [Fact]
    public async Task ImportFromFile_WhenThePickerReturnsAValidCode_SwitchesToUriMode()
    {
        var service = new FakeVaultService();
        var qr = new FakeQrCodeReader { ResultToReturn = "otpauth://totp/GitHub:ada?secret=ABC" };
        var stream = new InMemoryRandomAccessStream();
        var picker = new FakeImageFilePicker { StreamToReturn = stream };
        var vm = MakeVm(service, qr, picker);

        await vm.ImportFromFileCommand.ExecuteAsync(null);

        Assert.Equal(1, picker.CallCount);
        Assert.Equal(TotpSetupMode.Uri, vm.Mode);
        Assert.Equal("otpauth://totp/GitHub:ada?secret=ABC", vm.UriText);
        Assert.True(vm.CanSave);
        Assert.Contains("Imported", vm.QrStatus);
    }

    [Fact]
    public async Task ImportFromFile_WhenThePickerIsCancelled_LeavesEverythingAlone()
    {
        var picker = new FakeImageFilePicker { StreamToReturn = null };
        var vm = MakeVm(filePicker: picker);

        await vm.ImportFromFileCommand.ExecuteAsync(null);

        Assert.Null(vm.QrStatus);
        Assert.Equal(TotpSetupMode.Manual, vm.Mode);
    }

    [Fact]
    public async Task ImportFromFile_WhenNoQrCodeIsFound_ReportsThatAndStaysPut()
    {
        var qr = new FakeQrCodeReader { ResultToReturn = null };
        var stream = new InMemoryRandomAccessStream();
        var picker = new FakeImageFilePicker { StreamToReturn = stream };
        var vm = MakeVm(null, qr, picker);

        await vm.ImportFromFileCommand.ExecuteAsync(null);

        Assert.False(vm.CanSave);
        Assert.Equal(TotpSetupMode.Manual, vm.Mode);
        Assert.Contains("No QR code", vm.QrStatus);
    }

    [Fact]
    public async Task ImportFromFile_WhenTheDecodedTextIsNotAnOtpauthUri_IsRejected()
    {
        var qr = new FakeQrCodeReader { ResultToReturn = "https://example.com" }; // a real QR code, just not a TOTP one
        var stream = new InMemoryRandomAccessStream();
        var picker = new FakeImageFilePicker { StreamToReturn = stream };
        var vm = MakeVm(null, qr, picker);

        await vm.ImportFromFileCommand.ExecuteAsync(null);

        Assert.False(vm.CanSave);
        Assert.Equal(TotpSetupMode.Manual, vm.Mode); // never switched away from where the user was
        Assert.Contains("isn't a one-time-password", vm.QrStatus);
    }

    [Fact]
    public async Task ImportFromClipboard_WhenTheClipboardHasNoImage_ReportsThat()
    {
        var clipboard = new FakeClipboardImageSource { StreamToReturn = null };
        var vm = MakeVm(clipboard: clipboard);

        await vm.ImportFromClipboardCommand.ExecuteAsync(null);

        Assert.Equal(1, clipboard.CallCount);
        Assert.Contains("clipboard", vm.QrStatus);
        Assert.Equal(TotpSetupMode.Manual, vm.Mode);
    }

    [Fact]
    public async Task ImportFromClipboard_WhenItHasAValidCode_SwitchesToUriMode()
    {
        var qr = new FakeQrCodeReader { ResultToReturn = "otpauth://totp/GitHub:ada?secret=ABC" };
        var stream = new InMemoryRandomAccessStream();
        var clipboard = new FakeClipboardImageSource { StreamToReturn = stream };
        var vm = MakeVm(null, qr, null, clipboard);

        await vm.ImportFromClipboardCommand.ExecuteAsync(null);

        Assert.Equal(TotpSetupMode.Uri, vm.Mode);
        Assert.Equal("otpauth://totp/GitHub:ada?secret=ABC", vm.UriText);
    }
}

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;
using Windows.Storage.Streams;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// The one-time-password setup dialog (ui-spec.md §9), replacing raw-URI-only editing of a
/// <see cref="FieldKind.Totp"/> field. Three ways in: manual entry (secret + issuer/account +
/// advanced algorithm/digits/period), a QR code (file or clipboard — Windows-only; see
/// <see cref="IQrCodeReader"/>'s doc comment for why macOS has nothing to mirror here), and the raw
/// <c>otpauth://</c> URI kept as an advanced option, matching macOS's <c>TotpSetupSheet</c>.
///
/// Every validation and the live preview go through <see cref="IVaultService"/>'s <c>Totp*</c>
/// members (<c>TotpUriFromParts</c>, <c>TotpUriIsValid</c>, <c>TotpPreview</c>), which wrap
/// <c>Kagisecure.Interop.Totp</c> — none of it requires an unlocked vault, so this view model needs
/// nothing but that one seam and is fully exercisable against a fake in a unit test.
///
/// None of it releases anything from the vault either: the preview is <c>totp_preview</c> over a
/// seed the person is typing and the vault does not hold yet (ADR-0008 crossing 5), which is why it
/// asks for no presence. A stored setup is never read back into this dialog (ADR-0038 §5).
/// </summary>
public sealed partial class TotpSetupViewModel : ObservableObject
{
    private readonly IVaultService vaultService;
    private readonly IQrCodeReader qrCodeReader;
    private readonly IImageFilePicker filePicker;
    private readonly IClipboardImageSource clipboardImageSource;

    public TotpSetupViewModel(
        IVaultService vaultService,
        IQrCodeReader qrCodeReader,
        IImageFilePicker filePicker,
        IClipboardImageSource clipboardImageSource,
        string existingUri = "")
    {
        this.vaultService = vaultService;
        this.qrCodeReader = qrCodeReader;
        this.filePicker = filePicker;
        this.clipboardImageSource = clipboardImageSource;

        if (!string.IsNullOrWhiteSpace(existingUri))
        {
            // Reopened over a setup made earlier in this same edit: show it again, on the tab that
            // can show it (see ComposedUri — Manual mode can never reconstruct a secret from a URI,
            // since Totp.Describe deliberately never returns one). This is only ever what the
            // person typed or scanned in this edit, never the stored setup: the editor prefills
            // nothing concealed (ADR-0038 §5 and user decision 4), so over a stored field the
            // dialog opens blank and saving replaces the setup without showing the old one.
            uriText = existingUri;
            mode = TotpSetupMode.Uri;
        }

        RefreshPreview();
    }

    public static IReadOnlyList<TotpAlgorithm> Algorithms { get; } =
        new[] { TotpAlgorithm.Sha1, TotpAlgorithm.Sha256, TotpAlgorithm.Sha512 };

    public static IReadOnlyList<int> DigitChoices { get; } = new[] { 6, 7, 8 };

    [ObservableProperty]
    private TotpSetupMode mode = TotpSetupMode.Manual;

    [ObservableProperty]
    private string secretText = string.Empty;

    [ObservableProperty]
    private string issuer = string.Empty;

    [ObservableProperty]
    private string account = string.Empty;

    [ObservableProperty]
    private TotpAlgorithm algorithm = TotpAlgorithm.Sha1;

    [ObservableProperty]
    private int digits = 6;

    [ObservableProperty]
    private int period = 30;

    [ObservableProperty]
    private string uriText = string.Empty;

    [ObservableProperty]
    private string? previewCode;

    [ObservableProperty]
    private string? previewCaption;

    [ObservableProperty]
    private bool previewAvailable;

    [ObservableProperty]
    private string? qrStatus;

    [ObservableProperty]
    private bool qrBusy;

    [ObservableProperty]
    private bool canSave;

    /// <summary>
    /// The <c>otpauth://</c> URI the current tab's fields would produce, or <c>null</c> when what
    /// is on screen isn't usable yet (ui-spec.md §9: "a live preview appears before anything is
    /// saved"). Both non-URI modes still bottom out here: everything the field ends up storing is
    /// this one URI, built by Rust (<c>Totp.UriFromParts</c>) so there is one implementation of the
    /// escaping rules, not two — same reasoning as macOS's <c>composedUri</c>.
    /// </summary>
    public string? ComposedUri
    {
        get
        {
            try
            {
                if (Mode is TotpSetupMode.Uri or TotpSetupMode.Qr)
                {
                    string trimmed = UriText.Trim();
                    return trimmed.Length > 0 && vaultService.TotpUriIsValid(trimmed) ? trimmed : null;
                }

                if (string.IsNullOrWhiteSpace(SecretText))
                {
                    return null;
                }

                var parameters = new TotpParams(
                    Algorithm,
                    (byte)Digits,
                    (uint)Period,
                    string.IsNullOrWhiteSpace(Issuer) ? null : Issuer,
                    string.IsNullOrWhiteSpace(Account) ? null : Account,
                    null);
                return vaultService.TotpUriFromParts(SecretText, parameters);
            }
            catch (KagisecureException.Invalid)
            {
                return null;
            }
        }
    }

    /// <summary>Recomputes <see cref="ComposedUri"/>, <see cref="CanSave"/>, and the live preview code/caption. Called by every field's change hook, and once from the constructor.</summary>
    public void RefreshPreview()
    {
        string? uri = ComposedUri;
        CanSave = uri is not null;
        if (uri is null)
        {
            PreviewCode = null;
            PreviewCaption = null;
            PreviewAvailable = false;
            return;
        }

        try
        {
            TotpCode code = vaultService.TotpPreview(uri);
            PreviewCode = Group(code.Code);
            PreviewCaption = code.Params.Caption ?? "Check this against the service before saving.";
            PreviewAvailable = true;
        }
        catch (KagisecureException)
        {
            PreviewCode = null;
            PreviewCaption = null;
            PreviewAvailable = false;
        }
    }

    private static string Group(string code)
    {
        // "123456" -> "123 456", matching TotpFieldView/FieldRowViewModel's grouping.
        int half = code.Length / 2;
        return half == 0 ? code : $"{code[..half]} {code[half..]}";
    }

    /// <summary>
    /// <see cref="Mode"/> as the 0/1/2 a <c>RadioButtons</c> control's <c>SelectedIndex</c> needs —
    /// <see cref="TotpSetupMode"/>'s declaration order matches the dialog's radio-button order, so
    /// this is a plain cast rather than a lookup table.
    /// </summary>
    public int ModeIndex
    {
        get => (int)Mode;
        set => Mode = (TotpSetupMode)value;
    }

    partial void OnModeChanged(TotpSetupMode value)
    {
        OnPropertyChanged(nameof(ModeIndex));
        RefreshPreview();
    }

    partial void OnSecretTextChanged(string value) => RefreshPreview();

    partial void OnIssuerChanged(string value) => RefreshPreview();

    partial void OnAccountChanged(string value) => RefreshPreview();

    partial void OnAlgorithmChanged(TotpAlgorithm value) => RefreshPreview();

    partial void OnDigitsChanged(int value) => RefreshPreview();

    partial void OnPeriodChanged(int value) => RefreshPreview();

    partial void OnUriTextChanged(string value) => RefreshPreview();

    [RelayCommand]
    private async Task ImportFromFileAsync()
    {
        QrStatus = null;
        QrBusy = true;
        try
        {
            using IRandomAccessStream? stream = await filePicker.PickImageAsync().ConfigureAwait(true);
            if (stream is null)
            {
                return; // the user cancelled the picker.
            }

            await ImportFromStreamAsync(stream).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            QrStatus = "Couldn't read that file as an image.";
        }
        finally
        {
            QrBusy = false;
        }
    }

    [RelayCommand]
    private async Task ImportFromClipboardAsync()
    {
        QrStatus = null;
        QrBusy = true;
        try
        {
            using IRandomAccessStream? stream = await clipboardImageSource.GetImageAsync().ConfigureAwait(true);
            if (stream is null)
            {
                QrStatus = "The clipboard doesn't have an image right now.";
                return;
            }

            await ImportFromStreamAsync(stream).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            QrStatus = "Couldn't read the clipboard image.";
        }
        finally
        {
            QrBusy = false;
        }
    }

    /// <summary>
    /// The decoded text touches nothing but local fields here — no log, no exception message,
    /// nothing sent anywhere — because it may be a one-time-password seed the moment it is read.
    /// </summary>
    private async Task ImportFromStreamAsync(IRandomAccessStream stream)
    {
        string? text = await qrCodeReader.DecodeAsync(stream).ConfigureAwait(true);
        if (text is null)
        {
            QrStatus = "No QR code found in that image.";
            return;
        }

        if (!vaultService.TotpUriIsValid(text))
        {
            QrStatus = "That QR code isn't a one-time-password setup code.";
            return;
        }

        UriText = text;
        Mode = TotpSetupMode.Uri; // an otpauth:// URI carries its seed; the URI tab is the only place that can hold it as-is (see ComposedUri).
        QrStatus = "Imported from the QR code.";
    }
}

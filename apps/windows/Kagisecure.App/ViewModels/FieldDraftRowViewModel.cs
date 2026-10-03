using CommunityToolkit.Mvvm.ComponentModel;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// One field row of the item editor (ui-spec.md §4.3): mutable local state, nothing reaches the
/// vault until Save. Mirrors the macOS app's <c>FieldDraft</c> editing, but as a reference type
/// with observable properties instead of a value-type binding, since x:Bind needs a POCO with
/// property-changed notifications to update inline as the user types.
/// </summary>
public sealed partial class FieldDraftRowViewModel : ObservableObject
{
    /// <summary>Existing field id, or <c>null</c> for a field added in this edit session.</summary>
    public string? Id { get; }

    /// <summary>Per-field agent visibility, carried through unchanged — the draft never sets it (ADR: only the item-level toggle and per-field override commands change it).</summary>
    public bool AgentVisible { get; }

    public FieldDraftRowViewModel(FieldKind kind, string label = "New field")
    {
        Id = null;
        AgentVisible = false;
        this.kind = kind;
        this.label = kind == FieldKind.Totp ? "one-time password" : label;
        // A TOTP field stores its otpauth:// URI, which carries the shared seed, so it is secret
        // material from the moment the row exists (vault-format.md §5.3), same as macOS.
        concealed = kind is FieldKind.Concealed or FieldKind.CreditCardNumber or FieldKind.Totp;
    }

    public FieldDraftRowViewModel(Field existing)
    {
        Id = existing.Id;
        AgentVisible = existing.AgentVisible;
        label = existing.Label;
        kind = existing.Kind;
        concealed = existing.Concealed;
        section = existing.Section;
        // The editor prefills nothing concealed (ADR-0038 user decision 4): a stored secret starts
        // the row empty and is kept as it is unless something is typed over it. A plain field
        // starts with its value, which the item already carries.
        hasStoredSecret = existing.Concealed && existing.HasValue;
        value = existing.Concealed ? string.Empty : (existing.Value ?? string.Empty);
    }

    /// <summary>
    /// Whether this row is an existing concealed field with a stored value. While its box is
    /// empty, saving sends no value and the stored secret is kept — the vault reads an empty value
    /// for a stored secret the same way — so only typing a new value replaces it.
    /// </summary>
    private readonly bool hasStoredSecret;

    /// <summary>What the empty value box says: that the stored secret is kept, or just "Value".</summary>
    public string ValuePlaceholder =>
        hasStoredSecret && Value.Length == 0 ? "Unchanged (hidden) — type to replace" : "Value";

    [ObservableProperty]
    private string label;

    [ObservableProperty]
    private FieldKind kind;

    [ObservableProperty]
    private bool concealed;

    [ObservableProperty]
    private string value = string.Empty;

    [ObservableProperty]
    private string? section;

    /// <summary>Whether this row is a one-time-password field — gates the TOTP setup button vs. the plain value box (ui-spec.md §9), same switch <see cref="FieldRowViewModel.IsTotp"/> makes for the detail pane.</summary>
    public bool IsTotp => Kind == FieldKind.Totp;

    /// <summary>
    /// The TOTP setup button's label: "Set up" before a seed exists, "Change" once one does —
    /// stored (and kept, unseen) or typed in this edit — mirrors macOS's <c>FieldEditRow</c>.
    /// </summary>
    public string TotpSetupLabel =>
        Value.Length == 0 && !hasStoredSecret ? "Set up one-time password" : "Change one-time password";

    partial void OnKindChanged(FieldKind value)
    {
        OnPropertyChanged(nameof(IsTotp));
        OnPropertyChanged(nameof(TotpSetupLabel));
    }

    partial void OnValueChanged(string value)
    {
        OnPropertyChanged(nameof(ValuePlaceholder));
        OnPropertyChanged(nameof(TotpSetupLabel));
    }

    /// <summary>
    /// The row as the vault takes it. A kept secret goes as <c>null</c> ("keep the stored value");
    /// turning such a field public without typing a new value is refused by the vault, which is
    /// the point — unconcealing is not a way to read a secret.
    /// </summary>
    public FieldDraft ToDraft() => new(
        Id,
        Label,
        Kind,
        Concealed,
        hasStoredSecret && Value.Length == 0 ? null : Value,
        string.IsNullOrWhiteSpace(Section) ? null : Section,
        AgentVisible);
}

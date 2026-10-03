using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.Tests;

/// <summary>A scriptable <see cref="IVaultService"/> for view-model tests — no FFI, no disk I/O.</summary>
internal sealed class FakeVaultService : IVaultService
{
    public bool IsUnlocked { get; private set; }

    public string DefaultVaultPath { get; set; } = @"C:\fake\default.kagivault";

    /// <summary>Paths <see cref="VaultFileExists"/> should report as present.</summary>
    public HashSet<string> ExistingPaths { get; } = new();

    /// <summary>Set to throw from the next <see cref="CreateVaultAsync"/> call.</summary>
    public Exception? CreateVaultThrows { get; set; }

    /// <summary>Set to throw from the next <see cref="UnlockAsync"/> call.</summary>
    public Exception? UnlockThrows { get; set; }

    /// <summary>The recovery code the next <see cref="CreateVaultAsync"/> call hands back.</summary>
    public string? RecoveryCodeToReturn { get; set; } = "fake-recovery-code";

    /// <summary>Recorded arguments from the most recent <see cref="CreateVaultAsync"/> call.</summary>
    public (string Path, string Password, string Name)? LastCreateArgs { get; private set; }

    /// <summary>Recorded arguments from the most recent <see cref="UnlockAsync"/> call.</summary>
    public (string Path, string Password)? LastUnlockArgs { get; private set; }

    /// <summary>How many times <see cref="Lock"/> actually fired (i.e. while unlocked).</summary>
    public int LockCount { get; private set; }

    /// <summary>What <see cref="SidebarCountsAsync"/> hands back.</summary>
    public SidebarCounts SidebarCountsToReturn { get; set; } =
        new(0, 0, 0, 0, ValueList<TagCount>.Empty, ValueList<TagCount>.Empty);

    /// <summary>What <see cref="Categories"/> hands back.</summary>
    public IReadOnlyList<CategoryInfo> CategoriesToReturn { get; set; } = Array.Empty<CategoryInfo>();

    /// <summary>What <see cref="ListItemsAsync"/> hands back, regardless of filter/query/sort.</summary>
    public IReadOnlyList<Item> ItemsToReturn { get; set; } = Array.Empty<Item>();

    /// <summary>Recorded arguments from the most recent <see cref="ListItemsAsync"/> call.</summary>
    public (ItemFilter Filter, string? Query, ItemSort Sort)? LastListItemsArgs { get; private set; }

    /// <summary>What a field release (<see cref="ReleaseFieldAsync"/>) reads.</summary>
    public string RevealedValue { get; set; } = "revealed";

    /// <summary>What a notes release (<see cref="ReleaseNotesAsync"/>) reads.</summary>
    public string NotesText { get; set; } = "the notes";

    /// <summary>Every presence-gated release asked for, in order: what kind, which item and field, and why.</summary>
    public List<(string Kind, string ItemId, string? FieldId, ReleasePurpose Purpose)> ReleaseCalls { get; } = new();

    /// <summary>Set to make every release fail — a cancelled prompt, say.</summary>
    public Exception? ReleaseThrows { get; set; }

    public string GeneratePasswordResult { get; set; } = "generated-password";

    /// <summary>Set to throw from the next <see cref="GeneratePassword"/> call.</summary>
    public Exception? GeneratePasswordThrows { get; set; }

    public GeneratorRecipe? LastGeneratorRecipe { get; private set; }

    public GeneratorLimits GeneratorLimitsToReturn { get; set; } = new(8, 128, 3, 10, 7776);

    public Strength StrengthToReturn { get; set; } = new(40, StrengthBucket.Fair, "Fair", 0.5);

    public bool VaultFileExists(string path) => ExistingPaths.Contains(path);

    public Task<string?> CreateVaultAsync(
        string path, string masterPassword, string vaultName, CancellationToken cancellationToken = default)
    {
        LastCreateArgs = (path, masterPassword, vaultName);
        if (CreateVaultThrows is { } ex)
        {
            CreateVaultThrows = null;
            return Task.FromException<string?>(ex);
        }

        IsUnlocked = true;
        ExistingPaths.Add(path);
        Unlocked?.Invoke(this, EventArgs.Empty);
        return Task.FromResult(RecoveryCodeToReturn);
    }

    /// <summary>When set, <see cref="UnlockAsync"/> stays in flight (as the ~1 s KDF would) until the test completes it.</summary>
    public TaskCompletionSource? UnlockGate { get; set; }

    public async Task UnlockAsync(string path, string masterPassword, CancellationToken cancellationToken = default)
    {
        LastUnlockArgs = (path, masterPassword);
        if (UnlockGate is { } gate)
        {
            await gate.Task.ConfigureAwait(true);
        }

        if (UnlockThrows is { } ex)
        {
            UnlockThrows = null;
            throw ex;
        }

        IsUnlocked = true;
        Unlocked?.Invoke(this, EventArgs.Empty);
    }

    public void Lock()
    {
        if (!IsUnlocked)
        {
            return;
        }

        IsUnlocked = false;
        LockCount++;
        Locked?.Invoke(this, EventArgs.Empty);
    }

    public Task<SidebarCounts> SidebarCountsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(SidebarCountsToReturn);

    public IReadOnlyList<CategoryInfo> Categories() => CategoriesToReturn;

    public Task<IReadOnlyList<Item>> ListItemsAsync(
        ItemFilter filter, string? query, ItemSort sort, CancellationToken cancellationToken = default)
    {
        LastListItemsArgs = (filter, query, sort);
        return Task.FromResult(ItemsToReturn);
    }

    public Task<IFieldRelease> ReleaseFieldAsync(
        string itemId, string fieldId, ReleasePurpose purpose, CancellationToken cancellationToken = default)
    {
        ReleaseCalls.Add(("field", itemId, fieldId, purpose));
        return ReleaseThrows is { } ex
            ? Task.FromException<IFieldRelease>(ex)
            : Task.FromResult<IFieldRelease>(new FakeFieldRelease(itemId, fieldId, RevealedValue, purpose));
    }

    public Task<ITotpRelease> ReleaseTotpAsync(
        string itemId, string? fieldId, ReleasePurpose purpose, CancellationToken cancellationToken = default)
    {
        ReleaseCalls.Add(("totp", itemId, fieldId, purpose));
        return ReleaseThrows is { } ex
            ? Task.FromException<ITotpRelease>(ex)
            : Task.FromResult<ITotpRelease>(new FakeTotpRelease(itemId, TotpCodeToReturn, purpose));
    }

    public Task<INotesRelease> ReleaseNotesAsync(
        string itemId, ReleasePurpose purpose, CancellationToken cancellationToken = default)
    {
        ReleaseCalls.Add(("notes", itemId, null, purpose));
        return ReleaseThrows is { } ex
            ? Task.FromException<INotesRelease>(ex)
            : Task.FromResult<INotesRelease>(new FakeNotesRelease(itemId, NotesText, purpose));
    }

    public string GeneratePassword(GeneratorRecipe recipe)
    {
        LastGeneratorRecipe = recipe;
        if (GeneratePasswordThrows is { } ex)
        {
            GeneratePasswordThrows = null;
            throw ex;
        }

        return GeneratePasswordResult;
    }

    public GeneratorLimits GeneratorLimits() => GeneratorLimitsToReturn;

    public Strength RecipeStrength(GeneratorRecipe recipe) => StrengthToReturn;

    public Strength PasswordStrength(string password) => StrengthToReturn;

    public event EventHandler? Unlocked;

    public event EventHandler? Locked;

    // -----------------------------------------------------------------------------------------
    // Item create / edit / delete
    // -----------------------------------------------------------------------------------------

    public Func<string, string, string?, Item>? CreateItemHandler { get; set; }

    public Func<ItemDraft, Item>? SaveItemHandler { get; set; }

    public List<(string ItemId, bool Value)> FavoriteCalls { get; } = new();

    public List<(string ItemId, bool Value)> ArchivedCalls { get; } = new();

    public List<(string ItemId, bool Value)> TrashedCalls { get; } = new();

    public List<string> DeletedItemIds { get; } = new();

    /// <summary>The revision each <see cref="DeleteItemAsync"/> call carried, in order.</summary>
    public List<string> DeletedRevisions { get; } = new();

    /// <summary>What a mutation (favorite/archive/trash) hands back; defaults to a minimal fake item echoing the id.</summary>
    public Func<string, Item>? MutationResult { get; set; }

    public Exception? SaveItemThrows { get; set; }

    private static Item DefaultItem(string id) => new(
        id, "default", "login", "Login", "", "Item", ValueList<Field>.Empty, ValueList<string>.Empty,
        ValueList<string>.Empty, false, false, false, false, false, 0, 0, null, null, null, "rev-" + id);

    public Task<Item> CreateItemAsync(string category, string title, string? vaultId = null, CancellationToken cancellationToken = default) =>
        Task.FromResult(CreateItemHandler?.Invoke(category, title, vaultId) ?? DefaultItem("new-item"));

    public Task<Item> SaveItemAsync(ItemDraft draft, CancellationToken cancellationToken = default)
    {
        if (SaveItemThrows is { } ex)
        {
            SaveItemThrows = null;
            return Task.FromException<Item>(ex);
        }

        return Task.FromResult(SaveItemHandler?.Invoke(draft) ?? DefaultItem(draft.Id));
    }

    public Task<Item> SetFavoriteAsync(string itemId, bool favorite, CancellationToken cancellationToken = default)
    {
        FavoriteCalls.Add((itemId, favorite));
        return Task.FromResult(MutationResult?.Invoke(itemId) ?? DefaultItem(itemId));
    }

    public Task<Item> SetArchivedAsync(string itemId, bool archived, CancellationToken cancellationToken = default)
    {
        ArchivedCalls.Add((itemId, archived));
        return Task.FromResult(MutationResult?.Invoke(itemId) ?? DefaultItem(itemId));
    }

    public Task<Item> SetTrashedAsync(string itemId, bool trashed, CancellationToken cancellationToken = default)
    {
        TrashedCalls.Add((itemId, trashed));
        return Task.FromResult(MutationResult?.Invoke(itemId) ?? DefaultItem(itemId));
    }

    public Task DeleteItemAsync(string itemId, string revision, CancellationToken cancellationToken = default)
    {
        DeletedItemIds.Add(itemId);
        DeletedRevisions.Add(revision);
        return Task.CompletedTask;
    }

    // -----------------------------------------------------------------------------------------
    // TOTP
    // -----------------------------------------------------------------------------------------

    public TotpCode TotpCodeToReturn { get; set; } =
        new("123456", 30, new TotpParams(TotpAlgorithm.Sha1, 6, 30, null, null, null));

    public TotpParams TotpDescribe(string uri) => TotpCodeToReturn.Params;

    public TotpCode TotpPreview(string uri) => TotpCodeToReturn;

    public string TotpUriFromParts(string secretBase32, TotpParams parameters) => "otpauth://totp/fake";

    public bool TotpUriIsValid(string uri) => uri.StartsWith("otpauth://", StringComparison.Ordinal);

    // -----------------------------------------------------------------------------------------
    // Recovery code / master password change
    // -----------------------------------------------------------------------------------------

    public string? PendingRecoveryCode { get; set; }

    public string? TakePendingRecoveryCode()
    {
        string? code = PendingRecoveryCode;
        PendingRecoveryCode = null;
        return code;
    }

    public bool RequiresMasterPasswordChange { get; set; }

    public Exception? UnlockWithRecoveryThrows { get; set; }

    public (string Path, string Code)? LastRecoveryUnlockArgs { get; private set; }

    public Task UnlockWithRecoveryCodeAsync(string path, string recoveryCode, CancellationToken cancellationToken = default)
    {
        LastRecoveryUnlockArgs = (path, recoveryCode);
        if (UnlockWithRecoveryThrows is { } ex)
        {
            UnlockWithRecoveryThrows = null;
            return Task.FromException(ex);
        }

        IsUnlocked = true;
        Unlocked?.Invoke(this, EventArgs.Empty);
        return Task.CompletedTask;
    }

    public string? LastChangedPassword { get; private set; }

    public Exception? ChangeMasterPasswordThrows { get; set; }

    public Task ChangeMasterPasswordAsync(string newPassword, CancellationToken cancellationToken = default)
    {
        if (ChangeMasterPasswordThrows is { } ex)
        {
            ChangeMasterPasswordThrows = null;
            return Task.FromException(ex);
        }

        LastChangedPassword = newPassword;
        RequiresMasterPasswordChange = false;
        return Task.CompletedTask;
    }

    // -----------------------------------------------------------------------------------------
    // Import
    // -----------------------------------------------------------------------------------------

    public IReadOnlyList<ImportFormatInfo> ImportFormatsToReturn { get; set; } = Array.Empty<ImportFormatInfo>();

    public IReadOnlyList<ImportFormatInfo> ImportFormats() => ImportFormatsToReturn;

    public string ShredCaveatToReturn { get; set; } = "Not a secure erase.";

    public string ImportShredCaveat() => ShredCaveatToReturn;

    /// <summary>What <see cref="ImportPreviewAsync"/> hands back; the token is opaque to the caller, so any string works.</summary>
    public string ImportPlanTokenToReturn { get; set; } = "fake-plan-token";

    public ImportReport ImportReportToReturn { get; set; } = new(
        ImportFormat.OnePasswordCsv, "source.csv", "0 items", new ImportTotals(0, 0, 0, 0, 0),
        ValueList<ImportCategoryCount>.Empty, ValueList<DropNote>.Empty, ValueList<ImportDecision>.Empty,
        ValueList<ImportActionCount>.Empty, 0, false, ValueList<ImportItemRow>.Empty);

    public Exception? ImportPreviewThrows { get; set; }

    /// <summary>Every token <see cref="ImportPreviewAsync"/> has handed out and <see cref="DisposeImportPlan"/> hasn't released — a wizard that leaks its token fails a test here.</summary>
    public HashSet<string> OutstandingPlanTokens { get; } = new();

    public Task<(string PlanToken, ImportReport Report)> ImportPreviewAsync(
        string path, ImportFormat? format, CancellationToken cancellationToken = default)
    {
        if (ImportPreviewThrows is { } ex)
        {
            ImportPreviewThrows = null;
            return Task.FromException<(string, ImportReport)>(ex);
        }

        OutstandingPlanTokens.Add(ImportPlanTokenToReturn);
        return Task.FromResult((ImportPlanTokenToReturn, ImportReportToReturn));
    }

    public List<(string Token, DuplicatePolicy Policy)> ImportPreviewAgainstCalls { get; } = new();

    public Task<ImportReport> ImportPreviewAgainstAsync(string planToken, DuplicatePolicy policy, CancellationToken cancellationToken = default)
    {
        ImportPreviewAgainstCalls.Add((planToken, policy));
        return Task.FromResult(ImportReportToReturn);
    }

    public ImportOutcome? ImportOutcomeToReturn { get; set; }

    public List<(string Token, DuplicatePolicy Policy, string? TargetVault)> ImportCommitCalls { get; } = new();

    public Task<ImportOutcome> ImportCommitAsync(string planToken, DuplicatePolicy policy, string? targetVault, CancellationToken cancellationToken = default)
    {
        ImportCommitCalls.Add((planToken, policy, targetVault));
        OutstandingPlanTokens.Remove(planToken);
        return ImportOutcomeToReturn is { } outcome
            ? Task.FromResult(outcome)
            : Task.FromResult(new ImportOutcome(0, 0, 0, 0, 0, ValueList<string>.Empty, "Imported nothing", ImportReportToReturn));
    }

    public void DisposeImportPlan(string planToken) => OutstandingPlanTokens.Remove(planToken);

    public ShredOutcome ShredOutcomeToReturn { get; set; } = new(true, true, "Not a secure erase.");

    public Task<ShredOutcome> ImportShredSourceFileAsync(string path, CancellationToken cancellationToken = default) =>
        Task.FromResult(ShredOutcomeToReturn);

    public IReadOnlyList<LogicalVault> VaultsToReturn { get; set; } = Array.Empty<LogicalVault>();

    public Task<IReadOnlyList<LogicalVault>> VaultsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(VaultsToReturn);

    // -----------------------------------------------------------------------------------------
    // Settings / Audit
    // -----------------------------------------------------------------------------------------

    public string VaultFilePath { get; set; } = @"C:\fake\default.kagivault";

    public IReadOnlyList<AuditRow> AuditRowsToReturn { get; set; } = Array.Empty<AuditRow>();

    public Task<IReadOnlyList<AuditRow>> AuditPageAsync(uint limit, uint offset, CancellationToken cancellationToken = default) =>
        Task.FromResult(AuditRowsToReturn);

    public uint AuditCountToReturn { get; set; }

    public Task<uint> AuditCountAsync(CancellationToken cancellationToken = default) => Task.FromResult(AuditCountToReturn);

    public bool AuditIntactToReturn { get; set; } = true;

    public Task<bool> AuditIntactAsync(CancellationToken cancellationToken = default) => Task.FromResult(AuditIntactToReturn);

    public AuditDurability AuditDurabilityToReturn { get; set; } = new(0, null);

    public Task<AuditDurability> AuditDurabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(AuditDurabilityToReturn);

    public void Dispose()
    {
    }
}

/// <summary>A released field that reads a fixed value and ends when closed or when its one copy is used.</summary>
internal sealed class FakeFieldRelease : IFieldRelease
{
    private readonly string value;
    private readonly ReleasePurpose purpose;
    private bool live = true;

    public FakeFieldRelease(string itemId, string fieldId, string value, ReleasePurpose purpose)
    {
        ItemId = itemId;
        FieldId = fieldId;
        this.value = value;
        this.purpose = purpose;
    }

    public string ItemId { get; }

    public string FieldId { get; }

    public string Value() => Read();

    public byte[] ValueUtf8() => System.Text.Encoding.UTF8.GetBytes(Read());

    public byte[] CopyShownValueUtf8() => System.Text.Encoding.UTF8.GetBytes(Read());

    public void Close() => live = false;

    public ReleaseState State() => new(live, live ? 300u : 0u, purpose);

    public void Dispose() => Close();

    private string Read()
    {
        if (!live)
        {
            throw KagisecureExceptionFactory.Create<KagisecureException.ReleaseEnded>("the release has ended");
        }

        if (purpose is ReleasePurpose.Copy or ReleasePurpose.QuickAccessCopy)
        {
            live = false;
        }

        return value;
    }
}

/// <summary>A released one-time code that answers a fixed code until closed.</summary>
internal sealed class FakeTotpRelease : ITotpRelease
{
    private readonly TotpCode code;
    private readonly ReleasePurpose purpose;
    private bool live = true;

    public FakeTotpRelease(string itemId, TotpCode code, ReleasePurpose purpose)
    {
        ItemId = itemId;
        this.code = code;
        this.purpose = purpose;
    }

    public string ItemId { get; }

    public TotpCode CodeAt(ulong at) => live
        ? code
        : throw KagisecureExceptionFactory.Create<KagisecureException.ReleaseEnded>("the release has ended");

    public TotpCode CopyShownCodeAt(ulong at) => CodeAt(at);

    public void Close() => live = false;

    public ReleaseState State() => new(live, live ? 300u : 0u, purpose);

    public void Dispose() => Close();
}

/// <summary>Released notes that read fixed text until closed.</summary>
internal sealed class FakeNotesRelease : INotesRelease
{
    private readonly string text;
    private readonly ReleasePurpose purpose;
    private bool live = true;

    public FakeNotesRelease(string itemId, string text, ReleasePurpose purpose)
    {
        ItemId = itemId;
        this.text = text;
        this.purpose = purpose;
    }

    public string ItemId { get; }

    public string Text() => live
        ? text
        : throw KagisecureExceptionFactory.Create<KagisecureException.ReleaseEnded>("the release has ended");

    public byte[] CopyShownTextUtf8() => System.Text.Encoding.UTF8.GetBytes(Text());

    public void Close() => live = false;

    public ReleaseState State() => new(live, live ? 300u : 0u, purpose);

    public void Dispose() => Close();
}

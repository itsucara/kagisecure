using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>The real <see cref="IVaultService"/>, backed by <c>Kagisecure.Interop</c>.</summary>
public sealed partial class VaultService : IVaultService
{
    private readonly object gate = new();
    private VaultSession? session;
    private string? pendingRecoveryCode;
    private bool requiresMasterPasswordChange;

    /// <inheritdoc />
    public bool IsUnlocked
    {
        get
        {
            lock (gate)
            {
                return session is { IsDisposed: false };
            }
        }
    }

    /// <inheritdoc />
    public string DefaultVaultPath { get; } = VaultSession.DefaultPath();

    /// <inheritdoc />
    public bool VaultFileExists(string path) => VaultSession.Exists(path);

    /// <inheritdoc />
    public async Task<string?> CreateVaultAsync(
        string path, string masterPassword, string vaultName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // The KDF (Argon2id) runs synchronously in Rust and takes roughly a second at the desktop
        // profile; Task.Run keeps it off the UI thread. `masterPassword` is turned into a
        // ReadOnlySpan<char> and consumed entirely inside this synchronous delegate, so nothing
        // spans an `await` (a Span cannot be captured across one).
        int startedAt = CurrentLockGeneration();
        (VaultSession created, string? recoveryCode) = await Task.Run(
            () =>
            {
                VaultSession s = VaultSession.Create(path, masterPassword, vaultName);
                return (s, s.TakeRecoveryCode());
            }, cancellationToken).ConfigureAwait(false);
        pendingRecoveryCode = recoveryCode;
        requiresMasterPasswordChange = false;
        // A lock that arrived while the KDF ran wins, even here: the vault exists and stays
        // locked, and the pending recovery code is shown after the next unlock instead
        // (MainWindow's Unlocked handler takes it first). Not an error to the caller.
        AdoptLocked(created, startedAt);
        return recoveryCode;
    }

    /// <inheritdoc />
    public async Task UnlockAsync(string path, string masterPassword, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int startedAt = CurrentLockGeneration();
        VaultSession unlocked = await Task.Run(
            () => VaultSession.UnlockWithPassword(path, masterPassword), cancellationToken).ConfigureAwait(false);
        AdoptOrThrow(unlocked, startedAt, requiresPasswordChange: false);
    }

    /// <inheritdoc />
    public async Task UnlockWithRecoveryCodeAsync(string path, string recoveryCode, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int startedAt = CurrentLockGeneration();
        VaultSession unlocked = await Task.Run(
            () => VaultSession.UnlockWithRecoveryCode(path, recoveryCode), cancellationToken).ConfigureAwait(false);
        AdoptOrThrow(unlocked, startedAt, requiresPasswordChange: unlocked.UnlockedBy == UnlockKind.RecoveryCode);
    }

    /// <summary>Adopt an unlock, or throw <see cref="VaultLockedDuringUnlockException"/> if a Lock arrived while it ran.</summary>
    private void AdoptOrThrow(VaultSession unlocked, int startedAt, bool requiresPasswordChange)
    {
        // Set before adopting: the Unlocked handler reads it.
        requiresMasterPasswordChange = requiresPasswordChange;
        if (!AdoptLocked(unlocked, startedAt))
        {
            requiresMasterPasswordChange = false;
            throw new VaultLockedDuringUnlockException();
        }
    }

    /// <inheritdoc />
    public bool RequiresMasterPasswordChange => requiresMasterPasswordChange;

    /// <inheritdoc />
    public async Task ChangeMasterPasswordAsync(string newPassword, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        await Task.Run(() => current.ChangeMasterPassword(newPassword), cancellationToken).ConfigureAwait(false);
        requiresMasterPasswordChange = false;
    }

    /// <inheritdoc />
    public string? TakePendingRecoveryCode()
    {
        string? code = pendingRecoveryCode;
        pendingRecoveryCode = null;
        return code;
    }

    /// <inheritdoc />
    public void Lock()
    {
        // 1. Take the session out and bump the lock generation, atomically. From here on nothing
        //    can start serving it (AgentHostService re-checks the generation after binding), and an
        //    unlock still running its KDF will not be adopted.
        VaultSession? toDispose;
        lock (gate)
        {
            lockGeneration++;
            sessionGeneration++;
            toDispose = session;
            session = null;
        }

        // 2. Stop the listeners — unconditionally, even when there was no session here: a Start
        //    that raced an earlier lock must not survive it (the listeners hold their own reference
        //    to the Rust session, so disposing ours alone would not lock). Stop is idempotent and
        //    serialized against Start (ADR-0014, ADR-0020). See VaultService.AgentAccess.cs.
        RaiseLocking();

        requiresMasterPasswordChange = false;

        if (toDispose is null)
        {
            return;
        }

        // 3. Only now release our reference, the last one, which zeroizes the key in Rust.
        toDispose.Dispose();
        Locked?.Invoke(this, EventArgs.Empty);
    }

    /// <inheritdoc />
    public async Task<SidebarCounts> SidebarCountsAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.SidebarCounts(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public IReadOnlyList<CategoryInfo> Categories() => Interop.Categories.Catalog();

    /// <inheritdoc />
    public async Task<IReadOnlyList<Item>> ListItemsAsync(
        ItemFilter filter, string? query, ItemSort sort, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.ListItems(filter, query, sort), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the presence gate each unlocked session gets before it is published (ADR-0038). Set
    /// once by the composition root; while it is <c>null</c> no gate is installed, and every
    /// release fails closed with <see cref="KagisecureException.NoPresenceGate"/>.
    /// </summary>
    internal Func<VaultSession, IPresenceGate>? PresenceGateFactory { get; set; }

    // The release calls block their thread for as long as the prompt is up, so each runs on the
    // thread pool — never the UI thread, which the gate needs free to show Windows Hello.

    /// <inheritdoc />
    public async Task<IFieldRelease> ReleaseFieldAsync(
        string itemId, string fieldId, ReleasePurpose purpose, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run<IFieldRelease>(() => current.ReleaseField(itemId, fieldId, purpose), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ITotpRelease> ReleaseTotpAsync(
        string itemId, string? fieldId, ReleasePurpose purpose, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run<ITotpRelease>(() => current.ReleaseTotp(itemId, fieldId, purpose), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<INotesRelease> ReleaseNotesAsync(
        string itemId, ReleasePurpose purpose, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run<INotesRelease>(() => current.ReleaseNotes(itemId, purpose), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public string GeneratePassword(GeneratorRecipe recipe) => PasswordGenerator.Generate(recipe);

    /// <inheritdoc />
    public GeneratorLimits GeneratorLimits() => PasswordGenerator.Limits();

    /// <inheritdoc />
    public Strength RecipeStrength(GeneratorRecipe recipe) => PasswordGenerator.RecipeStrength(recipe);

    /// <inheritdoc />
    public Strength PasswordStrength(string password) => PasswordGenerator.PasswordStrength(password);

    /// <inheritdoc />
    public event EventHandler? Unlocked;

    /// <inheritdoc />
    public event EventHandler? Locked;

    // -----------------------------------------------------------------------------------------
    // Item create / edit / delete
    // -----------------------------------------------------------------------------------------

    /// <inheritdoc />
    public async Task<Item> CreateItemAsync(
        string category, string title, string? vaultId = null, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.CreateItem(category, title, vaultId), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Item> SaveItemAsync(ItemDraft draft, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.SaveItem(draft), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Item> SetFavoriteAsync(string itemId, bool favorite, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.SetFavorite(itemId, favorite), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Item> SetArchivedAsync(string itemId, bool archived, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.SetArchived(itemId, archived), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Item> SetTrashedAsync(string itemId, bool trashed, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.SetTrashed(itemId, trashed), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DeleteItemAsync(string itemId, string revision, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        await Task.Run(() => current.DeleteItem(itemId, revision), cancellationToken).ConfigureAwait(false);
    }

    // -----------------------------------------------------------------------------------------
    // TOTP
    // -----------------------------------------------------------------------------------------

    /// <inheritdoc />
    public TotpParams TotpDescribe(string uri) => Totp.Describe(uri);

    /// <inheritdoc />
    public TotpCode TotpPreview(string uri) => Totp.Preview(uri, (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    /// <inheritdoc />
    public string TotpUriFromParts(string secretBase32, TotpParams parameters) => Totp.UriFromParts(secretBase32, parameters);

    /// <inheritdoc />
    public bool TotpUriIsValid(string uri) => Totp.UriIsValid(uri);

    // -----------------------------------------------------------------------------------------
    // Import
    // -----------------------------------------------------------------------------------------

    private readonly object importGate = new();
    private readonly Dictionary<string, ImportPlan> importPlans = new();

    /// <inheritdoc />
    public IReadOnlyList<ImportFormatInfo> ImportFormats() => Importer.Formats();

    /// <inheritdoc />
    public string ImportShredCaveat() => Importer.ShredCaveat();

    /// <inheritdoc />
    public async Task<(string PlanToken, ImportReport Report)> ImportPreviewAsync(
        string path, ImportFormat? format, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        (ImportPlan plan, ImportReport report) = await Task.Run(
            () =>
            {
                ImportPlan p = current.ImportPreview(path, format);
                return (p, p.Report());
            }, cancellationToken).ConfigureAwait(false);

        string token = Guid.NewGuid().ToString("N");
        lock (importGate)
        {
            importPlans[token] = plan;
        }

        return (token, report);
    }

    /// <inheritdoc />
    public async Task<ImportReport> ImportPreviewAgainstAsync(
        string planToken, DuplicatePolicy policy, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        ImportPlan plan = RequirePlan(planToken);
        return await Task.Run(() => current.ImportPreviewAgainst(plan, policy), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ImportOutcome> ImportCommitAsync(
        string planToken, DuplicatePolicy policy, string? targetVault, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        ImportPlan plan = RequirePlan(planToken);
        try
        {
            return await Task.Run(() => current.ImportCommit(plan, policy, targetVault), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Spent either way — a failed commit still leaves the plan unusable to retry with the
            // same token, matching ImportPlan.IsSpent's own "committed or not" semantics closely
            // enough that holding onto it risks a leak more than it buys a retry.
            RemovePlan(planToken)?.Dispose();
        }
    }

    /// <inheritdoc />
    public void DisposeImportPlan(string planToken) => RemovePlan(planToken)?.Dispose();

    private ImportPlan RequirePlan(string planToken)
    {
        lock (importGate)
        {
            if (importPlans.TryGetValue(planToken, out ImportPlan? plan))
            {
                return plan;
            }
        }

        throw new InvalidOperationException($"No import plan for token {planToken}.");
    }

    private ImportPlan? RemovePlan(string planToken)
    {
        lock (importGate)
        {
            if (importPlans.Remove(planToken, out ImportPlan? plan))
            {
                return plan;
            }
        }

        return null;
    }

    /// <inheritdoc />
    public async Task<ShredOutcome> ImportShredSourceFileAsync(string path, CancellationToken cancellationToken = default) =>
        await Task.Run(() => Importer.ShredSourceFile(path), cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task<IReadOnlyList<LogicalVault>> VaultsAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.Vaults(), cancellationToken).ConfigureAwait(false);
    }

    // -----------------------------------------------------------------------------------------
    // Settings / Audit
    // -----------------------------------------------------------------------------------------

    /// <inheritdoc />
    public string VaultFilePath
    {
        get
        {
            lock (gate)
            {
                return session is { IsDisposed: false } s ? s.Path : DefaultVaultPath;
            }
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditRow>> AuditPageAsync(uint limit, uint offset, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.AuditPage(limit, offset), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<uint> AuditCountAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.AuditCount(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> AuditIntactAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.AuditIntact(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AuditDurability> AuditDurabilityAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return await Task.Run(() => current.AuditDurability(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Adopt <paramref name="newSession"/> unless a <see cref="Lock"/> arrived after
    /// <paramref name="startedAt"/> — the Argon2id unlock takes about a second, and a screen lock
    /// or sleep in that window must win. A superseded session is disposed at once and
    /// <see cref="Locked"/> is raised so the window shows the lock screen; returns <c>false</c>.
    /// Replacing a session that is still open goes through <see cref="IAgentVaultAccess.Locking"/>
    /// first, so the listeners serving the old one stop before it is released.
    /// </summary>
    private bool AdoptLocked(VaultSession newSession, int startedAt)
    {
        // The presence gate goes on before anything can see the session, so there is no moment in
        // which it is published without one. Without a factory nothing is installed, and every
        // release on it fails closed (NoPresenceGate) rather than going ungated.
        if (PresenceGateFactory is { } gates)
        {
            try
            {
                newSession.SetPresenceGate(gates(newSession));
            }
            catch
            {
                // Never leave an unlocked session behind for the finalizer.
                newSession.Dispose();
                throw;
            }
        }

        while (true)
        {
            bool superseded;
            bool replacing;
            lock (gate)
            {
                superseded = lockGeneration != startedAt;
                replacing = !superseded && session is not null;
                if (!superseded && !replacing)
                {
                    sessionGeneration++; // a new session: listeners bound to anything earlier are stale
                    session = newSession;
                }
            }

            if (superseded)
            {
                newSession.Dispose();
                if (IsUnlocked)
                {
                    // Superseded by a Lock that another unlock has since followed: the vault is
                    // open, just not with this session. Nothing to report.
                    return true;
                }

                Locked?.Invoke(this, EventArgs.Empty);
                return false;
            }

            if (replacing)
            {
                // Replacing an open session is a lock of that session: its listeners stop first.
                Lock();
                startedAt = CurrentLockGeneration();
                continue;
            }

            Unlocked?.Invoke(this, EventArgs.Empty);
            return true;
        }
    }

    /// <summary>
    /// Bumped by every <see cref="Lock"/>, including one with nothing to lock. An unlock records it
    /// before the KDF and is adopted only if it is unchanged afterwards.
    /// </summary>
    private int lockGeneration;

    /// <summary>
    /// Bumped whenever the session changes — every <see cref="Lock"/> and every adopted session.
    /// The agent host records it before binding the listeners and stops them if it changed
    /// underneath (<see cref="IAgentVaultAccess.SessionGeneration"/>).
    /// </summary>
    private int sessionGeneration;

    private int CurrentLockGeneration()
    {
        lock (gate)
        {
            return lockGeneration;
        }
    }

    private VaultSession RequireSession()
    {
        lock (gate)
        {
            if (session is { IsDisposed: false } s)
            {
                return s;
            }
        }

        throw new InvalidOperationException("The vault is locked.");
    }

    /// <summary>Locks, if still unlocked, releasing the native session.</summary>
    public void Dispose()
    {
        lock (importGate)
        {
            foreach (ImportPlan plan in importPlans.Values)
            {
                plan.Dispose();
            }

            importPlans.Clear();
        }

        lock (gate)
        {
            session?.Dispose();
            session = null;
        }
    }
}

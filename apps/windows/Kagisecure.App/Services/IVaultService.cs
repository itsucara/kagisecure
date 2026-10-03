using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>
/// The one seam between the views/view models and <c>Kagisecure.Interop</c>. Views and view
/// models never call <c>NativeMethods</c> or hold a <see cref="VaultSession"/> directly — they
/// go through this, so a fake implementation can drive the view models in tests without the real
/// FFI, and so every call that can block (the KDF on create/unlock takes roughly a second; every
/// mutating call re-encrypts and saves the file) is already off the UI thread by the time a view
/// model awaits it.
/// </summary>
public interface IVaultService : IDisposable
{
    /// <summary>Whether a vault is currently unlocked.</summary>
    bool IsUnlocked { get; }

    /// <summary>
    /// The per-user default vault path (<c>KAGISECURE_VAULT</c>, else <c>KAGISECURE_HOME</c>, else
    /// the per-user data directory — the same answer the CLI gives, via <c>kgs_default_vault_path</c>).
    /// </summary>
    string DefaultVaultPath { get; }

    /// <summary>Whether a vault file already exists at <paramref name="path"/>.</summary>
    bool VaultFileExists(string path);

    /// <summary>
    /// Create a vault at <paramref name="path"/> and leave it unlocked. Runs the KDF off the UI
    /// thread. Returns the one-time recovery code — show it once; it cannot be retrieved again.
    /// </summary>
    /// <exception cref="KagisecureException.AlreadyExists">A file is already there.</exception>
    Task<string?> CreateVaultAsync(
        string path, string masterPassword, string vaultName, CancellationToken cancellationToken = default);

    /// <summary>Unlock the vault at <paramref name="path"/> with the master password.</summary>
    /// <exception cref="KagisecureException.NotFound">No vault at <paramref name="path"/>.</exception>
    /// <exception cref="KagisecureException.WrongCredential">The password does not open it.</exception>
    Task UnlockAsync(string path, string masterPassword, CancellationToken cancellationToken = default);

    /// <summary>Lock: dispose the session. Safe to call when already locked.</summary>
    void Lock();

    /// <summary>The counts the sidebar shows: All/Favorites/Archive/Trash plus per-category and per-tag. Requires <see cref="IsUnlocked"/>.</summary>
    Task<SidebarCounts> SidebarCountsAsync(CancellationToken cancellationToken = default);

    /// <summary>Every category the vault format knows about — canonical name, display name, icon. No vault needed.</summary>
    IReadOnlyList<CategoryInfo> Categories();

    /// <summary>
    /// The item list for one sidebar section, optionally searched (title/tags/URLs — never field
    /// values) and sorted. Requires <see cref="IsUnlocked"/>.
    /// </summary>
    Task<IReadOnlyList<Item>> ListItemsAsync(
        ItemFilter filter, string? query, ItemSort sort, CancellationToken cancellationToken = default);

    /// <summary>
    /// Release one concealed field behind a presence check (ADR-0038): Windows Hello, or the master
    /// password where Hello cannot run. The prompt is up for as long as the returned task runs.
    /// Dispose the release when the value is hidden or copied.
    /// </summary>
    /// <exception cref="KagisecureException.PresenceCancelled">The person said no.</exception>
    /// <exception cref="KagisecureException.PresenceBusy">Another confirmation is already up.</exception>
    Task<IFieldRelease> ReleaseFieldAsync(string itemId, string fieldId, ReleasePurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>
    /// Release an item's one-time code behind a presence check — the named TOTP field's, or with
    /// <paramref name="fieldId"/> <c>null</c> the item's first. Live for at most five minutes.
    /// </summary>
    Task<ITotpRelease> ReleaseTotpAsync(string itemId, string? fieldId, ReleasePurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>Release an item's notes behind a presence check (every note is secret, ADR-0038).</summary>
    Task<INotesRelease> ReleaseNotesAsync(string itemId, ReleasePurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>Generate a password. Does not require an unlocked vault.</summary>
    string GeneratePassword(GeneratorRecipe recipe);

    /// <summary>The slider bounds and wordlist size the generator sheet must respect. Does not require an unlocked vault.</summary>
    GeneratorLimits GeneratorLimits();

    /// <summary>The strength a recipe's output would have — recomputed live as the sheet's options change.</summary>
    Strength RecipeStrength(GeneratorRecipe recipe);

    /// <summary>The strength of a password the user typed (the first-run master password field).</summary>
    Strength PasswordStrength(string password);

    /// <summary>Raised right after a vault is created or unlocked.</summary>
    event EventHandler? Unlocked;

    /// <summary>Raised right after <see cref="Lock"/> takes effect, from any cause.</summary>
    event EventHandler? Locked;

    // ---------------------------------------------------------------------------------------
    // Item create / edit / delete (ui-spec.md §4)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Create an item pre-populated with its category's default fields, saved at once.
    /// <paramref name="vaultId"/> <c>null</c> is the default logical vault.
    /// </summary>
    Task<Item> CreateItemAsync(string category, string title, string? vaultId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replace an item's editable content with what the edit form produced. A field value or note
    /// of <c>null</c> keeps what is stored; a draft read before the item last changed is refused
    /// with <see cref="KagisecureException.ItemChangedElsewhere"/>.
    /// </summary>
    Task<Item> SaveItemAsync(ItemDraft draft, CancellationToken cancellationToken = default);

    /// <summary>Toggle the favourite star.</summary>
    Task<Item> SetFavoriteAsync(string itemId, bool favorite, CancellationToken cancellationToken = default);

    /// <summary>Move an item to the archive, or bring it back.</summary>
    Task<Item> SetArchivedAsync(string itemId, bool archived, CancellationToken cancellationToken = default);

    /// <summary>Move an item to the trash, or restore it. A soft delete.</summary>
    Task<Item> SetTrashedAsync(string itemId, bool trashed, CancellationToken cancellationToken = default);

    /// <summary>
    /// Delete an item for good — only if it is still in the Trash and still at
    /// <paramref name="revision"/>, the <see cref="Item.Revision"/> of the row the person chose.
    /// </summary>
    Task DeleteItemAsync(string itemId, string revision, CancellationToken cancellationToken = default);

    // ---------------------------------------------------------------------------------------
    // TOTP (ui-spec.md §4.2/§9)
    // ---------------------------------------------------------------------------------------

    /// <summary>Parse a URI and report its parameters, without producing a code. Does not require an unlocked vault.</summary>
    TotpParams TotpDescribe(string uri);

    /// <summary>The code a not-yet-saved setup would produce right now. Does not require an unlocked vault.</summary>
    TotpCode TotpPreview(string uri);

    /// <summary>Build an <c>otpauth://</c> URI from a hand-typed Base32 seed. Does not require an unlocked vault.</summary>
    string TotpUriFromParts(string secretBase32, TotpParams parameters);

    /// <summary>Whether a string is a usable <c>otpauth://</c> URI. Does not require an unlocked vault.</summary>
    bool TotpUriIsValid(string uri);

    // ---------------------------------------------------------------------------------------
    // Recovery code (ui-spec.md §6.1, §12)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The one-time recovery code from the most recent <see cref="CreateVaultAsync"/> call,
    /// consumed once — <c>null</c> on every call after the first. Lets the shell decide whether
    /// to show the "write this down" interstitial without the caller having to thread the value
    /// returned by <see cref="CreateVaultAsync"/> through navigation by hand.
    /// </summary>
    string? TakePendingRecoveryCode();

    /// <summary>Unlock with the printable recovery code. Sets <see cref="RequiresMasterPasswordChange"/>.</summary>
    Task UnlockWithRecoveryCodeAsync(string path, string recoveryCode, CancellationToken cancellationToken = default);

    /// <summary>Whether the current session unlocked with the recovery code and must set a new master password before continuing.</summary>
    bool RequiresMasterPasswordChange { get; }

    /// <summary>Replace the master password — required after a recovery-code unlock. Clears <see cref="RequiresMasterPasswordChange"/>.</summary>
    Task ChangeMasterPasswordAsync(string newPassword, CancellationToken cancellationToken = default);

    // ---------------------------------------------------------------------------------------
    // Import (import.md, ui-spec.md §15 "Import")
    // ---------------------------------------------------------------------------------------

    /// <summary>Every format this build can read. Does not require an unlocked vault.</summary>
    IReadOnlyList<ImportFormatInfo> ImportFormats();

    /// <summary>What the "Delete the source file?" prompt must say before the user agrees.</summary>
    string ImportShredCaveat();

    /// <summary>
    /// Parse an export into a plan and hold it server-side (nothing is written to the vault yet),
    /// returning an opaque token for the other Import* calls and the vault-unaware preview report.
    /// The real <c>Kagisecure.Interop.ImportPlan</c> never crosses this seam — its methods reach
    /// the native session directly, which a fake <see cref="IVaultService"/> cannot honor, so the
    /// view model only ever holds the token. Dispose it with <see cref="DisposeImportPlan"/> when
    /// the wizard closes without committing.
    /// </summary>
    Task<(string PlanToken, ImportReport Report)> ImportPreviewAsync(
        string path, ImportFormat? format, CancellationToken cancellationToken = default);

    /// <summary>The plan previewed against this vault under <paramref name="policy"/>: duplicates known.</summary>
    Task<ImportReport> ImportPreviewAgainstAsync(string planToken, DuplicatePolicy policy, CancellationToken cancellationToken = default);

    /// <summary>Apply the plan and save. <paramref name="targetVault"/> <c>null</c> follows the source. Spends and disposes the plan.</summary>
    Task<ImportOutcome> ImportCommitAsync(string planToken, DuplicatePolicy policy, string? targetVault, CancellationToken cancellationToken = default);

    /// <summary>Release a plan that was never committed (the wizard was cancelled). Safe to call more than once.</summary>
    void DisposeImportPlan(string planToken);

    /// <summary>Overwrite, truncate and remove the file an import was read from. Best effort, not secure erase.</summary>
    Task<ShredOutcome> ImportShredSourceFileAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>The logical vaults inside the file, for the import target-vault picker.</summary>
    Task<IReadOnlyList<LogicalVault>> VaultsAsync(CancellationToken cancellationToken = default);

    // ---------------------------------------------------------------------------------------
    // Settings / Audit (ui-spec.md §6.2, §10.4 audit viewer)
    // ---------------------------------------------------------------------------------------

    /// <summary>Where the open vault's file lives; <see cref="DefaultVaultPath"/> when locked.</summary>
    string VaultFilePath { get; }

    /// <summary>A page of the audit log, newest first.</summary>
    Task<IReadOnlyList<AuditRow>> AuditPageAsync(uint limit, uint offset, CancellationToken cancellationToken = default);

    /// <summary>How many entries the audit log has.</summary>
    Task<uint> AuditCountAsync(CancellationToken cancellationToken = default);

    /// <summary>Whether the audit hash chain verifies.</summary>
    Task<bool> AuditIntactAsync(CancellationToken cancellationToken = default);

    /// <summary>Whether every appended audit entry has reached disk.</summary>
    Task<AuditDurability> AuditDurabilityAsync(CancellationToken cancellationToken = default);
}

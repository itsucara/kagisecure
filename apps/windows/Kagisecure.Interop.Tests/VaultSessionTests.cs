using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Kagisecure.Interop.Tests;

/// <summary>
/// The Arc-style object, its lifetime, typed errors, and every <see cref="VaultSession"/> member,
/// each against a real vault in a temp directory.
/// </summary>
public class VaultSessionTests
{
    private const string Uri =
        "otpauth://totp/ACME:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30";

    /// <summary>A login with a username, a password, a TOTP seed, tags, a URL and a note.</summary>
    private static Item FilledLogin(VaultSession session, string title = "GitHub")
    {
        Item login = session.CreateItem("login", title);
        var fields = login.Fields.Select(f => f.Kind switch
        {
            FieldKind.Totp => new FieldDraft(f.Id, f.Label, f.Kind, f.Concealed, Uri, f.Section, f.AgentVisible),
            FieldKind.Concealed => new FieldDraft(f.Id, f.Label, f.Kind, f.Concealed, "hunter2", f.Section, f.AgentVisible),
            _ when f.Label.Equals("username", StringComparison.OrdinalIgnoreCase) =>
                new FieldDraft(f.Id, f.Label, f.Kind, f.Concealed, "ada", f.Section, f.AgentVisible),
            _ => new FieldDraft(f.Id, f.Label, f.Kind, f.Concealed, f.Value ?? string.Empty, f.Section, f.AgentVisible),
        }).ToList();
        return session.SaveItem(new ItemDraft(
            login.Id, "login", title, fields, new[] { "work", "鍵" }, new[] { "https://github.com" }, "a note", login.Revision));
    }

    /// <summary>A scripted presence check: answers <see cref="Answer"/> and records every sentence it was asked to show.</summary>
    private sealed class ScriptedGate : IPresenceGate
    {
        internal ScriptedGate(PresenceOutcome answer)
        {
            Answer = answer;
        }

        internal PresenceOutcome Answer { get; }

        internal List<string> Reasons { get; } = new();

        public PresenceOutcome Confirm(string reason)
        {
            lock (Reasons)
            {
                Reasons.Add(reason);
            }

            return Answer;
        }
    }

    /// <summary>A session with a gate that always confirms, for tests about what a release carries.</summary>
    private static VaultSession Confirming(VaultSession session)
    {
        session.SetPresenceGate(new ScriptedGate(PresenceOutcome.Confirmed));
        return session;
    }

    /// <summary>Reveal one field through a release, the only way a concealed value leaves the vault.</summary>
    private static string Reveal(VaultSession session, string itemId, string fieldId)
    {
        using FieldRelease release = session.ReleaseField(itemId, fieldId, ReleasePurpose.Reveal);
        return release.Value();
    }

    // -------------------------------------------------------------------------------------------
    // Lifetime, constructors, errors
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void A_created_vault_unlocks_again_and_keeps_its_items()
    {
        using var temp = new TempVault();
        Assert.False(VaultSession.Exists(temp.Path));
        Item created;
        using (var session = temp.Create())
        {
            Assert.True(VaultSession.Exists(temp.Path));
            Assert.Equal(temp.Path, session.Path);
            Assert.Equal(UnlockKind.Password, session.UnlockedBy);
            created = session.CreateItem("login", "GitHub");
            Assert.Equal("GitHub", created.Title);
            Assert.Equal("login", created.Category);
            Assert.Equal("Login", created.CategoryDisplayName);
            Assert.False(created.Favorite);
            Assert.False(created.AgentVisible);
            Assert.NotEmpty(created.Fields);
            Assert.Equal(created, session.Item(created.Id));
            session.Save();
        }

        // A revision is keyed per session, so a reopened session's differs; everything else is equal.
        using var reopened = VaultSession.UnlockWithPassword(temp.Path, TempVault.Password);
        Assert.Equal(created with { Revision = string.Empty }, reopened.Item(created.Id) with { Revision = string.Empty });
    }

    [Fact]
    public void Non_ascii_text_survives_the_round_trip()
    {
        using var temp = new TempVault();
        using var session = temp.Create();

        var item = session.CreateItem("secure-note", "鍵 — ключ 🔑");

        Assert.Equal("鍵 — ключ 🔑", session.Item(item.Id).Title);
    }

    [Fact]
    public void A_password_held_in_a_clearable_buffer_unlocks_without_becoming_a_string()
    {
        using var temp = new TempVault();
        temp.Create().Dispose();
        char[] typed = TempVault.Password.ToCharArray();
        try
        {
            using var session = VaultSession.UnlockWithPassword(temp.Path, typed);
            Assert.False(session.IsDisposed);
        }
        finally
        {
            Array.Clear(typed);
        }
    }

    [Fact]
    public void Every_error_variant_this_surface_can_produce_arrives_typed_with_the_cores_message()
    {
        using var temp = new TempVault();

        Assert.Throws<KagisecureException.NotFound>(() => VaultSession.UnlockWithPassword(temp.Path, TempVault.Password));
        using var session = temp.Create();
        Assert.Throws<KagisecureException.AlreadyExists>(() => temp.Create());
        var wrong = Assert.Throws<KagisecureException.WrongCredential>(
            () => VaultSession.UnlockWithPassword(temp.Path, "not the password"));
        Assert.Equal("that did not unlock the vault", wrong.Message);
        Assert.Throws<KagisecureException.NotPresent>(() => session.Item(Guid.NewGuid().ToString()));
        Assert.Throws<KagisecureException.Invalid>(() => VaultSession.UnlockWithRecoveryCode(temp.Path, "not a code"));
    }

    [Fact]
    public void Dispose_locks_deterministically_and_a_locked_session_cannot_be_used()
    {
        using var temp = new TempVault();
        var session = temp.Create();
        string id = session.CreateItem("login", "GitHub").Id;

        session.Dispose();

        Assert.True(session.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => session.Item(id));
        Assert.Throws<ObjectDisposedException>(() => session.ExportVaultKeyForPlatformWrapping());
        Assert.Throws<ObjectDisposedException>(() => session.Path);
        session.Dispose(); // idempotent: no double free
    }

    [Fact]
    public void Two_sessions_on_one_file_are_independent_references()
    {
        using var temp = new TempVault();
        var first = temp.Create();
        using var second = VaultSession.UnlockWithPassword(temp.Path, TempVault.Password);

        string id = second.CreateItem("login", "GitHub").Id;
        first.Dispose();

        Assert.Equal("GitHub", second.Item(id).Title);
    }

    [Fact]
    public void VerifyMasterPassword_answers_for_the_session_in_memory_not_the_file_on_disk()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        Assert.True(session.VerifyMasterPassword(TempVault.Password).Verified);
        MasterPasswordCheck wrong = session.VerifyMasterPassword("wrong");
        Assert.Equal(MasterPasswordCheckKind.Wrong, wrong.Kind);
        Assert.Equal(TimeSpan.FromSeconds(1), wrong.RetryAfter);

        // Rate limited: until the back-off has passed, not even the right password is checked.
        Assert.Equal(MasterPasswordCheckKind.Throttled, session.VerifyMasterPassword(TempVault.Password).Kind);
        System.Threading.Thread.Sleep(wrong.RetryAfter + TimeSpan.FromMilliseconds(200));

        // Swap the file for another vault whose password "the attacker" knows.
        string other = System.IO.Path.Combine(temp.Directory, "other.kagivault");
        using (VaultSession.Create(other, "known to the attacker", "Personal", TempVault.KdfMKib, TempVault.KdfT))
        {
        }

        System.IO.File.Copy(other, temp.Path, overwrite: true);
        MasterPasswordCheck attacker = session.VerifyMasterPassword("known to the attacker");
        Assert.Equal(MasterPasswordCheckKind.Wrong, attacker.Kind);
        System.Threading.Thread.Sleep(attacker.RetryAfter + TimeSpan.FromMilliseconds(200));
        Assert.True(session.VerifyMasterPassword(TempVault.Password).Verified);
    }

    [Fact]
    public void PlatformSlotInfo_reads_the_vault_id_and_slot_in_one_go()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        PlatformSlotInfo none = VaultSession.PlatformSlotInfoOf(temp.Path);
        Assert.Equal(session.VaultFileId(), none.VaultId);
        Assert.Equal(16, none.VaultId.Length);
        Assert.Null(none.SlotId);
        Assert.Null(none.WrappedKey);

        session.InstallPlatformSlot("windows-hello-v2-test", "Hello", new byte[] { 0, 1, 0xFF });
        PlatformSlotInfo some = VaultSession.PlatformSlotInfoOf(temp.Path);
        Assert.Equal("windows-hello-v2-test", some.SlotId);
        Assert.Equal(new byte[] { 0, 1, 0xFF }, some.WrappedKey);
        Assert.Equal(none.VaultId, some.VaultId);
    }

    [Fact]
    public void The_default_path_is_a_vault_file_path()
    {
        string path = VaultSession.DefaultPath();
        Assert.False(string.IsNullOrWhiteSpace(path));
    }

    // -------------------------------------------------------------------------------------------
    // Credentials: recovery code, master password, and the platform slot Windows Hello uses
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void The_recovery_code_is_handed_out_once_and_unlocks_the_vault()
    {
        using var temp = new TempVault();
        string? code;
        using (var session = temp.Create())
        {
            code = session.TakeRecoveryCode();
            Assert.False(string.IsNullOrWhiteSpace(code));
            Assert.Null(session.TakeRecoveryCode());
        }

        using var recovered = VaultSession.UnlockWithRecoveryCode(temp.Path, code);
        Assert.Equal(UnlockKind.RecoveryCode, recovered.UnlockedBy);
        Assert.Null(recovered.TakeRecoveryCode());
    }

    [Fact]
    public void Changing_the_master_password_retires_the_old_one()
    {
        using var temp = new TempVault();
        using (var session = temp.Create())
        {
            char[] fresh = "a new master password".ToCharArray();
            session.ChangeMasterPassword(fresh);
            Array.Clear(fresh);
        }

        Assert.Throws<KagisecureException.WrongCredential>(
            () => VaultSession.UnlockWithPassword(temp.Path, TempVault.Password));
        using var reopened = VaultSession.UnlockWithPassword(temp.Path, "a new master password");
        Assert.Equal(UnlockKind.Password, reopened.UnlockedBy);
    }

    [Fact]
    public void The_vault_key_crosses_as_raw_bytes_in_both_directions()
    {
        using var temp = new TempVault();
        string id;
        byte[] key;
        using (var session = temp.Create())
        {
            id = session.CreateItem("login", "GitHub").Id;
            key = session.ExportVaultKeyForPlatformWrapping();
        }
        try
        {
            Assert.Equal(32, key.Length);

            // One flipped bit anywhere and the key no longer opens the vault, so a successful
            // unlock is a byte-exact round trip — no UTF-8 decoding, no NUL truncation.
            using (var session = VaultSession.UnlockWithVaultKey(temp.Path, key))
            {
                Assert.Equal("GitHub", session.Item(id).Title);
                Assert.Equal(UnlockKind.PlatformKey, session.UnlockedBy);
            }

            byte[] tampered = key.ToArray();
            tampered[^1] ^= 0x01;
            Assert.Throws<KagisecureException.WrongCredential>(() => VaultSession.UnlockWithVaultKey(temp.Path, tampered));

            // Bytes that are not UTF-8 and contain NULs are data, not text.
            byte[] notText = Enumerable.Range(0, 32).Select(i => (byte)(i % 2 == 0 ? 0x00 : 0xFF)).ToArray();
            Assert.Throws<KagisecureException.WrongCredential>(() => VaultSession.UnlockWithVaultKey(temp.Path, notText));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void A_platform_slot_round_trips_the_way_windows_hello_will_use_it()
    {
        using var temp = new TempVault();
        // A stand-in for the keystore's ciphertext: opaque bytes, NULs and all.
        byte[] wrapped = Enumerable.Range(0, 48).Select(i => (byte)(i * 37)).ToArray();
        using (var session = temp.Create())
        {
            Assert.False(session.HasPlatformSlot());
            Assert.Null(session.PlatformSlotId());
            Assert.Null(VaultSession.PlatformSlotIdOf(temp.Path));
            Assert.Null(VaultSession.PlatformWrappedKeyOf(temp.Path));
            Assert.Throws<KagisecureException.Invalid>(() => session.InstallPlatformSlot("hello-1", "Windows Hello", ReadOnlySpan<byte>.Empty));

            session.InstallPlatformSlot("hello-1", "Windows Hello", wrapped);

            Assert.True(session.HasPlatformSlot());
            Assert.Equal("hello-1", session.PlatformSlotId());
        }

        // Before any credential exists, the lock screen reads the header.
        Assert.Equal("hello-1", VaultSession.PlatformSlotIdOf(temp.Path));
        Assert.Equal(wrapped, VaultSession.PlatformWrappedKeyOf(temp.Path));

        using (var session = VaultSession.UnlockWithPassword(temp.Path, TempVault.Password))
        {
            Assert.True(session.RemovePlatformSlot());
            Assert.False(session.RemovePlatformSlot());
        }
        Assert.Null(VaultSession.PlatformSlotIdOf(temp.Path));
        Assert.Throws<KagisecureException.NotFound>(() => VaultSession.PlatformSlotIdOf(temp.Path + ".missing"));
        Assert.Throws<KagisecureException.NotFound>(() => VaultSession.PlatformWrappedKeyOf(temp.Path + ".missing"));
    }

    // -------------------------------------------------------------------------------------------
    // Items and fields
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void A_saved_draft_comes_back_whole_and_a_concealed_value_only_by_a_release()
    {
        using var temp = new TempVault();
        using var session = Confirming(temp.Create());

        Item saved = FilledLogin(session);

        Assert.Equal(new[] { "work", "鍵" }, saved.Tags);
        Assert.Equal(new[] { "https://github.com" }, saved.Urls);
        Assert.True(saved.HasNotes); // the note itself is a release, never on the item
        Assert.Equal("ada", saved.Subtitle);
        Assert.Equal("ada", saved.Username);
        Field password = saved.Fields.Single(f => f.Kind == FieldKind.Concealed);
        Assert.True(password.Concealed);
        Assert.True(password.HasValue);
        Assert.Null(password.Value);
        Assert.Equal(password, session.Field(saved.Id, password.Id));
        Assert.False(string.IsNullOrEmpty(saved.Revision));

        Assert.Equal("hunter2", Reveal(session, saved.Id, password.Id));
        using (FieldRelease release = session.ReleaseField(saved.Id, password.Id, ReleasePurpose.Copy))
        {
            byte[] utf8 = release.ValueUtf8();
            Assert.Equal("hunter2", Encoding.UTF8.GetString(utf8));
            CryptographicOperations.ZeroMemory(utf8);
            // A copy is one use.
            Assert.Throws<KagisecureException.ReleaseEnded>(() => release.ValueUtf8());
        }

        using (NotesRelease notes = session.ReleaseNotes(saved.Id, ReleasePurpose.Reveal))
        {
            Assert.Equal("a note", notes.Text());
        }

        Assert.Throws<KagisecureException.NotPresent>(() => session.ReleaseField(saved.Id, "no-such-field", ReleasePurpose.Reveal));
        Assert.Throws<KagisecureException.NotPresent>(() => session.Field(saved.Id, "no-such-field"));
    }

    [Fact]
    public void With_no_gate_or_a_refusing_one_nothing_is_released()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        Item saved = FilledLogin(session);
        Field password = saved.Fields.Single(f => f.Kind == FieldKind.Concealed);

        Assert.Throws<KagisecureException.NoPresenceGate>(() => session.ReleaseField(saved.Id, password.Id, ReleasePurpose.Reveal));
        Assert.Throws<KagisecureException.NoPresenceGate>(() => session.ReleaseNotes(saved.Id, ReleasePurpose.Reveal));
        Assert.Throws<KagisecureException.NoPresenceGate>(() => session.ReleaseTotp(saved.Id, null, ReleasePurpose.Reveal));

        var refusing = new ScriptedGate(PresenceOutcome.Cancelled);
        session.SetPresenceGate(refusing);
        // Once per session: a gate that always says yes cannot replace the first.
        Assert.Throws<KagisecureException.Invalid>(() => session.SetPresenceGate(new ScriptedGate(PresenceOutcome.Confirmed)));

        Assert.Throws<KagisecureException.PresenceCancelled>(() => session.ReleaseField(saved.Id, password.Id, ReleasePurpose.Reveal));
        string reason = Assert.Single(refusing.Reasons);
        Assert.Contains("GitHub", reason);
        Assert.Contains("Continue only if", reason);
    }

    [Fact]
    public void A_release_ends_when_the_vault_locks()
    {
        using var temp = new TempVault();
        using var session = Confirming(temp.Create());
        Item saved = FilledLogin(session);
        Field password = saved.Fields.Single(f => f.Kind == FieldKind.Concealed);

        using FieldRelease release = session.ReleaseField(saved.Id, password.Id, ReleasePurpose.Reveal);
        Assert.True(release.State().IsLive);
        Assert.True(session.IsUnlocked);

        session.Lock();

        Assert.False(session.IsUnlocked);
        Assert.ThrowsAny<KagisecureException>(() => release.Value());
        Assert.Throws<KagisecureException.VaultLocked>(() => session.Item(saved.Id));
    }

    [Fact]
    public void An_edit_that_sends_no_value_keeps_the_stored_secret_and_a_stale_one_is_refused()
    {
        using var temp = new TempVault();
        using var session = Confirming(temp.Create());
        Item saved = FilledLogin(session);
        Field password = saved.Fields.Single(f => f.Kind == FieldKind.Concealed);

        var fields = saved.Fields
            .Select(f => new FieldDraft(f.Id, f.Label, f.Kind, f.Concealed, f.Concealed ? null : f.Value, f.Section, f.AgentVisible))
            .ToList();
        var draft = new ItemDraft(saved.Id, "login", "GitHub (renamed)", fields, saved.Tags, saved.Urls, null, saved.Revision);
        Item renamed = session.SaveItem(draft);

        Assert.Equal("GitHub (renamed)", renamed.Title);
        Assert.True(renamed.HasNotes);
        Assert.Equal("hunter2", Reveal(session, saved.Id, password.Id));

        // The same draft again was read before the rename: refused, nothing written.
        Assert.Throws<KagisecureException.ItemChangedElsewhere>(() => session.SaveItem(draft));
    }

    [Fact]
    public void A_new_field_and_an_absent_note_cross_as_what_they_are()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        Item note = session.CreateItem("secure-note", "Wi-Fi");

        Item saved = session.SaveItem(new ItemDraft(
            note.Id,
            "secure-note",
            "Wi-Fi",
            new[] { new FieldDraft(null, "passphrase", FieldKind.Text, true, "s3cret\0with a NUL", "Router", false) },
            Array.Empty<string>(),
            Array.Empty<string>(),
            null,
            note.Revision));

        Field field = Assert.Single(saved.Fields);
        Assert.Equal(FieldKind.Concealed, field.Kind); // a concealed Text field is stored as Concealed
        Assert.Equal("Router", field.Section);
        Assert.False(saved.HasNotes);
        Assert.Empty(saved.Tags);
        session.SetPresenceGate(new ScriptedGate(PresenceOutcome.Confirmed));
        Assert.Equal("s3cret\0with a NUL", Reveal(session, saved.Id, field.Id));
    }

    [Fact]
    public void A_stored_totp_field_produces_the_same_code_the_preview_does()
    {
        using var temp = new TempVault();
        using var session = Confirming(temp.Create());
        Item login = FilledLogin(session);
        Field totp = login.Fields.Single(f => f.Kind == FieldKind.Totp);

        using TotpRelease named = session.ReleaseTotp(login.Id, totp.Id, ReleasePurpose.Reveal);
        TotpCode code = named.CodeAt(1_699_999_980);

        Assert.Equal(Totp.Preview(Uri, 1_699_999_980), code);
        Assert.Equal(30u, code.SecondsRemaining);
        Assert.Equal("ACME", code.Params.Issuer);
        using (TotpRelease first = session.ReleaseTotp(login.Id, null, ReleasePurpose.Reveal))
        {
            Assert.Equal(code, first.CodeAt(1_699_999_980));
        }

        Assert.Equal(Uri, Reveal(session, login.Id, totp.Id));

        Item bare = session.CreateItem("secure-note", "Notes");
        Assert.Throws<KagisecureException.NotPresent>(() => session.ReleaseTotp(bare.Id, null, ReleasePurpose.Reveal));
        Field password = login.Fields.Single(f => f.Kind == FieldKind.Concealed);
        Assert.Throws<KagisecureException.Invalid>(() => session.ReleaseTotp(login.Id, password.Id, ReleasePurpose.Reveal));
    }

    [Fact]
    public void Filters_search_and_sort_select_what_they_name()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        Item github = FilledLogin(session, "GitHub");
        Item gitlab = session.CreateItem("login", "GitLab");
        Item wifi = session.CreateItem("secure-note", "Wi-Fi");

        Assert.Equal(new[] { "GitHub", "GitLab", "Wi-Fi" }, session.ListItems(new ItemFilter.All()).Select(i => i.Title));
        Assert.Equal(2, session.ListItems(new ItemFilter.Category("login")).Count);
        Assert.Equal(github.Id, Assert.Single(session.ListItems(new ItemFilter.Tag("work"))).Id);
        Assert.Equal(new[] { "GitHub", "GitLab" }, session.ListItems(new ItemFilter.All(), "git").Select(i => i.Title));
        Assert.Equal(github.Id, Assert.Single(session.ListItems(new ItemFilter.All(), "github.com")).Id);
        Assert.Empty(session.ListItems(new ItemFilter.All(), "hunter2")); // never field values
        Assert.Equal(3, session.ListItems(new ItemFilter.All(), "   ").Count);
        Assert.Equal(new[] { "login", "login", "secure-note" }, session.ListItems(new ItemFilter.All(), null, ItemSort.Category).Select(i => i.Category));
        Assert.Equal(3, session.ListItems(new ItemFilter.All(), null, ItemSort.DateCreated).Count);
        Assert.Equal(3, session.ListItems(new ItemFilter.All(), null, ItemSort.DateModified).Count);

        Assert.True(session.SetFavorite(gitlab.Id, true).Favorite);
        Assert.True(session.SetArchived(wifi.Id, true).Archived);
        Assert.True(session.SetTrashed(github.Id, true).Trashed);

        Assert.Equal(gitlab.Id, Assert.Single(session.ListItems(new ItemFilter.Favorites())).Id);
        Assert.Equal(wifi.Id, Assert.Single(session.ListItems(new ItemFilter.Archive())).Id);
        Assert.Equal(github.Id, Assert.Single(session.ListItems(new ItemFilter.Trash())).Id);
        Assert.Equal(gitlab.Id, Assert.Single(session.ListItems(new ItemFilter.All())).Id);

        SidebarCounts counts = session.SidebarCounts();
        Assert.Equal((1u, 1u, 1u, 1u), (counts.All, counts.Favorites, counts.Archive, counts.Trash));
        Assert.Contains(new TagCount("login", 1), counts.Categories);
        Assert.Contains(counts.Categories, c => c.Name == "credit-card" && c.Count == 0);
        Assert.Empty(counts.Tags); // GitHub, the only tagged item, is in the trash

        Assert.False(session.SetTrashed(github.Id, false).Trashed);
        Assert.False(session.SetArchived(wifi.Id, false).Archived);
        Assert.False(session.SetFavorite(gitlab.Id, false).Favorite);
        Assert.Contains(new TagCount("work", 1), session.SidebarCounts().Tags);

        // Delete for good: only from the Trash, and only at the revision the Trash row showed.
        Assert.Throws<KagisecureException.Invalid>(() => session.DeleteItem(wifi.Id, session.Item(wifi.Id).Revision));
        string beforeTrash = session.Item(wifi.Id).Revision;
        Item trashed = session.SetTrashed(wifi.Id, true);
        Assert.Throws<KagisecureException.ItemChangedElsewhere>(() => session.DeleteItem(wifi.Id, beforeTrash));
        session.DeleteItem(wifi.Id, trashed.Revision);
        Assert.Throws<KagisecureException.NotPresent>(() => session.Item(wifi.Id));
        Assert.Throws<KagisecureException.NotPresent>(() => session.DeleteItem(wifi.Id, trashed.Revision));
    }

    [Fact]
    public void Agent_visibility_is_set_per_item_per_field_and_per_logical_vault()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        Item item = session.CreateItem("login", "GitHub");
        Field field = item.Fields[0];

        Assert.True(session.SetAgentVisible(item.Id, true).AgentVisible);
        Assert.True(session.SetFieldAgentVisible(item.Id, field.Id, true).Fields[0].AgentVisible);
        Item off = session.SetAgentVisible(item.Id, false);
        Assert.False(off.AgentVisible);
        Assert.All(off.Fields, f => Assert.False(f.AgentVisible));
        Assert.Throws<KagisecureException.NotPresent>(() => session.SetFieldAgentVisible(item.Id, "nope", true));

        LogicalVault vault = Assert.Single(session.Vaults());
        Assert.Equal("Personal", vault.Name);
        Assert.Equal(vault.Id, session.DefaultVaultId());
        Assert.Equal(1u, vault.ItemCount);
        Assert.False(vault.AgentVisible); // default-deny
        Assert.True(session.SetVaultAgentVisible(vault.Id, true));
        Assert.True(Assert.Single(session.Vaults()).AgentVisible);
        Assert.True(session.SetVaultAgentVisible(vault.Id, false));
        Assert.False(Assert.Single(session.Vaults()).AgentVisible);
        Assert.Throws<KagisecureException.NotPresent>(() => session.SetVaultAgentVisible("no-such-vault", true));

        Item placed = session.CreateItem("secure-note", "Placed", vault.Id);
        Assert.Equal(vault.Id, placed.VaultId);
        Assert.Throws<KagisecureException.NotPresent>(() => session.CreateItem("login", "Nowhere", "no-such-vault"));
    }

    // -------------------------------------------------------------------------------------------
    // Environments and audit
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void Environments_carry_names_and_bindings_never_values()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        Item login = FilledLogin(session);
        Field password = login.Fields.Single(f => f.Kind == FieldKind.Concealed);

        VaultEnvironment env = session.CreateEnvironment("Deploy", "production");
        Assert.Equal("production", env.Description);
        Assert.False(env.AgentVisible);
        Assert.Empty(env.Variables);
        Assert.Null(session.CreateEnvironment("Other").Description);
        Assert.Throws<KagisecureException.Invalid>(() => session.CreateEnvironment("   "));

        Assert.True(session.SetEnvironmentAgentVisible(env.Id, true).AgentVisible);
        char[] typed = "sk_live_123".ToCharArray();
        VaultEnvironment withLiteral = session.SetVariableValue(env.Id, "STRIPE_KEY", typed);
        Array.Clear(typed);
        EnvironmentVariable literal = Assert.Single(withLiteral.Variables);
        Assert.Equal(new EnvironmentVariable("STRIPE_KEY", VarBinding.Literal, null, null, true, null), literal);

        VaultEnvironment bound = session.BindVariable(env.Id, "GITHUB_PASSWORD", login.Id, password.Id);
        EnvironmentVariable reference = bound.Variables.Single(v => v.Name == "GITHUB_PASSWORD");
        Assert.Equal(VarBinding.ItemField, reference.Binding);
        Assert.Equal(login.Id, reference.ItemId);
        Assert.Equal(password.Id, reference.FieldId);
        Assert.Equal(new[] { "STRIPE_KEY", "GITHUB_PASSWORD" }, bound.VariableNames);
        Assert.Equal(0u, bound.PendingCount);
        Assert.Throws<KagisecureException.NotPresent>(() => session.BindVariable(env.Id, "X", login.Id, "no-such-field"));

        Assert.Equal(bound, session.Environment(env.Id));
        Assert.Equal(2, session.Environments().Count);
        Assert.Equal(new[] { "GITHUB_PASSWORD" }, session.RemoveVariable(env.Id, "STRIPE_KEY").VariableNames);

        session.DeleteEnvironment(env.Id);
        Assert.Throws<KagisecureException.NotPresent>(() => session.Environment(env.Id));
        Assert.Single(session.Environments());
    }

    [Fact]
    public void The_audit_log_pages_newest_first_and_verifies()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        session.CreateEnvironment("First");
        VaultEnvironment second = session.CreateEnvironment("Second");
        session.SetVariableValue(second.Id, "TOKEN", "x");

        uint count = session.AuditCount();
        Assert.True(count >= 3);
        var page = session.AuditPage(2, 0);
        Assert.Equal(2, page.Count);
        Assert.True(page[0].Seq > page[1].Seq);
        Assert.Equal("set_variable", page[0].Tool);
        Assert.Equal("app", page[0].Actor);
        Assert.Equal("allowed", page[0].Outcome);
        Assert.Equal(second.Id, page[0].EnvironmentId);
        Assert.Equal(new[] { "TOKEN" }, page[0].Variables);
        Assert.Equal((int)count, session.AuditPage(1000, 0).Count);
        Assert.Empty(session.AuditPage(10, count));
        Assert.True(session.AuditIntact());
        Assert.Equal(new AuditDurability(0, null), session.AuditDurability());
    }
}

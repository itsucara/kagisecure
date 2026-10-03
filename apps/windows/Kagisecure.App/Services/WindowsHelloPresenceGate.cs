using System;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Services;

/// <summary>
/// One confirmation prompt at a time, app-wide — the Windows counterpart of the macOS app's
/// <c>PresenceCoordinator</c> (ADR-0037 §3, ADR-0038 §6). A second request while one is up is
/// refused, never queued, so an automation agent cannot pile requests up behind a legitimate one.
/// Shared by the approval sheet's consent (<see cref="SerializedConsentGate"/>) and the release
/// gate (<see cref="WindowsHelloPresenceGate"/>).
/// </summary>
public sealed class PresencePromptGuard
{
    private readonly SemaphoreSlim slot = new(1, 1);

    /// <summary>Take the one prompt slot, or <c>false</c> at once if a prompt is already up.</summary>
    public bool TryEnter() => slot.Wait(0);

    /// <summary>Give the slot back.</summary>
    public void Exit() => slot.Release();
}

/// <summary>
/// The approval sheet's <see cref="IConsentGate"/>, serialized with every other confirmation the
/// app raises through a shared <see cref="PresencePromptGuard"/>.
/// </summary>
public sealed class SerializedConsentGate : IConsentGate
{
    private readonly IConsentGate inner;
    private readonly PresencePromptGuard guard;

    public SerializedConsentGate(IConsentGate inner, PresencePromptGuard guard)
    {
        this.inner = inner;
        this.guard = guard;
    }

    /// <inheritdoc />
    public async Task<ConsentOutcome> RequestAsync(string reason)
    {
        if (!guard.TryEnter())
        {
            return new ConsentOutcome(ConsentStatus.Failed, "Another confirmation is already in progress.");
        }

        try
        {
            return await inner.RequestAsync(reason).ConfigureAwait(true);
        }
        finally
        {
            guard.Exit();
        }
    }
}

/// <summary>Asks for the vault's master password, on the UI thread. <c>null</c> when the person cancels.</summary>
public interface IMasterPasswordPrompt
{
    /// <summary>Show <paramref name="reason"/> and ask; <paramref name="error"/> is the previous attempt's problem, if any.</summary>
    Task<string?> AskAsync(string reason, string? error);
}

/// <summary>
/// The presence gate every unlocked session gets (ADR-0038): Windows Hello
/// (<see cref="UserConsentVerifierInterop"/> through <see cref="WindowsHelloConsentGate"/>), and —
/// only when Hello reports itself unavailable — the vault's master password, checked by Rust on
/// the same session while the release waits (user decision 7).
/// </summary>
/// <remarks>
/// <para>
/// Rust calls <see cref="Confirm"/> on the thread-pool thread that asked for the release and
/// blocks it until the answer; the prompt itself runs on the UI thread. Called on the UI thread by
/// mistake, it refuses rather than deadlock.
/// </para>
/// <para>
/// Fail closed throughout: a cancelled, failed or busy Hello, a dismissed password dialog, an
/// exception, a UI thread that will not take the work — none of them is
/// <see cref="PresenceOutcome.Confirmed"/>. A Hello that is merely unavailable opens the password
/// fallback, never a silent grant. Every Hello call is a fresh verification: Windows Hello has no
/// reuse window to turn off, and none is added here.
/// </para>
/// <para>
/// Stated plainly (threat-model W-1, W-20): a Windows Hello verification is scoped to the user and
/// the device, not to this app, and Hello always accepts the account's PIN. It proves someone who
/// can sign in to this Windows account answered this app's prompt, which is weaker evidence of a
/// person than Touch ID is on a Mac.
/// </para>
/// </remarks>
public sealed class WindowsHelloPresenceGate : IPresenceGate
{
    private readonly VaultSession session;
    private readonly IConsentGate hello;
    private readonly PresencePromptGuard guard;
    private readonly DispatcherQueue ui;
    private readonly IMasterPasswordPrompt passwordPrompt;

    /// <param name="session">The session this gate is installed on — the one the password fallback checks against.</param>
    /// <param name="hello">Windows Hello, <b>not</b> serialized: this gate holds <paramref name="guard"/> itself for the whole prompt, fallback included.</param>
    /// <param name="guard">The app-wide one-prompt guard.</param>
    /// <param name="ui">The UI thread's queue.</param>
    /// <param name="passwordPrompt">The master-password fallback's dialog.</param>
    public WindowsHelloPresenceGate(
        VaultSession session, IConsentGate hello, PresencePromptGuard guard, DispatcherQueue ui, IMasterPasswordPrompt passwordPrompt)
    {
        this.session = session;
        this.hello = hello;
        this.guard = guard;
        this.ui = ui;
        this.passwordPrompt = passwordPrompt;
    }

    /// <inheritdoc />
    public PresenceOutcome Confirm(string reason)
    {
        if (ui.HasThreadAccess)
        {
            // Blocking the UI thread on a prompt the UI thread must show would never return.
            return PresenceOutcome.Cancelled;
        }

        if (!guard.TryEnter())
        {
            return PresenceOutcome.Busy;
        }

        try
        {
            var answer = new TaskCompletionSource<PresenceOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            bool queued = ui.TryEnqueue(async () =>
            {
                try
                {
                    answer.TrySetResult(await AskAsync(reason).ConfigureAwait(true));
                }
                catch (Exception)
                {
                    answer.TrySetResult(PresenceOutcome.Cancelled);
                }
            });
            return queued ? answer.Task.GetAwaiter().GetResult() : PresenceOutcome.Unavailable;
        }
        catch (Exception)
        {
            return PresenceOutcome.Cancelled;
        }
        finally
        {
            guard.Exit();
        }
    }

    private async Task<PresenceOutcome> AskAsync(string reason)
    {
        ConsentOutcome outcome = await hello.RequestAsync(reason).ConfigureAwait(true);
        return outcome.Status switch
        {
            ConsentStatus.Verified => PresenceOutcome.Confirmed,
            ConsentStatus.Unavailable => await MasterPasswordFallbackAsync(reason).ConfigureAwait(true),
            // Cancelled, and Failed (busy device, retries exhausted, an error): nothing granted.
            _ => PresenceOutcome.Cancelled,
        };
    }

    private async Task<PresenceOutcome> MasterPasswordFallbackAsync(string reason)
    {
        string? error = null;
        while (true)
        {
            string? password = await passwordPrompt.AskAsync(reason, error).ConfigureAwait(true);
            if (password is null)
            {
                return PresenceOutcome.Cancelled;
            }

            MasterPasswordCheck check;
            try
            {
                // Argon2id, off the UI thread. No vault lock is held while the release waits, so
                // this cannot deadlock against it; a right password marks that release as granted
                // by the master password in the audit log.
                check = await Task.Run(() => session.VerifyMasterPassword(password)).ConfigureAwait(true);
            }
            catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
            {
                return PresenceOutcome.Cancelled;
            }

            int seconds = Math.Max(1, (int)Math.Ceiling(check.RetryAfter.TotalSeconds));
            switch (check.Kind)
            {
                case MasterPasswordCheckKind.Verified:
                    return PresenceOutcome.Confirmed;
                case MasterPasswordCheckKind.Wrong:
                    error = $"Wrong password. Try again in {seconds} s.";
                    break;
                default:
                    error = $"Too many attempts. Try again in {seconds} s.";
                    break;
            }
        }
    }
}

/// <summary>
/// The master-password fallback's dialog: a <see cref="ContentDialog"/> over the main window, with
/// no default button (threat-model M-20: nothing confirms on a stray Enter).
/// </summary>
public sealed class ContentDialogMasterPasswordPrompt : IMasterPasswordPrompt
{
    private readonly Func<XamlRoot?> xamlRoot;

    public ContentDialogMasterPasswordPrompt(Func<XamlRoot?> xamlRoot)
    {
        this.xamlRoot = xamlRoot;
    }

    /// <inheritdoc />
    public async Task<string?> AskAsync(string reason, string? error)
    {
        XamlRoot? root = xamlRoot();
        if (root is null)
        {
            return null;
        }

        var password = new PasswordBox { PlaceholderText = "Master password" };
        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(new TextBlock
        {
            Text = "Windows Hello is not available, so confirm with this vault's master password.",
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(new TextBlock { Text = reason, TextWrapping = TextWrapping.Wrap });
        if (error is not null)
        {
            panel.Children.Add(new TextBlock { Text = error, TextWrapping = TextWrapping.Wrap });
        }

        panel.Children.Add(password);
        var dialog = new ContentDialog
        {
            Title = "Confirm it is you",
            Content = panel,
            PrimaryButtonText = "Confirm",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.None,
            XamlRoot = root,
        };
        ContentDialogResult result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary ? password.Password : null;
    }
}

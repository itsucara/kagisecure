using System;
using System.IO;

namespace Kagisecure.App.Services;

/// <summary>
/// Writes an unhandled exception's type, message and stack trace to
/// <c>%LOCALAPPDATA%\Kagisecure\logs</c> before the process goes down. Nothing else — never a
/// secret, never a field value; exceptions from this codebase don't carry either, and this class
/// doesn't inspect exception data beyond the standard <see cref="Exception"/> surface.
/// </summary>
public static class CrashLogger
{
    private static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kagisecure", "logs");

    /// <summary>Hook <see cref="AppDomain.UnhandledException"/> and <see cref="Microsoft.UI.Xaml.Application.UnhandledException"/> equivalents. Call once, as early as possible.</summary>
    public static void Install()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Write("AppDomain.UnhandledException", e.ExceptionObject as Exception, e.IsTerminating);

        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
            Write("TaskScheduler.UnobservedTaskException", e.Exception, isTerminating: false);
    }

    /// <summary>Write one crash record. Public so <see cref="App"/>'s XAML-level handler can call it too.</summary>
    public static void Write(string source, Exception? exception, bool isTerminating)
    {
        try
        {
            Directory.CreateDirectory(LogDirectory);
            string path = Path.Combine(LogDirectory, $"crash-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}.log");
            string body =
                $"{DateTime.UtcNow:O} UTC{Environment.NewLine}" +
                $"Source: {source}{Environment.NewLine}" +
                $"Terminating: {isTerminating}{Environment.NewLine}" +
                $"Exception: {exception?.GetType().FullName ?? "(none)"}{Environment.NewLine}" +
                $"Message: {exception?.Message}{Environment.NewLine}" +
                $"StackTrace:{Environment.NewLine}{exception?.StackTrace}{Environment.NewLine}" +
                $"InnerException: {exception?.InnerException}{Environment.NewLine}";
            File.WriteAllText(path, body);
        }
        catch (Exception)
        {
            // A crash handler that itself throws is worse than no crash handler; nothing to do
            // beyond swallowing it and letting the original crash proceed.
        }
    }
}

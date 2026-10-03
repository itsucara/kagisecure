using System;
using Microsoft.UI.Dispatching;

namespace Kagisecure.App.Services;

/// <summary>
/// How the agent host gets back onto the UI thread — the Swift app's hop to the main actor. A
/// seam so the host's tests can run everything inline.
/// </summary>
public interface IAgentDispatcher
{
    /// <summary>Run <paramref name="action"/> on the UI thread: inline when already there, queued otherwise. Never blocks.</summary>
    void Post(Action action);

    /// <summary>
    /// Call <paramref name="tick"/> on the UI thread every <paramref name="interval"/> until the
    /// returned handle is disposed. The one-second tick that drives countdowns, lease refreshes,
    /// <see cref="Kagisecure.Interop.Agent.TakeLockRequest"/> and the timeout sweep.
    /// </summary>
    IDisposable StartTimer(TimeSpan interval, Action tick);
}

/// <summary>The real <see cref="IAgentDispatcher"/>, over the window's <see cref="DispatcherQueue"/>.</summary>
public sealed class DispatcherQueueAgentDispatcher : IAgentDispatcher
{
    private readonly DispatcherQueue queue;

    public DispatcherQueueAgentDispatcher(DispatcherQueue queue)
    {
        this.queue = queue;
    }

    /// <inheritdoc />
    public void Post(Action action)
    {
        if (queue.HasThreadAccess)
        {
            action();
        }
        else
        {
            queue.TryEnqueue(() => action());
        }
    }

    /// <inheritdoc />
    public IDisposable StartTimer(TimeSpan interval, Action tick)
    {
        DispatcherQueueTimer timer = queue.CreateTimer();
        timer.Interval = interval;
        timer.IsRepeating = true;
        timer.Tick += (_, _) => tick();
        timer.Start();
        return new TimerHandle(timer);
    }

    private sealed class TimerHandle : IDisposable
    {
        private DispatcherQueueTimer? timer;

        public TimerHandle(DispatcherQueueTimer timer)
        {
            this.timer = timer;
        }

        public void Dispose()
        {
            timer?.Stop();
            timer = null;
        }
    }
}

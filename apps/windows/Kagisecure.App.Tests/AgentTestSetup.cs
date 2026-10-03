using System.Runtime.CompilerServices;
using System.Threading;

namespace Kagisecure.App.Tests;

/// <summary>
/// The agent-host tests run a real poll loop per test (a dedicated thread plus thread-pool
/// continuations) while xUnit runs test classes in parallel and the tests pump their fake
/// dispatcher by polling. With the default minimum, the pool can be starved long enough for a
/// delivery to miss its deadline; a higher floor keeps the tests about the host, not the pool.
/// </summary>
internal static class AgentTestSetup
{
    [ModuleInitializer]
    internal static void RaiseThreadPoolFloor()
    {
        ThreadPool.GetMinThreads(out int workers, out int io);
        ThreadPool.SetMinThreads(System.Math.Max(workers, 64), System.Math.Max(io, 64));
    }
}

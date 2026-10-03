using System;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Kagisecure.Interop.Tests;

/// <summary>
/// Just enough of the agent's IPC protocol to play an MCP sidecar: a named pipe carrying frames of
/// a <c>u32</c> little-endian length and that many bytes of UTF-8 JSON (kagisecure-ipc's
/// <c>frame.rs</c>). It exists so the approval queue can be driven end to end — a real request
/// arriving on the pipe, surfacing through <see cref="Agent.NextRequest"/>, and being answered by
/// <see cref="Agent.Resolve"/> — with no Rust test double in between.
/// </summary>
internal sealed class AgentPipeClient : IAsyncDisposable
{
    private readonly NamedPipeClientStream pipe;

    private AgentPipeClient(NamedPipeClientStream pipe)
    {
        this.pipe = pipe;
    }

    /// <summary>Connect to <paramref name="endpoint"/> (a pipe name, with or without <c>\\.\pipe\</c>) and say hello.</summary>
    internal static async Task<AgentPipeClient> ConnectAsync(string endpoint)
    {
        const string prefix = @"\\.\pipe\";
        string name = endpoint.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? endpoint[prefix.Length..] : endpoint;
        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5_000);
        var client = new AgentPipeClient(pipe);
        JsonElement hello = await client.RequestAsync(new
        {
            op = "Hello",
            protocol = 2, // kagisecure-ipc PROTOCOL_VERSION: the agent refuses any other at Hello
            client = new
            {
                name = "xunit",
                version = "1",
                pid = Environment.ProcessId,
                parent_pid = (int?)null,
                argv0 = "xunit",
                cwd = (string?)null,
            },
        });
        if (hello.GetProperty("reply").GetString() != "Hello")
        {
            throw new InvalidOperationException($"the agent refused the handshake: {hello}");
        }
        return client;
    }

    /// <summary>Send one request and wait for its reply.</summary>
    internal async Task<JsonElement> RequestAsync(object message, CancellationToken cancellationToken = default)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(message);
        byte[] prefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, (uint)body.Length);
        await pipe.WriteAsync(prefix, cancellationToken);
        await pipe.WriteAsync(body, cancellationToken);
        await pipe.FlushAsync(cancellationToken);

        await pipe.ReadExactlyAsync(prefix, cancellationToken);
        byte[] reply = new byte[BinaryPrimitives.ReadUInt32LittleEndian(prefix)];
        await pipe.ReadExactlyAsync(reply, cancellationToken);
        using JsonDocument document = JsonDocument.Parse(reply);
        return document.RootElement.Clone();
    }

    public ValueTask DisposeAsync() => pipe.DisposeAsync();
}

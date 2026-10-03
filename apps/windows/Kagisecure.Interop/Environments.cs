using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>Where one environment variable's value comes from.</summary>
public enum VarBinding : uint
{
    /// <summary>A value typed into the app and stored inline.</summary>
    Literal = (uint)KgsVarBinding.Literal,

    /// <summary>A reference into an item's field.</summary>
    ItemField = (uint)KgsVarBinding.ItemField,

    /// <summary>Declared by an agent and still waiting for the user to supply a value.</summary>
    Pending = (uint)KgsVarBinding.Pending,
}

/// <summary>One variable in an environment: its name and binding, never its value.</summary>
/// <param name="Name">Variable name, e.g. <c>"STRIPE_SECRET_KEY"</c>.</param>
/// <param name="Binding">Where the value comes from.</param>
/// <param name="ItemId">The item referenced, for <see cref="VarBinding.ItemField"/>.</param>
/// <param name="FieldId">The field referenced, for <see cref="VarBinding.ItemField"/>.</param>
/// <param name="Populated">Whether a value is available right now.</param>
/// <param name="Hint">The agent's explanation of what to paste, for a pending variable.</param>
public sealed record EnvironmentVariable(
    string Name,
    VarBinding Binding,
    string? ItemId,
    string? FieldId,
    bool Populated,
    string? Hint)
{
    internal static EnvironmentVariable From(in KgsEnvVarView n) => new(
        Str(n.name),
        (VarBinding)n.binding,
        Str(n.item_id),
        Str(n.field_id),
        n.populated != 0,
        Str(n.hint));
}

/// <summary>
/// An environment, for the "Agent access" section: names and bindings only, never values. Rust's
/// <c>EnvironmentView</c>; not called <c>Environment</c> so it does not collide with
/// <see cref="System.Environment"/>.
/// </summary>
/// <param name="Id">Identifier.</param>
/// <param name="Name">Display name.</param>
/// <param name="Description">Optional description.</param>
/// <param name="VariableNames">Variable names, in order.</param>
/// <param name="Variables">The variables in full, in order.</param>
/// <param name="PendingCount">How many are still waiting for a value.</param>
/// <param name="AgentVisible">Whether agents may see it.</param>
public sealed record VaultEnvironment(
    string Id,
    string Name,
    string? Description,
    ValueList<string> VariableNames,
    ValueList<EnvironmentVariable> Variables,
    uint PendingCount,
    bool AgentVisible)
{
    internal static unsafe VaultEnvironment From(in KgsEnvironmentView n) => new(
        Str(n.id),
        Str(n.name),
        Str(n.description),
        Strings(n.variable_names),
        List<KgsEnvVarView, EnvironmentVariable>(n.variables.ptr, n.variables.len, EnvironmentVariable.From),
        n.pending_count,
        n.agent_visible != 0);

    /// <summary>Copy the native environment out and free it, whatever happens.</summary>
    internal static unsafe VaultEnvironment Take(ref KgsEnvironmentView native)
    {
        try
        {
            return From(native);
        }
        finally
        {
            fixed (KgsEnvironmentView* p = &native)
            {
                NativeMethods.kgs_environment_view_free(p);
            }
        }
    }
}

/// <summary>One audit entry, for the audit viewer.</summary>
/// <param name="Seq">Position in the chain.</param>
/// <param name="Timestamp">Unix seconds.</param>
/// <param name="Actor"><c>"cli"</c>, <c>"app"</c> or <c>"mcp"</c>.</param>
/// <param name="Tool">The tool or subcommand.</param>
/// <param name="Outcome"><c>"allowed"</c>, <c>"denied"</c> or <c>"failed"</c>.</param>
/// <param name="EnvironmentId">Environment involved.</param>
/// <param name="ItemId">Item involved.</param>
/// <param name="Variables">Variable names.</param>
/// <param name="TargetPath">Target path involved.</param>
/// <param name="Detail">A short machine-readable reason.</param>
public sealed record AuditRow(
    ulong Seq,
    ulong Timestamp,
    string Actor,
    string Tool,
    string Outcome,
    string? EnvironmentId,
    string? ItemId,
    ValueList<string> Variables,
    string? TargetPath,
    string? Detail)
{
    internal static AuditRow From(in KgsAuditRow n) => new(
        n.seq,
        n.timestamp,
        Str(n.actor),
        Str(n.tool),
        Str(n.outcome),
        Str(n.environment_id),
        Str(n.item_id),
        Strings(n.variables),
        Str(n.target_path),
        Str(n.detail));
}

/// <summary>Whether the audit log on disk has caught up with what has been appended.</summary>
/// <param name="UnsavedEntries">Appended entries not yet saved; zero when the log on disk is complete.</param>
/// <param name="LastError">The most recent save failure, value-free, or <c>null</c> when none is outstanding.</param>
public sealed record AuditDurability(uint UnsavedEntries, string? LastError);

// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.Json;
using Komogentic.Server.Auth;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Komogentic.Server.Tools;

/// <summary>
/// A grant of <c>komodo:read</c> without <c>komodo:operate</c> (<see cref="RequestCaller.ReadOnly"/>) gets the four
/// read tools only: <c>tools/list</c> leaves out the others, and a call of one is refused, with an audit line.
/// </summary>
public static class ScopeFilter
{
    public const string ReadOnlyRefusal = "this connection was granted read-only access";

    public const string RefusedOutcome = "refused: read-only";

    public static readonly IReadOnlySet<string> OperateTools = new HashSet<string>(StringComparer.Ordinal) { StackTools.DeployName, StackTools.RestartName };

    public static McpRequestHandler<ListToolsRequestParams, ListToolsResult> List(McpRequestHandler<ListToolsRequestParams, ListToolsResult> next) =>
        async (request, ct) => Visible(await next(request, ct), ReadOnly(request.Services));

    public static McpRequestHandler<CallToolRequestParams, CallToolResult> Call(McpRequestHandler<CallToolRequestParams, CallToolResult> next) =>
        async (request, ct) =>
        {
            var matched = (request.MatchedPrimitive as McpServerTool)?.ProtocolTool.Name;
            var requested = request.Params?.Name;
            if (!Refused(matched, requested, ReadOnly(request.Services))) return await next(request, ct);

            var services = request.Services!;
            var stack = request.Params?.Arguments is { } args && args.TryGetValue("stack", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
            Audit.Log(services.GetRequiredService<ILoggerFactory>().CreateLogger(Audit.Category), services.GetRequiredService<RequestCaller>(),
                Audit.Text(matched ?? requested ?? "-"), stack is null ? null : Audit.Text(stack), RefusedOutcome);
            return Refusal();
        };

    internal static ListToolsResult Visible(ListToolsResult result, bool readOnly)
    {
        if (!readOnly) return result;
        result.Tools = [.. result.Tools.Where(t => !OperateTools.Contains(t.Name))];
        return result;
    }

    /// <summary>Fails closed: the tool the SDK matched and the name the request gives both count, and either one being
    /// an operate tool is enough.</summary>
    internal static bool Refused(string? matched, string? requested, bool readOnly) =>
        readOnly && ((matched is not null && OperateTools.Contains(matched)) || (requested is not null && OperateTools.Contains(requested)));

    internal static CallToolResult? Refusal(string tool, bool readOnly) => Refused(tool, null, readOnly) ? Refusal() : null;

    private static CallToolResult Refusal() => new() { IsError = true, Content = [new TextContentBlock { Text = ReadOnlyRefusal }] };

    /// <summary>Fails closed: a request without a caller has no business here (<see cref="RequestCaller.Current"/> throws).</summary>
    private static bool ReadOnly(IServiceProvider? services) =>
        (services ?? throw new InvalidOperationException("An MCP request without services")).GetRequiredService<RequestCaller>().ReadOnly;
}

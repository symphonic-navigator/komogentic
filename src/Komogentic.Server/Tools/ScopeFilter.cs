// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Auth;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Komogentic.Server.Tools;

/// <summary>
/// A grant of <c>komodo:read</c> without <c>komodo:operate</c> (<see cref="RequestCaller.ReadOnly"/>) gets the four
/// read tools only: <c>tools/list</c> leaves out the others, and a call of one is refused.
/// </summary>
public static class ScopeFilter
{
    public const string ReadOnlyRefusal = "this connection was granted read-only access";

    public static readonly IReadOnlySet<string> OperateTools = new HashSet<string>(StringComparer.Ordinal) { StackTools.DeployName, StackTools.RestartName };

    public static McpRequestHandler<ListToolsRequestParams, ListToolsResult> List(McpRequestHandler<ListToolsRequestParams, ListToolsResult> next) =>
        async (request, ct) => Visible(await next(request, ct), ReadOnly(request.Services));

    public static McpRequestHandler<CallToolRequestParams, CallToolResult> Call(McpRequestHandler<CallToolRequestParams, CallToolResult> next) =>
        async (request, ct) =>
            request.MatchedPrimitive is McpServerTool tool && Refusal(tool.ProtocolTool.Name, ReadOnly(request.Services)) is { } refusal
                ? refusal
                : await next(request, ct);

    internal static ListToolsResult Visible(ListToolsResult result, bool readOnly)
    {
        if (!readOnly) return result;
        result.Tools = [.. result.Tools.Where(t => !OperateTools.Contains(t.Name))];
        return result;
    }

    internal static CallToolResult? Refusal(string tool, bool readOnly) =>
        readOnly && OperateTools.Contains(tool)
            ? new CallToolResult { IsError = true, Content = [new TextContentBlock { Text = ReadOnlyRefusal }] }
            : null;

    /// <summary>Fails closed: a request without a caller has no business here (<see cref="RequestCaller.Current"/> throws).</summary>
    private static bool ReadOnly(IServiceProvider? services) =>
        (services ?? throw new InvalidOperationException("An MCP request without services")).GetRequiredService<RequestCaller>().ReadOnly;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Tools;
using ModelContextProtocol.Protocol;

namespace Komogentic.Server.Tests.Tools;

/// <summary>A grant of <c>komodo:read</c> alone sees and runs the four read tools only.</summary>
public sealed class ScopeFilterTests
{
    private static ListToolsResult All() => new()
    {
        Tools = [.. new[] { "list_stacks", "get_stack_status", "get_stack_logs", "list_stack_updates", "deploy_stack", "restart_stack" }
            .Select(n => new Tool { Name = n })],
    };

    [Fact]
    public void Read_only_list_has_no_operate_tools()
    {
        Assert.Equal(["list_stacks", "get_stack_status", "get_stack_logs", "list_stack_updates"], ScopeFilter.Visible(All(), readOnly: true).Tools.Select(t => t.Name));
        Assert.Equal(6, ScopeFilter.Visible(All(), readOnly: false).Tools.Count);
    }

    [Fact]
    public void Read_only_call_of_an_operate_tool_is_refused()
    {
        foreach (var tool in new[] { "deploy_stack", "restart_stack" })
        {
            var refusal = ScopeFilter.Refusal(tool, readOnly: true);
            Assert.NotNull(refusal);
            Assert.True(refusal.IsError);
            Assert.Equal("this connection was granted read-only access", Assert.IsType<TextContentBlock>(Assert.Single(refusal.Content)).Text);
            Assert.Null(ScopeFilter.Refusal(tool, readOnly: false));
        }

        Assert.Null(ScopeFilter.Refusal("list_stacks", readOnly: true));
    }

    [Fact]
    public void Refusal_reads_the_requested_name_too()
    {
        // Fails closed: without a matched tool, or with one that disagrees with the request, the request's name counts.
        Assert.True(ScopeFilter.Refused(null, "deploy_stack", readOnly: true));
        Assert.True(ScopeFilter.Refused("list_stacks", "restart_stack", readOnly: true));
        Assert.True(ScopeFilter.Refused("deploy_stack", null, readOnly: true));
        Assert.False(ScopeFilter.Refused(null, "deploy_stack", readOnly: false));
        Assert.False(ScopeFilter.Refused("list_stacks", "list_stacks", readOnly: true));
        Assert.False(ScopeFilter.Refused(null, null, readOnly: true));
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Komodo;
using Komogentic.Server.Tools;

namespace Komogentic.Server.Tests.Tools;

/// <summary>The green/yellow/red verdict (Decision 4): Komodo's StackState snake_case, StackServiceState PascalCase,
/// health only inside the container's Docker status.</summary>
public sealed class VerdictTests
{
    private static StackService Service(string state, string? status = "Up 5 minutes", string name = "web") =>
        new("stack-id", "app", name, "nginx:1", new ContainerListItem($"app-{name}-1", state.ToLowerInvariant(), status), null, state);

    private static StackService SwarmService(string state, string name = "web") =>
        new("stack-id", "app", name, "nginx:1", null, new SwarmServiceListItem("id", $"app_{name}", "nginx:1"), state);

    private static StackListItem Stack(string state, bool updateAvailable = false, bool projectMissing = false, string[]? missingFiles = null) =>
        new("stack-id", "app", new StackListItemInfo("server-1", "server-1", "", "", state, null,
            [new StackServiceWithUpdate("web", "nginx:1", null, updateAvailable)], projectMissing, missingFiles ?? []));

    [Fact]
    public void Running_and_healthy_is_green()
    {
        Assert.Equal(Colour.Green, Verdict.OfService(Service("Running", "Up 5 minutes (healthy)")).Colour);
        Assert.Equal(Colour.Green, Verdict.OfStack(Stack("running"), [Service("Running", "Up 5 minutes (healthy)")]).Colour);
    }

    [Fact]
    public void Running_without_healthcheck_is_green()
    {
        Assert.Equal(Colour.Green, Verdict.OfService(Service("Running", "Up 5 minutes")).Colour);
        Assert.Equal(Colour.Green, Verdict.OfService(Service("Running", null)).Colour);
    }

    [Fact]
    public void Health_starting_is_yellow()
    {
        Assert.Equal(Colour.Yellow, Verdict.OfService(Service("Running", "Up 3 seconds (health: starting)")).Colour);
        Assert.Equal(Colour.Yellow, Verdict.OfService(Service("Created", "Created")).Colour);
        var (colour, why) = Verdict.OfStack(Stack("running"), [Service("Running"), Service("Running", "Up 3 seconds (health: starting)", "api")]);
        Assert.Equal(Colour.Yellow, colour);
        Assert.Contains("api", why, StringComparison.Ordinal);
    }

    [Fact]
    public void Unhealthy_container_is_red()
    {
        Assert.Equal(Colour.Red, Verdict.OfService(Service("Running", "Up 5 minutes (unhealthy)")).Colour);
        var (colour, why) = Verdict.OfStack(Stack("running"), [Service("Running"), Service("Running", "Up 5 minutes (unhealthy)", "backend")]);
        Assert.Equal(Colour.Red, colour);
        Assert.Contains("backend", why, StringComparison.Ordinal);
    }

    [Fact]
    public void Restarting_service_is_red()
    {
        Assert.Equal(Colour.Red, Verdict.OfService(Service("Restarting", "Restarting (1) 2 seconds ago")).Colour);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("unhealthy"), [Service("Running"), Service("Restarting", "Restarting (1) 2 seconds ago", "backend")]).Colour);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("restarting"), [Service("Restarting", "Restarting (1) 2 seconds ago")]).Colour);
    }

    [Fact]
    public void Exited_zero_is_completed_not_red()
    {
        var migrate = Service("Exited", "Exited (0) 3 minutes ago", "migrate");
        Assert.True(Verdict.IsCompleted(migrate));
        Assert.Equal(Colour.Green, Verdict.OfStack(Stack("unhealthy"), [Service("Running"), migrate]).Colour);
    }

    [Fact]
    public void Exited_nonzero_is_red()
    {
        var crashed = Service("Exited", "Exited (1) 3 minutes ago", "backend");
        Assert.False(Verdict.IsCompleted(crashed));
        Assert.Equal(Colour.Red, Verdict.OfService(crashed).Colour);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("unhealthy"), [Service("Running"), crashed]).Colour);
    }

    [Fact]
    public void Deploying_stack_is_yellow()
    {
        Assert.Equal(Colour.Yellow, Verdict.OfStack(Stack("deploying"), null).Colour);
        Assert.Equal(Colour.Yellow, Verdict.OfStack(Stack("created"), null).Colour);
    }

    [Theory]
    [InlineData("down")]
    [InlineData("stopped")]
    [InlineData("paused")]
    [InlineData("dead")]
    [InlineData("removing")]
    [InlineData("unknown")]
    public void Down_stack_is_red(string state)
    {
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack(state), null).Colour);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack(state), [Service("Running")]).Colour);
    }

    [Fact]
    public void Update_available_keeps_the_colour()
    {
        Assert.Equal(Verdict.OfStack(Stack("running"), [Service("Running")]), Verdict.OfStack(Stack("running", updateAvailable: true), [Service("Running")]));
        Assert.Equal(Colour.Green, Verdict.OfStack(Stack("running", updateAvailable: true), [Service("Running")]).Colour);
    }

    [Fact]
    public void Swarm_healthy_is_green_and_unhealthy_red()
    {
        Assert.Equal(Colour.Green, Verdict.OfService(SwarmService("Healthy")).Colour);
        Assert.Equal(Colour.Red, Verdict.OfService(SwarmService("Unhealthy")).Colour);
        Assert.Equal(Colour.Red, Verdict.OfService(SwarmService("Down")).Colour);
    }

    [Theory]
    [InlineData("Dead")]
    [InlineData("Paused")]
    [InlineData("Stopping")]
    [InlineData("Removing")]
    [InlineData("Unknown")]
    [InlineData("SomethingNew")]
    public void Other_service_states_are_red(string state) =>
        Assert.Equal(Colour.Red, Verdict.OfService(Service(state, null)).Colour);

    [Fact]
    public void Running_without_services_is_red()
    {
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("running"), []).Colour);
        // Only completed one-shot services: nothing runs.
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("running"), [Service("Exited", "Exited (0) 1 minute ago")]).Colour);
    }

    [Fact]
    public void Ignored_services_do_not_count()
    {
        var init = Service("Exited", "Exited (1) 3 minutes ago", "init");
        var starting = Service("Running", "Up 3 seconds (health: starting)", "sidecar");

        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("running"), [Service("Running"), init]).Colour);
        Assert.Equal((Colour.Green, "every service is running"), Verdict.OfStack(Stack("running"), [Service("Running"), init, starting], ["init", "sidecar"]));
        Assert.Equal(Colour.Yellow, Verdict.OfStack(Stack("running"), [Service("Running"), init, starting], ["init"]).Colour);
    }

    [Fact]
    public void Missing_project_is_red_unless_down_or_deploying()
    {
        var (colour, why) = Verdict.OfStack(Stack("running", projectMissing: true), [Service("Running")]);
        Assert.Equal(Colour.Red, colour);
        Assert.Contains("compose project", why, StringComparison.Ordinal);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("unhealthy", projectMissing: true), [Service("Running")]).Colour);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("down", projectMissing: true), null).Colour);
        Assert.Equal("down: not deployed", Verdict.OfStack(Stack("down", projectMissing: true), null).Why);
        // As in Komodo's own UI: a first deploy has no project yet.
        Assert.Equal(Colour.Yellow, Verdict.OfStack(Stack("deploying", projectMissing: true), null).Colour);
    }

    [Fact]
    public void Missing_files_are_red()
    {
        var (colour, why) = Verdict.OfStack(Stack("running", missingFiles: ["compose.yaml", "compose.prod.yaml"]), [Service("Running")]);

        Assert.Equal(Colour.Red, colour);
        Assert.Equal("compose files missing: compose.yaml, compose.prod.yaml", why);
        Assert.Equal(Colour.Red, Verdict.OfStack(Stack("deploying", missingFiles: ["compose.yaml"]), null).Colour);
    }
}

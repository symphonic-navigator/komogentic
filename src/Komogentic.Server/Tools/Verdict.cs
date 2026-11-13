// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Komodo;

namespace Komogentic.Server.Tools;

/// <summary>Worst last: a stack is the worst of its services.</summary>
public enum Colour
{
    Green,
    Yellow,
    Red,
}

/// <summary>
/// Green, yellow or red in one word, with why (spec §4, Decision 4). Komodo's <c>StackState</c> is snake_case,
/// <c>StackServiceState</c> PascalCase (client/core/rs/src/entities/stack.rs), and a container's health shows only in
/// its Docker status ("Up 5 minutes (healthy)"). "Update available" never changes the colour. The stack's
/// <c>ignore_services</c> don't count, as in Komodo's own state; missing compose files, or a compose project missing
/// on the host while the stack should be up, are red whatever the services say.
/// </summary>
public static class Verdict
{
    public static (Colour Colour, string Why) OfStack(StackListItem stack, IReadOnlyList<StackService>? services, IReadOnlyCollection<string>? ignored = null)
    {
        // entities/stack.rs StackListItemInfo: "if there are paths here, this is an unhealthy state, and deploying will fail".
        if (stack.Info.MissingFiles.Count > 0) return (Colour.Red, "compose files missing: " + string.Join(", ", stack.Info.MissingFiles));
        // Komodo sets project_missing only off down and unknown; its UI ignores it while deploying, as a first deploy has none yet.
        if (stack.Info.ProjectMissing && stack.Info.State is not ("down" or "deploying"))
            return (Colour.Red, "its compose project is missing on the server (not in docker compose ls)");

        switch (stack.Info.State)
        {
            case "deploying":
                return (Colour.Yellow, "deploying");
            case "created":
                return (Colour.Yellow, "created, not started yet");
            case "restarting":
                // Komodo says so only when every container is in Docker's restart loop.
                return (Colour.Red, "every container is restarting");
            case "running" or "unhealthy":
                break;
            case "down":
                return (Colour.Red, "down: not deployed");
            case "unknown":
                return (Colour.Red, "unknown: Komodo can't reach its server");
            default:
                return (Colour.Red, stack.Info.State);
        }

        if (services is null) return (Colour.Yellow, "its services' health could not be read");
        var counted = services.Where(s => !IsCompleted(s) && !IsIgnored(s, ignored)).Select(s => (s.Service, Verdict: OfService(s))).ToList();
        if (counted.Count == 0) return (Colour.Red, "no service is running");
        var worst = counted.Max(c => c.Verdict.Colour);
        return worst == Colour.Green
            ? (Colour.Green, "every service is running")
            : (worst, string.Join("; ", counted.Where(c => c.Verdict.Colour == worst).Select(c => $"{c.Service}: {c.Verdict.Why}")));
    }

    /// <summary>A completed one-shot service (<see cref="IsCompleted"/>) is green here, and not counted in a stack.</summary>
    public static (Colour Colour, string Why) OfService(StackService service)
    {
        var status = service.Container?.Status ?? "";
        return service.State switch
        {
            "Running" when status.Contains("(unhealthy)", StringComparison.Ordinal) => (Colour.Red, "unhealthy"),
            "Running" when status.Contains("(health: starting)", StringComparison.Ordinal) => (Colour.Yellow, "health check starting"),
            "Running" => (Colour.Green, status.Contains("(healthy)", StringComparison.Ordinal) ? "running and healthy" : "running"),
            // Swarm: every task in its desired state.
            "Healthy" => (Colour.Green, "every task running"),
            "Created" => (Colour.Yellow, "created, not started yet"),
            "Exited" when IsCompleted(service) => (Colour.Green, "completed (exited with code 0)"),
            "Exited" => (Colour.Red, status.Length > 0 ? status : "exited"),
            "Restarting" => (Colour.Red, "restarting"),
            "Unhealthy" => (Colour.Red, "some tasks are not in their desired state"),
            "Down" => (Colour.Red, "every task is down"),
            "Dead" or "Paused" or "Stopping" or "Removing" => (Colour.Red, service.State.ToLowerInvariant()),
            _ => (Colour.Red, "state unknown"),
        };
    }

    /// <summary>One of the stack's <c>config.ignore_services</c>: Komodo leaves it out of the stack's state, and so does the verdict.</summary>
    public static bool IsIgnored(StackService service, IReadOnlyCollection<string>? ignored) => ignored?.Contains(service.Service) == true;

    /// <summary>A container that ran and exited with code 0: a migration or another one-shot job, done.</summary>
    public static bool IsCompleted(StackService service) =>
        service.State == "Exited" && (service.Container?.Status ?? "").StartsWith("Exited (0)", StringComparison.Ordinal);

    public static string Word(Colour colour) => colour switch
    {
        Colour.Green => "green",
        Colour.Yellow => "yellow",
        _ => "red",
    };
}

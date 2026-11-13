// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Komogentic.Server.Tools;

/// <summary>
/// The six stack tools (spec §4). Each calls Komodo as the caller (<see cref="RequestCaller.Komodo"/>), so Komodo's
/// permissions decide; Komogentic decides only which operations exist at all. Every failure is an <c>isError</c>
/// result with a sentence for the agent, and every call leaves one audit line (<see cref="Audit"/>).
/// </summary>
[McpServerToolType]
public sealed partial class StackTools(RequestCaller caller, KomodoClient komodo, ICredentialHealth health, TimeProvider time, ILoggerFactory logs)
{
    public const string DeployName = "deploy_stack";
    public const string RestartName = "restart_stack";

    /// <summary>Decision 5: the MCP TypeScript SDK's default request timeout is 60 s, and most clients keep it.</summary>
    public const int DefaultWaitSeconds = 50;

    public const string ServerInstructions =
        "Komogentic is a gateway to Komodo: it lists, inspects, reads the logs of, deploys and restarts Komodo stacks, always " +
        "with the Komodo account and rights of the person you work for. Start with list_stacks. A stack's verdict is one word: " +
        "green (running, every service up and not unhealthy), yellow (deploying, starting, or no health yet) or red (anything " +
        "else: down, stopped, exited, unhealthy, restarting in a loop, unknown); \"update available\" never changes the colour. " +
        "deploy_stack and restart_stack change running software, so confirm with the user first; they wait for Komodo's " +
        "update and report its outcome, or give an update id to follow with list_stack_updates.";

    /// <summary>How long to wait before the next <c>GetUpdate</c>: every 2 s for the first 30 s of the call, as most
    /// deploys end by then, then every 5 s.</summary>
    internal static TimeSpan PollDelay(TimeSpan elapsed) => elapsed < TimeSpan.FromSeconds(30) ? TimeSpan.FromSeconds(2) : TimeSpan.FromSeconds(5);

    private const int MaxLogLines = 5000;
    private const int MaxLogChars = 200_000;
    // docker compose's own complaints, not the services' logs: a share of their own, so that they can't push stdout out.
    private const int MaxStderrLines = 500;
    private const int MaxStderrChars = 20_000;
    private const int MaxUpdateLogChars = 20_000;
    private const int MaxParallel = 4;

    private ILogger AuditLog => logs.CreateLogger(Audit.Category);

    /// <summary>The stack's canonical name once <see cref="StackAsync"/> has found it, for the audit line. The SDK makes
    /// an instance per tool call.</summary>
    private string? _auditStack;

    [McpServerTool(Name = "list_stacks", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Every Komodo stack your user can see, one line each: name — server — state — verdict (green, yellow or red), " +
                 "and whether an image update is available; then a count per colour. \"Is everything green?\" is this tool.")]
    public Task<CallToolResult> ListStacks(CancellationToken ct = default) =>
        RunAsync("list_stacks", null, async () =>
        {
            var stacks = (await komodo.ListStacksAsync(caller.Komodo, ct)).OrderBy(s => s.Name, StringComparer.Ordinal).ToList();
            // Decision 8: "green" includes health, which only the services tell; which of them count, only GetStack.
            var services = new IReadOnlyList<StackService>?[stacks.Count];
            var ignored = new IReadOnlyList<string>?[stacks.Count];
            await Parallel.ForEachAsync(
                Enumerable.Range(0, stacks.Count).Where(i => stacks[i].Info.State is "running" or "unhealthy"),
                new ParallelOptions { MaxDegreeOfParallelism = MaxParallel, CancellationToken = ct },
                async (i, t) => (services[i], ignored[i]) = await HealthOrNullAsync(stacks[i], t));

            var text = new StringBuilder();
            if (stacks.Count == 0) text.AppendLine("Your Komodo user sees no stacks.");
            var counts = new int[3];
            for (var i = 0; i < stacks.Count; i++)
            {
                var (colour, _) = Verdict.OfStack(stacks[i], services[i], ignored[i]);
                counts[(int)colour]++;
                text.AppendLine($"{stacks[i].Name} — {Server(stacks[i])} — {stacks[i].Info.State} — {Verdict.Word(colour)}{UpdateNote(stacks[i])}");
            }

            text.Append($"{counts[0]} green, {counts[1]} yellow, {counts[2]} red");
            return Ok(text.ToString());
        });

    [McpServerTool(Name = "get_stack_status", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("One stack in detail: its verdict (green, yellow or red) and why, then each service's state, container status, " +
                 "health, image and whether an update is available. Where Komodo knows them, the image's version and short id " +
                 "show which build runs behind a tag such as :latest. Use it after list_stacks shows a stack that isn't green.")]
    public Task<CallToolResult> GetStackStatus(
        [Description("The stack's Komodo name (or id)")] string stack,
        CancellationToken ct = default) =>
        RunAsync("get_stack_status", stack, async () =>
        {
            var found = await StackAsync(stack, ct);
            var item = await komodo.FindStackAsync(caller.Komodo, found.Name, ct)
                ?? throw new ToolFailure(ToolErrors.NoSuchStack(ToolErrors.Shown(stack)), "no such stack");
            var services = await komodo.ListStackServicesAsync(caller.Komodo, found.Name, ct);
            var (colour, why) = Verdict.OfStack(item, services, found.IgnoreServices);
            var versions = await VersionsAsync(item, services, ct);

            var text = new StringBuilder($"{item.Name} — {Server(item)} — {item.Info.State} — {Verdict.Word(colour)}: {why}{UpdateNote(item)}");
            if (services.Count == 0) text.Append("\nKomodo lists no services for it.");
            foreach (var service in services)
            {
                var (serviceColour, serviceWhy) = Verdict.OfService(service);
                var status = service.Container?.Status is { Length: > 0 } s ? $" (\"{s}\")" : "";
                var update = item.Info.Services.FirstOrDefault(u => u.Service == service.Service) is { } u
                    ? (u.UpdateAvailable ? ", update available" : "")
                      + (u.LatestImage is { Length: > 0 } latest && latest != service.Image ? $", the compose file now names {latest}" : "")
                    : "";
                var counted = Verdict.IsIgnored(service, found.IgnoreServices) ? "ignored (in the stack's ignore_services), not counted"
                    : Verdict.IsCompleted(service) ? "completed, not counted"
                    : $"{Verdict.Word(serviceColour)}: {serviceWhy}";
                text.Append($"\n- {service.Service}: {service.State}{status}, health: {Health(service)}, image {service.Image}{ImageDetails(service, versions)}{update} — {counted}");
            }

            return Ok(text.ToString());
        });

    [McpServerTool(Name = "get_stack_logs", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Recent log lines of a stack, of all services or the ones named. With search, only the lines (of the last 5000) " +
                 "that contain any of the terms, or all of them with match_all; terms match literally and case-insensitively. " +
                 "A Swarm stack's logs come one service at a time, and Komodo 2.3.4 can't search a Swarm stack's logs: read " +
                 "its tail without search there. Long output is cut to its last 5000 lines and 200 000 characters, with a " +
                 "note. Needs the Logs permission on the stack in Komodo.")]
    public Task<CallToolResult> GetStackLogs(
        [Description("The stack's Komodo name (or id)")] string stack,
        [Description("Only these services (names as get_stack_status shows them); leave out for all")] string[]? services = null,
        [Description("How many of the last lines, 1 to 5000 (ignored with search)")] int tail = 200,
        [Description("Prefix each line with its timestamp")] bool timestamps = false,
        [Description("Search terms, e.g. [\"exception\"]: matching lines instead of the tail")] string[]? search = null,
        [Description("With search: a line must contain every term, not just one")] bool match_all = false,
        CancellationToken ct = default) =>
        RunAsync("get_stack_logs", stack, async () =>
        {
            if (tail is < 1 or > MaxLogLines) throw Invalid("tail must be between 1 and 5000");
            var terms = search ?? [];
            if (terms.Length > 20) throw Invalid("search takes at most 20 terms");
            if (terms.Any(t => t.Length is 0 or > 200 || t.Any(char.IsControl)))
                throw Invalid("each search term has 1 to 200 characters, without control characters");

            var found = await StackAsync(stack, ct);
            // komodo bin/core/src/api/read/stack.rs SearchStackLog passes the bare service name to the Swarm, which knows
            // the service as <stack>_<service> only (GetStackLog prefixes it): every Swarm search fails.
            if (found.SwarmId.Length > 0 && terms.Length > 0)
                throw new ToolFailure(
                    $"Komodo 2.3.4 can't search the logs of a Swarm service (stack {found.Name} runs in Swarm mode): call get_stack_logs without search, with one service and a tail, and look through those lines",
                    "swarm search unsupported");
            var chosen = await ServicesAsync(found, services, ct);
            // komodo bin/core/src/api/read/stack.rs: "Must pass single service for Swarm mode Stack logs".
            if (found.SwarmId.Length > 0 && chosen.Count != 1)
            {
                var all = (await komodo.ListStackServicesAsync(caller.Komodo, found.Name, ct)).Select(s => s.Service);
                throw new ToolFailure(
                    $"stack {found.Name} runs in Swarm mode, where Komodo gives the logs of exactly one service at a time: pass one in services (its services are {string.Join(", ", all)})",
                    "swarm needs one service");
            }

            KomodoLog log;
            try
            {
                log = terms.Length > 0
                    ? await komodo.SearchStackLogAsync(caller.Komodo, found.Name, chosen, [.. terms.Select(LogSearch.Pattern)], match_all, timestamps, ct)
                    : await komodo.GetStackLogAsync(caller.Komodo, found.Name, chosen, tail, timestamps, ct);
            }
            catch (KomodoException e) when (e.Kind == KomodoErrorKind.NotFoundOrForbidden)
            {
                // GetStack (Read) answered, so this is the Logs permission the log calls need on top.
                throw new ToolFailure(ToolErrors.NoLogs(found.Name), "no logs permission");
            }

            // grep exits 1 when no line matches, so Komodo's log of a search without a match fails, with nothing in it
            // (bin/periphery/src/api/compose.rs GetComposeLogSearch, lib/command/src/lib.rs output_into_log).
            if (terms.Length > 0 && !log.Success && string.IsNullOrWhiteSpace(log.Stdout) && string.IsNullOrWhiteSpace(log.Stderr))
                return Ok("(no line matches)");
            var text = LogOutput(log, terms.Length > 0);
            return log.Success ? Ok(text) : new ToolAnswer($"Komodo's log command failed on the server:\n{text}", true, "log command failed");
        });

    [McpServerTool(Name = "list_stack_updates", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("The last operations on a stack, newest first: update id — operation (DeployStack, RestartStack, …) — who " +
                 "started it — start and end (UTC) — succeeded, failed or in progress. Answers \"what was deployed when, and " +
                 "did it work?\". With update_id, that update's logs: each stage with its command, stdout and stderr.")]
    public Task<CallToolResult> ListStackUpdates(
        [Description("The stack's Komodo name (or id)")] string stack,
        [Description("How many updates, 1 to 50")] int limit = 10,
        [Description("An update id from this list or from deploy_stack/restart_stack: show its logs")] string? update_id = null,
        CancellationToken ct = default) =>
        RunAsync("list_stack_updates", stack, async () =>
        {
            if (limit is < 1 or > 50) throw Invalid("limit must be between 1 and 50");
            var found = await StackAsync(stack, ct);
            if (update_id is not null) return Ok(UpdateText(found, await UpdateOfAsync(found, update_id, ct)));

            var items = (await komodo.ListUpdatesAsync(caller.Komodo, found.Id, ct)).Take(limit).ToList();
            if (items.Count == 0) return Ok($"stack {found.Name} has no updates yet");
            // amendment R8: the list items carry no end time.
            var ends = new long?[items.Count];
            var unread = new bool[items.Count];
            await Parallel.ForEachAsync(
                Enumerable.Range(0, items.Count),
                new ParallelOptions { MaxDegreeOfParallelism = MaxParallel, CancellationToken = ct },
                async (i, t) =>
                {
                    try
                    {
                        ends[i] = (await komodo.GetUpdateAsync(caller.Komodo, items[i].Id, t)).EndTs;
                    }
                    catch (KomodoException e) when (e.Kind != KomodoErrorKind.Unauthorized)
                    {
                        // One update that can't be read costs its end time, not the list.
                        unread[i] = true;
                    }
                });

            var text = new StringBuilder($"The last {items.Count} updates of stack {found.Name}, newest first:");
            for (var i = 0; i < items.Count; i++)
            {
                var u = items[i];
                var end = ends[i] is { } e ? $"ended {ToolText.Time(e)}" : unread[i] || u.Status == "Complete" ? "end unknown" : "not ended";
                text.Append($"\n{u.Id} — {u.Operation} — {u.Username} — started {ToolText.Time(u.StartTs)} — {end} — {Outcome(u.Status, u.Success)}");
            }

            return Ok(text.ToString());
        });

    [McpServerTool(Name = DeployName, ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Deploys a stack, or the named services of it: Komodo pulls its images (and its repository, if it has one) and " +
                 "brings it up. Waits for Komodo's update up to wait_seconds, then reports success with the new verdict and the " +
                 "end of the update's log, or failure with the failing log; if it is still running then, its update id for " +
                 "list_stack_updates. Changes running software: confirm with the user first. Needs Execute on the stack.")]
    public Task<CallToolResult> DeployStack(
        [Description("The stack's Komodo name (or id)")] string stack,
        [Description("Only these services; leave out for the whole stack")] string[]? services = null,
        [Description("How long to wait for the outcome, 5 to 600 seconds")] int wait_seconds = DefaultWaitSeconds,
        CancellationToken ct = default) =>
        RunAsync(DeployName, stack, () => ExecuteAsync("deploy", stack, services, wait_seconds, ct));

    [McpServerTool(Name = RestartName, ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Restarts a stack's containers, or those of the named services, without pulling anything new. Waits and " +
                 "reports like deploy_stack. Changes running software: confirm with the user first. Needs Execute on the stack.")]
    public Task<CallToolResult> RestartStack(
        [Description("The stack's Komodo name (or id)")] string stack,
        [Description("Only these services; leave out for the whole stack")] string[]? services = null,
        [Description("How long to wait for the outcome, 5 to 600 seconds")] int wait_seconds = DefaultWaitSeconds,
        CancellationToken ct = default) =>
        RunAsync(RestartName, stack, () => ExecuteAsync("restart", stack, services, wait_seconds, ct));

    /// <summary>
    /// Deploy or restart, then wait for the update (amendment R9): one deadline, <paramref name="waitSeconds"/> from the
    /// start of the call, cancels every Komodo request in it, and the answer is then "still running" with the update id,
    /// or that Komodo did not answer in time if there is none yet. Once the update id is known, a failing poll never
    /// loses it: the next poll may answer, and if none does, the answer is still the id, not an error that invites a
    /// second deploy.
    /// </summary>
    private async Task<ToolAnswer> ExecuteAsync(string verb, string stack, string[]? services, int waitSeconds, CancellationToken ct)
    {
        if (waitSeconds is < 5 or > 600) throw Invalid("wait_seconds must be between 5 and 600");
        var started = time.GetTimestamp();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(waitSeconds), time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, deadline.Token);
        var token = linked.Token;
        string? updateId = null;
        var lastPollFailed = false;
        try
        {
            // GetStack first: Komodo accepts the execution of a stack the user may not even read, and fails it only later.
            var found = await StackAsync(stack, token);
            var chosen = await ServicesAsync(found, services, token);
            Update update;
            try
            {
                update = verb == "deploy"
                    ? await komodo.DeployStackAsync(caller.Komodo, found.Name, chosen, token)
                    : await komodo.RestartStackAsync(caller.Komodo, found.Name, chosen, token);
            }
            catch (KomodoException e) when (e.Kind == KomodoErrorKind.NotFoundOrForbidden)
            {
                // GetStack (Read) answered, so this is the Execute permission the execution needs on top.
                throw new ToolFailure(ToolErrors.NoExecute(found.Name), "no execute permission");
            }

            updateId = update.Id;
            while (update.Status != "Complete")
            {
                await Task.Delay(PollDelay(time.GetElapsedTime(started)), time, token);
                try
                {
                    update = await komodo.GetUpdateAsync(caller.Komodo, updateId, token);
                    lastPollFailed = false;
                }
                catch (KomodoException e) when (e.Kind == KomodoErrorKind.Unauthorized)
                {
                    var rejected = await KomodoFailureAsync(e, stack);
                    return rejected with { Text = $"{rejected.Text} The {verb} was started as update {updateId}; follow it in Komodo." };
                }
                catch (KomodoException)
                {
                    lastPollFailed = true;
                }
            }

            var seconds = update.EndTs is { } end ? (end - update.StartTs) / 1000.0 : time.GetElapsedTime(started).TotalSeconds;
            var took = Math.Round(Math.Max(0, seconds)).ToString(CultureInfo.InvariantCulture);
            if (!update.Success)
            {
                // Decision 7: a missing Execute permission is a task that failed with this log.
                if (update.Logs.Any(l => l.Stage == "Task Error" && (l.Stderr + l.Stdout).Contains("does not have required permissions", StringComparison.Ordinal)))
                    return new ToolAnswer(ToolErrors.NoExecute(found.Name), true, "no execute permission");
                var failing = update.Logs.Where(l => !l.Success).ToList();
                return new ToolAnswer($"{verb} failed after {took} s; update id {update.Id}\n\n{LogsText(failing.Count > 0 ? failing : update.Logs)}", true, "failed");
            }

            var verdict = await VerdictAfterAsync(found, token, ct);
            var (tailText, _) = ToolText.Tail(string.Join('\n', update.Logs.Select(l => (l.Stdout + "\n" + l.Stderr).Trim('\n')).Where(t => t.Length > 0)), 40, MaxUpdateLogChars);
            var text = $"{verb} succeeded in {took} s; {verdict}";
            if (tailText.Length > 0) text += $"\n\nThe end of update {update.Id}'s log:\n{tailText}";
            return new ToolAnswer(text, false, "succeeded");
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return updateId is null
                ? new ToolAnswer(
                    $"Komodo did not answer within {waitSeconds} s; the {verb} may or may not have started: check with list_stack_updates", true,
                    "komodo did not answer in time")
                : new ToolAnswer(
                    $"still running{(lastPollFailed ? " (or unknown)" : "")} after {waitSeconds} s; update id {updateId} — follow it with list_stack_updates", false,
                    lastPollFailed ? "still running or unknown" : "still running");
        }
    }

    /// <summary>The stack's verdict after a successful update, within the same deadline.</summary>
    private async Task<string> VerdictAfterAsync(StackRef stack, CancellationToken token, CancellationToken ct)
    {
        try
        {
            if (await komodo.FindStackAsync(caller.Komodo, stack.Name, token) is not { } item) return $"{stack.Name}'s state could not be read";
            var services = item.Info.State is "running" or "unhealthy" ? await komodo.ListStackServicesAsync(caller.Komodo, stack.Name, token) : null;
            var (colour, why) = Verdict.OfStack(item, services, stack.IgnoreServices);
            return colour == Colour.Green ? $"{stack.Name} is green" : $"{stack.Name} is {Verdict.Word(colour)} ({why})";
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return $"{stack.Name}'s state could not be read in time";
        }
        catch (KomodoException e) when (e.Kind != KomodoErrorKind.Unauthorized)
        {
            return $"{stack.Name}'s state could not be read";
        }
    }

    /// <summary>The stack by name or id (Komodo's <c>GetStack</c> takes either), canonical; unknown and invisible alike.</summary>
    private async Task<StackRef> StackAsync(string? stack, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(stack)) throw Invalid("stack is required: a Komodo stack's name or id");
        try
        {
            var found = await komodo.GetStackAsync(caller.Komodo, stack, ct);
            _auditStack = Audit.Text(found.Name);
            return found;
        }
        catch (KomodoException e) when (e.Kind == KomodoErrorKind.NotFoundOrForbidden)
        {
            throw new ToolFailure(ToolErrors.NoSuchStack(ToolErrors.Shown(stack)), "no such stack");
        }
    }

    /// <summary>Amendment R4: each named service is a plain name and one of the stack's, before Komodo runs anything with it.</summary>
    private async Task<IReadOnlyList<string>> ServicesAsync(StackRef stack, string[]? services, CancellationToken ct)
    {
        if (services is null or []) return [];
        if (services.FirstOrDefault(s => s.Length > 128 || !ServiceName().IsMatch(s)) is { } malformed)
            throw Invalid($"not a service name: {ToolErrors.Shown(malformed)} (a service name has letters, digits, '_', '.' and '-', and starts with a letter or digit)");
        var known = (await komodo.ListStackServicesAsync(caller.Komodo, stack.Name, ct)).Select(s => s.Service).ToList();
        if (services.FirstOrDefault(s => !known.Contains(s, StringComparer.Ordinal)) is { } unknown)
        {
            var list = known.Count == 0 ? "Komodo lists none" : "its services are " + string.Join(", ", known);
            throw new ToolFailure($"stack {stack.Name} has no service {unknown}; {list}", "unknown service");
        }

        return [.. services.Distinct(StringComparer.Ordinal)];
    }

    /// <summary>A listed stack's services and the ones it ignores (GetStack by id), or nulls if Komodo won't say.</summary>
    private async Task<(IReadOnlyList<StackService>? Services, IReadOnlyList<string>? Ignored)> HealthOrNullAsync(StackListItem stack, CancellationToken ct)
    {
        try
        {
            var found = await komodo.GetStackAsync(caller.Komodo, stack.Id, ct);
            return (await komodo.ListStackServicesAsync(caller.Komodo, stack.Name, ct), found.IgnoreServices);
        }
        catch (KomodoException e) when (e.Kind == KomodoErrorKind.NotFoundOrForbidden)
        {
            return (null, null);
        }
    }

    /// <summary>Amendment R3: only an update whose target is this stack; any other is answered as if it didn't exist.</summary>
    private async Task<Update> UpdateOfAsync(StackRef stack, string id, CancellationToken ct)
    {
        var none = new ToolFailure($"no update {ToolErrors.Shown(id)} of stack {stack.Name}", "no such update");
        Update update;
        try
        {
            update = await komodo.GetUpdateAsync(caller.Komodo, id.Trim(), ct);
        }
        catch (KomodoException e) when (e.Kind == KomodoErrorKind.NotFoundOrForbidden)
        {
            throw none;
        }

        return update.Target is { Type: "Stack" } target && target.Id == stack.Id ? update : throw none;
    }

    private static string UpdateText(StackRef stack, Update u)
    {
        var end = u.EndTs is { } e ? $"ended {ToolText.Time(e)}" : "not ended";
        return $"update {u.Id} of stack {stack.Name}: {u.Operation}, started {ToolText.Time(u.StartTs)}, {end}, {Outcome(u.Status, u.Success)}\n\n{LogsText(u.Logs)}";
    }

    /// <summary>A log tool's answer: stdout cut to its last 5000 lines and 200 000 characters, then stderr cut on its
    /// own to its last 500 lines and 20 000, each with a note when cut.</summary>
    private static string LogOutput(KomodoLog log, bool search)
    {
        var (stdout, stdoutTrimmed) = ToolText.Tail(log.Stdout.TrimEnd('\n'), MaxLogLines, MaxLogChars);
        var (stderr, stderrTrimmed) = ToolText.Tail(log.Stderr.TrimEnd('\n'), MaxStderrLines, MaxStderrChars);
        if (stdout.Length == 0 && stderr.Length == 0) return search ? "(no line matches)" : "(no log lines)";

        var text = new StringBuilder();
        if (stdoutTrimmed) text.Append($"[trimmed to the last {Lines(stdout)} lines, at most 5000 lines and 200 000 characters]\n");
        text.Append(stdout);
        if (stderr.Length == 0) return text.ToString();
        if (text.Length > 0) text.Append('\n');
        text.Append("--- stderr ---\n");
        if (stderrTrimmed) text.Append($"[stderr trimmed to its last {Lines(stderr)} lines, at most 500 lines and 20 000 characters]\n");
        return text.Append(stderr).ToString();

        static int Lines(string s) => s.Count(c => c == '\n') + 1;
    }

    /// <summary>Each log's stage, command, stdout and stderr, each log cut to its last 20 000 characters.</summary>
    private static string LogsText(IEnumerable<KomodoLog> logs)
    {
        var text = new StringBuilder();
        foreach (var log in logs)
        {
            var body = new StringBuilder();
            if (log.Stdout.Length > 0) body.Append("stdout:\n").Append(log.Stdout.TrimEnd('\n')).Append('\n');
            if (log.Stderr.Length > 0) body.Append("stderr:\n").Append(log.Stderr.TrimEnd('\n')).Append('\n');
            var (shown, trimmed) = ToolText.Tail(body.ToString(), int.MaxValue, MaxUpdateLogChars);
            text.Append($"## {log.Stage} ({(log.Success ? "ok" : "failed")})\n");
            if (log.Command.Length > 0) text.Append($"command: {log.Command}\n");
            if (trimmed) text.Append("[trimmed to its last 20 000 characters]\n");
            text.Append(shown).Append('\n');
        }

        return text.Length == 0 ? "(no logs)" : text.ToString().TrimEnd('\n');
    }

    /// <summary>
    /// Best effort: the version of each image the stack's containers run, by image id. InspectImage needs Read on the
    /// server, which a user with rights on the stack alone lacks, so any failure only leaves the version out. A Swarm
    /// stack's tasks run on nodes Komodo doesn't name here: there is no one server to ask.
    /// </summary>
    private async Task<IReadOnlyDictionary<string, string>> VersionsAsync(StackListItem stack, IReadOnlyList<StackService> services, CancellationToken ct)
    {
        var versions = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        if (stack.Info.SwarmId.Length > 0 || stack.Info.ServerId.Length == 0) return versions;
        var ids = services.Select(s => s.Container?.ImageId).OfType<string>().Where(id => ShortImageId(id) is not null).Distinct(StringComparer.Ordinal);
        await Parallel.ForEachAsync(ids, new ParallelOptions { MaxDegreeOfParallelism = MaxParallel, CancellationToken = ct }, async (id, t) =>
        {
            try
            {
                if (Version(await komodo.InspectImageVersionAsync(caller.Komodo, stack.Info.ServerId, id, t)) is { } version) versions[id] = version;
            }
            catch (KomodoException)
            {
            }
        });
        return versions;
    }

    /// <summary>" (version 1.2.3, id 0123456789ab)", either part only, or nothing.</summary>
    private static string ImageDetails(StackService service, IReadOnlyDictionary<string, string> versions)
    {
        var id = service.Container?.ImageId;
        var parts = new List<string>(2);
        if (id is not null && versions.TryGetValue(id, out var version)) parts.Add($"version {version}");
        if (ShortImageId(id) is { } shortId) parts.Add($"id {shortId}");
        return parts.Count == 0 ? "" : $" ({string.Join(", ", parts)})";
    }

    /// <summary>Docker's short form, the first 12 hex digits of <c>sha256:…</c>; null for anything else.</summary>
    private static string? ShortImageId(string? id) =>
        id is not null && ImageId().IsMatch(id) ? id["sha256:".Length..("sha256:".Length + 12)] : null;

    /// <summary>A label is whatever the image's author wrote: only a short, version-like one reaches the agent.</summary>
    private static string? Version(string? label) => label?.Trim() is { } v && VersionText().IsMatch(v) ? v : null;

    private static string Outcome(string status, bool success) => status != "Complete" ? "in progress" : success ? "succeeded" : "failed";

    private static string Server(StackListItem stack) => stack.Info.SwarmId.Length > 0 ? $"swarm {stack.Info.SwarmName}" : stack.Info.ServerName;

    private static string UpdateNote(StackListItem stack) => stack.Info.Services.Any(s => s.UpdateAvailable) ? ", update available" : "";

    private static string Health(StackService service)
    {
        if (service.Container is not { } container) return service.SwarmService is null ? "unknown" : "per Swarm task";
        var status = container.Status ?? "";
        return status.Contains("(unhealthy)", StringComparison.Ordinal) ? "unhealthy"
            : status.Contains("(health: starting)", StringComparison.Ordinal) ? "starting"
            : status.Contains("(healthy)", StringComparison.Ordinal) ? "healthy"
            : "no health check";
    }

    private static ToolFailure Invalid(string message) => new(message, "invalid arguments");

    private static ToolAnswer Ok(string text) => new(text, false, "ok");

    /// <summary>Runs a tool body: its refusals and Komodo's failures become error results, and the call leaves exactly
    /// one audit line however it ends: cancelled by the agent, or with an exception nobody expected.</summary>
    private async Task<CallToolResult> RunAsync(string tool, string? stack, Func<Task<ToolAnswer>> body)
    {
        var outcome = "error";
        try
        {
            ToolAnswer answer;
            try
            {
                answer = await body();
            }
            catch (ToolFailure f)
            {
                answer = new ToolAnswer(f.Message, true, f.Outcome);
            }
            catch (KomodoException e)
            {
                answer = await KomodoFailureAsync(e, stack);
            }

            outcome = answer.Outcome;
            return new CallToolResult { IsError = answer.IsError, Content = [new TextContentBlock { Text = answer.Text }] };
        }
        catch (OperationCanceledException)
        {
            outcome = "cancelled";
            throw;
        }
        finally
        {
            Audit.Log(AuditLog, caller, tool, _auditStack ?? (stack is null ? null : Audit.Text(stack)), outcome);
        }
    }

    private async Task<ToolAnswer> KomodoFailureAsync(KomodoException e, string? stack)
    {
        switch (e.Kind)
        {
            case KomodoErrorKind.Unauthorized:
                // Not the request's token: the credential must be marked even if the agent hangs up now.
                if (caller.Komodo is KomodoAuth.Key key) await health.KomodoKeyRejectedAsync(caller, key.ApiKey, CancellationToken.None);
                return new ToolAnswer(ToolErrors.KomodoKeyRejected, true, "komodo key rejected");
            case KomodoErrorKind.RateLimited:
                // Komodo's limiter counts every failure from Komogentic's address: never a reason to give up the key.
                return new ToolAnswer(e.Message, true, "komodo rate limited");
            case KomodoErrorKind.Unreachable:
                return new ToolAnswer(ToolErrors.KomodoUnreachable, true, "komodo unreachable");
            case KomodoErrorKind.NotFoundOrForbidden:
                return new ToolAnswer(ToolErrors.NoSuchStack(ToolErrors.Shown(stack ?? "")), true, "no such stack");
            default:
                return new ToolAnswer($"Komodo refused this: {e.Message}", true, "komodo error");
        }
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
    private static partial Regex ServiceName();

    [GeneratedRegex("^sha256:[0-9a-f]{64}$")]
    private static partial Regex ImageId();

    // Semantic versions with pre-release and build parts, dates, "master", a commit hash.
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")]
    private static partial Regex VersionText();

    private sealed record ToolAnswer(string Text, bool IsError, string Outcome);
}

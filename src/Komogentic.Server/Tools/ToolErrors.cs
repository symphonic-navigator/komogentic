// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text;

namespace Komogentic.Server.Tools;

/// <summary>What the tools tell an agent when something fails (spec §4): what failed, what Komodo said, what to try.
/// Every one is an <c>isError</c> tool result, never a JSON-RPC error.</summary>
public static class ToolErrors
{
    public const string KomodoKeyRejected =
        "Komodo rejected this credential's API key (it was probably deleted in Komodo). Reconnect it in Komogentic's dashboard.";

    public const string KomodoUnreachable = "Komodo could not be reached; try again in a minute.";

    /// <summary>Unknown and invisible alike, so that an agent can't probe for stacks its user may not see.</summary>
    public static string NoSuchStack(string stack) => $"no such stack: {stack} (or your Komodo user may not see it)";

    public static string NoExecute(string stack) => $"your Komodo user lacks Execute on stack {stack}";

    public static string NoLogs(string stack) => $"your Komodo user lacks the Logs permission on stack {stack}";

    /// <summary>An agent's own text in an answer or the audit: one line, at most 100 characters.</summary>
    public static string Shown(string text)
    {
        var line = new StringBuilder(Math.Min(text.Length, 101));
        foreach (var c in text.Length > 100 ? text[..100] : text) line.Append(char.IsControl(c) ? '?' : c);
        if (text.Length > 100) line.Append('…');
        return line.ToString();
    }
}

/// <summary>A refusal of the tool itself, with the sentence for the agent and the audit's word for it.</summary>
internal sealed class ToolFailure(string message, string outcome) : Exception(message)
{
    public string Outcome { get; } = outcome;
}

/// <summary>Trimming Komodo's output to what a tool result can carry.</summary>
internal static class ToolText
{
    /// <summary>The end of <paramref name="text"/>: at most <paramref name="maxLines"/> lines and
    /// <paramref name="maxChars"/> characters, cut at a line start; whether anything was cut.</summary>
    public static (string Text, bool Trimmed) Tail(string text, int maxLines, int maxChars)
    {
        var trimmed = false;
        var lines = text.Split('\n');
        if (lines.Length > maxLines)
        {
            text = string.Join('\n', lines[^maxLines..]);
            trimmed = true;
        }

        if (text.Length > maxChars)
        {
            text = text[^maxChars..];
            var lineStart = text.IndexOf('\n');
            if (lineStart >= 0 && lineStart < text.Length - 1) text = text[(lineStart + 1)..];
            trimmed = true;
        }

        return (text, trimmed);
    }

    public static string Time(long unixMs) =>
        DateTimeOffset.FromUnixTimeMilliseconds(unixMs).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
}

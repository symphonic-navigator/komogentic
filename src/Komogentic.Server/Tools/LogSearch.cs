// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text;

namespace Komogentic.Server.Tools;

/// <summary>
/// Komodo's periphery pipes the last 5000 log lines through <c>grep -E 'a|b'</c> (any term) or
/// <c>grep -P '^(?=.*a)(?=.*b)'</c> (every term), case-sensitive and as regular expressions (komodo
/// bin/periphery/src/helpers.rs <c>format_log_grep</c>). An agent's terms are meant literally and case-insensitively,
/// so each is sent as a pattern that ERE and PCRE read alike: metacharacters escaped with a backslash, each ASCII letter
/// as a bracket pair, and <c>-</c> as <c>[-]</c>, so that a pattern never starts with a dash and grep never reads one
/// ("-1", "--retry") as an option: the periphery puts it right after <c>-E</c>, without <c>--</c>. Other letters stay as they are, matching their own case only: in a bracket, a multibyte
/// character would be read byte by byte under a C locale, and the periphery's locale is not known.
/// </summary>
public static class LogSearch
{
    private const string Metacharacters = @"\^$.|?*+()[]{}";

    public static string Pattern(string term)
    {
        var pattern = new StringBuilder(term.Length * 4);
        foreach (var c in term)
        {
            if (char.IsAsciiLetter(c)) pattern.Append('[').Append(char.ToLowerInvariant(c)).Append(char.ToUpperInvariant(c)).Append(']');
            else if (Metacharacters.Contains(c)) pattern.Append('\\').Append(c);
            else if (c == '-') pattern.Append("[-]");
            else pattern.Append(c);
        }

        return pattern.ToString();
    }
}

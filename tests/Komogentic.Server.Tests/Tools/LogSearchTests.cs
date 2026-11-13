// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.RegularExpressions;
using Komogentic.Server.Tools;

namespace Komogentic.Server.Tests.Tools;

/// <summary>Komodo's periphery greps the logs with each term as a case-sensitive regular expression; the tool sends a
/// literal, case-insensitive pattern that ERE and PCRE read alike.</summary>
public sealed class LogSearchTests
{
    [Fact]
    public void Letters_become_bracket_pairs()
    {
        Assert.Equal("[eE][xX][cC][eE][pP][tT][iI][oO][nN]", LogSearch.Pattern("exception"));
        Assert.Equal("[nN][uU][lL][lL][rR][eE][fF]", LogSearch.Pattern("NullRef"));
    }

    [Fact]
    public void Metacharacters_are_escaped()
    {
        Assert.Equal(@"[aA]\.[bB]\([cC]\)\*\+\?\[\]\{2\}\|\^\$\\", LogSearch.Pattern(@"a.b(c)*+?[]{2}|^$\"));
    }

    [Fact]
    public void Other_characters_stay_as_they_are()
    {
        Assert.Equal("500 [eE][rR][rR][oO][rR]: /[aA][pP][iI]/[sS][aA][vV][eE][-]1 '[xX]' #ä", LogSearch.Pattern("500 error: /api/save-1 'x' #ä"));
    }

    [Fact]
    public void Dash_is_a_bracket_so_no_term_reads_as_a_grep_option()
    {
        Assert.Equal("[-]1", LogSearch.Pattern("-1"));
        Assert.Equal("[-][-][rR][eE][tT][rR][yY]", LogSearch.Pattern("--retry"));
    }

    private static readonly string[] Sample =
    [
        "ERROR: Null Ref EXCEPTION in save",
        "an exception only",
        "retry -1 failed",
        "--retry given",
        "path A.B(C) failed",
        "axb(c) other",
        "[WARN] disk 100%",
        "price $5 ^ caret|pipe",
        "Grüße: ä",
    ];

    public static TheoryData<string, string[], int[]> GrepCases() => new()
    {
        { "Or", ["exception"], [0, 1] },
        { "Or", ["-1"], [2] },
        { "Or", ["--retry"], [3] },
        { "Or", ["-1", "--retry"], [2, 3] },
        { "Or", ["a.b(c)"], [4] },
        { "Or", ["[warn]", "$5 ^"], [6, 7] },
        { "Or", ["|pipe"], [7] },
        { "Or", ["ä"], [8] },
        { "And", ["null ref", "exception"], [0] },
        { "And", ["retry", "-1"], [2] },
        { "And", ["--retry", "-1"], [] },
        { "And", ["EXCEPTION", "only"], [1] },
    };

    /// <summary>As the periphery runs it (bin/periphery/src/helpers.rs <c>format_log_grep</c>): <c>grep -E 'a|b'</c> or
    /// <c>grep -P '^(?=.*a)(?=.*b)'</c>, here without a shell, under the C locale.</summary>
    [Theory]
    [MemberData(nameof(GrepCases))]
    public void Real_grep_reads_the_patterns_literally(string combinator, string[] terms, int[] expected)
    {
        var grep = FindGrep();
        if (grep is null)
        {
            Assert.Skip("grep is not on the PATH, so the patterns can't be tried with a real grep here.");
            return;
        }

        var patterns = terms.Select(LogSearch.Pattern).ToArray();
        var (flag, pattern) = combinator == "And"
            ? ("-P", $"^(?=.*{string.Join(")(?=.*", patterns)})")
            : ("-E", string.Join("|", patterns));

        var start = new System.Diagnostics.ProcessStartInfo(grep)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = new System.Text.UTF8Encoding(false),
            StandardOutputEncoding = System.Text.Encoding.UTF8,
        };
        start.ArgumentList.Add(flag);
        start.ArgumentList.Add(pattern);
        start.Environment["LC_ALL"] = "C";
        using var process = System.Diagnostics.Process.Start(start)!;
        process.StandardInput.Write(string.Join("\n", Sample) + "\n");
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (flag == "-P" && process.ExitCode == 2 && error.Contains("support", StringComparison.OrdinalIgnoreCase))
            Assert.Skip($"this grep has no -P (PCRE): {error.Trim()}");
        Assert.True(process.ExitCode is 0 or 1, $"grep {flag} {pattern} exited {process.ExitCode}: {error}");
        Assert.Equal(expected.Select(i => Sample[i]), output.Split('\n', StringSplitOptions.RemoveEmptyEntries));
    }

    private static string? FindGrep() =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(d => Path.Combine(d, "grep"))
            .FirstOrDefault(File.Exists);

    [Theory]
    [InlineData("exception", "System.NullReferenceException: Object reference")]
    [InlineData("EXCEPTION", "an exception occurred")]
    [InlineData("a.b(c)", "path A.B(C) failed")]
    [InlineData("[warn]", "[WARN] disk")]
    [InlineData("500 error", "HTTP 500 Error in save")]
    public void Pattern_matches_the_term_literally_whatever_its_case(string term, string line)
    {
        Assert.Matches(new Regex(LogSearch.Pattern(term)), line);
    }

    [Theory]
    [InlineData("a.b", "axb")]
    [InlineData("x*", "y")]
    [InlineData("(a|b)", "a")]
    public void Pattern_does_not_match_as_a_regular_expression(string term, string line)
    {
        Assert.DoesNotMatch(new Regex(LogSearch.Pattern(term)), line);
    }
}

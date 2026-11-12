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
        Assert.Equal("500 [eE][rR][rR][oO][rR]: /[aA][pP][iI]/[sS][aA][vV][eE]-1 '[xX]' #ä", LogSearch.Pattern("500 error: /api/save-1 'x' #ä"));
    }

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

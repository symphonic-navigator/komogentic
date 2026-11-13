// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Komogentic.Server.Tests;

/// <summary>Every setting an operator can set is documented, and the release's version is the same everywhere.</summary>
public sealed partial class DocsTests
{
    private static readonly string Root = FindRoot();

    [Fact]
    public void Every_configuration_variable_is_documented()
    {
        var variables = new[] { "compose.yaml", "compose.traefik.yaml" }
            .SelectMany(f => Variable().Matches(File.ReadAllText(Path.Combine(Root, f))).Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);
        var example = File.ReadAllText(Path.Combine(Root, ".env.example"));
        var table = ReadmeTable();

        Assert.NotEmpty(variables);
        Assert.All(variables, v =>
        {
            Assert.True(example.Contains(v + "=", StringComparison.Ordinal), $"{v} is missing from .env.example");
            Assert.True(table.Contains($"| `{v}` |", StringComparison.Ordinal), $"{v} is missing from the README's configuration table");
        });
    }

    [Fact]
    public void Versions_agree()
    {
        var version = File.ReadAllText(Path.Combine(Root, "version.txt")).Trim();
        var project = File.ReadAllText(Path.Combine(Root, "src/Komogentic.Server/Komogentic.Server.csproj"));
        using var web = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "web/package.json")));

        Assert.Matches(@"^[0-9]+\.[0-9]+\.[0-9]+$", version);
        Assert.Contains($"<Version>{version}</Version>", project, StringComparison.Ordinal);
        Assert.Equal(version, web.RootElement.GetProperty("version").GetString());
    }

    /// <summary>The README's section "Configuration", up to the next heading.</summary>
    private static string ReadmeTable()
    {
        var readme = File.ReadAllText(Path.Combine(Root, "README.md"));
        var start = readme.IndexOf("\n## Configuration", StringComparison.Ordinal);
        Assert.True(start >= 0, "The README has no Configuration section");
        var end = readme.IndexOf("\n## ", start + 1, StringComparison.Ordinal);
        return end < 0 ? readme[start..] : readme[start..end];
    }

    [GeneratedRegex(@"\$\{(KOMOGENTIC_[A-Z_]+|TZ)[:}?\-]")]
    private static partial Regex Variable();

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Komogentic.slnx"))) return dir.FullName;
        throw new InvalidOperationException("Could not find Komogentic.slnx above " + AppContext.BaseDirectory);
    }
}

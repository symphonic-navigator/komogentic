// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace Komogentic.Server.Tests;

/// <summary>A record's generated ToString prints every property: one holding a JWT, password, secret or token would
/// put it in a log line or an assertion's message. Each such record prints its own, without them (CLAUDE.md).</summary>
public sealed partial class SecretRecordsTests
{
    private const string Sentinel = "SENTINEL-not-to-be-printed";

    [GeneratedRegex("Jwt|Password|Secret|Token", RegexOptions.IgnoreCase)]
    private static partial Regex SecretName();

    private static IEnumerable<Type> Records() =>
        typeof(Program).Assembly.GetTypes().Where(t =>
            t.GetMethod("PrintMembers", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public, [typeof(System.Text.StringBuilder)]) is not null
            && !t.IsAbstract);

    private static IEnumerable<PropertyInfo> SecretProperties(Type t) =>
        t.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Where(p => p.PropertyType == typeof(string) && SecretName().IsMatch(p.Name));

    [Fact]
    public void Records_are_found()
    {
        Assert.Contains(Records(), t => t.Name == "ResolvedSession");
        Assert.Contains(Records(), t => t.Name == "SignInRequest");
    }

    [Fact]
    public void Records_with_secrets_override_to_string_without_printing_them()
    {
        var offending = new List<string>();
        foreach (var type in Records())
        {
            var secrets = SecretProperties(type).ToList();
            if (secrets.Count == 0) continue;
            var toString = type.GetMethod(nameof(ToString), BindingFlags.Instance | BindingFlags.Public, Type.EmptyTypes)!;
            if (toString.DeclaringType != type || toString.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false))
            {
                offending.Add($"{type.FullName} has the generated ToString");
                continue;
            }

            var instance = RuntimeHelpers.GetUninitializedObject(type);
            foreach (var property in secrets)
                (type.GetField($"<{property.Name}>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new InvalidOperationException($"{type.FullName}.{property.Name} has no backing field"))
                    .SetValue(instance, Sentinel);
            string printed;
            try
            {
                printed = instance.ToString()!;
            }
            catch (Exception e)
            {
                offending.Add($"{type.FullName}.ToString throws {e.GetType().Name} on an empty instance");
                continue;
            }

            if (printed.Contains(Sentinel, StringComparison.Ordinal)) offending.Add($"{type.FullName}.ToString prints {string.Join(", ", secrets.Select(p => p.Name))}");
        }

        Assert.True(offending.Count == 0, string.Join("\n", offending));
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Komogentic.Server.Komodo;

namespace Komogentic.Server.Tests.Komodo;

/// <summary>Komogentic sends Komodo the twelve calls of the spec and nothing else (CLAUDE.md, "Security rules").</summary>
public sealed partial class ClosedListTests
{
    private static readonly Dictionary<string, string> Expected = new()
    {
        ["LoginLocalUser"] = "/auth/login",
        ["CreateApiKey"] = "/auth/manage",
        ["DeleteApiKey"] = "/auth/manage",
        ["ListStacks"] = "/read",
        ["GetStack"] = "/read",
        ["ListStackServices"] = "/read",
        ["GetStackLog"] = "/read",
        ["SearchStackLog"] = "/read",
        ["ListUpdates"] = "/read",
        ["GetUpdate"] = "/read",
        ["DeployStack"] = "/execute",
        ["RestartStack"] = "/execute",
    };

    [Fact]
    public void Calls_are_exactly_the_closed_list()
    {
        var type = typeof(KomodoCall);
        Assert.True(type.IsSealed);
        Assert.All(type.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance), c => Assert.True(c.IsPrivate));

        var fields = type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(f => f.FieldType == type)
            .Select(f => (KomodoCall)f.GetValue(null)!)
            .ToDictionary(c => c.Name, c => c.Path);

        Assert.Equal(Expected.OrderBy(e => e.Key), fields.OrderBy(e => e.Key));
        Assert.Equal(Expected.OrderBy(e => e.Key), KomodoCalls.Paths.OrderBy(e => e.Key));
        Assert.Equal(Expected.Keys.Order(), KomodoCalls.All.Select(c => c.Name).Order());
    }

    [Fact]
    public void Source_names_no_other_komodo_request()
    {
        var known = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "Komodo", "komodo-2.3.4-requests.txt"))
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToHashSet();
        Assert.True(known.Count > 300, "the requests file looks truncated");
        Assert.Subset(known, Expected.Keys.ToHashSet());

        var src = Path.Combine(RepositoryRoot(), "src");
        var offending = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                        && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .SelectMany(f => StringLiteral().Matches(File.ReadAllText(f))
                .Select(m => m.Groups["text"].Value)
                .Where(text => known.Contains(text) && !Expected.ContainsKey(text))
                .Select(text => $"{Path.GetRelativePath(src, f)}: \"{text}\""))
            .ToList();

        Assert.Empty(offending);
    }

    [Fact]
    public void Only_send_builds_requests()
    {
        var client = typeof(KomodoClient);
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var takingACall = client.GetMethods(all).Where(m => m.GetParameters().Any(p => p.ParameterType == typeof(KomodoCall))).ToList();
        var send = Assert.Single(takingACall);
        Assert.Equal("SendAsync", send.Name);
        Assert.True(send.IsPrivate);

        // The body of an async method lives in its state machine's MoveNext; lambdas live in nested closure types.
        var sendBodies = Bodies(send).ToHashSet();
        var others = client.GetMethods(all).Cast<MethodBase>()
            .Concat(client.GetConstructors(all))
            .Where(m => m != send)
            .SelectMany(Bodies)
            .Concat(client.GetNestedTypes(all).SelectMany(Nested).Where(m => !sendBodies.Contains(m)))
            .Distinct()
            .ToList();
        Assert.NotEmpty(others);

        Assert.Contains(sendBodies, m => References(m).Any(IsHttpSending));
        var offending = others
            .SelectMany(m => References(m).Where(IsHttpSending).Select(r => $"{m.DeclaringType?.Name}.{m.Name} uses {r.DeclaringType?.Name ?? r.Name}.{r.Name}"))
            .ToList();
        Assert.Empty(offending);
    }

    private static bool IsHttpSending(MemberInfo member)
    {
        Type[] sending = [typeof(HttpRequestMessage), typeof(HttpClient), typeof(HttpMessageInvoker), typeof(System.Net.Http.Json.HttpClientJsonExtensions)];
        return member is Type t ? sending.Contains(t) : sending.Contains(member.DeclaringType);
    }

    private static IEnumerable<MethodBase> Bodies(MethodBase method)
    {
        yield return method;
        if (method.GetCustomAttribute<AsyncStateMachineAttribute>() is { } machine)
            foreach (var m in Nested(machine.StateMachineType)) yield return m;
    }

    private static IEnumerable<MethodBase> Nested(Type type)
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        return type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all)).Concat(type.GetNestedTypes(all).SelectMany(Nested));
    }

    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(o => o.Value);

    /// <summary>The members and types a method's IL refers to (calls, field accesses, object creation, ldtoken).</summary>
    private static IEnumerable<MemberInfo> References(MethodBase method)
    {
        var il = method.GetMethodBody()?.GetILAsByteArray();
        if (il is null) yield break;
        var typeArgs = method.DeclaringType is { IsGenericType: true } d ? d.GetGenericArguments() : null;
        var methodArgs = method.IsGenericMethod ? method.GetGenericArguments() : null;

        for (var i = 0; i < il.Length;)
        {
            short value = il[i++];
            if (value == 0xFE) value = unchecked((short)(0xFE00 | il[i++]));
            var op = OpCodesByValue[value];
            switch (op.OperandType)
            {
                case OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok:
                    var token = BitConverter.ToInt32(il, i);
                    MemberInfo? member = null;
                    try
                    {
                        member = method.Module.ResolveMember(token, typeArgs, methodArgs);
                    }
                    catch (ArgumentException)
                    {
                    }
                    if (member is not null) yield return member;
                    i += 4;
                    break;
                case OperandType.InlineNone:
                    break;
                case OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar:
                    i += 1;
                    break;
                case OperandType.InlineVar:
                    i += 2;
                    break;
                case OperandType.InlineI8 or OperandType.InlineR:
                    i += 8;
                    break;
                case OperandType.InlineSwitch:
                    i += 4 + 4 * BitConverter.ToInt32(il, i);
                    break;
                default:
                    i += 4;
                    break;
            }
        }
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Komogentic.slnx"))) return dir.FullName;
        throw new InvalidOperationException("Komogentic.slnx not found above " + AppContext.BaseDirectory);
    }

    [GeneratedRegex("""@?"(?<text>(?:[^"\\\r\n]|\\.)*)"(?!")""")]
    private static partial Regex StringLiteral();
}

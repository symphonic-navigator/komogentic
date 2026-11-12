// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Komogentic.Server.Komodo;
using Komogentic.Server.OAuth;

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

    /// <summary>
    /// The server's other HTTP users, reviewed: none of them may reach Komodo. Each sends only with a client of its
    /// own (a named client of IHttpClientFactory), never with the Komodo client's.
    /// </summary>
    private static readonly Dictionary<Type, string> OtherHttpUsers = new()
    {
        [typeof(ClientMetadataFetcher)] = "a client's metadata document, with the named client \"cimd\" (ClientMetadataServices.HttpClientName)",
    };

    private const BindingFlags Everything = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    [Fact]
    public void Only_the_komodo_client_sends_requests()
    {
        var offending = ServerMethods()
            .Where(m => Outermost(m.DeclaringType!) is var owner && owner != typeof(KomodoClient) && !OtherHttpUsers.ContainsKey(owner))
            .SelectMany(m => References(m).Where(SendsOrBuildsRequests).Select(r => $"{m.DeclaringType}.{m.Name} uses {r.DeclaringType?.Name ?? r.Name}.{r.Name}"))
            .Distinct()
            .ToList();
        Assert.Empty(offending);

        // The allowed ones do send (else the list is stale), and only the Komodo client takes an HttpClient of its
        // own: a typed client, which is what AddHttpClient<KomodoClient> hands it.
        Assert.All(OtherHttpUsers.Keys, t => Assert.Contains(ServerMethods(), m => Outermost(m.DeclaringType!) == t && References(m).Any(SendsOrBuildsRequests)));
        var typedClients = typeof(KomodoClient).Assembly.GetTypes()
            .Where(t => t.GetConstructors(Everything).Any(c => c.GetParameters().Any(p => p.ParameterType == typeof(HttpClient))))
            .ToList();
        Assert.Equal([typeof(KomodoClient)], typedClients);
        // Nobody asks the factory for the Komodo client's HttpClient by its name.
        Assert.DoesNotContain(ServerMethods(), m => Strings(m).Contains(nameof(KomodoClient)));
    }

    [Fact]
    public void Calls_are_made_only_by_their_static_constructor()
    {
        var makers = ServerMethods()
            .Where(m => References(m).Any(r => r is ConstructorInfo { IsStatic: false } c && c.DeclaringType == typeof(KomodoCall)))
            .Select(m => $"{m.DeclaringType}.{m.Name}")
            .Distinct()
            .ToList();

        Assert.Equal([$"{typeof(KomodoCall)}..cctor"], makers);
    }

    /// <summary>Every method, constructor and type initializer of the server assembly, compiler-generated ones included.</summary>
    private static IEnumerable<MethodBase> ServerMethods() =>
        typeof(KomodoClient).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(Everything).Cast<MethodBase>().Concat(t.GetConstructors(Everything)))
            .Where(m => !m.IsAbstract);

    private static Type Outermost(Type type)
    {
        while (type.DeclaringType is { } outer) type = outer;
        return type;
    }

    /// <summary>Building a request, creating a client, or a method of HttpClient that sends one.</summary>
    private static bool SendsOrBuildsRequests(MemberInfo member) => member switch
    {
        Type t => t == typeof(HttpRequestMessage),
        _ when member.DeclaringType == typeof(HttpRequestMessage) || member.DeclaringType == typeof(System.Net.Http.Json.HttpClientJsonExtensions) => true,
        ConstructorInfo c => c.DeclaringType == typeof(HttpClient) || c.DeclaringType == typeof(HttpMessageInvoker),
        MethodInfo m when m.DeclaringType == typeof(HttpClient) || m.DeclaringType == typeof(HttpMessageInvoker) =>
            ((string[])["Send", "Get", "Post", "Put", "Patch", "Delete"]).Any(verb => m.Name.StartsWith(verb, StringComparison.Ordinal)),
        _ => false,
    };

    /// <summary>The string literals a method's IL loads.</summary>
    private static IEnumerable<string> Strings(MethodBase method)
    {
        var il = method.GetMethodBody()?.GetILAsByteArray();
        if (il is null) yield break;
        foreach (var (op, offset) in Instructions(il))
            if (op.OperandType == OperandType.InlineString)
                yield return method.Module.ResolveString(BitConverter.ToInt32(il, offset));
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

        foreach (var (op, offset) in Instructions(il))
        {
            if (op.OperandType is not (OperandType.InlineMethod or OperandType.InlineField or OperandType.InlineType or OperandType.InlineTok)) continue;
            MemberInfo? member = null;
            try
            {
                member = method.Module.ResolveMember(BitConverter.ToInt32(il, offset), typeArgs, methodArgs);
            }
            catch (ArgumentException)
            {
            }
            if (member is not null) yield return member;
        }
    }

    /// <summary>Each instruction's opcode and the offset of its operand.</summary>
    private static IEnumerable<(OpCode Op, int Operand)> Instructions(byte[] il)
    {
        for (var i = 0; i < il.Length;)
        {
            short value = il[i++];
            if (value == 0xFE) value = unchecked((short)(0xFE00 | il[i++]));
            var op = OpCodesByValue[value];
            yield return (op, i);
            i += op.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(il, i),
                _ => 4,
            };
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

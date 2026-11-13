// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Komogentic.Server.Komodo;

/// <summary>
/// One request type Komogentic may send to Komodo, with its route. The constructor is private, so the static fields
/// below are the only calls there are: the closed list of the spec. Adding one is a spec change.
/// </summary>
public sealed class KomodoCall
{
    private const string Login = "/auth/login";
    private const string Manage = "/auth/manage";
    private const string Read = "/read";
    private const string Execute = "/execute";

    public static readonly KomodoCall LoginLocalUser = new("LoginLocalUser", Login);
    public static readonly KomodoCall CreateApiKey = new("CreateApiKey", Manage);
    public static readonly KomodoCall DeleteApiKey = new("DeleteApiKey", Manage);
    public static readonly KomodoCall ListStacks = new("ListStacks", Read);
    public static readonly KomodoCall GetStack = new("GetStack", Read);
    public static readonly KomodoCall ListStackServices = new("ListStackServices", Read);
    public static readonly KomodoCall GetStackLog = new("GetStackLog", Read);
    public static readonly KomodoCall SearchStackLog = new("SearchStackLog", Read);
    public static readonly KomodoCall ListUpdates = new("ListUpdates", Read);
    public static readonly KomodoCall GetUpdate = new("GetUpdate", Read);
    public static readonly KomodoCall InspectImage = new("InspectImage", Read);
    public static readonly KomodoCall DeployStack = new("DeployStack", Execute);
    public static readonly KomodoCall RestartStack = new("RestartStack", Execute);

    private KomodoCall(string name, string path)
    {
        Name = name;
        Path = path;
    }

    /// <summary>The request's <c>type</c>.</summary>
    public string Name { get; }

    /// <summary>The route it is posted to as <c>{"type": Name, "params": {…}}</c>.</summary>
    public string Path { get; }

    public override string ToString() => Name;
}

public static class KomodoCalls
{
    public static IReadOnlyList<KomodoCall> All { get; } =
    [
        KomodoCall.LoginLocalUser, KomodoCall.CreateApiKey, KomodoCall.DeleteApiKey,
        KomodoCall.ListStacks, KomodoCall.GetStack, KomodoCall.ListStackServices, KomodoCall.GetStackLog,
        KomodoCall.SearchStackLog, KomodoCall.ListUpdates, KomodoCall.GetUpdate, KomodoCall.InspectImage,
        KomodoCall.DeployStack, KomodoCall.RestartStack,
    ];

    /// <summary>Call name → route.</summary>
    public static IReadOnlyDictionary<string, string> Paths { get; } = All.ToDictionary(c => c.Name, c => c.Path);
}

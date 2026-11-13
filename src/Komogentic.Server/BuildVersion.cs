// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Reflection;

namespace Komogentic.Server;

/// <summary>
/// The version the image build gave this server: <c>0.2.0+a6362ec</c> (the release or <c>0.1.0-pre.N</c>, then the
/// short commit), the same string the web app is built with (Dockerfile). A local build has no commit, or reports
/// <c>0.0.0-dev</c>.
/// </summary>
public static class BuildVersion
{
    /// <summary>The assembly's informational version, commit included.</summary>
    public static string Full { get; } =
        typeof(BuildVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        is { Length: > 0 } informational ? informational : "0.0.0-dev";

    /// <summary>Without the commit: for MCP clients and people, who don't need it.</summary>
    public static string Semver { get; } = Full.Split('+')[0];
}


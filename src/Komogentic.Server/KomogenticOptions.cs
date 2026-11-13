// SPDX-License-Identifier: AGPL-3.0-or-later
using Microsoft.Extensions.Options;

namespace Komogentic.Server;

/// <summary>The configuration section <c>Komogentic</c> (environment variables <c>Komogentic__…</c>; README, "Configuration").</summary>
public sealed class KomogenticOptions
{
    /// <summary>Scheme, host and port people and apps reach Komogentic at, no path. Without it, the request's own.</summary>
    public string? PublicUrl { get; set; }

    public KomodoOptions Komodo { get; set; } = new();

    public MongoOptions Mongo { get; set; } = new();

    public OAuthOptions OAuth { get; set; } = new();

    public ProxyOptions Proxy { get; set; } = new();

    public sealed class KomodoOptions
    {
        /// <summary>Komodo Core's address as Komogentic reaches it, e.g. <c>http://komodo-core:9120</c>.</summary>
        public string Url { get; set; } = "";

        /// <summary>How long one Komodo request may take.</summary>
        public int TimeoutSeconds { get; set; } = 30;
    }

    public sealed class MongoOptions
    {
        public string ConnectionString { get; set; } = "";

        public string Database { get; set; } = "komogentic";
    }

    public sealed class OAuthOptions
    {
        public int AccessTokenMinutes { get; set; } = 60;

        /// <summary>Tests and development only: client metadata documents on loopback addresses.</summary>
        public bool AllowLoopbackClients { get; set; }
    }

    public sealed class ProxyOptions
    {
        /// <summary>A reverse proxy in front sets X-Forwarded-For and X-Forwarded-Proto and is the only way in.</summary>
        public bool Trusted { get; set; }
    }
}

/// <summary>Refuses to start with a configuration that can't work, naming the setting.</summary>
public sealed class KomogenticOptionsValidator(IHostEnvironment environment) : IValidateOptions<KomogenticOptions>
{
    public ValidateOptionsResult Validate(string? name, KomogenticOptions options)
    {
        var failures = new List<string>();
        if (!Uri.TryCreate(options.Komodo.Url, UriKind.Absolute, out var komodo) || komodo.Scheme is not ("http" or "https"))
            failures.Add("Komogentic:Komodo:Url must be Komodo Core's absolute http(s) address (KOMOGENTIC_KOMODO_URL).");
        if (options.Komodo.TimeoutSeconds is < 1 or > 600)
            failures.Add("Komogentic:Komodo:TimeoutSeconds must be between 1 and 600.");
        if (string.IsNullOrWhiteSpace(options.Mongo.ConnectionString))
            failures.Add("Komogentic:Mongo:ConnectionString must be set.");
        if (options.OAuth.AccessTokenMinutes is < 5 or > 1440)
            failures.Add("Komogentic:OAuth:AccessTokenMinutes must be between 5 and 1440.");
        if (options.PublicUrl is { Length: > 0 } publicUrl
            && (!Uri.TryCreate(publicUrl, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https") || url.AbsolutePath != "/" || url.Query != "" || url.Fragment != ""))
            failures.Add("Komogentic:PublicUrl must be scheme, host and port only, without a path (KOMOGENTIC_PUBLIC_URL).");
        if (options.OAuth.AllowLoopbackClients && environment.IsProduction())
            failures.Add("Komogentic:OAuth:AllowLoopbackClients is for tests and development only: it lets client metadata documents come from this machine's own addresses, so it is refused in Production.");
        // In Production the address must not come from the Host header, which a client picks: not for the issuer, the
        // connection URLs or the Origin check.
        if (string.IsNullOrEmpty(options.PublicUrl) && environment.IsProduction())
            failures.Add("Komogentic:PublicUrl (KOMOGENTIC_PUBLIC_URL) must be set in Production: the address people and apps reach Komogentic at.");
        // Without a public URL the issuer and the connection URLs would come from the Host header, which a client picks.
        if (options.Proxy.Trusted && string.IsNullOrEmpty(options.PublicUrl))
            failures.Add("Komogentic:Proxy:Trusted (KOMOGENTIC_TRUSTED_PROXY) needs Komogentic:PublicUrl (KOMOGENTIC_PUBLIC_URL).");
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}

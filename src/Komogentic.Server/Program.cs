// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server;
using Komogentic.Server.Komodo;
using Komogentic.Server.Accounts;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

var builder = WebApplication.CreateBuilder(args);

// ASP.NET logs every request line at Information ("Request starting GET /oauth/authorize?..."): nothing an operator
// needs, and a URL may carry something secret (an authorisation's state and challenge). Warnings and errors stay.
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

builder.Services.AddOptions<KomogenticOptions>()
    .Bind(builder.Configuration.GetSection("Komogentic"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<KomogenticOptions>, KomogenticOptionsValidator>();

builder.Services.AddHttpClient<KomodoClient>((services, http) =>
    {
        var komodo = services.GetRequiredService<IOptions<KomogenticOptions>>().Value.Komodo;
        // A trailing slash keeps a path prefix in front of /read, /execute and /auth.
        http.BaseAddress = new Uri(komodo.Url.EndsWith('/') ? komodo.Url : komodo.Url + "/");
        http.Timeout = TimeSpan.FromSeconds(komodo.TimeoutSeconds);
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
    })
    // The JWT and the API secret travel in headers; the factory's logging never shows their values.
    .RedactLoggedHeaders(_ => true);

// Storage and the clock.
builder.Services.AddSingleton<IMongoClient>(sp =>
    new MongoClient(sp.GetRequiredService<IOptions<KomogenticOptions>>().Value.Mongo.ConnectionString));
builder.Services.AddSingleton(sp =>
    sp.GetRequiredService<IMongoClient>().GetDatabase(sp.GetRequiredService<IOptions<KomogenticOptions>>().Value.Mongo.Database));
builder.Services.AddSingleton(TimeProvider.System);

// The OAuth authorisation server: connections, clients (metadata documents and registrations), pending requests.
builder.Services.AddSingleton<Connections>();
builder.Services.AddClientMetadataFetcher();
builder.Services.AddSingleton<OAuthClients>();
builder.Services.AddSingleton<AuthorizationRequests>();
builder.Services.AddSingleton<OAuthLimits>();

var app = builder.Build();

if (app.Services.GetRequiredService<IOptions<KomogenticOptions>>().Value.Proxy.Trusted)
{
    // Traefik reaches the container over a Docker network whose addresses Docker assigns, so no proxy address
    // can be pinned: any peer is trusted, safe only while the proxy is the only way in from outside the host (no
    // published port; the other containers on its networks are trusted too, an accepted limit). ForwardLimit 1 takes
    // the rightmost X-Forwarded-For entry, the one Traefik appended; whatever a client put there is ignored.
    // X-Forwarded-Proto (which Traefik overwrites) makes Request.IsHttps true for a request that reached Traefik over
    // https, for HSTS. First, so that everything after sees the client's address and scheme. Otherwise neither is read.
    var forwarded = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto, ForwardLimit = 1 };
    forwarded.KnownIPNetworks.Clear();
    forwarded.KnownProxies.Clear();
    app.UseForwardedHeaders(forwarded);
}

app.UseOAuthCors();

app.MapGet("/healthz", () => "ok").AllowAnonymous().ExcludeFromDescription();
app.MapDiscovery();
app.MapOAuthEndpoints();

app.Run();

public partial class Program;

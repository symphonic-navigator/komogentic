// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server;
using Komogentic.Server.Accounts;
using Komogentic.Server.Api;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

var builder = WebApplication.CreateBuilder(args);

// ASP.NET logs every request line at Information ("Request starting GET /oauth/authorize?..."): nothing an operator
// needs, and a URL may carry something secret (an authorisation's state and challenge). Warnings and errors stay.
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
// HttpClientFactory logs every outgoing request's URL: a client metadata document's is a stranger's to choose, and
// Komodo's would say who called what when. Failures are logged where they are handled.
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);

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

// The dashboard: sessions holding the sign-in's Komodo JWT, and the Komodo keys waiting for one to be deleted with.
builder.Services.AddSingleton<Sessions>();
builder.Services.AddSingleton<PendingDeletions>();
builder.Services.AddSingleton<SignInLimiter>();

// The REST API's JSON: a required field that is missing or null is a bad request, not a null in a handler. And a
// body that can't be bound throws, so ApiErrors answers it as {"error": ...} like every other refusal.
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.RespectNullableAnnotations = true;
    o.SerializerOptions.RespectRequiredConstructorParameters = true;
});
builder.Services.Configure<RouteHandlerOptions>(o => o.ThrowOnBadRequest = true);

// Per request: CallerMiddleware resolves the caller, and with it how Komodo calls authenticate. Scoped, and nothing
// singleton may depend on it.
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped(RequestCaller.Current);

// The OAuth authorisation server: connections, clients (metadata documents and registrations), pending requests.
builder.Services.AddSingleton<Connections>();
builder.Services.AddClientMetadataFetcher();
builder.Services.AddSingleton<OAuthClients>();
builder.Services.AddSingleton<AuthorizationRequests>();
builder.Services.AddSingleton<OAuthLimits>();

var app = builder.Build();
var options = app.Services.GetRequiredService<IOptions<KomogenticOptions>>().Value;

if (options.Proxy.Trusted)
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

var publicUrl = options.PublicUrl is { Length: > 0 } url ? url : null;
app.UseSecurityHeaders(publicUrl);
app.Use(ApiErrors.BadRequestsAsync);

// The web app (web/, built into wwwroot): index.html changes with every build and must be revalidated, the
// hashed files under /assets never change. Before routing: static files need no caller.
var webApp = new StaticFileOptions
{
    OnPrepareResponse = context => context.Context.Response.Headers.CacheControl =
        context.Context.Request.Path.StartsWithSegments("/assets") ? "public, max-age=31536000, immutable" : "no-cache",
};
app.UseDefaultFiles();
app.UseStaticFiles(webApp);

// Routing first, so that CallerMiddleware sees the endpoint and its AllowAnonymous.
app.UseRouting();
app.UseOAuthCors();
app.UseMiddleware<CallerMiddleware>();
app.UseCallerRules(publicUrl);

app.MapGet("/healthz", () => "ok").AllowAnonymous().ExcludeFromDescription();
app.MapDiscovery();
app.MapOAuthEndpoints();
app.MapSessionApi();

// An unknown /api or /mcp path is a JSON 404, never the web app. These are the more specific fallbacks, so they
// win over the web app's; and they are not anonymous: CallerMiddleware still asks for a caller first.
app.MapFallback("/api/{**path}", () => Results.Json(new ApiError("Not found."), statusCode: StatusCodes.Status404NotFound));
app.MapFallback("/mcp/{**path}", () => Results.Json(new ApiError("Not found."), statusCode: StatusCodes.Status404NotFound));
// A missing build file (an old chunk after a redeploy) is a plain 404: the shell in its place would fail as a script.
app.MapFallback("/assets/{**path}", () => Results.NotFound()).AllowAnonymous();
// Every other path is the web app's router's: index.html, without signing in (the app itself asks for that).
app.MapFallbackToFile("{**path}", "index.html", webApp).AllowAnonymous();

app.Run();

public partial class Program;

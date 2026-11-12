// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server;
using Komogentic.Server.Komodo;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

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

var app = builder.Build();

app.MapGet("/healthz", () => "ok").AllowAnonymous().ExcludeFromDescription();

app.Run();

public partial class Program;

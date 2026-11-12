// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions<KomogenticOptions>()
    .Bind(builder.Configuration.GetSection("Komogentic"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<KomogenticOptions>, KomogenticOptionsValidator>();

var app = builder.Build();

app.MapGet("/healthz", () => "ok").AllowAnonymous().ExcludeFromDescription();

app.Run();

public partial class Program;

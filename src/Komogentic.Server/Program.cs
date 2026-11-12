// SPDX-License-Identifier: AGPL-3.0-or-later
var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapGet("/healthz", () => "ok").AllowAnonymous().ExcludeFromDescription();

app.Run();

public partial class Program;

// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Tests.Komodo;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using MongoDB.Driver;
using Testcontainers.MongoDb;

namespace Komogentic.Server.Tests;

/// <summary>
/// The real server in memory: Program.cs wiring, a MongoDB container (or the server in <c>KOMOGENTIC_TEST_MONGO</c>)
/// and a fake Komodo Core.
/// </summary>
public sealed class AppFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly MongoDbContainer? _mongo = TestImages.ExternalMongo is null ? TestImages.MongoContainer() : null;

    public string MongoConnectionString => TestImages.ExternalMongo ?? _mongo!.GetConnectionString();

    public string DatabaseName { get; } = "t" + Guid.NewGuid().ToString("N");

    /// <summary>The origin <see cref="PublicApi"/> is reached at.</summary>
    public const string PublicUrl = "https://komogentic.test";

    private WebApplicationFactory<Program>? _publicApi;

    /// <summary>
    /// The app as a public instance: <c>Komogentic:PublicUrl</c> set and the client address taken from
    /// <c>X-Forwarded-For</c>, so each test can count against an address of its own. Built once and shared, so its
    /// in-memory rate limits are shared too.
    /// </summary>
    public WebApplicationFactory<Program> PublicApi => _publicApi ??= WithWebHostBuilder(b =>
    {
        b.UseSetting("Komogentic:PublicUrl", PublicUrl);
        b.UseSetting("Komogentic:Proxy:Trusted", "true");
    });

    /// <summary>The app's database, for tests that look behind the server's back.</summary>
    public IMongoDatabase Database => new MongoClient(MongoConnectionString).GetDatabase(DatabaseName);

    public FakeKomodo Komodo { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        Komodo = await FakeKomodo.StartAsync();
        if (_mongo is not null)
        {
            await _mongo.StartAsync();
        }
        else
        {
            await TestImages.EnsureReplicaSetAsync(MongoConnectionString, TestContext.Current.CancellationToken);
        }
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        var violations = Komodo.Violations;
        await Komodo.DisposeAsync();
        if (_mongo is not null)
        {
            await _mongo.DisposeAsync();
        }

        // Last, so that everything is cleaned up first; a fixture's cleanup failure fails the run.
        if (violations.Count > 0)
            throw new InvalidOperationException("The fake Core saw calls outside the closed list: " + string.Join(", ", violations));
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Komogentic:Mongo:ConnectionString", MongoConnectionString);
        builder.UseSetting("Komogentic:Mongo:Database", DatabaseName);
        builder.UseSetting("Komogentic:Komodo:Url", Komodo.Url.ToString());
    }
}

[CollectionDefinition("app")]
public sealed class AppCollection : ICollectionFixture<AppFactory>;

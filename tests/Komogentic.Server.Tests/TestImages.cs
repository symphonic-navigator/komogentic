// SPDX-License-Identifier: AGPL-3.0-or-later
using Docker.DotNet.Models;
using MongoDB.Bson;
using MongoDB.Driver;
using Testcontainers.MongoDb;

namespace Komogentic.Server.Tests;

internal static class TestImages
{
    public const string Mongo = "mongo:8";

    /// <summary>
    /// A replica-set MongoDB for tests. Every test gets its own database, and each collection and index is a
    /// WiredTiger file kept open: a full run passes 2000 of them, and at the Docker default soft limit of 2048
    /// open files WiredTiger panics and mongod exits mid-run. 64000 is MongoDB's recommended limit.
    /// </summary>
    /// <remarks>Testcontainers fills <c>HostConfig</c> (ports, labels) before the modifier runs, hence the <c>!</c>.</remarks>
    public static MongoDbContainer MongoContainer() => new MongoDbBuilder(Mongo)
        .WithReplicaSet()
        .WithCreateParameterModifier(p => p.HostConfig!.Ulimits = [new Ulimit { Name = "nofile", Soft = 64000, Hard = 64000 }])
        .Build();

    /// <summary>
    /// A MongoDB the tests share instead of starting a container (<c>KOMOGENTIC_TEST_MONGO</c>), for machines where
    /// Docker cannot run it. Databases are per test and random, so nothing needs cleaning up.
    /// </summary>
    public static string? ExternalMongo { get; } =
        Environment.GetEnvironmentVariable("KOMOGENTIC_TEST_MONGO") is { Length: > 0 } value ? value : null;

    /// <summary>
    /// Initiates the single-node replica set <c>rs0</c> on a fresh <c>mongod --replSet rs0</c> and waits until it
    /// has a primary; an already initiated set is left as it is. The member host is the connection string's own.
    /// </summary>
    public static async Task EnsureReplicaSetAsync(string connectionString, CancellationToken ct)
    {
        var url = MongoUrl.Create(connectionString);
        var admin = new MongoClient(url).GetDatabase("admin");
        var hello = new BsonDocument("hello", 1);

        if (!(await admin.RunCommandAsync<BsonDocument>(hello, cancellationToken: ct)).Contains("setName"))
        {
            var host = url.Server.ToString();
            var config = new BsonDocument
            {
                { "_id", "rs0" },
                { "members", new BsonArray { new BsonDocument { { "_id", 0 }, { "host", host } } } },
            };
            try
            {
                await admin.RunCommandAsync<BsonDocument>(new BsonDocument("replSetInitiate", config), cancellationToken: ct);
            }
            catch (MongoCommandException e) when (e.Code == 23)
            {
                // AlreadyInitialized: another fixture won the race between our hello and here.
            }
        }

        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!(await admin.RunCommandAsync<BsonDocument>(hello, cancellationToken: ct)).GetValue("isWritablePrimary", false).ToBoolean())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"{url.Server} did not become a writable primary within 30 s.");
            }

            await Task.Delay(250, ct);
        }
    }
}

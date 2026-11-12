// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.OAuth;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.Accounts;

[Collection("mongo")]
public sealed class ConnectionsTests(MongoFixture mongo)
{
    private static readonly KomodoUser Anna = new("u-anna", "anna");
    private static readonly KomodoUser Ben = new("u-ben", "ben");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly IMongoDatabase _db = mongo.NewDatabase();

    // Real "now": the stored times must read back as they were written.
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);

    private Connections Connections => new(_db, _time);

    [Fact]
    public async Task Creates_a_waiting_connection_with_a_url_shaped_id()
    {
        var info = await Connections.CreateAsync(Anna, "  claude.ai  ", 30, Ct);

        Assert.True(OAuthUrls.IsConnectionId(info.Id));
        Assert.Equal("claude.ai", info.Name);
        Assert.Equal(ConnectionState.Waiting, info.State);
        Assert.Null(info.Client);
        Assert.Equal(info.CreatedAt.AddDays(30), info.ExpiresAt);

        var doc = await Connections.FindAsync(info.Id, Ct);
        Assert.NotNull(doc);
        Assert.Equal("u-anna", doc.User);
        Assert.Equal("anna", doc.Username);
        Assert.Equal("claude.ai", doc.Name);
        Assert.Equal(info.ExpiresAt, doc.ExpiresAt);
        Assert.Null(doc.KomodoKey);
        Assert.Null(doc.Client);
        Assert.Equal(0, doc.Wraps);
    }

    [Fact]
    public async Task Ids_differ()
    {
        var ids = new HashSet<string>();
        for (var i = 0; i < 20; i++) ids.Add((await Connections.CreateAsync(Anna, $"c{i}", null, Ct)).Id);

        Assert.Equal(20, ids.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a​b")]
    [InlineData("a\nb")]
    public async Task Refuses_unusable_names(string name) =>
        await Assert.ThrowsAsync<UserInputException>(() => Connections.CreateAsync(Anna, name, null, Ct));

    [Fact]
    public async Task Names_have_at_most_60_characters()
    {
        Assert.Equal(60, (await Connections.CreateAsync(Anna, new string('x', 60), null, Ct)).Name.Length);
        await Assert.ThrowsAsync<UserInputException>(() => Connections.CreateAsync(Anna, new string('y', 61), null, Ct));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(366)]
    public async Task Refuses_other_expiries(int days) =>
        await Assert.ThrowsAsync<UserInputException>(() => Connections.CreateAsync(Anna, "claude", days, Ct));

    [Fact]
    public async Task A_name_is_unique_among_the_users_live_connections()
    {
        await Connections.CreateAsync(Anna, "claude", 30, Ct);

        await Assert.ThrowsAsync<ConnectionNameTakenException>(() => Connections.CreateAsync(Anna, "Claude ", null, Ct));
        // Another user's names are their own.
        await Connections.CreateAsync(Ben, "claude", null, Ct);

        // Once the first has expired, its name is free again.
        _time.Advance(TimeSpan.FromDays(31));
        await Connections.CreateAsync(Anna, "claude", null, Ct);
    }

    [Fact]
    public async Task Two_creations_with_one_name_at_once_make_one_connection()
    {
        var connections = Connections;
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            try
            {
                await connections.CreateAsync(Anna, "parallel", null, Ct);
                return true;
            }
            catch (ConnectionNameTakenException)
            {
                return false;
            }
        }));

        Assert.Single(results, r => r);
    }

    [Fact]
    public async Task Unknown_ids_are_not_found()
    {
        Assert.Null(await Connections.FindAsync("abcdefghijklmnop", Ct));
    }

    [Fact]
    public async Task The_client_and_komodo_key_read_back()
    {
        var info = await Connections.CreateAsync(Anna, "claude", null, Ct);
        await _db.GetCollection<BsonDocument>("connections").UpdateOneAsync(
            new BsonDocument("_id", info.Id),
            new BsonDocument("$set", new BsonDocument
            {
                ["client"] = new BsonDocument { ["name"] = "Claude", ["host"] = "claude.ai", ["verified"] = true },
                ["komodoKey"] = "K-anna-1",
            }),
            cancellationToken: Ct);

        var doc = await Connections.FindAsync(info.Id, Ct);

        Assert.Equal(new ConnectedClient("Claude", "claude.ai", true), doc!.Client);
        Assert.Equal("K-anna-1", doc.KomodoKey);
    }
}

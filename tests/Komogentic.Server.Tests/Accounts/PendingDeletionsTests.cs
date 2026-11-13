// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Komodo;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.Accounts;

public sealed class PendingDeletionsTests
{
    [Fact]
    public async Task A_key_that_cannot_be_queued_is_named_in_the_log()
    {
        // Nothing listens on port 1: every write fails quickly.
        var settings = MongoClientSettings.FromConnectionString("mongodb://127.0.0.1:1/?directConnection=true");
        settings.ServerSelectionTimeout = TimeSpan.FromMilliseconds(300);
        var log = new CapturedLog();
        using var logs = LoggerFactory.Create(b => b.AddProvider(log));
        var pending = new PendingDeletions(
            new MongoClient(settings).GetDatabase("unreachable"), new KomodoClient(new HttpClient()), TimeProvider.System, logs.CreateLogger<PendingDeletions>());

        await Assert.ThrowsAnyAsync<Exception>(() => pending.AddAsync(null, "u-anna", "K_lost_K", "revoked", TestContext.Current.CancellationToken));

        // The id is no secret: with it, the key can be deleted in Komodo by hand.
        Assert.Contains(log.Lines, l => l.Contains("K_lost_K", StringComparison.Ordinal) && l.Contains("u-anna", StringComparison.Ordinal));
    }
}

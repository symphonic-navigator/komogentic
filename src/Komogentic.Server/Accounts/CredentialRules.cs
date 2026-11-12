// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Globalization;
using System.Text;

namespace Komogentic.Server.Accounts;

/// <summary>What connections and API keys share: a name a person can tell apart, and an expiry of 30, 90 or 365
/// days, or never. Each check throws a <see cref="UserInputException"/> with a sentence for the dashboard.</summary>
public static class CredentialRules
{
    public const int MaxNameLength = 60;

    public static readonly IReadOnlySet<int> ExpiryDays = new HashSet<int> { 30, 90, 365 };

    /// <summary>The name normalised (NFC) and trimmed; refused if empty, longer than <see cref="MaxNameLength"/>, or
    /// holding control or invisible formatting characters. <paramref name="noun"/>: "A connection", "An API key".</summary>
    public static string Name(string name, string noun)
    {
        var clean = name.Normalize(NormalizationForm.FormC).Trim();
        if (clean.Length is 0 or > MaxNameLength) throw new UserInputException($"{noun}'s name has 1 to {MaxNameLength} characters.");
        // Format characters (zero-width, bidi overrides) are invisible: "claude​" would show as "claude".
        if (clean.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format))
            throw new UserInputException($"{noun}'s name can't contain control or invisible formatting characters.");
        return clean;
    }

    /// <summary>When a credential made at <paramref name="now"/> expires, in whole milliseconds as MongoDB keeps them;
    /// null for never.</summary>
    public static DateTime? ExpiresAt(DateTime now, int? expiresInDays, string noun)
    {
        if (expiresInDays is not { } days) return null;
        if (!ExpiryDays.Contains(days))
            throw new UserInputException($"{noun} expires after {string.Join(", ", ExpiryDays.Order())} days, or never.");
        return Milliseconds(now.AddDays(days));
    }

    public static DateTime Milliseconds(DateTime t) => new(t.Ticks - (t.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc);
}

/// <summary>Another live credential of the user has this name (case aside): a 409 in the dashboard.</summary>
public abstract class CredentialNameTakenException(string message) : Exception(message);

/// <summary>Input a person can correct (a name, an expiry): a 400 in the dashboard, with this sentence. Its own type, so
/// that no other <see cref="ArgumentException"/>, which comes from a bug, is ever shown as one.</summary>
public sealed class UserInputException(string message) : Exception(message);

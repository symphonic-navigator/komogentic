// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Buffers.Text;
using System.Text.Json;

namespace Komogentic.Server.Komodo;

public static class KomodoJwt
{
    /// <summary>
    /// The user id (<c>sub</c>) and expiry of a JWT Komodo just issued; null when it isn't one. The signature is not
    /// checked: the token came straight from Komodo, and Komodo checks it on every use. <c>exp</c> is in
    /// milliseconds since the epoch (mogh_auth_server 1.8.0, <c>provider/jwt.rs</c>, <c>JwtClaims</c>).
    /// </summary>
    public static (string UserId, DateTime ExpiresAt)? Read(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3 || !Base64Url.IsValid(parts[1])) return null;
        try
        {
            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
            var root = payload.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("sub", out var sub) || sub.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("exp", out var exp) || !exp.TryGetInt64(out var expMs))
                return null;
            return (sub.GetString()!, DateTimeOffset.FromUnixTimeMilliseconds(expMs).UtcDateTime);
        }
        catch (Exception e) when (e is JsonException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}

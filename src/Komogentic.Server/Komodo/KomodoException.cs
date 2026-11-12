// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Komogentic.Server.Komodo;

public enum KomodoErrorKind
{
    /// <summary>Komodo refused the credentials: wrong password, a deleted or expired API key, an expired JWT.</summary>
    Unauthorized,

    /// <summary>No such resource, or the user may not see it: Komodo answers both alike, and so does Komogentic.</summary>
    NotFoundOrForbidden,

    BadRequest,

    /// <summary>Komodo's auth rate limiter (HTTP 429); it counts failures per address, and it sees only Komogentic's.</summary>
    RateLimited,

    /// <summary>No answer: refused, dropped, timed out, or a proxy in front of Komodo said it is not there.</summary>
    Unreachable,

    Failed,
}

/// <summary>
/// A failed Komodo call. The message is Komodo's own error text (or a fixed one), never a request header or
/// parameter: it may end up in logs and in an agent's tool result.
/// </summary>
public sealed class KomodoException(KomodoErrorKind kind, int status, string message) : Exception(message)
{
    public KomodoErrorKind Kind { get; } = kind;

    /// <summary>Komodo's HTTP status; 0 when there was no answer.</summary>
    public int Status { get; } = status;
}

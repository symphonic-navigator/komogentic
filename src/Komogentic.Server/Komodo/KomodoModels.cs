// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Komogentic.Server.Komodo;

// Komodo's answers as far as Komogentic reads them; read with snake_case names (KomodoClient.Json). Paths are in
// Komodo 2.3.4 (client/core/rs/src/…) or the mogh auth crates. States stay strings, as Komodo spells them:
// StackState snake_case, StackServiceState PascalCase, a container's state lowercase. Nullable exactly where Komodo's
// field is an Option; a default only where Komodo leaves the field out (skip_serializing_if), as every other one is
// required (KomodoClient.Json).

/// <summary>mogh_auth_client 1.7.0 <c>api/login.rs</c> <c>JwtOrTwoFactor</c>, reduced: TOTP and passkey are both "two factor".</summary>
public sealed record LoginResult(string? Jwt, bool TwoFactor)
{
    public override string ToString() => $"LoginResult {{ TwoFactor = {TwoFactor} }}";
}

/// <summary>mogh_auth_client 1.7.0 <c>api/manage.rs</c> <c>CreateApiKeyResponse</c>.</summary>
public sealed record CreatedKey(string Key, string Secret)
{
    public override string ToString() => $"CreatedKey {{ Key = {Key} }}";
}

/// <summary>A stack's id (<c>_id.$oid</c>) and canonical name, from <c>entities/stack.rs</c> <c>Stack</c> (a <c>Resource</c>, <c>entities/mod.rs</c>).</summary>
public sealed record StackRef(string Id, string Name);

/// <summary><c>entities/stack.rs</c> <c>StackListItem</c> = <c>ResourceListItem&lt;StackListItemInfo&gt;</c> (<c>entities/resource.rs</c>).</summary>
public sealed record StackListItem(string Id, string Name, StackListItemInfo Info);

/// <summary><c>entities/stack.rs</c> <c>StackListItemInfo</c>; <c>State</c> is a snake_case <c>StackState</c>.</summary>
public sealed record StackListItemInfo(
    string ServerId,
    string ServerName,
    string SwarmId,
    string SwarmName,
    string State,
    string? Status,
    IReadOnlyList<StackServiceWithUpdate> Services);

/// <summary><c>entities/stack.rs</c> <c>StackServiceWithUpdate</c>.</summary>
public sealed record StackServiceWithUpdate(string Service, string Image, string? LatestImage, bool UpdateAvailable);

/// <summary><c>entities/stack.rs</c> <c>StackService</c>; <c>State</c> is a PascalCase <c>StackServiceState</c>.</summary>
public sealed record StackService(
    string StackId,
    string StackName,
    string Service,
    string Image,
    ContainerListItem? Container,
    SwarmServiceListItem? SwarmService,
    string State);

/// <summary><c>entities/docker/container.rs</c> <c>ContainerListItem</c>; <c>State</c> lowercase, health only inside <c>Status</c>
/// ("Up 5 minutes (healthy)"), which Komodo leaves out when it has none.</summary>
public sealed record ContainerListItem(string Name, string State, string? Status = null);

/// <summary><c>entities/docker/service.rs</c> <c>SwarmServiceListItem</c>, whose fields are PascalCase.</summary>
public sealed record SwarmServiceListItem(
    [property: JsonPropertyName("ID")] string? Id,
    [property: JsonPropertyName("Name")] string? Name,
    [property: JsonPropertyName("Image")] string? Image);

/// <summary><c>entities/update.rs</c> <c>Log</c>; timestamps in Unix milliseconds.</summary>
public sealed record KomodoLog(string Stage, string Command, string Stdout, string Stderr, bool Success, long StartTs, long EndTs);

/// <summary><c>entities/mod.rs</c> <c>ResourceTarget</c> (<c>{"type": "Stack", "id": …}</c>).</summary>
public sealed record ResourceTarget(string Type, string Id);

/// <summary><c>entities/update.rs</c> <c>UpdateListItem</c>; it has no end time (<c>GetUpdate</c> has).</summary>
public sealed record UpdateListItem(
    string Id,
    string Operation,
    long StartTs,
    bool Success,
    string Username,
    string Operator,
    ResourceTarget Target,
    string Status);

/// <summary><c>api/read/update.rs</c> <c>ListUpdatesResponse</c>: 100 per page, newest first.</summary>
public sealed record UpdateListPage(IReadOnlyList<UpdateListItem> Updates, int? NextPage);

/// <summary><c>entities/update.rs</c> <c>Update</c>; <c>Status</c> is <c>Queued</c>, <c>InProgress</c> or <c>Complete</c>.</summary>
public sealed record Update(
    [property: JsonPropertyName("_id"), JsonConverter(typeof(ObjectIdConverter))] string Id,
    string Operation,
    long StartTs,
    long? EndTs,
    bool Success,
    string Operator,
    ResourceTarget Target,
    string Status,
    IReadOnlyList<KomodoLog> Logs);

/// <summary>bson's <c>hex_string_as_object_id</c> through serde_json: <c>{"$oid": "…"}</c>.</summary>
public sealed class ObjectIdConverter : JsonConverter<string>
{
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String) return reader.GetString()!;
        using var doc = JsonDocument.ParseValue(ref reader);
        return doc.RootElement.TryGetProperty("$oid", out var oid) && oid.ValueKind == JsonValueKind.String
            ? oid.GetString()!
            : throw new JsonException("Expected an ObjectId as {\"$oid\": …}.");
    }

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("$oid", value);
        writer.WriteEndObject();
    }
}

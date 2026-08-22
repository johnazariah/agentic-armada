using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Armada.Contracts;

public readonly record struct ResourceId(Guid Value)
{
    public static ResourceId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

public readonly record struct OrganisationId(Guid Value)
{
    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

public readonly record struct ProjectId(Guid Value)
{
    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

public readonly record struct ResourceVersion(string Value)
{
    public override string ToString() => Value;
}

public readonly record struct TransitionId(Guid Value)
{
    public static TransitionId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("D", CultureInfo.InvariantCulture);
}

[JsonConverter(typeof(Sha256DigestJsonConverter))]
public sealed record Sha256Digest
{
    private Sha256Digest(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<Sha256Digest, ContractValidationError> Parse(string value) =>
        value is not null && value.Length == 71 &&
        value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value[7..].All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f')
            ? new Result<Sha256Digest, ContractValidationError>.Success(new Sha256Digest(value))
            : new Result<Sha256Digest, ContractValidationError>.Failure(
                new("invalid-sha256-digest", "A digest must be sha256: followed by 64 lowercase hexadecimal characters."));

    public override string ToString() => Value;
}

public sealed class Sha256DigestJsonConverter : JsonConverter<Sha256Digest>
{
    public override Sha256Digest Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("A SHA-256 digest must be a JSON string.");
        }

        return Sha256Digest.Parse(reader.GetString() ?? string.Empty) switch
        {
            Result<Sha256Digest, ContractValidationError>.Success success => success.Value,
            Result<Sha256Digest, ContractValidationError>.Failure failure => throw new JsonException(failure.Error.Message),
            _ => throw new JsonException("Digest validation returned an unsupported result.")
        };
    }

    public override void Write(Utf8JsonWriter writer, Sha256Digest value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.Value);
}

public sealed record RepositoryName
{
    private RepositoryName(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public static Result<RepositoryName, ContractValidationError> Parse(string value)
    {
        if (value is null)
        {
            return new Result<RepositoryName, ContractValidationError>.Failure(
                new("invalid-repository-name", "A repository must be an owner/name pair."));
        }

        var parts = value.Split('/', StringSplitOptions.None);

        return parts is [var owner, var repository] &&
               !string.IsNullOrWhiteSpace(owner) &&
               !string.IsNullOrWhiteSpace(repository)
            ? new Result<RepositoryName, ContractValidationError>.Success(new(value))
            : new Result<RepositoryName, ContractValidationError>.Failure(
                new("invalid-repository-name", "A repository must be an owner/name pair."));
    }

    public override string ToString() => Value;
}

public sealed record ActorId(string Value);

public sealed record OwnerReference(string Kind, ResourceId Uid);

public sealed record ResourceMetadata(
    ResourceId Uid,
    OrganisationId OrganisationId,
    ProjectId? ProjectId,
    string Name,
    ResourceVersion ResourceVersion,
    long Generation,
    ImmutableDictionary<string, string> Labels,
    ImmutableDictionary<string, string> Annotations,
    ImmutableArray<OwnerReference> OwnerReferences,
    ImmutableArray<string> Finalizers,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? DeletionRequestedAt = null);

public enum ConditionStatus
{
    True,
    False,
    Unknown
}

public sealed record BlockedEscalation
{
    private BlockedEscalation(
        string exactBlocker,
        ActorId actor,
        string requiredAction,
        string location,
        ActorId successor,
        DateTimeOffset deadline)
    {
        ExactBlocker = exactBlocker;
        Actor = actor;
        RequiredAction = requiredAction;
        Location = location;
        Successor = successor;
        Deadline = deadline;
    }

    public string ExactBlocker { get; }
    public ActorId Actor { get; }
    public string RequiredAction { get; }
    public string Location { get; }
    public ActorId Successor { get; }
    public DateTimeOffset Deadline { get; }

    public static Result<BlockedEscalation, ContractValidationError> Create(
        string exactBlocker,
        ActorId actor,
        string requiredAction,
        string location,
        ActorId successor,
        DateTimeOffset deadline)
    {
        var missingFields = new[]
        {
            (exactBlocker, "exactBlocker"),
            (actor.Value, "actor"),
            (requiredAction, "requiredAction"),
            (location, "location"),
            (successor.Value, "successor")
        }
        .Where(static field => string.IsNullOrWhiteSpace(field.Item1))
        .Select(static field => field.Item2)
        .ToArray();

        return missingFields.Length == 0
            ? new Result<BlockedEscalation, ContractValidationError>.Success(
                new(exactBlocker, actor, requiredAction, location, successor, deadline))
            : new Result<BlockedEscalation, ContractValidationError>.Failure(
                new("invalid-blocked-escalation", $"Blocked escalation requires {string.Join(", ", missingFields)}."));
    }
}

public sealed record Condition
{
    private Condition(
        string type,
        ConditionStatus status,
        string reason,
        string message,
        long observedGeneration,
        DateTimeOffset lastTransitionTime,
        BlockedEscalation? escalation)
    {
        Type = type;
        Status = status;
        Reason = reason;
        Message = message;
        ObservedGeneration = observedGeneration;
        LastTransitionTime = lastTransitionTime;
        Escalation = escalation;
    }

    public string Type { get; }
    public ConditionStatus Status { get; }
    public string Reason { get; }
    public string Message { get; }
    public long ObservedGeneration { get; }
    public DateTimeOffset LastTransitionTime { get; }
    public BlockedEscalation? Escalation { get; }

    public static Result<Condition, ContractValidationError> Create(
        string type,
        ConditionStatus status,
        string reason,
        string message,
        long observedGeneration,
        DateTimeOffset lastTransitionTime,
        BlockedEscalation? escalation = null)
    {
        if (string.IsNullOrWhiteSpace(type) ||
            string.IsNullOrWhiteSpace(reason) ||
            string.IsNullOrWhiteSpace(message) ||
            observedGeneration < 0)
        {
            return new Result<Condition, ContractValidationError>.Failure(
                new("invalid-condition", "Conditions require type, reason, message, and a non-negative observed generation."));
        }

        if (type == "Blocked" && status == ConditionStatus.True && escalation is null)
        {
            return new Result<Condition, ContractValidationError>.Failure(
                new("blocked-escalation-required", "Blocked=True requires a complete escalation."));
        }

        return new Result<Condition, ContractValidationError>.Success(
            new(type, status, reason, message, observedGeneration, lastTransitionTime, escalation));
    }
}

public sealed record ResourceStatus(
    long ObservedGeneration,
    ImmutableArray<Condition> Conditions);

public static class ImmutableValues
{
    public static readonly ImmutableDictionary<string, string> EmptyLabels =
        ImmutableDictionary<string, string>.Empty;

    public static readonly ImmutableArray<OwnerReference> EmptyOwners =
        ImmutableArray<OwnerReference>.Empty;

    public static readonly ImmutableArray<string> EmptyFinalizers =
        ImmutableArray<string>.Empty;
}

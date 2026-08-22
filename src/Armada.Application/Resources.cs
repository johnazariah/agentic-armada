using System.Text.Json;
using System.Text.Json.Nodes;
using Armada.Contracts;

namespace Armada.Application;

public sealed record PersistedResource(
    ResourceId Id,
    string Kind,
    OrganisationId OrganisationId,
    ProjectId? ProjectId,
    string Name,
    long Generation,
    ResourceVersion ResourceVersion,
    JsonElement Document,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record LedgerEvent(
    Guid Id,
    ResourceId ResourceId,
    string Type,
    ActorId Actor,
    Guid CorrelationId,
    Guid? CausationId,
    string IdempotencyKey,
    DateTimeOffset OccurredAt,
    JsonElement Payload);

public sealed record OutboxMessage(
    Guid Id,
    string Type,
    string IdempotencyKey,
    DateTimeOffset OccurredAt,
    JsonElement Payload);

public sealed record ResourceCommit(
    PersistedResource Resource,
    LedgerEvent LedgerEvent,
    OutboxMessage OutboxMessage);

public abstract record ResourceStoreResult
{
    private ResourceStoreResult()
    {
    }

    public sealed record Committed(ResourceCommit Commit) : ResourceStoreResult;
    public sealed record AlreadyApplied(ResourceCommit Commit) : ResourceStoreResult;
    public sealed record Conflict(ResourceVersion? ActualVersion) : ResourceStoreResult;
}

public interface IResourceRepository
{
    Task<PersistedResource?> GetAsync(ResourceId id, CancellationToken cancellationToken);

    Task<ResourceStoreResult> CreateAsync(ResourceCommit commit, CancellationToken cancellationToken);

    Task<ResourceStoreResult> CompareAndSwapAsync(
        ResourceCommit commit,
        ResourceVersion expectedVersion,
        CancellationToken cancellationToken);
}

public sealed record ResourceCommandFailure(string Code, string Message);

public sealed record CreateResourceCommand(
    IArmadaResource Resource,
    ActorId Actor,
    Guid CorrelationId,
    Guid? CausationId,
    DateTimeOffset OccurredAt);

public sealed record UpdateResourceSpecCommand(
    ResourceId ResourceId,
    ResourceVersion ExpectedResourceVersion,
    JsonElement Spec,
    ActorId Actor,
    Guid CorrelationId,
    Guid? CausationId,
    DateTimeOffset OccurredAt);

public static class ResourceDocuments
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static PersistedResource From(IArmadaResource resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var document = JsonSerializer.SerializeToElement(resource, resource.GetType(), SerializerOptions);

        return new(
            resource.Metadata.Uid,
            resource.Kind,
            resource.Metadata.OrganisationId,
            resource.Metadata.ProjectId,
            resource.Metadata.Name,
            resource.Metadata.Generation,
            resource.Metadata.ResourceVersion,
            document,
            resource.Metadata.CreatedAt,
            resource.Metadata.UpdatedAt);
    }

    internal static JsonElement EventPayload(PersistedResource resource) =>
        JsonSerializer.SerializeToElement(
            new ResourceEventPayload(resource.Id, resource.Kind, resource.Generation, resource.ResourceVersion.Value),
            SerializerOptions);

    private sealed record ResourceEventPayload(
        ResourceId ResourceId,
        string Kind,
        long Generation,
        string ResourceVersion);
}

public static class ResourceCommandDecisions
{
    private static readonly HashSet<string> KnownKinds =
    [
        "Project",
        "Node",
        "NodeIdentity",
        "Capability",
        "Workload",
        "AdmissionDecision",
        "Attempt",
        "Lease",
        "AgentSession",
        "EvidenceReceipt",
        "Event"
    ];

    public static Result<ResourceCommit, ResourceCommandFailure> Create(CreateResourceCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var resource = ResourceDocuments.From(command.Resource);
        var validation = ValidateCreation(resource);
        if (validation is Result<bool, ResourceCommandFailure>.Failure failure)
        {
            return new Result<ResourceCommit, ResourceCommandFailure>.Failure(failure.Error);
        }

        var eventType = $"{resource.Kind}.created";
        return new Result<ResourceCommit, ResourceCommandFailure>.Success(
            Commit(resource, eventType, "created", command.Actor, command.CorrelationId, command.CausationId, command.OccurredAt));
    }

    public static Result<ResourceCommit, ResourceCommandFailure> UpdateSpec(
        PersistedResource current,
        UpdateResourceSpecCommand command)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(command);

        if (current.Id != command.ResourceId)
        {
            return Failure("resource-id-mismatch", "The update command must target the supplied resource.");
        }

        if (current.ResourceVersion != command.ExpectedResourceVersion)
        {
            return Failure("stale-resource-version", "The supplied resource version is stale.");
        }

        if (!TryNextVersion(current.ResourceVersion, out var nextVersion))
        {
            return Failure("unsupported-resource-version", "The persisted resource version cannot be advanced.");
        }

        var document = JsonNode.Parse(current.Document.GetRawText())?.AsObject();
        if (document is null || document["metadata"] is not JsonObject metadata)
        {
            return Failure("invalid-persisted-document", "The persisted resource is missing metadata.");
        }

        var nextGeneration = checked(current.Generation + 1);
        metadata["resourceVersion"] = new JsonObject { ["value"] = nextVersion.Value };
        metadata["generation"] = nextGeneration;
        metadata["updatedAt"] = command.OccurredAt;
        document["spec"] = JsonNode.Parse(command.Spec.GetRawText());

        var updated = current with
        {
            Generation = nextGeneration,
            ResourceVersion = nextVersion,
            Document = JsonSerializer.SerializeToElement(document),
            UpdatedAt = command.OccurredAt
        };

        return new Result<ResourceCommit, ResourceCommandFailure>.Success(
            Commit(
                updated,
                $"{updated.Kind}.spec-updated",
                "spec-updated",
                command.Actor,
                command.CorrelationId,
                command.CausationId,
                command.OccurredAt));
    }

    private static Result<bool, ResourceCommandFailure> ValidateCreation(PersistedResource resource)
    {
        if (resource.Id.Value == Guid.Empty || resource.OrganisationId.Value == Guid.Empty)
        {
            return new Result<bool, ResourceCommandFailure>.Failure(
                new("invalid-resource-identity", "Resource and organisation identifiers must be non-empty UUIDs."));
        }

        if (!KnownKinds.Contains(resource.Kind) || !IsValidName(resource.Name))
        {
            return new Result<bool, ResourceCommandFailure>.Failure(
                new("invalid-resource-metadata", "A recognised resource kind and lower-case DNS name are required."));
        }

        if (resource.Generation != 1 || resource.ResourceVersion.Value != "1" ||
            resource.UpdatedAt < resource.CreatedAt)
        {
            return new Result<bool, ResourceCommandFailure>.Failure(
                new("invalid-initial-version", "New resources must begin at generation and resource version 1."));
        }

        if (resource.Document.ValueKind != JsonValueKind.Object)
        {
            return new Result<bool, ResourceCommandFailure>.Failure(
                new("invalid-resource-document", "A resource document must be a JSON object."));
        }

        if (!resource.Document.TryGetProperty("apiVersion", out var apiVersion) ||
            apiVersion.GetString() != ArmadaApi.V1Alpha1 ||
            !resource.Document.TryGetProperty("kind", out var kind) ||
            PropertyString(kind) != resource.Kind ||
            !resource.Document.TryGetProperty("metadata", out var metadata) ||
            metadata.ValueKind != JsonValueKind.Object ||
            !metadata.TryGetProperty("uid", out var uid) ||
            PropertyString(uid) != resource.Id.ToString() ||
            !metadata.TryGetProperty("resourceVersion", out var resourceVersion) ||
            PropertyString(resourceVersion) != resource.ResourceVersion.Value)
        {
            return new Result<bool, ResourceCommandFailure>.Failure(
                new("invalid-resource-document", "The resource document must be a matching v1 envelope."));
        }

        return new Result<bool, ResourceCommandFailure>.Success(true);
    }

    private static ResourceCommit Commit(
        PersistedResource resource,
        string eventType,
        string operation,
        ActorId actor,
        Guid correlationId,
        Guid? causationId,
        DateTimeOffset occurredAt)
    {
        var idempotencyKey = $"{resource.Id}:{resource.ResourceVersion}:{operation}";
        var payload = ResourceDocuments.EventPayload(resource);
        var ledgerEvent = new LedgerEvent(
            Guid.NewGuid(),
            resource.Id,
            eventType,
            actor,
            correlationId,
            causationId,
            idempotencyKey,
            occurredAt,
            payload);

        return new(
            resource,
            ledgerEvent,
            new OutboxMessage(Guid.NewGuid(), eventType, idempotencyKey, occurredAt, payload));
    }

    private static bool TryNextVersion(ResourceVersion version, out ResourceVersion next)
    {
        if (long.TryParse(version.Value, out var current) && current > 0 && current < long.MaxValue)
        {
            next = new ResourceVersion((current + 1).ToString(System.Globalization.CultureInfo.InvariantCulture));
            return true;
        }

        next = default;
        return false;
    }

    private static bool IsValidName(string name) =>
        name.Length is > 0 and <= 63 &&
        IsLowercaseAsciiLetterOrDigit(name[0]) &&
        IsLowercaseAsciiLetterOrDigit(name[^1]) &&
        name.All(static character => IsLowercaseAsciiLetterOrDigit(character) || character == '-');

    private static bool IsLowercaseAsciiLetterOrDigit(char character) =>
        character is >= 'a' and <= 'z' or >= '0' and <= '9';

    private static string? PropertyString(JsonElement value) =>
        value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Object when value.TryGetProperty("value", out var nested) &&
                                      nested.ValueKind == JsonValueKind.String => nested.GetString(),
            _ => null
        };

    private static Result<ResourceCommit, ResourceCommandFailure> Failure(string code, string message) =>
        new Result<ResourceCommit, ResourceCommandFailure>.Failure(new(code, message));
}

public sealed class ResourceApplicationService(IResourceRepository repository)
{
    public async Task<Result<ResourceStoreResult, ResourceCommandFailure>> CreateAsync(
        CreateResourceCommand command,
        CancellationToken cancellationToken)
    {
        var decision = ResourceCommandDecisions.Create(command);
        return decision switch
        {
            Result<ResourceCommit, ResourceCommandFailure>.Failure failure =>
                new Result<ResourceStoreResult, ResourceCommandFailure>.Failure(failure.Error),
            Result<ResourceCommit, ResourceCommandFailure>.Success success =>
                new Result<ResourceStoreResult, ResourceCommandFailure>.Success(
                    await repository.CreateAsync(success.Value, cancellationToken)),
            _ => throw new InvalidOperationException("Unsupported resource command decision.")
        };
    }

    public async Task<Result<ResourceStoreResult, ResourceCommandFailure>> UpdateSpecAsync(
        UpdateResourceSpecCommand command,
        CancellationToken cancellationToken)
    {
        var current = await repository.GetAsync(command.ResourceId, cancellationToken);
        if (current is null)
        {
            return new Result<ResourceStoreResult, ResourceCommandFailure>.Failure(
                new("resource-not-found", "The resource does not exist."));
        }

        var decision = ResourceCommandDecisions.UpdateSpec(current, command);
        return decision switch
        {
            Result<ResourceCommit, ResourceCommandFailure>.Failure failure =>
                new Result<ResourceStoreResult, ResourceCommandFailure>.Failure(failure.Error),
            Result<ResourceCommit, ResourceCommandFailure>.Success success =>
                new Result<ResourceStoreResult, ResourceCommandFailure>.Success(
                    await repository.CompareAndSwapAsync(success.Value, command.ExpectedResourceVersion, cancellationToken)),
            _ => throw new InvalidOperationException("Unsupported resource command decision.")
        };
    }
}

using System.Text.Json;
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

    Task<ResourceCommit?> FindByIdempotencyKeyAsync(string idempotencyKey, CancellationToken cancellationToken);

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
    TransitionId IdempotencyKey,
    ProjectSpec Spec,
    ActorId Actor,
    Guid CorrelationId,
    Guid? CausationId,
    DateTimeOffset OccurredAt);

public static class ResourceDocuments
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static PersistedResource From(IArmadaResource resource) =>
        TryFrom(resource) switch
        {
            Result<PersistedResource, ResourceCommandFailure>.Success success => success.Value,
            Result<PersistedResource, ResourceCommandFailure>.Failure failure =>
                throw new ArgumentException(failure.Error.Message, nameof(resource)),
            _ => throw new InvalidOperationException("Unsupported resource serialisation result.")
        };

    public static Result<PersistedResource, ResourceCommandFailure> TryFrom(IArmadaResource resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var canonical = resource switch
        {
            Project project => Canonical(V1Alpha1Json.Serialize(project), V1Alpha1Json.DeserializeProject),
            Workload workload => Canonical(V1Alpha1Json.Serialize(workload), V1Alpha1Json.DeserializeWorkload),
            AdmissionDecision decision => Canonical(V1Alpha1Json.Serialize(decision), V1Alpha1Json.DeserializeAdmissionDecision),
            _ => new Result<JsonElement, ResourceCommandFailure>.Failure(
                new("unsupported-canonical-resource", $"No canonical v1alpha1 mapper is available for {resource.Kind}."))
        };
        if (canonical is Result<JsonElement, ResourceCommandFailure>.Failure failure)
        {
            return new Result<PersistedResource, ResourceCommandFailure>.Failure(failure.Error);
        }

        var document = ((Result<JsonElement, ResourceCommandFailure>.Success)canonical).Value;
        return new Result<PersistedResource, ResourceCommandFailure>.Success(new(
            resource.Metadata.Uid,
            resource.Kind,
            resource.Metadata.OrganisationId,
            resource.Metadata.ProjectId,
            resource.Metadata.Name,
            resource.Metadata.Generation,
            resource.Metadata.ResourceVersion,
            document,
            resource.Metadata.CreatedAt,
            resource.Metadata.UpdatedAt));
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

    private static Result<JsonElement, ResourceCommandFailure> Canonical<T>(
        string json,
        Func<string, Result<T, ContractValidationError>> deserialize) =>
        deserialize(json) switch
        {
            Result<T, ContractValidationError>.Success => new Result<JsonElement, ResourceCommandFailure>.Success(
                JsonDocument.Parse(json).RootElement.Clone()),
            Result<T, ContractValidationError>.Failure failure => new Result<JsonElement, ResourceCommandFailure>.Failure(
                new(failure.Error.Code, failure.Error.Message)),
            _ => throw new InvalidOperationException("Unsupported canonical mapper result.")
        };

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

        if (command.Resource is AdmissionDecision)
        {
            return Failure(
                "admission-decision-requires-admission-command",
                "Admission decisions may only be created by the admission command.");
        }

        return CreateCore(command);
    }

    public static Result<ResourceCommit, ResourceCommandFailure> CreateAdmissionDecision(CreateResourceCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        return command.Resource is AdmissionDecision
            ? CreateCore(command)
            : Failure(
                "invalid-admission-command",
                "The admission command requires an AdmissionDecision resource.");
    }

    private static Result<ResourceCommit, ResourceCommandFailure> CreateCore(CreateResourceCommand command)
    {
        var persisted = ResourceDocuments.TryFrom(command.Resource);
        if (persisted is Result<PersistedResource, ResourceCommandFailure>.Failure serialisationFailure)
        {
            return new Result<ResourceCommit, ResourceCommandFailure>.Failure(serialisationFailure.Error);
        }

        var resource = ((Result<PersistedResource, ResourceCommandFailure>.Success)persisted).Value;
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

        if (current.Kind is not "Project")
        {
            return Failure("immutable-resource", $"{current.Kind} cannot be updated through a generic spec command.");
        }

        if (current.ResourceVersion != command.ExpectedResourceVersion)
        {
            return Failure("stale-resource-version", "The supplied resource version is stale.");
        }

        if (!TryNextVersion(current.ResourceVersion, out var nextVersion))
        {
            return Failure("unsupported-resource-version", "The persisted resource version cannot be advanced.");
        }

        if (V1Alpha1Json.DeserializeProject(current.Document.GetRawText()) is not Result<Project, ContractValidationError>.Success project)
        {
            return Failure("invalid-persisted-document", "The persisted project does not match the v1alpha1 mapper.");
        }

        var nextGeneration = checked(current.Generation + 1);
        var updatedProject = project.Value with
        {
            Metadata = project.Value.Metadata with
            {
                ResourceVersion = nextVersion,
                Generation = nextGeneration,
                UpdatedAt = command.OccurredAt
            },
            Spec = command.Spec
        };

        var updated = ResourceDocuments.TryFrom(updatedProject);
        if (updated is Result<PersistedResource, ResourceCommandFailure>.Failure canonicalFailure)
        {
            return Failure("invalid-updated-resource", canonicalFailure.Error.Message);
        }

        return new Result<ResourceCommit, ResourceCommandFailure>.Success(
            Commit(
                ((Result<PersistedResource, ResourceCommandFailure>.Success)updated).Value,
                $"{current.Kind}.spec-updated",
                "spec-updated",
                command.Actor,
                command.CorrelationId,
                command.CausationId,
                command.OccurredAt,
                command.IdempotencyKey.ToString()));
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
        => Commit(resource, eventType, operation, actor, correlationId, causationId, occurredAt, null);

    private static ResourceCommit Commit(
        PersistedResource resource,
        string eventType,
        string operation,
        ActorId actor,
        Guid correlationId,
        Guid? causationId,
        DateTimeOffset occurredAt,
        string? idempotencyKey)
    {
        idempotencyKey ??= $"{resource.Id}:{resource.ResourceVersion}:{operation}";
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
        var prior = await repository.FindByIdempotencyKeyAsync(command.IdempotencyKey.ToString(), cancellationToken);
        if (prior is not null)
        {
            return IsMatchingReplay(prior, command)
                ? new Result<ResourceStoreResult, ResourceCommandFailure>.Success(
                    new ResourceStoreResult.AlreadyApplied(prior))
                : new Result<ResourceStoreResult, ResourceCommandFailure>.Failure(
                    new("idempotency-key-reused", "The transition identity was already used for a different update."));
        }

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

    private static bool IsMatchingReplay(ResourceCommit prior, UpdateResourceSpecCommand command)
    {
        if (prior.Resource.Id != command.ResourceId ||
            !long.TryParse(command.ExpectedResourceVersion.Value, out var expectedVersion) ||
            !long.TryParse(prior.Resource.ResourceVersion.Value, out var persistedVersion) ||
            persistedVersion != expectedVersion + 1 ||
            V1Alpha1Json.DeserializeProject(prior.Resource.Document.GetRawText()) is not Result<Project, ContractValidationError>.Success persistedProject)
        {
            return false;
        }

        var expected = ResourceDocuments.TryFrom(persistedProject.Value with { Spec = command.Spec });
        return expected is Result<PersistedResource, ResourceCommandFailure>.Success expectedResource &&
               expectedResource.Value.Document.TryGetProperty("spec", out var expectedSpec) &&
               prior.Resource.Document.TryGetProperty("spec", out var persistedSpec) &&
               JsonElement.DeepEquals(expectedSpec, persistedSpec);
    }
}

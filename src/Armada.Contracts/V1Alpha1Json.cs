using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Armada.Contracts;

public static class V1Alpha1Json
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Serialize(Project project) =>
        JsonSerializer.Serialize(ToWire(project), Options);

    public static string Serialize(Workload workload) =>
        JsonSerializer.Serialize(ToWire(workload), Options);

    public static Result<Project, ContractValidationError> DeserializeProject(string json) =>
        Deserialize<V1Alpha1ProjectWire, Project>(json, static wire => FromWire(wire));

    public static Result<Workload, ContractValidationError> DeserializeWorkload(string json) =>
        Deserialize<V1Alpha1WorkloadWire, Workload>(json, static wire => FromWire(wire));

    public static V1Alpha1ProjectWire ToWire(Project project) =>
        new(
            project.ApiVersion,
            project.Kind,
            ToWire(project.Metadata),
            new(
                new(project.Spec.GitHubRepositories.Select(static repository => repository.Value).ToArray()),
                new("GitHubRelease", project.Spec.EvidenceArchive.Repository.Value),
                new("GitHubCopilot", project.Spec.SessionProfile.ProfileDigest.Value),
                project.Spec.PolicyBundleDigest.Value,
                project.Spec.BudgetLimit),
            new(
                project.Status.Common.ObservedGeneration,
                project.Status.Common.Conditions.Select(ToWire).ToArray(),
                project.Status.BudgetObserved));

    public static V1Alpha1WorkloadWire ToWire(Workload workload) =>
        new(
            workload.ApiVersion,
            workload.Kind,
            ToWire(workload.Metadata),
            new(
                workload.Spec.BundleDigest.Value,
                workload.Spec.PolicyDigest.Value,
                "GitHub",
                workload.Spec.Source.Repository.Value,
                workload.Spec.SourceRevision,
                workload.Spec.ConfigDigest.Value,
                workload.Spec.ActionSchemas.OrderBy(static action => action, StringComparer.Ordinal).ToArray(),
                "GitHubCopilot",
                workload.Spec.SessionAuthority.ToString(),
                workload.Spec.IsolationProfile.ToString(),
                new(workload.Spec.GitHubIssue.Number, workload.Spec.GitHubIssue.NodeId),
                ToWire(workload.Spec.Scheduling),
                new(
                    "GitHubRelease",
                    workload.Spec.Evidence.Archive.Repository.Value,
                    workload.Spec.Evidence.RetentionClass)),
            new(
                workload.Status.Common.ObservedGeneration,
                workload.Status.Common.Conditions.Select(ToWire).ToArray(),
                LifecycleValue(workload.Status.Lifecycle),
                workload.Status.AttemptReference?.ToString(),
                workload.Status.Owner?.Value,
                workload.Status.Successor?.Value,
                workload.Status.ExpectedNextEventAt,
                workload.Status.ProgressDeadlineAt,
                workload.Status.GitHubPullRequest is { } pullRequest
                    ? new(pullRequest.Number, pullRequest.NodeId)
                    : null));

    public static Result<Project, ContractValidationError> FromWire(V1Alpha1ProjectWire wire)
    {
        if (wire.ApiVersion != ArmadaApi.V1Alpha1 || wire.Kind != "Project")
        {
            return Failure<Project>("invalid-project-envelope", "Expected an armada.io/v1alpha1 Project envelope.");
        }
        if (wire.Metadata is null || wire.Spec is null || wire.Status is null ||
            wire.Spec.Github is null || wire.Spec.EvidenceArchive is null || wire.Spec.SessionProfile is null)
        {
            return Failure<Project>("missing-required-section", "Project metadata, spec, status, and provider profiles are required.");
        }

        var metadata = Metadata(wire.Metadata);
        var policyDigest = Sha256Digest.Parse(wire.Spec.PolicyBundleDigest);
        var evidenceRepository = RepositoryName.Parse(wire.Spec.EvidenceArchive.Repository);
        var sessionDigest = Sha256Digest.Parse(wire.Spec.SessionProfile.ProfileDigest);
        var repositories = Repositories(wire.Spec.Github.Repositories);

        if (metadata is not Result<ResourceMetadata, ContractValidationError>.Success metadataSuccess ||
            policyDigest is not Result<Sha256Digest, ContractValidationError>.Success policySuccess ||
            evidenceRepository is not Result<RepositoryName, ContractValidationError>.Success evidenceSuccess ||
            sessionDigest is not Result<Sha256Digest, ContractValidationError>.Success sessionSuccess ||
            repositories is not Result<ImmutableHashSet<RepositoryName>, ContractValidationError>.Success repositoriesSuccess)
        {
            return FirstFailure<Project>(metadata, policyDigest, evidenceRepository, sessionDigest, repositories);
        }

        if (wire.Spec.EvidenceArchive.Provider != "GitHubRelease" ||
            wire.Spec.SessionProfile.Provider != "GitHubCopilot")
        {
            return Failure<Project>("unsupported-provider-profile", "Project provider profiles must be GitHubRelease and GitHubCopilot.");
        }

        var status = Status(wire.Status.ObservedGeneration, wire.Status.Conditions);
        if (status is Result<ResourceStatus, ContractValidationError>.Failure statusFailure)
        {
            return new Result<Project, ContractValidationError>.Failure(statusFailure.Error);
        }

        return new Result<Project, ContractValidationError>.Success(
            new(
                metadataSuccess.Value,
                new(
                    repositoriesSuccess.Value,
                    new GitHubReleaseEvidenceArchiveProfile(evidenceSuccess.Value),
                    new GitHubCopilotSessionProfile(sessionSuccess.Value),
                    policySuccess.Value,
                    wire.Spec.BudgetLimit),
                new ProjectStatus(((Result<ResourceStatus, ContractValidationError>.Success)status).Value, wire.Status.BudgetObserved)));
    }

    public static Result<Workload, ContractValidationError> FromWire(V1Alpha1WorkloadWire wire)
    {
        if (wire.ApiVersion != ArmadaApi.V1Alpha1 || wire.Kind != "Workload")
        {
            return Failure<Workload>("invalid-workload-envelope", "Expected an armada.io/v1alpha1 Workload envelope.");
        }
        if (wire.Metadata is null || wire.Spec is null || wire.Status is null ||
            wire.Spec.GithubIssue is null || wire.Spec.Scheduling is null || wire.Spec.Evidence is null)
        {
            return Failure<Workload>("missing-required-section", "Workload metadata, spec, status, issue, scheduling, and evidence sections are required.");
        }

        if (wire.Spec.SourceProvider != "GitHub" ||
            wire.Spec.SessionProvider != "GitHubCopilot" ||
            wire.Spec.Evidence.ArchiveProvider != "GitHubRelease")
        {
            return Failure<Workload>("unsupported-provider-profile", "Workload providers must be GitHub, GitHubCopilot, and GitHubRelease.");
        }

        var metadata = Metadata(wire.Metadata);
        var bundleDigest = Sha256Digest.Parse(wire.Spec.BundleDigest);
        var policyDigest = Sha256Digest.Parse(wire.Spec.PolicyDigest);
        var configDigest = Sha256Digest.Parse(wire.Spec.ConfigDigest);
        var repository = RepositoryName.Parse(wire.Spec.Repository);
        var archiveRepository = RepositoryName.Parse(wire.Spec.Evidence.ArchiveRepository);
        var authority = ParseEnum<SessionAuthority>(wire.Spec.SessionAuthority, "invalid-session-authority");
        var isolation = ParseEnum<IsolationProfile>(wire.Spec.IsolationProfile, "invalid-isolation-profile");
        var lifecycle = ParseLifecycle(wire.Status.Lifecycle);
        var scheduling = Scheduling(wire.Spec.Scheduling);
        var status = Status(wire.Status.ObservedGeneration, wire.Status.Conditions);

        if (metadata is not Result<ResourceMetadata, ContractValidationError>.Success metadataSuccess ||
            bundleDigest is not Result<Sha256Digest, ContractValidationError>.Success bundleSuccess ||
            policyDigest is not Result<Sha256Digest, ContractValidationError>.Success policySuccess ||
            configDigest is not Result<Sha256Digest, ContractValidationError>.Success configSuccess ||
            repository is not Result<RepositoryName, ContractValidationError>.Success repositorySuccess ||
            archiveRepository is not Result<RepositoryName, ContractValidationError>.Success archiveSuccess ||
            authority is not Result<SessionAuthority, ContractValidationError>.Success authoritySuccess ||
            isolation is not Result<IsolationProfile, ContractValidationError>.Success isolationSuccess ||
            lifecycle is not Result<WorkloadLifecycleState, ContractValidationError>.Success lifecycleSuccess)
        {
            return FirstFailure<Workload>(
                metadata,
                bundleDigest,
                policyDigest,
                configDigest,
                repository,
                archiveRepository,
                authority,
                isolation,
                lifecycle);
        }
        if (metadataSuccess.Value.ProjectId is null)
        {
            return Failure<Workload>("project-scope-required", "Workload metadata requires a projectId.");
        }

        if (scheduling is Result<SchedulingRequirements, ContractValidationError>.Failure schedulingFailure)
        {
            return new Result<Workload, ContractValidationError>.Failure(schedulingFailure.Error);
        }
        if (status is Result<ResourceStatus, ContractValidationError>.Failure statusFailure)
        {
            return new Result<Workload, ContractValidationError>.Failure(statusFailure.Error);
        }

        var attemptReference = OptionalResourceId(wire.Status.AttemptRef);
        if (attemptReference is Result<ResourceId?, ContractValidationError>.Failure attemptFailure)
        {
            return new Result<Workload, ContractValidationError>.Failure(attemptFailure.Error);
        }

        var attemptSuccess = (Result<ResourceId?, ContractValidationError>.Success)attemptReference;
        return new Result<Workload, ContractValidationError>.Success(
            new(
                metadataSuccess.Value,
                new(
                    bundleSuccess.Value,
                    policySuccess.Value,
                    new GitHubSourceProfile(repositorySuccess.Value),
                    wire.Spec.SourceRevision,
                    configSuccess.Value,
                    (wire.Spec.ActionSchemas ?? []).ToImmutableHashSet(StringComparer.Ordinal),
                    new GitHubCopilotSessionProvider(),
                    authoritySuccess.Value,
                    isolationSuccess.Value,
                    new GitHubIssue(wire.Spec.GithubIssue.Number, wire.Spec.GithubIssue.NodeId),
                    ((Result<SchedulingRequirements, ContractValidationError>.Success)scheduling).Value,
                    new WorkloadEvidenceRequirement(
                        new GitHubReleaseEvidenceArchiveProfile(archiveSuccess.Value),
                        wire.Spec.Evidence.RetentionClass)),
                new(
                    ((Result<ResourceStatus, ContractValidationError>.Success)status).Value,
                    lifecycleSuccess.Value,
                    attemptSuccess.Value,
                    wire.Status.Owner is null ? null : new ActorId(wire.Status.Owner),
                    wire.Status.Successor is null ? null : new ActorId(wire.Status.Successor),
                    wire.Status.ExpectedNextEventAt,
                    wire.Status.ProgressDeadlineAt,
                    wire.Status.GithubPullRequest is { } pullRequest
                        ? new GitHubPullRequest(pullRequest.Number, pullRequest.NodeId)
                        : null)));
    }

    private static Result<T, ContractValidationError> Deserialize<TWire, T>(
        string json,
        Func<TWire, Result<T, ContractValidationError>> mapper)
        where TWire : class
    {
        try
        {
            return JsonSerializer.Deserialize<TWire>(json, Options) is { } wire
                ? mapper(wire)
                : Failure<T>("invalid-json", "The resource JSON cannot be empty.");
        }
        catch (JsonException exception)
        {
            return Failure<T>("invalid-json", exception.Message);
        }
    }

    private static V1Alpha1MetadataWire ToWire(ResourceMetadata metadata) =>
        new(
            metadata.Uid.ToString(),
            metadata.OrganisationId.ToString(),
            metadata.ProjectId?.ToString(),
            metadata.Name,
            metadata.ResourceVersion.Value,
            metadata.Generation,
            metadata.Labels,
            metadata.Annotations,
            metadata.OwnerReferences.Select(static owner => new V1Alpha1OwnerReferenceWire(owner.Kind, owner.Uid.ToString())).ToArray(),
            metadata.Finalizers.ToArray(),
            metadata.CreatedAt,
            metadata.UpdatedAt,
            metadata.DeletionRequestedAt);

    private static Result<ResourceMetadata, ContractValidationError> Metadata(V1Alpha1MetadataWire wire)
    {
        if (!Guid.TryParse(wire.Uid, out var uid) ||
            !Guid.TryParse(wire.OrganisationId, out var organisationId) ||
            (wire.ProjectId is not null && !Guid.TryParse(wire.ProjectId, out _)))
        {
            return Failure<ResourceMetadata>("invalid-resource-id", "Metadata IDs must be UUID strings.");
        }

        var owners = new List<OwnerReference>();
        foreach (var owner in wire.OwnerReferences ?? [])
        {
            if (owner is null || !Guid.TryParse(owner.Uid, out var ownerId))
            {
                return Failure<ResourceMetadata>("invalid-owner-reference", "Owner reference IDs must be UUID strings.");
            }

            owners.Add(new OwnerReference(owner.Kind, new ResourceId(ownerId)));
        }

        return new Result<ResourceMetadata, ContractValidationError>.Success(
            new(
                new ResourceId(uid),
                new OrganisationId(organisationId),
                wire.ProjectId is null ? null : new ProjectId(Guid.Parse(wire.ProjectId)),
                wire.Name,
                new ResourceVersion(wire.ResourceVersion),
                wire.Generation,
                wire.Labels?.ToImmutableDictionary() ?? ImmutableDictionary<string, string>.Empty,
                wire.Annotations?.ToImmutableDictionary() ?? ImmutableDictionary<string, string>.Empty,
                owners.ToImmutableArray(),
                (wire.Finalizers ?? []).ToImmutableArray(),
                wire.CreatedAt,
                wire.UpdatedAt,
                wire.DeletionRequestedAt));
    }

    private static V1Alpha1ConditionWire ToWire(Condition condition) =>
        new(
            condition.Type,
            condition.Status.ToString(),
            condition.Reason,
            condition.Message,
            condition.ObservedGeneration,
            condition.LastTransitionTime,
            condition.Escalation is { } escalation
                ? new(
                    escalation.ExactBlocker,
                    escalation.Actor.Value,
                    escalation.RequiredAction,
                    escalation.Location,
                    escalation.Successor.Value,
                    escalation.Deadline)
                : null);

    private static Result<ResourceStatus, ContractValidationError> Status(
        long observedGeneration,
        IEnumerable<V1Alpha1ConditionWire>? conditions)
    {
        var values = ImmutableArray.CreateBuilder<Condition>();
        foreach (var wire in conditions ?? [])
        {
            if (wire is null)
            {
                return Failure<ResourceStatus>("invalid-condition", "Condition array entries cannot be null.");
            }
            if (!Enum.TryParse<ConditionStatus>(wire.Status, false, out var conditionStatus))
            {
                return Failure<ResourceStatus>("invalid-condition-status", $"Unknown condition status '{wire.Status}'.");
            }
            BlockedEscalation? escalation = null;
            if (wire.Escalation is { } escalationWire)
            {
                if (BlockedEscalation.Create(escalationWire.ExactBlocker, new ActorId(escalationWire.Actor), escalationWire.RequiredAction, escalationWire.Location, new ActorId(escalationWire.Successor), escalationWire.Deadline) is not Result<BlockedEscalation, ContractValidationError>.Success escalationSuccess)
                {
                    return Failure<ResourceStatus>("invalid-blocked-escalation", "Condition escalation is invalid.");
                }
                escalation = escalationSuccess.Value;
            }
            if (Condition.Create(wire.Type, conditionStatus, wire.Reason, wire.Message, wire.ObservedGeneration, wire.LastTransitionTime, escalation) is not Result<Condition, ContractValidationError>.Success conditionSuccess)
            {
                return Failure<ResourceStatus>("invalid-condition", "Condition is invalid.");
            }
            values.Add(conditionSuccess.Value);
        }
        return Success(new ResourceStatus(observedGeneration, values.ToImmutable()));
    }

    private static V1Alpha1SchedulingWire ToWire(SchedulingRequirements scheduling) =>
        new(
            scheduling.HostSelector is null ? null : new(scheduling.HostSelector.MatchLabels),
            scheduling.Tolerations.AsEnumerable().Select(static toleration => new V1Alpha1TolerationWire(
                toleration.Key,
                toleration.Operator,
                toleration.Value,
                toleration.Effect.ToString())).ToArray(),
            scheduling.Affinity is null ? null : new(scheduling.Affinity.MatchLabels),
            scheduling.AntiAffinity is null ? null : new(scheduling.AntiAffinity.MatchLabels),
            new(
                scheduling.Resources.CpuMillicores,
                scheduling.Resources.GpuCount,
                scheduling.Resources.MemoryBytes,
                scheduling.Resources.StorageBytes),
            scheduling.MaximumEstimatedCost,
            scheduling.CheckpointMode);

    private static Result<SchedulingRequirements, ContractValidationError> Scheduling(V1Alpha1SchedulingWire wire)
    {
        if (wire.Resources is null)
        {
            return Failure<SchedulingRequirements>("missing-required-section", "Scheduling resources are required.");
        }
        if (wire.Resources.CpuMillicores < 1 ||
            wire.Resources.MemoryBytes < 1 ||
            wire.Resources.StorageBytes < 1 ||
            wire.Resources.GpuCount < 0)
        {
            return Failure<SchedulingRequirements>(
                "invalid-resource-requirements",
                "Scheduling CPU, memory, and storage must be at least one; GPU count cannot be negative.");
        }
        if (wire.MaximumEstimatedCost is < 0)
        {
            return Failure<SchedulingRequirements>(
                "invalid-maximum-estimated-cost",
                "Maximum estimated cost cannot be negative.");
        }
        var tolerations = ImmutableArray.CreateBuilder<Toleration>();
        foreach (var toleration in wire.Tolerations ?? [])
        {
            if (toleration is null)
            {
                return Failure<SchedulingRequirements>("invalid-toleration", "Toleration array entries cannot be null.");
            }
            if (!Enum.TryParse<TaintEffect>(toleration.Effect, false, out var effect))
            {
                return Failure<SchedulingRequirements>("invalid-taint-effect", $"Unknown taint effect '{toleration.Effect}'.");
            }
            tolerations.Add(new Toleration(toleration.Key, toleration.Operator, toleration.Value, effect));
        }
        return Success(new SchedulingRequirements(
            wire.HostSelector is null ? null : new LabelSelector(wire.HostSelector.MatchLabels ?? ImmutableDictionary<string, string>.Empty),
            tolerations.ToImmutable(),
            wire.Affinity is null ? null : new LabelSelector(wire.Affinity.MatchLabels ?? ImmutableDictionary<string, string>.Empty),
            wire.AntiAffinity is null ? null : new LabelSelector(wire.AntiAffinity.MatchLabels ?? ImmutableDictionary<string, string>.Empty),
            new(wire.Resources.CpuMillicores, wire.Resources.GpuCount, wire.Resources.MemoryBytes, wire.Resources.StorageBytes),
            wire.MaximumEstimatedCost,
            wire.CheckpointMode));
    }

    private static string LifecycleValue(WorkloadLifecycleState state) =>
        state switch
        {
            WorkloadLifecycleState.StartApproved => "start-approved",
            WorkloadLifecycleState.TerminalPending => "terminal-pending",
            _ => state.ToString().ToLowerInvariant()
        };

    private static Result<WorkloadLifecycleState, ContractValidationError> ParseLifecycle(string value) =>
        value switch
        {
            "desired" => Success(WorkloadLifecycleState.Desired),
            "admitted" => Success(WorkloadLifecycleState.Admitted),
            "assigned" => Success(WorkloadLifecycleState.Assigned),
            "claimed" => Success(WorkloadLifecycleState.Claimed),
            "start-approved" => Success(WorkloadLifecycleState.StartApproved),
            "running" => Success(WorkloadLifecycleState.Running),
            "terminal-pending" => Success(WorkloadLifecycleState.TerminalPending),
            "completed" => Success(WorkloadLifecycleState.Completed),
            "failed" => Success(WorkloadLifecycleState.Failed),
            "cancelled" => Success(WorkloadLifecycleState.Cancelled),
            "expired" => Success(WorkloadLifecycleState.Expired),
            _ => Failure<WorkloadLifecycleState>("invalid-lifecycle", $"Unknown lifecycle value '{value}'.")
        };

    private static Result<TEnum, ContractValidationError> ParseEnum<TEnum>(string value, string code)
        where TEnum : struct, Enum =>
        Enum.TryParse<TEnum>(value, false, out var parsed)
            ? Success(parsed)
            : Failure<TEnum>(code, $"Unknown {typeof(TEnum).Name} value '{value}'.");

    private static Result<ImmutableHashSet<RepositoryName>, ContractValidationError> Repositories(IEnumerable<string>? values)
    {
        var repositories = ImmutableHashSet.CreateBuilder<RepositoryName>();
        foreach (var value in values ?? [])
        {
            if (value is null || RepositoryName.Parse(value) is not Result<RepositoryName, ContractValidationError>.Success success)
            {
                return Failure<ImmutableHashSet<RepositoryName>>(
                    "invalid-repository-name",
                    "Project repository allowlists must contain owner/name values.");
            }

            repositories.Add(success.Value);
        }

        return Success(repositories.ToImmutable());
    }

    private static Result<ResourceId?, ContractValidationError> OptionalResourceId(string? value)
    {
        if (value is null)
        {
            return Success<ResourceId?>(null);
        }

        return Guid.TryParse(value, out var id)
            ? Success<ResourceId?>(new ResourceId(id))
            : Failure<ResourceId?>("invalid-resource-id", "Resource references must be UUID strings.");
    }

    private static Result<T, ContractValidationError> Success<T>(T value) =>
        new Result<T, ContractValidationError>.Success(value);

    private static Result<T, ContractValidationError> Failure<T>(string code, string message) =>
        new Result<T, ContractValidationError>.Failure(new(code, message));

    private static Result<T, ContractValidationError> FirstFailure<T>(
        params object[] results) =>
        results.OfType<Result<ResourceMetadata, ContractValidationError>.Failure>()
            .Select(static failure => failure.Error)
            .Concat(results.OfType<Result<Sha256Digest, ContractValidationError>.Failure>().Select(static failure => failure.Error))
            .Concat(results.OfType<Result<RepositoryName, ContractValidationError>.Failure>().Select(static failure => failure.Error))
            .Concat(results.OfType<Result<ImmutableHashSet<RepositoryName>, ContractValidationError>.Failure>().Select(static failure => failure.Error))
            .Concat(results.OfType<Result<SessionAuthority, ContractValidationError>.Failure>().Select(static failure => failure.Error))
            .Concat(results.OfType<Result<IsolationProfile, ContractValidationError>.Failure>().Select(static failure => failure.Error))
            .Concat(results.OfType<Result<WorkloadLifecycleState, ContractValidationError>.Failure>().Select(static failure => failure.Error))
            .Select(Failure<T>)
            .First();

    private static Result<T, ContractValidationError> Failure<T>(ContractValidationError error) =>
        new Result<T, ContractValidationError>.Failure(error);
}

public sealed record V1Alpha1ProjectWire(
    string ApiVersion,
    string Kind,
    V1Alpha1MetadataWire? Metadata,
    V1Alpha1ProjectSpecWire? Spec,
    V1Alpha1ProjectStatusWire? Status);

public sealed record V1Alpha1WorkloadWire(
    string ApiVersion,
    string Kind,
    V1Alpha1MetadataWire? Metadata,
    V1Alpha1WorkloadSpecWire? Spec,
    V1Alpha1WorkloadStatusWire? Status);

public sealed record V1Alpha1MetadataWire(
    string Uid,
    string OrganisationId,
    string? ProjectId,
    string Name,
    string ResourceVersion,
    long Generation,
    ImmutableDictionary<string, string>? Labels,
    ImmutableDictionary<string, string>? Annotations,
    IReadOnlyList<V1Alpha1OwnerReferenceWire>? OwnerReferences,
    IReadOnlyList<string>? Finalizers,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? DeletionRequestedAt);

public sealed record V1Alpha1OwnerReferenceWire(string Kind, string Uid);
public sealed record V1Alpha1ProjectStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, decimal? BudgetObserved);
public sealed record V1Alpha1ConditionWire(string Type, string Status, string Reason, string Message, long ObservedGeneration, DateTimeOffset LastTransitionTime, V1Alpha1BlockedEscalationWire? Escalation);
public sealed record V1Alpha1BlockedEscalationWire(string ExactBlocker, string Actor, string RequiredAction, string Location, string Successor, DateTimeOffset Deadline);
public sealed record V1Alpha1ProjectSpecWire(V1Alpha1GitHubWire? Github, V1Alpha1EvidenceArchiveWire? EvidenceArchive, V1Alpha1SessionProfileWire? SessionProfile, string PolicyBundleDigest, decimal? BudgetLimit);
public sealed record V1Alpha1GitHubWire(IReadOnlyList<string>? Repositories);
public sealed record V1Alpha1EvidenceArchiveWire(string Provider, string Repository);
public sealed record V1Alpha1SessionProfileWire(string Provider, string ProfileDigest);
public sealed record V1Alpha1WorkloadSpecWire(string BundleDigest, string PolicyDigest, string SourceProvider, string Repository, string SourceRevision, string ConfigDigest, IReadOnlyList<string>? ActionSchemas, string SessionProvider, string SessionAuthority, string IsolationProfile, V1Alpha1GitHubIssueWire? GithubIssue, V1Alpha1SchedulingWire? Scheduling, V1Alpha1WorkloadEvidenceWire? Evidence);
public sealed record V1Alpha1GitHubIssueWire(int Number, string? NodeId);
public sealed record V1Alpha1WorkloadEvidenceWire(string ArchiveProvider, string ArchiveRepository, string RetentionClass);
public sealed record V1Alpha1SchedulingWire(V1Alpha1LabelSelectorWire? HostSelector, IReadOnlyList<V1Alpha1TolerationWire>? Tolerations, V1Alpha1LabelSelectorWire? Affinity, V1Alpha1LabelSelectorWire? AntiAffinity, V1Alpha1ResourceRequirementsWire? Resources, decimal? MaximumEstimatedCost, string? CheckpointMode);
public sealed record V1Alpha1LabelSelectorWire(ImmutableDictionary<string, string>? MatchLabels);
public sealed record V1Alpha1TolerationWire(string Key, string Operator, string? Value, string Effect);
public sealed record V1Alpha1ResourceRequirementsWire(int CpuMillicores, int GpuCount, long MemoryBytes, long StorageBytes);
public sealed record V1Alpha1WorkloadStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, string Lifecycle, string? AttemptRef, string? Owner, string? Successor, DateTimeOffset? ExpectedNextEventAt, DateTimeOffset? ProgressDeadlineAt, V1Alpha1GitHubPullRequestWire? GithubPullRequest);
public sealed record V1Alpha1GitHubPullRequestWire(int Number, string? NodeId);

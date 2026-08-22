using Armada.Contracts;
using System.Text.Json.Nodes;

namespace Armada.Application;

public sealed record PolicyFailure(string Code, string Message);

public interface IAdmissionPolicy
{
    Task<Result<AdmissionDecision, PolicyFailure>> EvaluateAsync(
        Workload workload,
        CancellationToken cancellationToken);
}

public sealed record AdmissionCommandFailure(string Code, string Message);

public sealed record PersistAdmissionDecisionCommand(
    Workload Workload,
    AdmissionDecision Decision,
    ActorId Actor,
    Guid CorrelationId,
    Guid? CausationId,
    DateTimeOffset OccurredAt);

public static class AdmissionDecisions
{
    public static Result<CreateResourceCommand, AdmissionCommandFailure> Decide(
        PersistAdmissionDecisionCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.Decision.Metadata.ProjectId != command.Workload.Metadata.ProjectId ||
            command.Decision.Metadata.OrganisationId != command.Workload.Metadata.OrganisationId)
        {
            return Failure("admission-scope-mismatch", "The admission decision must remain within the workload project and organisation.");
        }

        if (command.Decision.Spec.WorkloadReference != command.Workload.Metadata.Uid ||
            command.Decision.Spec.WorkloadGeneration != command.Workload.Metadata.Generation)
        {
            return Failure("admission-workload-binding-mismatch", "The decision must bind the exact workload generation.");
        }

        if (command.Decision.Spec.BundleDigest != command.Workload.Spec.BundleDigest)
        {
            return Failure("admission-bundle-mismatch", "The decision must bind the workload bundle digest.");
        }

        if (command.Decision.Spec.PolicyDigest != command.Workload.Spec.PolicyDigest)
        {
            return Failure("admission-policy-mismatch", "The decision must bind the workload policy digest.");
        }

        if (command.Decision.Spec.SourceRepository != command.Workload.Spec.Source.Repository ||
            command.Decision.Spec.SourceRevision != command.Workload.Spec.SourceRevision ||
            command.Decision.Spec.ConfigDigest != command.Workload.Spec.ConfigDigest)
        {
            return Failure("admission-source-binding-mismatch", "The decision must bind the exact workload source repository, revision, and configuration digest.");
        }

        if (command.Decision.Spec.SessionAuthority != command.Workload.Spec.SessionAuthority)
        {
            return Failure("admission-session-authority-mismatch", "The decision must bind the workload session authority.");
        }

        if (command.Decision.Spec.IsolationProfile != command.Workload.Spec.IsolationProfile)
        {
            return Failure("admission-isolation-profile-mismatch", "The decision must bind the workload isolation profile.");
        }

        if (command.Decision.Spec.ResourceLimits != command.Workload.Spec.Scheduling.Resources)
        {
            return Failure("admission-resource-limits-mismatch", "The decision must bind the workload resource requirements.");
        }

        if (!command.Decision.Spec.ApprovedActions.IsSubsetOf(command.Workload.Spec.ActionSchemas))
        {
            return Failure("admission-approved-actions-mismatch", "The decision cannot approve actions absent from the workload.");
        }

        if (command.Decision.Status.Decision is AdmissionVerdict.Pending or AdmissionVerdict.Expired ||
            command.Decision.Spec.ExpiresAt <= command.OccurredAt)
        {
            return Failure("invalid-admission-decision", "Only an unexpired admitted or rejected decision may be persisted.");
        }

        if (command.Decision.Metadata.Generation != 1 ||
            command.Decision.Metadata.ResourceVersion.Value != "1")
        {
            return Failure("invalid-admission-version", "Admission decisions are immutable resources created at version 1.");
        }

        return new Result<CreateResourceCommand, AdmissionCommandFailure>.Success(
            new(command.Decision, command.Actor, command.CorrelationId, command.CausationId, command.OccurredAt));
    }

    private static Result<CreateResourceCommand, AdmissionCommandFailure> Failure(string code, string message) =>
        new Result<CreateResourceCommand, AdmissionCommandFailure>.Failure(new(code, message));
}

public sealed class AdmissionApplicationService(IAdmissionPolicy policy, IResourceRepository repository)
{
    public async Task<Result<ResourceStoreResult, AdmissionCommandFailure>> AdmitAsync(
        Workload workload,
        TransitionId transitionId,
        ActorId actor,
        Guid correlationId,
        Guid? causationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken)
    {
        var evaluated = await policy.EvaluateAsync(workload, cancellationToken);
        if (evaluated is Result<AdmissionDecision, PolicyFailure>.Failure failure)
        {
            return new Result<ResourceStoreResult, AdmissionCommandFailure>.Failure(
                new(failure.Error.Code, failure.Error.Message));
        }

        if (evaluated is not Result<AdmissionDecision, PolicyFailure>.Success success)
        {
            throw new InvalidOperationException("Unsupported policy evaluation result.");
        }

        var decision = AdmissionDecisions.Decide(
            new(workload, success.Value, actor, correlationId, causationId, occurredAt));
        if (decision is Result<CreateResourceCommand, AdmissionCommandFailure>.Failure failed)
        {
            return new Result<ResourceStoreResult, AdmissionCommandFailure>.Failure(failed.Error);
        }

        var createCommand = ((Result<CreateResourceCommand, AdmissionCommandFailure>.Success)decision).Value;
        var prior = await repository.FindByIdempotencyKeyAsync(transitionId.ToString(), cancellationToken);
        if (prior is not null)
        {
            return AdmissionReplayResult(prior, success.Value, actor, correlationId, causationId, occurredAt);
        }

        var creation = ResourceCommandDecisions.CreateAdmissionDecision(createCommand, transitionId);
        if (creation is Result<ResourceCommit, ResourceCommandFailure>.Failure invalid)
        {
            return new Result<ResourceStoreResult, AdmissionCommandFailure>.Failure(
                new(invalid.Error.Code, invalid.Error.Message));
        }

        var committed = await repository.CreateAsync(
            ((Result<ResourceCommit, ResourceCommandFailure>.Success)creation).Value,
            cancellationToken);
        return committed switch
        {
            ResourceStoreResult.AlreadyApplied replay =>
                AdmissionReplayResult(replay.Commit, success.Value, actor, correlationId, causationId, occurredAt),
            _ => new Result<ResourceStoreResult, AdmissionCommandFailure>.Success(committed)
        };
    }

    private static Result<ResourceStoreResult, AdmissionCommandFailure> AdmissionReplayResult(
        ResourceCommit prior,
        AdmissionDecision decision,
        ActorId actor,
        Guid correlationId,
        Guid? causationId,
        DateTimeOffset occurredAt) =>
        IsMatchingAdmission(prior, decision, actor, correlationId, causationId, occurredAt)
            ? new Result<ResourceStoreResult, AdmissionCommandFailure>.Success(
                new ResourceStoreResult.AlreadyApplied(prior))
            : new Result<ResourceStoreResult, AdmissionCommandFailure>.Failure(
                new("idempotency-key-reused", "The admission transition identity was already used for a different command."));

    private static bool IsMatchingAdmission(
        ResourceCommit prior,
        AdmissionDecision decision,
        ActorId actor,
        Guid correlationId,
        Guid? causationId,
        DateTimeOffset occurredAt)
    {
        if (prior.Resource.Kind != "AdmissionDecision" ||
            prior.LedgerEvent.Actor != actor ||
            prior.LedgerEvent.CorrelationId != correlationId ||
            prior.LedgerEvent.CausationId != causationId ||
            prior.LedgerEvent.OccurredAt != occurredAt ||
            ResourceDocuments.TryFrom(decision) is not Result<PersistedResource, ResourceCommandFailure>.Success expected)
        {
            return false;
        }

        var expectedDocument = JsonNode.Parse(expected.Value.Document.GetRawText())?.AsObject();
        var persistedDocument = JsonNode.Parse(prior.Resource.Document.GetRawText())?.AsObject();
        if (expectedDocument?["metadata"] is not JsonObject expectedMetadata ||
            persistedDocument?["metadata"] is not JsonObject persistedMetadata)
        {
            return false;
        }

        expectedMetadata.Remove("uid");
        persistedMetadata.Remove("uid");
        return JsonNode.DeepEquals(expectedDocument, persistedDocument);
    }
}

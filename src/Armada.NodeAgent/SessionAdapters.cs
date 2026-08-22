using System.Collections.Immutable;
using Armada.Contracts;
using Armada.Domain;

namespace Armada.NodeAgent;

public sealed record SessionAdapterFailure(string Code, string Message);

public sealed record CreateSessionRequest(
    AgentSession Session,
    Attempt Attempt,
    AdmissionDecision Admission,
    CapabilityEnvelope Envelope,
    Guid CorrelationId,
    DateTimeOffset OccurredAt,
    ResourceId? ReplacesSessionReference = null);

public sealed record SessionOperationRequest(
    AgentSession Session,
    Attempt Attempt,
    AdmissionDecision Admission,
    CapabilityEnvelope Envelope,
    Guid CorrelationId,
    string Reason,
    DateTimeOffset OccurredAt,
    EvidenceReceipt? Evidence = null);

public interface ISessionAdapter
{
    Task<Result<SessionRuntime, SessionAdapterFailure>> CreateParentAsync(CreateSessionRequest request, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> ObserveParentAsync(SessionOperationRequest request, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> WakeParentAsync(SessionOperationRequest request, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> CancelParentAsync(SessionOperationRequest request, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> ArchiveParentAsync(SessionOperationRequest request, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> CreateChildAsync(CreateSessionRequest request, AgentSession parent, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> ObserveChildAsync(SessionOperationRequest request, AgentSession parent, CancellationToken cancellationToken);

    Task<Result<SessionRuntime, SessionAdapterFailure>> ArchiveChildAsync(SessionOperationRequest request, AgentSession parent, CancellationToken cancellationToken);

    Task<Result<SessionObservation, SessionAdapterFailure>> EmitObservationAsync(
        SessionOperationRequest request,
        SessionObservation observation,
        CancellationToken cancellationToken);

    Task<Result<PlanDecisionObservation, SessionAdapterFailure>> EmitPlanDecisionAsync(
        SessionOperationRequest request,
        PlanDecisionObservation observation,
        CancellationToken cancellationToken);
}

public interface IDurableSessionAdapter : ISessionAdapter;

public sealed class InMemorySessionAdapter : ISessionAdapter
{
    private readonly object gate = new();
    private readonly Dictionary<ResourceId, SessionRuntime> sessions = [];
    private readonly Dictionary<ParentSessionIdempotencyKey, ParentSessionReplay> parentIdempotency = [];
    private readonly Dictionary<ChildSessionIdempotencyKey, AgentSession> childIdempotency = [];
    private readonly Dictionary<ResourceId, ResourceId> successors = [];
    private readonly List<SessionObservation> observations = [];

    public ImmutableArray<SessionObservation> Observations
    {
        get
        {
            lock (gate)
            {
                return observations.ToImmutableArray();
            }
        }
    }

    public ImmutableDictionary<ResourceId, ResourceId> Successors
    {
        get
        {
            lock (gate)
            {
                return successors.ToImmutableDictionary();
            }
        }
    }

    public Result<SessionRuntime, SessionAdapterFailure> MarkDisappearedForReconciliation(AgentSession session)
    {
        lock (gate)
        {
            if (!sessions.TryGetValue(session.Metadata.Uid, out var runtime))
            {
                return Failure<SessionRuntime>("session-not-found", "The requested session is not known by this adapter.");
            }

            var disappeared = runtime with { Liveness = SessionLiveness.Disappeared };
            sessions[session.Metadata.Uid] = disappeared;
            return Success(disappeared);
        }
    }

    public Task<Result<SessionRuntime, SessionAdapterFailure>> CreateParentAsync(CreateSessionRequest request, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            if (request.Session.Spec.Role != AgentSessionRole.IssueMaster)
            {
                return Task.FromResult(Failure<SessionRuntime>("invalid-parent-role", "A parent session must be an Issue Master."));
            }

            var authority = ValidateAuthority(request.Session, request.Attempt, request.Admission, request.Envelope, request.OccurredAt);
            if (authority is Result<bool, SessionAdapterFailure>.Failure failure)
            {
                return Task.FromResult(Failure<SessionRuntime>(failure.Error.Code, failure.Error.Message));
            }

            var key = new ParentSessionIdempotencyKey(
                request.Session.Spec.AttemptReference,
                request.Session.Spec.IdempotencyKey,
                request.ReplacesSessionReference);
            var replay = new ParentSessionReplay(
                request.Session,
                request.Attempt.Metadata.Uid,
                request.Envelope,
                request.ReplacesSessionReference);
            if (parentIdempotency.TryGetValue(key, out var existing))
            {
                if (existing != replay)
                {
                    return Task.FromResult(Failure<SessionRuntime>(
                        "parent-idempotency-key-reused",
                        "A parent idempotency key was already used with different session, attempt, capability envelope, or replacement bindings."));
                }

                var replayedRuntime = sessions[existing.Session.Metadata.Uid];
                return replayedRuntime.Liveness is SessionLiveness.Active or SessionLiveness.Idle &&
                       !replayedRuntime.Session.Status.ArchiveComplete
                    ? Task.FromResult(Success(replayedRuntime))
                    : Task.FromResult(Failure<SessionRuntime>(
                        "parent-idempotency-key-not-eligible",
                        "The prior Issue Master is no longer eligible for replay; an authorised replacement must name it explicitly."));
            }

            if (request.ReplacesSessionReference is { } replaces)
            {
                if (!sessions.TryGetValue(replaces, out var replaced) ||
                    replaced.Liveness != SessionLiveness.Disappeared ||
                    replaced.Session.Spec.AttemptReference != request.Session.Spec.AttemptReference ||
                    replaced.Session.Spec.NodeReference != request.Session.Spec.NodeReference ||
                    replaced.Session.Metadata.ProjectId != request.Session.Metadata.ProjectId ||
                    replaced.Session.Metadata.OrganisationId != request.Session.Metadata.OrganisationId ||
                    replaced.Session.Spec.Provider.ProfileDigest != request.Session.Spec.Provider.ProfileDigest)
                {
                    return Task.FromResult(Failure<SessionRuntime>(
                        "invalid-session-replacement",
                        "A replacement must name a disappeared Issue Master with exact attempt, node, project, organisation, and provider bindings."));
                }
            }

            var runtime = new SessionRuntime(request.Session, SessionLiveness.Idle, request.Session.Metadata.CreatedAt);
            sessions.Add(request.Session.Metadata.Uid, runtime);
            parentIdempotency.Add(key, replay);
            if (request.ReplacesSessionReference is { } replacedSession)
            {
                successors.Add(replacedSession, request.Session.Metadata.Uid);
            }
            return Task.FromResult(Success(runtime));
        }
    }

    public Task<Result<SessionRuntime, SessionAdapterFailure>> ObserveParentAsync(SessionOperationRequest request, CancellationToken cancellationToken) =>
        ObserveAsync(request, AgentSessionRole.IssueMaster);

    public Task<Result<SessionRuntime, SessionAdapterFailure>> WakeParentAsync(SessionOperationRequest request, CancellationToken cancellationToken) =>
        TransitionAsync(request, AgentSessionRole.IssueMaster, SessionLiveness.Active, SessionLiveness.Idle);

    public Task<Result<SessionRuntime, SessionAdapterFailure>> CancelParentAsync(SessionOperationRequest request, CancellationToken cancellationToken) =>
        TransitionAsync(request, AgentSessionRole.IssueMaster, SessionLiveness.Terminal, SessionLiveness.Active, SessionLiveness.Idle);

    public Task<Result<SessionRuntime, SessionAdapterFailure>> ArchiveParentAsync(SessionOperationRequest request, CancellationToken cancellationToken) =>
        ArchiveAsync(request, AgentSessionRole.IssueMaster);

    public Task<Result<SessionRuntime, SessionAdapterFailure>> CreateChildAsync(CreateSessionRequest request, AgentSession parent, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            var authority = ValidateAuthority(request.Session, request.Attempt, request.Admission, request.Envelope, request.OccurredAt);
            if (authority is Result<bool, SessionAdapterFailure>.Failure failure)
            {
                return Task.FromResult(Failure<SessionRuntime>(failure.Error.Code, failure.Error.Message));
            }

            if (request.Envelope.SessionAuthority != SessionAuthority.IssueMasterWithChildren ||
                parent.Spec.Role != AgentSessionRole.IssueMaster ||
                request.Session.Spec.Role != AgentSessionRole.Child ||
                request.Session.Spec.ParentSessionReference != parent.Metadata.Uid ||
                request.Session.Spec.AttemptReference != parent.Spec.AttemptReference ||
                request.Session.Spec.NodeReference != parent.Spec.NodeReference ||
                request.Session.Metadata.ProjectId != parent.Metadata.ProjectId ||
                request.Session.Metadata.OrganisationId != parent.Metadata.OrganisationId ||
                request.Session.Spec.Provider.ProfileDigest != parent.Spec.Provider.ProfileDigest ||
                !sessions.TryGetValue(parent.Metadata.Uid, out var durableParent) ||
                durableParent.Session != parent ||
                durableParent.Liveness != SessionLiveness.Active ||
                durableParent.Session.Status.ArchiveComplete)
            {
                return Task.FromResult(Failure<SessionRuntime>(
                    "child-session-authority-refused",
                    "Child creation requires IssueMasterWithChildren authority and exact parent, attempt, node, project, organisation, and provider bindings."));
            }

            var key = new ChildSessionIdempotencyKey(
                parent.Metadata.Uid,
                request.Session.Spec.AttemptReference,
                request.Session.Spec.IdempotencyKey);
            if (childIdempotency.TryGetValue(key, out var existing))
            {
                return existing == request.Session && sessions.TryGetValue(existing.Metadata.Uid, out var existingRuntime)
                    ? Task.FromResult(Success(existingRuntime))
                    : Task.FromResult(Failure<SessionRuntime>(
                        "child-idempotency-key-reused",
                        "A child idempotency key was already used with different child identity or bindings."));
            }

            var runtime = new SessionRuntime(request.Session, SessionLiveness.Active, request.Session.Metadata.CreatedAt);
            sessions.Add(request.Session.Metadata.Uid, runtime);
            childIdempotency.Add(key, request.Session);
            return Task.FromResult(Success(runtime));
        }
    }

    public Task<Result<SessionRuntime, SessionAdapterFailure>> ObserveChildAsync(SessionOperationRequest request, AgentSession parent, CancellationToken cancellationToken) =>
        ObserveAsync(request, AgentSessionRole.Child, parent);

    public Task<Result<SessionRuntime, SessionAdapterFailure>> ArchiveChildAsync(SessionOperationRequest request, AgentSession parent, CancellationToken cancellationToken) =>
        ArchiveAsync(request, AgentSessionRole.Child, parent);

    public Task<Result<SessionObservation, SessionAdapterFailure>> EmitObservationAsync(
        SessionOperationRequest request,
        SessionObservation observation,
        CancellationToken cancellationToken)
    {
        lock (gate)
        {
            var runtime = Find(request, request.Session.Spec.Role);
            if (runtime is Result<SessionRuntime, SessionAdapterFailure>.Failure runtimeFailure)
            {
                return Task.FromResult(Failure<SessionObservation>(runtimeFailure.Error.Code, runtimeFailure.Error.Message));
            }

            var durableSession = ((Result<SessionRuntime, SessionAdapterFailure>.Success)runtime).Value.Session;
            if (observation.CorrelationId != request.CorrelationId)
            {
                return Task.FromResult(Failure<SessionObservation>("session-observation-correlation-mismatch", "An observation must use the operation correlation ID."));
            }

            var validated = SessionAuthorityValidation.ValidateObservation(durableSession, request.Envelope, observation);
            if (validated is Result<bool, SessionReconciliationFailure>.Failure failure)
            {
                return Task.FromResult(Failure<SessionObservation>(failure.Error.Code, failure.Error.Message));
            }

            observations.Add(observation);
            return Task.FromResult(Success(observation));
        }
    }

    public Task<Result<PlanDecisionObservation, SessionAdapterFailure>> EmitPlanDecisionAsync(
        SessionOperationRequest request,
        PlanDecisionObservation observation,
        CancellationToken cancellationToken)
    {
        lock (gate)
        {
            var runtime = Find(request, request.Session.Spec.Role);
            if (runtime is Result<SessionRuntime, SessionAdapterFailure>.Failure runtimeFailure)
            {
                return Task.FromResult(Failure<PlanDecisionObservation>(runtimeFailure.Error.Code, runtimeFailure.Error.Message));
            }

            var durableSession = ((Result<SessionRuntime, SessionAdapterFailure>.Success)runtime).Value.Session;
            if (observation.Binding.CorrelationId != request.CorrelationId)
            {
                return Task.FromResult(Failure<PlanDecisionObservation>("session-observation-correlation-mismatch", "A plan decision must use the operation correlation ID."));
            }

            var validated = SessionAuthorityValidation.ValidateObservation(durableSession, request.Envelope, observation.Binding);
            if (validated is Result<bool, SessionReconciliationFailure>.Failure observationFailure)
            {
                return Task.FromResult(Failure<PlanDecisionObservation>(observationFailure.Error.Code, observationFailure.Error.Message));
            }

            var plan = SessionAuthorityValidation.ValidatePlanDecision(request.Admission, request.Envelope, observation);
            if (plan is Result<bool, SessionReconciliationFailure>.Failure planFailure)
            {
                return Task.FromResult(Failure<PlanDecisionObservation>(planFailure.Error.Code, planFailure.Error.Message));
            }

            observations.Add(observation.Binding);
            return Task.FromResult(Success(observation));
        }
    }

    private Task<Result<SessionRuntime, SessionAdapterFailure>> ObserveAsync(
        SessionOperationRequest request,
        AgentSessionRole expectedRole,
        AgentSession? parent = null)
    {
        lock (gate)
        {
            return Task.FromResult(Find(request, expectedRole, parent));
        }
    }

    private Task<Result<SessionRuntime, SessionAdapterFailure>> TransitionAsync(
        SessionOperationRequest request,
        AgentSessionRole expectedRole,
        SessionLiveness liveness,
        params SessionLiveness[] permittedStates)
    {
        lock (gate)
        {
            var current = Find(request, expectedRole);
            if (current is Result<SessionRuntime, SessionAdapterFailure>.Failure failure)
            {
                return Task.FromResult(Failure<SessionRuntime>(failure.Error.Code, failure.Error.Message));
            }

            var previous = ((Result<SessionRuntime, SessionAdapterFailure>.Success)current).Value;
            if (!permittedStates.Contains(previous.Liveness) || previous.Session.Status.ArchiveComplete)
            {
                return Task.FromResult(Failure<SessionRuntime>("invalid-session-transition", "The requested session lifecycle transition is not permitted."));
            }

            var runtime = previous with { Liveness = liveness };
            sessions[request.Session.Metadata.Uid] = runtime;
            return Task.FromResult(Success(runtime));
        }
    }

    private Task<Result<SessionRuntime, SessionAdapterFailure>> ArchiveAsync(
        SessionOperationRequest request,
        AgentSessionRole expectedRole,
        AgentSession? parent = null)
    {
        lock (gate)
        {
            var current = FindForArchive(request, expectedRole, parent);
            if (current is Result<SessionRuntime, SessionAdapterFailure>.Failure failure)
            {
                return Task.FromResult(Failure<SessionRuntime>(failure.Error.Code, failure.Error.Message));
            }

            var previous = ((Result<SessionRuntime, SessionAdapterFailure>.Success)current).Value;
            if (previous.Liveness == SessionLiveness.Archived || previous.Session.Status.ArchiveComplete)
            {
                return Task.FromResult(Failure<SessionRuntime>("invalid-session-transition", "An archived session cannot be archived again."));
            }

            var evidence = SessionAuthorityValidation.CanArchive(request.Attempt, request.Evidence);
            if (evidence is Result<bool, SessionReconciliationFailure>.Failure evidenceFailure)
            {
                return Task.FromResult(Failure<SessionRuntime>(evidenceFailure.Error.Code, evidenceFailure.Error.Message));
            }

            var runtime = previous with
            {
                Liveness = SessionLiveness.Archived,
                Session = ((Result<SessionRuntime, SessionAdapterFailure>.Success)current).Value.Session with
                {
                    Status = ((Result<SessionRuntime, SessionAdapterFailure>.Success)current).Value.Session.Status with { ArchiveComplete = true }
                }
            };
            sessions[request.Session.Metadata.Uid] = runtime;
            return Task.FromResult(Success(runtime));
        }
    }

    private Result<SessionRuntime, SessionAdapterFailure> Find(
        SessionOperationRequest request,
        AgentSessionRole expectedRole,
        AgentSession? parent = null)
    {
        if (request.CorrelationId == Guid.Empty || string.IsNullOrWhiteSpace(request.Reason))
        {
            return Failure<SessionRuntime>("invalid-session-operation", "Session operations require a correlation ID and exact reason.");
        }

        if (request.Session.Spec.Role != expectedRole ||
            parent is not null && request.Session.Spec.ParentSessionReference != parent.Metadata.Uid)
        {
            return Failure<SessionRuntime>("session-authority-refused", "The operation is not authorised for this session role or parent.");
        }

        if (!sessions.TryGetValue(request.Session.Metadata.Uid, out var runtime))
        {
            return Failure<SessionRuntime>("session-not-found", "The requested session is not known by this adapter.");
        }

        return ValidateAuthority(runtime.Session, request.Attempt, request.Admission, request.Envelope, request.OccurredAt) is
            Result<bool, SessionAdapterFailure>.Failure failure
                ? Failure<SessionRuntime>(failure.Error.Code, failure.Error.Message)
                : new Result<SessionRuntime, SessionAdapterFailure>.Success(runtime);
    }

    private Result<SessionRuntime, SessionAdapterFailure> FindForArchive(
        SessionOperationRequest request,
        AgentSessionRole expectedRole,
        AgentSession? parent)
    {
        if (request.CorrelationId == Guid.Empty || string.IsNullOrWhiteSpace(request.Reason) ||
            request.Session.Spec.Role != expectedRole ||
            parent is not null && request.Session.Spec.ParentSessionReference != parent.Metadata.Uid ||
            !sessions.TryGetValue(request.Session.Metadata.Uid, out var runtime) ||
            runtime.Session.Spec.AttemptReference != request.Attempt.Metadata.Uid)
        {
            return Failure<SessionRuntime>("invalid-terminal-archive-binding", "Terminal archival requires a known session with exact role, parent, attempt, correlation, and reason bindings.");
        }

        return new Result<SessionRuntime, SessionAdapterFailure>.Success(runtime);
    }

    private static Result<bool, SessionAdapterFailure> ValidateAuthority(
        AgentSession session,
        Attempt attempt,
        AdmissionDecision admission,
        CapabilityEnvelope envelope,
        DateTimeOffset occurredAt) =>
        SessionAuthorityValidation.ValidateOperation(session, attempt, admission, envelope, occurredAt) switch
        {
            Result<bool, SessionReconciliationFailure>.Success => new Result<bool, SessionAdapterFailure>.Success(true),
            Result<bool, SessionReconciliationFailure>.Failure failure =>
                new Result<bool, SessionAdapterFailure>.Failure(new(failure.Error.Code, failure.Error.Message)),
            _ => throw new InvalidOperationException("Unsupported session authority validation result.")
        };

    private static Result<T, SessionAdapterFailure> Failure<T>(string code, string message) =>
        new Result<T, SessionAdapterFailure>.Failure(new(code, message));

    private static Result<T, SessionAdapterFailure> Success<T>(T value) =>
        new Result<T, SessionAdapterFailure>.Success(value);

    private sealed record ChildSessionIdempotencyKey(
        ResourceId ParentSessionReference,
        ResourceId AttemptReference,
        string IdempotencyKey);

    private sealed record ParentSessionIdempotencyKey(
        ResourceId AttemptReference,
        string IdempotencyKey,
        ResourceId? ReplacesSessionReference);

    private sealed record ParentSessionReplay(
        AgentSession Session,
        ResourceId AttemptReference,
        CapabilityEnvelope Envelope,
        ResourceId? ReplacesSessionReference);
}

public sealed record SupportedCopilotIntegration(
    string Provider,
    string Version,
    Sha256Digest CapabilityContractDigest,
    ISessionAdapter Adapter);

public static class GitHubCopilotAdapterProfile
{
    public const string Provider = "GitHubCopilot";
    public const string Version = "v1";

    public static Result<ISessionAdapter, SessionAdapterFailure> Create(
        GitHubCopilotSessionProfile expectedProfile,
        SupportedCopilotIntegration? integration)
    {
        if (integration is null ||
            integration.Provider != Provider ||
            integration.Version != Version ||
            integration.CapabilityContractDigest != expectedProfile.ProfileDigest ||
            integration.Adapter is not IDurableSessionAdapter ||
            integration.Adapter is null)
        {
            return new Result<ISessionAdapter, SessionAdapterFailure>.Failure(
                new("supported-local-integration-unavailable", "GitHubCopilot requires a supported local integration with the exact capability contract."));
        }

        return new Result<ISessionAdapter, SessionAdapterFailure>.Success(integration.Adapter);
    }
}

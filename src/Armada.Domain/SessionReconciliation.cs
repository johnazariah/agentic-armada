using System.Collections.Immutable;
using System.Globalization;
using Armada.Contracts;

namespace Armada.Domain;

public enum SessionLiveness
{
    Active,
    Idle,
    Disappeared,
    Terminal,
    Archived
}

public enum SessionObservationKind
{
    Lifecycle,
    Progress,
    PlanDecision,
    Terminal
}

public enum PlanDecision
{
    Approved,
    Rejected
}

public sealed record CapabilityEnvelope(
    Sha256Digest Digest,
    ImmutableHashSet<string> Actions,
    SessionAuthority SessionAuthority);

public sealed record SessionObservation(
    SessionObservationKind Kind,
    ResourceId AgentSessionReference,
    ResourceId AttemptReference,
    Guid CorrelationId,
    Sha256Digest CapabilityEnvelopeDigest,
    DateTimeOffset ObservedAt,
    string Detail,
    TerminalOutcome? TerminalOutcome = null);

public sealed record PlanDecisionObservation(
    SessionObservation Binding,
    PlanDecision Decision,
    ImmutableHashSet<string> RequestedActions);

public sealed record SessionRuntime(
    AgentSession Session,
    SessionLiveness Liveness,
    DateTimeOffset ObservedAt,
    SessionHandoffReceipt? HandoffReceipt = null);

public sealed record SessionHandoffReceipt(
    ResourceId DisappearedSessionReference,
    ResourceId AttemptReference,
    ActorId Successor,
    DateTimeOffset CompletedAt);

public sealed record SessionReconciliationFailure(string Code, string Message);

public sealed record OwnerProtocol(
    ActorId Owner,
    ActorId Successor,
    DateTimeOffset ExpectedNextEventAt,
    DateTimeOffset ProgressDeadlineAt,
    HeartbeatPolicy HeartbeatPolicy,
    ActorId Watchdog);

public sealed record IssueMasterIntent(
    ResourceId NodeReference,
    ResourceId WorkloadReference,
    long WorkloadGeneration,
    ResourceId AttemptReference,
    string IdempotencyKey,
    ResourceId? ReplacesSessionReference);

public abstract record SessionReconciliationAction
{
    private SessionReconciliationAction()
    {
    }

    public sealed record EnsureIssueMaster(IssueMasterIntent Intent) : SessionReconciliationAction;

    public sealed record Wake(ResourceId AgentSessionReference) : SessionReconciliationAction;

    public sealed record Archive(ResourceId AgentSessionReference) : SessionReconciliationAction;

    public sealed record Handoff(ResourceId DisappearedSessionReference, ActorId Successor) : SessionReconciliationAction;

    public sealed record Block(Condition Condition) : SessionReconciliationAction;
}

public sealed record SessionReconciliationInput(
    Node Node,
    Workload Workload,
    AdmissionDecision Admission,
    Attempt? Attempt,
    ImmutableArray<SessionRuntime> Sessions,
    EvidenceReceipt? Evidence,
    DateTimeOffset Now);

public static class SessionAuthorityValidation
{
    public static Result<bool, SessionReconciliationFailure> ValidateOperation(
        AgentSession session,
        Attempt attempt,
        AdmissionDecision admission,
        CapabilityEnvelope envelope,
        DateTimeOffset evaluatedAt)
    {
        if (session.Spec.AttemptReference != attempt.Metadata.Uid ||
            session.Spec.NodeReference != attempt.Spec.NodeReference ||
            attempt.Spec.AdmissionDecisionReference != admission.Metadata.Uid ||
            attempt.Spec.WorkloadReference != admission.Spec.WorkloadReference ||
            attempt.Spec.WorkloadGeneration != admission.Spec.WorkloadGeneration ||
            attempt.Spec.NodeReference != admission.Spec.NodeReference ||
            admission.Status.Decision != AdmissionVerdict.Admitted ||
            admission.Spec.ExpiresAt <= evaluatedAt)
        {
            return Failure("session-operation-authority-mismatch", "A session operation must bind an active session to its admitted attempt and unexpired admission decision.");
        }

        if (envelope.SessionAuthority == Armada.Contracts.SessionAuthority.None ||
            envelope.SessionAuthority > admission.Spec.SessionAuthority ||
            !envelope.Actions.IsSubsetOf(admission.Spec.ApprovedActions))
        {
            return Failure("capability-envelope-outside-admission", "A capability envelope cannot enlarge the admitted session authority or action grant.");
        }

        return new Result<bool, SessionReconciliationFailure>.Success(true);
    }

    public static Result<bool, SessionReconciliationFailure> CanArchive(
        Attempt attempt,
        EvidenceReceipt? evidence)
    {
        if (evidence is null ||
            evidence.Spec.AttemptReference != attempt.Metadata.Uid ||
            evidence.Status.Verification != EvidenceVerification.Verified ||
            evidence.Status.VerifiedAt is null)
        {
            return Failure("independent-evidence-required", "Archival requires independently verified evidence for the session attempt.");
        }

        return new Result<bool, SessionReconciliationFailure>.Success(true);
    }

    public static Result<bool, SessionReconciliationFailure> CanCreateChild(
        AdmissionDecision admission,
        AgentSession parent,
        AgentSession child)
    {
        if (admission.Spec.SessionAuthority != Armada.Contracts.SessionAuthority.IssueMasterWithChildren)
        {
            return Failure("child-session-authority-refused", "Child sessions require IssueMasterWithChildren authority.");
        }

        if (parent.Spec.Role != AgentSessionRole.IssueMaster ||
            child.Spec.Role != AgentSessionRole.Child ||
            child.Spec.ParentSessionReference != parent.Metadata.Uid)
        {
            return Failure("invalid-child-session-binding", "A child must name the admitted Issue Master as its parent.");
        }

        return new Result<bool, SessionReconciliationFailure>.Success(true);
    }

    public static Result<bool, SessionReconciliationFailure> ValidateObservation(
        AgentSession session,
        CapabilityEnvelope envelope,
        SessionObservation observation)
    {
        if (observation.AgentSessionReference != session.Metadata.Uid ||
            observation.AttemptReference != session.Spec.AttemptReference)
        {
            return Failure("session-observation-binding-mismatch", "An observation must bind the exact AgentSession and Attempt.");
        }

        if (observation.CorrelationId == Guid.Empty ||
            observation.CapabilityEnvelopeDigest != envelope.Digest)
        {
            return Failure("capability-envelope-mismatch", "An observation requires a correlation ID and the admitted capability envelope digest.");
        }

        if (string.IsNullOrWhiteSpace(observation.Detail))
        {
            return Failure("invalid-session-observation", "Session observations require an exact detail.");
        }

        if (observation.Kind == SessionObservationKind.Terminal && observation.TerminalOutcome is null)
        {
            return Failure("invalid-terminal-observation", "Terminal observations require a terminal outcome.");
        }

        return new Result<bool, SessionReconciliationFailure>.Success(true);
    }

    public static Result<bool, SessionReconciliationFailure> ValidatePlanDecision(
        AdmissionDecision admission,
        CapabilityEnvelope envelope,
        PlanDecisionObservation observation)
    {
        if (observation.Binding.Kind != SessionObservationKind.PlanDecision)
        {
            return Failure("invalid-plan-observation", "A plan decision must be reported as a plan-decision observation.");
        }

        if (!observation.RequestedActions.IsSubsetOf(admission.Spec.ApprovedActions) ||
            !observation.RequestedActions.IsSubsetOf(envelope.Actions))
        {
            return Failure("plan-action-outside-grant", "A plan cannot approve actions outside the admission and capability envelope.");
        }

        return new Result<bool, SessionReconciliationFailure>.Success(true);
    }

    private static Result<bool, SessionReconciliationFailure> Failure(string code, string message) =>
        new Result<bool, SessionReconciliationFailure>.Failure(new(code, message));
}

public static class MajorDomoReconciliation
{
    public static Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure> Reconcile(
        SessionReconciliationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (input.Workload.Status.Lifecycle == WorkloadLifecycleState.TerminalPending)
        {
            return ReconcileTerminal(input);
        }

        var binding = ValidateBindings(input);
        if (binding is Result<bool, SessionReconciliationFailure>.Failure failure)
        {
            return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Failure(failure.Error);
        }

        var actions = ImmutableArray.CreateBuilder<SessionReconciliationAction>();
        var issueMasters = input.Sessions
            .Where(session =>
                session.Session.Spec.Role == AgentSessionRole.IssueMaster &&
                session.Session.Spec.NodeReference == input.Node.Metadata.Uid &&
                session.Session.Spec.AttemptReference == input.Attempt!.Metadata.Uid &&
                !session.Session.Status.ArchiveComplete &&
                session.Liveness is not SessionLiveness.Archived)
            .OrderBy(session => session.Session.Metadata.Uid.Value)
            .ToImmutableArray();

        var active = issueMasters
            .Where(session => session.Liveness is SessionLiveness.Active or SessionLiveness.Idle)
            .ToImmutableArray();
        if (active.Length > 1)
        {
            actions.Add(new SessionReconciliationAction.Block(Blocked(
                input,
                "multiple active Issue Master sessions exist for the node/workload generation",
                "major-domo",
                "archive duplicate AgentSession resources and retain one Issue Master",
                $"Workload/{input.Workload.Metadata.Uid}",
                "control-plane-operator")));
            return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(actions.ToImmutable());
        }

        if (IsTerminal(input.Workload.Status.Lifecycle))
        {
            return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(actions.ToImmutable());
        }

        if (active.Length == 1)
        {
            if (active[0].Liveness == SessionLiveness.Idle)
            {
                actions.Add(new SessionReconciliationAction.Wake(active[0].Session.Metadata.Uid));
            }

            return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(actions.ToImmutable());
        }

        var disappeared = issueMasters.FirstOrDefault(session => session.Liveness == SessionLiveness.Disappeared);
        if (disappeared is not null)
        {
            var owner = RequireOwnerProtocol(input.Workload, input.Now);
            if (owner is Result<OwnerProtocol, SessionReconciliationFailure>.Failure ownerFailure)
            {
                return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Failure(ownerFailure.Error);
            }

            var successor = ((Result<OwnerProtocol, SessionReconciliationFailure>.Success)owner).Value.Successor;
            if (disappeared.HandoffReceipt is not
                {
                    DisappearedSessionReference: var sessionReference,
                    AttemptReference: var attemptReference,
                    Successor: var receiptSuccessor,
                    CompletedAt: var completedAt
                } ||
                sessionReference != disappeared.Session.Metadata.Uid ||
                attemptReference != input.Attempt!.Metadata.Uid ||
                receiptSuccessor != successor ||
                completedAt > input.Now)
            {
                actions.Add(new SessionReconciliationAction.Handoff(
                    disappeared.Session.Metadata.Uid,
                    successor));
                return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(actions.ToImmutable());
            }
        }

        actions.Add(new SessionReconciliationAction.EnsureIssueMaster(new(
            input.Node.Metadata.Uid,
            input.Workload.Metadata.Uid,
            input.Workload.Metadata.Generation,
            input.Attempt!.Metadata.Uid,
            IssueMasterIdempotencyKey(input.Node.Metadata.Uid, input.Workload.Metadata.Uid, input.Workload.Metadata.Generation),
            disappeared?.Session.Metadata.Uid)));
        return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(actions.ToImmutable());
    }

    public static string IssueMasterIdempotencyKey(ResourceId node, ResourceId workload, long generation) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"issue-master:{node}:{workload}:{generation}");

    private static Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure> ReconcileTerminal(
        SessionReconciliationInput input)
    {
        if (input.Attempt is null ||
            input.Attempt.Spec.WorkloadReference != input.Workload.Metadata.Uid ||
            input.Attempt.Spec.WorkloadGeneration != input.Workload.Metadata.Generation ||
            input.Workload.Status.AttemptReference != input.Attempt.Metadata.Uid)
        {
            return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Failure(
                new("attempt-binding-mismatch", "Terminal session archival requires the attempt bound to the workload generation."));
        }

        var sessions = input.Sessions
            .Where(session =>
                session.Session.Spec.Role == AgentSessionRole.IssueMaster &&
                session.Session.Spec.AttemptReference == input.Attempt.Metadata.Uid &&
                session.Session.Spec.NodeReference == input.Attempt.Spec.NodeReference &&
                !session.Session.Status.ArchiveComplete &&
                session.Liveness is not SessionLiveness.Archived)
            .OrderBy(session => session.Session.Metadata.Uid.Value)
            .Select(session => (SessionReconciliationAction)new SessionReconciliationAction.Archive(session.Session.Metadata.Uid))
            .ToImmutableArray();

        if (HasIndependentlyFinalisedEvidence(input))
        {
            return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(sessions);
        }

        return new Result<ImmutableArray<SessionReconciliationAction>, SessionReconciliationFailure>.Success(
            ImmutableArray.Create<SessionReconciliationAction>(new SessionReconciliationAction.Block(Blocked(
                input,
                "terminal Issue Master session cannot be archived before independently verified evidence exists",
                "evidence-controller",
                "finalise the EvidenceReceipt for the current attempt",
                $"Attempt/{input.Attempt.Metadata.Uid}",
                "evidence-controller"))));
    }

    private static Result<bool, SessionReconciliationFailure> ValidateBindings(SessionReconciliationInput input)
    {
        if (input.Workload.Status.Lifecycle is WorkloadLifecycleState.Desired or WorkloadLifecycleState.Admitted ||
            input.Workload.Status.Lifecycle is WorkloadLifecycleState.Completed or WorkloadLifecycleState.Failed or WorkloadLifecycleState.Cancelled or WorkloadLifecycleState.Expired)
        {
            return Failure("workload-not-session-reconcilable", "Only assigned, claimed, running, or terminal-pending workloads can be reconciled by Major Domo.");
        }

        if (input.Attempt is null ||
            input.Attempt.Spec.WorkloadReference != input.Workload.Metadata.Uid ||
            input.Attempt.Spec.WorkloadGeneration != input.Workload.Metadata.Generation ||
            input.Attempt.Spec.NodeReference != input.Node.Metadata.Uid ||
            input.Attempt.Spec.AdmissionDecisionReference != input.Admission.Metadata.Uid ||
            input.Workload.Status.AttemptReference != input.Attempt.Metadata.Uid)
        {
            return Failure("attempt-binding-mismatch", "Major Domo requires the attempt bound to the assigned workload generation and node.");
        }

        if (input.Admission.Status.Decision != AdmissionVerdict.Admitted ||
            input.Admission.Spec.ExpiresAt <= input.Now ||
            input.Admission.Spec.WorkloadReference != input.Workload.Metadata.Uid ||
            input.Admission.Spec.WorkloadGeneration != input.Workload.Metadata.Generation ||
            input.Admission.Spec.NodeReference != input.Node.Metadata.Uid ||
            input.Admission.Spec.SessionAuthority is not (Armada.Contracts.SessionAuthority.IssueMaster or Armada.Contracts.SessionAuthority.IssueMasterWithChildren))
        {
            return Failure("session-authority-not-admitted", "Major Domo requires an unexpired admission decision for this workload, node, and Issue Master authority.");
        }

        return new Result<bool, SessionReconciliationFailure>.Success(true);
    }

    private static Result<OwnerProtocol, SessionReconciliationFailure> RequireOwnerProtocol(Workload workload, DateTimeOffset now)
    {
        var status = workload.Status;
        if (status.Owner is null ||
            status.Successor is null ||
            status.ExpectedNextEventAt is null ||
            status.ProgressDeadlineAt is null ||
            status.HeartbeatPolicy is null ||
            status.Watchdog is null)
        {
            return new Result<OwnerProtocol, SessionReconciliationFailure>.Failure(
                new("owner-protocol-incomplete", "Disappeared-session recovery requires durable owner, successor, expected event, progress deadline, heartbeat policy, and watchdog bindings."));
        }

        if (status.ProgressDeadlineAt <= now ||
            status.ExpectedNextEventAt > status.ProgressDeadlineAt ||
            status.HeartbeatPolicy.IntervalSeconds <= 0 ||
            status.HeartbeatPolicy.TimeoutSeconds < status.HeartbeatPolicy.IntervalSeconds)
        {
            return new Result<OwnerProtocol, SessionReconciliationFailure>.Failure(
                new("owner-protocol-invalid", "Disappeared-session recovery requires a current, ordered deadline and valid heartbeat policy."));
        }

        return new Result<OwnerProtocol, SessionReconciliationFailure>.Success(new(
            status.Owner,
            status.Successor,
            status.ExpectedNextEventAt.Value,
            status.ProgressDeadlineAt.Value,
            status.HeartbeatPolicy,
            status.Watchdog));
    }

    private static bool HasIndependentlyFinalisedEvidence(SessionReconciliationInput input) =>
        input.Evidence is not null &&
        input.Evidence.Spec.AttemptReference == input.Attempt!.Metadata.Uid &&
        input.Evidence.Status.Verification == EvidenceVerification.Verified &&
        input.Evidence.Status.VerifiedAt is not null;

    private static bool IsTerminal(WorkloadLifecycleState lifecycle) =>
        lifecycle is WorkloadLifecycleState.Completed or WorkloadLifecycleState.Failed or WorkloadLifecycleState.Cancelled or WorkloadLifecycleState.Expired;

    private static Condition Blocked(
        SessionReconciliationInput input,
        string exactBlocker,
        string actor,
        string requiredAction,
        string location,
        string successor) =>
        ((Result<Condition, ContractValidationError>.Success)Condition.Create(
            "Blocked",
            ConditionStatus.True,
            "session-reconciliation-blocked",
            exactBlocker,
            input.Workload.Metadata.Generation,
            input.Now,
            ((Result<BlockedEscalation, ContractValidationError>.Success)BlockedEscalation.Create(
                exactBlocker,
                new ActorId(actor),
                requiredAction,
                location,
                new ActorId(successor),
                input.Now.AddMinutes(15))).Value)).Value;

    private static Result<bool, SessionReconciliationFailure> Failure(string code, string message) =>
        new Result<bool, SessionReconciliationFailure>.Failure(new(code, message));
}

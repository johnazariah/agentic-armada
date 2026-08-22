using System.Collections.Immutable;
using System.Globalization;
using Armada.Contracts;

namespace Armada.Domain;

public enum TerminalOutcome
{
    Completed,
    Failed,
    Cancelled,
    Expired
}

public sealed record LifecycleFailure(string Code, string Message);

public sealed record AppliedTransition(
    TransitionId Id,
    string CanonicalPayload);

public sealed record WorkloadLifecycle(
    ResourceId WorkloadId,
    long Generation,
    ResourceVersion ResourceVersion,
    WorkloadLifecycleState State,
    ResourceId? AdmissionDecisionReference,
    ResourceId? AdmittedNodeReference,
    SessionAuthority? AdmittedSessionAuthority,
    Sha256Digest? AdmittedBundleDigest,
    Sha256Digest? AdmittedPolicyDigest,
    ImmutableArray<Sha256Digest> AdmittedCapabilityGrantDigests,
    DateTimeOffset? AdmissionExpiresAt,
    ResourceId? AssignedNodeReference,
    ResourceId? AttemptReference,
    ResourceId? LeaseReference,
    ResourceId? RunningSessionReference,
    TerminalOutcome? PendingOutcome,
    ImmutableArray<AppliedTransition> AppliedTransitions)
{
    public static WorkloadLifecycle Desired(
        ResourceId workloadId,
        long generation,
        ResourceVersion resourceVersion) =>
        new(
            workloadId,
            generation,
            resourceVersion,
            WorkloadLifecycleState.Desired,
            null,
            null,
            null,
            null,
            null,
            ImmutableArray<Sha256Digest>.Empty,
            null,
            null,
            null,
            null,
            null,
            null,
            ImmutableArray<AppliedTransition>.Empty);
}

public abstract record LifecycleCommand(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration)
{
    public abstract WorkloadLifecycleState Target { get; }
}

public sealed record AdmitWorkload(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    AdmissionDecision Decision,
    DateTimeOffset EvaluatedAt)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => WorkloadLifecycleState.Admitted;
}

public sealed record AssignWorkload(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    ResourceId NodeReference)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => WorkloadLifecycleState.Assigned;
}

public sealed record ClaimWorkload(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    Attempt Attempt)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => WorkloadLifecycleState.Claimed;
}

public sealed record ApproveStart(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    Lease Lease,
    DateTimeOffset EvaluatedAt)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => WorkloadLifecycleState.StartApproved;
}

public sealed record StartWorkload(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    AgentSession Session,
    Lease Lease,
    DateTimeOffset EvaluatedAt)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => WorkloadLifecycleState.Running;
}

public sealed record SubmitTerminalObservation(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    TerminalOutcome Outcome,
    ResourceId ObservingSessionReference)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => WorkloadLifecycleState.TerminalPending;
}

public sealed record FinaliseTerminalState(
    TransitionId Id,
    ResourceVersion ExpectedResourceVersion,
    ResourceVersion ResultingResourceVersion,
    long ExpectedGeneration,
    TerminalOutcome Outcome,
    EvidenceReceipt Evidence)
    : LifecycleCommand(Id, ExpectedResourceVersion, ResultingResourceVersion, ExpectedGeneration)
{
    public override WorkloadLifecycleState Target => Outcome switch
    {
        TerminalOutcome.Completed => WorkloadLifecycleState.Completed,
        TerminalOutcome.Failed => WorkloadLifecycleState.Failed,
        TerminalOutcome.Cancelled => WorkloadLifecycleState.Cancelled,
        TerminalOutcome.Expired => WorkloadLifecycleState.Expired,
        _ => throw new ArgumentOutOfRangeException(nameof(Outcome), Outcome, "Unknown terminal outcome.")
    };
}

public static class WorkloadLifecycleTransitions
{
    public static Result<WorkloadLifecycle, LifecycleFailure> Apply(
        WorkloadLifecycle lifecycle,
        LifecycleCommand command)
    {
        var replay = lifecycle.AppliedTransitions.FirstOrDefault(applied => applied.Id == command.Id);
        var canonicalPayload = LifecycleCommandIdentity.Create(command);
        if (replay is not null)
        {
            return replay.CanonicalPayload == canonicalPayload
                ? new Result<WorkloadLifecycle, LifecycleFailure>.Success(lifecycle)
                : Failure(
                    "transition-replay-conflict",
                    $"Transition {command.Id} was already applied with different command bindings.");
        }

        if (command.ExpectedGeneration != lifecycle.Generation)
        {
            return Failure(
                "stale-generation",
                $"Expected generation {command.ExpectedGeneration} does not match workload generation {lifecycle.Generation}.");
        }

        if (command.ExpectedResourceVersion != lifecycle.ResourceVersion)
        {
            return Failure(
                "stale-resource-version",
                $"Expected resource version {command.ExpectedResourceVersion} does not match {lifecycle.ResourceVersion}.");
        }

        if (command.ResultingResourceVersion == lifecycle.ResourceVersion)
        {
            return Failure(
                "unchanged-resource-version",
                "A successful transition must produce a distinct resource version.");
        }

        return command switch
        {
            AdmitWorkload admit => ApplyAdmission(lifecycle, admit),
            AssignWorkload assign => ApplyAssignment(lifecycle, assign),
            ClaimWorkload claim => ApplyClaim(lifecycle, claim),
            ApproveStart approve => ApplyStartApproval(lifecycle, approve),
            StartWorkload start => ApplyStart(lifecycle, start),
            SubmitTerminalObservation terminal => ApplyTerminalObservation(lifecycle, terminal),
            FinaliseTerminalState finalise => ApplyFinalisation(lifecycle, finalise),
            _ => Failure("unknown-command", $"The command {command.GetType().Name} is not supported.")
        };
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyAdmission(
        WorkloadLifecycle lifecycle,
        AdmitWorkload command)
    {
        if (lifecycle.State != WorkloadLifecycleState.Desired)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        var decision = command.Decision;
        if (decision.Status.Decision != AdmissionVerdict.Admitted ||
            decision.Spec.WorkloadReference != lifecycle.WorkloadId ||
            decision.Spec.WorkloadGeneration != lifecycle.Generation ||
            decision.Spec.ExpiresAt <= command.EvaluatedAt)
        {
            return Failure(
                "invalid-admission-decision",
                "Admission requires an unexpired admitted decision bound to this workload generation.");
        }

        return Succeed(
            lifecycle,
            command,
            WorkloadLifecycleState.Admitted,
            admissionDecisionReference: decision.Metadata.Uid,
            admittedNodeReference: decision.Spec.NodeReference,
            admittedSessionAuthority: decision.Spec.SessionAuthority,
            admittedBundleDigest: decision.Spec.BundleDigest,
            admittedPolicyDigest: decision.Spec.PolicyDigest,
            admittedCapabilityGrantDigests: decision.Spec.CredentialGrantDigests,
            admissionExpiresAt: decision.Spec.ExpiresAt);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyAssignment(
        WorkloadLifecycle lifecycle,
        AssignWorkload command)
    {
        if (lifecycle.State != WorkloadLifecycleState.Admitted)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        if (lifecycle.AdmittedNodeReference != command.NodeReference)
        {
            return Failure(
                "assignment-outside-admission",
                "Assignment must use the node bound by the admitted decision.");
        }

        return Succeed(
            lifecycle,
            command,
            WorkloadLifecycleState.Assigned,
            assignedNodeReference: command.NodeReference);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyClaim(
        WorkloadLifecycle lifecycle,
        ClaimWorkload command)
    {
        if (lifecycle.State != WorkloadLifecycleState.Assigned)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        var attempt = command.Attempt;
        if (lifecycle.AdmissionDecisionReference is null ||
            lifecycle.AssignedNodeReference is null ||
            lifecycle.AdmittedBundleDigest is null ||
            lifecycle.AdmittedPolicyDigest is null ||
            attempt.Spec.WorkloadReference != lifecycle.WorkloadId ||
            attempt.Spec.WorkloadGeneration != lifecycle.Generation ||
            attempt.Spec.NodeReference != lifecycle.AssignedNodeReference ||
            attempt.Spec.AdmissionDecisionReference != lifecycle.AdmissionDecisionReference ||
            attempt.Spec.BundleDigest != lifecycle.AdmittedBundleDigest ||
            attempt.Spec.PolicyDigest != lifecycle.AdmittedPolicyDigest ||
            !lifecycle.AdmittedCapabilityGrantDigests.Contains(attempt.Spec.CapabilityGrantDigest))
        {
            return Failure(
                "invalid-attempt-binding",
                "Claim requires an attempt bound to the workload generation, selected node, admitted decision, bundle, policy, and approved capability grant.");
        }

        return Succeed(
            lifecycle,
            command,
            WorkloadLifecycleState.Claimed,
            attemptReference: attempt.Metadata.Uid);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyStartApproval(
        WorkloadLifecycle lifecycle,
        ApproveStart command)
    {
        if (lifecycle.State != WorkloadLifecycleState.Claimed)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        var lease = command.Lease;
        if (lifecycle.AttemptReference is null ||
            lifecycle.AssignedNodeReference is null ||
            lifecycle.AdmissionExpiresAt is null ||
            lifecycle.AdmissionExpiresAt <= command.EvaluatedAt ||
            lease.Spec.ExpiresAt > lifecycle.AdmissionExpiresAt ||
            lease.Spec.AttemptReference != lifecycle.AttemptReference ||
            lease.Spec.NodeReference != lifecycle.AssignedNodeReference ||
            lease.Spec.ExpiresAt <= command.EvaluatedAt ||
            lease.Status.RevokedAt is not null)
        {
            return Failure(
                "invalid-lease-binding",
                "Start approval requires unexpired admission authority and a current, unrevoked lease bound to the claimed attempt and assigned node.");
        }

        return Succeed(
            lifecycle,
            command,
            WorkloadLifecycleState.StartApproved,
            leaseReference: lease.Metadata.Uid);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyStart(
        WorkloadLifecycle lifecycle,
        StartWorkload command)
    {
        if (lifecycle.State != WorkloadLifecycleState.StartApproved)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        var session = command.Session;
        if (lifecycle.AttemptReference is null ||
            lifecycle.AssignedNodeReference is null ||
            session.Spec.AttemptReference != lifecycle.AttemptReference ||
            session.Spec.NodeReference != lifecycle.AssignedNodeReference ||
            session.Spec.Role != AgentSessionRole.IssueMaster)
        {
            return Failure(
                "invalid-session-binding",
                "Running requires an Issue Master session bound to the claimed attempt and assigned node.");
        }

        if (lifecycle.AdmittedSessionAuthority is not (
            SessionAuthority.IssueMaster or SessionAuthority.IssueMasterWithChildren))
        {
            return Failure(
                "session-authority-not-admitted",
                "Running requires Issue Master authority in the admitted decision.");
        }

        var lease = command.Lease;
        if (lifecycle.LeaseReference is null ||
            lifecycle.AdmissionExpiresAt is null ||
            lifecycle.AdmissionExpiresAt <= command.EvaluatedAt ||
            lease.Spec.ExpiresAt > lifecycle.AdmissionExpiresAt ||
            lease.Metadata.Uid != lifecycle.LeaseReference ||
            lease.Spec.AttemptReference != lifecycle.AttemptReference ||
            lease.Spec.NodeReference != lifecycle.AssignedNodeReference ||
            lease.Spec.ExpiresAt <= command.EvaluatedAt ||
            lease.Status.RevokedAt is not null)
        {
            return Failure(
                "invalid-lease-binding",
                "Running requires unexpired admission authority and the current, unrevoked lease approved for the claimed attempt and assigned node.");
        }

        return Succeed(
            lifecycle,
            command,
            WorkloadLifecycleState.Running,
            runningSessionReference: session.Metadata.Uid);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyTerminalObservation(
        WorkloadLifecycle lifecycle,
        SubmitTerminalObservation command)
    {
        if (lifecycle.State != WorkloadLifecycleState.Running)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        if (lifecycle.RunningSessionReference != command.ObservingSessionReference)
        {
            return Failure(
                "invalid-terminal-observer",
                "Terminal observations must come from the running Issue Master session.");
        }

        return Succeed(
            lifecycle,
            command,
            WorkloadLifecycleState.TerminalPending,
            pendingOutcome: command.Outcome);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> ApplyFinalisation(
        WorkloadLifecycle lifecycle,
        FinaliseTerminalState command)
    {
        if (lifecycle.State != WorkloadLifecycleState.TerminalPending)
        {
            return InvalidPredecessor(lifecycle, command);
        }

        if (lifecycle.PendingOutcome != command.Outcome)
        {
            return Failure(
                "terminal-outcome-mismatch",
                "Finalisation must match the pending terminal observation.");
        }

        if (lifecycle.AttemptReference is null ||
            command.Evidence.Spec.AttemptReference != lifecycle.AttemptReference ||
            command.Evidence.Status.Verification != EvidenceVerification.Verified ||
            command.Evidence.Status.VerifiedAt is null)
        {
            return Failure(
                "independent-evidence-required",
                "Terminalisation requires an independently verified evidence receipt for the claimed attempt.");
        }

        return Succeed(lifecycle, command, command.Target, pendingOutcome: null);
    }

    private static Result<WorkloadLifecycle, LifecycleFailure> Succeed(
        WorkloadLifecycle lifecycle,
        LifecycleCommand command,
        WorkloadLifecycleState state,
        ResourceId? admissionDecisionReference = null,
        ResourceId? admittedNodeReference = null,
        SessionAuthority? admittedSessionAuthority = null,
        Sha256Digest? admittedBundleDigest = null,
        Sha256Digest? admittedPolicyDigest = null,
        ImmutableArray<Sha256Digest>? admittedCapabilityGrantDigests = null,
        DateTimeOffset? admissionExpiresAt = null,
        ResourceId? assignedNodeReference = null,
        ResourceId? attemptReference = null,
        ResourceId? leaseReference = null,
        ResourceId? runningSessionReference = null,
        TerminalOutcome? pendingOutcome = null) =>
        new Result<WorkloadLifecycle, LifecycleFailure>.Success(
            lifecycle with
            {
                ResourceVersion = command.ResultingResourceVersion,
                State = state,
                AdmissionDecisionReference = admissionDecisionReference ?? lifecycle.AdmissionDecisionReference,
                AdmittedNodeReference = admittedNodeReference ?? lifecycle.AdmittedNodeReference,
                AdmittedSessionAuthority = admittedSessionAuthority ?? lifecycle.AdmittedSessionAuthority,
                AdmittedBundleDigest = admittedBundleDigest ?? lifecycle.AdmittedBundleDigest,
                AdmittedPolicyDigest = admittedPolicyDigest ?? lifecycle.AdmittedPolicyDigest,
                AdmittedCapabilityGrantDigests = admittedCapabilityGrantDigests ?? lifecycle.AdmittedCapabilityGrantDigests,
                AdmissionExpiresAt = admissionExpiresAt ?? lifecycle.AdmissionExpiresAt,
                AssignedNodeReference = assignedNodeReference ?? lifecycle.AssignedNodeReference,
                AttemptReference = attemptReference ?? lifecycle.AttemptReference,
                LeaseReference = leaseReference ?? lifecycle.LeaseReference,
                RunningSessionReference = runningSessionReference ?? lifecycle.RunningSessionReference,
                PendingOutcome = pendingOutcome,
                AppliedTransitions = lifecycle.AppliedTransitions.Add(
                    new(command.Id, LifecycleCommandIdentity.Create(command)))
            });

    private static Result<WorkloadLifecycle, LifecycleFailure> InvalidPredecessor(
        WorkloadLifecycle lifecycle,
        LifecycleCommand command) =>
        Failure(
            "invalid-predecessor",
            $"Cannot apply {command.Target} while workload is {lifecycle.State}.");

    private static Result<WorkloadLifecycle, LifecycleFailure> Failure(
        string code,
        string message) =>
        new Result<WorkloadLifecycle, LifecycleFailure>.Failure(new(code, message));
}

internal static class LifecycleCommandIdentity
{
    public static string Create(LifecycleCommand command) =>
        Combine(
            command.GetType().Name,
            command.Id.ToString(),
            command.ExpectedResourceVersion.Value,
            command.ResultingResourceVersion.Value,
            Number(command.ExpectedGeneration),
            command switch
            {
                AdmitWorkload admit => Admission(admit),
                AssignWorkload assign => assign.NodeReference.ToString(),
                ClaimWorkload claim => Attempt(claim.Attempt),
                ApproveStart approve => Combine(Lease(approve.Lease), Timestamp(approve.EvaluatedAt)),
                StartWorkload start => Combine(Session(start.Session), Lease(start.Lease), Timestamp(start.EvaluatedAt)),
                SubmitTerminalObservation terminal => Combine(
                    terminal.Outcome.ToString(),
                    terminal.ObservingSessionReference.ToString()),
                FinaliseTerminalState finalise => Combine(
                    finalise.Outcome.ToString(),
                    Evidence(finalise.Evidence)),
                _ => throw new ArgumentOutOfRangeException(nameof(command), command, "Unsupported lifecycle command.")
            });

    private static string Admission(AdmitWorkload command)
    {
        var decision = command.Decision;
        var spec = decision.Spec;

        return Combine(
            decision.Metadata.Uid.ToString(),
            spec.WorkloadReference.ToString(),
            Number(spec.WorkloadGeneration),
            spec.NodeReference.ToString(),
            spec.BundleDigest.Value,
            spec.PolicyDigest.Value,
            Values(spec.ApprovedActions),
            spec.SessionAuthority.ToString(),
            spec.IsolationProfile.ToString(),
            Resources(spec.ResourceLimits),
            Values(spec.CredentialGrantDigests.Select(static digest => digest.Value)),
            Values(spec.NetworkScope),
            spec.EvidenceRequirementsDigest.Value,
            Timestamp(spec.ExpiresAt),
            decision.Status.Decision.ToString(),
            decision.Status.DecisionDigest?.Value,
            Timestamp(command.EvaluatedAt));
    }

    private static string Attempt(Attempt attempt)
    {
        var spec = attempt.Spec;

        return Combine(
            attempt.Metadata.Uid.ToString(),
            spec.WorkloadReference.ToString(),
            Number(spec.WorkloadGeneration),
            spec.NodeReference.ToString(),
            spec.AdmissionDecisionReference.ToString(),
            spec.BundleDigest.Value,
            spec.PolicyDigest.Value,
            spec.CapabilityGrantDigest.Value,
            spec.EnvironmentDigest.Value);
    }

    private static string Lease(Lease lease)
    {
        var spec = lease.Spec;

        return Combine(
            lease.Metadata.Uid.ToString(),
            spec.AttemptReference.ToString(),
            spec.NodeReference.ToString(),
            Number(spec.HolderEpoch),
            Timestamp(spec.ExpiresAt),
            Timestamp(lease.Status.RevokedAt));
    }

    private static string Session(AgentSession session)
    {
        var spec = session.Spec;

        return Combine(
            session.Metadata.Uid.ToString(),
            spec.AttemptReference.ToString(),
            spec.NodeReference.ToString(),
            spec.Provider.ProfileDigest.Value,
            spec.Role.ToString(),
            spec.IdempotencyKey,
            spec.ParentSessionReference?.ToString());
    }

    private static string Evidence(EvidenceReceipt evidence)
    {
        var spec = evidence.Spec;

        return Combine(
            evidence.Metadata.Uid.ToString(),
            spec.AttemptReference.ToString(),
            spec.ManifestDigest.Value,
            spec.Archive.Repository.Value,
            spec.ReleaseId,
            spec.AssetDigest.Value,
            evidence.Status.Verification.ToString(),
            Timestamp(evidence.Status.VerifiedAt));
    }

    private static string Resources(ResourceRequirements resources) =>
        Combine(
            Number(resources.CpuMillicores),
            Number(resources.GpuCount),
            Number(resources.MemoryBytes),
            Number(resources.StorageBytes));

    private static string Values(IEnumerable<string> values) =>
        Combine(values.OrderBy(static value => value, StringComparer.Ordinal).ToArray());

    private static string? Timestamp(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static string Number<TNumber>(TNumber value)
        where TNumber : IFormattable =>
        value.ToString(null, CultureInfo.InvariantCulture);

    private static string Combine(params string?[] values) =>
        string.Concat(values.Select(static value =>
            $"{value?.Length ?? -1}:{value ?? string.Empty};"));
}

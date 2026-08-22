using System.Collections.Immutable;
using Armada.Contracts;
using Armada.Domain;

namespace Armada.Domain.Tests;

public sealed class WorkloadLifecycleTests
{
    [Fact]
    public void Valid_lifecycle_reaches_completed_only_after_verified_evidence()
    {
        var fixture = new LifecycleFixture();
        var lifecycle = fixture.ProgressToTerminalPending(TerminalOutcome.Completed);

        var completed = Apply(
            lifecycle,
            fixture.Finalise(
                lifecycle,
                TerminalOutcome.Completed,
                fixture.Evidence(verified: true)));

        Assert.Equal(WorkloadLifecycleState.Completed, completed.State);
        Assert.Null(completed.PendingOutcome);
        Assert.Equal(7, completed.AppliedTransitions.Length);
    }

    [Fact]
    public void Terminalisation_rejects_unverified_evidence()
    {
        var fixture = new LifecycleFixture();
        var lifecycle = fixture.ProgressToTerminalPending(TerminalOutcome.Failed);

        var result = WorkloadLifecycleTransitions.Apply(
            lifecycle,
            fixture.Finalise(
                lifecycle,
                TerminalOutcome.Failed,
                fixture.Evidence(verified: false)));

        var failure = Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Failure>(result);

        Assert.Equal("independent-evidence-required", failure.Error.Code);
    }

    [Fact]
    public void Stale_resource_version_is_rejected_before_transition()
    {
        var fixture = new LifecycleFixture();
        var lifecycle = fixture.Desired();
        var command = fixture.Admit(lifecycle) with
        {
            ExpectedResourceVersion = new ResourceVersion("stale")
        };

        var result = WorkloadLifecycleTransitions.Apply(lifecycle, command);

        var failure = Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Failure>(result);
        Assert.Equal("stale-resource-version", failure.Error.Code);
    }

    [Fact]
    public void Replaying_the_same_transition_is_idempotent_but_cannot_change_its_target()
    {
        var fixture = new LifecycleFixture();
        var desired = fixture.Desired();
        var admission = fixture.Admit(desired);
        var admitted = Apply(desired, admission);

        var replay = Apply(admitted, admission);
        var conflictingReplay = WorkloadLifecycleTransitions.Apply(
            admitted,
            new AssignWorkload(
                admission.Id,
                admitted.ResourceVersion,
                new ResourceVersion("2"),
                admitted.Generation,
                fixture.NodeId));

        Assert.Equal(admitted, replay);
        Assert.Single(replay.AppliedTransitions);
        Assert.Equal(
            "transition-replay-conflict",
            Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Failure>(conflictingReplay).Error.Code);
    }

    [Fact]
    public void Assignment_outside_the_admitted_node_is_rejected()
    {
        var fixture = new LifecycleFixture();
        var desired = fixture.Desired();
        var admitted = Apply(desired, fixture.Admit(desired));
        var command = fixture.Assign(admitted) with
        {
            NodeReference = ResourceId.New()
        };

        var result = WorkloadLifecycleTransitions.Apply(admitted, command);

        Assert.Equal(
            "assignment-outside-admission",
            Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Skipping_a_lifecycle_predecessor_is_rejected()
    {
        var fixture = new LifecycleFixture();
        var lifecycle = fixture.Desired();

        var result = WorkloadLifecycleTransitions.Apply(lifecycle, fixture.Claim(lifecycle));

        Assert.Equal(
            "invalid-predecessor",
            Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Failure>(result).Error.Code);
    }

    [Theory]
    [InlineData(WorkloadLifecycleState.Desired)]
    [InlineData(WorkloadLifecycleState.Admitted)]
    [InlineData(WorkloadLifecycleState.Assigned)]
    [InlineData(WorkloadLifecycleState.Claimed)]
    [InlineData(WorkloadLifecycleState.StartApproved)]
    [InlineData(WorkloadLifecycleState.Running)]
    [InlineData(WorkloadLifecycleState.Completed)]
    [InlineData(WorkloadLifecycleState.Failed)]
    [InlineData(WorkloadLifecycleState.Cancelled)]
    [InlineData(WorkloadLifecycleState.Expired)]
    public void Terminal_states_are_reachable_only_from_terminal_pending(WorkloadLifecycleState state)
    {
        var fixture = new LifecycleFixture();
        var lifecycle = fixture.Desired() with { State = state };
        var command = fixture.Finalise(lifecycle, TerminalOutcome.Completed, fixture.Evidence(verified: true));

        var result = WorkloadLifecycleTransitions.Apply(lifecycle, command);

        Assert.Equal(
            "invalid-predecessor",
            Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Failure>(result).Error.Code);
    }

    private static WorkloadLifecycle Apply(
        WorkloadLifecycle lifecycle,
        LifecycleCommand command) =>
        Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Success>(
            WorkloadLifecycleTransitions.Apply(lifecycle, command)).Value;
}

internal sealed class LifecycleFixture
{
    private static readonly Sha256Digest Digest =
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string('a', 64)}")).Value;

    public ResourceId WorkloadId { get; } = ResourceId.New();
    public ResourceId NodeId { get; } = ResourceId.New();
    public ResourceId DecisionId { get; } = ResourceId.New();
    public ResourceId AttemptId { get; } = ResourceId.New();
    public ResourceId LeaseId { get; } = ResourceId.New();
    public ResourceId SessionId { get; } = ResourceId.New();

    public WorkloadLifecycle Desired() =>
        WorkloadLifecycle.Desired(WorkloadId, 1, new ResourceVersion("0"));

    public AdmitWorkload Admit(WorkloadLifecycle lifecycle) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            new AdmissionDecision(
                Metadata(DecisionId),
                new AdmissionDecisionSpec(
                    WorkloadId,
                    lifecycle.Generation,
                    NodeId,
                    Digest,
                    Digest,
                    ImmutableHashSet.Create("create-worktree"),
                    SessionAuthority.IssueMaster,
                    IsolationProfile.IsolatedContainer,
                    new ResourceRequirements(1000, 0, 1024, 1024),
                    ImmutableArray<Sha256Digest>.Empty,
                    ImmutableHashSet<string>.Empty,
                    Digest,
                    DateTimeOffset.Parse("2030-01-01T00:00:00Z")),
                new AdmissionDecisionStatus(CommonStatus(), AdmissionVerdict.Admitted, Digest)),
            DateTimeOffset.Parse("2029-01-01T00:00:00Z"));

    public AssignWorkload Assign(WorkloadLifecycle lifecycle) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            NodeId);

    public ClaimWorkload Claim(WorkloadLifecycle lifecycle) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            new Attempt(
                Metadata(AttemptId),
                new AttemptSpec(
                    WorkloadId,
                    lifecycle.Generation,
                    NodeId,
                    DecisionId,
                    Digest,
                    Digest,
                    Digest,
                    Digest),
                new AttemptStatus(CommonStatus(), null)));

    public ApproveStart Approve(WorkloadLifecycle lifecycle) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            new Lease(
                Metadata(LeaseId),
                new LeaseSpec(AttemptId, NodeId, 1, DateTimeOffset.Parse("2030-01-01T00:00:00Z")),
                new LeaseStatus(CommonStatus(), null, null)),
            DateTimeOffset.Parse("2029-01-01T00:00:00Z"));

    public StartWorkload Start(WorkloadLifecycle lifecycle) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            new AgentSession(
                Metadata(SessionId),
                new AgentSessionSpec(
                    AttemptId,
                    NodeId,
                    new GitHubCopilotSessionProfile(Digest),
                    AgentSessionRole.IssueMaster,
                    "issue-master-1",
                    null),
                new AgentSessionStatus(CommonStatus(), null, null, null, false)));

    public SubmitTerminalObservation SubmitTerminal(WorkloadLifecycle lifecycle, TerminalOutcome outcome) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            outcome,
            SessionId);

    public FinaliseTerminalState Finalise(
        WorkloadLifecycle lifecycle,
        TerminalOutcome outcome,
        EvidenceReceipt evidence) =>
        new(
            TransitionId.New(),
            lifecycle.ResourceVersion,
            NextVersion(lifecycle),
            lifecycle.Generation,
            outcome,
            evidence);

    public EvidenceReceipt Evidence(bool verified) =>
        new(
            Metadata(ResourceId.New()),
            new EvidenceReceiptSpec(
                AttemptId,
                Digest,
                new GitHubReleaseEvidenceArchiveProfile(
                    Assert.IsType<Result<RepositoryName, ContractValidationError>.Success>(
                        RepositoryName.Parse("johnazariah/agentic-armada-evidence")).Value),
                "release-1",
                Digest),
            new EvidenceReceiptStatus(
                CommonStatus(),
                verified ? EvidenceVerification.Verified : EvidenceVerification.Pending,
                verified ? DateTimeOffset.Parse("2029-01-01T00:00:00Z") : null));

    public WorkloadLifecycle ProgressToTerminalPending(TerminalOutcome outcome)
    {
        var desired = Desired();
        var admitted = Apply(desired, Admit(desired));
        var assigned = Apply(admitted, Assign(admitted));
        var claimed = Apply(assigned, Claim(assigned));
        var approved = Apply(claimed, Approve(claimed));
        var running = Apply(approved, Start(approved));

        return Apply(running, SubmitTerminal(running, outcome));
    }

    private static ResourceVersion NextVersion(WorkloadLifecycle lifecycle) =>
        new((int.Parse(lifecycle.ResourceVersion.Value) + 1).ToString());

    private static ResourceMetadata Metadata(ResourceId id) =>
        new(
            id,
            new OrganisationId(Guid.Parse("11111111-1111-1111-1111-111111111111")),
            new ProjectId(Guid.Parse("22222222-2222-2222-2222-222222222222")),
            "test-resource",
            new ResourceVersion("resource"),
            1,
            ImmutableDictionary<string, string>.Empty,
            ImmutableDictionary<string, string>.Empty,
            ImmutableArray<OwnerReference>.Empty,
            ImmutableArray<string>.Empty,
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"));

    private static ResourceStatus CommonStatus() =>
        new(1, ImmutableArray<Condition>.Empty);

    private static WorkloadLifecycle Apply(WorkloadLifecycle lifecycle, LifecycleCommand command) =>
        Assert.IsType<Result<WorkloadLifecycle, LifecycleFailure>.Success>(
            WorkloadLifecycleTransitions.Apply(lifecycle, command)).Value;
}

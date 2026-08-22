using System.Collections.Immutable;
using Armada.Contracts;
using Armada.NodeAgent;

namespace Armada.NodeAgent.Tests;

public sealed class NodeAgentBoundaryTests
{
    [Fact]
    public async Task Restart_reconciles_the_durable_snapshot_and_exact_replays_are_idempotent()
    {
        var fixture = new NodeAgentFixture();
        var journal = new InMemoryJournal();
        var first = fixture.Boundary(journal);
        var command = fixture.StartEnvelope(sequence: 1);

        var accepted = await first.ReceiveAsync(command, CancellationToken.None);
        var restarted = fixture.Boundary(journal);
        var snapshot = await restarted.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None);
        var retransmission = command with { MessageId = Guid.NewGuid(), CorrelationId = Guid.NewGuid() };
        var duplicate = await restarted.ReceiveAsync(retransmission, CancellationToken.None);

        Assert.True(Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(accepted).Value.Accepted);
        var reconciled = Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(snapshot).Value;
        Assert.Equal(1, reconciled.LastInboundSequence);
        Assert.Single(reconciled.Attempts);
        Assert.Equal(AttemptExecutionState.Prepared, reconciled.Attempts.Single().State);
        var acknowledgement = Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(duplicate).Value;
        Assert.True(acknowledgement.Accepted);
        Assert.True(acknowledgement.Duplicate);
        Assert.Equal(retransmission.MessageId, acknowledgement.MessageId);
        Assert.Equal(retransmission.CorrelationId, acknowledgement.CorrelationId);
    }

    [Fact]
    public async Task Stale_sequences_and_conflicting_idempotency_keys_are_rejected()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());
        var command = fixture.StartEnvelope(sequence: 2);

        await boundary.ReceiveAsync(command, CancellationToken.None);
        var stale = await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1, idempotencyKey: "different"), CancellationToken.None);
        var conflict = await boundary.ReceiveAsync(
            fixture.StartEnvelope(sequence: 3, idempotencyKey: command.IdempotencyKey, profile: IsolationProfile.DedicatedNode),
            CancellationToken.None);

        Assert.Equal(
            "stale-or-replayed-sequence",
            Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(stale).Value.Code);
        Assert.Equal(
            "idempotency-conflict",
            Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(conflict).Value.Code);
    }

    [Theory]
    [InlineData("invalid-signature", "authority-invalid-signature")]
    [InlineData("unknown-key", "authority-unknown-key")]
    public async Task Unverified_authority_is_rejected_fail_closed(string verifierCode, string expectedCode)
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(
            new InMemoryJournal(),
            new DeterministicVerifier(new(false, verifierCode, "Verification failed.")));

        var result = await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);

        Assert.Equal(
            expectedCode,
            Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(result).Value.Code);
    }

    [Fact]
    public async Task Mismatched_expired_unknown_and_unsupported_commands_are_rejected()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());
        var wrongIdentity = fixture.StartEnvelope(sequence: 1) with { NodeId = ResourceId.New() };
        var expired = fixture.StartEnvelope(sequence: 2, expiresAt: fixture.Now.AddSeconds(-1));
        var unknown = new OutboundEnvelope<NodeCommand>(
            NodeAgentProtocol.Version,
            fixture.Identity.NodeId,
            fixture.Identity.IdentityEpoch,
            1,
            3,
            Guid.NewGuid(),
            Guid.NewGuid(),
            "unknown-schema",
            fixture.Now,
            new UnsupportedNodeCommand("future-command/v2", fixture.Identity.NodeId, fixture.ProjectId, fixture.AttemptId, fixture.Now.AddMinutes(5)));
        var unsupportedProfile = fixture.StartEnvelope(sequence: 4, profile: IsolationProfile.EphemeralVm);

        var identityResult = await boundary.ReceiveAsync(wrongIdentity, CancellationToken.None);
        var expiredResult = await boundary.ReceiveAsync(expired, CancellationToken.None);
        var unknownResult = await boundary.ReceiveAsync(unknown, CancellationToken.None);
        var profileResult = await boundary.ReceiveAsync(unsupportedProfile, CancellationToken.None);

        Assert.Equal("node-identity-mismatch", Value(identityResult).Code);
        Assert.Equal("expired-authority", Value(expiredResult).Code);
        Assert.Equal("unknown-command-schema", Value(unknownResult).Code);
        Assert.Equal("unsupported-isolation-profile", Value(profileResult).Code);
    }

    [Fact]
    public async Task Wrong_node_binding_is_audited_without_advancing_the_local_replay_window()
    {
        var fixture = new NodeAgentFixture();
        var journal = new InMemoryJournal();
        var boundary = fixture.Boundary(journal);
        var wrongBinding = fixture.StartEnvelope(sequence: 1) with { NodeId = ResourceId.New() };

        var rejected = await boundary.ReceiveAsync(wrongBinding, CancellationToken.None);
        var accepted = await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);
        var restarted = fixture.Boundary(journal);
        var snapshot = await restarted.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None);

        Assert.Equal("node-identity-mismatch", Value(rejected).Code);
        Assert.True(Value(accepted).Accepted);
        Assert.Equal(1, Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(snapshot).Value.LastInboundSequence);
    }

    [Fact]
    public async Task Dedicated_node_attempt_refuses_cross_project_co_scheduling()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());
        var first = fixture.StartEnvelope(sequence: 1, profile: IsolationProfile.DedicatedNode);
        var second = fixture.StartEnvelope(
            sequence: 2,
            idempotencyKey: "project-two",
            projectId: ResourceId.New(),
            attemptId: ResourceId.New(),
            profile: IsolationProfile.IsolatedContainer);

        await boundary.ReceiveAsync(first, CancellationToken.None);
        var result = await boundary.ReceiveAsync(second, CancellationToken.None);

        Assert.Equal("cross-project-isolation-refused", Value(result).Code);
    }

    [Fact]
    public async Task Cancellation_requires_an_existing_project_bound_attempt()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());
        await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);

        var cancellation = fixture.CancelEnvelope(sequence: 2);
        var accepted = await boundary.ReceiveAsync(cancellation, CancellationToken.None);
        var snapshot = await boundary.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None);
        var unknownAttempt = await boundary.ReceiveAsync(
            fixture.CancelEnvelope(sequence: 3, attemptId: ResourceId.New(), idempotencyKey: "unknown-cancel"),
            CancellationToken.None);

        Assert.Equal("accepted-cancellation", Value(accepted).Code);
        Assert.Equal(
            AttemptExecutionState.CancellationRequested,
            Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(snapshot).Value.Attempts.Single().State);
        Assert.Equal("unknown-attempt-binding", Value(unknownAttempt).Code);
    }

    [Fact]
    public async Task Persistence_failures_are_returned_and_never_acknowledged_as_success()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal(new JournalFailure("disk-full", "The journal volume is full.")));

        var result = await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);

        Assert.Equal(
            "disk-full",
            Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public async Task Snapshot_carries_observations_but_never_node_readiness_or_capability_authority()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());

        var snapshot = await boundary.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None);

        var value = Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(snapshot).Value;
        Assert.Equal(fixture.Inventory, value.Inventory);
        Assert.Equal(fixture.Health, value.Health);
        Assert.DoesNotContain(
            typeof(FullReconciliationSnapshot).GetProperties(),
            property => property.Name.Contains("readiness", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("capability", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evidence_observations_are_durable_and_bound_to_an_attempt()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());
        await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);
        var evidence = new EvidenceObservation(fixture.AttemptId, fixture.Digest('e'), fixture.Digest('f'), fixture.Now);

        var recorded = await boundary.RecordEvidenceAsync(evidence, CancellationToken.None);
        var snapshot = await boundary.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None);

        Assert.Equal(evidence, Assert.IsType<Result<EvidenceObservation, NodeAgentFailure>.Success>(recorded).Value);
        Assert.Equal(
            evidence,
            Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(snapshot).Value.Evidence.Single());
    }

    private static NodeCommandAcknowledgement Value(Result<NodeCommandAcknowledgement, NodeAgentFailure> result) =>
        Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(result).Value;
}

internal sealed class NodeAgentFixture
{
    public DateTimeOffset Now { get; } = DateTimeOffset.Parse("2026-08-22T00:00:00Z");
    public NodeDeviceIdentity Identity { get; } = new(ResourceId.New(), 7);
    public ResourceId ProjectId { get; } = ResourceId.New();
    public ResourceId AttemptId { get; } = ResourceId.New();
    public InventoryObservation Inventory { get; }
    public HealthObservation Health { get; }

    public NodeAgentFixture()
    {
        Inventory = new(
            "macOS",
            "arm64",
            ImmutableHashSet.Create(IsolationProfile.DedicatedNode, IsolationProfile.IsolatedContainer),
            Now);
        Health = new("1.0.0-test", true, Now);
    }

    public NodeAgentBoundary Boundary(INodeJournal journal, IAuthorityVerifier? verifier = null) =>
        new(
            Identity,
            new LocalIsolationCapabilities(Inventory.EnforceableIsolationProfiles),
            journal,
            verifier ?? new DeterministicVerifier(AuthorityVerification.Verified),
            new FixedClock(Now));

    public OutboundEnvelope<NodeCommand> StartEnvelope(
        long sequence,
        string? idempotencyKey = null,
        ResourceId? projectId = null,
        ResourceId? attemptId = null,
        IsolationProfile profile = IsolationProfile.IsolatedContainer,
        DateTimeOffset? expiresAt = null) =>
        new(
            NodeAgentProtocol.Version,
            Identity.NodeId,
            Identity.IdentityEpoch,
            1,
            sequence,
            Guid.NewGuid(),
            Guid.NewGuid(),
            idempotencyKey ?? $"start-{sequence}",
            Now,
            new StartAttemptCommand(
                NodeAgentProtocol.StartAttemptSchema,
                Identity.NodeId,
                projectId ?? ProjectId,
                attemptId ?? AttemptId,
                expiresAt ?? Now.AddMinutes(5),
                ResourceId.New(),
                ResourceId.New(),
                profile,
                Digest('a'),
                Digest('b'),
                Digest('c')));

    public OutboundEnvelope<NodeCommand> CancelEnvelope(
        long sequence,
        ResourceId? attemptId = null,
        string? idempotencyKey = null) =>
        new(
            NodeAgentProtocol.Version,
            Identity.NodeId,
            Identity.IdentityEpoch,
            1,
            sequence,
            Guid.NewGuid(),
            Guid.NewGuid(),
            idempotencyKey ?? $"cancel-{sequence}",
            Now,
            new CancelAttemptCommand(
                NodeAgentProtocol.CancelAttemptSchema,
                Identity.NodeId,
                ProjectId,
                attemptId ?? AttemptId,
                Now.AddMinutes(5),
                ResourceId.New(),
                "Operator requested cancellation."));

    public Sha256Digest Digest(char character) =>
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string(character, 64)}")).Value;
}

internal sealed class FixedClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset UtcNow => now;
}

internal sealed class DeterministicVerifier(AuthorityVerification result) : IAuthorityVerifier
{
    public Task<AuthorityVerification> VerifyAsync(
        OutboundEnvelope<NodeCommand> envelope,
        CancellationToken cancellationToken) =>
        Task.FromResult(result);
}

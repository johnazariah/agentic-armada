using System.Collections.Immutable;
using Armada.Contracts;

namespace Armada.NodeAgent;

public sealed record NodeAgentFailure(string Code, string Message);

public sealed class NodeAgentBoundary
{
    private readonly INodeJournal journal;
    private readonly IAuthorityVerifier verifier;
    private readonly IClock clock;
    private readonly NodeDeviceIdentity identity;
    private readonly LocalIsolationCapabilities capabilities;
    private AgentState state;

    public NodeAgentBoundary(
        NodeDeviceIdentity identity,
        LocalIsolationCapabilities capabilities,
        INodeJournal journal,
        IAuthorityVerifier verifier,
        IClock clock)
    {
        this.identity = identity;
        this.capabilities = capabilities;
        this.journal = journal;
        this.verifier = verifier;
        this.clock = clock;
        state = AgentState.Empty(identity);
    }

    public async Task<Result<FullReconciliationSnapshot, NodeAgentFailure>> ReconcileAsync(
        InventoryObservation inventory,
        HealthObservation health,
        CancellationToken cancellationToken)
    {
        var entries = await journal.ReadAsync(cancellationToken);
        if (entries is Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure failure)
        {
            return Failure<FullReconciliationSnapshot>(failure.Error);
        }

        var restored = AgentState.Replay(identity, ((Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success)entries).Value);
        if (restored is Result<AgentState, JournalFailure>.Failure restoreFailure)
        {
            return Failure<FullReconciliationSnapshot>(restoreFailure.Error);
        }

        state = ((Result<AgentState, JournalFailure>.Success)restored).Value;
        return new Result<FullReconciliationSnapshot, NodeAgentFailure>.Success(
            new(
                identity,
                state.StreamEpoch,
                state.LastInboundSequence,
                inventory,
                health,
                state.Attempts.Values.OrderBy(static attempt => attempt.AttemptId.Value).ToImmutableArray(),
                state.Evidence.Values.OrderBy(static evidence => evidence.AttemptId.Value).ToImmutableArray()));
    }

    public async Task<Result<NodeCommandAcknowledgement, NodeAgentFailure>> ReceiveAsync(
        OutboundEnvelope<NodeCommand> envelope,
        CancellationToken cancellationToken)
    {
        var verification = await verifier.VerifyAsync(envelope, cancellationToken);
        var outcome = CommandValidation.Validate(state, envelope, verification, capabilities, clock.UtcNow);
        if (outcome.Acknowledgement.Duplicate)
        {
            return new Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success(outcome.Acknowledgement);
        }

        var entry = JournalEntry.ForCommand(
            NextOrdinal(),
            identity,
            envelope,
            outcome,
            clock.UtcNow);
        var persisted = await journal.AppendAsync(entry, cancellationToken);
        if (persisted is Result<JournalEntry, JournalFailure>.Failure failure)
        {
            return Failure<NodeCommandAcknowledgement>(failure.Error);
        }

        state = AgentState.Apply(state, ((Result<JournalEntry, JournalFailure>.Success)persisted).Value);
        return new Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success(outcome.Acknowledgement);
    }

    public async Task<Result<EvidenceObservation, NodeAgentFailure>> RecordEvidenceAsync(
        EvidenceObservation observation,
        CancellationToken cancellationToken)
    {
        if (!state.Attempts.ContainsKey(observation.AttemptId))
        {
            return new Result<EvidenceObservation, NodeAgentFailure>.Failure(
                new("unknown-attempt-binding", "Evidence must bind to an observed local attempt."));
        }

        var entry = JournalEntry.ForEvidence(NextOrdinal(), identity, observation);
        var persisted = await journal.AppendAsync(entry, cancellationToken);
        if (persisted is Result<JournalEntry, JournalFailure>.Failure failure)
        {
            return Failure<EvidenceObservation>(failure.Error);
        }

        state = AgentState.Apply(state, ((Result<JournalEntry, JournalFailure>.Success)persisted).Value);
        return new Result<EvidenceObservation, NodeAgentFailure>.Success(observation);
    }

    public async Task<Result<AttemptRuntime, NodeAgentFailure>> AuthoriseProcessStartAsync(
        ResourceId attemptId,
        Sha256Digest capabilityGrantDigest,
        CancellationToken cancellationToken)
    {
        if (!state.Attempts.TryGetValue(attemptId, out var attempt))
        {
            return new Result<AttemptRuntime, NodeAgentFailure>.Failure(
                new("unknown-attempt-binding", "Process start requires a locally observed attempt."));
        }
        if (attempt.State != AttemptExecutionState.Prepared)
        {
            return new Result<AttemptRuntime, NodeAgentFailure>.Failure(
                new("attempt-not-prepared", "Only a durable prepared attempt can start a process."));
        }
        if (attempt.AuthorityExpiresAt <= clock.UtcNow)
        {
            return new Result<AttemptRuntime, NodeAgentFailure>.Failure(
                new("expired-authority", "The persisted attempt authority has expired."));
        }
        if (capabilityGrantDigest is null ||
            attempt.CapabilityGrantDigest is null ||
            attempt.CapabilityGrantDigest != capabilityGrantDigest)
        {
            return new Result<AttemptRuntime, NodeAgentFailure>.Failure(
                new("capability-grant-mismatch", "Process start requires the capability grant bound to the durable attempt."));
        }

        if (ProcessSupervision.MarkStarted(attempt, clock.UtcNow) is not Result<AttemptRuntime, ProcessTransitionFailure>.Success started)
        {
            return new Result<AttemptRuntime, NodeAgentFailure>.Failure(
                new("attempt-not-prepared", "The process start transition is not valid for this attempt."));
        }

        var entry = JournalEntry.ForAttemptStarted(NextOrdinal(), identity, started.Value, clock.UtcNow);
        var persisted = await journal.AppendAsync(entry, cancellationToken);
        if (persisted is Result<JournalEntry, JournalFailure>.Failure failure)
        {
            return Failure<AttemptRuntime>(failure.Error);
        }

        state = AgentState.Apply(state, ((Result<JournalEntry, JournalFailure>.Success)persisted).Value);
        return new Result<AttemptRuntime, NodeAgentFailure>.Success(started.Value);
    }

    private long NextOrdinal() => state.LastJournalOrdinal + 1;

    private static Result<T, NodeAgentFailure> Failure<T>(JournalFailure failure) =>
        new Result<T, NodeAgentFailure>.Failure(new(failure.Code, failure.Message));
}

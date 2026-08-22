using Armada.Contracts;
using Armada.NodeAgent;

namespace Armada.NodeAgent.Tests;

public sealed class AssuranceScenarioTests
{
    [Fact]
    public async Task Reconnect_epoch_resets_the_sequence_window_but_rejects_replays_within_the_new_epoch()
    {
        var fixture = new NodeAgentFixture();
        var boundary = fixture.Boundary(new InMemoryJournal());
        var initial = fixture.StartEnvelope(sequence: 5, idempotencyKey: "stream-one");
        var reconnected = fixture.StartEnvelope(
            sequence: 1,
            idempotencyKey: "stream-two",
            attemptId: ResourceId.New()) with { StreamEpoch = 2 };
        var replay = fixture.StartEnvelope(
            sequence: 1,
            idempotencyKey: "stream-two-replay",
            attemptId: ResourceId.New()) with { StreamEpoch = 2 };

        var first = await boundary.ReceiveAsync(initial, CancellationToken.None);
        var second = await boundary.ReceiveAsync(reconnected, CancellationToken.None);
        var rejected = await boundary.ReceiveAsync(replay, CancellationToken.None);
        var snapshot = Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(
            await boundary.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None)).Value;

        Assert.True(Value(first).Accepted);
        Assert.True(Value(second).Accepted);
        Assert.Equal("stale-or-replayed-sequence", Value(rejected).Code);
        Assert.Equal(2, snapshot.StreamEpoch);
        Assert.Equal(1, snapshot.LastInboundSequence);
        Assert.Equal(2, snapshot.Attempts.Length);
    }

    [Fact]
    public async Task Concurrent_same_command_delivery_creates_one_attempt_and_replays_every_duplicate()
    {
        var fixture = new NodeAgentFixture();
        var journal = new InMemoryJournal();
        var boundary = fixture.Boundary(journal);
        var command = fixture.StartEnvelope(sequence: 1, idempotencyKey: "concurrent-start");
        var deliveries = Enumerable.Range(0, 16)
            .Select(_ => boundary.ReceiveAsync(
                command with { MessageId = Guid.NewGuid(), CorrelationId = Guid.NewGuid() },
                CancellationToken.None));

        var acknowledgements = (await Task.WhenAll(deliveries))
            .Select(static result => Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(result).Value)
            .ToArray();
        var restarted = fixture.Boundary(journal);
        var snapshot = Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(
            await restarted.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None)).Value;

        Assert.Equal(1, acknowledgements.Count(static acknowledgement => acknowledgement.Accepted && !acknowledgement.Duplicate));
        Assert.Equal(15, acknowledgements.Count(static acknowledgement => acknowledgement.Accepted && acknowledgement.Duplicate));
        Assert.Single(snapshot.Attempts);
        Assert.Single(
            Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success>(
                await journal.ReadAsync(CancellationToken.None)).Value);
    }

    [Fact]
    public async Task Rebooted_running_attempt_is_reconciled_and_cannot_start_a_second_process()
    {
        var fixture = new NodeAgentFixture();
        var journal = new InMemoryJournal();
        var first = fixture.Boundary(journal);
        var command = fixture.StartEnvelope(sequence: 1);

        await first.ReceiveAsync(command, CancellationToken.None);
        await first.AuthoriseProcessStartAsync(
            fixture.AttemptId,
            ((StartAttemptCommand)command.Payload).CapabilityGrantDigest,
            CancellationToken.None);

        var restarted = fixture.Boundary(journal);
        var snapshot = Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(
            await restarted.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None)).Value;
        var restartAttempt = await restarted.AuthoriseProcessStartAsync(
            fixture.AttemptId,
            ((StartAttemptCommand)command.Payload).CapabilityGrantDigest,
            CancellationToken.None);

        Assert.Equal(AttemptExecutionState.Running, Assert.Single(snapshot.Attempts).State);
        Assert.Equal(
            "attempt-not-prepared",
            Assert.IsType<Result<AttemptRuntime, NodeAgentFailure>.Failure>(restartAttempt).Error.Code);
    }

    [Fact]
    public async Task Malformed_untrusted_envelopes_are_rejected_without_throwing_or_poisoning_recovery()
    {
        var fixture = new NodeAgentFixture();
        var journal = new InMemoryJournal();
        var boundary = fixture.Boundary(journal);
        var missingIdentity = fixture.StartEnvelope(sequence: 1) with { IdempotencyKey = null! };
        var missingPayload = fixture.StartEnvelope(sequence: 1) with { Payload = null! };

        var identityException = await Record.ExceptionAsync(() => boundary.ReceiveAsync(missingIdentity, CancellationToken.None));
        var payloadException = await Record.ExceptionAsync(() => boundary.ReceiveAsync(missingPayload, CancellationToken.None));
        var started = await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);
        var malformedCancellation = fixture.CancelEnvelope(sequence: 2) with
        {
            Payload = ((CancelAttemptCommand)fixture.CancelEnvelope(sequence: 2).Payload) with { Reason = null! }
        };
        var cancellationException = await Record.ExceptionAsync(() => boundary.ReceiveAsync(malformedCancellation, CancellationToken.None));
        var rejectedCancellation = await boundary.ReceiveAsync(malformedCancellation, CancellationToken.None);
        var restarted = fixture.Boundary(journal);
        var snapshot = await restarted.ReconcileAsync(fixture.Inventory, fixture.Health, CancellationToken.None);

        Assert.Null(identityException);
        Assert.Null(payloadException);
        Assert.Null(cancellationException);
        Assert.Equal("invalid-envelope-identity", Value(await boundary.ReceiveAsync(missingIdentity, CancellationToken.None)).Code);
        Assert.Equal("invalid-envelope-identity", Value(await boundary.ReceiveAsync(missingPayload, CancellationToken.None)).Code);
        Assert.True(Value(started).Accepted);
        Assert.Equal("invalid-command-binding", Value(rejectedCancellation).Code);
        Assert.Single(Assert.IsType<Result<FullReconciliationSnapshot, NodeAgentFailure>.Success>(snapshot).Value.Attempts);
    }

    private static NodeCommandAcknowledgement Value(Result<NodeCommandAcknowledgement, NodeAgentFailure> result) =>
        Assert.IsType<Result<NodeCommandAcknowledgement, NodeAgentFailure>.Success>(result).Value;
}

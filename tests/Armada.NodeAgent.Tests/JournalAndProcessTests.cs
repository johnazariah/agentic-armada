using System.Security.Cryptography;
using Armada.Contracts;
using Armada.NodeAgent;
using FsCheck.Xunit;

namespace Armada.NodeAgent.Tests;

public sealed class JournalAndProcessTests
{
    [Fact]
    public async Task Encrypted_file_journal_round_trips_without_plaintext_and_rejects_wrong_key()
    {
        var fixture = new NodeAgentFixture();
        var path = Path.Combine(Path.GetTempPath(), $"armada-journal-{Guid.NewGuid():N}.log");
        var key = RandomNumberGenerator.GetBytes(32);
        var rollbackAnchor = new InMemoryRollbackAnchorStore();
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(key),
            rollbackAnchor);
        var entry = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));

        try
        {
            var appended = await journal.AppendAsync(entry, CancellationToken.None);
            var restored = await journal.ReadAsync(CancellationToken.None);
            var raw = await File.ReadAllTextAsync(path);
            var wrongKey = new EncryptedFileJournal(
                path,
                new AesGcmJournalProtector(RandomNumberGenerator.GetBytes(32)),
                rollbackAnchor);
            var failedRead = await wrongKey.ReadAsync(CancellationToken.None);

            Assert.Equal(entry, Assert.IsType<Result<JournalEntry, JournalFailure>.Success>(appended).Value);
            Assert.Equal(entry, Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success>(restored).Value.Single());
            Assert.DoesNotContain(entry.Code, raw, StringComparison.Ordinal);
            Assert.Equal(
                "journal-decryption-failed",
                Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure>(failedRead).Error.Code);
        }
        finally
        {
            File.Delete(path);
            File.Delete($"{path}.anchor");
        }
    }

    [Fact]
    public async Task Encrypted_file_journal_rejects_tampering_and_tail_truncation_against_its_anchor()
    {
        var fixture = new NodeAgentFixture();
        var path = Path.Combine(Path.GetTempPath(), $"armada-journal-{Guid.NewGuid():N}.log");
        var key = RandomNumberGenerator.GetBytes(32);
        var rollbackAnchor = new InMemoryRollbackAnchorStore();
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(key),
            rollbackAnchor);
        var first = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));
        var second = JournalEntry.ForEvidence(
            2,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('c'), fixture.Digest('d'), fixture.Now.AddSeconds(1)));

        try
        {
            await journal.AppendAsync(first, CancellationToken.None);
            await journal.AppendAsync(second, CancellationToken.None);
            var lines = await File.ReadAllLinesAsync(path);
            await File.WriteAllLinesAsync(path, [lines[0]]);

            var truncated = await journal.ReadAsync(CancellationToken.None);

            Assert.Equal(
                "journal-rollback-detected",
                Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure>(truncated).Error.Code);

            await File.WriteAllLinesAsync(path, lines);
            await File.WriteAllTextAsync(path, lines[0].Replace("\"entryHash\":\"", "\"entryHash\":\"f", StringComparison.Ordinal));

            var tampered = await journal.ReadAsync(CancellationToken.None);

            Assert.Equal(
                "journal-chain-invalid",
                Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure>(tampered).Error.Code);
        }
        finally
        {
            File.Delete(path);
            File.Delete($"{path}.anchor");
        }
    }

    [Fact]
    public async Task Rollback_resistant_anchor_rejects_restoring_a_journal_and_local_marker_together()
    {
        var fixture = new NodeAgentFixture();
        var path = Path.Combine(Path.GetTempPath(), $"armada-journal-{Guid.NewGuid():N}.log");
        var key = RandomNumberGenerator.GetBytes(32);
        var rollbackAnchor = new InMemoryRollbackAnchorStore();
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(key),
            rollbackAnchor);
        var first = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));
        var second = JournalEntry.ForEvidence(
            2,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('c'), fixture.Digest('d'), fixture.Now.AddSeconds(1)));

        try
        {
            await journal.AppendAsync(first, CancellationToken.None);
            var journalSnapshot = await File.ReadAllBytesAsync(path);
            var markerSnapshot = await File.ReadAllBytesAsync($"{path}.anchor");
            await journal.AppendAsync(second, CancellationToken.None);

            await File.WriteAllBytesAsync(path, journalSnapshot);
            await File.WriteAllBytesAsync($"{path}.anchor", markerSnapshot);
            var restored = new EncryptedFileJournal(
                path,
                new AesGcmJournalProtector(key),
                rollbackAnchor);

            var result = await restored.ReadAsync(CancellationToken.None);

            Assert.Equal(
                "journal-rollback-detected",
                Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure>(result).Error.Code);
        }
        finally
        {
            File.Delete(path);
            File.Delete($"{path}.anchor");
        }
    }

    [Fact]
    public async Task Production_journal_fails_closed_without_a_platform_rollback_anchor()
    {
        var path = Path.Combine(Path.GetTempPath(), $"armada-journal-{Guid.NewGuid():N}.log");
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(RandomNumberGenerator.GetBytes(32)));

        var result = await journal.ReadAsync(CancellationToken.None);

        Assert.Equal(
            "rollback-anchor-platform-unavailable",
            Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure>(result).Error.Code);
        Assert.DoesNotContain(
            typeof(EncryptedFileJournal).GetConstructors(),
            constructor => constructor.GetParameters().Any(parameter => parameter.ParameterType == typeof(IRollbackAnchorStore)));
    }

    [Fact]
    public async Task Journal_rejects_a_missing_local_marker_and_non_contiguous_append()
    {
        var fixture = new NodeAgentFixture();
        var path = Path.Combine(Path.GetTempPath(), $"armada-journal-{Guid.NewGuid():N}.log");
        var rollbackAnchor = new InMemoryRollbackAnchorStore();
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(RandomNumberGenerator.GetBytes(32)),
            rollbackAnchor);
        var first = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));

        try
        {
            var invalidAppend = await journal.AppendAsync(first with { Ordinal = 2 }, CancellationToken.None);
            await journal.AppendAsync(first, CancellationToken.None);
            File.Delete($"{path}.anchor");
            var missingMarker = await journal.ReadAsync(CancellationToken.None);

            Assert.Equal(
                "journal-ordinal-invalid",
                Assert.IsType<Result<JournalEntry, JournalFailure>.Failure>(invalidAppend).Error.Code);
            Assert.Equal(
                "journal-anchor-missing",
                Assert.IsType<Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure>(missingMarker).Error.Code);
        }
        finally
        {
            File.Delete(path);
            File.Delete($"{path}.anchor");
        }
    }

    [Fact]
    public async Task Rollback_anchor_store_rejects_nonmonotonic_advances()
    {
        var store = new InMemoryRollbackAnchorStore();

        var result = await store.AdvanceAsync(new RollbackAnchor(2, "tail"), CancellationToken.None);

        Assert.Equal(
            "rollback-anchor-nonmonotonic",
            Assert.IsType<Result<RollbackAnchor, JournalFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public async Task Journal_rejects_an_anchor_store_that_does_not_confirm_the_written_checkpoint()
    {
        var fixture = new NodeAgentFixture();
        var path = Path.Combine(Path.GetTempPath(), $"armada-journal-{Guid.NewGuid():N}.log");
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(RandomNumberGenerator.GetBytes(32)),
            new MismatchingRollbackAnchorStore());
        var entry = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));

        try
        {
            var result = await journal.AppendAsync(entry, CancellationToken.None);

            Assert.Equal(
                "rollback-anchor-invalid",
                Assert.IsType<Result<JournalEntry, JournalFailure>.Failure>(result).Error.Code);
        }
        finally
        {
            File.Delete(path);
            File.Delete($"{path}.anchor");
        }
    }

    [Fact]
    public void Replay_rejects_duplicated_or_gapped_journal_ordinals_before_restoring_state()
    {
        var fixture = new NodeAgentFixture();
        var first = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));
        var duplicate = first with { Ordinal = 1 };
        var gap = first with { Ordinal = 3 };

        var duplicateResult = AgentState.Replay(fixture.Identity, [first, duplicate]);
        var gapResult = AgentState.Replay(fixture.Identity, [first, gap]);

        Assert.Equal(
            "journal-ordinal-invalid",
            Assert.IsType<Result<AgentState, JournalFailure>.Failure>(duplicateResult).Error.Code);
        Assert.Equal(
            "journal-ordinal-invalid",
            Assert.IsType<Result<AgentState, JournalFailure>.Failure>(gapResult).Error.Code);
    }

    [Fact]
    public void Process_supervision_models_attempt_scoped_cancellation_and_observation()
    {
        var fixture = new NodeAgentFixture();
        var prepared = new AttemptRuntime(
            fixture.ProjectId,
            fixture.WorkloadId,
            fixture.AttemptId,
            ResourceId.New(),
            ResourceId.New(),
            IsolationProfile.IsolatedContainer,
            fixture.Digest('a'),
            fixture.Digest('b'),
            fixture.Digest('c'),
            fixture.Digest('d'),
            fixture.Now.AddMinutes(5),
            AttemptExecutionState.Prepared,
            fixture.Now);

        var running = Value(ProcessSupervision.MarkStarted(prepared, fixture.Now.AddSeconds(1)));
        var cancelling = Value(ProcessSupervision.RequestCancellation(running, fixture.Now.AddSeconds(2)));
        var terminated = Value(ProcessSupervision.Observe(
            cancelling,
            new ProcessTreeObservation(fixture.AttemptId, 137, false, fixture.Now.AddSeconds(3))));
        var invalid = ProcessSupervision.RequestCancellation(terminated, fixture.Now.AddSeconds(4));

        Assert.Equal(AttemptExecutionState.Terminated, terminated.State);
        Assert.Equal(
            "invalid-process-transition",
            Assert.IsType<Result<AttemptRuntime, ProcessTransitionFailure>.Failure>(invalid).Error.Code);
        Assert.DoesNotContain(typeof(IProcessSupervisor).GetMethods(), method => method.Name.Contains("launch", StringComparison.OrdinalIgnoreCase));
    }

    [Property(MaxTest = 50)]
    public void Repeated_cancellation_is_idempotent_for_a_running_attempt(int seconds)
    {
        var fixture = new NodeAgentFixture();
        var running = new AttemptRuntime(
            fixture.ProjectId,
            fixture.WorkloadId,
            fixture.AttemptId,
            ResourceId.New(),
            ResourceId.New(),
            IsolationProfile.IsolatedContainer,
            fixture.Digest('a'),
            fixture.Digest('b'),
            fixture.Digest('c'),
            fixture.Digest('d'),
            fixture.Now.AddMinutes(5),
            AttemptExecutionState.Running,
            fixture.Now);
        var time = fixture.Now.AddSeconds(Math.Abs((long)seconds % 1000));

        var first = Value(ProcessSupervision.RequestCancellation(running, time));
        var second = Value(ProcessSupervision.RequestCancellation(first, time.AddSeconds(1)));

        Assert.Equal(first, second);
    }

    [Fact]
    public void Process_observations_cannot_be_applied_to_a_different_attempt()
    {
        var fixture = new NodeAgentFixture();
        var running = new AttemptRuntime(
            fixture.ProjectId,
            fixture.WorkloadId,
            fixture.AttemptId,
            ResourceId.New(),
            ResourceId.New(),
            IsolationProfile.IsolatedContainer,
            fixture.Digest('a'),
            fixture.Digest('b'),
            fixture.Digest('c'),
            fixture.Digest('d'),
            fixture.Now.AddMinutes(5),
            AttemptExecutionState.Running,
            fixture.Now);

        var result = ProcessSupervision.Observe(
            running,
            new ProcessTreeObservation(ResourceId.New(), null, true, fixture.Now));

        Assert.Equal(
            "attempt-observation-mismatch",
            Assert.IsType<Result<AttemptRuntime, ProcessTransitionFailure>.Failure>(result).Error.Code);
    }

    private static AttemptRuntime Value(Result<AttemptRuntime, ProcessTransitionFailure> result) =>
        Assert.IsType<Result<AttemptRuntime, ProcessTransitionFailure>.Success>(result).Value;
}

internal sealed class MismatchingRollbackAnchorStore : IRollbackAnchorStore
{
    public Task<Result<RollbackAnchor, JournalFailure>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Success(RollbackAnchor.Empty));

    public Task<Result<RollbackAnchor, JournalFailure>> AdvanceAsync(
        RollbackAnchor next,
        CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Success(RollbackAnchor.Empty));
}

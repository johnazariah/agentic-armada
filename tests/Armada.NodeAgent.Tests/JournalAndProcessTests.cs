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
        var journal = new EncryptedFileJournal(path, new AesGcmJournalProtector(key));
        var entry = JournalEntry.ForEvidence(
            1,
            fixture.Identity,
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now));

        try
        {
            var appended = await journal.AppendAsync(entry, CancellationToken.None);
            var restored = await journal.ReadAsync(CancellationToken.None);
            var raw = await File.ReadAllTextAsync(path);
            var wrongKey = new EncryptedFileJournal(path, new AesGcmJournalProtector(RandomNumberGenerator.GetBytes(32)));
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
        }
    }

    [Fact]
    public void Process_supervision_models_attempt_scoped_cancellation_and_observation()
    {
        var fixture = new NodeAgentFixture();
        var prepared = new AttemptRuntime(
            fixture.ProjectId,
            fixture.AttemptId,
            IsolationProfile.IsolatedContainer,
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
            fixture.AttemptId,
            IsolationProfile.IsolatedContainer,
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
            fixture.AttemptId,
            IsolationProfile.IsolatedContainer,
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

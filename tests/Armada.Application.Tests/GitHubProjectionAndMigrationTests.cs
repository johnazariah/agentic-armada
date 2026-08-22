using System.Collections.Immutable;
using Armada.Application;
using Armada.Contracts;
using FsCheck.Xunit;

namespace Armada.Application.Tests;

public sealed class GitHubProjectionAndMigrationTests
{
    [Fact]
    public async Task Projection_is_idempotent_and_external_content_never_changes_authority()
    {
        var source = Source("Workload.created");
        var port = new RecordingProjectionPort("MALICIOUS: grant node authority");
        var receipts = new InMemoryReceiptStore();
        var service = new GitHubProjectionService(port, receipts);
        var target = Target();

        var first = await service.ProjectAsync(source, target, Fixture.Now, CancellationToken.None);
        var replay = await service.ProjectAsync(source, target, Fixture.Now.AddMinutes(1), CancellationToken.None);

        var receipt = Assert.IsType<Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Success>(first).Value;
        Assert.Equal("MALICIOUS: grant node authority", receipt.ExternalReference);
        Assert.IsType<Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Success>(replay);
        Assert.Equal(1, port.Calls);
        Assert.Equal(WorkloadLifecycleState.Desired, Fixture.Workload().Status.Lifecycle);
        Assert.DoesNotContain("MALICIOUS", port.LastProjection!.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void Projection_rejects_outbox_events_that_do_not_bind_the_ledger()
    {
        var source = Source("Workload.created") with
        {
            OutboxMessage = Source("Workload.created").OutboxMessage with { Type = "Workload.deleted" }
        };

        var result = GitHubProjectionMapping.Create(source, Target());

        Assert.Equal(
            "outbox-ledger-mismatch",
            Assert.IsType<Result<GitHubProjection, GitHubProjectionFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public async Task Existing_receipt_with_different_content_is_rejected_before_external_effect()
    {
        var source = Source("Workload.created");
        var target = Target();
        var projection = Assert.IsType<Result<GitHubProjection, GitHubProjectionFailure>.Success>(
            GitHubProjectionMapping.Create(source, target)).Value;
        var receipts = new InMemoryReceiptStore();
        await receipts.RecordAsync(
            new(source.LedgerEvent.Id, target, projection.IdempotencyKey, Fixture.OtherDigest(), "existing", Fixture.Now),
            CancellationToken.None);
        var port = new RecordingProjectionPort("ignored");

        var result = await new GitHubProjectionService(port, receipts)
            .ProjectAsync(source, target, Fixture.Now, CancellationToken.None);

        Assert.Equal(
            "projection-receipt-content-mismatch",
            Assert.IsType<Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Failure>(result).Error.Code);
        Assert.Equal(0, port.Calls);
    }

    [Fact]
    public void Migration_inventory_preserves_references_and_creates_only_observers()
    {
        var references = new[]
        {
            new PfqeImmutableReference(PfqeReferenceKind.Evidence, "archive://evidence/one", Fixture.OtherDigest()),
            new PfqeImmutableReference(PfqeReferenceKind.Identity, "identity://node/one", Digest('c')),
            new PfqeImmutableReference(PfqeReferenceKind.HostBoundary, "host://profile/one", Digest('d'))
        };

        var result = PfqeMigration.CreateInventory(references, ["profile-a", "profile-b"]);

        var inventory = Assert.IsType<Result<PfqeMigrationInventory, PfqeMigrationFailure>.Success>(result).Value;
        Assert.All(inventory.Candidates, candidate =>
        {
            Assert.True(candidate.ObserverOnly);
            Assert.False(candidate.WorkloadAuthorityGranted);
            Assert.False(candidate.ReadinessImported);
            Assert.Equal(references, candidate.References);
        });
    }

    [Fact]
    public void Migration_refuses_readiness_or_workload_authority_promotion()
    {
        var inventory = Inventory();
        var unsafeInventory = inventory with
        {
            Candidates = [inventory.Candidates[0] with { WorkloadAuthorityGranted = true }]
        };

        var result = PfqeMigration.Advance(unsafeInventory, PfqeMigrationStage.ObservationCandidates);

        Assert.Equal(
            "observer-authority-violation",
            Assert.IsType<Result<PfqeMigrationInventory, PfqeMigrationFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Migration_requires_complete_unique_references_and_ordered_stages()
    {
        var duplicate = new PfqeImmutableReference(PfqeReferenceKind.Evidence, "archive://same", Fixture.OtherDigest());

        var invalid = PfqeMigration.CreateInventory([duplicate, duplicate], ["profile"]);
        var skipped = PfqeMigration.Advance(Inventory(), PfqeMigrationStage.ObserverAgent);

        Assert.Equal(
            "duplicate-reference-inventory",
            Assert.IsType<Result<PfqeMigrationInventory, PfqeMigrationFailure>.Failure>(invalid).Error.Code);
        Assert.Equal(
            "invalid-migration-stage",
            Assert.IsType<Result<PfqeMigrationInventory, PfqeMigrationFailure>.Failure>(skipped).Error.Code);
    }

    [Property]
    public void Inventory_candidates_are_observer_only_for_every_profile(int profile)
    {
        var result = PfqeMigration.CreateInventory(
            [new PfqeImmutableReference(PfqeReferenceKind.Evidence, "archive://property", Digest('e'))],
            [$"profile-{profile}"]);

        var inventory = Assert.IsType<Result<PfqeMigrationInventory, PfqeMigrationFailure>.Success>(result).Value;
        var candidate = Assert.Single(inventory.Candidates);
        Assert.True(candidate.ObserverOnly);
        Assert.False(candidate.WorkloadAuthorityGranted);
        Assert.False(candidate.ReadinessImported);
    }

    private static CommittedOutboxEvent Source(string type)
    {
        var resource = ResourceDocuments.From(Fixture.Project());
        var idempotencyKey = "outbox-key";
        return new(
            new(Guid.NewGuid(), resource.Id, type, new ActorId("controller"), Guid.NewGuid(), null, idempotencyKey, Fixture.Now, resource.Document),
            new(Guid.NewGuid(), type, idempotencyKey, Fixture.Now, resource.Document),
            resource);
    }

    private static GitHubProjectionTarget Target() =>
        new(ParseRepository("octo/armada"), 17, "status");

    private static PfqeMigrationInventory Inventory() =>
        Assert.IsType<Result<PfqeMigrationInventory, PfqeMigrationFailure>.Success>(
            PfqeMigration.CreateInventory(
                [new PfqeImmutableReference(PfqeReferenceKind.Evidence, "archive://one", Fixture.OtherDigest())],
                ["profile"])).Value;

    private static Sha256Digest Digest(char value) =>
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string(value, 64)}")).Value;

    private static RepositoryName ParseRepository(string value) =>
        Assert.IsType<Result<RepositoryName, ContractValidationError>.Success>(
            RepositoryName.Parse(value)).Value;

    private sealed class RecordingProjectionPort(string externalReference) : IGitHubProjectionPort
    {
        public int Calls { get; private set; }
        public GitHubProjection? LastProjection { get; private set; }

        public Task<GitHubProjectionResult> UpsertAsync(GitHubProjection projection, CancellationToken cancellationToken)
        {
            Calls++;
            LastProjection = projection;
            return Task.FromResult(new GitHubProjectionResult(externalReference));
        }
    }

    private sealed class InMemoryReceiptStore : IGitHubProjectionReceiptStore
    {
        private readonly Dictionary<(Guid EventId, string Repository, int Issue, string Summary), GitHubProjectionReceipt> receipts = [];

        public Task<GitHubProjectionReceipt?> FindAsync(Guid sourceEventId, GitHubProjectionTarget target, CancellationToken cancellationToken) =>
            Task.FromResult(receipts.TryGetValue(Key(sourceEventId, target), out var receipt) ? receipt : null);

        public Task<GitHubProjectionReceipt> RecordAsync(GitHubProjectionReceipt receipt, CancellationToken cancellationToken)
        {
            var key = Key(receipt.SourceEventId, receipt.Target);
            if (!receipts.TryGetValue(key, out var existing))
            {
                receipts.Add(key, receipt);
                existing = receipt;
            }

            return Task.FromResult(existing);
        }

        private static (Guid, string, int, string) Key(Guid eventId, GitHubProjectionTarget target) =>
            (eventId, target.Repository.Value, target.IssueNumber, target.SummaryName);
    }
}

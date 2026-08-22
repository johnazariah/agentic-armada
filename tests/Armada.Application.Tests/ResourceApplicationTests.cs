using System.Collections.Concurrent;
using System.Text.Json;
using Armada.Application;
using Armada.Contracts;
using FsCheck;
using FsCheck.Xunit;

namespace Armada.Application.Tests;

public sealed class ResourceApplicationTests
{
    [Fact]
    public async Task Create_persists_resource_ledger_and_outbox_atomically()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();

        var result = await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);

        var committed = Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Success>(result).Value;
        var commit = Assert.IsType<ResourceStoreResult.Committed>(committed).Commit;
        Assert.Equal(resource.Metadata.Uid, commit.Resource.Id);
        Assert.Single(repository.Resources);
        Assert.Single(repository.Ledger);
        Assert.Single(repository.Outbox);
        Assert.Equal(repository.Ledger.Single().Id, repository.Outbox.Single().EventId);
    }

    [Fact]
    public async Task Create_replay_returns_original_atomic_commit()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var command = Fixture.Create(Fixture.Project());

        await service.CreateAsync(command, CancellationToken.None);
        var replay = await service.CreateAsync(command, CancellationToken.None);

        var result = Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Success>(replay).Value;
        Assert.IsType<ResourceStoreResult.AlreadyApplied>(result);
        Assert.Single(repository.Resources);
        Assert.Single(repository.Ledger);
        Assert.Single(repository.Outbox);
    }

    [Fact]
    public async Task Create_replay_with_different_command_metadata_is_rejected()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var command = Fixture.Create(Fixture.Project());

        await service.CreateAsync(command, CancellationToken.None);
        var replay = await service.CreateAsync(
            command with { Actor = new ActorId("different-actor") },
            CancellationToken.None);

        Assert.Equal(
            "idempotency-key-reused",
            Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Failure>(replay).Error.Code);
    }

    [Fact]
    public void Generic_creation_rejects_admission_decision_authority()
    {
        var workload = Fixture.Workload();

        var result = ResourceCommandDecisions.Create(Fixture.Create(Fixture.AdmissionDecision(workload)));

        Assert.Equal(
            "admission-decision-requires-admission-command",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public async Task Concurrent_updates_allow_exactly_one_matching_CAS_write()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();
        await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);

        var updates = Enumerable.Range(0, 16)
            .Select(index => service.UpdateSpecAsync(
                Fixture.Update(resource.Metadata.Uid, new ResourceVersion("1"), index),
                CancellationToken.None));
        var results = await Task.WhenAll(updates);

        Assert.Equal(
            1,
            results.Count(static result =>
                result is Result<ResourceStoreResult, ResourceCommandFailure>.Success
                {
                    Value: ResourceStoreResult.Committed
                }));
        Assert.Equal("2", repository.Resources[resource.Metadata.Uid].ResourceVersion.Value);
        Assert.Single(repository.Ledger, static item => item.Type == "Project.spec-updated");
        Assert.Equal(2, repository.Outbox.Count);
    }

    [Fact]
    public async Task Failed_CAS_leaves_no_event_or_outbox_partial_write()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();
        await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);

        var result = await service.UpdateSpecAsync(
            Fixture.Update(resource.Metadata.Uid, new ResourceVersion("not-current"), 42),
            CancellationToken.None);

        var failure = Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Failure>(result);
        Assert.Equal("stale-resource-version", failure.Error.Code);
        Assert.Single(repository.Ledger);
        Assert.Single(repository.Outbox);
    }

    [Fact]
    public async Task Identical_update_replay_returns_the_durable_commit_before_CAS_rejection()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();
        await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);
        var command = Fixture.Update(resource.Metadata.Uid, new ResourceVersion("1"), 7);

        await service.UpdateSpecAsync(command, CancellationToken.None);
        var replay = await service.UpdateSpecAsync(command, CancellationToken.None);

        Assert.IsType<ResourceStoreResult.AlreadyApplied>(
            Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Success>(replay).Value);
        Assert.Equal("2", repository.Resources[resource.Metadata.Uid].ResourceVersion.Value);
        Assert.Equal(2, repository.Ledger.Count);
    }

    [Fact]
    public async Task Reusing_an_update_transition_identity_for_a_different_spec_is_rejected()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();
        await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);
        var idempotencyKey = TransitionId.New();

        await service.UpdateSpecAsync(
            Fixture.Update(resource.Metadata.Uid, new ResourceVersion("1"), 7, idempotencyKey),
            CancellationToken.None);
        var replay = await service.UpdateSpecAsync(
            Fixture.Update(resource.Metadata.Uid, new ResourceVersion("1"), 8, idempotencyKey),
            CancellationToken.None);

        Assert.Equal(
            "idempotency-key-reused",
            Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Failure>(replay).Error.Code);
    }

    [Fact]
    public async Task Reusing_an_update_transition_identity_with_different_command_metadata_is_rejected()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();
        await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);
        var command = Fixture.Update(resource.Metadata.Uid, new ResourceVersion("1"), 7);

        await service.UpdateSpecAsync(command, CancellationToken.None);
        var replay = await service.UpdateSpecAsync(
            command with { Actor = new ActorId("different-actor") },
            CancellationToken.None);

        Assert.Equal(
            "idempotency-key-reused",
            Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Failure>(replay).Error.Code);
    }

    [Fact]
    public async Task Replay_returns_the_original_update_after_later_updates()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);
        var resource = Fixture.Project();
        await service.CreateAsync(Fixture.Create(resource), CancellationToken.None);
        var first = Fixture.Update(resource.Metadata.Uid, new ResourceVersion("1"), 1);

        await service.UpdateSpecAsync(first, CancellationToken.None);
        await service.UpdateSpecAsync(
            Fixture.Update(resource.Metadata.Uid, new ResourceVersion("2"), 2),
            CancellationToken.None);
        var replay = await service.UpdateSpecAsync(first, CancellationToken.None);

        var original = Assert.IsType<ResourceStoreResult.AlreadyApplied>(
            Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Success>(replay).Value).Commit;
        Assert.Equal("2", original.Resource.ResourceVersion.Value);
        Assert.Equal("3", repository.Resources[resource.Metadata.Uid].ResourceVersion.Value);
    }

    [Theory]
    [InlineData("Invalid")]
    [InlineData("non_ascii-é")]
    [InlineData("-leading-dash")]
    [InlineData("trailing-dash-")]
    public void Creation_rejects_untrusted_or_invalid_resource_envelopes(string name)
    {
        var project = Fixture.Project() with
        {
            Metadata = Fixture.Project().Metadata with { Name = name }
        };

        var result = ResourceCommandDecisions.Create(Fixture.Create(project));

        Assert.Equal(
            "invalid-resource-name",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Creation_rejects_a_non_initial_version()
    {
        var project = Fixture.Project() with
        {
            Metadata = Fixture.Project().Metadata with
            {
                Generation = 2,
                ResourceVersion = new ResourceVersion("2")
            }
        };

        var result = ResourceCommandDecisions.Create(Fixture.Create(project));

        Assert.Equal(
            "invalid-initial-version",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Update_rejects_a_non_numeric_persisted_version()
    {
        var current = ResourceDocuments.From(Fixture.Project()) with
        {
            ResourceVersion = new ResourceVersion("opaque"),
            Document = JsonSerializer.SerializeToElement(new
            {
                apiVersion = ArmadaApi.V1Alpha1,
                kind = "Project",
                metadata = new { resourceVersion = "opaque" }
            })
        };

        var result = ResourceCommandDecisions.UpdateSpec(
            current,
            Fixture.Update(current.Id, current.ResourceVersion, 1));

        Assert.Equal(
            "unsupported-resource-version",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Generic_spec_updates_reject_immutable_admission_decisions()
    {
        var workload = Fixture.Workload();
        var current = ResourceDocuments.From(Fixture.AdmissionDecision(workload));

        var result = ResourceCommandDecisions.UpdateSpec(
            current,
            Fixture.Update(current.Id, current.ResourceVersion, 1));

        Assert.Equal(
            "immutable-resource",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Project_documents_are_canonical_v1alpha1_and_round_trip_through_the_mapper()
    {
        var project = Fixture.Project();
        var document = ResourceDocuments.From(project).Document;

        Assert.Equal(project.Metadata.Uid.ToString(), document.GetProperty("metadata").GetProperty("uid").GetString());
        Assert.Equal("1", document.GetProperty("metadata").GetProperty("resourceVersion").GetString());
        Assert.Equal("GitHubRelease", document.GetProperty("spec").GetProperty("evidenceArchive").GetProperty("provider").GetString());
        Assert.IsType<Result<Project, ContractValidationError>.Success>(
            V1Alpha1Json.DeserializeProject(document.GetRawText()));
    }

    [Fact]
    public void Workload_documents_use_the_canonical_v1alpha1_mapper()
    {
        var document = ResourceDocuments.TryFrom(Fixture.Workload());

        var persisted = Assert.IsType<Result<PersistedResource, ResourceCommandFailure>.Success>(document).Value;
        Assert.Equal("GitHub", persisted.Document.GetProperty("spec").GetProperty("sourceProvider").GetString());
        Assert.IsType<Result<Workload, ContractValidationError>.Success>(
            V1Alpha1Json.DeserializeWorkload(persisted.Document.GetRawText()));
    }

    [Fact]
    public void Unsupported_resources_are_not_reflection_serialised()
    {
        var result = ResourceDocuments.TryFrom(new UnsupportedResource(Fixture.Project().Metadata));

        Assert.Equal(
            "unsupported-canonical-resource",
            Assert.IsType<Result<PersistedResource, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Update_rejects_an_invalid_persisted_canonical_document()
    {
        var current = ResourceDocuments.From(Fixture.Project()) with
        {
            Document = JsonSerializer.SerializeToElement(new { invalid = true })
        };

        var result = ResourceCommandDecisions.UpdateSpec(
            current,
            Fixture.Update(current.Id, current.ResourceVersion, 1));

        Assert.Equal(
            "invalid-persisted-document",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Update_rejects_a_command_for_another_resource()
    {
        var current = ResourceDocuments.From(Fixture.Project());

        var result = ResourceCommandDecisions.UpdateSpec(
            current,
            Fixture.Update(ResourceId.New(), current.ResourceVersion, 1));

        Assert.Equal(
            "resource-id-mismatch",
            Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public async Task Update_of_a_missing_resource_does_not_write_a_partial_effect()
    {
        var repository = new InMemoryResourceRepository();
        var service = new ResourceApplicationService(repository);

        var result = await service.UpdateSpecAsync(
            Fixture.Update(ResourceId.New(), new ResourceVersion("1"), 1),
            CancellationToken.None);

        Assert.Equal(
            "resource-not-found",
            Assert.IsType<Result<ResourceStoreResult, ResourceCommandFailure>.Failure>(result).Error.Code);
        Assert.Empty(repository.Ledger);
        Assert.Empty(repository.Outbox);
    }

    [Property(MaxTest = 100)]
    public void Version_advancement_is_monotonic_and_preserves_non_spec_state(PositiveInt increments)
    {
        var current = ResourceDocuments.From(Fixture.Project());
        var count = Math.Min(increments.Get, 100);

        for (var index = 0; index < count; index++)
        {
            var decision = ResourceCommandDecisions.UpdateSpec(
                current,
                Fixture.Update(current.Id, current.ResourceVersion, index));
            current = Assert.IsType<Result<ResourceCommit, ResourceCommandFailure>.Success>(decision).Value.Resource;
        }

        Assert.Equal((count + 1).ToString(), current.ResourceVersion.Value);
        Assert.Equal(count + 1, current.Generation);
        Assert.Equal("Project", current.Document.GetProperty("kind").GetString());
        Assert.True(current.Document.TryGetProperty("status", out _));
    }

    [Fact]
    public async Task Policy_failure_is_not_converted_to_admission_success()
    {
        var service = new AdmissionApplicationService(
            new FailingPolicy(),
            new InMemoryResourceRepository());

        var result = await service.AdmitAsync(
            Fixture.Workload(),
            new ActorId("admission-controller"),
            Guid.NewGuid(),
            null,
            Fixture.Now,
            CancellationToken.None);

        var failure = Assert.IsType<Result<ResourceStoreResult, AdmissionCommandFailure>.Failure>(result);
        Assert.Equal("policy-unavailable", failure.Error.Code);
    }

    [Fact]
    public async Task Admission_persists_only_a_valid_policy_decision_with_an_outbox_effect()
    {
        var workload = Fixture.Workload();
        var repository = new InMemoryResourceRepository();
        var service = new AdmissionApplicationService(new AdmittingPolicy(Fixture.AdmissionDecision(workload)), repository);

        var result = await service.AdmitAsync(
            workload,
            new ActorId("admission-controller"),
            Guid.NewGuid(),
            null,
            Fixture.Now,
            CancellationToken.None);

        Assert.IsType<Result<ResourceStoreResult, AdmissionCommandFailure>.Success>(result);
        Assert.Single(repository.Resources);
        Assert.Single(repository.Ledger);
        Assert.Single(repository.Outbox);
        Assert.Equal("AdmissionDecision.created", repository.Ledger.Single().Type);
    }

    [Fact]
    public void Admission_rejects_wrong_workload_generation()
    {
        var workload = Fixture.Workload();
        var decision = Fixture.AdmissionDecision(workload) with
        {
            Spec = Fixture.AdmissionDecision(workload).Spec with { WorkloadGeneration = 99 }
        };

        var result = AdmissionDecisions.Decide(
            new(
                workload,
                decision,
                new ActorId("admission-controller"),
                Guid.NewGuid(),
                null,
                Fixture.Now));

        var failure = Assert.IsType<Result<CreateResourceCommand, AdmissionCommandFailure>.Failure>(result);
        Assert.Equal("admission-workload-binding-mismatch", failure.Error.Code);
    }

    [Fact]
    public void Admission_rejects_each_mismatched_workload_authority_constraint()
    {
        var workload = Fixture.Workload();
        var decision = Fixture.AdmissionDecision(workload);
        var cases = new (string Code, AdmissionDecision Decision)[]
        {
            ("admission-bundle-mismatch", decision with { Spec = decision.Spec with { BundleDigest = Fixture.OtherDigest() } }),
            ("admission-policy-mismatch", decision with { Spec = decision.Spec with { PolicyDigest = Fixture.OtherDigest() } }),
            ("admission-source-binding-mismatch", decision with { Spec = decision.Spec with { SourceRevision = new string('f', 40) } }),
            ("admission-session-authority-mismatch", decision with { Spec = decision.Spec with { SessionAuthority = SessionAuthority.IssueMasterWithChildren } }),
            ("admission-isolation-profile-mismatch", decision with { Spec = decision.Spec with { IsolationProfile = IsolationProfile.IsolatedContainer } }),
            ("admission-resource-limits-mismatch", decision with { Spec = decision.Spec with { ResourceLimits = new ResourceRequirements(101, 0, 1024, 1024) } }),
            ("admission-approved-actions-mismatch", decision with { Spec = decision.Spec with { ApprovedActions = ["unapproved-action"] } })
        };

        foreach (var testCase in cases)
        {
            var result = AdmissionDecisions.Decide(
                new(workload, testCase.Decision, new ActorId("admission-controller"), Guid.NewGuid(), null, Fixture.Now));

            Assert.Equal(
                testCase.Code,
                Assert.IsType<Result<CreateResourceCommand, AdmissionCommandFailure>.Failure>(result).Error.Code);
        }
    }

    private sealed class FailingPolicy : IAdmissionPolicy
    {
        public Task<Result<AdmissionDecision, PolicyFailure>> EvaluateAsync(
            Workload workload,
            CancellationToken cancellationToken) =>
            Task.FromResult<Result<AdmissionDecision, PolicyFailure>>(
                new Result<AdmissionDecision, PolicyFailure>.Failure(
                    new("policy-unavailable", "The signed policy evaluator did not return a decision.")));
    }

    private sealed class AdmittingPolicy(AdmissionDecision decision) : IAdmissionPolicy
    {
        public Task<Result<AdmissionDecision, PolicyFailure>> EvaluateAsync(
            Workload workload,
            CancellationToken cancellationToken) =>
            Task.FromResult<Result<AdmissionDecision, PolicyFailure>>(
                new Result<AdmissionDecision, PolicyFailure>.Success(decision));
    }

    private sealed record UnsupportedResource(ResourceMetadata Metadata) : IArmadaResource
    {
        public string ApiVersion => ArmadaApi.V1Alpha1;
        public string Kind => "Node";
    }

    private sealed class InMemoryResourceRepository : IResourceRepository
    {
        private readonly object gate = new();
        private readonly Dictionary<string, ResourceCommit> commits = [];

        public ConcurrentDictionary<ResourceId, PersistedResource> Resources { get; } = [];
        public ConcurrentBag<LedgerEvent> Ledger { get; } = [];
        public ConcurrentBag<OutboxRecord> Outbox { get; } = [];

        public Task<PersistedResource?> GetAsync(ResourceId id, CancellationToken cancellationToken) =>
            Task.FromResult(Resources.TryGetValue(id, out var resource) ? resource : null);

        public Task<ResourceCommit?> FindByIdempotencyKeyAsync(string idempotencyKey, CancellationToken cancellationToken)
        {
            lock (gate)
            {
                return Task.FromResult(commits.GetValueOrDefault(idempotencyKey));
            }
        }

        public Task<ResourceStoreResult> CreateAsync(ResourceCommit commit, CancellationToken cancellationToken)
        {
            lock (gate)
            {
                if (commits.TryGetValue(commit.LedgerEvent.IdempotencyKey, out var replay))
                {
                    return Task.FromResult<ResourceStoreResult>(new ResourceStoreResult.AlreadyApplied(replay));
                }

                if (!Resources.TryAdd(commit.Resource.Id, commit.Resource))
                {
                    return Task.FromResult<ResourceStoreResult>(
                        new ResourceStoreResult.Conflict(Resources[commit.Resource.Id].ResourceVersion));
                }

                commits.Add(commit.LedgerEvent.IdempotencyKey, commit);
                Ledger.Add(commit.LedgerEvent);
                Outbox.Add(new(commit.OutboxMessage.Id, commit.LedgerEvent.Id));
                return Task.FromResult<ResourceStoreResult>(new ResourceStoreResult.Committed(commit));
            }
        }

        public Task<ResourceStoreResult> CompareAndSwapAsync(
            ResourceCommit commit,
            ResourceVersion expectedVersion,
            CancellationToken cancellationToken)
        {
            lock (gate)
            {
                if (commits.TryGetValue(commit.LedgerEvent.IdempotencyKey, out var replay))
                {
                    return Task.FromResult<ResourceStoreResult>(new ResourceStoreResult.AlreadyApplied(replay));
                }

                if (!Resources.TryGetValue(commit.Resource.Id, out var current) ||
                    current.ResourceVersion != expectedVersion)
                {
                    return Task.FromResult<ResourceStoreResult>(
                        new ResourceStoreResult.Conflict(current?.ResourceVersion));
                }

                Resources[commit.Resource.Id] = commit.Resource;
                commits.Add(commit.LedgerEvent.IdempotencyKey, commit);
                Ledger.Add(commit.LedgerEvent);
                Outbox.Add(new(commit.OutboxMessage.Id, commit.LedgerEvent.Id));
                return Task.FromResult<ResourceStoreResult>(new ResourceStoreResult.Committed(commit));
            }
        }
    }

    private sealed record OutboxRecord(Guid Id, Guid EventId);
}

internal static class Fixture
{
    public static readonly DateTimeOffset Now = new(2026, 8, 22, 12, 0, 0, TimeSpan.Zero);

    public static Project Project() =>
        new(
            Metadata("project-one", null),
            CreateProjectSpec(),
            new(new(0, []), null));

    public static Workload Workload()
    {
        var project = new ProjectId(Guid.NewGuid());
        return new(
            Metadata("workload-one", project),
            new(
                Digest(),
                Digest(),
                new(Repository("johnazariah/agentic-armada")),
                "0123456789012345678901234567890123456789",
                Digest(),
                ["worktree"],
                new(),
                SessionAuthority.IssueMaster,
                IsolationProfile.DedicatedNode,
                new(2),
                new(null, [], null, null, new(100, 0, 1024, 1024), null, null),
                new(new(Repository("johnazariah/armada-evidence")), "standard")),
            new(new(0, []), WorkloadLifecycleState.Desired, null, null, null, null, null, null, null, null, null));
    }

    public static AdmissionDecision AdmissionDecision(Workload workload) =>
        new(
            workload.Metadata with
            {
                Uid = ResourceId.New(),
                Name = "admission-one"
            },
            new(
                workload.Metadata.Uid,
                workload.Metadata.Generation,
                ResourceId.New(),
                workload.Spec.BundleDigest,
                workload.Spec.PolicyDigest,
                workload.Spec.Source.Repository,
                workload.Spec.SourceRevision,
                workload.Spec.ConfigDigest,
                ["worktree"],
                SessionAuthority.IssueMaster,
                IsolationProfile.DedicatedNode,
                new(100, 0, 1024, 1024),
                [],
                ["github.com"],
                Digest(),
                Now.AddMinutes(5)),
            new(new(0, []), AdmissionVerdict.Admitted, Digest()));

    public static CreateResourceCommand Create(IArmadaResource resource) =>
        new(resource, new ActorId("api-user"), Guid.NewGuid(), null, Now);

    public static UpdateResourceSpecCommand Update(
        ResourceId id,
        ResourceVersion version,
        int revision,
        TransitionId? idempotencyKey = null) =>
        new(
            id,
            version,
            idempotencyKey ?? TransitionId.New(),
            CreateProjectSpec(revision),
            new ActorId("api-user"),
            Guid.NewGuid(),
            null,
            Now.AddMinutes(1));

    private static ProjectSpec CreateProjectSpec(int revision = 0) =>
        new(
            [Repository("johnazariah/agentic-armada")],
            new(Repository("johnazariah/armada-evidence")),
            new(Digest()),
            Digest(),
            revision == 0 ? null : revision);

    private static ResourceMetadata Metadata(string name, ProjectId? projectId) =>
        new(
            ResourceId.New(),
            new OrganisationId(Guid.NewGuid()),
            projectId,
            name,
            new ResourceVersion("1"),
            1,
            ImmutableValues.EmptyLabels,
            ImmutableValues.EmptyLabels,
            ImmutableValues.EmptyOwners,
            ImmutableValues.EmptyFinalizers,
            Now,
            Now);

    private static RepositoryName Repository(string value) =>
        ((Result<RepositoryName, ContractValidationError>.Success)RepositoryName.Parse(value)).Value;

    private static Sha256Digest Digest() =>
        ((Result<Sha256Digest, ContractValidationError>.Success)Sha256Digest.Parse($"sha256:{new string('a', 64)}")).Value;

    public static Sha256Digest OtherDigest() =>
        ((Result<Sha256Digest, ContractValidationError>.Success)Sha256Digest.Parse($"sha256:{new string('b', 64)}")).Value;
}

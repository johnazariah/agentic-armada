using System.Collections.Immutable;
using Armada.Contracts;
using Armada.Domain;
using Armada.NodeAgent;

namespace Armada.NodeAgent.Tests;

public sealed class SessionAdapterTests
{
    [Fact]
    public async Task Parent_creation_is_idempotent_and_supports_observe_wake_cancel_and_archive()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        var create = fixture.Create(fixture.Parent);

        var first = Value(await adapter.CreateParentAsync(create, CancellationToken.None));
        var replay = Value(await adapter.CreateParentAsync(create, CancellationToken.None));
        Assert.Equal(first, replay);

        var request = fixture.Operation(fixture.Parent);
        Assert.Equal(SessionLiveness.Idle, Value(await adapter.ObserveParentAsync(request, CancellationToken.None)).Liveness);
        Assert.Equal(SessionLiveness.Active, Value(await adapter.WakeParentAsync(request, CancellationToken.None)).Liveness);
        Assert.Equal(SessionLiveness.Terminal, Value(await adapter.CancelParentAsync(request, CancellationToken.None)).Liveness);
        Assert.Equal(
            "independent-evidence-required",
            Failure(await adapter.ArchiveParentAsync(request with { Evidence = null }, CancellationToken.None)).Code);
        Assert.True(Value(await adapter.ArchiveParentAsync(request, CancellationToken.None)).Session.Status.ArchiveComplete);
    }

    [Fact]
    public async Task Child_creation_requires_authority_and_exact_parent_binding()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);

        var refused = await adapter.CreateChildAsync(
            fixture.Create(fixture.Child, SessionAuthority.IssueMaster),
            fixture.Parent,
            CancellationToken.None);
        Assert.Equal("child-session-authority-refused", Failure(refused).Code);

        await adapter.WakeParentAsync(fixture.Operation(fixture.Parent), CancellationToken.None);
        var created = Value(await adapter.CreateChildAsync(
            fixture.Create(fixture.Child, SessionAuthority.IssueMasterWithChildren),
            fixture.Parent,
            CancellationToken.None));
        Assert.Equal(AgentSessionRole.Child, created.Session.Spec.Role);
        Assert.True(Value(await adapter.ArchiveChildAsync(fixture.Operation(fixture.Child), fixture.Parent, CancellationToken.None)).Session.Status.ArchiveComplete);
    }

    [Fact]
    public async Task Parent_creation_refuses_an_envelope_that_exceeds_admission()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();

        var refused = await adapter.CreateParentAsync(
            fixture.Create(fixture.Parent, SessionAuthority.None),
            CancellationToken.None);

        Assert.Equal("capability-envelope-outside-admission", Failure(refused).Code);
    }

    [Fact]
    public async Task Session_operations_refuse_a_node_not_bound_to_the_admitted_attempt()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        var wrongNode = fixture.Parent with
        {
            Spec = fixture.Parent.Spec with { NodeReference = ResourceId.New() }
        };

        var refused = await adapter.CreateParentAsync(fixture.Create(wrongNode), CancellationToken.None);
        Assert.Equal("session-operation-authority-mismatch", Failure(refused).Code);
    }

    [Fact]
    public async Task Parent_creation_and_operations_refuse_cross_project_or_organisation_scope()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        var crossProject = fixture.Parent with
        {
            Metadata = fixture.Parent.Metadata with { ProjectId = new ProjectId(Guid.NewGuid()) }
        };
        Assert.Equal("session-scope-mismatch", Failure(await adapter.CreateParentAsync(fixture.Create(crossProject), CancellationToken.None)).Code);

        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        var crossOrganisation = fixture.Parent with
        {
            Metadata = fixture.Parent.Metadata with { OrganisationId = new OrganisationId(Guid.NewGuid()) }
        };
        Assert.Equal(
            "session-metadata-mismatch",
            Failure(await adapter.ObserveParentAsync(fixture.Operation(crossOrganisation), CancellationToken.None)).Code);
    }

    [Fact]
    public async Task Archived_parent_cannot_be_woken_or_used_to_create_children()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        var request = fixture.Operation(fixture.Parent);
        await adapter.WakeParentAsync(request, CancellationToken.None);
        await adapter.CancelParentAsync(request, CancellationToken.None);
        await adapter.ArchiveParentAsync(request, CancellationToken.None);

        Assert.Equal("invalid-session-transition", Failure(await adapter.WakeParentAsync(request, CancellationToken.None)).Code);
        Assert.Equal(
            "child-session-authority-refused",
            Failure(await adapter.CreateChildAsync(fixture.Create(fixture.Child), fixture.Parent, CancellationToken.None)).Code);
    }

    [Fact]
    public async Task Terminal_archive_allows_verified_evidence_after_execution_admission_expires()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        var request = fixture.Operation(fixture.Parent);
        await adapter.WakeParentAsync(request, CancellationToken.None);
        await adapter.CancelParentAsync(request, CancellationToken.None);

        var archived = Value(await adapter.ArchiveParentAsync(
            request with { OccurredAt = fixture.AfterAdmissionExpiry },
            CancellationToken.None));
        Assert.True(archived.Session.Status.ArchiveComplete);
    }

    [Fact]
    public async Task Child_creation_refuses_cross_attempt_and_cross_node_bindings()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        await adapter.WakeParentAsync(fixture.Operation(fixture.Parent), CancellationToken.None);

        var otherAttempt = fixture.Attempt with { Metadata = fixture.Metadata("other-attempt") };
        var crossAttempt = fixture.Child with
        {
            Spec = fixture.Child.Spec with { AttemptReference = otherAttempt.Metadata.Uid }
        };
        Assert.Equal(
            "child-session-authority-refused",
            Failure(await adapter.CreateChildAsync(fixture.Create(crossAttempt, attempt: otherAttempt), fixture.Parent, CancellationToken.None)).Code);

        var otherNode = ResourceId.New();
        var otherAdmission = fixture.Admission with
        {
            Metadata = fixture.Metadata("other-admission"),
            Spec = fixture.Admission.Spec with { NodeReference = otherNode }
        };
        var nodeAttempt = fixture.Attempt with
        {
            Metadata = fixture.Metadata("node-attempt"),
            Spec = fixture.Attempt.Spec with
            {
                NodeReference = otherNode,
                AdmissionDecisionReference = otherAdmission.Metadata.Uid
            }
        };
        var crossNode = fixture.Child with
        {
            Spec = fixture.Child.Spec with
            {
                AttemptReference = nodeAttempt.Metadata.Uid,
                NodeReference = otherNode
            }
        };
        Assert.Equal(
            "child-session-authority-refused",
            Failure(await adapter.CreateChildAsync(
                fixture.Create(crossNode, attempt: nodeAttempt, admission: otherAdmission),
                fixture.Parent,
                CancellationToken.None)).Code);
    }

    [Fact]
    public async Task Child_creation_replays_by_parent_attempt_and_idempotency_key()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        await adapter.WakeParentAsync(fixture.Operation(fixture.Parent), CancellationToken.None);

        var created = Value(await adapter.CreateChildAsync(fixture.Create(fixture.Child), fixture.Parent, CancellationToken.None));
        var replay = Value(await adapter.CreateChildAsync(fixture.Create(fixture.Child), fixture.Parent, CancellationToken.None));
        Assert.Equal(created, replay);

        var collision = fixture.Child with { Metadata = fixture.Metadata("different-child") };
        Assert.Equal(
            "child-idempotency-key-reused",
            Failure(await adapter.CreateChildAsync(fixture.Create(collision), fixture.Parent, CancellationToken.None)).Code);
    }

    [Fact]
    public async Task Disappeared_parent_is_replaced_once_with_durable_successor_replay()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        Value(await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None));
        Value(adapter.MarkDisappearedForReconciliation(fixture.Parent));

        var replacement = fixture.Parent with { Metadata = fixture.Metadata("replacement") };
        var request = fixture.Create(replacement, replaces: fixture.Parent.Metadata.Uid);
        var created = Value(await adapter.CreateParentAsync(request, CancellationToken.None));
        var replay = Value(await adapter.CreateParentAsync(request, CancellationToken.None));

        Assert.Equal(replacement.Metadata.Uid, created.Session.Metadata.Uid);
        Assert.Equal(created, replay);
        Assert.Equal(replacement.Metadata.Uid, adapter.Successors[fixture.Parent.Metadata.Uid]);

        var conflicting = replacement with { Metadata = fixture.Metadata("replacement-conflict") };
        Assert.Equal(
            "parent-idempotency-key-reused",
            Failure(await adapter.CreateParentAsync(
                fixture.Create(conflicting, replaces: fixture.Parent.Metadata.Uid),
                CancellationToken.None)).Code);
    }

    [Fact]
    public async Task Conflicting_second_replacement_persists_no_successor_or_replay_state()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        Value(await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None));
        Value(adapter.MarkDisappearedForReconciliation(fixture.Parent));

        var first = fixture.Parent with { Metadata = fixture.Metadata("replacement-first") };
        Value(await adapter.CreateParentAsync(
            fixture.Create(first, replaces: fixture.Parent.Metadata.Uid),
            CancellationToken.None));

        var second = fixture.Parent with
        {
            Metadata = fixture.Metadata("replacement-second"),
            Spec = fixture.Parent.Spec with { IdempotencyKey = "alternate-replacement" }
        };
        var request = fixture.Create(second, replaces: fixture.Parent.Metadata.Uid);
        Assert.Equal(
            "replacement-successor-already-exists",
            Failure(await adapter.CreateParentAsync(request, CancellationToken.None)).Code);
        Assert.Equal(first.Metadata.Uid, adapter.Successors[fixture.Parent.Metadata.Uid]);

        Assert.Equal(
            "replacement-successor-already-exists",
            Failure(await adapter.CreateParentAsync(request, CancellationToken.None)).Code);
        Assert.Equal(first.Metadata.Uid, adapter.Successors[fixture.Parent.Metadata.Uid]);
    }

    [Fact]
    public async Task Durable_observations_bind_session_attempt_correlation_and_envelope()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        var request = fixture.Operation(fixture.Parent);
        var observation = fixture.Observation(SessionObservationKind.Terminal, TerminalOutcome.Completed) with { CorrelationId = request.CorrelationId };

        Assert.Equal(observation, Value(await adapter.EmitObservationAsync(request, observation, CancellationToken.None)));
        Assert.Single(adapter.Observations);

        var invalid = await adapter.EmitObservationAsync(
            request,
            observation with { CapabilityEnvelopeDigest = fixture.Digest('a') },
            CancellationToken.None);
        Assert.Equal("capability-envelope-mismatch", Failure(invalid).Code);
    }

    [Fact]
    public async Task Plan_decisions_cannot_expand_the_capability_envelope()
    {
        var fixture = new AdapterFixture();
        var adapter = new InMemorySessionAdapter();
        await adapter.CreateParentAsync(fixture.Create(fixture.Parent), CancellationToken.None);
        var request = fixture.Operation(fixture.Parent);
        var plan = new PlanDecisionObservation(
            fixture.Observation(SessionObservationKind.PlanDecision) with { CorrelationId = request.CorrelationId },
            PlanDecision.Approved,
            ImmutableHashSet.Create("write"));

        Assert.Equal("plan-action-outside-grant", Failure(await adapter.EmitPlanDecisionAsync(request, plan, CancellationToken.None)).Code);
    }

    [Fact]
    public void Github_copilot_profile_fails_closed_without_an_exact_supported_local_contract()
    {
        var fixture = new AdapterFixture();

        Assert.Equal("supported-local-integration-unavailable", Failure(GitHubCopilotAdapterProfile.Create(new(fixture.Digest('f')), null)).Code);
        Assert.Equal(
            "supported-local-integration-unavailable",
            Failure(GitHubCopilotAdapterProfile.Create(
                new(fixture.Digest('f')),
                new("GitHubCopilot", "v1", fixture.Digest('a'), new InMemorySessionAdapter()))).Code);

        Assert.Equal(
            "supported-local-integration-unavailable",
            Failure(GitHubCopilotAdapterProfile.Create(
                new(fixture.Digest('f')),
                new("GitHubCopilot", "v1", fixture.Digest('f'), new InMemorySessionAdapter()))).Code);
    }

    private static T Value<T>(Result<T, SessionAdapterFailure> result) =>
        Assert.IsType<Result<T, SessionAdapterFailure>.Success>(result).Value;

    private static SessionAdapterFailure Failure<T>(Result<T, SessionAdapterFailure> result) =>
        Assert.IsType<Result<T, SessionAdapterFailure>.Failure>(result).Error;

    private sealed class AdapterFixture
    {
        private readonly DateTimeOffset now = new(2026, 8, 23, 0, 0, 0, TimeSpan.Zero);
        public DateTimeOffset AfterAdmissionExpiry => now.AddHours(2);
        public AgentSession Parent { get; }
        public AgentSession Child { get; }
        public Attempt Attempt { get; }
        public AdmissionDecision Admission { get; }
        public CapabilityEnvelope Envelope { get; }

        public AdapterFixture()
        {
            var workload = ResourceId.New();
            var node = ResourceId.New();
            var admissionId = ResourceId.New();
            Attempt = new(
                Metadata("attempt"),
                new(workload, 1, node, admissionId, Digest('a'), Digest('b'), Digest('c'), Digest('d')),
                new(new(1, ImmutableArray<Condition>.Empty), null));
            Admission = new(
                Metadata("admission", admissionId),
                new(workload, 1, node, Digest('a'), Digest('b'), Repository(), "main", Digest('c'), ImmutableHashSet.Create("read"), SessionAuthority.IssueMasterWithChildren, IsolationProfile.DedicatedNode, new(1, 0, 1, 1), ImmutableArray.Create(Digest('d')), ImmutableHashSet<string>.Empty, Digest('e'), now.AddHours(1)),
                new(new(1, ImmutableArray<Condition>.Empty), AdmissionVerdict.Admitted, Digest('f')));
            Parent = Session("parent", Attempt.Metadata.Uid, node, AgentSessionRole.IssueMaster, null);
            Child = Session("child", Attempt.Metadata.Uid, node, AgentSessionRole.Child, Parent.Metadata.Uid);
            Envelope = new(Digest('f'), ImmutableHashSet.Create("read"), SessionAuthority.IssueMasterWithChildren);
        }

        public CreateSessionRequest Create(
            AgentSession session,
            SessionAuthority authority = SessionAuthority.IssueMasterWithChildren,
            Attempt? attempt = null,
            AdmissionDecision? admission = null,
            ResourceId? replaces = null) =>
            new(session, attempt ?? Attempt, admission ?? Admission, Envelope with { SessionAuthority = authority }, Guid.NewGuid(), now, replaces);

        public SessionOperationRequest Operation(AgentSession session, EvidenceReceipt? evidence = null) =>
            new(session, Attempt, Admission, Envelope, Guid.NewGuid(), "test operation", now, evidence ?? Evidence());

        public SessionObservation Observation(SessionObservationKind kind, TerminalOutcome? terminal = null) =>
            new(kind, Parent.Metadata.Uid, Parent.Spec.AttemptReference, Guid.NewGuid(), Envelope.Digest, now, "test observation", terminal);

        public Sha256Digest Digest(char value) => Sha256Digest.Parse($"sha256:{new string(value, 64)}") is Result<Sha256Digest, ContractValidationError>.Success success
            ? success.Value
            : throw new InvalidOperationException();

        private EvidenceReceipt Evidence() =>
            new(Metadata("evidence"), new(Attempt.Metadata.Uid, Digest('a'), new(Repository()), "release", Digest('b')), new(new(1, ImmutableArray<Condition>.Empty), EvidenceVerification.Verified, now));

        public ResourceMetadata Metadata(string name, ResourceId? id = null) =>
            new(id ?? ResourceId.New(), new(Guid.Parse("11111111-1111-1111-1111-111111111111")), new(Guid.Parse("22222222-2222-2222-2222-222222222222")), name, new("1"), 1, ImmutableValues.EmptyLabels, ImmutableDictionary<string, string>.Empty, ImmutableValues.EmptyOwners, ImmutableValues.EmptyFinalizers, now, now);

        private static RepositoryName Repository() => RepositoryName.Parse("octo/armada") is Result<RepositoryName, ContractValidationError>.Success success
            ? success.Value
            : throw new InvalidOperationException();

        private AgentSession Session(string name, ResourceId attempt, ResourceId node, AgentSessionRole role, ResourceId? parent) =>
            new(
                Metadata(name),
                new(attempt, node, new(Digest('f')), role, name, parent),
                new(new(1, ImmutableArray<Condition>.Empty), new("owner"), new("successor"), now, false));
    }
}

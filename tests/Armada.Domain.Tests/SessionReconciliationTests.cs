using System.Collections.Immutable;
using Armada.Contracts;
using Armada.Domain;
using FsCheck;
using FsCheck.Xunit;

namespace Armada.Domain.Tests;

public sealed class SessionReconciliationTests
{
    [Fact]
    public void Reconciliation_creates_one_deterministic_issue_master_intent()
    {
        var fixture = new SessionFixture();

        var first = Value(MajorDomoReconciliation.Reconcile(fixture.Input()));
        var replay = Value(MajorDomoReconciliation.Reconcile(fixture.Input()));

        var created = Assert.IsType<SessionReconciliationAction.EnsureIssueMaster>(Assert.Single(first));
        Assert.Equal(created, Assert.IsType<SessionReconciliationAction.EnsureIssueMaster>(Assert.Single(replay)));
        Assert.Equal(
            MajorDomoReconciliation.IssueMasterIdempotencyKey(fixture.Node.Metadata.Uid, fixture.Workload.Metadata.Uid, fixture.Workload.Metadata.Generation),
            created.Intent.IdempotencyKey);
    }

    [Fact]
    public void Idle_issue_master_is_woken_without_creating_a_duplicate()
    {
        var fixture = new SessionFixture();
        var actions = Value(MajorDomoReconciliation.Reconcile(fixture.Input(
            fixture.Runtime(SessionLiveness.Idle))));

        var wake = Assert.IsType<SessionReconciliationAction.Wake>(Assert.Single(actions));
        Assert.Equal(fixture.Session.Metadata.Uid, wake.AgentSessionReference);
    }

    [Fact]
    public void Duplicate_active_issue_masters_produce_a_structured_blocker()
    {
        var fixture = new SessionFixture();
        var duplicate = fixture.Session with { Metadata = fixture.Metadata("second-session") };

        var actions = Value(MajorDomoReconciliation.Reconcile(fixture.Input(
            fixture.Runtime(SessionLiveness.Active),
            new SessionRuntime(duplicate, SessionLiveness.Active, fixture.Now))));

        var block = Assert.IsType<SessionReconciliationAction.Block>(Assert.Single(actions)).Condition;
        Assert.Equal("Blocked", block.Type);
        Assert.NotNull(block.Escalation);
        Assert.Contains("multiple active", block.Escalation!.ExactBlocker);
    }

    [Fact]
    public void Disappeared_owner_hands_off_and_replaces_the_issue_master()
    {
        var fixture = new SessionFixture();
        var actions = Value(MajorDomoReconciliation.Reconcile(fixture.Input(fixture.Runtime(SessionLiveness.Disappeared))));

        var handoff = Assert.IsType<SessionReconciliationAction.Handoff>(Assert.Single(actions));
        Assert.Equal(fixture.Workload.Status.Successor, handoff.Successor);
        var replacement = Assert.IsType<SessionReconciliationAction.EnsureIssueMaster>(Assert.Single(Value(
            MajorDomoReconciliation.Reconcile(fixture.Input(
                fixture.Runtime(SessionLiveness.Disappeared) with
                {
                    HandoffReceipt = new(
                        fixture.Session.Metadata.Uid,
                        fixture.Attempt.Metadata.Uid,
                        fixture.Workload.Status.Successor!,
                        fixture.Now)
                })))));
        Assert.Equal(fixture.Session.Metadata.Uid, replacement.Intent.ReplacesSessionReference);
    }

    [Fact]
    public void Disappeared_owner_without_a_durable_watchdog_protocol_is_refused()
    {
        var fixture = new SessionFixture();
        fixture.Workload = fixture.Workload with
        {
            Status = fixture.Workload.Status with { Watchdog = null }
        };

        var failure = Failure(MajorDomoReconciliation.Reconcile(fixture.Input(fixture.Runtime(SessionLiveness.Disappeared))));
        Assert.Equal("owner-protocol-incomplete", failure.Code);
    }

    [Fact]
    public void Terminal_pending_session_blocks_until_evidence_is_independently_verified()
    {
        var fixture = new SessionFixture();
        fixture.Workload = fixture.Workload with
        {
            Status = fixture.Workload.Status with { Lifecycle = WorkloadLifecycleState.TerminalPending }
        };

        var actions = Value(MajorDomoReconciliation.Reconcile(fixture.Input(fixture.Runtime(SessionLiveness.Terminal))));
        Assert.IsType<SessionReconciliationAction.Block>(Assert.Single(actions));
    }

    [Fact]
    public void Terminal_pending_session_archives_only_after_independent_evidence()
    {
        var fixture = new SessionFixture();
        fixture.Workload = fixture.Workload with
        {
            Status = fixture.Workload.Status with { Lifecycle = WorkloadLifecycleState.TerminalPending }
        };

        var evidence = fixture.Evidence(EvidenceVerification.Verified);
        var actions = Value(MajorDomoReconciliation.Reconcile(fixture.Input(fixture.Runtime(SessionLiveness.Terminal), evidence: evidence)));
        Assert.Equal(fixture.Session.Metadata.Uid, Assert.IsType<SessionReconciliationAction.Archive>(Assert.Single(actions)).AgentSessionReference);
    }

    [Fact]
    public void Terminal_evidence_cleanup_ignores_expired_execution_admission()
    {
        var fixture = new SessionFixture();
        fixture.Workload = fixture.Workload with
        {
            Status = fixture.Workload.Status with { Lifecycle = WorkloadLifecycleState.TerminalPending }
        };
        fixture.Admission = fixture.Admission with
        {
            Spec = fixture.Admission.Spec with { ExpiresAt = fixture.Now.AddMinutes(-1) }
        };

        var actions = Value(MajorDomoReconciliation.Reconcile(
            fixture.Input(fixture.Runtime(SessionLiveness.Terminal), fixture.Evidence(EvidenceVerification.Verified))));
        Assert.IsType<SessionReconciliationAction.Archive>(Assert.Single(actions));
    }

    [Fact]
    public void Reconciliation_refuses_an_expired_or_wrongly_bound_admission()
    {
        var fixture = new SessionFixture();
        fixture.Admission = fixture.Admission with
        {
            Spec = fixture.Admission.Spec with { ExpiresAt = fixture.Now }
        };

        Assert.Equal("session-authority-not-admitted", Failure(MajorDomoReconciliation.Reconcile(fixture.Input())).Code);
    }

    [Fact]
    public void Reconciliation_refuses_an_attempt_bound_to_another_admission()
    {
        var fixture = new SessionFixture();
        fixture.Attempt = fixture.Attempt with
        {
            Spec = fixture.Attempt.Spec with { AdmissionDecisionReference = ResourceId.New() }
        };

        Assert.Equal("attempt-binding-mismatch", Failure(MajorDomoReconciliation.Reconcile(fixture.Input())).Code);
    }

    [Fact]
    public void Child_creation_requires_explicit_admission_authority_and_parent_binding()
    {
        var fixture = new SessionFixture();
        var child = fixture.Session with
        {
            Metadata = fixture.Metadata("child"),
            Spec = fixture.Session.Spec with
            {
                Role = AgentSessionRole.Child,
                ParentSessionReference = fixture.Session.Metadata.Uid
            }
        };

        fixture.Admission = fixture.Admission with
        {
            Spec = fixture.Admission.Spec with { SessionAuthority = SessionAuthority.IssueMaster }
        };
        Assert.Equal("child-session-authority-refused", Failure(SessionAuthorityValidation.CanCreateChild(fixture.Admission, fixture.Session, child)).Code);

        fixture.Admission = fixture.Admission with
        {
            Spec = fixture.Admission.Spec with { SessionAuthority = SessionAuthority.IssueMasterWithChildren }
        };
        Assert.True(Value(SessionAuthorityValidation.CanCreateChild(fixture.Admission, fixture.Session, child)));
    }

    [Fact]
    public void Plan_and_observation_validation_refuse_capability_expansion_and_mismatched_bindings()
    {
        var fixture = new SessionFixture();
        var envelope = new CapabilityEnvelope(fixture.Digest('e'), ImmutableHashSet.Create("read"), SessionAuthority.IssueMasterWithChildren);
        var observation = new SessionObservation(
            SessionObservationKind.PlanDecision,
            fixture.Session.Metadata.Uid,
            fixture.Attempt.Metadata.Uid,
            Guid.NewGuid(),
            envelope.Digest,
            fixture.Now,
            "approved plan");

        var plan = new PlanDecisionObservation(observation, PlanDecision.Approved, ImmutableHashSet.Create("write"));
        Assert.Equal("plan-action-outside-grant", Failure(SessionAuthorityValidation.ValidatePlanDecision(fixture.Admission, envelope, plan)).Code);

        Assert.Equal(
            "session-observation-binding-mismatch",
            Failure(SessionAuthorityValidation.ValidateObservation(
                fixture.Session,
                envelope,
                observation with { AttemptReference = ResourceId.New() })).Code);
    }

    [Fact]
    public void Session_operations_require_the_complete_session_attempt_admission_chain()
    {
        var fixture = new SessionFixture();
        var envelope = new CapabilityEnvelope(fixture.Digest('e'), ImmutableHashSet.Create("read"), SessionAuthority.IssueMasterWithChildren);

        Assert.True(Value(SessionAuthorityValidation.ValidateOperation(
            fixture.Session,
            fixture.Attempt,
            fixture.Admission,
            envelope,
            fixture.Now)));

        Assert.Equal(
            "session-operation-authority-mismatch",
            Failure(SessionAuthorityValidation.ValidateOperation(
                fixture.Session with { Spec = fixture.Session.Spec with { NodeReference = ResourceId.New() } },
                fixture.Attempt,
                fixture.Admission,
                envelope,
                fixture.Now)).Code);
    }

    [Property]
    public void Issue_master_keys_are_stable_for_the_same_values(PositiveInt generation)
    {
        var node = ResourceId.New();
        var workload = ResourceId.New();
        var first = MajorDomoReconciliation.IssueMasterIdempotencyKey(node, workload, generation.Get);
        var second = MajorDomoReconciliation.IssueMasterIdempotencyKey(node, workload, generation.Get);

        Assert.Equal(first, second);
    }

    private static T Value<T>(Result<T, SessionReconciliationFailure> result) =>
        Assert.IsType<Result<T, SessionReconciliationFailure>.Success>(result).Value;

    private static SessionReconciliationFailure Failure<T>(Result<T, SessionReconciliationFailure> result) =>
        Assert.IsType<Result<T, SessionReconciliationFailure>.Failure>(result).Error;

    private sealed class SessionFixture
    {
        public DateTimeOffset Now { get; } = new(2026, 8, 23, 0, 0, 0, TimeSpan.Zero);
        public OrganisationId OrganisationId { get; } = new(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        public ProjectId ProjectId { get; } = new(Guid.Parse("22222222-2222-2222-2222-222222222222"));
        public Node Node { get; }
        public Workload Workload { get; set; }
        public AdmissionDecision Admission { get; set; }
        public Attempt Attempt { get; set; }
        public AgentSession Session { get; }

        public SessionFixture()
        {
            Node = new(Metadata("node"), new(ResourceId.New(), new(1, 1, 1, 1), DesiredNodeOperation.Active, ImmutableArray<Taint>.Empty), new(Common(), null, Now));
            Attempt = new(Metadata("attempt"), new(ResourceId.New(), 1, Node.Metadata.Uid, ResourceId.New(), Digest('b'), Digest('d'), Digest('f'), Digest('e')), new(Common(), null));
            Workload = new(
                Metadata("workload"),
                new(Digest('b'), Digest('d'), new(Repository()), "main", Digest('c'), ImmutableHashSet.Create("read", "write"), new(), SessionAuthority.IssueMasterWithChildren, IsolationProfile.DedicatedNode, new(1), Scheduling(), new(new(Repository()), "retained")),
                new(Common(), WorkloadLifecycleState.Running, Attempt.Metadata.Uid, new("owner"), new("successor"), Now.AddMinutes(1), Now.AddMinutes(10), new(30, 60), new("watchdog"), null, null));
            Admission = new(
                Metadata("admission"),
                new(Workload.Metadata.Uid, Workload.Metadata.Generation, Node.Metadata.Uid, Digest('b'), Digest('d'), Repository(), "main", Digest('c'), ImmutableHashSet.Create("read", "write"), SessionAuthority.IssueMasterWithChildren, IsolationProfile.DedicatedNode, Scheduling().Resources, ImmutableArray.Create(Digest('e')), ImmutableHashSet<string>.Empty, Digest('a'), Now.AddHours(1)),
                new(Common(), AdmissionVerdict.Admitted, Digest('a')));
            Attempt = Attempt with
            {
                Spec = Attempt.Spec with
                {
                    WorkloadReference = Workload.Metadata.Uid,
                    WorkloadGeneration = Workload.Metadata.Generation,
                    AdmissionDecisionReference = Admission.Metadata.Uid
                }
            };
            Session = new(Metadata("session"), new(Attempt.Metadata.Uid, Node.Metadata.Uid, new(Digest('f')), AgentSessionRole.IssueMaster, "issue-master", null), new(Common(), new("owner"), new("successor"), Now, false));
        }

        public SessionReconciliationInput Input(params SessionRuntime[] sessions) =>
            Input(sessions.ToImmutableArray(), null);

        public SessionReconciliationInput Input(SessionRuntime session, EvidenceReceipt? evidence = null) =>
            Input(ImmutableArray.Create(session), evidence);

        public SessionReconciliationInput Input(ImmutableArray<SessionRuntime> sessions, EvidenceReceipt? evidence = null) =>
            new(Node, Workload, Admission, Attempt, sessions, evidence, Now);

        public SessionRuntime Runtime(SessionLiveness liveness) => new(Session, liveness, Now);

        public EvidenceReceipt Evidence(EvidenceVerification verification) =>
            new(Metadata("evidence"), new(Attempt.Metadata.Uid, Digest('d'), new(Repository()), "release", Digest('a')), new(Common(), verification, verification == EvidenceVerification.Verified ? Now : null));

        public ResourceMetadata Metadata(string name) =>
            new(ResourceId.New(), OrganisationId, ProjectId, name, new("1"), 1, ImmutableValues.EmptyLabels, ImmutableDictionary<string, string>.Empty, ImmutableValues.EmptyOwners, ImmutableValues.EmptyFinalizers, Now, Now);

        public Sha256Digest Digest(char value) => Sha256Digest.Parse($"sha256:{new string(value, 64)}") is Result<Sha256Digest, ContractValidationError>.Success success
            ? success.Value
            : throw new InvalidOperationException();

        private static RepositoryName Repository() => RepositoryName.Parse("octo/armada") is Result<RepositoryName, ContractValidationError>.Success success
            ? success.Value
            : throw new InvalidOperationException();

        private static ResourceStatus Common() => new(1, ImmutableArray<Condition>.Empty);

        private static SchedulingRequirements Scheduling() => new(null, ImmutableArray<Toleration>.Empty, null, null, new(1, 0, 1, 1), null, null);
    }
}

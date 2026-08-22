using Armada.Contracts;
using System.Collections.Immutable;
using System.Reflection;
using System.Text.Json;
using FsCheck.Xunit;

namespace Armada.Contracts.Tests;

public sealed class ContractValidationTests
{
    [Fact]
    public void Blocked_condition_requires_a_complete_escalation()
    {
        var result = Condition.Create(
            "Blocked",
            ConditionStatus.True,
            "CertificateExpired",
            "The node certificate expired.",
            4,
            DateTimeOffset.UtcNow);

        var failure = Assert.IsType<Result<Condition, ContractValidationError>.Failure>(result);

        Assert.Equal("blocked-escalation-required", failure.Error.Code);
    }

    [Fact]
    public void Blocked_condition_preserves_the_structured_escalation()
    {
        var escalation = BlockedEscalation.Create(
            "certificate epoch 7 expired",
            new ActorId("node-identity-controller"),
            "approve or reject rotation request 812",
            "NodeIdentity/812",
            new ActorId("control-plane-operator"),
            DateTimeOffset.Parse("2026-08-22T00:15:00Z"));

        var escalationValue = Assert.IsType<Result<BlockedEscalation, ContractValidationError>.Success>(escalation).Value;
        var condition = Condition.Create(
            "Blocked",
            ConditionStatus.True,
            "CertificateExpired",
            "The node cannot claim work until its identity is resolved.",
            4,
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"),
            escalationValue);

        var conditionValue = Assert.IsType<Result<Condition, ContractValidationError>.Success>(condition).Value;

        Assert.Equal("certificate epoch 7 expired", conditionValue.Escalation!.ExactBlocker);
        Assert.Equal("NodeIdentity/812", conditionValue.Escalation.Location);
        Assert.Equal(new ActorId("control-plane-operator"), conditionValue.Escalation.Successor);
    }

    [Theory]
    [InlineData("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false)]
    [InlineData("sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
    public void Sha256_digest_is_fail_closed(string value, bool isValid)
    {
        var result = Sha256Digest.Parse(value);

        Assert.Equal(isValid, result.IsSuccess);
    }

    [Fact]
    public void Sha256_digest_has_no_public_constructor_and_json_validation_is_fail_closed()
    {
        Assert.Empty(typeof(Sha256Digest).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<Sha256Digest>("\"sha256:not-a-digest\""));

        var digest = Digest('c');
        var roundTrip = JsonSerializer.Deserialize<Sha256Digest>(JsonSerializer.Serialize(digest));

        Assert.Equal(digest, roundTrip);
    }

    [Fact]
    public void Primitive_validation_rejects_null_and_incomplete_values()
    {
        Assert.False(RepositoryName.Parse(null!).IsSuccess);
        Assert.False(BlockedEscalation.Create("", new ActorId(""), "", "", new ActorId(""), DateTimeOffset.UtcNow).IsSuccess);
        Assert.False(Condition.Create("", ConditionStatus.True, "", "", -1, DateTimeOffset.UtcNow).IsSuccess);
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Sha256Digest>("42"));
    }

    [Fact]
    public void Every_resource_exposes_the_v1alpha1_envelope_discriminator()
    {
        var metadata = Metadata(new ProjectId(Guid.Parse("22222222-2222-2222-2222-222222222222")));
        var status = Status();
        var repository = Repository("johnazariah/agentic-armada");
        var resources = new IArmadaResource[]
        {
            new Project(metadata with { ProjectId = null }, new ProjectSpec([repository], new GitHubReleaseEvidenceArchiveProfile(repository), new GitHubCopilotSessionProfile(Digest('a')), Digest('b'), null), new ProjectStatus(status, null)),
            new Node(metadata with { ProjectId = null }, new NodeSpec(ResourceId.New(), new NodeSchedulingCeiling(1, 1000, 1024, 1024), DesiredNodeOperation.Active, []), new NodeStatus(status, null, null)),
            new NodeIdentity(metadata with { ProjectId = null }, new NodeIdentitySpec(Digest('a'), NodeAssurance.DeviceKey, 1, null), new NodeIdentityStatus(status, null, null, null, null)),
            new Capability(metadata with { ProjectId = null }, new CapabilitySpec(ResourceId.New(), ["container"]), new CapabilityStatus(status, [], null, null)),
            new Workload(metadata, new WorkloadSpec(Digest('a'), Digest('b'), new GitHubSourceProfile(repository), new string('c', 40), Digest('d'), ["action"], new GitHubCopilotSessionProvider(), SessionAuthority.None, IsolationProfile.DedicatedNode, new GitHubIssue(1), new SchedulingRequirements(null, [], null, null, new ResourceRequirements(1, 0, 1, 1), null, null), new WorkloadEvidenceRequirement(new GitHubReleaseEvidenceArchiveProfile(repository), "standard")), new WorkloadStatus(status, WorkloadLifecycleState.Desired, null, null, null, null, null, null)),
            new AdmissionDecision(metadata, new AdmissionDecisionSpec(ResourceId.New(), 1, ResourceId.New(), Digest('a'), Digest('b'), ["action"], SessionAuthority.None, IsolationProfile.DedicatedNode, new ResourceRequirements(1, 0, 1, 1), [], [], Digest('d'), DateTimeOffset.UtcNow.AddHours(1)), new AdmissionDecisionStatus(status, AdmissionVerdict.Pending, null)),
            new Attempt(metadata, new AttemptSpec(ResourceId.New(), 1, ResourceId.New(), ResourceId.New(), Digest('a'), Digest('b'), Digest('c'), Digest('d')), new AttemptStatus(status, null)),
            new Lease(metadata, new LeaseSpec(ResourceId.New(), ResourceId.New(), 1, DateTimeOffset.UtcNow.AddHours(1)), new LeaseStatus(status, null, null)),
            new AgentSession(metadata, new AgentSessionSpec(ResourceId.New(), ResourceId.New(), new GitHubCopilotSessionProfile(Digest('a')), AgentSessionRole.IssueMaster, "key", null), new AgentSessionStatus(status, null, null, null, false)),
            new EvidenceReceipt(metadata, new EvidenceReceiptSpec(ResourceId.New(), Digest('a'), new GitHubReleaseEvidenceArchiveProfile(repository), "release", Digest('b')), new EvidenceReceiptStatus(status, EvidenceVerification.Pending, null)),
            new Event(metadata with { ProjectId = null }, new EventSpec("Observed", DateTimeOffset.UtcNow, new ActorId("controller"), Guid.NewGuid(), null, Digest('a')), status)
        };

        Assert.All(resources, resource => Assert.Equal(ArmadaApi.V1Alpha1, resource.ApiVersion));
        Assert.Equal(
            ["Project", "Node", "NodeIdentity", "Capability", "Workload", "AdmissionDecision", "Attempt", "Lease", "AgentSession", "EvidenceReceipt", "Event"],
            resources.Select(static resource => resource.Kind));
    }

    [Fact]
    public void Provider_profiles_are_explicit_typed_v1_profiles()
    {
        var repository = Assert.IsType<Result<RepositoryName, ContractValidationError>.Success>(
            RepositoryName.Parse("johnazariah/agentic-armada")).Value;
        var profile = new ProjectSpec(
            [repository],
            new GitHubReleaseEvidenceArchiveProfile(repository),
            new GitHubCopilotSessionProfile(Digest('a')),
            Digest('b'),
            100m);

        Assert.IsType<GitHubReleaseEvidenceArchiveProfile>(profile.EvidenceArchive);
        Assert.IsType<GitHubCopilotSessionProfile>(profile.SessionProfile);
        Assert.Equal(repository, profile.GitHubRepositories.Single());
    }

    [Fact]
    public void Project_round_trips_as_a_v1alpha1_schema_shaped_envelope()
    {
        var repository = Repository("johnazariah/agentic-armada");
        var escalation = Assert.IsType<Result<BlockedEscalation, ContractValidationError>.Success>(
            BlockedEscalation.Create(
                "certificate epoch expired",
                new ActorId("node-identity-controller"),
                "approve rotation",
                "NodeIdentity/identity-1",
                new ActorId("control-plane-operator"),
                DateTimeOffset.Parse("2026-08-22T00:15:00Z"))).Value;
        var blocked = Assert.IsType<Result<Condition, ContractValidationError>.Success>(
            Condition.Create(
                "Blocked",
                ConditionStatus.True,
                "CertificateExpired",
                "The node identity requires intervention.",
                1,
                DateTimeOffset.Parse("2026-08-22T00:00:00Z"),
                escalation)).Value;
        var project = new Project(
            Metadata(projectId: null),
            new ProjectSpec(
                [repository],
                new GitHubReleaseEvidenceArchiveProfile(Repository("johnazariah/agentic-armada-evidence")),
                new GitHubCopilotSessionProfile(Digest('a')),
                Digest('b'),
                100m),
            new ProjectStatus(new ResourceStatus(1, [blocked]), 37m));

        var json = V1Alpha1Json.Serialize(project);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var roundTrip = V1Alpha1Json.DeserializeProject(json);

        Assert.Equal("armada.io/v1alpha1", root.GetProperty("apiVersion").GetString());
        Assert.Equal("Project", root.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.String, root.GetProperty("metadata").GetProperty("uid").ValueKind);
        Assert.Equal("GitHubRelease", root.GetProperty("spec").GetProperty("evidenceArchive").GetProperty("provider").GetString());
        Assert.Equal("GitHubCopilot", root.GetProperty("spec").GetProperty("sessionProfile").GetProperty("provider").GetString());
        var projectRoundTrip = Assert.IsType<Result<Project, ContractValidationError>.Success>(roundTrip).Value;
        Assert.Equal(
            project.Spec.GitHubRepositories,
            projectRoundTrip.Spec.GitHubRepositories);
        Assert.Equal(37m, projectRoundTrip.Status.BudgetObserved);
        Assert.Equal("certificate epoch expired", projectRoundTrip.Status.Common.Conditions.Single().Escalation!.ExactBlocker);

        var nullOwner = V1Alpha1Json.DeserializeProject(
            json.Replace("\"ownerReferences\":[]", "\"ownerReferences\":[null]", StringComparison.Ordinal));

        Assert.Equal(
            "invalid-owner-reference",
            Assert.IsType<Result<Project, ContractValidationError>.Failure>(nullOwner).Error.Code);

        var unsupportedProvider = V1Alpha1Json.DeserializeProject(
            json.Replace("\"GitHubRelease\"", "\"UnsupportedArchive\"", StringComparison.Ordinal));

        Assert.Equal(
            "unsupported-provider-profile",
            Assert.IsType<Result<Project, ContractValidationError>.Failure>(unsupportedProvider).Error.Code);
    }

    [Fact]
    public void Workload_round_trips_as_a_v1alpha1_schema_shaped_envelope()
    {
        var repository = Repository("johnazariah/agentic-armada");
        var policyDigest = Digest('d');
        var workload = new Workload(
            Metadata(new ProjectId(Guid.Parse("22222222-2222-2222-2222-222222222222"))),
            new WorkloadSpec(
                Digest('a'),
                policyDigest,
                new GitHubSourceProfile(repository),
                new string('c', 40),
                Digest('b'),
                ImmutableHashSet.Create("create-worktree"),
                new GitHubCopilotSessionProvider(),
                SessionAuthority.IssueMaster,
                IsolationProfile.IsolatedContainer,
                new GitHubIssue(42),
                new SchedulingRequirements(
                    new LabelSelector(ImmutableDictionary<string, string>.Empty.Add("os", "macos")),
                    [new Toleration("dedicated", "Equal", "armada", TaintEffect.NoSchedule)],
                    new LabelSelector(ImmutableDictionary<string, string>.Empty.Add("region", "ap-southeast-2")),
                    new LabelSelector(ImmutableDictionary<string, string>.Empty.Add("host", "other")),
                    new ResourceRequirements(1000, 0, 1024, 2048),
                    12m,
                    "Preferred"),
                new WorkloadEvidenceRequirement(
                    new GitHubReleaseEvidenceArchiveProfile(Repository("johnazariah/agentic-armada-evidence")),
                    "standard")),
            new WorkloadStatus(
                Status(),
                WorkloadLifecycleState.StartApproved,
                ResourceId.New(),
                new ActorId("issue-master"),
                new ActorId("successor"),
                DateTimeOffset.Parse("2026-08-22T00:05:00Z"),
                DateTimeOffset.Parse("2026-08-22T00:10:00Z"),
                new GitHubPullRequest(84, "PR_kwDO")));

        var json = V1Alpha1Json.Serialize(workload);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var roundTrip = V1Alpha1Json.DeserializeWorkload(json);

        Assert.Equal("GitHub", root.GetProperty("spec").GetProperty("sourceProvider").GetString());
        Assert.Equal("GitHubCopilot", root.GetProperty("spec").GetProperty("sessionProvider").GetString());
        Assert.Equal("GitHubRelease", root.GetProperty("spec").GetProperty("evidence").GetProperty("archiveProvider").GetString());
        Assert.Equal("start-approved", root.GetProperty("status").GetProperty("lifecycle").GetString());
        var scheduling = root.GetProperty("spec").GetProperty("scheduling");
        Assert.Equal(12m, scheduling.GetProperty("maxEstimatedCost").GetDecimal());
        Assert.False(scheduling.TryGetProperty("maximumEstimatedCost", out _));
        Assert.Equal(
            workload.Spec.BundleDigest,
            Assert.IsType<Result<Workload, ContractValidationError>.Success>(roundTrip).Value.Spec.BundleDigest);

        var invalidEnum = V1Alpha1Json.DeserializeWorkload(json.Replace("IsolatedContainer", "UnsupportedIsolation", StringComparison.Ordinal));

        Assert.Equal(
            "invalid-isolation-profile",
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(invalidEnum).Error.Code);

        var invalidTaint = V1Alpha1Json.DeserializeWorkload(
            json.Replace("\"NoSchedule\"", "\"UnsupportedTaint\"", StringComparison.Ordinal));

        Assert.Equal(
            "invalid-taint-effect",
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(invalidTaint).Error.Code);

        var negativeSchemaCost = V1Alpha1Json.DeserializeWorkload(
            json.Replace("\"maxEstimatedCost\":12", "\"maxEstimatedCost\":-1", StringComparison.Ordinal));

        Assert.Equal(
            "invalid-maximum-estimated-cost",
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(negativeSchemaCost).Error.Code);
    }

    [Fact]
    public void Parseable_workload_missing_required_sections_returns_a_typed_failure()
    {
        const string json = """{"apiVersion":"armada.io/v1alpha1","kind":"Workload","metadata":null,"spec":null,"status":null}""";

        var exception = Record.Exception(() => V1Alpha1Json.DeserializeWorkload(json));
        var result = V1Alpha1Json.DeserializeWorkload(json);

        Assert.Null(exception);
        Assert.Equal(
            "missing-required-section",
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Workload_wire_requires_project_scoped_metadata()
    {
        var wire = ValidWorkloadWire() with
        {
            Metadata = ValidWorkloadWire().Metadata! with { ProjectId = null }
        };

        var result = V1Alpha1Json.FromWire(wire);

        Assert.Equal(
            "project-scope-required",
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(result).Error.Code);
    }

    [Theory]
    [InlineData("bundle-digest", "invalid-sha256-digest")]
    [InlineData("policy-digest", "invalid-sha256-digest")]
    [InlineData("config-digest", "invalid-sha256-digest")]
    [InlineData("source-provider", "unsupported-provider-profile")]
    [InlineData("session-provider", "unsupported-provider-profile")]
    [InlineData("archive-provider", "unsupported-provider-profile")]
    [InlineData("repository", "invalid-repository-name")]
    [InlineData("source-revision", "invalid-source-revision")]
    [InlineData("action-schemas", "invalid-action-schemas")]
    [InlineData("github-issue", "invalid-github-issue")]
    [InlineData("scheduling", "missing-required-section")]
    [InlineData("scheduling-resources", "missing-required-section")]
    [InlineData("evidence", "missing-required-section")]
    [InlineData("archive-repository", "invalid-repository-name")]
    [InlineData("retention-class", "invalid-evidence-requirement")]
    [InlineData("project-scope", "project-scope-required")]
    [InlineData("checkpoint-mode", "invalid-checkpoint-mode")]
    [InlineData("pull-request", "invalid-github-pull-request")]
    public void Workload_wire_required_fields_and_constraints_fail_closed(
        string boundary,
        string expectedCode)
    {
        var result = V1Alpha1Json.FromWire(InvalidWorkloadWire(boundary));

        Assert.Equal(
            expectedCode,
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(result).Error.Code);
    }

    [Theory]
    [InlineData("invalid-resource-id")]
    [InlineData("invalid-lifecycle")]
    [InlineData("invalid-session-authority")]
    [InlineData("invalid-taint-effect")]
    [InlineData("invalid-attempt-reference")]
    public void Parseable_wire_validation_returns_typed_errors_for_each_boundary(string expectedCode)
    {
        var wire = ValidWorkloadWire();
        wire = expectedCode switch
        {
            "invalid-resource-id" => wire with
            {
                Metadata = wire.Metadata! with { Uid = "not-a-uuid" }
            },
            "invalid-lifecycle" => wire with
            {
                Status = wire.Status! with { Lifecycle = "unknown" }
            },
            "invalid-session-authority" => wire with
            {
                Spec = wire.Spec! with { SessionAuthority = "Unbounded" }
            },
            "invalid-taint-effect" => wire with
            {
                Spec = wire.Spec! with
                {
                    Scheduling = wire.Spec.Scheduling! with
                    {
                        Tolerations = [new V1Alpha1TolerationWire("dedicated", "Equal", "armada", "Unknown")]
                    }
                }
            },
            _ => wire with
            {
                Status = wire.Status! with { AttemptRef = "not-a-uuid" }
            }
        };

        var result = V1Alpha1Json.FromWire(wire);

        Assert.Equal(
            expectedCode == "invalid-attempt-reference" ? "invalid-resource-id" : expectedCode,
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(result).Error.Code);
    }

    [Theory]
    [InlineData(0, 0, 1, 1, 0, "invalid-resource-requirements")]
    [InlineData(1, -1, 1, 1, 0, "invalid-resource-requirements")]
    [InlineData(1, 0, 0, 1, 0, "invalid-resource-requirements")]
    [InlineData(1, 0, 1, 0, 0, "invalid-resource-requirements")]
    [InlineData(1, 0, 1, 1, -1, "invalid-maximum-estimated-cost")]
    public void Workload_wire_rejects_invalid_scheduling_minima(
        int cpu,
        int gpu,
        long memory,
        long storage,
        int cost,
        string expectedCode)
    {
        var result = V1Alpha1Json.FromWire(WithScheduling(cpu, gpu, memory, storage, cost));

        Assert.Equal(
            expectedCode,
            Assert.IsType<Result<Workload, ContractValidationError>.Failure>(result).Error.Code);
    }

    [Property(MaxTest = 50)]
    public void Workload_scheduling_numeric_validation_is_fail_closed(
        int cpu,
        int gpu,
        int memory,
        int storage,
        int cost)
    {
        var result = V1Alpha1Json.FromWire(WithScheduling(cpu, gpu, memory, storage, cost));
        var valid = cpu >= 1 && gpu >= 0 && memory >= 1 && storage >= 1 && cost >= 0;

        Assert.Equal(valid, result.IsSuccess);
    }

    [Fact]
    public void Wire_status_and_metadata_validation_handles_invalid_conditions_and_references()
    {
        var wire = ValidProjectWire() with
        {
            Metadata = ValidProjectWire().Metadata! with
            {
                OwnerReferences = [new V1Alpha1OwnerReferenceWire("Project", "not-a-uuid")]
            }
        };
        var ownerResult = V1Alpha1Json.FromWire(wire);

        var invalidStatus = ValidProjectWire() with
        {
            Status = ValidProjectWire().Status! with
            {
                Conditions = [new V1Alpha1ConditionWire(
                    "Ready",
                    "Invalid",
                    "Unknown",
                    "Invalid status",
                    1,
                    DateTimeOffset.UtcNow,
                    null)]
            }
        };
        var statusResult = V1Alpha1Json.FromWire(invalidStatus);

        Assert.Equal(
            "invalid-owner-reference",
            Assert.IsType<Result<Project, ContractValidationError>.Failure>(ownerResult).Error.Code);
        Assert.Equal(
            "invalid-condition-status",
            Assert.IsType<Result<Project, ContractValidationError>.Failure>(statusResult).Error.Code);
    }

    [Fact]
    public void Project_wire_requires_all_nested_profiles()
    {
        var result = V1Alpha1Json.FromWire(ValidProjectWire() with
        {
            Spec = ValidProjectWire().Spec! with { SessionProfile = null }
        });

        Assert.Equal(
            "missing-required-section",
            Assert.IsType<Result<Project, ContractValidationError>.Failure>(result).Error.Code);
    }

    private static Sha256Digest Digest(char character) =>
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string(character, 64)}")).Value;

    private static RepositoryName Repository(string value) =>
        Assert.IsType<Result<RepositoryName, ContractValidationError>.Success>(
            RepositoryName.Parse(value)).Value;

    private static ResourceMetadata Metadata(ProjectId? projectId) =>
        new(
            ResourceId.New(),
            new OrganisationId(Guid.Parse("11111111-1111-1111-1111-111111111111")),
            projectId,
            "contract-test",
            new ResourceVersion("rv-1"),
            1,
            ImmutableDictionary<string, string>.Empty,
            ImmutableDictionary<string, string>.Empty,
            ImmutableArray<OwnerReference>.Empty,
            ImmutableArray<string>.Empty,
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"));

    private static ResourceStatus Status() =>
        new(1, ImmutableArray<Condition>.Empty);

    private static V1Alpha1ProjectWire ValidProjectWire() =>
        new(
            ArmadaApi.V1Alpha1,
            "Project",
            WireMetadata(projectId: null),
            new(
                new(["johnazariah/agentic-armada"]),
                new("GitHubRelease", "johnazariah/agentic-armada-evidence"),
                new("GitHubCopilot", Digest('a').Value),
                Digest('b').Value,
                100m),
            new(1, [], 10m));

    private static V1Alpha1WorkloadWire ValidWorkloadWire() =>
        new(
            ArmadaApi.V1Alpha1,
            "Workload",
            WireMetadata("22222222-2222-2222-2222-222222222222"),
            new(
                Digest('a').Value,
                Digest('b').Value,
                "GitHub",
                "johnazariah/agentic-armada",
                new string('c', 40),
                Digest('d').Value,
                ["create-worktree"],
                "GitHubCopilot",
                "IssueMaster",
                "IsolatedContainer",
                new(42, null),
                new(
                    null,
                    [],
                    null,
                    null,
                    new(1000, 0, 1024, 2048),
                    null,
                    null),
                new("GitHubRelease", "johnazariah/agentic-armada-evidence", "standard")),
            new(1, [], "desired", null, null, null, null, null, null));

    private static V1Alpha1WorkloadWire WithScheduling(
        int cpu,
        int gpu,
        long memory,
        long storage,
        decimal maximumEstimatedCost) =>
        ValidWorkloadWire() with
        {
            Spec = ValidWorkloadWire().Spec! with
            {
                Scheduling = ValidWorkloadWire().Spec!.Scheduling! with
                {
                    Resources = new V1Alpha1ResourceRequirementsWire(cpu, gpu, memory, storage),
                    MaximumEstimatedCost = maximumEstimatedCost
                }
            }
        };

    private static V1Alpha1WorkloadWire InvalidWorkloadWire(string boundary)
    {
        var wire = ValidWorkloadWire();
        var spec = wire.Spec!;

        return boundary switch
        {
            "bundle-digest" => wire with { Spec = spec with { BundleDigest = null! } },
            "policy-digest" => wire with { Spec = spec with { PolicyDigest = null! } },
            "config-digest" => wire with { Spec = spec with { ConfigDigest = null! } },
            "source-provider" => wire with { Spec = spec with { SourceProvider = "Other" } },
            "session-provider" => wire with { Spec = spec with { SessionProvider = "Other" } },
            "archive-provider" => wire with { Spec = spec with { Evidence = spec.Evidence! with { ArchiveProvider = "Other" } } },
            "repository" => wire with { Spec = spec with { Repository = null! } },
            "source-revision" => wire with { Spec = spec with { SourceRevision = "short" } },
            "action-schemas" => wire with { Spec = spec with { ActionSchemas = [] } },
            "github-issue" => wire with { Spec = spec with { GithubIssue = new(0, null) } },
            "scheduling" => wire with { Spec = spec with { Scheduling = null } },
            "scheduling-resources" => wire with { Spec = spec with { Scheduling = spec.Scheduling! with { Resources = null } } },
            "evidence" => wire with { Spec = spec with { Evidence = null } },
            "archive-repository" => wire with { Spec = spec with { Evidence = spec.Evidence! with { ArchiveRepository = null! } } },
            "retention-class" => wire with { Spec = spec with { Evidence = spec.Evidence! with { RetentionClass = string.Empty } } },
            "project-scope" => wire with { Metadata = wire.Metadata! with { ProjectId = null } },
            "checkpoint-mode" => wire with { Spec = spec with { Scheduling = spec.Scheduling! with { CheckpointMode = "Other" } } },
            "pull-request" => wire with { Status = wire.Status! with { GithubPullRequest = new(0, null) } },
            _ => throw new ArgumentOutOfRangeException(nameof(boundary), boundary, "Unknown workload validation boundary.")
        };
    }

    private static V1Alpha1MetadataWire WireMetadata(string? projectId) =>
        new(
            "11111111-1111-1111-1111-111111111111",
            "33333333-3333-3333-3333-333333333333",
            projectId,
            "contract-test",
            "rv-1",
            1,
            ImmutableDictionary<string, string>.Empty,
            ImmutableDictionary<string, string>.Empty,
            [],
            [],
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-22T00:00:00Z"),
            null);
}

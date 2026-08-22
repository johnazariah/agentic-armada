using Armada.Contracts;
using System.Collections.Immutable;
using System.Reflection;
using System.Text.Json;

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
        var project = new Project(
            Metadata(projectId: null),
            new ProjectSpec(
                [repository],
                new GitHubReleaseEvidenceArchiveProfile(Repository("johnazariah/agentic-armada-evidence")),
                new GitHubCopilotSessionProfile(Digest('a')),
                Digest('b'),
                100m),
            new ProjectStatus(Status(), null));

        var json = V1Alpha1Json.Serialize(project);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var roundTrip = V1Alpha1Json.DeserializeProject(json);

        Assert.Equal("armada.io/v1alpha1", root.GetProperty("apiVersion").GetString());
        Assert.Equal("Project", root.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.String, root.GetProperty("metadata").GetProperty("uid").ValueKind);
        Assert.Equal("GitHubRelease", root.GetProperty("spec").GetProperty("evidenceArchive").GetProperty("provider").GetString());
        Assert.Equal("GitHubCopilot", root.GetProperty("spec").GetProperty("sessionProfile").GetProperty("provider").GetString());
        Assert.Equal(
            project.Spec.GitHubRepositories,
            Assert.IsType<Result<Project, ContractValidationError>.Success>(roundTrip).Value.Spec.GitHubRepositories);
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
                    null,
                    ImmutableArray<Toleration>.Empty,
                    null,
                    null,
                    new ResourceRequirements(1000, 0, 1024, 2048),
                    12m,
                    "Preferred"),
                new WorkloadEvidenceRequirement(
                    new GitHubReleaseEvidenceArchiveProfile(Repository("johnazariah/agentic-armada-evidence")),
                    "standard")),
            new WorkloadStatus(
                Status(),
                WorkloadLifecycleState.StartApproved,
                null,
                null,
                null,
                null,
                null,
                null));

        var json = V1Alpha1Json.Serialize(workload);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var roundTrip = V1Alpha1Json.DeserializeWorkload(json);

        Assert.Equal("GitHub", root.GetProperty("spec").GetProperty("sourceProvider").GetString());
        Assert.Equal("GitHubCopilot", root.GetProperty("spec").GetProperty("sessionProvider").GetString());
        Assert.Equal("GitHubRelease", root.GetProperty("spec").GetProperty("evidence").GetProperty("archiveProvider").GetString());
        Assert.Equal("start-approved", root.GetProperty("status").GetProperty("lifecycle").GetString());
        Assert.Equal(
            workload.Spec.BundleDigest,
            Assert.IsType<Result<Workload, ContractValidationError>.Success>(roundTrip).Value.Spec.BundleDigest);
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
}

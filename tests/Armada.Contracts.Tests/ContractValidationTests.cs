using Armada.Contracts;
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

    private static Sha256Digest Digest(char character) =>
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string(character, 64)}")).Value;
}

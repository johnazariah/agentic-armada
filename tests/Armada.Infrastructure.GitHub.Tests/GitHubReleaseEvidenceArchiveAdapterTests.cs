using System.Security.Cryptography;
using System.Text.Json;
using Armada.Application;
using Armada.Contracts;
using Armada.Infrastructure.GitHub;

namespace Armada.Infrastructure.GitHub.Tests;

public sealed class GitHubReleaseEvidenceArchiveAdapterTests
{
    [Fact]
    public async Task Verifies_independently_retrieved_release_assets_and_provenance()
    {
        var fixture = EvidenceFixture.Create();

        var result = await fixture.Adapter.VerifyAsync(fixture.Expectation, CancellationToken.None);

        Assert.True(result.IsVerified);
        Assert.Equal("verified", result.Code);
    }

    [Fact]
    public async Task Rejects_missing_release_assets()
    {
        var fixture = EvidenceFixture.Create(includeManifest: false);

        var result = await fixture.Adapter.VerifyAsync(fixture.Expectation, CancellationToken.None);

        Assert.False(result.IsVerified);
        Assert.Equal("release-asset-missing", result.Code);
    }

    [Fact]
    public async Task Rejects_provider_or_repository_substitution()
    {
        var fixture = EvidenceFixture.Create();
        var substituted = fixture.Expectation with { Provider = "GitLab" };

        var result = await fixture.Adapter.VerifyAsync(substituted, CancellationToken.None);

        Assert.False(result.IsVerified);
        Assert.Equal("invalid-evidence-expectation", result.Code);
    }

    [Fact]
    public async Task Rejects_asset_tampering_even_when_the_api_declares_the_expected_digest()
    {
        var fixture = EvidenceFixture.Create(tamperEvidence: true);

        var result = await fixture.Adapter.VerifyAsync(fixture.Expectation, CancellationToken.None);

        Assert.False(result.IsVerified);
        Assert.Equal("release-asset-identity-mismatch", result.Code);
    }

    [Fact]
    public async Task Rejects_manifest_provenance_that_does_not_bind_the_expected_asset()
    {
        var fixture = EvidenceFixture.Create(provenanceDigest: Digest("different-provenance"));

        var result = await fixture.Adapter.VerifyAsync(fixture.Expectation, CancellationToken.None);

        Assert.False(result.IsVerified);
        Assert.Equal("evidence-provenance-mismatch", result.Code);
    }

    private static Sha256Digest Digest(string text) =>
        ParseDigest($"sha256:{Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)))}");

    private static Sha256Digest ParseDigest(string value) =>
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(Sha256Digest.Parse(value)).Value;

    private static RepositoryName ParseRepository(string value) =>
        Assert.IsType<Result<RepositoryName, ContractValidationError>.Success>(RepositoryName.Parse(value)).Value;

    private sealed record EvidenceFixture(
        GitHubReleaseEvidenceArchiveAdapter Adapter,
        GitHubReleaseEvidenceExpectation Expectation)
    {
        public static EvidenceFixture Create(
            bool includeManifest = true,
            bool tamperEvidence = false,
            Sha256Digest? provenanceDigest = null)
        {
            var archive = new GitHubReleaseEvidenceArchiveProfile(ParseRepository("octo/evidence"));
            var evidenceBytes = System.Text.Encoding.UTF8.GetBytes("retained evidence");
            var evidenceDigest = Digest("retained evidence");
            var expectedProvenance = Digest("provenance");
            var manifest = JsonSerializer.SerializeToUtf8Bytes(new
            {
                Provider = "GitHub",
                Repository = archive.Repository.Value,
                ReleaseId = "release-17",
                AssetName = "evidence.tar",
                AssetDigest = evidenceDigest.Value,
                ProvenanceDigest = (provenanceDigest ?? expectedProvenance).Value
            });
            var manifestDigest = ParseDigest(
                $"sha256:{Convert.ToHexStringLower(SHA256.HashData(manifest))}");
            var receipt = new EvidenceReceipt(
                Metadata(),
                new EvidenceReceiptSpec(ResourceId.New(), manifestDigest, archive, "release-17", evidenceDigest),
                new EvidenceReceiptStatus(new ResourceStatus(0, []), EvidenceVerification.Pending, null));
            var evidenceLocator = new GitHubReleaseAssetLocator("GitHub", archive.Repository, "release-17", "evidence.tar");
            var manifestLocator = evidenceLocator with { AssetName = "manifest.json" };
            var assets = new Dictionary<GitHubReleaseAssetLocator, GitHubReleaseAsset>
            {
                [evidenceLocator] = new(
                    evidenceLocator,
                    evidenceDigest,
                    tamperEvidence ? System.Text.Encoding.UTF8.GetBytes("tampered") : evidenceBytes)
            };
            if (includeManifest)
            {
                assets.Add(manifestLocator, new(manifestLocator, manifestDigest, manifest));
            }

            return new(
                new GitHubReleaseEvidenceArchiveAdapter(new InMemoryReleaseApi(assets)),
                new GitHubReleaseEvidenceExpectation(receipt, "GitHub", "evidence.tar", "manifest.json", expectedProvenance));
        }

        private static ResourceMetadata Metadata() =>
            new(
                ResourceId.New(),
                new OrganisationId(Guid.NewGuid()),
                new ProjectId(Guid.NewGuid()),
                "evidence-receipt",
                new ResourceVersion("1"),
                1,
                ImmutableValues.EmptyLabels,
                ImmutableValues.EmptyLabels,
                ImmutableValues.EmptyOwners,
                ImmutableValues.EmptyFinalizers,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch);
    }

    private sealed class InMemoryReleaseApi(
        IReadOnlyDictionary<GitHubReleaseAssetLocator, GitHubReleaseAsset> assets) : IGitHubReleaseApi
    {
        public Task<GitHubReleaseAsset?> GetAssetAsync(
            GitHubReleaseAssetLocator locator,
            CancellationToken cancellationToken) =>
            Task.FromResult(assets.TryGetValue(locator, out var asset) ? asset : null);
    }
}

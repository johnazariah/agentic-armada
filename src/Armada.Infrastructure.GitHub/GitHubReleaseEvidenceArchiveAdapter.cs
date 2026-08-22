using System.Security.Cryptography;
using System.Text.Json;
using Armada.Application;
using Armada.Contracts;

namespace Armada.Infrastructure.GitHub;

public sealed class GitHubReleaseEvidenceArchiveAdapter(IGitHubReleaseApi api) : IEvidenceArchive
{
    public async Task<EvidenceArchiveVerification> VerifyAsync(
        GitHubReleaseEvidenceExpectation expectation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectation);
        if (!string.Equals(expectation.Provider, "GitHub", StringComparison.Ordinal) ||
            !IsValid(expectation.Receipt, expectation.EvidenceAssetName, expectation.ManifestAssetName))
        {
            return Rejected("invalid-evidence-expectation", "Evidence verification requires explicit GitHub release, asset, and manifest identities.");
        }

        var evidenceLocator = new GitHubReleaseAssetLocator(
            expectation.Provider,
            expectation.Receipt.Spec.Archive.Repository,
            expectation.Receipt.Spec.ReleaseId,
            expectation.EvidenceAssetName);
        var manifestLocator = evidenceLocator with { AssetName = expectation.ManifestAssetName };
        var evidence = await api.GetAssetAsync(evidenceLocator, cancellationToken);
        var manifest = await api.GetAssetAsync(manifestLocator, cancellationToken);

        if (evidence is null || manifest is null)
        {
            return Rejected("release-asset-missing", "The expected evidence asset or manifest asset is missing from the release.");
        }

        if (!Matches(evidence, evidenceLocator, expectation.Receipt.Spec.AssetDigest) ||
            !Matches(manifest, manifestLocator, expectation.Receipt.Spec.ManifestDigest))
        {
            return Rejected("release-asset-identity-mismatch", "The retrieved release assets do not match the expected provider, repository, release, name, and digest.");
        }

        var parsedManifest = ParseManifest(manifest.Content.Span);
        if (parsedManifest is null ||
            !string.Equals(parsedManifest.Provider, expectation.Provider, StringComparison.Ordinal) ||
            parsedManifest.Repository != expectation.Receipt.Spec.Archive.Repository.Value ||
            parsedManifest.ReleaseId != expectation.Receipt.Spec.ReleaseId ||
            parsedManifest.AssetName != expectation.EvidenceAssetName ||
            parsedManifest.AssetDigest != expectation.Receipt.Spec.AssetDigest.Value ||
            parsedManifest.ProvenanceDigest != expectation.ProvenanceDigest.Value)
        {
            return Rejected("evidence-provenance-mismatch", "The independently retrieved manifest does not bind the expected evidence asset provenance.");
        }

        return new EvidenceArchiveVerification(true, "verified", "The GitHub release evidence and provenance are independently verified.");
    }

    private static bool IsValid(EvidenceReceipt receipt, string evidenceAssetName, string manifestAssetName) =>
        !string.IsNullOrWhiteSpace(receipt.Spec.ReleaseId) &&
        !string.IsNullOrWhiteSpace(evidenceAssetName) &&
        !string.IsNullOrWhiteSpace(manifestAssetName) &&
        receipt.Spec.AssetDigest is not null &&
        receipt.Spec.ManifestDigest is not null;

    private static bool Matches(
        GitHubReleaseAsset asset,
        GitHubReleaseAssetLocator expected,
        Sha256Digest expectedDigest) =>
        asset.Locator == expected &&
        asset.DeclaredContentDigest == expectedDigest &&
        Digest(asset.Content.Span) == expectedDigest;

    private static ReleaseEvidenceManifest? ParseManifest(ReadOnlySpan<byte> content)
    {
        try
        {
            return JsonSerializer.Deserialize<ReleaseEvidenceManifest>(content);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Sha256Digest Digest(ReadOnlySpan<byte> content)
    {
        var computed = Convert.ToHexStringLower(SHA256.HashData(content));
        return Sha256Digest.Parse($"sha256:{computed}") switch
        {
            Result<Sha256Digest, ContractValidationError>.Success success => success.Value,
            Result<Sha256Digest, ContractValidationError>.Failure failure =>
                throw new InvalidOperationException(failure.Error.Message),
            _ => throw new InvalidOperationException("Digest calculation returned an unsupported result.")
        };
    }

    private static EvidenceArchiveVerification Rejected(string code, string message) =>
        new(false, code, message);

    private sealed record ReleaseEvidenceManifest(
        string Provider,
        string Repository,
        string ReleaseId,
        string AssetName,
        string AssetDigest,
        string ProvenanceDigest);
}

using Armada.Contracts;

namespace Armada.Application;

public sealed record GitHubReleaseAssetLocator(
    string Provider,
    RepositoryName Repository,
    string ReleaseId,
    string AssetName);

public sealed record GitHubReleaseAsset(
    GitHubReleaseAssetLocator Locator,
    Sha256Digest DeclaredContentDigest,
    ReadOnlyMemory<byte> Content);

public sealed record GitHubReleaseEvidenceExpectation(
    EvidenceReceipt Receipt,
    string Provider,
    string EvidenceAssetName,
    string ManifestAssetName,
    Sha256Digest ProvenanceDigest);

public sealed record EvidenceArchiveVerification(
    bool IsVerified,
    string Code,
    string Message);

public interface IGitHubReleaseApi
{
    Task<GitHubReleaseAsset?> GetAssetAsync(
        GitHubReleaseAssetLocator locator,
        CancellationToken cancellationToken);
}

public interface IEvidenceArchive
{
    Task<EvidenceArchiveVerification> VerifyAsync(
        GitHubReleaseEvidenceExpectation expectation,
        CancellationToken cancellationToken);
}

using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace Armada.Contracts;

public enum ReleaseChannel
{
    Canary,
    Beta,
    Stable
}

public enum ReleaseComponent
{
    ControlPlane,
    NodeAgent,
    Installer
}

public enum SupportedPlatform
{
    LinuxX64,
    MacOsArm64,
    WindowsX64
}

public sealed record ReleaseVersion(int Major, int Minor, int Patch) : IComparable<ReleaseVersion>
{
    public int CompareTo(ReleaseVersion? other) =>
        other is null
            ? 1
            : Major != other.Major
                ? Major.CompareTo(other.Major)
                : Minor != other.Minor
                    ? Minor.CompareTo(other.Minor)
                    : Patch.CompareTo(other.Patch);

    public override string ToString() => $"{Major}.{Minor}.{Patch}";

    public static Result<ReleaseVersion, ReleaseValidationFailure> Parse(string? value)
    {
        var parts = value?.Split('.', StringSplitOptions.None);
        return parts is [var major, var minor, var patch] &&
               int.TryParse(major, out var parsedMajor) &&
               int.TryParse(minor, out var parsedMinor) &&
               int.TryParse(patch, out var parsedPatch) &&
               parsedMajor >= 0 &&
               parsedMinor >= 0 &&
               parsedPatch >= 0
            ? new Result<ReleaseVersion, ReleaseValidationFailure>.Success(
                new(parsedMajor, parsedMinor, parsedPatch))
            : new Result<ReleaseVersion, ReleaseValidationFailure>.Failure(
                new("invalid-release-version", "Release versions must be non-negative major.minor.patch values."));
    }
}

public sealed record ReleaseCompatibility(
    string MinimumNodeProtocol,
    string MaximumNodeProtocol,
    string MinimumControlPlaneProtocol,
    string MaximumControlPlaneProtocol)
{
    public bool Supports(string nodeProtocol, string controlPlaneProtocol) =>
        InRange(nodeProtocol, MinimumNodeProtocol, MaximumNodeProtocol) &&
        InRange(controlPlaneProtocol, MinimumControlPlaneProtocol, MaximumControlPlaneProtocol);

    private static bool InRange(string value, string minimum, string maximum) =>
        !string.IsNullOrWhiteSpace(value) &&
        !string.IsNullOrWhiteSpace(minimum) &&
        !string.IsNullOrWhiteSpace(maximum) &&
        string.CompareOrdinal(minimum, value) <= 0 &&
        string.CompareOrdinal(value, maximum) <= 0;
}

public sealed record ReleaseRevocation(
    bool IsRevoked,
    DateTimeOffset? RevokedAt,
    string? Reason,
    string? ReplacementReleaseId);

public sealed record ReleaseRollback(
    string RollbackReleaseId,
    Sha256Digest RollbackManifestDigest);

public sealed record ReleaseArtifact(
    ReleaseComponent Component,
    SupportedPlatform? Platform,
    string Name,
    Sha256Digest Digest,
    string SchemaVersion,
    string ProtocolVersion);

public sealed record ReleaseManifest(
    string SchemaVersion,
    string ReleaseId,
    ReleaseVersion Version,
    ReleaseChannel Channel,
    DateTimeOffset CreatedAt,
    string SignerKeyId,
    ReleaseCompatibility Compatibility,
    ReleaseRevocation Revocation,
    ReleaseRollback? Rollback,
    ImmutableArray<ReleaseArtifact> Artifacts);

public sealed record ReleaseSignature(string KeyId, ImmutableArray<byte> Value);

public sealed record ReleaseArtifactPayload(ReleaseArtifact Artifact, ImmutableArray<byte> Bytes);

public sealed record ReleaseSignatureVerification(bool IsValid, string Code, string Message)
{
    public static readonly ReleaseSignatureVerification Verified =
        new(true, "verified", "The release signature is valid.");
}

public interface IReleaseManifestSigner
{
    Result<ReleaseSignature, ReleaseValidationFailure> Sign(
        ReleaseManifest manifest,
        ImmutableArray<byte> canonicalManifest);
}

public interface IReleaseManifestVerifier
{
    Result<ReleaseSignatureVerification, ReleaseValidationFailure> Verify(
        ReleaseManifest manifest,
        ImmutableArray<byte> canonicalManifest,
        ReleaseSignature signature);
}

public sealed record SignedRelease(
    ReleaseManifest Manifest,
    Sha256Digest ManifestDigest,
    ReleaseSignature Signature,
    ImmutableArray<ReleaseArtifactPayload> Artifacts);

public sealed record ReleaseValidationFailure(string Code, string Message);

public static class ReleaseManifestContract
{
    public const string SchemaVersion = "armada.release/v1";

    public static Result<bool, ReleaseValidationFailure> Validate(ReleaseManifest? manifest)
    {
        if (manifest is null ||
            manifest.SchemaVersion != SchemaVersion ||
            string.IsNullOrWhiteSpace(manifest.ReleaseId) ||
            string.IsNullOrWhiteSpace(manifest.SignerKeyId) ||
            manifest.CreatedAt == default ||
            manifest.Artifacts.IsDefaultOrEmpty)
        {
            return Failure("invalid-release-manifest", "A release manifest requires its schema, identity, signer, creation time, and artifacts.");
        }

        if (manifest.Compatibility is null ||
            !manifest.Compatibility.Supports(manifest.Compatibility.MinimumNodeProtocol, manifest.Compatibility.MinimumControlPlaneProtocol) ||
            manifest.Revocation is null ||
            (manifest.Revocation.IsRevoked && (manifest.Revocation.RevokedAt is null || string.IsNullOrWhiteSpace(manifest.Revocation.Reason))) ||
            (manifest.Rollback is not null &&
             (string.IsNullOrWhiteSpace(manifest.Rollback.RollbackReleaseId) || manifest.Rollback.RollbackManifestDigest is null)))
        {
            return Failure("invalid-release-manifest", "Release compatibility, revocation, and rollback metadata must be complete.");
        }

        if (manifest.Artifacts.Any(static artifact =>
                artifact is null ||
                string.IsNullOrWhiteSpace(artifact.Name) ||
                artifact.Digest is null ||
                string.IsNullOrWhiteSpace(artifact.SchemaVersion) ||
                string.IsNullOrWhiteSpace(artifact.ProtocolVersion) ||
                (artifact.Component == ReleaseComponent.Installer) != artifact.Platform.HasValue) ||
            manifest.Artifacts.Select(static artifact => (artifact.Component, artifact.Platform, artifact.Name))
                .Distinct()
                .Count() != manifest.Artifacts.Length ||
            manifest.Artifacts.Count(static artifact => artifact.Component == ReleaseComponent.ControlPlane) != 1 ||
            manifest.Artifacts.Count(static artifact => artifact.Component == ReleaseComponent.NodeAgent) != 1 ||
            !manifest.Artifacts.Any(static artifact => artifact.Component == ReleaseComponent.Installer) ||
            manifest.Artifacts
                .Where(static artifact => artifact.Component == ReleaseComponent.Installer)
                .GroupBy(static artifact => artifact.Platform)
                .Any(static platformArtifacts => platformArtifacts.Count() != 1))
        {
            return Failure("invalid-release-artifact", "Releases require unique, content-addressed control-plane, node-agent, and platform installer artifacts.");
        }

        return new Result<bool, ReleaseValidationFailure>.Success(true);
    }

    public static ImmutableArray<byte> CanonicalBytes(ReleaseManifest manifest)
    {
        var fields = new List<string>
        {
            manifest.SchemaVersion,
            manifest.ReleaseId,
            manifest.Version.ToString(),
            manifest.Channel.ToString(),
            manifest.CreatedAt.ToUniversalTime().ToString("O"),
            manifest.SignerKeyId,
            manifest.Compatibility.MinimumNodeProtocol,
            manifest.Compatibility.MaximumNodeProtocol,
            manifest.Compatibility.MinimumControlPlaneProtocol,
            manifest.Compatibility.MaximumControlPlaneProtocol,
            manifest.Revocation.IsRevoked ? "true" : "false",
            manifest.Revocation.RevokedAt?.ToUniversalTime().ToString("O") ?? string.Empty,
            manifest.Revocation.Reason ?? string.Empty,
            manifest.Revocation.ReplacementReleaseId ?? string.Empty,
            manifest.Rollback?.RollbackReleaseId ?? string.Empty,
            manifest.Rollback?.RollbackManifestDigest.Value ?? string.Empty
        };

        foreach (var artifact in manifest.Artifacts
                     .OrderBy(static artifact => artifact.Component)
                     .ThenBy(static artifact => artifact.Platform)
                     .ThenBy(static artifact => artifact.Name, StringComparer.Ordinal))
        {
            fields.Add(artifact.Component.ToString());
            fields.Add(artifact.Platform?.ToString() ?? string.Empty);
            fields.Add(artifact.Name);
            fields.Add(artifact.Digest.Value);
            fields.Add(artifact.SchemaVersion);
            fields.Add(artifact.ProtocolVersion);
        }

        return Encoding.UTF8.GetBytes(string.Concat(fields.Select(static field => $"{field.Length}:{field};"))).ToImmutableArray();
    }

    public static Sha256Digest Digest(ImmutableArray<byte> bytes)
    {
        var value = $"sha256:{Convert.ToHexStringLower(SHA256.HashData(bytes.AsSpan()))}";
        return Sha256Digest.Parse(value) switch
        {
            Result<Sha256Digest, ContractValidationError>.Success success => success.Value,
            Result<Sha256Digest, ContractValidationError>.Failure failure => throw new InvalidOperationException(failure.Error.Message),
            _ => throw new InvalidOperationException("SHA-256 digest parsing returned an unsupported result.")
        };
    }

    private static Result<bool, ReleaseValidationFailure> Failure(string code, string message) =>
        new Result<bool, ReleaseValidationFailure>.Failure(new(code, message));
}

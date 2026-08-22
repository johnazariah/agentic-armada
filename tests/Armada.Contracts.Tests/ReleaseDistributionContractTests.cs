using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Armada.Contracts;
using FsCheck;
using FsCheck.Xunit;

namespace Armada.Contracts.Tests;

public sealed class ReleaseDistributionContractTests
{
    [Fact]
    public void Canonical_manifest_digest_is_independent_of_input_artifact_order()
    {
        var manifest = Manifest();
        var reordered = manifest with { Artifacts = manifest.Artifacts.Reverse().ToImmutableArray() };

        var first = ReleaseManifestContract.Digest(ReleaseManifestContract.CanonicalBytes(manifest));
        var second = ReleaseManifestContract.Digest(ReleaseManifestContract.CanonicalBytes(reordered));

        Assert.Equal(first, second);
    }

    [Fact]
    public void Tampering_with_a_signed_manifest_changes_its_canonical_digest_and_invalidates_the_signature()
    {
        var manifest = Manifest();
        var signer = new DeterministicTestSigner("test-release-key", [1, 2, 3, 4]);
        var canonical = ReleaseManifestContract.CanonicalBytes(manifest);
        var signature = Value(signer.Sign(manifest, canonical));
        var tampered = manifest with { Channel = ReleaseChannel.Stable };

        var result = signer.Verify(tampered, ReleaseManifestContract.CanonicalBytes(tampered), signature);

        Assert.NotEqual(
            ReleaseManifestContract.Digest(canonical),
            ReleaseManifestContract.Digest(ReleaseManifestContract.CanonicalBytes(tampered)));
        Assert.False(Value(result).IsValid);
        Assert.Equal("invalid-signature", Value(result).Code);
    }

    [Fact]
    public void Revoked_releases_require_a_timestamp_and_reason()
    {
        var manifest = Manifest() with
        {
            Revocation = new(true, null, null, "r2")
        };

        var result = ReleaseManifestContract.Validate(manifest);

        Assert.Equal(
            "invalid-release-manifest",
            Assert.IsType<Result<bool, ReleaseValidationFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public void Compatibility_range_requires_both_node_and_control_plane_protocols()
    {
        var compatibility = new ReleaseCompatibility(
            "armada.node/v1alpha1",
            "armada.node/v1alpha1",
            "armada.control/v1alpha1",
            "armada.control/v1alpha1");

        Assert.True(compatibility.Supports("armada.node/v1alpha1", "armada.control/v1alpha1"));
        Assert.False(compatibility.Supports("armada.node/v1alpha2", "armada.control/v1alpha1"));
        Assert.False(compatibility.Supports("armada.node/v1alpha1", "armada.control/v1alpha2"));
    }

    [Fact]
    public void Compatibility_compares_numeric_alpha_components_not_lexical_protocol_text()
    {
        var narrow = new ReleaseCompatibility(
            "armada.node/v1alpha1",
            "armada.node/v1alpha2",
            "armada.control/v1alpha1",
            "armada.control/v1alpha2");
        var wide = narrow with { MaximumNodeProtocol = "armada.node/v1alpha10" };

        Assert.False(narrow.Supports("armada.node/v1alpha10", "armada.control/v1alpha1"));
        Assert.True(wide.Supports("armada.node/v1alpha10", "armada.control/v1alpha1"));
        Assert.False(wide.Supports("armada.control/v1alpha1", "armada.control/v1alpha1"));
    }

    [Property(MaxTest = 50)]
    public void Canonical_digest_changes_when_the_release_identity_changes(NonEmptyString suffix)
    {
        var manifest = Manifest();
        var changed = manifest with { ReleaseId = $"r-{suffix.Get}-changed" };

        var originalDigest = ReleaseManifestContract.Digest(ReleaseManifestContract.CanonicalBytes(manifest));
        var changedDigest = ReleaseManifestContract.Digest(ReleaseManifestContract.CanonicalBytes(changed));

        Assert.NotEqual(originalDigest, changedDigest);
    }

    private static ReleaseManifest Manifest() =>
        new(
            ReleaseManifestContract.SchemaVersion,
            "r-1",
            new ReleaseVersion(1, 2, 3),
            ReleaseChannel.Canary,
            DateTimeOffset.Parse("2026-08-23T00:00:00Z"),
            "test-release-key",
            new(
                "armada.node/v1alpha1",
                "armada.node/v1alpha1",
                "armada.control/v1alpha1",
                "armada.control/v1alpha1"),
            new(false, null, null, null),
            null,
            [
                Artifact(ReleaseComponent.Installer, SupportedPlatform.WindowsX64, "armada.msi", 'c'),
                Artifact(ReleaseComponent.NodeAgent, null, "node-agent.tar.gz", 'a'),
                Artifact(ReleaseComponent.ControlPlane, null, "control-plane.tar.gz", 'b')
            ]);

    private static ReleaseArtifact Artifact(
        ReleaseComponent component,
        SupportedPlatform? platform,
        string name,
        char digest) =>
        new(component, platform, name, Digest(digest), "armada.artifact/v1", "armada.node/v1alpha1");

    private static Sha256Digest Digest(char value) =>
        Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string(value, 64)}")).Value;

    private static T Value<T>(Result<T, ReleaseValidationFailure> result) =>
        Assert.IsType<Result<T, ReleaseValidationFailure>.Success>(result).Value;

    private sealed class DeterministicTestSigner(string keyId, byte[] key) : IReleaseManifestSigner, IReleaseManifestVerifier
    {
        public Result<ReleaseSignature, ReleaseValidationFailure> Sign(
            ReleaseManifest manifest,
            ImmutableArray<byte> canonicalManifest) =>
            manifest.SignerKeyId != keyId
                ? Failure<ReleaseSignature>("signer-key-mismatch", "The test signer does not own the manifest key identity.")
                : new Result<ReleaseSignature, ReleaseValidationFailure>.Success(
                    new(keyId, HMACSHA256.HashData(key, canonicalManifest.AsSpan()).ToImmutableArray()));

        public Result<ReleaseSignatureVerification, ReleaseValidationFailure> Verify(
            ReleaseManifest manifest,
            ImmutableArray<byte> canonicalManifest,
            ReleaseSignature signature) =>
            signature.KeyId == keyId &&
            CryptographicOperations.FixedTimeEquals(
                signature.Value.AsSpan(),
                HMACSHA256.HashData(key, canonicalManifest.AsSpan()))
                ? new Result<ReleaseSignatureVerification, ReleaseValidationFailure>.Success(
                    ReleaseSignatureVerification.Verified)
                : new Result<ReleaseSignatureVerification, ReleaseValidationFailure>.Success(
                    new(false, "invalid-signature", "The release signature does not match the canonical manifest."));

        private static Result<T, ReleaseValidationFailure> Failure<T>(string code, string message) =>
            new Result<T, ReleaseValidationFailure>.Failure(new(code, message));
    }
}

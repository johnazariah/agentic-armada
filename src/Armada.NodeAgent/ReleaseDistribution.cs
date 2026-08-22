using System.Collections.Immutable;
using System.Security.Cryptography;
using Armada.Contracts;

namespace Armada.NodeAgent;

public sealed record UpgradeFailure(string Code, string Message);

public interface IProductionReleaseKeyProvider
{
    Result<ReleaseSignature, ReleaseValidationFailure> Sign(
        ReleaseManifest manifest,
        ImmutableArray<byte> canonicalManifest);

    Result<ReleaseSignatureVerification, ReleaseValidationFailure> Verify(
        ReleaseManifest manifest,
        ImmutableArray<byte> canonicalManifest,
        ReleaseSignature signature);
}

public sealed class ProductionReleaseSigner(IProductionReleaseKeyProvider? keys) : IReleaseManifestSigner
{
    public Result<ReleaseSignature, ReleaseValidationFailure> Sign(
        ReleaseManifest manifest,
        ImmutableArray<byte> canonicalManifest) =>
        keys is null
            ? Failure<ReleaseSignature>("trusted-key-source-unavailable", "Production release signing requires a configured trusted-key source.")
            : keys.Sign(manifest, canonicalManifest);

    private static Result<T, ReleaseValidationFailure> Failure<T>(string code, string message) =>
        new Result<T, ReleaseValidationFailure>.Failure(new(code, message));
}

public sealed class ProductionReleaseVerifier(IProductionReleaseKeyProvider? keys) : IReleaseManifestVerifier
{
    public Result<ReleaseSignatureVerification, ReleaseValidationFailure> Verify(
        ReleaseManifest manifest,
        ImmutableArray<byte> canonicalManifest,
        ReleaseSignature signature) =>
        keys is null
            ? Failure<ReleaseSignatureVerification>(
                "trusted-key-source-unavailable",
                "Production release verification requires a configured trusted-key source.")
            : keys.Verify(manifest, canonicalManifest, signature);

    private static Result<T, ReleaseValidationFailure> Failure<T>(string code, string message) =>
        new Result<T, ReleaseValidationFailure>.Failure(new(code, message));
}

internal sealed class DeterministicTestReleaseSigner(string keyId, byte[] key) : IReleaseManifestSigner, IReleaseManifestVerifier
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

public sealed record VerifiedRelease(SignedRelease Value);

public static class ReleaseVerification
{
    public static Result<VerifiedRelease, UpgradeFailure> Verify(
        SignedRelease? release,
        IReleaseManifestVerifier? verifier)
    {
        if (release is null || verifier is null)
        {
            return Failure("release-verifier-unavailable", "A signed release and configured verifier are required.");
        }

        if (ReleaseManifestContract.Validate(release.Manifest) is Result<bool, ReleaseValidationFailure>.Failure validationFailure)
        {
            return Failure(validationFailure.Error.Code, validationFailure.Error.Message);
        }

        var canonical = ReleaseManifestContract.CanonicalBytes(release.Manifest);
        if (release.ManifestDigest != ReleaseManifestContract.Digest(canonical))
        {
            return Failure("manifest-digest-mismatch", "The manifest digest does not match its canonical bytes.");
        }
        if (release.Signature.KeyId != release.Manifest.SignerKeyId || release.Signature.Value.IsDefaultOrEmpty)
        {
            return Failure("release-signature-identity-mismatch", "The signature must name the manifest signer and contain bytes.");
        }

        var signature = verifier.Verify(release.Manifest, canonical, release.Signature);
        if (signature is Result<ReleaseSignatureVerification, ReleaseValidationFailure>.Failure signatureFailure)
        {
            return Failure(signatureFailure.Error.Code, signatureFailure.Error.Message);
        }
        var signatureValue = ((Result<ReleaseSignatureVerification, ReleaseValidationFailure>.Success)signature).Value;
        if (!signatureValue.IsValid)
        {
            return Failure(signatureValue.Code, signatureValue.Message);
        }

        if (release.Artifacts.Length != release.Manifest.Artifacts.Length ||
            release.Artifacts.Any(static payload =>
                payload.Artifact is null ||
                payload.Bytes.IsDefault ||
                ReleaseManifestContract.Digest(payload.Bytes) != payload.Artifact.Digest) ||
            release.Manifest.Artifacts.Any(artifact =>
                !release.Artifacts.Any(payload => payload.Artifact == artifact)) ||
            release.Artifacts.Select(static payload => payload.Artifact).Distinct().Count() != release.Artifacts.Length)
        {
            return Failure("release-artifact-digest-mismatch", "Release artifact bytes must exactly match each signed manifest digest.");
        }

        return new Result<VerifiedRelease, UpgradeFailure>.Success(new(release));
    }

    private static Result<VerifiedRelease, UpgradeFailure> Failure(string code, string message) =>
        new Result<VerifiedRelease, UpgradeFailure>.Failure(new(code, message));
}

public sealed record UpgradeRollbackAnchor(
    string ReleaseId,
    ReleaseVersion Version,
    Sha256Digest ManifestDigest);

public sealed record NodeUpgradeState(
    SupportedPlatform Platform,
    string NodeProtocol,
    string ControlPlaneProtocol,
    ReleaseChannel PinnedChannel,
    string ActiveReleaseId,
    ReleaseVersion ActiveVersion,
    Sha256Digest ActiveManifestDigest,
    UpgradeRollbackAnchor? RollbackAnchor,
    ImmutableHashSet<Sha256Digest> SeenManifestDigests);

public sealed record UpgradePlan(
    string IdempotencyKey,
    VerifiedRelease Release,
    ReleaseArtifact NodeAgentArtifact,
    ReleaseArtifact InstallerArtifact,
    UpgradeRollbackAnchor RollbackAnchor);

public static class UpgradePlanning
{
    public static Result<UpgradePlan, UpgradeFailure> Plan(NodeUpgradeState state, VerifiedRelease release)
    {
        var manifest = release.Value.Manifest;
        if (manifest.Revocation.IsRevoked)
        {
            return Failure("release-revoked", "The selected release is explicitly revoked.");
        }
        if (manifest.Channel != state.PinnedChannel)
        {
            return Failure("release-channel-not-pinned", "The selected release does not match the node's pinned channel.");
        }
        if (!manifest.Compatibility.Supports(state.NodeProtocol, state.ControlPlaneProtocol))
        {
            return Failure("release-incompatible", "The release is incompatible with the node or control-plane protocol.");
        }
        if (state.SeenManifestDigests.Contains(release.Value.ManifestDigest))
        {
            return Failure("release-replay-refused", "The release manifest was already processed by this node.");
        }
        if (manifest.Version.CompareTo(state.ActiveVersion) <= 0)
        {
            return Failure("release-downgrade-refused", "The release version must be newer than the active version.");
        }
        if (state.RollbackAnchor is null)
        {
            return Failure("rollback-anchor-missing", "Upgrade activation requires a durable rollback anchor.");
        }

        var nodeAgent = manifest.Artifacts.SingleOrDefault(static artifact => artifact.Component == ReleaseComponent.NodeAgent);
        var installer = manifest.Artifacts.SingleOrDefault(artifact =>
            artifact.Component == ReleaseComponent.Installer && artifact.Platform == state.Platform);
        return nodeAgent is null || installer is null
            ? Failure("release-platform-unsupported", "The release has no signed node-agent and installer artifacts for this platform.")
            : new Result<UpgradePlan, UpgradeFailure>.Success(
                new(
                    $"upgrade:{state.ActiveManifestDigest.Value}:{release.Value.ManifestDigest.Value}",
                    release,
                    nodeAgent,
                    installer,
                    state.RollbackAnchor));
    }

    private static Result<UpgradePlan, UpgradeFailure> Failure(string code, string message) =>
        new Result<UpgradePlan, UpgradeFailure>.Failure(new(code, message));
}

public enum UpgradePhase
{
    StageClaimed,
    Staged,
    HealthClaimed,
    HealthConfirmed,
    ActivationClaimed,
    Activated,
    RollbackClaimed,
    RolledBack
}

public sealed record UpgradeJournalEvent(
    string IdempotencyKey,
    string ReleaseId,
    Sha256Digest ManifestDigest,
    UpgradePhase Phase,
    DateTimeOffset RecordedAt,
    string Code,
    string Message,
    Guid OperationId,
    DateTimeOffset? ClaimExpiresAt);

public enum UpgradePlatformStatus
{
    NotStaged,
    Staged,
    Healthy,
    Activated,
    RolledBack
}

public interface IUpgradeStaging
{
    Task<Result<UpgradePlatformStatus, UpgradeFailure>> GetStatusAsync(
        UpgradePlan plan,
        CancellationToken cancellationToken);

    Task<Result<bool, UpgradeFailure>> StageAsync(UpgradePlan plan, CancellationToken cancellationToken);

    Task<Result<bool, UpgradeFailure>> ConfirmHealthAsync(UpgradePlan plan, CancellationToken cancellationToken);

    Task<Result<bool, UpgradeFailure>> ActivateAsync(UpgradePlan plan, CancellationToken cancellationToken);

    Task<Result<bool, UpgradeFailure>> RollbackAsync(UpgradePlan plan, CancellationToken cancellationToken);
}

public sealed record UpgradeExecutionResult(
    bool Activated,
    bool RolledBack,
    string Code,
    string Message);

public sealed class NodeUpgradeCoordinator(
    INodeJournal journal,
    IUpgradeStaging staging,
    IClock clock)
{
    private static readonly TimeSpan ClaimDuration = TimeSpan.FromMinutes(5);

    public async Task<Result<UpgradeExecutionResult, UpgradeFailure>> ExecuteAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        CancellationToken cancellationToken)
    {
        var history = await ReadHistoryAsync(plan, cancellationToken);
        if (history is Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Failure historyFailure)
        {
            return Failure(historyFailure.Error);
        }

        if (TerminalOutcome(((Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Success)history).Value) is { } terminal)
        {
            return new Result<UpgradeExecutionResult, UpgradeFailure>.Success(terminal);
        }

        var staged = await EnsureStageAsync(identity, plan, cancellationToken);
        if (staged is Result<bool, UpgradeFailure>.Failure stageFailure)
        {
            return Failure(stageFailure.Error);
        }

        var healthy = await EnsureHealthAsync(identity, plan, cancellationToken);
        if (healthy is Result<bool, UpgradeFailure>.Failure healthFailure)
        {
            return await RollbackAfterFailureAsync(identity, plan, healthFailure.Error, cancellationToken);
        }

        var activated = await EnsureActivationAsync(identity, plan, cancellationToken);
        if (activated is Result<bool, UpgradeFailure>.Failure activationFailure)
        {
            return await RollbackAfterFailureAsync(identity, plan, activationFailure.Error, cancellationToken);
        }

        return new Result<UpgradeExecutionResult, UpgradeFailure>.Success(
            new(true, false, "upgrade-activated", "The verified and healthy release was atomically activated."));
    }

    private async Task<Result<bool, UpgradeFailure>> EnsureStageAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        CancellationToken cancellationToken)
    {
        var history = await ReadHistoryAsync(plan, cancellationToken);
        if (history is Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Failure failure)
        {
            return Failure<bool>(failure.Error);
        }

        var values = ((Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Success)history).Value;
        if (HasPhase(values, UpgradePhase.Staged))
        {
            return Success(true);
        }

        var claim = await ClaimAsync(identity, plan, UpgradePhase.StageClaimed, cancellationToken);
        if (claim is Result<bool, UpgradeFailure>.Failure claimFailure)
        {
            return Failure<bool>(claimFailure.Error);
        }

        var status = await staging.GetStatusAsync(plan, cancellationToken);
        if (status is Result<UpgradePlatformStatus, UpgradeFailure>.Failure statusFailure)
        {
            return Failure<bool>(statusFailure.Error);
        }

        if (((Result<UpgradePlatformStatus, UpgradeFailure>.Success)status).Value == UpgradePlatformStatus.NotStaged)
        {
            var stage = await staging.StageAsync(plan, cancellationToken);
            if (!Succeeded(stage, out var stageFailure))
            {
                return Failure<bool>(stageFailure);
            }
        }

        return await CompleteAsync(
            identity,
            plan,
            UpgradePhase.Staged,
            "upgrade-staged",
            "Signed artifacts were staged.",
            cancellationToken);
    }

    private async Task<Result<bool, UpgradeFailure>> EnsureHealthAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        CancellationToken cancellationToken)
    {
        var history = await ReadHistoryAsync(plan, cancellationToken);
        if (history is Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Failure failure)
        {
            return Failure<bool>(failure.Error);
        }

        var values = ((Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Success)history).Value;
        if (HasPhase(values, UpgradePhase.HealthConfirmed))
        {
            return Success(true);
        }

        var claim = await ClaimAsync(identity, plan, UpgradePhase.HealthClaimed, cancellationToken);
        if (claim is Result<bool, UpgradeFailure>.Failure claimFailure)
        {
            return Failure<bool>(claimFailure.Error);
        }

        var status = await staging.GetStatusAsync(plan, cancellationToken);
        if (status is Result<UpgradePlatformStatus, UpgradeFailure>.Failure statusFailure)
        {
            return Failure<bool>(statusFailure.Error);
        }

        if (((Result<UpgradePlatformStatus, UpgradeFailure>.Success)status).Value == UpgradePlatformStatus.Staged)
        {
            var health = await staging.ConfirmHealthAsync(plan, cancellationToken);
            if (!Succeeded(health, out var healthFailure))
            {
                return Failure<bool>(healthFailure);
            }
        }

        return await CompleteAsync(
            identity,
            plan,
            UpgradePhase.HealthConfirmed,
            "upgrade-health-confirmed",
            "Staged artifacts passed health confirmation.",
            cancellationToken);
    }

    private async Task<Result<bool, UpgradeFailure>> EnsureActivationAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        CancellationToken cancellationToken)
    {
        var history = await ReadHistoryAsync(plan, cancellationToken);
        if (history is Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Failure failure)
        {
            return Failure<bool>(failure.Error);
        }

        var values = ((Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Success)history).Value;
        if (HasPhase(values, UpgradePhase.Activated))
        {
            return Success(true);
        }

        var claim = await ClaimAsync(identity, plan, UpgradePhase.ActivationClaimed, cancellationToken);
        if (claim is Result<bool, UpgradeFailure>.Failure claimFailure)
        {
            return Failure<bool>(claimFailure.Error);
        }

        var status = await staging.GetStatusAsync(plan, cancellationToken);
        if (status is Result<UpgradePlatformStatus, UpgradeFailure>.Failure statusFailure)
        {
            return Failure<bool>(statusFailure.Error);
        }

        if (((Result<UpgradePlatformStatus, UpgradeFailure>.Success)status).Value == UpgradePlatformStatus.Healthy)
        {
            var activation = await staging.ActivateAsync(plan, cancellationToken);
            if (!Succeeded(activation, out var activationFailure))
            {
                return Failure<bool>(activationFailure);
            }
        }
        else if (((Result<UpgradePlatformStatus, UpgradeFailure>.Success)status).Value != UpgradePlatformStatus.Activated)
        {
            return Failure<bool>(new(
                "upgrade-activation-precondition-failed",
                "Activation requires a platform-reported healthy or already activated release."));
        }

        return await CompleteAsync(
            identity,
            plan,
            UpgradePhase.Activated,
            "upgrade-activated",
            "The verified and healthy release was atomically activated.",
            cancellationToken);
    }

    private async Task<Result<UpgradeExecutionResult, UpgradeFailure>> RollbackAfterFailureAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        UpgradeFailure failure,
        CancellationToken cancellationToken)
    {
        var claim = await ClaimAsync(identity, plan, UpgradePhase.RollbackClaimed, cancellationToken);
        if (claim is Result<bool, UpgradeFailure>.Failure claimFailure)
        {
            return Failure(claimFailure.Error);
        }

        var status = await staging.GetStatusAsync(plan, cancellationToken);
        if (status is Result<UpgradePlatformStatus, UpgradeFailure>.Failure statusFailure)
        {
            return Failure(statusFailure.Error);
        }

        if (((Result<UpgradePlatformStatus, UpgradeFailure>.Success)status).Value != UpgradePlatformStatus.RolledBack)
        {
            var rollback = await staging.RollbackAsync(plan, cancellationToken);
            if (!Succeeded(rollback, out var rollbackFailure))
            {
                return Failure(rollbackFailure);
            }
        }

        var completion = await CompleteAsync(
            identity,
            plan,
            UpgradePhase.RolledBack,
            failure.Code,
            failure.Message,
            cancellationToken);
        return completion is Result<bool, UpgradeFailure>.Failure completionFailure
            ? Failure(completionFailure.Error)
            : new Result<UpgradeExecutionResult, UpgradeFailure>.Success(
                new(false, true, failure.Code, failure.Message));
    }

    private async Task<Result<bool, UpgradeFailure>> ClaimAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        UpgradePhase phase,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var claim = new UpgradeJournalEvent(
            plan.IdempotencyKey,
            plan.Release.Value.Manifest.ReleaseId,
            plan.Release.Value.ManifestDigest,
            phase,
            now,
            "upgrade-transition-claimed",
            $"The {phase} transition is durably claimed.",
            Guid.NewGuid(),
            now.Add(ClaimDuration));
        var result = await journal.ClaimUpgradeTransitionAsync(identity, claim, cancellationToken);
        return result switch
        {
            Result<JournalAppendClaim, JournalFailure>.Success { Value.Added: true } =>
                Success(true),
            Result<JournalAppendClaim, JournalFailure>.Success =>
                Failure<bool>(new(
                    "upgrade-transition-in-progress",
                    $"The {phase} transition is claimed by another coordinator until its durable claim expires.")),
            Result<JournalAppendClaim, JournalFailure>.Failure journalFailure =>
                Failure<bool>(new(journalFailure.Error.Code, journalFailure.Error.Message)),
            _ => Failure<bool>(new("journal-write-failed", "The journal claim returned an unsupported result."))
        };
    }

    private async Task<Result<bool, UpgradeFailure>> CompleteAsync(
        NodeDeviceIdentity identity,
        UpgradePlan plan,
        UpgradePhase phase,
        string code,
        string message,
        CancellationToken cancellationToken)
    {
        var completed = new UpgradeJournalEvent(
            plan.IdempotencyKey,
            plan.Release.Value.Manifest.ReleaseId,
            plan.Release.Value.ManifestDigest,
            phase,
            clock.UtcNow,
            code,
            message,
            Guid.Empty,
            null);
        var result = await journal.AppendClaimedAsync(
            JournalEntry.UpgradeClaimIdentity(completed),
            ordinal => JournalEntry.ForUpgrade(ordinal, identity, completed),
            cancellationToken);
        return result switch
        {
            Result<JournalAppendClaim, JournalFailure>.Success => Success(true),
            Result<JournalAppendClaim, JournalFailure>.Failure journalFailure =>
                Failure<bool>(new(journalFailure.Error.Code, journalFailure.Error.Message)),
            _ => Failure<bool>(new("journal-write-failed", "The journal completion returned an unsupported result."))
        };
    }

    private async Task<Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>> ReadHistoryAsync(
        UpgradePlan plan,
        CancellationToken cancellationToken)
    {
        var entries = await journal.ReadAsync(cancellationToken);
        return entries switch
        {
            Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success success =>
                new Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Success(
                    success.Value
                        .Select(static entry => entry.Upgrade)
                        .OfType<UpgradeJournalEvent>()
                        .Where(upgrade => upgrade.IdempotencyKey == plan.IdempotencyKey)
                        .ToArray()),
            Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure failure =>
                new Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Failure(
                    new(failure.Error.Code, failure.Error.Message)),
            _ => new Result<IReadOnlyList<UpgradeJournalEvent>, UpgradeFailure>.Failure(
                new("journal-read-failed", "The journal reader returned an unsupported result."))
        };
    }

    private static UpgradeExecutionResult? TerminalOutcome(IReadOnlyList<UpgradeJournalEvent> history) =>
        history.LastOrDefault(static upgrade => upgrade.Phase is UpgradePhase.Activated or UpgradePhase.RolledBack) switch
        {
            { Phase: UpgradePhase.Activated } activated => new(true, false, activated.Code, activated.Message),
            { Phase: UpgradePhase.RolledBack } rolledBack => new(false, true, rolledBack.Code, rolledBack.Message),
            _ => null
        };

    private static bool HasPhase(IReadOnlyList<UpgradeJournalEvent> history, UpgradePhase phase) =>
        history.Any(upgrade => upgrade.Phase == phase);

    private static bool Succeeded(
        Result<bool, UpgradeFailure> result,
        out UpgradeFailure failure)
    {
        failure = result switch
        {
            Result<bool, UpgradeFailure>.Failure rejected => rejected.Error,
            Result<bool, UpgradeFailure>.Success { Value: false } => new(
                "upgrade-operation-refused",
                "The platform staging boundary refused the requested upgrade operation."),
            _ => new("not-applicable", "No failure occurred.")
        };
        return result is Result<bool, UpgradeFailure>.Success { Value: true };
    }

    private static Result<UpgradeExecutionResult, UpgradeFailure> Failure(UpgradeFailure failure) =>
        new Result<UpgradeExecutionResult, UpgradeFailure>.Failure(failure);

    private static Result<T, UpgradeFailure> Success<T>(T value) =>
        new Result<T, UpgradeFailure>.Success(value);

    private static Result<T, UpgradeFailure> Failure<T>(UpgradeFailure failure) =>
        new Result<T, UpgradeFailure>.Failure(failure);
}

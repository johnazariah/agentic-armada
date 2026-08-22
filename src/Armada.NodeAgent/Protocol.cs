using System.Collections.Immutable;
using System.Globalization;
using Armada.Contracts;

namespace Armada.NodeAgent;

public static class NodeAgentProtocol
{
    public const string Version = "armada.node/v1alpha1";
    public const string StartAttemptSchema = "armada.node.command.start-attempt/v1alpha1";
    public const string CancelAttemptSchema = "armada.node.command.cancel-attempt/v1alpha1";
}

public sealed record NodeDeviceIdentity(ResourceId NodeId, long IdentityEpoch);

public sealed record OutboundEnvelope<TPayload>(
    string ProtocolVersion,
    ResourceId NodeId,
    long IdentityEpoch,
    long StreamEpoch,
    long Sequence,
    Guid MessageId,
    Guid CorrelationId,
    string IdempotencyKey,
    DateTimeOffset SentAt,
    TPayload Payload);

public abstract record NodeCommand(
    string SchemaVersion,
    ResourceId NodeReference,
    ResourceId ProjectId,
    ResourceId AttemptId,
    DateTimeOffset ExpiresAt)
{
    internal abstract string CanonicalIdentity();
}

public sealed record StartAttemptCommand(
    string SchemaVersion,
    ResourceId NodeReference,
    ResourceId ProjectId,
    ResourceId WorkloadReference,
    ResourceId AttemptId,
    DateTimeOffset ExpiresAt,
    ResourceId AdmissionDecisionReference,
    ResourceId LeaseReference,
    IsolationProfile IsolationProfile,
    Sha256Digest BundleDigest,
    Sha256Digest PolicyDigest,
    Sha256Digest ReleaseDigest,
    Sha256Digest CapabilityGrantDigest)
    : NodeCommand(SchemaVersion, NodeReference, ProjectId, AttemptId, ExpiresAt)
{
    internal override string CanonicalIdentity() =>
        ProtocolIdentity.Join(
            GetType().Name,
            SchemaVersion,
            NodeReference.ToString(),
            ProjectId.ToString(),
            WorkloadReference.ToString(),
            AttemptId.ToString(),
            ExpiresAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            AdmissionDecisionReference.ToString(),
            LeaseReference.ToString(),
            IsolationProfile.ToString(),
            BundleDigest?.Value ?? string.Empty,
            PolicyDigest?.Value ?? string.Empty,
            ReleaseDigest?.Value ?? string.Empty,
            CapabilityGrantDigest?.Value ?? string.Empty);
}

public sealed record CancelAttemptCommand(
    string SchemaVersion,
    ResourceId NodeReference,
    ResourceId ProjectId,
    ResourceId AttemptId,
    DateTimeOffset ExpiresAt,
    ResourceId LeaseReference,
    string Reason)
    : NodeCommand(SchemaVersion, NodeReference, ProjectId, AttemptId, ExpiresAt)
{
    internal override string CanonicalIdentity() =>
        ProtocolIdentity.Join(
            GetType().Name,
            SchemaVersion,
            NodeReference.ToString(),
            ProjectId.ToString(),
            AttemptId.ToString(),
            ExpiresAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            LeaseReference.ToString(),
            Reason);
}

public sealed record UnsupportedNodeCommand(
    string SchemaVersion,
    ResourceId NodeReference,
    ResourceId ProjectId,
    ResourceId AttemptId,
    DateTimeOffset ExpiresAt)
    : NodeCommand(SchemaVersion, NodeReference, ProjectId, AttemptId, ExpiresAt)
{
    internal override string CanonicalIdentity() =>
        ProtocolIdentity.Join(GetType().Name, SchemaVersion, NodeReference.ToString(), ProjectId.ToString(), AttemptId.ToString());
}

public sealed record InventoryObservation(
    string OperatingSystem,
    string Architecture,
    ImmutableHashSet<IsolationProfile> EnforceableIsolationProfiles,
    DateTimeOffset ObservedAt);

public sealed record HealthObservation(
    string AgentVersion,
    bool StorageAvailable,
    DateTimeOffset ObservedAt);

public sealed record LocalIsolationCapabilities(
    ImmutableHashSet<IsolationProfile> EnforceableProfiles);

public enum AttemptExecutionState
{
    Prepared,
    Running,
    CancellationRequested,
    Terminated,
    Failed
}

public sealed record AttemptRuntime(
    ResourceId ProjectId,
    ResourceId WorkloadId,
    ResourceId AttemptId,
    ResourceId AdmissionDecisionReference,
    ResourceId LeaseReference,
    IsolationProfile IsolationProfile,
    Sha256Digest BundleDigest,
    Sha256Digest PolicyDigest,
    Sha256Digest ReleaseDigest,
    Sha256Digest CapabilityGrantDigest,
    DateTimeOffset AuthorityExpiresAt,
    AttemptExecutionState State,
    DateTimeOffset UpdatedAt);

public sealed record ProcessTreeObservation(
    ResourceId AttemptId,
    int? ExitCode,
    bool ProcessTreePresent,
    DateTimeOffset ObservedAt);

public sealed record EvidenceObservation(
    ResourceId AttemptId,
    Sha256Digest ManifestDigest,
    Sha256Digest OutputDigest,
    DateTimeOffset ObservedAt);

public sealed record NodeCommandAcknowledgement(
    Guid MessageId,
    Guid CorrelationId,
    string IdempotencyKey,
    bool Accepted,
    bool Duplicate,
    string Code,
    string Message);

public sealed record FullReconciliationSnapshot(
    NodeDeviceIdentity Identity,
    long StreamEpoch,
    long LastInboundSequence,
    InventoryObservation Inventory,
    HealthObservation Health,
    ImmutableArray<AttemptRuntime> Attempts,
    ImmutableArray<EvidenceObservation> Evidence,
    ImmutableArray<UpgradeJournalEvent> Upgrades);

internal static class ProtocolIdentity
{
    public static string Envelope(NodeCommand? command, string? idempotencyKey) =>
        Join(idempotencyKey, command?.CanonicalIdentity());

    public static string Join(params string?[] values) =>
        string.Concat(values.Select(static value =>
        {
            var normalised = value ?? string.Empty;
            return $"{normalised.Length}:{normalised};";
        }));
}

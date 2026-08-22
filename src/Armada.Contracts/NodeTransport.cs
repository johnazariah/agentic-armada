using System.Collections.Immutable;

namespace Armada.Contracts;

public static class NodeTransportProtocol
{
    public const string Version = "armada.node.transport/v1alpha1";
    public const int MinimumClaimSecretBytes = 32;
    public const int MaximumClaimSecretBytes = 128;
    public const int MaximumInventoryFacts = 64;
    public const int MaximumInventoryCapabilities = 64;
    public const int MaximumInventoryValueBytes = 512;
    public const int MaximumAttestationBytes = 16 * 1024;
    public const int MaximumPublicKeyBytes = 4 * 1024;
    public const int MaximumCsrBytes = 16 * 1024;
    public const int MaximumTransportPayloadBytes = 64 * 1024;
    public const int MaximumTransportEnvelopeBytes = 128 * 1024;
    public const int MaximumIdempotencyKeyBytes = 128;
    public const string HelloPayloadType = "armada.node.transport.payload.hello/v1alpha1";
    public const string FullReconciliationSnapshotPayloadType = "armada.node.transport.payload.full-reconciliation-snapshot/v1alpha1";
    public const string InventoryObservationPayloadType = "armada.node.transport.payload.inventory-observation/v1alpha1";
    public const string HealthObservationPayloadType = "armada.node.transport.payload.health-observation/v1alpha1";
    public const string TransportAcknowledgementPayloadType = "armada.node.transport.payload.acknowledgement/v1alpha1";
    public const string TransportRejectionPayloadType = "armada.node.transport.payload.rejection/v1alpha1";
}

public readonly record struct NodeUid(Guid Value)
{
    public override string ToString() => Value.ToString("D");
}

public sealed record EnrollmentInventory(
    ImmutableDictionary<string, string> Facts,
    ImmutableArray<string> Capabilities);

// The secret is untrusted input only. Successful validation intentionally does
// not return it, so callers cannot accidentally retain it in decision state.
public sealed record EnrollmentRequestDto(
    string ProtocolVersion,
    string ClaimId,
    ImmutableArray<byte> ClaimSecret,
    string NodeUid,
    long IdentityEpoch,
    ImmutableArray<byte> DevicePublicKey,
    ImmutableArray<byte> PublicKeySha256,
    ImmutableArray<byte> CertificateSigningRequest,
    EnrollmentInventory Inventory,
    ImmutableArray<byte>? Attestation,
    string RequestId,
    DateTimeOffset SentAt);

public sealed record EnrollmentResponseDto(
    string ProtocolVersion,
    string NodeUid,
    long IdentityEpoch,
    string CertificateSerial,
    DateTimeOffset ExpiresAt,
    ImmutableArray<byte> LeafCertificateDer,
    ImmutableArray<byte> IssuingCaDer,
    string CorrelationId);

public enum TransportPayloadKind
{
    Unspecified = 0,
    Hello = 1,
    FullReconciliationSnapshot = 2,
    InventoryObservation = 3,
    HealthObservation = 4,
    TransportAck = 5,
    TransportRejection = 6,
    ReservedCommand = 100,
    ReservedAdmission = 101,
    ReservedLease = 102,
    ReservedProcess = 103,
    ReservedCredential = 104
}

public sealed record ValidatedTransportPayload(
    TransportPayloadKind Kind,
    string SchemaVersion,
    ImmutableArray<byte> CanonicalPayload);

public sealed record TransportAcknowledgement(
    Guid MessageId,
    Guid CorrelationId,
    string IdempotencyKey,
    bool Accepted,
    string Code,
    string Message);

public sealed record CertificateBindingDto(
    string NodeUid,
    long IdentityEpoch,
    ImmutableArray<byte> ExpectedPublicKeySha256,
    ImmutableArray<byte> LeafCertificateDer,
    string CertificateSerial,
    string CertificateThumbprintSha256,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt);

public sealed record ValidatedEnrollmentRequest(
    Guid ClaimId,
    NodeUid NodeUid,
    long IdentityEpoch,
    ImmutableArray<byte> DevicePublicKey,
    Sha256Digest PublicKeyDigest,
    ImmutableArray<byte> CertificateSigningRequest,
    EnrollmentInventory Inventory,
    ImmutableArray<byte>? Attestation,
    Guid RequestId,
    DateTimeOffset SentAt);

public sealed record ReplayIdentity(
    NodeUid NodeUid,
    long IdentityEpoch,
    long StreamEpoch,
    long Sequence,
    Guid MessageId,
    Guid CorrelationId,
    string IdempotencyKey,
    string ProtocolVersion,
    TransportPayloadKind PayloadKind,
    DateTimeOffset SentAt,
    Sha256Digest PayloadDigest)
{
    public string CanonicalValue =>
        string.Concat(
            NodeUid, "|",
            IdentityEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            StreamEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            MessageId.ToString("D"), "|",
            CorrelationId.ToString("D"), "|",
            IdempotencyKey.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), ":", IdempotencyKey, "|",
            ProtocolVersion.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), ":", ProtocolVersion, "|",
            PayloadKind.ToString(), "|",
            SentAt.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture), "|",
            PayloadDigest.Value);
}

public sealed record ValidatedTransportEnvelope(
    ReplayIdentity ReplayIdentity,
    ValidatedTransportPayload Payload,
    DateTimeOffset SentAt);

public sealed record NodeTransportValidationError(string Code, string Message);

using System.Collections.Immutable;
using Armada.Contracts;

namespace Armada.Application;

public sealed record EnrollmentClaimReference(Guid ClaimId, NodeUid NodeUid, long IdentityEpoch, Sha256Digest PublicKeyDigest);
public sealed record EnrollmentClaimState(
    EnrollmentClaimReference Reference,
    DateTimeOffset ExpiresAt,
    bool IsConsumed);
public sealed record EnrollmentClaimConsumption(EnrollmentClaimReference Reference, DateTimeOffset ConsumedAt, Guid CorrelationId);
public sealed record EnrollmentClaimReservation(
    EnrollmentClaimState Claim,
    Guid RequestId,
    DateTimeOffset ExpiresAt);
public sealed record EnrollmentClaimStoreFailure(string Code, string Message);

public interface IEnrollmentClaimStore
{
    Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> GetAsync(
        Guid claimId,
        CancellationToken cancellationToken);

    // This verifies the one-use claim before an external issuer is invoked. It
    // deliberately leaves consumption to the atomic identity-binding operation.
    Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> VerifyAsync(
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    Task<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>> ReserveAsync(
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret,
        Guid requestId,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    Task<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>> ConsumeAsync(
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret,
        CancellationToken cancellationToken);
}

public sealed record NodeIdentityBinding(
    NodeUid NodeUid,
    long IdentityEpoch,
    Sha256Digest PublicKeyDigest,
    string CertificateSerial,
    string CertificateThumbprintSha256,
    DateTimeOffset ExpiresAt,
    bool IsRevoked);
public sealed record NodeIdentityRegistryFailure(string Code, string Message);

public interface INodeIdentityRegistry
{
    Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
        NodeUid nodeUid,
        long identityEpoch,
        string certificateSerial,
        string certificateThumbprintSha256,
        CancellationToken cancellationToken);

    Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
        NodeIdentityBinding binding,
        CancellationToken cancellationToken);

    Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
        NodeUid nodeUid,
        long identityEpoch,
        string reason,
        Guid correlationId,
        CancellationToken cancellationToken);
}

public sealed record ReplayReceipt(ReplayIdentity Identity, TransportAcknowledgement Acknowledgement);
public sealed record ReplayReceiptStoreFailure(string Code, string Message);

public interface ITransportReplayReceiptStore
{
    Task<Result<ReplayReceipt, ReplayReceiptStoreFailure>> RetrieveOrRecordAsync(
        ReplayReceipt receipt,
        CancellationToken cancellationToken);
}

public sealed record EnrollmentCompletionRequest(
    EnrollmentClaimReference Claim,
    ReadOnlyMemory<byte> PresentedSecret,
    NodeIdentityBinding Identity,
    EnrollmentResponseDto Response,
    Guid RequestId,
    Guid CorrelationId,
    DateTimeOffset OccurredAt);

public abstract record EnrollmentCompletion
{
    private EnrollmentCompletion()
    {
    }

    public sealed record Completed(EnrollmentResponseDto Response, NodeIdentityBinding Identity) : EnrollmentCompletion;
    public sealed record AlreadyCompleted(EnrollmentResponseDto Response, NodeIdentityBinding Identity) : EnrollmentCompletion;
}

public sealed record EnrollmentStateStoreFailure(string Code, string Message);

// Claim consumption, certificate identity binding, and their durable evidence
// are one controller-side transition. This prevents callers from consuming a
// claim and attempting a separate, lossy identity registration afterwards.
public interface IEnrollmentStateStore
{
    Task<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>> FindCompletedAsync(
        EnrollmentClaimReference claim,
        ReadOnlyMemory<byte> presentedSecret,
        CancellationToken cancellationToken);

    Task<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>> CompleteAsync(
        EnrollmentCompletionRequest request,
        CancellationToken cancellationToken);
}

public sealed record CertificateIssuanceRequest(
    ValidatedEnrollmentRequest Enrollment,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    Guid CorrelationId);
public sealed record CertificateIssuanceFailure(string Code, string Message);
public sealed record IssuedCertificate(
    string Serial,
    ImmutableArray<byte> LeafCertificateDer,
    ImmutableArray<byte> IssuingCaDer,
    DateTimeOffset ExpiresAt);

public interface ILabCertificateIssuer
{
    Task<Result<IssuedCertificate, CertificateIssuanceFailure>> IssueAsync(
        CertificateIssuanceRequest request,
        CancellationToken cancellationToken);
}

public sealed record DeviceCsrRequest(NodeUid NodeUid, long IdentityEpoch, ImmutableArray<byte> SubjectAlternativeName);
public sealed record DeviceKeyFailure(string Code, string Message);

public interface IDeviceKeyHandle
{
    Sha256Digest PublicKeyDigest { get; }

    Task<Result<ImmutableArray<byte>, DeviceKeyFailure>> CreateSigningRequestAsync(
        DeviceCsrRequest request,
        CancellationToken cancellationToken);
}

public interface IDeviceKeyStore
{
    Task<Result<IDeviceKeyHandle, DeviceKeyFailure>> OpenOrCreateAsync(
        NodeUid nodeUid,
        CancellationToken cancellationToken);
}

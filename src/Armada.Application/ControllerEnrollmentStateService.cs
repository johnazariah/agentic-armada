using System.Security.Cryptography;
using Armada.Contracts;

namespace Armada.Application;

public sealed record EnrollmentStateApplicationFailure(string Code, string Message);

// This service is deliberately transport- and issuer-free. A later lab adapter
// validates the request, verifies it before issuance, then supplies the issued
// certificate response to this durable controller transition.
public sealed class ControllerEnrollmentStateService(
    IEnrollmentClaimStore claims,
    IEnrollmentStateStore state)
{
    public async Task<Result<EnrollmentCompletion?, EnrollmentStateApplicationFailure>> FindCompletedAsync(
        ValidatedEnrollmentRequest enrollment,
        ReadOnlyMemory<byte> presentedSecret,
        CancellationToken cancellationToken)
    {
        var result = await state.FindCompletedAsync(
            new EnrollmentClaimReference(
                enrollment.ClaimId,
                enrollment.NodeUid,
                enrollment.IdentityEpoch,
                enrollment.PublicKeyDigest),
            presentedSecret,
            cancellationToken);
        return result switch
        {
            Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Success success =>
                new Result<EnrollmentCompletion?, EnrollmentStateApplicationFailure>.Success(success.Value),
            Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Failure failure =>
                Failure<EnrollmentCompletion?>(failure.Error.Code, failure.Error.Message),
            _ => throw new InvalidOperationException("Unsupported completed enrolment lookup result.")
        };
    }

    public async Task<Result<EnrollmentClaimState, EnrollmentStateApplicationFailure>> VerifyBeforeIssuanceAsync(
        ValidatedEnrollmentRequest enrollment,
        ReadOnlyMemory<byte> presentedSecret,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = await claims.ReserveAsync(
            new EnrollmentClaimReference(
                enrollment.ClaimId,
                enrollment.NodeUid,
                enrollment.IdentityEpoch,
                enrollment.PublicKeyDigest),
            presentedSecret,
            enrollment.RequestId,
            now,
            cancellationToken);
        return result switch
        {
            Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success success =>
                new Result<EnrollmentClaimState, EnrollmentStateApplicationFailure>.Success(success.Value.Claim),
            Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure failure =>
                Failure<EnrollmentClaimState>(failure.Error.Code, failure.Error.Message),
            _ => throw new InvalidOperationException("Unsupported claim verification result.")
        };
    }

    public async Task<Result<EnrollmentCompletion, EnrollmentStateApplicationFailure>> CompleteAsync(
        ValidatedEnrollmentRequest enrollment,
        ReadOnlyMemory<byte> presentedSecret,
        CertificateBindingDto certificate,
        EnrollmentResponseDto response,
        Guid correlationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken)
    {
        var certificateValidation = NodeEnrollmentDecisions.ValidateCertificateBinding(certificate, occurredAt);
        if (certificateValidation is Result<CertificateBindingDto, NodeTransportValidationError>.Failure certificateFailure)
        {
            return Failure<EnrollmentCompletion>(certificateFailure.Error.Code, certificateFailure.Error.Message);
        }

        if (!Matches(enrollment, certificate, response, correlationId))
        {
            return Failure<EnrollmentCompletion>(
                "enrollment-response-binding-mismatch",
                "The durable enrolment response does not exactly bind the validated request and certificate.");
        }

        var completion = await state.CompleteAsync(
            new EnrollmentCompletionRequest(
                new EnrollmentClaimReference(
                    enrollment.ClaimId,
                    enrollment.NodeUid,
                    enrollment.IdentityEpoch,
                    enrollment.PublicKeyDigest),
                presentedSecret,
                new NodeIdentityBinding(
                    enrollment.NodeUid,
                    enrollment.IdentityEpoch,
                    enrollment.PublicKeyDigest,
                    certificate.CertificateSerial,
                    certificate.CertificateThumbprintSha256,
                    certificate.ExpiresAt,
                    false),
                response,
                enrollment.RequestId,
                correlationId,
                occurredAt),
            cancellationToken);
        return completion switch
        {
            Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success success =>
                new Result<EnrollmentCompletion, EnrollmentStateApplicationFailure>.Success(success.Value),
            Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Failure failure =>
                Failure<EnrollmentCompletion>(failure.Error.Code, failure.Error.Message),
            _ => throw new InvalidOperationException("Unsupported enrolment completion result.")
        };
    }

    private static bool Matches(
        ValidatedEnrollmentRequest enrollment,
        CertificateBindingDto certificate,
        EnrollmentResponseDto response,
        Guid correlationId) =>
        response is not null &&
        response.ProtocolVersion == NodeTransportProtocol.Version &&
        response.NodeUid == enrollment.NodeUid.ToString() &&
        response.IdentityEpoch == enrollment.IdentityEpoch &&
        response.CertificateSerial == certificate.CertificateSerial &&
        response.ExpiresAt == certificate.ExpiresAt &&
        response.LeafCertificateDer.SequenceEqual(certificate.LeafCertificateDer) &&
        response.CorrelationId == correlationId.ToString("D") &&
        certificate.NodeUid == enrollment.NodeUid.ToString() &&
        certificate.IdentityEpoch == enrollment.IdentityEpoch &&
        certificate.ExpectedPublicKeySha256.AsSpan().SequenceEqual(
            Convert.FromHexString(enrollment.PublicKeyDigest.Value["sha256:".Length..]));

    private static Result<T, EnrollmentStateApplicationFailure> Failure<T>(string code, string message) =>
        new Result<T, EnrollmentStateApplicationFailure>.Failure(new(code, message));
}

using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Application;
using Armada.Contracts;

namespace Armada.Application.Tests;

public sealed class ControllerEnrollmentStateServiceTests
{
    [Fact]
    public async Task Service_reserves_validated_claims_and_returns_completed_results_from_state()
    {
        var material = Material();
        var claim = new ClaimStore(material.ClaimState);
        var state = new StateStore(new EnrollmentCompletion.AlreadyCompleted(material.Response, material.Identity));
        var service = new ControllerEnrollmentStateService(claim, state);

        var reserved = await service.VerifyBeforeIssuanceAsync(
            material.Enrollment,
            material.Secret,
            material.Now,
            CancellationToken.None);
        var completed = await service.FindCompletedAsync(
            material.Enrollment,
            material.Secret,
            CancellationToken.None);

        Assert.Equal(material.ClaimState, Success(reserved));
        Assert.Equal(material.Enrollment.RequestId, claim.ReservedRequestId);
        Assert.IsType<EnrollmentCompletion.AlreadyCompleted>(Success(completed));
    }

    [Fact]
    public async Task Service_validates_certificate_response_before_the_atomic_completion()
    {
        var material = Material();
        var state = new StateStore(null);
        var service = new ControllerEnrollmentStateService(new ClaimStore(material.ClaimState), state);

        var completed = await service.CompleteAsync(
            material.Enrollment,
            material.Secret,
            material.Certificate,
            material.Response,
            material.CorrelationId,
            material.Now,
            CancellationToken.None);
        var rejected = await service.CompleteAsync(
            material.Enrollment,
            material.Secret,
            material.Certificate,
            material.Response with { CertificateSerial = "00" },
            material.CorrelationId,
            material.Now,
            CancellationToken.None);

        Assert.IsType<EnrollmentCompletion.Completed>(Success(completed));
        Assert.NotNull(state.Request);
        Assert.Equal(material.Enrollment.RequestId, state.Request!.RequestId);
        Assert.Equal(
            "enrollment-response-binding-mismatch",
            Failure(rejected).Code);
        Assert.Equal(1, state.CompletionCount);
    }

    [Fact]
    public async Task Service_maps_claim_and_state_failures_without_invoking_completion()
    {
        var material = Material();
        var claim = new ClaimStore(material.ClaimState)
        {
            ReservationFailure = new EnrollmentClaimStoreFailure("claim-refused", "Refused.")
        };
        var state = new StateStore(null)
        {
            LookupFailure = new EnrollmentStateStoreFailure("lookup-refused", "Refused.")
        };
        var service = new ControllerEnrollmentStateService(claim, state);

        var reservation = await service.VerifyBeforeIssuanceAsync(
            material.Enrollment,
            material.Secret,
            material.Now,
            CancellationToken.None);
        var lookup = await service.FindCompletedAsync(
            material.Enrollment,
            material.Secret,
            CancellationToken.None);

        Assert.Equal("claim-refused", Failure(reservation).Code);
        Assert.Equal("lookup-refused", Failure(lookup).Code);
        Assert.Equal(0, state.CompletionCount);
    }

    private static EnrollmentMaterial Material()
    {
        var now = DateTimeOffset.UtcNow;
        var nodeUid = new NodeUid(Guid.NewGuid());
        var epoch = 1L;
        var claimId = Guid.NewGuid();
        var requestId = Guid.NewGuid();
        var correlationId = Guid.NewGuid();
        var secret = Enumerable.Repeat((byte)9, 32).ToArray();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var digest = Digest(SHA256.HashData(publicKey));
        var certificateRequest = new CertificateRequest("CN=armada-node", key, HashAlgorithmName.SHA256);
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"spiffe://armada.lab/node/{nodeUid}/epoch/{epoch}"));
        certificateRequest.CertificateExtensions.Add(san.Build());
        using var certificate = certificateRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
        var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime());
        var expiresAt = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        var leaf = ImmutableArray.CreateRange(certificate.Export(X509ContentType.Cert));
        var binding = new CertificateBindingDto(
            nodeUid.ToString(),
            epoch,
            ImmutableArray.CreateRange(SHA256.HashData(publicKey)),
            leaf,
            certificate.SerialNumber,
            Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            notBefore,
            expiresAt);
        var identity = new NodeIdentityBinding(
            nodeUid,
            epoch,
            digest,
            binding.CertificateSerial,
            binding.CertificateThumbprintSha256,
            expiresAt,
            false);
        var enrollment = new ValidatedEnrollmentRequest(
            claimId,
            nodeUid,
            epoch,
            ImmutableArray.CreateRange(publicKey),
            digest,
            ImmutableArray<byte>.Empty,
            new EnrollmentInventory(ImmutableDictionary<string, string>.Empty, ImmutableArray<string>.Empty),
            null,
            requestId,
            now);
        var response = new EnrollmentResponseDto(
            NodeTransportProtocol.Version,
            nodeUid.ToString(),
            epoch,
            binding.CertificateSerial,
            expiresAt,
            leaf,
            ImmutableArray.Create<byte>(1),
            correlationId.ToString("D"));
        return new(
            enrollment,
            binding,
            response,
            identity,
            new EnrollmentClaimState(
                new EnrollmentClaimReference(claimId, nodeUid, epoch, digest),
                now.AddMinutes(5),
                false),
            secret,
            correlationId,
            now);
    }

    private static Sha256Digest Digest(ReadOnlySpan<byte> bytes) =>
        Sha256Digest.Parse($"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}") is Result<Sha256Digest, ContractValidationError>.Success digest
            ? digest.Value
            : throw new InvalidOperationException("Test digest is invalid.");

    private static T Success<T>(Result<T, EnrollmentStateApplicationFailure> result) =>
        Assert.IsType<Result<T, EnrollmentStateApplicationFailure>.Success>(result).Value;

    private static EnrollmentStateApplicationFailure Failure<T>(Result<T, EnrollmentStateApplicationFailure> result) =>
        Assert.IsType<Result<T, EnrollmentStateApplicationFailure>.Failure>(result).Error;

    private sealed record EnrollmentMaterial(
        ValidatedEnrollmentRequest Enrollment,
        CertificateBindingDto Certificate,
        EnrollmentResponseDto Response,
        NodeIdentityBinding Identity,
        EnrollmentClaimState ClaimState,
        byte[] Secret,
        Guid CorrelationId,
        DateTimeOffset Now);

    private sealed class ClaimStore(EnrollmentClaimState state) : IEnrollmentClaimStore
    {
        public EnrollmentClaimStoreFailure? ReservationFailure { get; init; }
        public Guid ReservedRequestId { get; private set; }

        public Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> GetAsync(Guid claimId, CancellationToken cancellationToken) =>
            Task.FromResult<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>>(
                new Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Success(state));

        public Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> VerifyAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            DateTimeOffset now,
            CancellationToken cancellationToken) =>
            Task.FromResult<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>>(
                new Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Success(state));

        public Task<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>> ReserveAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            Guid requestId,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            ReservedRequestId = requestId;
            return Task.FromResult<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>>(
                ReservationFailure is null
                    ? new Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success(
                        new EnrollmentClaimReservation(state, requestId, now.AddMinutes(1)))
                    : new Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure(ReservationFailure));
        }

        public Task<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>> ConsumeAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            CancellationToken cancellationToken) =>
            Task.FromResult<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>>(
                new Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>.Failure(
                    new EnrollmentClaimStoreFailure("not-used", "Not used by this service.")));
    }

    private sealed class StateStore(EnrollmentCompletion? completion) : IEnrollmentStateStore
    {
        public EnrollmentStateStoreFailure? LookupFailure { get; init; }
        public EnrollmentCompletionRequest? Request { get; private set; }
        public int CompletionCount { get; private set; }

        public Task<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>> FindCompletedAsync(
            EnrollmentClaimReference claim,
            ReadOnlyMemory<byte> presentedSecret,
            CancellationToken cancellationToken) =>
            Task.FromResult<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>>(
                LookupFailure is null
                    ? new Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Success(completion)
                    : new Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Failure(LookupFailure));

        public Task<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>> CompleteAsync(
            EnrollmentCompletionRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            CompletionCount++;
            return Task.FromResult<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>>(
                new Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success(
                    new EnrollmentCompletion.Completed(request.Response, request.Identity)));
        }
    }
}

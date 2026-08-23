using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Application;
using Armada.Contracts;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls;

public sealed class LabNodeEnrollmentGrpcService(
    ControllerEnrollmentStateService enrollmentState,
    ILabCertificateIssuer certificateIssuer,
    TimeProvider? clock = null,
    TimeSpan? certificateLifetime = null) : Proto.NodeEnrollment.NodeEnrollmentBase
{
    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly TimeSpan certificateLifetime = certificateLifetime ?? TimeSpan.FromDays(1);

    public TimeSpan CertificateLifetime => certificateLifetime;

    public override async Task<Proto.EnrollmentResponse> Enroll(
        Proto.EnrollmentRequest request,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        var now = clock.GetUtcNow();
        var validation = NodeEnrollmentDecisions.ValidateEnrollment(ToDto(request), now);
        if (validation is Result<ValidatedEnrollmentRequest, NodeTransportValidationError>.Failure failure)
        {
            throw RpcFailure(StatusCode.InvalidArgument, failure.Error);
        }

        var validated = ((Result<ValidatedEnrollmentRequest, NodeTransportValidationError>.Success)validation).Value;
        var secret = request.ClaimSecret.Memory;
        var completed = await enrollmentState.FindCompletedAsync(validated, secret, context.CancellationToken);
        if (completed is Result<EnrollmentCompletion?, EnrollmentStateApplicationFailure>.Failure completedFailure)
        {
            throw RpcFailure(StatusCode.FailedPrecondition, completedFailure.Error);
        }

        if (((Result<EnrollmentCompletion?, EnrollmentStateApplicationFailure>.Success)completed).Value is { } existing)
        {
            return ToProto(ResponseOf(existing));
        }

        var reservation = await enrollmentState.VerifyBeforeIssuanceAsync(
            validated,
            secret,
            now,
            context.CancellationToken);
        if (reservation is Result<EnrollmentClaimState, EnrollmentStateApplicationFailure>.Failure reservationFailure)
        {
            throw RpcFailure(StatusCode.FailedPrecondition, reservationFailure.Error);
        }

        var correlationId = Guid.NewGuid();
        var notBefore = now.AddMinutes(-1);
        var expiresAt = now.Add(certificateLifetime);
        var issuance = await certificateIssuer.IssueAsync(
            new CertificateIssuanceRequest(validated, notBefore, expiresAt, correlationId),
            context.CancellationToken);
        if (issuance is Result<IssuedCertificate, CertificateIssuanceFailure>.Failure issuanceFailure)
        {
            throw new RpcException(new Status(StatusCode.Unavailable, $"{issuanceFailure.Error.Code}: {issuanceFailure.Error.Message}"));
        }

        var issued = ((Result<IssuedCertificate, CertificateIssuanceFailure>.Success)issuance).Value;
        var certificate = ToCertificateBinding(validated, issued, notBefore, expiresAt);
        var response = new EnrollmentResponseDto(
            NodeTransportProtocol.Version,
            validated.NodeUid.ToString(),
            validated.IdentityEpoch,
            issued.Serial,
            issued.ExpiresAt,
            issued.LeafCertificateDer,
            issued.IssuingCaDer,
            correlationId.ToString("D"));
        var completion = await enrollmentState.CompleteAsync(
            validated,
            secret,
            certificate,
            response,
            correlationId,
            now,
            context.CancellationToken);
        if (completion is Result<EnrollmentCompletion, EnrollmentStateApplicationFailure>.Failure completionFailure)
        {
            throw RpcFailure(StatusCode.FailedPrecondition, completionFailure.Error);
        }

        return ToProto(ResponseOf(
            ((Result<EnrollmentCompletion, EnrollmentStateApplicationFailure>.Success)completion).Value));
    }

    internal async Task<Proto.EnrollmentResponse> EnrollRawAsync(
        RawGrpcMessage rawRequest,
        ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(rawRequest);
        ArgumentNullException.ThrowIfNull(context);

        if (!IsStrictEnrollmentOuterWire(rawRequest.Bytes.AsSpan()))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid-enrollment-request"));
        }

        try
        {
            return await Enroll(Proto.EnrollmentRequest.Parser.ParseFrom(rawRequest.Bytes.ToArray()), context);
        }
        catch (InvalidProtocolBufferException)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "invalid-enrollment-request"));
        }
    }

    private static EnrollmentRequestDto ToDto(Proto.EnrollmentRequest request) =>
        new(
            request.ProtocolVersion,
            request.ClaimId,
            request.ClaimSecret.ToByteArray().ToImmutableArray(),
            request.NodeUid,
            request.IdentityEpoch,
            request.DevicePublicKey.ToByteArray().ToImmutableArray(),
            request.PublicKeySha256.ToByteArray().ToImmutableArray(),
            request.CertificateSigningRequest.ToByteArray().ToImmutableArray(),
            new EnrollmentInventory(
                request.Inventory?.Facts.ToImmutableDictionary(StringComparer.Ordinal) ??
                    ImmutableDictionary<string, string>.Empty,
                request.Inventory?.Capabilities.ToImmutableArray() ?? ImmutableArray<string>.Empty),
            request.HasAttestation ? request.Attestation.ToByteArray().ToImmutableArray() : null,
            request.RequestId,
            TimestampOrDefault(request.SentAt));

    private static CertificateBindingDto ToCertificateBinding(
        ValidatedEnrollmentRequest enrollment,
        IssuedCertificate issued,
        DateTimeOffset notBefore,
        DateTimeOffset expiresAt)
    {
        using var certificate = X509CertificateLoader.LoadCertificate(issued.LeafCertificateDer.AsSpan());
        return new(
            enrollment.NodeUid.ToString(),
            enrollment.IdentityEpoch,
            ImmutableArray.CreateRange(Convert.FromHexString(enrollment.PublicKeyDigest.Value["sha256:".Length..])),
            issued.LeafCertificateDer,
            issued.Serial,
            Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            notBefore,
            expiresAt);
    }

    private static DateTimeOffset TimestampOrDefault(Timestamp? timestamp)
    {
        if (timestamp is null)
        {
            return default;
        }

        try
        {
            return timestamp.ToDateTimeOffset();
        }
        catch (ArgumentOutOfRangeException)
        {
            return default;
        }
        catch (InvalidOperationException)
        {
            return default;
        }
    }

    internal static Proto.EnrollmentResponse ToProto(EnrollmentResponseDto response) =>
        new()
        {
            ProtocolVersion = response.ProtocolVersion,
            NodeUid = response.NodeUid,
            IdentityEpoch = response.IdentityEpoch,
            CertificateSerial = response.CertificateSerial,
            ExpiresAt = Timestamp.FromDateTimeOffset(response.ExpiresAt),
            LeafCertificateDer = Google.Protobuf.ByteString.CopyFrom(response.LeafCertificateDer.AsSpan()),
            IssuingCaDer = Google.Protobuf.ByteString.CopyFrom(response.IssuingCaDer.AsSpan()),
            CorrelationId = response.CorrelationId
        };

    private static EnrollmentResponseDto ResponseOf(EnrollmentCompletion completion) =>
        completion switch
        {
            EnrollmentCompletion.Completed completed => completed.Response,
            EnrollmentCompletion.AlreadyCompleted completed => completed.Response,
            _ => throw new InvalidOperationException("Unsupported enrolment completion.")
        };

    private static RpcException RpcFailure(StatusCode status, EnrollmentStateApplicationFailure failure) =>
        new(new Status(status, $"{failure.Code}: {failure.Message}"));

    private static RpcException RpcFailure(StatusCode status, NodeTransportValidationError failure) =>
        new(new Status(status, $"{failure.Code}: {failure.Message}"));

    private static bool IsStrictEnrollmentOuterWire(ReadOnlySpan<byte> bytes)
    {
        var seen = new HashSet<uint>();
        try
        {
            var input = new Google.Protobuf.CodedInputStream(bytes.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!seen.Add(tag))
                {
                    return false;
                }

                switch (tag)
                {
                    case 10:
                    case 18:
                    case 26:
                    case 34:
                    case 50:
                    case 58:
                    case 66:
                    case 82:
                    case 90:
                    case 98:
                        input.ReadBytes();
                        break;
                    case 74:
                        if (!IsStrictEnrollmentInventory(input.ReadBytes().Span))
                        {
                            return false;
                        }

                        break;
                    case 40:
                        input.ReadInt64();
                        break;
                    default:
                        return false;
                }
            }

            return true;
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }
    }

    private static bool IsStrictEnrollmentInventory(ReadOnlySpan<byte> bytes)
    {
        var mapKeys = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var input = new Google.Protobuf.CodedInputStream(bytes.ToArray());
            while (!input.IsAtEnd)
            {
                switch (input.ReadTag())
                {
                    case 10:
                        if (!TryReadStrictInventoryMapEntry(input.ReadBytes().Span, out var key) ||
                            !mapKeys.Add(key))
                        {
                            return false;
                        }

                        break;
                    case 18:
                        input.ReadString();
                        break;
                    default:
                        return false;
                }
            }

            return true;
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }
    }

    private static bool TryReadStrictInventoryMapEntry(ReadOnlySpan<byte> bytes, out string key)
    {
        var seen = new HashSet<uint>();
        key = string.Empty;
        try
        {
            var input = new Google.Protobuf.CodedInputStream(bytes.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!seen.Add(tag))
                {
                    return false;
                }

                switch (tag)
                {
                    case 10:
                        key = input.ReadString();
                        break;
                    case 18:
                        input.ReadString();
                        break;
                    default:
                        return false;
                }
            }

            return !string.IsNullOrEmpty(key);
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }
    }
}

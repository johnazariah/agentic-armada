using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Application;
using Armada.Contracts;
using Google.Protobuf.WellKnownTypes;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls;

// This core accepts the received protobuf bytes. The generated gRPC stream binder
// deliberately does not call it because it cannot provide those bytes losslessly.
public sealed class RawNodeTransportService(
    INodeIdentityRegistry identities,
    ITransportReplayReceiptStore replayReceipts,
    TimeProvider? clock = null)
{
    private readonly TimeProvider clock = clock ?? TimeProvider.System;

    public async Task<Proto.ControlToNode> ProcessAsync(
        ReadOnlyMemory<byte> encodedEnvelope,
        X509Certificate2 clientCertificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientCertificate);

        var now = clock.GetUtcNow();
        // Do not parse or canonicalise before this decision: replay validation needs
        // the exact protobuf bytes received from the node.
        var validation = NodeEnrollmentDecisions.ValidateTransportEnvelope(encodedEnvelope.Span, now);
        if (validation is Result<ValidatedTransportEnvelope, NodeTransportValidationError>.Failure failure)
        {
            return Rejection(default, failure.Error.Code, failure.Error.Message, now);
        }

        var envelope = ((Result<ValidatedTransportEnvelope, NodeTransportValidationError>.Success)validation).Value;
        if (!IsNodeReport(envelope.Payload.Kind))
        {
            return Rejection(envelope.ReplayIdentity, "unsupported-transport-payload", "Only node reports are accepted.", now);
        }

        var identity = await identities.ResolveAsync(
            envelope.ReplayIdentity.NodeUid,
            envelope.ReplayIdentity.IdentityEpoch,
            clientCertificate.SerialNumber,
            Convert.ToHexString(clientCertificate.GetCertHash(HashAlgorithmName.SHA256)),
            cancellationToken);
        if (identity is Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure identityFailure)
        {
            return Rejection(envelope.ReplayIdentity, "unknown-node-identity", identityFailure.Error.Message, now);
        }

        var binding = ((Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success)identity).Value;
        if (binding.NodeUid != envelope.ReplayIdentity.NodeUid ||
            binding.IdentityEpoch != envelope.ReplayIdentity.IdentityEpoch ||
            !string.Equals(binding.CertificateSerial, clientCertificate.SerialNumber, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                binding.CertificateThumbprintSha256,
                Convert.ToHexString(clientCertificate.GetCertHash(HashAlgorithmName.SHA256)),
                StringComparison.OrdinalIgnoreCase) ||
            binding.IsRevoked ||
            binding.ExpiresAt <= now)
        {
            return Rejection(envelope.ReplayIdentity, "revoked-node-identity", "The client certificate identity is not active.", now);
        }

        var acknowledgement = new TransportAcknowledgement(
            envelope.ReplayIdentity.MessageId,
            envelope.ReplayIdentity.CorrelationId,
            envelope.ReplayIdentity.IdempotencyKey,
            true,
            "accepted",
            "The node report was accepted.");
        var receipt = await replayReceipts.RetrieveOrRecordAsync(
            new ReplayReceipt(envelope.ReplayIdentity, acknowledgement),
            cancellationToken);
        if (receipt is Result<ReplayReceipt, ReplayReceiptStoreFailure>.Failure replayFailure)
        {
            return Rejection(envelope.ReplayIdentity, "replay-conflict", replayFailure.Error.Message, now);
        }

        return Acknowledgement(
            ((Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success)receipt).Value.Acknowledgement,
            envelope.ReplayIdentity,
            now);
    }

    private static bool IsNodeReport(TransportPayloadKind kind) =>
        kind is TransportPayloadKind.Hello or
            TransportPayloadKind.FullReconciliationSnapshot or
            TransportPayloadKind.InventoryObservation or
            TransportPayloadKind.HealthObservation;

    private static Proto.ControlToNode Acknowledgement(
        TransportAcknowledgement acknowledgement,
        ReplayIdentity identity,
        DateTimeOffset now) =>
        Response(identity, now, response => response.TransportAck = new()
        {
            SchemaVersion = NodeTransportProtocol.Version,
            AcknowledgedMessageId = acknowledgement.MessageId.ToString("D"),
            Code = acknowledgement.Code,
            PayloadType = NodeTransportProtocol.TransportAcknowledgementPayloadType
        });

    private static Proto.ControlToNode Rejection(
        ReplayIdentity? identity,
        string code,
        string message,
        DateTimeOffset now) =>
        Response(identity, now, response => response.TransportRejection = new()
        {
            SchemaVersion = NodeTransportProtocol.Version,
            Code = ToRejectionCode(code),
            Message = message,
            PayloadType = NodeTransportProtocol.TransportRejectionPayloadType
        });

    private static Proto.ControlToNode Response(
        ReplayIdentity? identity,
        DateTimeOffset now,
        Action<Proto.ControlToNode> payload)
    {
        var response = new Proto.ControlToNode
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            NodeUid = identity?.NodeUid.ToString() ?? string.Empty,
            IdentityEpoch = identity?.IdentityEpoch ?? 0,
            StreamEpoch = identity?.StreamEpoch ?? 0,
            Sequence = identity?.Sequence ?? 0,
            MessageId = Guid.NewGuid().ToString("D"),
            CorrelationId = identity?.CorrelationId.ToString("D") ?? Guid.Empty.ToString("D"),
            IdempotencyKey = identity?.IdempotencyKey ?? "rejected",
            SentAt = Timestamp.FromDateTimeOffset(now)
        };
        payload(response);
        return response;
    }

    private static Proto.TransportRejectionCode ToRejectionCode(string code) =>
        code switch
        {
            "unsupported-protocol-version" => Proto.TransportRejectionCode.UnsupportedVersion,
            "replay-conflict" => Proto.TransportRejectionCode.ReplayConflict,
            "revoked-node-identity" => Proto.TransportRejectionCode.RevokedIdentity,
            _ => Proto.TransportRejectionCode.InvalidEnvelope
        };
}

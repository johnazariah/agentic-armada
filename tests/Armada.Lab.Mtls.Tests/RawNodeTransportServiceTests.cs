using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Application;
using Armada.Contracts;
using Armada.Lab.Mtls;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls.Tests;

public sealed class RawNodeTransportServiceTests
{
    [Fact]
    public async Task Raw_node_report_is_validated_before_replay_recording_and_acknowledged()
    {
        var now = DateTimeOffset.UtcNow;
        var nodeUid = new NodeUid(Guid.NewGuid());
        using var certificate = Certificate();
        var identity = new NodeIdentityBinding(
            nodeUid,
            1,
            Digest(new byte[32]),
            certificate.SerialNumber,
            Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            now.AddHours(1),
            false);
        var identities = new IdentityRegistry(identity);
        var receipts = new ReplayReceipts();
        var service = new RawNodeTransportService(identities, receipts, new FixedTimeProvider(now));
        var request = Envelope(nodeUid, Proto.NodeToControl.PayloadOneofCase.Hello);

        var response = await service.ProcessAsync(request.ToByteArray(), certificate, CancellationToken.None);

        Assert.Equal(Proto.ControlToNode.PayloadOneofCase.TransportAck, response.PayloadCase);
        Assert.Equal("accepted", response.TransportAck.Code);
        Assert.Equal(1, receipts.Calls);
    }

    [Fact]
    public async Task Node_acknowledgements_are_rejected_without_replay_recording()
    {
        var now = DateTimeOffset.UtcNow;
        var nodeUid = new NodeUid(Guid.NewGuid());
        using var certificate = Certificate();
        var identity = new NodeIdentityBinding(
            nodeUid,
            1,
            Digest(new byte[32]),
            certificate.SerialNumber,
            Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            now.AddHours(1),
            false);
        var receipts = new ReplayReceipts();
        var service = new RawNodeTransportService(
            new IdentityRegistry(identity),
            receipts,
            new FixedTimeProvider(now));
        var request = Envelope(nodeUid, Proto.NodeToControl.PayloadOneofCase.TransportAck);

        var response = await service.ProcessAsync(request.ToByteArray(), certificate, CancellationToken.None);

        Assert.Equal(Proto.ControlToNode.PayloadOneofCase.TransportRejection, response.PayloadCase);
        Assert.Equal(Proto.TransportRejectionCode.InvalidEnvelope, response.TransportRejection.Code);
        Assert.Equal(0, receipts.Calls);
    }

    private static Proto.NodeToControl Envelope(NodeUid nodeUid, Proto.NodeToControl.PayloadOneofCase payload)
    {
        var envelope = new Proto.NodeToControl
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            NodeUid = nodeUid.ToString(),
            IdentityEpoch = 1,
            StreamEpoch = 1,
            Sequence = 1,
            MessageId = Guid.NewGuid().ToString("D"),
            CorrelationId = Guid.NewGuid().ToString("D"),
            IdempotencyKey = "report-1",
            SentAt = Timestamp.FromDateTime(DateTime.UtcNow)
        };
        switch (payload)
        {
            case Proto.NodeToControl.PayloadOneofCase.Hello:
                envelope.Hello = new Proto.Hello
                {
                    SchemaVersion = NodeTransportProtocol.Version,
                    AgentVersion = "1.0.0",
                    PayloadType = NodeTransportProtocol.HelloPayloadType
                };
                break;
            case Proto.NodeToControl.PayloadOneofCase.TransportAck:
                envelope.TransportAck = new Proto.TransportAck
                {
                    SchemaVersion = NodeTransportProtocol.Version,
                    AcknowledgedMessageId = Guid.NewGuid().ToString("D"),
                    Code = "received",
                    PayloadType = NodeTransportProtocol.TransportAcknowledgementPayloadType
                };
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(payload));
        }

        return envelope;
    }

    private static Sha256Digest Digest(ReadOnlySpan<byte> bytes) =>
        Sha256Digest.Parse($"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}") is Result<Sha256Digest, ContractValidationError>.Success digest
            ? digest.Value
            : throw new InvalidOperationException();

    private static X509Certificate2 Certificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=node", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.Exportable);
    }

    private sealed class IdentityRegistry(NodeIdentityBinding identity) : INodeIdentityRegistry
    {
        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string certificateSerial,
            string certificateThumbprintSha256,
            CancellationToken cancellationToken) =>
            Task.FromResult<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>>(
                nodeUid == identity.NodeUid &&
                identityEpoch == identity.IdentityEpoch &&
                certificateSerial == identity.CertificateSerial &&
                certificateThumbprintSha256 == identity.CertificateThumbprintSha256
                    ? new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success(identity)
                    : new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure(new("not-found", "Not found.")));

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
            NodeIdentityBinding binding,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string reason,
            Guid correlationId,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class ReplayReceipts : ITransportReplayReceiptStore
    {
        public int Calls { get; private set; }

        public Task<Result<ReplayReceipt, ReplayReceiptStoreFailure>> RetrieveOrRecordAsync(
            ReplayReceipt receipt,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<Result<ReplayReceipt, ReplayReceiptStoreFailure>>(
                new Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success(receipt));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

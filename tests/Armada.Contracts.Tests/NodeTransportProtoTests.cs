using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Contracts.Tests;

public sealed class NodeTransportProtoTests
{
    [Fact]
    public void Enrollment_and_transport_messages_round_trip_with_the_v1alpha1_family()
    {
        var nodeId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var request = new Proto.EnrollmentRequest
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            ClaimId = "22222222-2222-2222-2222-222222222222",
            ClaimSecret = ByteString.CopyFrom(new byte[32]),
            NodeUid = nodeId.ToString("D"),
            IdentityEpoch = 1,
            DevicePublicKey = ByteString.CopyFrom([1, 2, 3]),
            PublicKeySha256 = ByteString.CopyFrom(new byte[32]),
            CertificateSigningRequest = ByteString.CopyFrom([4, 5, 6]),
            Inventory = new Proto.EnrollmentInventory(),
            RequestId = "33333333-3333-3333-3333-333333333333",
            SentAt = Timestamp.FromDateTime(DateTime.UtcNow)
        };
        request.Inventory.Facts.Add("os", "linux");
        request.Inventory.Capabilities.Add("container");

        var parsedRequest = Proto.EnrollmentRequest.Parser.ParseFrom(request.ToByteArray());
        var frame = new Proto.NodeToControl
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            NodeUid = nodeId.ToString("D"),
            IdentityEpoch = 1,
            StreamEpoch = 1,
            Sequence = 1,
            MessageId = "44444444-4444-4444-4444-444444444444",
            CorrelationId = "55555555-5555-5555-5555-555555555555",
            IdempotencyKey = "first-hello",
            SentAt = Timestamp.FromDateTime(DateTime.UtcNow),
            Hello = new Proto.Hello
            {
                SchemaVersion = NodeTransportProtocol.Version,
                AgentVersion = "0.1.0",
                PayloadType = NodeTransportProtocol.HelloPayloadType
            }
        };

        var parsedFrame = Proto.NodeToControl.Parser.ParseFrom(frame.ToByteArray());

        Assert.Equal(NodeTransportProtocol.Version, parsedRequest.ProtocolVersion);
        Assert.Equal("linux", parsedRequest.Inventory.Facts["os"]);
        Assert.Equal(Proto.NodeToControl.PayloadOneofCase.Hello, parsedFrame.PayloadCase);
        Assert.Equal("0.1.0", parsedFrame.Hello.AgentVersion);
    }

    [Fact]
    public void Transport_contract_does_not_define_workload_command_payloads()
    {
        var payloadNames = typeof(Proto.NodeToControl.PayloadOneofCase)
            .GetEnumNames();

        Assert.Equal(
            ["None", "Hello", "FullReconciliationSnapshot", "InventoryObservation", "HealthObservation", "TransportAck", "TransportRejection"],
            payloadNames);
    }

    [Fact]
    public void Replay_identity_has_an_unambiguous_canonical_form()
    {
        var digest = Assert.IsType<Result<Sha256Digest, ContractValidationError>.Success>(
            Sha256Digest.Parse($"sha256:{new string('a', 64)}")).Value;
        var identity = new ReplayIdentity(
            new NodeUid(Guid.Parse("11111111-1111-1111-1111-111111111111")),
            2,
            3,
            4,
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            "ack:1",
            NodeTransportProtocol.Version,
            TransportPayloadKind.TransportAck,
            new DateTimeOffset(2026, 8, 23, 0, 0, 0, TimeSpan.Zero),
            digest);

        Assert.Equal(
            "11111111-1111-1111-1111-111111111111|2|3|4|22222222-2222-2222-2222-222222222222|33333333-3333-3333-3333-333333333333|5:ack:1|30:armada.node.transport/v1alpha1|TransportAck|2026-08-23T00:00:00.0000000Z|sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            identity.CanonicalValue);
    }
}

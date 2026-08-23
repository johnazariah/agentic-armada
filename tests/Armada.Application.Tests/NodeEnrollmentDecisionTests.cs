using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Contracts;
using FsCheck.Xunit;
using Google.Protobuf;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Application.Tests;

public sealed class NodeEnrollmentDecisionTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 23, 0, 0, 0, TimeSpan.Zero);
    private static readonly ImmutableArray<byte> TestSpki = Decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW/eyDIYsHAMCgKIj7Cf2qME59W8bxyxazaVIACHp1eL/pEbdB6LH0T39Fyid3EWT6+pNnut9jO58/43SWprrew==");
    private static readonly ImmutableArray<byte> TestCsr = Decode("MIHPMHgCAQAwFjEUMBIGA1UEAxMLYXJtYWRhLW5vZGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARb97IMhiwcAwKAoiPsJ/aowTn1bxvHLFrNpUgAIenV4v+kRt0HosfRPf0XKJ3cRZPr6k2e632M7nz/jdJamut7oAAwCgYIKoZIzj0EAwIDRwAwRAIgbqNsfDkoEOqjxNfQb054CyVlMIB6Oqx/Lyllo1YOFn8CICNL5f9uO89te9rtM350HzN95gwOTf3NnR77GcvQ+BZi");
    private static readonly ImmutableArray<byte> TestCertificate = Decode("MIIBizCCATGgAwIBAgIIe7+oSfKz0akwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxMLYXJtYWRhLW5vZGUwHhcNMjYwODIzMDAwMDAwWhcNMjYwODI0MDAwMDAwWjAWMRQwEgYDVQQDEwthcm1hZGEtbm9kZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFv3sgyGLBwDAoCiI+wn9qjBOfVvG8csWs2lSAAh6dXi/6RG3Qeix9E9/RcondxFk+vqTZ7rfYzufP+N0lqa63ujaTBnMFAGA1UdEQRJMEeGRXNwaWZmZTovL2FybWFkYS5sYWIvbm9kZS8xMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEvZXBvY2gvMjATBgNVHSUEDDAKBggrBgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiEA1RqMqbwzMRshb2kAGwJNr78W8UQhq7VA39Cs2cOERAkCIFPCW4AQ/kMwtWx/CnTKNuTiMkBbYE7GShv9ZI87ePVn");
    private static readonly ImmutableArray<byte> NoEkuCertificate = Decode("MIIBdzCCAR2gAwIBAgIJALRIiApRY6Q+MAoGCCqGSM49BAMCMBYxFDASBgNVBAMTC2FybWFkYS1ub2RlMB4XDTI2MDgyMzAwMDAwMFoXDTI2MDgyNDAwMDAwMFowFjEUMBIGA1UEAxMLYXJtYWRhLW5vZGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARb97IMhiwcAwKAoiPsJ/aowTn1bxvHLFrNpUgAIenV4v+kRt0HosfRPf0XKJ3cRZPr6k2e632M7nz/jdJamut7o1QwUjBQBgNVHREESTBHhkVzcGlmZmU6Ly9hcm1hZGEubGFiL25vZGUvMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExL2Vwb2NoLzIwCgYIKoZIzj0EAwIDSAAwRQIgBWY3ASd7lVeyzT9cISwxfUl2/Yf4uCcfZhj/enUWxDsCIQDw0SpzslgXgcUbNAw4AfPaMwK8Y5zRbI5jXqZQ/AIqUA==");
    private static readonly ImmutableArray<byte> WrongSanCertificate = Decode("MIIBjDCCATGgAwIBAgIIbLygeP8GDeUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxMLYXJtYWRhLW5vZGUwHhcNMjYwODIzMDAwMDAwWhcNMjYwODI0MDAwMDAwWjAWMRQwEgYDVQQDEwthcm1hZGEtbm9kZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFv3sgyGLBwDAoCiI+wn9qjBOfVvG8csWs2lSAAh6dXi/6RG3Qeix9E9/RcondxFk+vqTZ7rfYzufP+N0lqa63ujaTBnMFAGA1UdEQRJMEeGRXNwaWZmZTovL2FybWFkYS5sYWIvbm9kZS8xMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEvZXBvY2gvMzATBgNVHSUEDDAKBggrBgEFBQcDAjAKBggqhkjOPQQDAgNJADBGAiEA2xYRX0KP6PGPIfN3za2t3tRXFNSsiFcDnlfNQguYsgwCIQCKKuAKroG3aTNHJzQEnxXk7CqWicAvNAcTHQeqgXsBBg==");

    [Fact]
    public void Valid_enrolment_is_accepted_without_retaining_the_claim_secret()
    {
        var request = Enrollment();

        var result = NodeEnrollmentDecisions.ValidateEnrollment(request, Now);
        var accepted = Assert.IsType<Result<ValidatedEnrollmentRequest, NodeTransportValidationError>.Success>(result).Value;

        Assert.Equal(request.IdentityEpoch, accepted.IdentityEpoch);
        Assert.Equal(request.DevicePublicKey, accepted.DevicePublicKey);
        Assert.DoesNotContain(
            typeof(ValidatedEnrollmentRequest).GetProperties(),
            property => property.Name.Contains("secret", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("unknown/version", "unsupported-protocol-version")]
    [InlineData("armada.node.transport/v1alpha1", "invalid-enrollment-identifier")]
    public void Enrolment_rejects_versions_and_identifiers(string version, string code)
    {
        var request = Enrollment() with
        {
            ProtocolVersion = version,
            ClaimId = version == NodeTransportProtocol.Version ? Guid.Empty.ToString("D") : Guid.NewGuid().ToString("D")
        };

        Assert.Equal(code, Failure(NodeEnrollmentDecisions.ValidateEnrollment(request, Now)).Code);
    }

    [Fact]
    public void Enrolment_rejects_epoch_secret_timestamp_inventory_and_attestation_bounds()
    {
        var request = Enrollment();

        Assert.Equal("invalid-identity-epoch", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with { IdentityEpoch = 0 }, Now)).Code);
        Assert.Equal("invalid-claim-secret", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with { ClaimSecret = [1] }, Now)).Code);
        Assert.Equal("invalid-enrollment-timestamp", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with { SentAt = Now.AddMinutes(6) }, Now)).Code);
        Assert.Equal("invalid-inventory", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with
        {
            Inventory = request.Inventory with { Capabilities = ["same", "same"] }
        }, Now)).Code);
        Assert.Equal("invalid-attestation", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with
        {
            Attestation = ImmutableArray.CreateRange(new byte[NodeTransportProtocol.MaximumAttestationBytes + 1])
        }, Now)).Code);
    }

    [Fact]
    public void Enrolment_rejects_malformed_or_mismatched_key_material_non_throwing()
    {
        var request = Enrollment();

        Assert.Equal("invalid-device-public-key", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with
        {
            DevicePublicKey = [1, 2, 3]
        }, Now)).Code);
        Assert.Equal("public-key-digest-mismatch", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with
        {
            PublicKeySha256 = ImmutableArray.CreateRange(new byte[32])
        }, Now)).Code);
        Assert.Equal("csr-public-key-mismatch", Failure(NodeEnrollmentDecisions.ValidateEnrollment(request with
        {
            CertificateSigningRequest = ImmutableArray.CreateRange(request.CertificateSigningRequest.Take(request.CertificateSigningRequest.Length - 1).Append((byte)(request.CertificateSigningRequest[^1] ^ 1)))
        }, Now)).Code);
    }

    [Fact]
    public void Transport_envelope_derives_the_payload_kind_schema_and_canonical_bytes_from_the_parsed_oneof()
    {
        var envelope = Envelope();

        Assert.True(Validate(envelope).IsSuccess);
        var accepted = Success(Validate(envelope));

        Assert.Equal(TransportPayloadKind.Hello, accepted.Payload.Kind);
        Assert.Equal(NodeTransportProtocol.Version, accepted.Payload.SchemaVersion);
        Assert.Equal(envelope.Hello.ToByteArray(), accepted.Payload.CanonicalPayload);
    }

    [Fact]
    public void Transport_envelope_rejects_bad_versions_ids_bounds_schemas_and_absent_payloads()
    {
        var wrongVersion = Envelope();
        wrongVersion.ProtocolVersion = "future";
        var wrongNode = Envelope();
        wrongNode.NodeUid = Guid.Empty.ToString("D");
        var staleSequence = Envelope();
        staleSequence.Sequence = 0;
        var wrongKey = Envelope();
        wrongKey.IdempotencyKey = " not-canonical";
        var wrongSchema = Envelope();
        wrongSchema.Hello.SchemaVersion = "future";
        var noPayload = Envelope();
        noPayload.ClearPayload();
        var invalidTimestamp = Envelope();
        invalidTimestamp.SentAt = new Google.Protobuf.WellKnownTypes.Timestamp { Seconds = long.MaxValue };

        Assert.Equal("unsupported-protocol-version", Failure(Validate(wrongVersion)).Code);
        Assert.Equal("invalid-transport-identifier", Failure(Validate(wrongNode)).Code);
        Assert.Equal("invalid-transport-epoch-or-sequence", Failure(Validate(staleSequence)).Code);
        Assert.Equal("invalid-transport-envelope", Failure(Validate(wrongKey)).Code);
        Assert.Equal("unsupported-protocol-version", Failure(Validate(wrongSchema)).Code);
        Assert.Equal("invalid-transport-payload", Failure(Validate(noPayload)).Code);
        Assert.Equal("invalid-transport-envelope", Failure(Validate(invalidTimestamp)).Code);
    }

    [Fact]
    public void Transport_envelope_rejects_malformed_payload_bytes_and_a_hello_oneof_with_health_message_bytes()
    {
        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope([1, 2, 3], Now)).Code);

        var health = new Proto.HealthObservation
        {
            SchemaVersion = NodeTransportProtocol.Version,
            StorageAvailable = true,
            PayloadType = NodeTransportProtocol.HealthObservationPayloadType
        };
        var mismatched = EncodeFrameWithPayloadField(EnvelopeWithoutPayload(), 20, health.ToByteArray());
        var unknownPayload = EncodeFrameWithPayloadField(EnvelopeWithoutPayload(), 30, [1]);
        var unknownTimestampHeader = EnvelopeWithoutPayload();
        unknownTimestampHeader.SentAt = null;
        var unknownTimestamp = EncodeFrameWithFields(
            unknownTimestampHeader,
            (9, [8, 0, 24, 1]),
            (20, Envelope().Hello.ToByteArray()));
        var subTickTimestampHeader = EnvelopeWithoutPayload();
        subTickTimestampHeader.SentAt = null;
        var subTickNanosOne = EncodeFrameWithFields(
            subTickTimestampHeader,
            (9, new Google.Protobuf.WellKnownTypes.Timestamp
            {
                Seconds = Now.ToUnixTimeSeconds(),
                Nanos = 1
            }.ToByteArray()),
            (20, Envelope().Hello.ToByteArray()));
        var subTickNanosNinetyNine = EncodeFrameWithFields(
            subTickTimestampHeader,
            (9, new Google.Protobuf.WellKnownTypes.Timestamp
            {
                Seconds = Now.ToUnixTimeSeconds(),
                Nanos = 99
            }.ToByteArray()),
            (20, Envelope().Hello.ToByteArray()));
        var duplicateInventoryFacts = EncodeFrameWithPayloadField(
            EnvelopeWithoutPayload(),
            22,
            EncodeInventoryObservationWithDuplicateFacts());

        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope(mismatched, Now)).Code);
        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope(unknownPayload, Now)).Code);
        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope(unknownTimestamp, Now)).Code);
        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope(subTickNanosOne, Now)).Code);
        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope(subTickNanosNinetyNine, Now)).Code);
        Assert.Equal(
            "invalid-transport-payload",
            Failure(NodeEnrollmentDecisions.ValidateTransportEnvelope(duplicateInventoryFacts, Now)).Code);
    }

    [Fact]
    public void Transport_envelope_validates_each_enabled_typed_payload_before_canonicalising_it()
    {
        var fullSnapshot = Envelope();
        fullSnapshot.FullReconciliationSnapshot = new Proto.FullReconciliationSnapshot
        {
            SchemaVersion = NodeTransportProtocol.Version,
            Snapshot = ByteString.CopyFrom([1]),
            PayloadType = NodeTransportProtocol.FullReconciliationSnapshotPayloadType
        };
        var inventory = Envelope();
        inventory.InventoryObservation = new Proto.InventoryObservation
        {
            SchemaVersion = NodeTransportProtocol.Version,
            Inventory = new Proto.EnrollmentInventory(),
            PayloadType = NodeTransportProtocol.InventoryObservationPayloadType
        };
        inventory.InventoryObservation.Inventory.Facts.Add("os", "linux");
        inventory.InventoryObservation.Inventory.Capabilities.Add("container");
        var health = Envelope();
        health.HealthObservation = new Proto.HealthObservation
        {
            SchemaVersion = NodeTransportProtocol.Version,
            StorageAvailable = true,
            PayloadType = NodeTransportProtocol.HealthObservationPayloadType
        };
        var acknowledgement = Envelope();
        acknowledgement.TransportAck = new Proto.TransportAck
        {
            SchemaVersion = NodeTransportProtocol.Version,
            AcknowledgedMessageId = "44444444-4444-4444-4444-444444444444",
            Code = "accepted",
            PayloadType = NodeTransportProtocol.TransportAcknowledgementPayloadType
        };
        var rejection = Envelope();
        rejection.TransportRejection = new Proto.TransportRejection
        {
            SchemaVersion = NodeTransportProtocol.Version,
            Code = Proto.TransportRejectionCode.ReplayConflict,
            Message = "Replay conflict.",
            PayloadType = NodeTransportProtocol.TransportRejectionPayloadType
        };

        Assert.Equal(TransportPayloadKind.FullReconciliationSnapshot, Success(Validate(fullSnapshot)).Payload.Kind);
        Assert.Equal(TransportPayloadKind.InventoryObservation, Success(Validate(inventory)).Payload.Kind);
        Assert.Equal(TransportPayloadKind.HealthObservation, Success(Validate(health)).Payload.Kind);
        Assert.Equal(TransportPayloadKind.TransportAck, Success(Validate(acknowledgement)).Payload.Kind);
        Assert.Equal(TransportPayloadKind.TransportRejection, Success(Validate(rejection)).Payload.Kind);
        Assert.True(NodeEnrollmentDecisions.ValidateTransportEnvelope(health.ToByteArray(), Now).IsSuccess);
    }

    [Fact]
    public void Transport_envelope_rejects_empty_or_invalid_enabled_typed_payloads()
    {
        var emptyHello = Envelope();
        emptyHello.Hello.AgentVersion = string.Empty;
        var emptySnapshot = Envelope();
        emptySnapshot.FullReconciliationSnapshot = new Proto.FullReconciliationSnapshot
        {
            SchemaVersion = NodeTransportProtocol.Version,
            PayloadType = NodeTransportProtocol.FullReconciliationSnapshotPayloadType
        };
        var invalidInventory = Envelope();
        invalidInventory.InventoryObservation = new Proto.InventoryObservation
        {
            SchemaVersion = NodeTransportProtocol.Version,
            Inventory = new Proto.EnrollmentInventory(),
            PayloadType = NodeTransportProtocol.InventoryObservationPayloadType
        };
        invalidInventory.InventoryObservation.Inventory.Capabilities.Add("duplicate");
        invalidInventory.InventoryObservation.Inventory.Capabilities.Add("duplicate");
        var missingInventory = Envelope();
        missingInventory.InventoryObservation = new Proto.InventoryObservation
        {
            SchemaVersion = NodeTransportProtocol.Version,
            PayloadType = NodeTransportProtocol.InventoryObservationPayloadType
        };
        var invalidAcknowledgement = Envelope();
        invalidAcknowledgement.TransportAck = new Proto.TransportAck
        {
            SchemaVersion = NodeTransportProtocol.Version,
            AcknowledgedMessageId = Guid.Empty.ToString("D"),
            Code = "accepted",
            PayloadType = NodeTransportProtocol.TransportAcknowledgementPayloadType
        };
        var invalidRejection = Envelope();
        invalidRejection.TransportRejection = new Proto.TransportRejection
        {
            SchemaVersion = NodeTransportProtocol.Version,
            Code = Proto.TransportRejectionCode.Unspecified,
            Message = "Missing code.",
            PayloadType = NodeTransportProtocol.TransportRejectionPayloadType
        };

        Assert.Equal("invalid-transport-payload", Failure(Validate(emptyHello)).Code);
        Assert.Equal("invalid-transport-payload", Failure(Validate(emptySnapshot)).Code);
        Assert.Equal("invalid-inventory", Failure(Validate(invalidInventory)).Code);
        Assert.Equal("invalid-transport-payload", Failure(Validate(missingInventory)).Code);
        Assert.Equal("invalid-transport-payload", Failure(Validate(invalidAcknowledgement)).Code);
        Assert.Equal("invalid-transport-payload", Failure(Validate(invalidRejection)).Code);
    }

    [Property(MaxTest = 50)]
    public void Equivalent_envelopes_have_one_replay_identity_and_a_changed_binding_does_not(int sequence)
    {
        var safeSequence = Math.Abs((long)sequence) + 1;
        var envelope = Envelope(safeSequence);
        var equivalent = envelope.Clone();
        var changed = envelope.Clone();
        changed.Sequence = safeSequence + 1;

        var first = Success(Validate(envelope));
        var second = Success(Validate(equivalent));
        var third = Success(Validate(changed));
        var changedNode = envelope.Clone();
        changedNode.NodeUid = "66666666-6666-6666-6666-666666666666";
        var changedIdentityEpoch = envelope.Clone();
        changedIdentityEpoch.IdentityEpoch = 3;
        var changedStreamEpoch = envelope.Clone();
        changedStreamEpoch.StreamEpoch = 2;
        var changedMessage = envelope.Clone();
        changedMessage.MessageId = "77777777-7777-7777-7777-777777777777";
        var changedCorrelation = envelope.Clone();
        changedCorrelation.CorrelationId = "88888888-8888-8888-8888-888888888888";
        var changedIdempotency = envelope.Clone();
        changedIdempotency.IdempotencyKey = "hello-2";
        var changedSentAt = envelope.Clone();
        changedSentAt.SentAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(Now.AddSeconds(1).UtcDateTime);
        var changedPayload = envelope.Clone();
        changedPayload.Hello.AgentVersion = "0.2.0";
        var changedBindings = new[]
        {
            changedNode,
            changedIdentityEpoch,
            changedStreamEpoch,
            changed,
            changedMessage,
            changedCorrelation,
            changedIdempotency,
            changedSentAt,
            changedPayload
        };

        Assert.Equal(first.ReplayIdentity.CanonicalValue, second.ReplayIdentity.CanonicalValue);
        Assert.NotEqual(first.ReplayIdentity.CanonicalValue, third.ReplayIdentity.CanonicalValue);
        Assert.All(
            changedBindings,
            candidate => Assert.NotEqual(
                first.ReplayIdentity.CanonicalValue,
                Success(Validate(candidate)).ReplayIdentity.CanonicalValue));
        var unsupportedVersion = envelope.Clone();
        unsupportedVersion.ProtocolVersion = "future";
        Assert.False(Validate(unsupportedVersion).IsSuccess);
    }

    [Fact]
    public void Certificate_binding_requires_exact_spiffe_san_eku_times_serial_and_thumbprint()
    {
        var nodeUid = Guid.Parse("11111111-1111-1111-1111-111111111111");
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificate.AsSpan());
        var binding = Binding(certificate, nodeUid, 2);

        Assert.True(NodeEnrollmentDecisions.ValidateCertificateBinding(binding, Now).IsSuccess);
        Assert.Equal("certificate-binding-mismatch", Failure(NodeEnrollmentDecisions.ValidateCertificateBinding(binding with { CertificateSerial = "00" }, Now)).Code);
        Assert.Equal("invalid-certificate-binding", Failure(NodeEnrollmentDecisions.ValidateCertificateBinding(binding with { ExpiresAt = Now }, Now)).Code);
        Assert.Equal("certificate-public-key-mismatch", Failure(NodeEnrollmentDecisions.ValidateCertificateBinding(binding with { ExpectedPublicKeySha256 = ImmutableArray.CreateRange(new byte[32]) }, Now)).Code);
        Assert.Equal("invalid-certificate-der", Failure(NodeEnrollmentDecisions.ValidateCertificateBinding(binding with { LeafCertificateDer = [1, 2] }, Now)).Code);

        using var noEku = X509CertificateLoader.LoadCertificate(NoEkuCertificate.AsSpan());
        Assert.Equal("certificate-binding-mismatch", Failure(NodeEnrollmentDecisions.ValidateCertificateBinding(Binding(noEku, nodeUid, 2), Now)).Code);

        using var wrongSan = X509CertificateLoader.LoadCertificate(WrongSanCertificate.AsSpan());
        Assert.Equal("certificate-binding-mismatch", Failure(NodeEnrollmentDecisions.ValidateCertificateBinding(Binding(wrongSan, nodeUid, 2), Now)).Code);
    }

    private static EnrollmentRequestDto Enrollment()
    {
        return new(
            NodeTransportProtocol.Version,
            "22222222-2222-2222-2222-222222222222",
            ImmutableArray.CreateRange(Enumerable.Repeat((byte)7, 32)),
            "11111111-1111-1111-1111-111111111111",
            2,
            TestSpki,
            ImmutableArray.CreateRange(SHA256.HashData(TestSpki.AsSpan())),
            TestCsr,
            new EnrollmentInventory(ImmutableDictionary<string, string>.Empty.Add("os", "linux"), ["container"]),
            null,
            "33333333-3333-3333-3333-333333333333",
            Now);
    }

    private static Proto.NodeToControl Envelope(long sequence = 1) =>
        new()
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            NodeUid = "11111111-1111-1111-1111-111111111111",
            IdentityEpoch = 2,
            StreamEpoch = 1,
            Sequence = sequence,
            MessageId = "44444444-4444-4444-4444-444444444444",
            CorrelationId = "55555555-5555-5555-5555-555555555555",
            IdempotencyKey = "hello-1",
            SentAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(Now.UtcDateTime),
            Hello = new Proto.Hello
            {
                SchemaVersion = NodeTransportProtocol.Version,
                AgentVersion = "0.1.0",
                PayloadType = NodeTransportProtocol.HelloPayloadType
            }
        };

    private static Proto.NodeToControl EnvelopeWithoutPayload()
    {
        var frame = Envelope();
        frame.ClearPayload();
        return frame;
    }

    private static byte[] EncodeFrameWithPayloadField(
        Proto.NodeToControl header,
        int payloadFieldNumber,
        byte[] payload)
        => EncodeFrameWithFields(header, (payloadFieldNumber, payload));

    private static byte[] EncodeFrameWithFields(
        Proto.NodeToControl header,
        params (int FieldNumber, byte[] Value)[] fields)
    {
        using var stream = new MemoryStream();
        stream.Write(header.ToByteArray());
        using var output = new CodedOutputStream(stream, leaveOpen: true);
        foreach (var (fieldNumber, value) in fields)
        {
            output.WriteTag(fieldNumber, WireFormat.WireType.LengthDelimited);
            output.WriteBytes(ByteString.CopyFrom(value));
        }

        output.Flush();
        return stream.ToArray();
    }

    private static byte[] EncodeInventoryObservationWithDuplicateFacts()
    {
        var firstFact = EncodeMessage(output =>
        {
            WriteStringField(output, 1, "os");
            WriteStringField(output, 2, "linux");
        });
        var secondFact = EncodeMessage(output =>
        {
            WriteStringField(output, 1, "os");
            WriteStringField(output, 2, "windows");
        });
        var inventory = EncodeMessage(output =>
        {
            WriteBytesField(output, 1, firstFact);
            WriteBytesField(output, 1, secondFact);
        });

        return EncodeMessage(output =>
        {
            WriteStringField(output, 1, NodeTransportProtocol.Version);
            WriteBytesField(output, 2, inventory);
            WriteStringField(output, 3, NodeTransportProtocol.InventoryObservationPayloadType);
        });
    }

    private static byte[] EncodeMessage(Action<CodedOutputStream> write)
    {
        using var stream = new MemoryStream();
        using var output = new CodedOutputStream(stream, leaveOpen: true);
        write(output);
        output.Flush();
        return stream.ToArray();
    }

    private static void WriteStringField(CodedOutputStream output, int fieldNumber, string value)
    {
        output.WriteTag(fieldNumber, WireFormat.WireType.LengthDelimited);
        output.WriteString(value);
    }

    private static void WriteBytesField(CodedOutputStream output, int fieldNumber, byte[] value)
    {
        output.WriteTag(fieldNumber, WireFormat.WireType.LengthDelimited);
        output.WriteBytes(ByteString.CopyFrom(value));
    }

    private static Result<ValidatedTransportEnvelope, NodeTransportValidationError> Validate(
        Proto.NodeToControl envelope) =>
        NodeEnrollmentDecisions.ValidateTransportEnvelope(envelope.ToByteArray(), Now);

    private static CertificateBindingDto Binding(X509Certificate2 certificate, Guid nodeUid, long epoch) =>
        new(
            nodeUid.ToString("D"),
            epoch,
            ImmutableArray.CreateRange(SHA256.HashData(TestSpki.AsSpan())),
            ImmutableArray.CreateRange(certificate.Export(X509ContentType.Cert)),
            certificate.SerialNumber,
            Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            new DateTimeOffset(certificate.NotAfter.ToUniversalTime()));

    private static ImmutableArray<byte> Decode(string value) =>
        ImmutableArray.CreateRange(Convert.FromBase64String(value));

    private static NodeTransportValidationError Failure<T>(Result<T, NodeTransportValidationError> result) =>
        Assert.IsType<Result<T, NodeTransportValidationError>.Failure>(result).Error;

    private static T Success<T>(Result<T, NodeTransportValidationError> result) =>
        Assert.IsType<Result<T, NodeTransportValidationError>.Success>(result).Value;
}

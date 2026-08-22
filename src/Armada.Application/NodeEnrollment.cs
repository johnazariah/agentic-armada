using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Contracts;
using Google.Protobuf;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Application;

public static class NodeEnrollmentDecisions
{
    private static readonly Oid ClientAuthenticationOid = new("1.3.6.1.5.5.7.3.2");

    public static Result<ValidatedEnrollmentRequest, NodeTransportValidationError> ValidateEnrollment(
        EnrollmentRequestDto request,
        DateTimeOffset now)
    {
        if (request is null)
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-enrollment-request", "An enrolment request is required.");
        }

        if (request.ProtocolVersion != NodeTransportProtocol.Version)
        {
            return Failure<ValidatedEnrollmentRequest>("unsupported-protocol-version", "The enrolment protocol version is not supported.");
        }

        if (!TryNonEmptyGuid(request.ClaimId, out var claimId) ||
            !TryNonEmptyGuid(request.NodeUid, out var nodeUid) ||
            !TryNonEmptyGuid(request.RequestId, out var requestId))
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-enrollment-identifier", "Claim, node, and request IDs must be non-empty canonical UUIDs.");
        }

        if (request.IdentityEpoch <= 0)
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-identity-epoch", "The identity epoch must be positive.");
        }

        if (request.ClaimSecret.IsDefaultOrEmpty ||
            request.ClaimSecret.Length is < NodeTransportProtocol.MinimumClaimSecretBytes or > NodeTransportProtocol.MaximumClaimSecretBytes)
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-claim-secret", "The claim secret must contain between 256 and 1024 bits.");
        }

        if (!IsUtcWithin(request.SentAt, now, TimeSpan.FromMinutes(5)))
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-enrollment-timestamp", "The enrolment timestamp must be UTC and within five minutes of validation.");
        }

        var inventory = ValidateInventory(request.Inventory);
        if (inventory is Result<bool, NodeTransportValidationError>.Failure inventoryFailure)
        {
            return Failure<ValidatedEnrollmentRequest>(inventoryFailure.Error.Code, inventoryFailure.Error.Message);
        }

        if (request.Attestation is { } attestation &&
            (attestation.IsDefaultOrEmpty || attestation.Length > NodeTransportProtocol.MaximumAttestationBytes))
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-attestation", "Attestation must be non-empty and within the transport limit.");
        }

        if (request.DevicePublicKey.IsDefaultOrEmpty || request.DevicePublicKey.Length > NodeTransportProtocol.MaximumPublicKeyBytes ||
            request.PublicKeySha256.Length != 32 ||
            request.CertificateSigningRequest.IsDefaultOrEmpty || request.CertificateSigningRequest.Length > NodeTransportProtocol.MaximumCsrBytes)
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-enrollment-key-material", "The public key, digest, and CSR must be bounded and complete.");
        }

        if (!IsP256Spki(request.DevicePublicKey.AsSpan()))
        {
            return Failure<ValidatedEnrollmentRequest>("invalid-device-public-key", "The device public key must be a canonical DER ECDSA P-256 SPKI.");
        }

        var calculatedDigest = SHA256.HashData(request.DevicePublicKey.AsSpan());
        if (!CryptographicOperations.FixedTimeEquals(calculatedDigest, request.PublicKeySha256.AsSpan()))
        {
            return Failure<ValidatedEnrollmentRequest>("public-key-digest-mismatch", "The public key digest does not bind the supplied SPKI.");
        }

        if (!CsrBindsToPublicKey(request.CertificateSigningRequest.AsSpan(), request.DevicePublicKey.AsSpan()))
        {
            return Failure<ValidatedEnrollmentRequest>("csr-public-key-mismatch", "The CSR signature or subject public key does not bind the supplied SPKI.");
        }

        var digest = ParseDigest(calculatedDigest);
        return new Result<ValidatedEnrollmentRequest, NodeTransportValidationError>.Success(
            new(
                claimId,
                new NodeUid(nodeUid),
                request.IdentityEpoch,
                request.DevicePublicKey,
                digest,
                request.CertificateSigningRequest,
                request.Inventory,
                request.Attestation,
                requestId,
                request.SentAt));
    }

    public static Result<ValidatedTransportEnvelope, NodeTransportValidationError> ValidateTransportEnvelope(
        ReadOnlySpan<byte> encodedEnvelope,
        DateTimeOffset now)
    {
        if (encodedEnvelope.IsEmpty || encodedEnvelope.Length > NodeTransportProtocol.MaximumTransportEnvelopeBytes)
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-envelope", "The encoded transport envelope is empty or exceeds its limit.");
        }

        if (!TryReadStrictEnvelope(encodedEnvelope, out var strictEnvelope))
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-payload", "The transport envelope contains malformed, duplicate, or unknown fields.");
        }

        try
        {
            return ValidateTransportEnvelope(
                Proto.NodeToControl.Parser.ParseFrom(encodedEnvelope.ToArray()),
                strictEnvelope,
                now);
        }
        catch (InvalidProtocolBufferException)
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-payload", "The transport envelope is not valid protobuf.");
        }
    }

    private static Result<ValidatedTransportEnvelope, NodeTransportValidationError> ValidateTransportEnvelope(
        Proto.NodeToControl envelope,
        StrictEnvelope strictEnvelope,
        DateTimeOffset now)
    {
        if (envelope is null)
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-envelope", "A complete transport envelope is required.");
        }

        if (envelope.ProtocolVersion != NodeTransportProtocol.Version)
        {
            return Failure<ValidatedTransportEnvelope>("unsupported-protocol-version", "The transport protocol version is not supported.");
        }

        if (!TryNonEmptyGuid(envelope.NodeUid, out var nodeUid) ||
            !TryNonEmptyGuid(envelope.MessageId, out var messageId) ||
            !TryNonEmptyGuid(envelope.CorrelationId, out var correlationId))
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-identifier", "Node, message, and correlation IDs must be non-empty canonical UUIDs.");
        }

        if (envelope.IdentityEpoch <= 0 || envelope.StreamEpoch <= 0 || envelope.Sequence <= 0)
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-epoch-or-sequence", "Identity epoch, stream epoch, and sequence must be positive.");
        }

        if (!IsCanonicalIdempotencyKey(envelope.IdempotencyKey) ||
            envelope.SentAt is null ||
            !TryGetUtcTimestamp(envelope.SentAt, out var sentAt) ||
            !IsUtcWithin(sentAt, now, TimeSpan.FromMinutes(5)))
        {
            return Failure<ValidatedTransportEnvelope>("invalid-transport-envelope", "The idempotency key or timestamp is invalid.");
        }

        var payload = ValidatePayload(envelope, strictEnvelope);
        if (payload is Result<ValidatedTransportPayload, NodeTransportValidationError>.Failure payloadFailure)
        {
            return Failure<ValidatedTransportEnvelope>(payloadFailure.Error.Code, payloadFailure.Error.Message);
        }

        var acceptedPayload = ((Result<ValidatedTransportPayload, NodeTransportValidationError>.Success)payload).Value;
        var digest = ParseDigest(SHA256.HashData(acceptedPayload.CanonicalPayload.AsSpan()));
        var identity = new ReplayIdentity(
            new NodeUid(nodeUid),
            envelope.IdentityEpoch,
            envelope.StreamEpoch,
            envelope.Sequence,
            messageId,
            correlationId,
            envelope.IdempotencyKey,
            envelope.ProtocolVersion,
            acceptedPayload.Kind,
            sentAt,
            digest);

        return new Result<ValidatedTransportEnvelope, NodeTransportValidationError>.Success(
            new(identity, acceptedPayload, sentAt));
    }

    public static Result<CertificateBindingDto, NodeTransportValidationError> ValidateCertificateBinding(
        CertificateBindingDto binding,
        DateTimeOffset now)
    {
        if (binding is null ||
            !TryNonEmptyGuid(binding.NodeUid, out var nodeUid) ||
            binding.IdentityEpoch <= 0 ||
            binding.ExpectedPublicKeySha256.Length != 32 ||
            binding.LeafCertificateDer.IsDefaultOrEmpty ||
            !IsCanonicalHex(binding.CertificateSerial) ||
            !IsCanonicalHex(binding.CertificateThumbprintSha256, 64) ||
            binding.NotBefore.Offset != TimeSpan.Zero ||
            binding.ExpiresAt.Offset != TimeSpan.Zero ||
            binding.NotBefore > now ||
            binding.ExpiresAt <= now ||
            binding.ExpiresAt <= binding.NotBefore ||
            binding.ExpiresAt > binding.NotBefore.AddDays(31))
        {
            return Failure<CertificateBindingDto>("invalid-certificate-binding", "Certificate binding fields, UTC validity bounds, serial, or thumbprint are invalid.");
        }

        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(binding.LeafCertificateDer.AsSpan());
            var actualDigest = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());
            if (!CryptographicOperations.FixedTimeEquals(actualDigest, binding.ExpectedPublicKeySha256.AsSpan()))
            {
                return Failure<CertificateBindingDto>("certificate-public-key-mismatch", "The certificate public key does not bind the enrolled device key.");
            }

            if (!IsP256Spki(certificate.PublicKey.ExportSubjectPublicKeyInfo()) ||
                !string.Equals(certificate.SerialNumber, binding.CertificateSerial, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)), binding.CertificateThumbprintSha256, StringComparison.OrdinalIgnoreCase) ||
                certificate.NotBefore.ToUniversalTime() != binding.NotBefore.UtcDateTime ||
                certificate.NotAfter.ToUniversalTime() != binding.ExpiresAt.UtcDateTime ||
                !HasClientAuthenticationEku(certificate) ||
                !HasExactNodeSan(certificate, new NodeUid(nodeUid), binding.IdentityEpoch))
            {
                return Failure<CertificateBindingDto>("certificate-binding-mismatch", "The certificate does not exactly bind the expected identity, validity, EKU, or SAN.");
            }
        }
        catch (CryptographicException)
        {
            return Failure<CertificateBindingDto>("invalid-certificate-der", "The leaf certificate must be valid DER.");
        }
        catch (AsnContentException)
        {
            return Failure<CertificateBindingDto>("invalid-certificate-san", "The certificate SAN extension is malformed.");
        }

        return new Result<CertificateBindingDto, NodeTransportValidationError>.Success(binding);
    }

    private static Result<bool, NodeTransportValidationError> ValidateInventory(EnrollmentInventory inventory)
    {
        if (inventory is null ||
            inventory.Facts is null ||
            inventory.Capabilities.IsDefault ||
            inventory.Facts.Count > NodeTransportProtocol.MaximumInventoryFacts ||
            inventory.Capabilities.Length > NodeTransportProtocol.MaximumInventoryCapabilities)
        {
            return Failure<bool>("invalid-inventory", "Inventory exceeds the bounded transport shape.");
        }

        if (inventory.Facts.Any(static fact =>
                string.IsNullOrWhiteSpace(fact.Key) ||
                string.IsNullOrWhiteSpace(fact.Value) ||
                !string.Equals(fact.Key, fact.Key.Trim(), StringComparison.Ordinal) ||
                fact.Key.Length > NodeTransportProtocol.MaximumInventoryValueBytes ||
                fact.Value.Length > NodeTransportProtocol.MaximumInventoryValueBytes) ||
            inventory.Capabilities.Any(static capability =>
                string.IsNullOrWhiteSpace(capability) ||
                !string.Equals(capability, capability.Trim(), StringComparison.Ordinal) ||
                capability.Length > NodeTransportProtocol.MaximumInventoryValueBytes) ||
            inventory.Capabilities.Distinct(StringComparer.Ordinal).Count() != inventory.Capabilities.Length)
        {
            return Failure<bool>("invalid-inventory", "Inventory contains an empty, oversized, duplicate, or noncanonical value.");
        }

        return new Result<bool, NodeTransportValidationError>.Success(true);
    }

    private sealed record StrictEnvelope(int PayloadField, byte[] Payload);

    private static bool TryReadStrictEnvelope(ReadOnlySpan<byte> encoded, out StrictEnvelope envelope)
    {
        var seenFields = new HashSet<uint>();
        var payloadField = 0;
        byte[]? payload = null;
        try
        {
            var input = new CodedInputStream(encoded.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!seenFields.Add(tag))
                {
                    envelope = default!;
                    return false;
                }

                switch (tag)
                {
                    case 10:
                    case 18:
                    case 50:
                    case 58:
                    case 66:
                        input.ReadString();
                        break;
                    case 74:
                        if (!IsStrictTimestamp(input.ReadBytes().Span))
                        {
                            envelope = default!;
                            return false;
                        }

                        break;
                    case 24:
                    case 32:
                    case 40:
                        input.ReadInt64();
                        break;
                    case 162:
                    case 170:
                    case 178:
                    case 186:
                    case 194:
                    case 202:
                        if (payloadField != 0)
                        {
                            envelope = default!;
                            return false;
                        }

                        payloadField = (int)(tag >> 3);
                        payload = input.ReadBytes().ToByteArray();
                        break;
                    default:
                        envelope = default!;
                        return false;
                }
            }
        }
        catch (InvalidProtocolBufferException)
        {
            envelope = default!;
            return false;
        }

        if (payloadField == 0 || payload is not { Length: > 0 })
        {
            envelope = default!;
            return false;
        }

        envelope = new(payloadField, payload);
        return true;
    }

    private static bool HasOnlyKnownFields(ReadOnlySpan<byte> encoded, params uint[] allowedTags)
    {
        var seenFields = new HashSet<uint>();
        try
        {
            var input = new CodedInputStream(encoded.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!allowedTags.Contains(tag) || !seenFields.Add(tag))
                {
                    return false;
                }

                switch ((WireFormat.WireType)(tag & 7))
                {
                    case WireFormat.WireType.LengthDelimited:
                        input.ReadBytes();
                        break;
                    case WireFormat.WireType.Varint:
                        input.ReadUInt64();
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

    private static bool IsStrictInventoryObservation(ReadOnlySpan<byte> encoded)
    {
        var seenFields = new HashSet<uint>();
        try
        {
            var input = new CodedInputStream(encoded.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!seenFields.Add(tag))
                {
                    return false;
                }

                switch (tag)
                {
                    case 10:
                    case 26:
                        input.ReadString();
                        break;
                    case 18:
                        if (!IsStrictInventory(input.ReadBytes().Span))
                        {
                            return false;
                        }

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

    private static bool IsStrictInventory(ReadOnlySpan<byte> encoded)
    {
        var factKeys = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var input = new CodedInputStream(encoded.ToArray());
            while (!input.IsAtEnd)
            {
                switch (input.ReadTag())
                {
                    case 10:
                        if (!TryReadStrictInventoryFact(input.ReadBytes().Span, out var key) ||
                            !factKeys.Add(key))
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

    private static bool TryReadStrictInventoryFact(ReadOnlySpan<byte> encoded, out string key)
    {
        var seenFields = new HashSet<uint>();
        string? parsedKey = null;
        try
        {
            var input = new CodedInputStream(encoded.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!seenFields.Add(tag))
                {
                    key = string.Empty;
                    return false;
                }

                switch (tag)
                {
                    case 10:
                        parsedKey = input.ReadString();
                        break;
                    case 18:
                        input.ReadString();
                        break;
                    default:
                        key = string.Empty;
                        return false;
                }
            }
        }
        catch (InvalidProtocolBufferException)
        {
            key = string.Empty;
            return false;
        }

        key = parsedKey ?? string.Empty;
        return parsedKey is not null;
    }

    private static bool IsStrictTimestamp(ReadOnlySpan<byte> encoded)
    {
        var seenFields = new HashSet<uint>();
        var nanos = 0;
        try
        {
            var input = new CodedInputStream(encoded.ToArray());
            while (!input.IsAtEnd)
            {
                var tag = input.ReadTag();
                if (!seenFields.Add(tag))
                {
                    return false;
                }

                switch (tag)
                {
                    case 8:
                        input.ReadInt64();
                        break;
                    case 16:
                        nanos = input.ReadInt32();
                        break;
                    default:
                        return false;
                }
            }

            return nanos % 100 == 0;
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }
    }

    private static Result<ValidatedTransportPayload, NodeTransportValidationError> ValidatePayload(
        Proto.NodeToControl envelope,
        StrictEnvelope strictEnvelope) =>
        envelope.PayloadCase switch
        {
            Proto.NodeToControl.PayloadOneofCase.Hello =>
                CreateValidatedPayload(
                    TransportPayloadKind.Hello,
                    envelope.Hello.SchemaVersion,
                    envelope.Hello.PayloadType,
                    NodeTransportProtocol.HelloPayloadType,
                    envelope.Hello,
                    HasOnlyKnownFields(strictEnvelope.Payload, 10, 18, 26),
                    !string.IsNullOrWhiteSpace(envelope.Hello.AgentVersion),
                    "A hello payload requires an agent version."),
            Proto.NodeToControl.PayloadOneofCase.FullReconciliationSnapshot =>
                CreateValidatedPayload(
                    TransportPayloadKind.FullReconciliationSnapshot,
                    envelope.FullReconciliationSnapshot.SchemaVersion,
                    envelope.FullReconciliationSnapshot.PayloadType,
                    NodeTransportProtocol.FullReconciliationSnapshotPayloadType,
                    envelope.FullReconciliationSnapshot,
                    HasOnlyKnownFields(strictEnvelope.Payload, 10, 18, 26),
                    envelope.FullReconciliationSnapshot.Snapshot.Length > 0,
                    "A reconciliation snapshot payload requires snapshot bytes."),
            Proto.NodeToControl.PayloadOneofCase.InventoryObservation =>
                ValidateInventoryPayload(envelope.InventoryObservation, strictEnvelope.Payload),
            Proto.NodeToControl.PayloadOneofCase.HealthObservation =>
                CreateValidatedPayload(
                    TransportPayloadKind.HealthObservation,
                    envelope.HealthObservation.SchemaVersion,
                    envelope.HealthObservation.PayloadType,
                    NodeTransportProtocol.HealthObservationPayloadType,
                    envelope.HealthObservation,
                    HasOnlyKnownFields(strictEnvelope.Payload, 10, 16, 26),
                    valid: true,
                    "A health observation is valid when its schema is valid."),
            Proto.NodeToControl.PayloadOneofCase.TransportAck =>
                CreateValidatedPayload(
                    TransportPayloadKind.TransportAck,
                    envelope.TransportAck.SchemaVersion,
                    envelope.TransportAck.PayloadType,
                    NodeTransportProtocol.TransportAcknowledgementPayloadType,
                    envelope.TransportAck,
                    HasOnlyKnownFields(strictEnvelope.Payload, 10, 18, 26, 34),
                    TryNonEmptyGuid(envelope.TransportAck.AcknowledgedMessageId, out _) &&
                    !string.IsNullOrWhiteSpace(envelope.TransportAck.Code),
                    "A transport acknowledgement requires a message ID and code."),
            Proto.NodeToControl.PayloadOneofCase.TransportRejection =>
                CreateValidatedPayload(
                    TransportPayloadKind.TransportRejection,
                    envelope.TransportRejection.SchemaVersion,
                    envelope.TransportRejection.PayloadType,
                    NodeTransportProtocol.TransportRejectionPayloadType,
                    envelope.TransportRejection,
                    HasOnlyKnownFields(strictEnvelope.Payload, 10, 16, 26, 34),
                    envelope.TransportRejection.Code != Proto.TransportRejectionCode.Unspecified &&
                    Enum.IsDefined(envelope.TransportRejection.Code) &&
                    !string.IsNullOrWhiteSpace(envelope.TransportRejection.Message),
                    "A transport rejection requires a known code and message."),
            _ => Failure<ValidatedTransportPayload>(
                "unsupported-transport-payload",
                "The transport envelope does not contain an enabled typed payload.")
        };

    private static Result<ValidatedTransportPayload, NodeTransportValidationError> ValidateInventoryPayload(
        Proto.InventoryObservation observation,
        ReadOnlySpan<byte> encodedPayload)
    {
        if (observation is null ||
            observation.Inventory is null ||
            !IsStrictInventoryObservation(encodedPayload))
        {
            return Failure<ValidatedTransportPayload>("invalid-transport-payload", "An inventory observation contains malformed or unknown fields.");
        }

        var inventory = new EnrollmentInventory(
            observation.Inventory.Facts.ToImmutableDictionary(StringComparer.Ordinal),
            observation.Inventory.Capabilities.ToImmutableArray());
        var inventoryValidation = ValidateInventory(inventory);
        return inventoryValidation is Result<bool, NodeTransportValidationError>.Failure failure
            ? Failure<ValidatedTransportPayload>(failure.Error.Code, failure.Error.Message)
            : CreateValidatedPayload(
                TransportPayloadKind.InventoryObservation,
                observation.SchemaVersion,
                observation.PayloadType,
                NodeTransportProtocol.InventoryObservationPayloadType,
                observation,
                wireIsValid: true,
                valid: true,
                "An inventory observation is valid when its schema and inventory are valid.");
    }

    private static Result<ValidatedTransportPayload, NodeTransportValidationError> CreateValidatedPayload(
        TransportPayloadKind kind,
        string schemaVersion,
        string payloadType,
        string expectedPayloadType,
        IMessage payload,
        bool wireIsValid,
        bool valid,
        string invalidMessage)
    {
        if (!wireIsValid || !valid || schemaVersion != NodeTransportProtocol.Version || payloadType != expectedPayloadType)
        {
            return Failure<ValidatedTransportPayload>(
                schemaVersion == NodeTransportProtocol.Version ? "invalid-transport-payload" : "unsupported-protocol-version",
                schemaVersion == NodeTransportProtocol.Version ? invalidMessage : "The payload schema version is not supported.");
        }

        var canonicalPayload = CanonicalisePayload(payload);
        return canonicalPayload.IsDefaultOrEmpty ||
               canonicalPayload.Length > NodeTransportProtocol.MaximumTransportPayloadBytes
            ? Failure<ValidatedTransportPayload>("invalid-transport-payload", "The transport payload is empty or exceeds its limit.")
            : new Result<ValidatedTransportPayload, NodeTransportValidationError>.Success(
                new(kind, schemaVersion, canonicalPayload));
    }

    private static ImmutableArray<byte> CanonicalisePayload(IMessage payload)
    {
        var bytes = new byte[payload.CalculateSize()];
        var output = new CodedOutputStream(bytes) { Deterministic = true };
        payload.WriteTo(output);
        output.CheckNoSpaceLeft();
        return ImmutableArray.CreateRange(bytes);
    }

    private static bool CsrBindsToPublicKey(ReadOnlySpan<byte> csr, ReadOnlySpan<byte> expectedSpki)
    {
        try
        {
            var request = CertificateRequest.LoadSigningRequest(
                csr.ToArray(),
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default,
                RSASignaturePadding.Pkcs1);
            return CryptographicOperations.FixedTimeEquals(
                request.PublicKey.ExportSubjectPublicKeyInfo(),
                expectedSpki);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool IsP256Spki(ReadOnlySpan<byte> spki)
    {
        try
        {
            var reader = new AsnReader(spki.ToArray(), AsnEncodingRules.DER);
            var subjectPublicKeyInfo = reader.ReadSequence();
            var algorithm = subjectPublicKeyInfo.ReadSequence();
            var algorithmOid = algorithm.ReadObjectIdentifier();
            var curveOid = algorithm.ReadObjectIdentifier();
            algorithm.ThrowIfNotEmpty();
            subjectPublicKeyInfo.ReadBitString(out _);
            subjectPublicKeyInfo.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            if (algorithmOid != "1.2.840.10045.2.1" || curveOid != "1.2.840.10045.3.1.7")
            {
                return false;
            }

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
            return bytesRead == spki.Length && key.KeySize == 256;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool HasClientAuthenticationEku(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>()
                .Any(usage => usage.Value == ClientAuthenticationOid.Value));

    private static bool HasExactNodeSan(X509Certificate2 certificate, NodeUid nodeUid, long epoch)
    {
        var san = certificate.Extensions["2.5.29.17"];
        if (san is null)
        {
            return false;
        }

        var reader = new AsnReader(san.RawData, AsnEncodingRules.DER);
        var names = reader.ReadSequence();
        var expected = $"spiffe://armada.lab/node/{nodeUid}/epoch/{epoch}";
        var matchingUris = 0;
        var uriCount = 0;
        while (names.HasData)
        {
            var tag = names.PeekTag();
            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6)
            {
                uriCount++;
                var uri = names.ReadCharacterString(
                    UniversalTagNumber.IA5String,
                    new Asn1Tag(TagClass.ContextSpecific, 6));
                if (uri == expected)
                {
                    matchingUris++;
                }
            }
            else
            {
                return false;
            }
        }

        reader.ThrowIfNotEmpty();
        return uriCount == 1 && matchingUris == 1;
    }

    private static bool IsUtcWithin(DateTimeOffset value, DateTimeOffset now, TimeSpan tolerance) =>
        value.Offset == TimeSpan.Zero &&
        value >= now - tolerance &&
        value <= now + tolerance;

    private static bool TryGetUtcTimestamp(
        Google.Protobuf.WellKnownTypes.Timestamp timestamp,
        out DateTimeOffset value)
    {
        try
        {
            value = timestamp.ToDateTimeOffset();
            return value.Offset == TimeSpan.Zero;
        }
        catch (ArgumentOutOfRangeException)
        {
            value = default;
            return false;
        }
        catch (InvalidOperationException)
        {
            value = default;
            return false;
        }
    }

    private static bool TryNonEmptyGuid(string? value, out Guid parsed) =>
        Guid.TryParseExact(value, "D", out parsed) &&
        parsed != Guid.Empty &&
        string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool IsCanonicalIdempotencyKey(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= NodeTransportProtocol.MaximumIdempotencyKeyBytes &&
        value == value.Trim() &&
        value.All(static character => character is >= '!' and <= '~');

    private static bool IsCanonicalHex(string? value, int? exactLength = null) =>
        !string.IsNullOrWhiteSpace(value) &&
        (!exactLength.HasValue || value.Length == exactLength.Value) &&
        value.Length % 2 == 0 &&
        value.All(static character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static Sha256Digest ParseDigest(ReadOnlySpan<byte> value)
    {
        var digest = Sha256Digest.Parse($"sha256:{Convert.ToHexString(value).ToLowerInvariant()}");
        return ((Result<Sha256Digest, ContractValidationError>.Success)digest).Value;
    }

    private static Result<T, NodeTransportValidationError> Failure<T>(string code, string message) =>
        new Result<T, NodeTransportValidationError>.Failure(new(code, message));
}

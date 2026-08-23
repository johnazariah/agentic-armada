using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Armada.Application;
using Armada.Contracts;
using Npgsql;

namespace Armada.Infrastructure.Postgres;

public sealed class PostgresNodeEnrollmentStateRepository(NpgsqlDataSource dataSource) :
    IEnrollmentClaimStore,
    IEnrollmentStateStore,
    INodeIdentityRegistry,
    ITransportReplayReceiptStore
{
    public async Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> GetAsync(
        Guid claimId,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var claim = await ReadClaimAsync(connection, null, claimId, false, cancellationToken);
        return claim is null
            ? ClaimFailure("unknown-enrollment-claim", "The enrolment claim does not exist.")
            : new Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Success(ToState(claim));
    }

    public async Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> VerifyAsync(
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var claim = await ReadClaimAsync(connection, null, reference.ClaimId, false, cancellationToken);
        return VerifyClaim(claim, reference, presentedSecret) switch
        {
            EnrollmentClaimStoreFailure failure =>
                new Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Failure(failure),
            _ when claim!.ConsumedAt is not null =>
                ClaimFailure("enrollment-claim-consumed", "The enrolment claim has already been consumed."),
            _ when claim!.ExpiresAt <= now =>
                ClaimFailure("enrollment-claim-expired", "The enrolment claim has expired."),
            _ => new Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Success(ToState(claim!))
        };
    }

    public Task<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>> ConsumeAsync(
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret,
        CancellationToken cancellationToken) =>
        Task.FromResult(ClaimFailure<EnrollmentClaimConsumption>(
            "atomic-identity-binding-required",
            "A claim may only be consumed with its certificate identity binding."));

    public async Task<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>> ReserveAsync(
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret,
        Guid requestId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (requestId == Guid.Empty || now.Offset != TimeSpan.Zero)
        {
            return ClaimFailure<EnrollmentClaimReservation>(
                "invalid-enrollment-reservation",
                "Claim reservation requires a request ID and UTC timestamp.");
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var claim = await ReadClaimAsync(connection, transaction, reference.ClaimId, true, cancellationToken);
        var verification = VerifyClaim(claim, reference, presentedSecret);
        if (verification is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return ClaimFailure<EnrollmentClaimReservation>(verification.Code, verification.Message);
        }

        if (claim!.ConsumedAt is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return ClaimFailure<EnrollmentClaimReservation>(
                "enrollment-claim-consumed",
                "The enrolment claim has already been consumed.");
        }

        var reservationExpiresAt = await TryReserveAsync(
            connection,
            transaction,
            reference.ClaimId,
            requestId,
            cancellationToken);
        if (reservationExpiresAt is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return claim.ReservationRequestId is not null
                ? ClaimFailure<EnrollmentClaimReservation>(
                    "enrollment-claim-in-progress",
                    "An issuer reservation already exists for this enrolment claim.")
                : ClaimFailure<EnrollmentClaimReservation>(
                    "enrollment-claim-expired",
                    "The enrolment claim has expired.");
        }

        await transaction.CommitAsync(cancellationToken);
        return new Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success(
            new(new EnrollmentClaimState(reference, claim.ExpiresAt, false), requestId, reservationExpiresAt.Value));
    }

    private static async Task<DateTimeOffset?> TryReserveAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid claimId,
        Guid requestId,
        CancellationToken cancellationToken)
    {
        await using var reserve = new NpgsqlCommand(
            """
            WITH reservation_clock AS (
                SELECT clock_timestamp() AS value
            )
            UPDATE armada_enrollment_claims AS claim
            SET issuance_request_id = @requestId,
                issuance_reserved_at = reservation_clock.value,
                issuance_reservation_expires_at = LEAST(
                    claim.expires_at,
                    reservation_clock.value + INTERVAL '5 minutes')
            FROM reservation_clock
            WHERE claim.claim_id = @claimId
              AND claim.expires_at > reservation_clock.value
              AND claim.issuance_request_id IS NULL
            RETURNING claim.issuance_reservation_expires_at;
            """,
            connection,
            transaction);
        reserve.Parameters.AddWithValue("requestId", requestId);
        reserve.Parameters.AddWithValue("claimId", claimId);
        await using var reader = await reserve.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? reader.GetFieldValue<DateTimeOffset>(0)
            : null;
    }

    public async Task<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>> FindCompletedAsync(
        EnrollmentClaimReference claimReference,
        ReadOnlyMemory<byte> presentedSecret,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var claim = await ReadClaimAsync(connection, null, claimReference.ClaimId, false, cancellationToken);
        var verification = VerifyClaim(claim, claimReference, presentedSecret);
        if (verification is not null)
        {
            return StateFailure<EnrollmentCompletion?>(verification.Code, verification.Message);
        }

        if (claim!.ConsumedAt is null)
        {
            return new Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Success(null);
        }

        var identity = await ReadIdentityAsync(
            connection,
            null,
            claimReference.NodeUid,
            claimReference.IdentityEpoch,
            cancellationToken);
        return identity is null
            ? StateFailure<EnrollmentCompletion?>(
                "incomplete-enrollment-consumption",
                "A consumed claim has no durable certificate identity.")
            : new Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Success(
                new EnrollmentCompletion.AlreadyCompleted(ReadResponse(identity.Response), ToBinding(identity)));
    }

    public async Task<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>> CompleteAsync(
        EnrollmentCompletionRequest request,
        CancellationToken cancellationToken)
    {
        if (!IsCompletionConsistent(request))
        {
            return StateFailure<EnrollmentCompletion>(
                "invalid-enrollment-completion",
                "The enrolment response and identity binding must exactly describe the claim.");
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var claim = await ReadClaimAsync(connection, transaction, request.Claim.ClaimId, true, cancellationToken);
        var verification = VerifyClaim(claim, request.Claim, request.PresentedSecret);
        if (verification is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return StateFailure<EnrollmentCompletion>(verification.Code, verification.Message);
        }

        if (claim!.ConsumedAt is not null)
        {
            if (claim.ReservationRequestId != request.RequestId)
            {
                await transaction.RollbackAsync(cancellationToken);
                return StateFailure<EnrollmentCompletion>(
                    "enrollment-claim-reservation-mismatch",
                    "The completed claim belongs to a different enrolment request.");
            }

            var existing = await ReadIdentityAsync(
                connection,
                transaction,
                request.Claim.NodeUid,
                request.Claim.IdentityEpoch,
                cancellationToken);
            await transaction.RollbackAsync(cancellationToken);
            return existing is null
                ? StateFailure<EnrollmentCompletion>(
                    "incomplete-enrollment-consumption",
                    "A consumed claim has no durable certificate identity.")
                : !Matches(existing, request)
                    ? StateFailure<EnrollmentCompletion>(
                        "enrollment-completion-conflict",
                        "The consumed claim is bound to a different certificate response.")
                : new Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success(
                    new EnrollmentCompletion.AlreadyCompleted(ReadResponse(existing.Response), ToBinding(existing)));
        }

        var timing = await ReadCompletionTimingAsync(
            connection,
            transaction,
            request.Claim.ClaimId,
            cancellationToken);
        if (!timing.ClaimIsCurrent)
        {
            await transaction.RollbackAsync(cancellationToken);
            return StateFailure<EnrollmentCompletion>(
                "enrollment-claim-expired",
                "The enrolment claim has expired.");
        }

        if (claim.ReservationRequestId != request.RequestId)
        {
            await transaction.RollbackAsync(cancellationToken);
            return StateFailure<EnrollmentCompletion>(
                "enrollment-claim-reservation-mismatch",
                "The enrolment completion does not own the claim reservation.");
        }

        if (!await InsertIdentityAsync(connection, transaction, request, cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return StateFailure<EnrollmentCompletion>(
                "certificate-identity-conflict",
                "The node epoch, certificate serial, or thumbprint is already bound.");
        }

        var result = SerializeResponse(request.Response);
        await using (var consume = new NpgsqlCommand(
            """
            UPDATE armada_enrollment_claims
            SET consumed_at = @consumedAt,
                consumption_correlation_id = @correlationId,
                consumption_result = CAST(@result AS jsonb)
            WHERE claim_id = @claimId
              AND consumed_at IS NULL;
            """,
            connection,
            transaction))
        {
            consume.Parameters.AddWithValue("consumedAt", request.OccurredAt);
            consume.Parameters.AddWithValue("correlationId", request.CorrelationId);
            consume.Parameters.AddWithValue("result", result);
            consume.Parameters.AddWithValue("claimId", request.Claim.ClaimId);
            if (await consume.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                await transaction.RollbackAsync(cancellationToken);
                return StateFailure<EnrollmentCompletion>(
                    "enrollment-claim-concurrent-consumption",
                    "The enrolment claim was consumed concurrently.");
            }
        }

        await AppendAuditAndOutboxAsync(
            connection,
            transaction,
            "enrollment-claim-consumed",
            request.CorrelationId,
            $"enrollment:{request.Claim.ClaimId:D}",
            request.OccurredAt,
            JsonSerializer.Serialize(new
            {
                claimId = request.Claim.ClaimId,
                nodeUid = request.Claim.NodeUid.Value,
                request.Claim.IdentityEpoch,
                publicKeyDigest = request.Claim.PublicKeyDigest.Value,
                request.Identity.CertificateSerial,
                request.Identity.CertificateThumbprintSha256
            }),
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success(
            new EnrollmentCompletion.Completed(request.Response, request.Identity));
    }

    public async Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
        NodeUid nodeUid,
        long identityEpoch,
        string certificateSerial,
        string certificateThumbprintSha256,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var identity = await ReadIdentityAsync(connection, null, nodeUid, identityEpoch, cancellationToken);
        if (identity is null ||
            identity.CertificateSerial != certificateSerial ||
            identity.CertificateThumbprintSha256 != certificateThumbprintSha256)
        {
            return IdentityFailure("unknown-node-identity", "The certificate is not bound to the supplied node identity epoch.");
        }

        if (identity.RevokedAt is not null)
        {
            return IdentityFailure("identity-revoked", "The node certificate identity has been revoked by the controller.");
        }

        if (identity.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return IdentityFailure("identity-expired", "The node certificate identity has expired.");
        }

        return new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success(ToBinding(identity));
    }

    public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
        NodeIdentityBinding binding,
        CancellationToken cancellationToken) =>
        Task.FromResult(IdentityFailure(
            "direct-identity-registration-disabled",
            "Certificate identities are created only by atomic claim consumption."));

    public async Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
        NodeUid nodeUid,
        long identityEpoch,
        string reason,
        Guid correlationId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(reason) || correlationId == Guid.Empty)
        {
            return IdentityFailure("invalid-revocation-request", "Controller revocation requires a reason and correlation ID.");
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var identity = await ReadIdentityAsync(connection, transaction, nodeUid, identityEpoch, cancellationToken, true);
        if (identity is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return IdentityFailure("unknown-node-identity", "The node certificate identity does not exist.");
        }

        if (identity.RevokedAt is null)
        {
            var revokedAt = DateTimeOffset.UtcNow;
            await using (var command = new NpgsqlCommand(
                """
                UPDATE armada_node_certificate_identities
                SET revoked_at = @revokedAt,
                    revocation_reason = @reason
                WHERE node_uid = @nodeUid
                  AND identity_epoch = @identityEpoch
                  AND revoked_at IS NULL;
                """,
                connection,
                transaction))
            {
                command.Parameters.AddWithValue("revokedAt", revokedAt);
                command.Parameters.AddWithValue("reason", reason);
                command.Parameters.AddWithValue("nodeUid", nodeUid.Value);
                command.Parameters.AddWithValue("identityEpoch", identityEpoch);
                if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return IdentityFailure("identity-revocation-conflict", "The node identity changed during revocation.");
                }
            }

            await AppendAuditAndOutboxAsync(
                connection,
                transaction,
                "node-certificate-identity-revoked",
                correlationId,
                $"identity-revocation:{nodeUid}:{identityEpoch}",
                revokedAt,
                JsonSerializer.Serialize(new { nodeUid = nodeUid.Value, identityEpoch, reason }),
                cancellationToken);
            identity = identity with { RevokedAt = revokedAt, RevocationReason = reason };
        }

        await transaction.CommitAsync(cancellationToken);
        return new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success(ToBinding(identity));
    }

    public async Task<Result<ReplayReceipt, ReplayReceiptStoreFailure>> RetrieveOrRecordAsync(
        ReplayReceipt receipt,
        CancellationToken cancellationToken)
    {
        if (!IsReceiptConsistent(receipt))
        {
            return ReplayFailure("invalid-replay-receipt", "The acknowledgement must bind the replay identity.");
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        if (await InsertReceiptAsync(connection, transaction, receipt, cancellationToken))
        {
            await AppendAuditAndOutboxAsync(
                connection,
                transaction,
                "transport-replay-receipt-recorded",
                receipt.Identity.CorrelationId,
                $"transport-receipt:{receipt.Identity.CanonicalValue}",
                receipt.Identity.SentAt,
                JsonSerializer.Serialize(new
                {
                    nodeUid = receipt.Identity.NodeUid.Value,
                    receipt.Identity.IdentityEpoch,
                    receipt.Identity.StreamEpoch,
                    receipt.Identity.Sequence,
                    receipt.Identity.MessageId,
                    receipt.Identity.IdempotencyKey,
                    payloadDigest = receipt.Identity.PayloadDigest.Value,
                    acknowledgementCode = receipt.Acknowledgement.Code
                }),
                cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success(receipt);
        }

        var stored = await ReadConflictingReceiptAsync(connection, transaction, receipt.Identity, cancellationToken);
        await transaction.RollbackAsync(cancellationToken);
        if (stored is not null && stored.Identity == receipt.Identity)
        {
            return new Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success(stored);
        }

        return ReplayFailure(
            "replay-conflict",
            "A stream sequence, message ID, or idempotency key is already bound to a different transport envelope.");
    }

    private static async Task<StoredClaim?> ReadClaimAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        Guid claimId,
        bool forUpdate,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            $"""
            SELECT claim_id, secret_verifier, intended_node_uid, intended_identity_epoch,
                   intended_public_key_digest, expires_at, issuance_request_id,
                   issuance_reservation_expires_at, consumed_at
            FROM armada_enrollment_claims
            WHERE claim_id = @claimId
            {(forUpdate ? "FOR UPDATE" : string.Empty)};
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("claimId", claimId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new StoredClaim(
                reader.GetGuid(0),
                reader.GetFieldValue<byte[]>(1),
                new NodeUid(reader.GetGuid(2)),
                reader.GetInt64(3),
                ParseDigest(reader.GetString(4)),
                reader.GetFieldValue<DateTimeOffset>(5),
                reader.IsDBNull(6) ? null : reader.GetGuid(6),
                reader.IsDBNull(7) ? DateTimeOffset.MinValue : reader.GetFieldValue<DateTimeOffset>(7),
                reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8))
            : null;
    }

    private static EnrollmentClaimStoreFailure? VerifyClaim(
        StoredClaim? claim,
        EnrollmentClaimReference reference,
        ReadOnlyMemory<byte> presentedSecret)
    {
        var verifier = SHA256.HashData(presentedSecret.Span);
        if (claim is null)
        {
            return new("unauthenticated-enrollment-claim", "The enrolment claim credentials are invalid.");
        }

        if (!CryptographicOperations.FixedTimeEquals(claim.SecretVerifier, verifier))
        {
            return new("unauthenticated-enrollment-claim", "The enrolment claim credentials are invalid.");
        }

        if (claim.NodeUid != reference.NodeUid ||
            claim.IdentityEpoch != reference.IdentityEpoch ||
            claim.PublicKeyDigest != reference.PublicKeyDigest)
        {
            return new("enrollment-claim-identity-mismatch", "The enrolment claim is not intended for this node identity.");
        }

        return null;
    }

    private static async Task<CompletionTiming> ReadCompletionTimingAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid claimId,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT expires_at > clock_timestamp()
            FROM armada_enrollment_claims
            WHERE claim_id = @claimId;
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("claimId", claimId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("A locked enrolment claim disappeared before completion.");
        }

        return new(
            reader.GetBoolean(0));
    }

    private static async Task<bool> InsertIdentityAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        EnrollmentCompletionRequest request,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO armada_node_certificate_identities
                (node_uid, identity_epoch, public_key_digest, certificate_serial,
                 certificate_thumbprint_sha256, issued_at, expires_at, enrollment_response)
            VALUES
                (@nodeUid, @identityEpoch, @publicKeyDigest, @certificateSerial,
                 @certificateThumbprint, CURRENT_TIMESTAMP, @expiresAt, CAST(@response AS jsonb))
            ON CONFLICT DO NOTHING;
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("nodeUid", request.Identity.NodeUid.Value);
        command.Parameters.AddWithValue("identityEpoch", request.Identity.IdentityEpoch);
        command.Parameters.AddWithValue("publicKeyDigest", request.Identity.PublicKeyDigest.Value);
        command.Parameters.AddWithValue("certificateSerial", request.Identity.CertificateSerial);
        command.Parameters.AddWithValue("certificateThumbprint", request.Identity.CertificateThumbprintSha256);
        command.Parameters.AddWithValue("expiresAt", request.Identity.ExpiresAt);
        command.Parameters.AddWithValue("response", SerializeResponse(request.Response));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static async Task<StoredIdentity?> ReadIdentityAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        NodeUid nodeUid,
        long identityEpoch,
        CancellationToken cancellationToken,
        bool forUpdate = false)
    {
        await using var command = new NpgsqlCommand(
            $"""
            SELECT node_uid, identity_epoch, public_key_digest, certificate_serial,
                   certificate_thumbprint_sha256, expires_at, revoked_at, revocation_reason,
                   enrollment_response::text
            FROM armada_node_certificate_identities
            WHERE node_uid = @nodeUid
              AND identity_epoch = @identityEpoch
            {(forUpdate ? "FOR UPDATE" : string.Empty)};
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("nodeUid", nodeUid.Value);
        command.Parameters.AddWithValue("identityEpoch", identityEpoch);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new StoredIdentity(
                new NodeUid(reader.GetGuid(0)),
                reader.GetInt64(1),
                ParseDigest(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetFieldValue<DateTimeOffset>(5),
                reader.IsDBNull(6) ? null : reader.GetFieldValue<DateTimeOffset>(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.GetString(8))
            : null;
    }

    private static async Task<bool> InsertReceiptAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ReplayReceipt receipt,
        CancellationToken cancellationToken)
    {
        var identity = receipt.Identity;
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO armada_transport_replay_receipts
                (node_uid, identity_epoch, stream_epoch, sequence, message_id, correlation_id,
                 idempotency_key, protocol_version, payload_kind, sent_at, sent_at_ticks, payload_digest,
                 acknowledgement, recorded_at)
            VALUES
                (@nodeUid, @identityEpoch, @streamEpoch, @sequence, @messageId, @correlationId,
                 @idempotencyKey, @protocolVersion, @payloadKind, @sentAt, @sentAtTicks, @payloadDigest,
                 CAST(@acknowledgement AS jsonb), @recordedAt)
            ON CONFLICT DO NOTHING;
            """,
            connection,
            transaction);
        AddReceiptParameters(command, receipt);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static async Task<ReplayReceipt?> ReadConflictingReceiptAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ReplayIdentity identity,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT node_uid, identity_epoch, stream_epoch, sequence, message_id, correlation_id,
                   idempotency_key, protocol_version, payload_kind, sent_at_ticks, payload_digest,
                   acknowledgement::text
            FROM armada_transport_replay_receipts
            WHERE (node_uid = @nodeUid AND identity_epoch = @identityEpoch
                   AND stream_epoch = @streamEpoch AND sequence = @sequence)
               OR (node_uid = @nodeUid AND identity_epoch = @identityEpoch AND message_id = @messageId)
               OR (node_uid = @nodeUid AND identity_epoch = @identityEpoch AND idempotency_key = @idempotencyKey)
            ORDER BY recorded_at
            LIMIT 1;
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("nodeUid", identity.NodeUid.Value);
        command.Parameters.AddWithValue("identityEpoch", identity.IdentityEpoch);
        command.Parameters.AddWithValue("streamEpoch", identity.StreamEpoch);
        command.Parameters.AddWithValue("sequence", identity.Sequence);
        command.Parameters.AddWithValue("messageId", identity.MessageId);
        command.Parameters.AddWithValue("idempotencyKey", identity.IdempotencyKey);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var storedIdentity = new ReplayIdentity(
            new NodeUid(reader.GetGuid(0)),
            reader.GetInt64(1),
            reader.GetInt64(2),
            reader.GetInt64(3),
            reader.GetGuid(4),
            reader.GetGuid(5),
            reader.GetString(6),
            reader.GetString(7),
            Enum.Parse<TransportPayloadKind>(reader.GetString(8), ignoreCase: false),
            new DateTimeOffset(reader.GetInt64(9), TimeSpan.Zero),
            ParseDigest(reader.GetString(10)));
        var acknowledgement = JsonSerializer.Deserialize<TransportAcknowledgement>(reader.GetString(11))
            ?? throw new InvalidOperationException("A persisted replay acknowledgement could not be deserialised.");
        return new ReplayReceipt(storedIdentity, acknowledgement);
    }

    private static async Task AppendAuditAndOutboxAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string eventType,
        Guid correlationId,
        string idempotencyKey,
        DateTimeOffset occurredAt,
        string payload,
        CancellationToken cancellationToken)
    {
        var eventId = Guid.NewGuid();
        await using (var audit = new NpgsqlCommand(
            """
            INSERT INTO armada_node_transport_audit
                (event_id, event_type, actor, correlation_id, causation_id, idempotency_key, occurred_at, payload)
            VALUES
                (@eventId, @eventType, 'controller', @correlationId, NULL, @idempotencyKey, @occurredAt, CAST(@payload AS jsonb));
            """,
            connection,
            transaction))
        {
            audit.Parameters.AddWithValue("eventId", eventId);
            audit.Parameters.AddWithValue("eventType", eventType);
            audit.Parameters.AddWithValue("correlationId", correlationId);
            audit.Parameters.AddWithValue("idempotencyKey", idempotencyKey);
            audit.Parameters.AddWithValue("occurredAt", occurredAt);
            audit.Parameters.AddWithValue("payload", payload);
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var outbox = new NpgsqlCommand(
            """
            INSERT INTO armada_node_transport_outbox
                (message_id, event_id, message_type, idempotency_key, occurred_at, payload)
            VALUES
                (@messageId, @eventId, @messageType, @idempotencyKey, @occurredAt, CAST(@payload AS jsonb));
            """,
            connection,
            transaction);
        outbox.Parameters.AddWithValue("messageId", Guid.NewGuid());
        outbox.Parameters.AddWithValue("eventId", eventId);
        outbox.Parameters.AddWithValue("messageType", eventType);
        outbox.Parameters.AddWithValue("idempotencyKey", $"{idempotencyKey}:outbox");
        outbox.Parameters.AddWithValue("occurredAt", occurredAt);
        outbox.Parameters.AddWithValue("payload", payload);
        await outbox.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddReceiptParameters(NpgsqlCommand command, ReplayReceipt receipt)
    {
        var identity = receipt.Identity;
        command.Parameters.AddWithValue("nodeUid", identity.NodeUid.Value);
        command.Parameters.AddWithValue("identityEpoch", identity.IdentityEpoch);
        command.Parameters.AddWithValue("streamEpoch", identity.StreamEpoch);
        command.Parameters.AddWithValue("sequence", identity.Sequence);
        command.Parameters.AddWithValue("messageId", identity.MessageId);
        command.Parameters.AddWithValue("correlationId", identity.CorrelationId);
        command.Parameters.AddWithValue("idempotencyKey", identity.IdempotencyKey);
        command.Parameters.AddWithValue("protocolVersion", identity.ProtocolVersion);
        command.Parameters.AddWithValue("payloadKind", identity.PayloadKind.ToString());
        command.Parameters.AddWithValue("sentAt", identity.SentAt);
        command.Parameters.AddWithValue("sentAtTicks", identity.SentAt.UtcDateTime.Ticks);
        command.Parameters.AddWithValue("payloadDigest", identity.PayloadDigest.Value);
        command.Parameters.AddWithValue("acknowledgement", JsonSerializer.Serialize(receipt.Acknowledgement));
        command.Parameters.AddWithValue("recordedAt", DateTimeOffset.UtcNow);
    }

    private static bool IsCompletionConsistent(EnrollmentCompletionRequest request) =>
        request.Claim.ClaimId != Guid.Empty &&
        request.RequestId != Guid.Empty &&
        request.CorrelationId != Guid.Empty &&
        request.OccurredAt.Offset == TimeSpan.Zero &&
        request.Claim.NodeUid == request.Identity.NodeUid &&
        request.Claim.IdentityEpoch == request.Identity.IdentityEpoch &&
        request.Claim.PublicKeyDigest == request.Identity.PublicKeyDigest &&
        !request.Identity.IsRevoked &&
        request.Response.ProtocolVersion == NodeTransportProtocol.Version &&
        request.Response.NodeUid == request.Identity.NodeUid.ToString() &&
        request.Response.IdentityEpoch == request.Identity.IdentityEpoch &&
        request.Response.CertificateSerial == request.Identity.CertificateSerial &&
        request.Response.ExpiresAt == request.Identity.ExpiresAt &&
        !request.Response.LeafCertificateDer.IsDefaultOrEmpty &&
        !request.Response.IssuingCaDer.IsDefaultOrEmpty &&
        request.Response.CorrelationId == request.CorrelationId.ToString("D");

    private static bool Matches(StoredIdentity identity, EnrollmentCompletionRequest request)
    {
        var response = ReadResponse(identity.Response);
        return identity.NodeUid == request.Identity.NodeUid &&
               identity.IdentityEpoch == request.Identity.IdentityEpoch &&
               identity.PublicKeyDigest == request.Identity.PublicKeyDigest &&
               identity.CertificateSerial == request.Identity.CertificateSerial &&
               identity.CertificateThumbprintSha256 == request.Identity.CertificateThumbprintSha256 &&
               response.ProtocolVersion == request.Response.ProtocolVersion &&
               response.NodeUid == request.Response.NodeUid &&
               response.IdentityEpoch == request.Response.IdentityEpoch &&
               response.CertificateSerial == request.Response.CertificateSerial &&
               response.ExpiresAt == request.Response.ExpiresAt &&
               response.LeafCertificateDer.SequenceEqual(request.Response.LeafCertificateDer) &&
               response.IssuingCaDer.SequenceEqual(request.Response.IssuingCaDer) &&
               response.CorrelationId == request.Response.CorrelationId;
    }

    private static bool IsReceiptConsistent(ReplayReceipt receipt) =>
        receipt.Identity.MessageId == receipt.Acknowledgement.MessageId &&
        receipt.Identity.CorrelationId == receipt.Acknowledgement.CorrelationId &&
        receipt.Identity.IdempotencyKey == receipt.Acknowledgement.IdempotencyKey;

    private static EnrollmentClaimState ToState(StoredClaim claim) =>
        new(
            new EnrollmentClaimReference(claim.ClaimId, claim.NodeUid, claim.IdentityEpoch, claim.PublicKeyDigest),
            claim.ExpiresAt,
            claim.ConsumedAt is not null);

    private static NodeIdentityBinding ToBinding(StoredIdentity identity) =>
        new(
            identity.NodeUid,
            identity.IdentityEpoch,
            identity.PublicKeyDigest,
            identity.CertificateSerial,
            identity.CertificateThumbprintSha256,
            identity.ExpiresAt,
            identity.RevokedAt is not null);

    private static string SerializeResponse(EnrollmentResponseDto response) =>
        JsonSerializer.Serialize(new StoredEnrollmentResponse(
            response.ProtocolVersion,
            response.NodeUid,
            response.IdentityEpoch,
            response.CertificateSerial,
            response.ExpiresAt,
            response.LeafCertificateDer.ToArray(),
            response.IssuingCaDer.ToArray(),
            response.CorrelationId));

    private static EnrollmentResponseDto ReadResponse(string json)
    {
        var response = JsonSerializer.Deserialize<StoredEnrollmentResponse>(json)
            ?? throw new InvalidOperationException("A persisted enrolment response could not be deserialised.");
        return new EnrollmentResponseDto(
            response.ProtocolVersion,
            response.NodeUid,
            response.IdentityEpoch,
            response.CertificateSerial,
            response.ExpiresAt,
            response.LeafCertificateDer.ToImmutableArray(),
            response.IssuingCaDer.ToImmutableArray(),
            response.CorrelationId);
    }

    private static Sha256Digest ParseDigest(string value) =>
        Sha256Digest.Parse(value) is Result<Sha256Digest, ContractValidationError>.Success digest
            ? digest.Value
            : throw new InvalidOperationException("A persisted SHA-256 digest is invalid.");

    private static Result<T, EnrollmentClaimStoreFailure> ClaimFailure<T>(string code, string message) =>
        new Result<T, EnrollmentClaimStoreFailure>.Failure(new(code, message));

    private static Result<EnrollmentClaimState, EnrollmentClaimStoreFailure> ClaimFailure(string code, string message) =>
        ClaimFailure<EnrollmentClaimState>(code, message);

    private static Result<T, EnrollmentStateStoreFailure> StateFailure<T>(string code, string message) =>
        new Result<T, EnrollmentStateStoreFailure>.Failure(new(code, message));

    private static Result<NodeIdentityBinding, NodeIdentityRegistryFailure> IdentityFailure(string code, string message) =>
        new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure(new(code, message));

    private static Result<ReplayReceipt, ReplayReceiptStoreFailure> ReplayFailure(string code, string message) =>
        new Result<ReplayReceipt, ReplayReceiptStoreFailure>.Failure(new(code, message));

    private sealed record StoredClaim(
        Guid ClaimId,
        byte[] SecretVerifier,
        NodeUid NodeUid,
        long IdentityEpoch,
        Sha256Digest PublicKeyDigest,
        DateTimeOffset ExpiresAt,
        Guid? ReservationRequestId,
        DateTimeOffset ReservationExpiresAt,
        DateTimeOffset? ConsumedAt);

    private sealed record CompletionTiming(bool ClaimIsCurrent);

    private sealed record StoredIdentity(
        NodeUid NodeUid,
        long IdentityEpoch,
        Sha256Digest PublicKeyDigest,
        string CertificateSerial,
        string CertificateThumbprintSha256,
        DateTimeOffset ExpiresAt,
        DateTimeOffset? RevokedAt,
        string? RevocationReason,
        string Response);

    private sealed record StoredEnrollmentResponse(
        string ProtocolVersion,
        string NodeUid,
        long IdentityEpoch,
        string CertificateSerial,
        DateTimeOffset ExpiresAt,
        byte[] LeafCertificateDer,
        byte[] IssuingCaDer,
        string CorrelationId);
}

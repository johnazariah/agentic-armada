using System.Collections.Immutable;
using System.Security.Cryptography;
using Armada.Application;
using Armada.Contracts;
using Armada.Infrastructure.Postgres;
using Npgsql;

namespace Armada.Infrastructure.Postgres.Tests;

[Collection("postgres-integration")]
public sealed class PostgresNodeEnrollmentStateIntegrationTests : IAsyncLifetime
{
    private const string ConnectionVariable = "ARMADA_POSTGRES_CONNECTION";
    private NpgsqlDataSource? dataSource;
    private PostgresNodeEnrollmentStateRepository? repository;

    public async Task InitializeAsync()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException($"{ConnectionVariable} is required for PostgreSQL integration tests.");
        }

        dataSource = NpgsqlDataSource.Create(connectionString);
        await new PostgresMigrationRunner(dataSource).ApplyAsync(DateTimeOffset.UtcNow, CancellationToken.None);
        repository = new PostgresNodeEnrollmentStateRepository(dataSource);
    }

    public Task DisposeAsync()
    {
        dataSource?.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Concurrent_same_request_reservations_authorise_one_issuance_and_bind_one_identity()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)7, 32).ToArray();
        var claim = Claim();
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10));
        var request = Completion(claim, secret);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reservations = new[]
        {
            ReserveAfterStartAsync(request, start.Task),
            ReserveAfterStartAsync(request, start.Task)
        };
        start.SetResult();
        var reservationResults = await Task.WhenAll(reservations);
        Assert.Equal(1, reservationResults.Count(static result => result is Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success));
        Assert.Equal(
            "enrollment-claim-in-progress",
            Assert.IsType<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure>(
                Assert.Single(reservationResults, static result => result is Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure)).Error.Code);
        var completions = new[]
        {
            CompleteAfterStartAsync(request, Task.CompletedTask),
            CompleteAfterStartAsync(request, Task.CompletedTask)
        };
        var results = await Task.WhenAll(completions);

        Assert.Equal(
            1,
            results.Count(static result => result is Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success
            {
                Value: EnrollmentCompletion.Completed
            }));
        var replay = Assert.IsType<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success>(
            Assert.Single(results, static result => result is Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success
            {
                Value: EnrollmentCompletion.AlreadyCompleted
            })).Value;
        var replayResponse = Assert.IsType<EnrollmentCompletion.AlreadyCompleted>(replay).Response;
        Assert.Equal(request.Response.CertificateSerial, replayResponse.CertificateSerial);
        Assert.True(request.Response.LeafCertificateDer.SequenceEqual(replayResponse.LeafCertificateDer));
        Assert.Equal(1L, await CountAsync("armada_node_certificate_identities"));
        Assert.Equal(1L, await CountAsync("armada_node_transport_audit"));
        Assert.Equal(1L, await CountAsync("armada_node_transport_outbox"));
    }

    [Fact]
    public async Task Exact_receipt_is_replayed_and_changed_payload_is_a_typed_conflict()
    {
        await ResetAsync();
        var receipt = Receipt('a');

        var recorded = await Repository.RetrieveOrRecordAsync(receipt, CancellationToken.None);
        var replay = await Repository.RetrieveOrRecordAsync(receipt, CancellationToken.None);
        var changed = await Repository.RetrieveOrRecordAsync(
            receipt with { Identity = receipt.Identity with { PayloadDigest = Digest('b') } },
            CancellationToken.None);

        Assert.Equal(receipt, Assert.IsType<Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success>(recorded).Value);
        Assert.Equal(receipt, Assert.IsType<Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success>(replay).Value);
        Assert.Equal(
            "replay-conflict",
            Assert.IsType<Result<ReplayReceipt, ReplayReceiptStoreFailure>.Failure>(changed).Error.Code);
        Assert.Equal(1L, await CountAsync("armada_transport_replay_receipts"));
        Assert.Equal(1L, await CountAsync("armada_node_transport_audit"));
    }

    [Fact]
    public async Task Expired_wrong_and_revoked_identities_fail_closed_and_reconnect_reads_durable_state()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)3, 32).ToArray();
        var expired = Claim();
        await SeedClaimAsync(expired, secret, DateTimeOffset.UtcNow.AddMinutes(-1));
        var expiredResult = await Repository.VerifyAsync(expired, secret, DateTimeOffset.UtcNow, CancellationToken.None);

        var claim = Claim();
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10));
        var wrong = await Repository.VerifyAsync(
            claim with { PublicKeyDigest = Digest('f') },
            secret,
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        var completion = Completion(claim, secret);
        Assert.IsType<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success>(
            await Repository.ReserveAsync(claim, secret, completion.RequestId, completion.OccurredAt, CancellationToken.None));
        Assert.IsType<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success>(
            await Repository.CompleteAsync(completion, CancellationToken.None));

        var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable)!;
        await using var reconnectSource = NpgsqlDataSource.Create(connectionString);
        var reconnected = new PostgresNodeEnrollmentStateRepository(reconnectSource);
        var resolved = await reconnected.ResolveAsync(
            claim.NodeUid,
            claim.IdentityEpoch,
            completion.Identity.CertificateSerial,
            completion.Identity.CertificateThumbprintSha256,
            CancellationToken.None);
        var completedAfterReconnect = await reconnected.FindCompletedAsync(
            claim,
            secret,
            CancellationToken.None);
        var revoked = await reconnected.RevokeAsync(
            claim.NodeUid,
            claim.IdentityEpoch,
            "operator incident response",
            Guid.NewGuid(),
            CancellationToken.None);
        var refused = await reconnected.ResolveAsync(
            claim.NodeUid,
            claim.IdentityEpoch,
            completion.Identity.CertificateSerial,
            completion.Identity.CertificateThumbprintSha256,
            CancellationToken.None);

        Assert.Equal(
            "enrollment-claim-expired",
            Assert.IsType<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Failure>(expiredResult).Error.Code);
        Assert.Equal(
            "enrollment-claim-identity-mismatch",
            Assert.IsType<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Failure>(wrong).Error.Code);
        Assert.False(Assert.IsType<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success>(resolved).Value.IsRevoked);
        var completed = Assert.IsType<EnrollmentCompletion.AlreadyCompleted>(
            Assert.IsType<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Success>(completedAfterReconnect).Value);
        Assert.Equal(completion.Response.CertificateSerial, completed.Response.CertificateSerial);
        Assert.True(completion.Response.LeafCertificateDer.SequenceEqual(completed.Response.LeafCertificateDer));
        Assert.True(Assert.IsType<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success>(revoked).Value.IsRevoked);
        Assert.Equal(
            "identity-revoked",
            Assert.IsType<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure>(refused).Error.Code);
    }

    [Fact]
    public async Task Completion_uses_database_time_not_a_stale_caller_timestamp()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)5, 32).ToArray();
        var claim = Claim();
        var completion = Completion(claim, secret);
        var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        await SeedClaimAsync(claim, secret, expiredAt);
        await SeedReservationAsync(claim.ClaimId, completion.RequestId, DateTimeOffset.UtcNow.AddMinutes(5));

        var result = await Repository.CompleteAsync(
            completion with { OccurredAt = expiredAt.AddMinutes(-1) },
            CancellationToken.None);

        Assert.Equal(
            "enrollment-claim-expired",
            Assert.IsType<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Failure>(result).Error.Code);
        Assert.Equal(0L, await CountAsync("armada_node_certificate_identities"));
    }

    [Fact]
    public async Task Expired_reservation_is_never_reassigned_while_the_original_issuer_may_still_complete()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)10, 32).ToArray();
        var claim = Claim();
        var original = Completion(claim, secret);
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10));
        await SeedReservationAsync(claim.ClaimId, original.RequestId, DateTimeOffset.UtcNow.AddMinutes(-1));

        var competing = await Repository.ReserveAsync(
            claim,
            secret,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        var originalCompletion = await Repository.CompleteAsync(original, CancellationToken.None);

        Assert.Equal(
            "enrollment-claim-in-progress",
            Assert.IsType<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure>(competing).Error.Code);
        Assert.IsType<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success>(originalCompletion);
        Assert.Equal(1L, await CountAsync("armada_node_certificate_identities"));
    }

    [Fact]
    public async Task Wrong_secret_hides_whether_the_claim_identity_matches()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)6, 32).ToArray();
        var wrongSecret = Enumerable.Repeat((byte)8, 32).ToArray();
        var claim = Claim();
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10));

        var matching = await Repository.VerifyAsync(claim, wrongSecret, DateTimeOffset.UtcNow, CancellationToken.None);
        var mismatched = await Repository.VerifyAsync(
            claim with { PublicKeyDigest = Digest('f') },
            wrongSecret,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal(
            "unauthenticated-enrollment-claim",
            Assert.IsType<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Failure>(matching).Error.Code);
        Assert.Equal(
            FailureCode(matching),
            FailureCode(mismatched));
    }

    [Fact]
    public async Task Queued_reservation_cannot_authorise_issuance_after_database_expiry()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)11, 32).ToArray();
        var claim = Claim();
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddSeconds(1));
        await using var lockConnection = await (dataSource ?? throw new InvalidOperationException()).OpenConnectionAsync();
        await using var lockTransaction = await lockConnection.BeginTransactionAsync();
        await using (var lockClaim = new NpgsqlCommand(
            "SELECT claim_id FROM armada_enrollment_claims WHERE claim_id = @claimId FOR UPDATE;",
            lockConnection,
            lockTransaction))
        {
            lockClaim.Parameters.AddWithValue("claimId", claim.ClaimId);
            await lockClaim.ExecuteNonQueryAsync();
        }

        var reservation = Repository.ReserveAsync(
            claim,
            secret,
            Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(-2),
            CancellationToken.None);
        await Task.Delay(TimeSpan.FromMilliseconds(1200));
        await lockTransaction.CommitAsync();
        var result = await reservation;

        Assert.Equal(
            "enrollment-claim-expired",
            Assert.IsType<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure>(result).Error.Code);
    }

    [Fact]
    public async Task Direct_claim_consumption_and_identity_registration_cannot_bypass_atomic_binding()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)4, 32).ToArray();
        var claim = Claim();
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10));
        var directConsumption = await Repository.ConsumeAsync(claim, secret, CancellationToken.None);
        var directRegistration = await Repository.RegisterAsync(
            Completion(claim, secret).Identity,
            CancellationToken.None);

        Assert.Equal(
            "atomic-identity-binding-required",
            Assert.IsType<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>.Failure>(directConsumption).Error.Code);
        Assert.Equal(
            "direct-identity-registration-disabled",
            Assert.IsType<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure>(directRegistration).Error.Code);
        Assert.False(Assert.IsType<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>.Success>(
            await Repository.GetAsync(claim.ClaimId, CancellationToken.None)).Value.IsConsumed);
    }

    private PostgresNodeEnrollmentStateRepository Repository =>
        repository ?? throw new InvalidOperationException("The PostgreSQL repository was not initialised.");

    private async Task<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>> CompleteAfterStartAsync(
        EnrollmentCompletionRequest request,
        Task start)
    {
        await start;
        return await Repository.CompleteAsync(request, CancellationToken.None);
    }

    private async Task<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>> ReserveAfterStartAsync(
        EnrollmentCompletionRequest request,
        Task start)
    {
        await start;
        return await Repository.ReserveAsync(
            request.Claim,
            request.PresentedSecret,
            request.RequestId,
            request.OccurredAt,
            CancellationToken.None);
    }

    private async Task ResetAsync()
    {
        await using var connection = await (dataSource ?? throw new InvalidOperationException()).OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            """
            TRUNCATE armada_node_transport_outbox, armada_node_transport_audit,
                     armada_transport_replay_receipts, armada_node_certificate_identities,
                     armada_enrollment_claims;
            """,
            connection);
        await command.ExecuteNonQueryAsync();
    }

    private async Task SeedClaimAsync(
        EnrollmentClaimReference claim,
        byte[] secret,
        DateTimeOffset expiresAt)
    {
        await using var connection = await (dataSource ?? throw new InvalidOperationException()).OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO armada_enrollment_claims
                (claim_id, secret_verifier, intended_node_uid, intended_identity_epoch,
                 intended_public_key_digest, intended_assurance, expires_at)
            VALUES
                (@claimId, @verifier, @nodeUid, @identityEpoch,
                 @publicKeyDigest, CAST(@assurance AS jsonb), @expiresAt);
            """,
            connection);
        command.Parameters.AddWithValue("claimId", claim.ClaimId);
        command.Parameters.AddWithValue("verifier", SHA256.HashData(secret));
        command.Parameters.AddWithValue("nodeUid", claim.NodeUid.Value);
        command.Parameters.AddWithValue("identityEpoch", claim.IdentityEpoch);
        command.Parameters.AddWithValue("publicKeyDigest", claim.PublicKeyDigest.Value);
        command.Parameters.AddWithValue("assurance", """{"profile":"lab"}""");
        command.Parameters.AddWithValue("expiresAt", expiresAt);
        await command.ExecuteNonQueryAsync();
    }

    private async Task SeedReservationAsync(Guid claimId, Guid requestId, DateTimeOffset expiresAt)
    {
        await using var connection = await (dataSource ?? throw new InvalidOperationException()).OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            """
            UPDATE armada_enrollment_claims
            SET issuance_request_id = @requestId,
                issuance_reserved_at = @reservedAt,
                issuance_reservation_expires_at = @expiresAt
            WHERE claim_id = @claimId;
            """,
            connection);
        command.Parameters.AddWithValue("claimId", claimId);
        command.Parameters.AddWithValue("requestId", requestId);
        command.Parameters.AddWithValue("reservedAt", DateTimeOffset.UtcNow.AddMinutes(-2));
        command.Parameters.AddWithValue("expiresAt", expiresAt);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<long> CountAsync(string table)
    {
        await using var connection = await (dataSource ?? throw new InvalidOperationException()).OpenConnectionAsync();
        await using var command = new NpgsqlCommand($"SELECT COUNT(*) FROM {table};", connection);
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static EnrollmentClaimReference Claim() =>
        new(Guid.NewGuid(), new NodeUid(Guid.NewGuid()), 1, Digest('a'));

    private static EnrollmentCompletionRequest Completion(
        EnrollmentClaimReference claim,
        ReadOnlyMemory<byte> secret)
    {
        var correlationId = Guid.NewGuid();
        var expiry = DateTimeOffset.UtcNow.AddHours(1);
        var identity = new NodeIdentityBinding(
            claim.NodeUid,
            claim.IdentityEpoch,
            claim.PublicKeyDigest,
            "ABCD",
            new string('B', 64),
            expiry,
            false);
        return new EnrollmentCompletionRequest(
            claim,
            secret,
            identity,
            new EnrollmentResponseDto(
                NodeTransportProtocol.Version,
                claim.NodeUid.ToString(),
                claim.IdentityEpoch,
                identity.CertificateSerial,
                expiry,
                ImmutableArray.Create<byte>(1, 2),
                ImmutableArray.Create<byte>(3, 4),
                correlationId.ToString("D")),
            Guid.NewGuid(),
            correlationId,
            DateTimeOffset.UtcNow);
    }

    private static ReplayReceipt Receipt(char digestCharacter)
    {
        var messageId = Guid.NewGuid();
        var correlationId = Guid.NewGuid();
        var identity = new ReplayIdentity(
            new NodeUid(Guid.NewGuid()),
            1,
            1,
            1,
            messageId,
            correlationId,
            "receipt-1",
            NodeTransportProtocol.Version,
            TransportPayloadKind.Hello,
            DateTimeOffset.UtcNow,
            Digest(digestCharacter));
        return new ReplayReceipt(
            identity,
            new TransportAcknowledgement(messageId, correlationId, "receipt-1", true, "accepted", "Recorded."));
    }

    private static Sha256Digest Digest(char character) =>
        Sha256Digest.Parse($"sha256:{new string(character, 64)}") is Result<Sha256Digest, ContractValidationError>.Success digest
            ? digest.Value
            : throw new InvalidOperationException("Test digest is invalid.");

    private static string FailureCode<T>(Result<T, EnrollmentClaimStoreFailure> result) =>
        Assert.IsType<Result<T, EnrollmentClaimStoreFailure>.Failure>(result).Error.Code;
}

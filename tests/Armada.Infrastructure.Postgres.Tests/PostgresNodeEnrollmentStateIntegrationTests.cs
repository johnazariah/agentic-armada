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
    public async Task Concurrent_same_claim_binds_one_identity_and_returns_the_durable_response()
    {
        await ResetAsync();
        var secret = Enumerable.Repeat((byte)7, 32).ToArray();
        var claim = Claim();
        await SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10));
        var request = Completion(claim, secret);
        var competingRequest = request with { RequestId = Guid.NewGuid() };
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reservations = new[]
        {
            ReserveAfterStartAsync(request, start.Task),
            ReserveAfterStartAsync(competingRequest, start.Task)
        };
        start.SetResult();
        var reservationResults = await Task.WhenAll(reservations);
        Assert.Equal(1, reservationResults.Count(static result => result is Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success));
        Assert.Equal(
            "enrollment-claim-in-progress",
            Assert.IsType<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure>(
                Assert.Single(reservationResults, static result => result is Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Failure)).Error.Code);
        var winner = reservationResults[0] is Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success
            ? request
            : competingRequest;

        var completions = new[]
        {
            CompleteAfterStartAsync(winner, Task.CompletedTask),
            CompleteAfterStartAsync(winner, Task.CompletedTask)
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
        Assert.Equal(
            request.Response,
            Assert.IsType<EnrollmentCompletion.AlreadyCompleted>(replay).Response);
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
}

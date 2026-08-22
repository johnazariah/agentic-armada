using System.Text.Json;
using Armada.Application;
using Armada.Contracts;
using Npgsql;

namespace Armada.Infrastructure.Postgres;

public sealed class PostgresResourceRepository(NpgsqlDataSource dataSource) : IResourceRepository
{
    public async Task<PersistedResource?> GetAsync(ResourceId id, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            SELECT uid, kind, organisation_id, project_id, name, generation, resource_version,
                   document::text, created_at, updated_at
            FROM armada_current_resources
            WHERE uid = @uid;
            """,
            connection);
        command.Parameters.AddWithValue("uid", id.Value);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadResource(reader) : null;
    }

    public async Task<ResourceCommit?> FindByIdempotencyKeyAsync(
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var commit = await FindCommitByIdempotencyKeyAsync(connection, transaction, idempotencyKey, cancellationToken);
        await transaction.RollbackAsync(cancellationToken);
        return commit;
    }

    public Task<ResourceStoreResult> CreateAsync(ResourceCommit commit, CancellationToken cancellationToken) =>
        CommitAsync(commit, null, cancellationToken);

    public Task<ResourceStoreResult> CompareAndSwapAsync(
        ResourceCommit commit,
        ResourceVersion expectedVersion,
        CancellationToken cancellationToken) =>
        CommitAsync(commit, expectedVersion, cancellationToken);

    private async Task<ResourceStoreResult> CommitAsync(
        ResourceCommit commit,
        ResourceVersion? expectedVersion,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        var prior = await FindCommitByIdempotencyKeyAsync(
            connection,
            transaction,
            commit.LedgerEvent.IdempotencyKey,
            cancellationToken);
        if (prior is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new ResourceStoreResult.AlreadyApplied(prior);
        }

        var changed = expectedVersion is null
            ? await InsertResourceAsync(connection, transaction, commit.Resource, cancellationToken)
            : await UpdateResourceAsync(connection, transaction, commit.Resource, expectedVersion.Value, cancellationToken);

        if (!changed)
        {
            var concurrentlyCommitted = await FindCommitByIdempotencyKeyAsync(
                connection,
                transaction,
                commit.LedgerEvent.IdempotencyKey,
                cancellationToken);
            if (concurrentlyCommitted is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new ResourceStoreResult.AlreadyApplied(concurrentlyCommitted);
            }

            var actual = await GetVersionAsync(connection, transaction, commit.Resource.Id, cancellationToken);
            await transaction.RollbackAsync(cancellationToken);
            return new ResourceStoreResult.Conflict(actual);
        }

        await AppendLedgerAndOutboxAsync(connection, transaction, commit, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new ResourceStoreResult.Committed(commit);
    }

    private static async Task<bool> InsertResourceAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        PersistedResource resource,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO armada_current_resources
                (uid, kind, organisation_id, project_id, name, generation, resource_version, document, created_at, updated_at)
            VALUES
                (@uid, @kind, @organisationId, @projectId, @name, @generation, @resourceVersion, CAST(@document AS jsonb), @createdAt, @updatedAt)
            ON CONFLICT DO NOTHING;
            """,
            connection,
            transaction);
        AddResourceParameters(command, resource);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static async Task<bool> UpdateResourceAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        PersistedResource resource,
        ResourceVersion expectedVersion,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            PostgresResourceSql.CompareAndSwapResource,
            connection,
            transaction);
        AddResourceParameters(command, resource);
        command.Parameters.AddWithValue("expectedVersion", expectedVersion.Value);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static async Task AppendLedgerAndOutboxAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ResourceCommit commit,
        CancellationToken cancellationToken)
    {
        await using (var ledger = new NpgsqlCommand(
            """
            INSERT INTO armada_event_ledger
                (event_id, resource_id, event_type, actor, correlation_id, causation_id, idempotency_key, occurred_at, payload, commit_snapshot)
            VALUES
                (@eventId, @resourceId, @eventType, @actor, @correlationId, @causationId, @idempotencyKey, @occurredAt, CAST(@payload AS jsonb), CAST(@commitSnapshot AS jsonb));
            """,
            connection,
            transaction))
        {
            AddLedgerParameters(ledger, commit);
            await ledger.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var outbox = new NpgsqlCommand(
            """
            INSERT INTO armada_outbox (message_id, event_id, message_type, idempotency_key, occurred_at, payload)
            VALUES (@messageId, @eventId, @messageType, @idempotencyKey, @occurredAt, CAST(@payload AS jsonb));
            """,
            connection,
            transaction);
        outbox.Parameters.AddWithValue("messageId", commit.OutboxMessage.Id);
        outbox.Parameters.AddWithValue("eventId", commit.LedgerEvent.Id);
        outbox.Parameters.AddWithValue("messageType", commit.OutboxMessage.Type);
        outbox.Parameters.AddWithValue("idempotencyKey", commit.OutboxMessage.IdempotencyKey);
        outbox.Parameters.AddWithValue("occurredAt", commit.OutboxMessage.OccurredAt);
        outbox.Parameters.AddWithValue("payload", commit.OutboxMessage.Payload.GetRawText());
        await outbox.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<ResourceCommit?> FindCommitByIdempotencyKeyAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            PostgresResourceSql.FindCommitByIdempotency,
            connection,
            transaction);
        command.Parameters.AddWithValue("idempotencyKey", idempotencyKey);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return JsonSerializer.Deserialize<ResourceCommit>(reader.GetString(0))
            ?? throw new InvalidOperationException("The immutable commit snapshot could not be deserialised.");
    }

    private static async Task<ResourceVersion?> GetVersionAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ResourceId id,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT resource_version FROM armada_current_resources WHERE uid = @uid;",
            connection,
            transaction);
        command.Parameters.AddWithValue("uid", id.Value);
        var version = await command.ExecuteScalarAsync(cancellationToken);
        return version is string value ? new ResourceVersion(value) : null;
    }

    private static void AddResourceParameters(NpgsqlCommand command, PersistedResource resource)
    {
        command.Parameters.AddWithValue("uid", resource.Id.Value);
        command.Parameters.AddWithValue("kind", resource.Kind);
        command.Parameters.AddWithValue("organisationId", resource.OrganisationId.Value);
        command.Parameters.AddWithValue("projectId", resource.ProjectId?.Value ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("name", resource.Name);
        command.Parameters.AddWithValue("generation", resource.Generation);
        command.Parameters.AddWithValue("resourceVersion", resource.ResourceVersion.Value);
        command.Parameters.AddWithValue("document", resource.Document.GetRawText());
        command.Parameters.AddWithValue("createdAt", resource.CreatedAt);
        command.Parameters.AddWithValue("updatedAt", resource.UpdatedAt);
    }

    private static void AddLedgerParameters(NpgsqlCommand command, ResourceCommit commit)
    {
        var ledgerEvent = commit.LedgerEvent;
        command.Parameters.AddWithValue("eventId", ledgerEvent.Id);
        command.Parameters.AddWithValue("resourceId", ledgerEvent.ResourceId.Value);
        command.Parameters.AddWithValue("eventType", ledgerEvent.Type);
        command.Parameters.AddWithValue("actor", ledgerEvent.Actor.Value);
        command.Parameters.AddWithValue("correlationId", ledgerEvent.CorrelationId);
        command.Parameters.AddWithValue("causationId", ledgerEvent.CausationId ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("idempotencyKey", ledgerEvent.IdempotencyKey);
        command.Parameters.AddWithValue("occurredAt", ledgerEvent.OccurredAt);
        command.Parameters.AddWithValue("payload", ledgerEvent.Payload.GetRawText());
        command.Parameters.AddWithValue("commitSnapshot", JsonSerializer.Serialize(commit));
    }

    private static PersistedResource ReadResource(NpgsqlDataReader reader) =>
        new(
            new(reader.GetGuid(0)),
            reader.GetString(1),
            new(reader.GetGuid(2)),
            reader.IsDBNull(3) ? null : new ProjectId(reader.GetGuid(3)),
            reader.GetString(4),
            reader.GetInt64(5),
            new(reader.GetString(6)),
            JsonDocument.Parse(reader.GetString(7)).RootElement.Clone(),
            reader.GetFieldValue<DateTimeOffset>(8),
            reader.GetFieldValue<DateTimeOffset>(9));
}

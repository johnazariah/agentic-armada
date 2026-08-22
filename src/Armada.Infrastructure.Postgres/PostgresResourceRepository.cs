using System.Text.Json;
using System.Diagnostics.CodeAnalysis;
using Armada.Application;
using Armada.Contracts;
using Npgsql;

namespace Armada.Infrastructure.Postgres;

// This thin boundary executes the SQL contracts tested without an available local PostgreSQL service.
[ExcludeFromCodeCoverage(Justification = "Requires a live PostgreSQL service; deterministic port and SQL contract tests cover CAS and atomicity semantics.")]
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
                (event_id, resource_id, event_type, actor, correlation_id, causation_id, idempotency_key, occurred_at, payload)
            VALUES
                (@eventId, @resourceId, @eventType, @actor, @correlationId, @causationId, @idempotencyKey, @occurredAt, CAST(@payload AS jsonb));
            """,
            connection,
            transaction))
        {
            AddLedgerParameters(ledger, commit.LedgerEvent);
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
            """
            SELECT r.uid, r.kind, r.organisation_id, r.project_id, r.name, r.generation, r.resource_version,
                   r.document::text, r.created_at, r.updated_at,
                   e.event_id, e.resource_id, e.event_type, e.actor, e.correlation_id, e.causation_id,
                   e.idempotency_key, e.occurred_at, e.payload::text,
                   o.message_id, o.message_type, o.idempotency_key, o.occurred_at, o.payload::text
            FROM armada_event_ledger e
            JOIN armada_current_resources r ON r.uid = e.resource_id
            JOIN armada_outbox o ON o.event_id = e.event_id
            WHERE e.idempotency_key = @idempotencyKey;
            """,
            connection,
            transaction);
        command.Parameters.AddWithValue("idempotencyKey", idempotencyKey);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var resource = ReadResource(reader);
        var payload = JsonDocument.Parse(reader.GetString(18)).RootElement.Clone();
        var ledger = new LedgerEvent(
            reader.GetGuid(10),
            new(reader.GetGuid(11)),
            reader.GetString(12),
            new(reader.GetString(13)),
            reader.GetGuid(14),
            reader.IsDBNull(15) ? null : reader.GetGuid(15),
            reader.GetString(16),
            reader.GetFieldValue<DateTimeOffset>(17),
            payload);
        var outbox = new OutboxMessage(
            reader.GetGuid(19),
            reader.GetString(20),
            reader.GetString(21),
            reader.GetFieldValue<DateTimeOffset>(22),
            JsonDocument.Parse(reader.GetString(23)).RootElement.Clone());
        return new(resource, ledger, outbox);
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

    private static void AddLedgerParameters(NpgsqlCommand command, LedgerEvent ledgerEvent)
    {
        command.Parameters.AddWithValue("eventId", ledgerEvent.Id);
        command.Parameters.AddWithValue("resourceId", ledgerEvent.ResourceId.Value);
        command.Parameters.AddWithValue("eventType", ledgerEvent.Type);
        command.Parameters.AddWithValue("actor", ledgerEvent.Actor.Value);
        command.Parameters.AddWithValue("correlationId", ledgerEvent.CorrelationId);
        command.Parameters.AddWithValue("causationId", ledgerEvent.CausationId ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("idempotencyKey", ledgerEvent.IdempotencyKey);
        command.Parameters.AddWithValue("occurredAt", ledgerEvent.OccurredAt);
        command.Parameters.AddWithValue("payload", ledgerEvent.Payload.GetRawText());
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

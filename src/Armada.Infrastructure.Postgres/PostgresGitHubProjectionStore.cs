using System.Text.Json;
using Armada.Application;
using Armada.Contracts;
using Npgsql;

namespace Armada.Infrastructure.Postgres;

public sealed class PostgresCommittedOutboxEventReader(NpgsqlDataSource dataSource) : ICommittedOutboxEventReader
{
    public async Task<IReadOnlyList<CommittedOutboxEvent>> ReadAsync(
        int maximumCount,
        CancellationToken cancellationToken)
    {
        if (maximumCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount), "The maximum event count must be positive.");
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            SELECT ledger.commit_snapshot::text
            FROM armada_outbox AS outbox
            INNER JOIN armada_event_ledger AS ledger ON ledger.event_id = outbox.event_id
            ORDER BY outbox.occurred_at, outbox.message_id
            LIMIT @maximumCount;
            """,
            connection);
        command.Parameters.AddWithValue("maximumCount", maximumCount);

        var events = new List<CommittedOutboxEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var commit = JsonSerializer.Deserialize<ResourceCommit>(reader.GetString(0))
                ?? throw new InvalidOperationException("The immutable outbox commit snapshot could not be deserialised.");
            events.Add(new CommittedOutboxEvent(commit.LedgerEvent, commit.OutboxMessage, commit.Resource));
        }

        return events;
    }
}

public sealed class PostgresGitHubProjectionReceiptStore(NpgsqlDataSource dataSource) : IGitHubProjectionReceiptStore
{
    public async Task<GitHubProjectionReceipt?> FindAsync(
        Guid sourceEventId,
        GitHubProjectionTarget target,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        return await FindAsync(connection, sourceEventId, target, cancellationToken);
    }

    public async Task<GitHubProjectionReceipt> RecordAsync(
        GitHubProjectionReceipt receipt,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO armada_github_projection_receipts
                (source_event_id, repository, issue_number, summary_name, idempotency_key, content_digest, external_reference, recorded_at)
            VALUES
                (@sourceEventId, @repository, @issueNumber, @summaryName, @idempotencyKey, @contentDigest, @externalReference, @recordedAt)
            ON CONFLICT DO NOTHING;
            """,
            connection,
            transaction);
        AddParameters(command, receipt);
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        if (inserted == 1)
        {
            await transaction.CommitAsync(cancellationToken);
            return receipt;
        }

        await transaction.RollbackAsync(cancellationToken);
        return await FindAsync(connection, receipt.SourceEventId, receipt.Target, cancellationToken)
            ?? throw new InvalidOperationException("A conflicting projection receipt disappeared before it could be read.");
    }

    private static async Task<GitHubProjectionReceipt?> FindAsync(
        NpgsqlConnection connection,
        Guid sourceEventId,
        GitHubProjectionTarget target,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT idempotency_key, content_digest, external_reference, recorded_at
            FROM armada_github_projection_receipts
            WHERE source_event_id = @sourceEventId
              AND repository = @repository
              AND issue_number = @issueNumber
              AND summary_name = @summaryName;
            """,
            connection);
        command.Parameters.AddWithValue("sourceEventId", sourceEventId);
        command.Parameters.AddWithValue("repository", target.Repository.Value);
        command.Parameters.AddWithValue("issueNumber", target.IssueNumber);
        command.Parameters.AddWithValue("summaryName", target.SummaryName);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var digest = Sha256Digest.Parse(reader.GetString(1));
        if (digest is not Result<Sha256Digest, ContractValidationError>.Success validDigest)
        {
            throw new InvalidOperationException("A persisted projection receipt has an invalid content digest.");
        }

        return new GitHubProjectionReceipt(
            sourceEventId,
            target,
            reader.GetString(0),
            validDigest.Value,
            reader.GetString(2),
            reader.GetFieldValue<DateTimeOffset>(3));
    }

    private static void AddParameters(NpgsqlCommand command, GitHubProjectionReceipt receipt)
    {
        command.Parameters.AddWithValue("sourceEventId", receipt.SourceEventId);
        command.Parameters.AddWithValue("repository", receipt.Target.Repository.Value);
        command.Parameters.AddWithValue("issueNumber", receipt.Target.IssueNumber);
        command.Parameters.AddWithValue("summaryName", receipt.Target.SummaryName);
        command.Parameters.AddWithValue("idempotencyKey", receipt.IdempotencyKey);
        command.Parameters.AddWithValue("contentDigest", receipt.ContentDigest.Value);
        command.Parameters.AddWithValue("externalReference", receipt.ExternalReference);
        command.Parameters.AddWithValue("recordedAt", receipt.RecordedAt);
    }
}

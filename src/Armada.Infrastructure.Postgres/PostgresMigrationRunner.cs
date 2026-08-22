using Npgsql;

namespace Armada.Infrastructure.Postgres;

public sealed class PostgresMigrationRunner(NpgsqlDataSource dataSource)
{
    public async Task ApplyAsync(DateTimeOffset appliedAt, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var initialise = new NpgsqlCommand(
            "CREATE TABLE IF NOT EXISTS armada_schema_migrations (version BIGINT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL);",
            connection,
            transaction))
        {
            await initialise.ExecuteNonQueryAsync(cancellationToken);
        }

        foreach (var migration in PostgresSchema.Migrations)
        {
            await using var exists = new NpgsqlCommand(
                "SELECT EXISTS (SELECT 1 FROM armada_schema_migrations WHERE version = @version);",
                connection,
                transaction);
            exists.Parameters.AddWithValue("version", migration.Version);
            if ((bool)(await exists.ExecuteScalarAsync(cancellationToken) ?? false))
            {
                continue;
            }

            await using (var apply = new NpgsqlCommand(migration.Sql, connection, transaction))
            {
                await apply.ExecuteNonQueryAsync(cancellationToken);
            }

            await using var record = new NpgsqlCommand(
                "INSERT INTO armada_schema_migrations (version, applied_at) VALUES (@version, @appliedAt);",
                connection,
                transaction);
            record.Parameters.AddWithValue("version", migration.Version);
            record.Parameters.AddWithValue("appliedAt", appliedAt);
            await record.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }
}

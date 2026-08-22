using Armada.Infrastructure.Postgres;

namespace Armada.Infrastructure.Postgres.Tests;

public sealed class PostgresSchemaTests
{
    [Fact]
    public void Migration_creates_authoritative_current_state_with_CAS_column()
    {
        var sql = PostgresSchema.Migrations.Single(static migration => migration.Version == 1).Sql;

        Assert.Contains("CREATE TABLE IF NOT EXISTS armada_current_resources", sql, StringComparison.Ordinal);
        Assert.Contains("resource_version TEXT NOT NULL", sql, StringComparison.Ordinal);
        Assert.Contains("generation BIGINT NOT NULL CHECK (generation > 0)", sql, StringComparison.Ordinal);
        Assert.Contains("document JSONB NOT NULL", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Migration_binds_ledger_and_outbox_to_the_same_transactional_event()
    {
        var sql = PostgresSchema.Migrations.Single(static migration => migration.Version == 1).Sql;

        Assert.Contains("CREATE TABLE IF NOT EXISTS armada_event_ledger", sql, StringComparison.Ordinal);
        Assert.Contains("CREATE TABLE IF NOT EXISTS armada_outbox", sql, StringComparison.Ordinal);
        Assert.Contains("event_id UUID NOT NULL UNIQUE REFERENCES armada_event_ledger(event_id)", sql, StringComparison.Ordinal);
        Assert.Contains("idempotency_key TEXT NOT NULL UNIQUE", sql, StringComparison.Ordinal);
        Assert.Contains("commit_snapshot JSONB NOT NULL", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Migration_prevents_ledger_rewrites()
    {
        var sql = PostgresSchema.Migrations.Single(static migration => migration.Version == 1).Sql;

        Assert.Contains("armada_event_ledger is append-only", sql, StringComparison.Ordinal);
        Assert.Contains("BEFORE UPDATE OR DELETE ON armada_event_ledger", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Repository_CAS_contract_updates_only_the_expected_resource_version()
    {
        var sql = PostgresResourceSql.CompareAndSwapResource;

        Assert.Contains("UPDATE armada_current_resources", sql, StringComparison.Ordinal);
        Assert.Contains("WHERE uid = @uid AND resource_version = @expectedVersion", sql, StringComparison.Ordinal);
        Assert.Contains("resource_version = @resourceVersion", sql, StringComparison.Ordinal);
        Assert.Contains("document = CAST(@document AS jsonb)", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Replay_lookup_uses_the_immutable_commit_snapshot_not_current_resource_state()
    {
        var sql = PostgresResourceSql.FindCommitByIdempotency;

        Assert.Contains("SELECT commit_snapshot::text", sql, StringComparison.Ordinal);
        Assert.Contains("FROM armada_event_ledger", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("armada_current_resources", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void Pending_projection_query_never_replays_acknowledged_outbox_messages()
    {
        Assert.Contains("WHERE outbox.dispatched_at IS NULL", PostgresOutboxSql.PendingEvents, StringComparison.Ordinal);
        Assert.Contains("SET dispatched_at = @dispatchedAt", PostgresOutboxSql.Acknowledge, StringComparison.Ordinal);
        Assert.Contains("dispatch_attempts = dispatch_attempts + 1", PostgresOutboxSql.Acknowledge, StringComparison.Ordinal);
    }

    [Fact]
    public void Projection_receipt_migration_binds_receipts_to_immutable_ledger_events()
    {
        var sql = PostgresSchema.Migrations.Single(static migration => migration.Version == 2).Sql;

        Assert.Contains("CREATE TABLE IF NOT EXISTS armada_github_projection_receipts", sql, StringComparison.Ordinal);
        Assert.Contains("source_event_id UUID NOT NULL REFERENCES armada_event_ledger(event_id)", sql, StringComparison.Ordinal);
        Assert.Contains("PRIMARY KEY (source_event_id, repository, issue_number, summary_name)", sql, StringComparison.Ordinal);
    }
}

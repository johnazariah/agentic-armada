namespace Armada.Infrastructure.Postgres;

public sealed record PostgresMigration(long Version, string Name, string Sql);

public static class PostgresSchema
{
    public static IReadOnlyList<PostgresMigration> Migrations { get; } =
    [
        new(
            1,
            "authoritative-resource-ledger-outbox",
            """
            CREATE TABLE IF NOT EXISTS armada_schema_migrations (
                version BIGINT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS armada_current_resources (
                uid UUID PRIMARY KEY,
                kind TEXT NOT NULL,
                organisation_id UUID NOT NULL,
                project_id UUID NULL,
                name TEXT NOT NULL,
                generation BIGINT NOT NULL CHECK (generation > 0),
                resource_version TEXT NOT NULL,
                document JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                UNIQUE (organisation_id, project_id, kind, name)
            );

            CREATE TABLE IF NOT EXISTS armada_event_ledger (
                sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                event_id UUID NOT NULL UNIQUE,
                resource_id UUID NOT NULL REFERENCES armada_current_resources(uid),
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                correlation_id UUID NOT NULL,
                causation_id UUID NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                occurred_at TIMESTAMPTZ NOT NULL,
                payload JSONB NOT NULL,
                commit_snapshot JSONB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS armada_outbox (
                message_id UUID PRIMARY KEY,
                event_id UUID NOT NULL UNIQUE REFERENCES armada_event_ledger(event_id),
                message_type TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                occurred_at TIMESTAMPTZ NOT NULL,
                payload JSONB NOT NULL,
                dispatched_at TIMESTAMPTZ NULL,
                dispatch_attempts INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_attempts >= 0)
            );

            CREATE OR REPLACE FUNCTION armada_reject_ledger_mutation()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'armada_event_ledger is append-only';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS armada_event_ledger_no_update ON armada_event_ledger;
            CREATE TRIGGER armada_event_ledger_no_update
                BEFORE UPDATE OR DELETE ON armada_event_ledger
                FOR EACH ROW EXECUTE FUNCTION armada_reject_ledger_mutation();
            """)
    ];
}

public static class PostgresResourceSql
{
    public const string CompareAndSwapResource =
        """
        UPDATE armada_current_resources
        SET generation = @generation,
            resource_version = @resourceVersion,
            document = CAST(@document AS jsonb),
            updated_at = @updatedAt
        WHERE uid = @uid AND resource_version = @expectedVersion;
        """;

    public const string FindCommitByIdempotency =
        """
        SELECT commit_snapshot::text
        FROM armada_event_ledger
        WHERE idempotency_key = @idempotencyKey;
        """;
}

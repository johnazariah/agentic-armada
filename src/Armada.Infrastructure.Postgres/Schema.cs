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
            """),
        new(
            2,
            "github-projection-receipts",
            """
            CREATE TABLE IF NOT EXISTS armada_github_projection_receipts (
                source_event_id UUID NOT NULL REFERENCES armada_event_ledger(event_id),
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK (issue_number > 0),
                summary_name TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                external_reference TEXT NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (source_event_id, repository, issue_number, summary_name)
            );
            """),
        new(
            3,
            "node-enrolment-identity-replay-evidence",
            """
            CREATE TABLE IF NOT EXISTS armada_enrollment_claims (
                claim_id UUID PRIMARY KEY,
                secret_verifier BYTEA NOT NULL CHECK (octet_length(secret_verifier) = 32),
                intended_node_uid UUID NOT NULL,
                intended_identity_epoch BIGINT NOT NULL CHECK (intended_identity_epoch > 0),
                intended_public_key_digest TEXT NOT NULL CHECK (intended_public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
                intended_assurance JSONB NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                issuance_request_id UUID NULL,
                issuance_reserved_at TIMESTAMPTZ NULL,
                issuance_reservation_expires_at TIMESTAMPTZ NULL,
                consumed_at TIMESTAMPTZ NULL,
                consumption_correlation_id UUID NULL,
                consumption_result JSONB NULL,
                CHECK (
                    (consumed_at IS NULL AND consumption_correlation_id IS NULL AND consumption_result IS NULL) OR
                    (consumed_at IS NOT NULL AND consumption_correlation_id IS NOT NULL AND consumption_result IS NOT NULL)
                ),
                CHECK (
                    (issuance_request_id IS NULL AND issuance_reserved_at IS NULL AND issuance_reservation_expires_at IS NULL) OR
                    (issuance_request_id IS NOT NULL AND issuance_reserved_at IS NOT NULL AND issuance_reservation_expires_at > issuance_reserved_at)
                )
            );

            CREATE TABLE IF NOT EXISTS armada_node_certificate_identities (
                node_uid UUID NOT NULL,
                identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
                public_key_digest TEXT NOT NULL CHECK (public_key_digest ~ '^sha256:[0-9a-f]{64}$'),
                certificate_serial TEXT NOT NULL CHECK (certificate_serial ~ '^[0-9A-F]+$' AND length(certificate_serial) % 2 = 0),
                certificate_thumbprint_sha256 TEXT NOT NULL CHECK (certificate_thumbprint_sha256 ~ '^[0-9A-F]{64}$'),
                issued_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > issued_at),
                revoked_at TIMESTAMPTZ NULL,
                revocation_reason TEXT NULL,
                enrollment_response JSONB NOT NULL,
                PRIMARY KEY (node_uid, identity_epoch),
                UNIQUE (certificate_serial),
                UNIQUE (certificate_thumbprint_sha256),
                CHECK (
                    (revoked_at IS NULL AND revocation_reason IS NULL) OR
                    (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
                )
            );

            CREATE TABLE IF NOT EXISTS armada_transport_replay_receipts (
                node_uid UUID NOT NULL,
                identity_epoch BIGINT NOT NULL CHECK (identity_epoch > 0),
                stream_epoch BIGINT NOT NULL CHECK (stream_epoch > 0),
                sequence BIGINT NOT NULL CHECK (sequence > 0),
                message_id UUID NOT NULL,
                correlation_id UUID NOT NULL,
                idempotency_key TEXT NOT NULL,
                protocol_version TEXT NOT NULL,
                payload_kind TEXT NOT NULL,
                sent_at TIMESTAMPTZ NOT NULL,
                sent_at_ticks BIGINT NOT NULL,
                payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
                acknowledgement JSONB NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (node_uid, identity_epoch, stream_epoch, sequence),
                UNIQUE (node_uid, identity_epoch, message_id),
                UNIQUE (node_uid, identity_epoch, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS armada_node_transport_audit (
                event_id UUID PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                correlation_id UUID NOT NULL,
                causation_id UUID NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                occurred_at TIMESTAMPTZ NOT NULL,
                payload JSONB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS armada_node_transport_outbox (
                message_id UUID PRIMARY KEY,
                event_id UUID NOT NULL UNIQUE REFERENCES armada_node_transport_audit(event_id),
                message_type TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                occurred_at TIMESTAMPTZ NOT NULL,
                payload JSONB NOT NULL,
                dispatched_at TIMESTAMPTZ NULL,
                dispatch_attempts INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_attempts >= 0)
            );

            CREATE OR REPLACE FUNCTION armada_reject_transport_audit_mutation()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'armada_node_transport_audit is append-only';
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS armada_node_transport_audit_no_update ON armada_node_transport_audit;
            CREATE TRIGGER armada_node_transport_audit_no_update
                BEFORE UPDATE OR DELETE ON armada_node_transport_audit
                FOR EACH ROW EXECUTE FUNCTION armada_reject_transport_audit_mutation();

            CREATE OR REPLACE FUNCTION armada_restrict_certificate_identity_mutation()
            RETURNS TRIGGER AS $$
            BEGIN
                IF TG_OP = 'DELETE' OR
                   OLD.node_uid <> NEW.node_uid OR
                   OLD.identity_epoch <> NEW.identity_epoch OR
                   OLD.public_key_digest <> NEW.public_key_digest OR
                   OLD.certificate_serial <> NEW.certificate_serial OR
                   OLD.certificate_thumbprint_sha256 <> NEW.certificate_thumbprint_sha256 OR
                   OLD.issued_at <> NEW.issued_at OR
                   OLD.expires_at <> NEW.expires_at OR
                   OLD.enrollment_response <> NEW.enrollment_response OR
                   OLD.revoked_at IS NOT NULL OR
                   NEW.revoked_at IS NULL OR
                   NEW.revocation_reason IS NULL THEN
                    RAISE EXCEPTION 'certificate identity is immutable except controller revocation';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS armada_node_certificate_identity_restricted_update ON armada_node_certificate_identities;
            CREATE TRIGGER armada_node_certificate_identity_restricted_update
                BEFORE UPDATE OR DELETE ON armada_node_certificate_identities
                FOR EACH ROW EXECUTE FUNCTION armada_restrict_certificate_identity_mutation();
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

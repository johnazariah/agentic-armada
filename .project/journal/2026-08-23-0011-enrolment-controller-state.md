# Durable enrolment controller state

PR B adds PostgreSQL migration 3 and one controller-side repository for the
existing enrolment, certificate-identity and transport-replay ports. Claims retain
only SHA-256 verifiers. A request-bound, expiring reservation prevents concurrent
issuers from proceeding. The durable completion operation locks the claim and commits
identity, consumption result, immutable audit event and outbox message together.

The repository deliberately refuses the older direct consume/register paths:
without a certificate binding they cannot preserve the at-most-one transition.
Replay is exact only when the full persisted identity matches; sequence, message,
idempotency or payload changes are a typed conflict. Revocation is a controller
operation and the identity row permits no other mutation.

Integration coverage uses `ARMADA_POSTGRES_CONNECTION` for concurrent same-claim
completion, exact/changed replay, expired/wrong/revoked identity refusals and
reconnect reads. PR C remains responsible for a lab CA, request/response transport
and proving concrete mTLS behaviour.

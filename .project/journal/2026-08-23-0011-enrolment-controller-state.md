# Durable enrolment controller state

PR B adds PostgreSQL migration 3 and one controller-side repository for the
existing enrolment, certificate-identity and transport-replay ports. Claims retain
only SHA-256 verifiers. A request-bound, expiring reservation prevents concurrent
issuers from proceeding. The durable completion operation locks the claim and commits
identity, consumption result, immutable audit event and outbox message together.

Post-review correction: a live reservation rejects every contender, including a
same-request retry, so only its original holder may reach issuance. Completion
evaluates claim and reservation expiry against PostgreSQL's current database clock
in its locked transaction; the caller timestamp remains audit metadata only. Claim
credential checks hash and compare the secret before disclosing an authenticated
identity-binding mismatch.

Final recovery correction: reservation expiry is no longer a reassignment lease.
It records liveness only; a normal request cannot replace it, even after expiry.
The original reservation holder can complete before claim expiry. Otherwise the
claim remains fail-closed, with no automated abandonment or reissue path in PR B.

Reservation correction: claim expiry and reservation timestamps are derived from
`clock_timestamp()` while the claim row is locked. A stale caller timestamp cannot
authorise issuance after a queued reservation reaches database expiry.

Atomic transition correction: reservation creation is one conditional
`UPDATE ... RETURNING` with `expires_at > clock_timestamp()` and an unassigned
reservation predicate. No time read or row lock is treated as an issuance grant;
zero updated rows fail closed.

The repository deliberately refuses the older direct consume/register paths:
without a certificate binding they cannot preserve the at-most-one transition.
Replay is exact only when the full persisted identity matches; sequence, message,
idempotency or payload changes are a typed conflict. Revocation is a controller
operation and the identity row permits no other mutation.

Integration coverage uses `ARMADA_POSTGRES_CONNECTION` for concurrent same-claim
completion, exact/changed replay, expired/wrong/revoked identity refusals and
reconnect reads. PR C remains responsible for a lab CA, request/response transport
and proving concrete mTLS behaviour.

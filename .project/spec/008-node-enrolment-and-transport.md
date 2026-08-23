# Node enrolment and transport v1alpha1

**Protocol family:** `armada.node.transport/v1alpha1`  
**Status:** PR C1 raw-wire adapter foundation; no listener, issuer or device key store

`NodeEnrollment/Enroll` is unary. `NodeTransport/Connect` is duplex. The
protobuf source is `proto/armada/v1alpha1/node_transport.proto`; tags and
oneof members are append-only and deployed tags must never be repurposed.

Any untrusted implementation of these gRPC methods must retain the received
protobuf bytes until the strict parser has rejected unknown or duplicate fields.
It must not use generated request deserialisation followed by reserialisation:
that loses wire distinctions before validation. C1 registers the exact existing
service and method names through the public `ServerServiceDefinition` mapping
API, with a raw request marshaller for both methods and generated response
marshallers only. It maps no generated `MapGrpcService<T>` route.

For enrolment this check includes `EnrollmentInventory`: unknown nested fields,
duplicate map-entry fields and duplicate map keys are rejected before
materialising protobuf's map representation, which would otherwise overwrite a
prior key. The validated adapter composition carries the exact bounded
certificate lifetime to the raw unary handler; it must not reconstruct a
default lifetime while mapping routes.

## Enrolment

`EnrollmentRequest` has only protocol version, opaque claim ID and secret,
node UUID, positive identity epoch, DER ECDSA P-256 SPKI, its 32-byte SHA-256,
PKCS#10 CSR, bounded inventory, optional bounded attestation, request UUID and
UTC timestamp. The secret is at least 32 bytes and is input to validation only;
it is not returned in validated state or persisted by this contract.

Inventory permits at most 64 facts and 64 capabilities; names/values are
trimmed, non-empty and at most 512 characters. Attestation is at most 16 KiB,
SPKI 4 KiB, CSR 16 KiB. The timestamp is within five minutes of validation.
The CSR signature and subject public key must bind the SPKI and digest.

`EnrollmentResponse` has only protocol version, node UUID, epoch, certificate
serial, expiry, leaf DER, issuing-CA DER, and correlation UUID. It never
carries private keys, claims, policy, workload, grants or commands.

## Stream envelope and replay

Both stream directions have exactly these envelope fields: protocol version,
node UUID, identity epoch, stream epoch, sequence, message UUID, correlation
UUID, idempotency key, UTC sent-at, and typed `oneof` payload. Payload and
envelope versions equal the protocol family. Stream/identity epochs and
sequence are positive; UUIDs are canonical non-empty `D` values; idempotency
keys are printable ASCII, trimmed and at most 128 characters.

Only `hello`, full reconciliation snapshot, inventory observation, health
observation, transport acknowledgement and typed transport rejection are
enabled. Command, admission, lease, process and credential values are reserved
but deliberately undefined. Canonical replay identity includes every envelope
binding and SHA-256 of the canonical payload bytes. Validation accepts the typed
`NodeToControl` oneof (or its encoded protobuf), derives payload kind/schema/bytes
from that parsed message, and does not trust a caller-supplied kind, schema or byte
claim. Every enabled payload also has a required, exact payload-type discriminator;
unknown, duplicate, reserved and oneof/body-mismatched protobuf fields are rejected
before replay identity calculation. `sent_at` nanos must be a multiple of 100, because
the pure .NET representation is tick-precise; sub-tick values are rejected rather
than being silently collapsed in replay identity. Exact replay may return its receipt;
changed digest or stale sequence must fail closed in the later durable adapter.

## Certificate binding

Leaf certificates use client-auth EKU and must bind the enrolled P-256 public
key digest, canonical uppercase-even-hex serial, SHA-256 thumbprint, exact SAN
URI `spiffe://armada.lab/node/<uid>/epoch/<epoch>`, and UTC validity. Validation
rejects not-yet-valid, expired, inverted and greater-than-31-day windows.
The contract validates no chain and issues no certificate.

## Durable controller state

PR B uses operator-applied PostgreSQL migration 3. Claims store a unique ID,
SHA-256 verifier, intended node/epoch/key digest, assurance JSON and expiry;
the raw secret is never stored. A validated request first acquires a
request-bound, single-assignment reservation, so concurrent issuers cannot both
proceed. Reservation expiry is diagnostic only: it never authorises a second
request, including when the original issuer may still be running. The original
request may complete while the claim itself remains valid. If it never completes,
PR B leaves the claim fail-closed; it supplies no automatic abandonment or
reissue path. A future controller recovery operation must first prove the external
issuer did not issue and is explicitly outside this PR. The only completion transition locks the claim,
re-verifies its secret and intended identity, inserts the epoch-bound certificate
identity and response, consumes the claim, and writes correlated append-only audit
and outbox records in one transaction. A later retry with the same authenticated
claim returns the persisted response rather than issuing or binding again.

Certificate identities are immutable by database trigger except for a single
controller revocation transition. Direct claim consumption and direct identity
registration ports reject rather than bypassing that transition. Resolve fails
closed for unknown, revoked and expired identity bindings.

Replay receipts use the node/identity/stream/sequence key plus node-epoch message
and idempotency uniqueness. The exact complete `ReplayIdentity` returns its stored
acknowledgement. Any collision with a changed envelope or payload digest returns
the typed `replay-conflict` failure. Receipt creation writes its own correlated,
append-only transport audit and outbox record.

## Evolution

Unknown protocol/schema values, unsupported payloads, absent identities,
unknown enum states, malformed/truncated DER/PKCS#10, noncanonical or duplicate
inventory values and values over these bounds are typed rejections. Future
payloads require a later protocol version and an explicit compatibility record.

## Explicit exclusions

This state layer supplies no CA, key or claim-secret creation tool; no
standalone gRPC/HTTP listener, host endpoint or network client; no device
filesystem key store, executable or harness; and no workload, admission, lease,
process, credential, GitHub, Copilot, signer, installer or production
authority. C1's library is disabled by default and needs explicit later harness
composition before a Kestrel process can be started.

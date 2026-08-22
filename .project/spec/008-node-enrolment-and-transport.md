# Node enrolment and transport v1alpha1

**Protocol family:** `armada.node.transport/v1alpha1`  
**Status:** PR A contract; no listener or issuer

`NodeEnrollment/Enroll` is unary. `NodeTransport/Connect` is duplex. The
protobuf source is `proto/armada/v1alpha1/node_transport.proto`; tags and
oneof members are append-only and deployed tags must never be repurposed.

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

## Evolution

Unknown protocol/schema values, unsupported payloads, absent identities,
unknown enum states, malformed/truncated DER/PKCS#10, noncanonical or duplicate
inventory values and values over these bounds are typed rejections. Future
payloads require a later protocol version and an explicit compatibility record.

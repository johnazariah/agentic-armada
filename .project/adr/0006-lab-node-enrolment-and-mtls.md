# ADR 0006: Lab node enrolment and mutual TLS transport

**Status:** accepted

## Context

The lab control plane is loopback-only and has no node trust path. The first
outbound node connection needs a versioned, binary protocol and a node identity
that does not make inventory, GitHub, or an observed connection authoritative.

## Decision

Use the `armada.node.transport/v1alpha1` gRPC contract. Bootstrap enrolment is
a unary claim-gated request; subsequent communication is a mutually
authenticated bidirectional stream. A node identity is bound to a UUID node,
positive identity epoch, ECDSA P-256 SPKI SHA-256 digest, CSR, short-lived
client-auth certificate, and exactly one SAN URI:
`spiffe://armada.lab/node/<uid>/epoch/<epoch>`.

Claims are one-use and store only verifiers. Replay identity is the complete
envelope identity plus canonical payload digest. Unknown versions, malformed
input, expired/revoked identities, and replay conflicts fail closed.

## Consequences

PR A supplies immutable contracts, pure validation decisions and narrow ports
only. It supplies neither a CA nor storage, a listener, a network client, a
claim-creation path, or a mutation of `NodeIdentity`. PR B owns durable
claim/identity/replay state; PR C owns the lab-only CA and endpoints.

# Lab node enrolment and transport

## PR A: contracts and pure decisions

Add the v1alpha1 gRPC enrolment and duplex transport contract, immutable DTOs,
pure validation/canonicalisation, narrow claim/identity/replay/issuer/device-key
ports, and unit, protobuf and FsCheck tests. Validate version, size limits,
UUIDs, timestamps, inventory, attestation, SPKI/digest/CSR, certificate
SAN/EKU/validity/serial/thumbprint and replay binding. No private key, claim
creation, issuer, storage, migration, network endpoint, client, node
filesystem or NodeIdentity mutation is in scope.

## PR B: durable controller state

Implement the PR A claim, identity and replay ports with PostgreSQL verifier,
one-use consumption, certificate identity/revocation bindings and replay
receipts. It has no CA or network listener.

## PR C: explicit lab adapters

Add an ephemeral test/lab CA, device-key adapter, explicitly bound mTLS gRPC
enrolment/stream endpoints and outbound node transport. It must prove
response-loss, wrong-CA, replay and revocation failures without adding workload
commands or general web APIs.

## Compatibility

This is a new, isolated `armada.node.transport/v1alpha1` family. It does not
alter immutable `armada.io/v1alpha1` resources or their JSON mapping. Future
payload families require a versioned compatible extension and review.

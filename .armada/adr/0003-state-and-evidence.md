# ADR 0003: CAS resources, immutable ledger and GitHub evidence archive

**Status:** accepted

## Decision

The API stores current resources in PostgreSQL. Every write supplies the
current `metadata.resourceVersion`; a stale write is rejected. Each successful
write emits an immutable audit/domain event and durable outbox record in the
same transaction.

Evidence bundles are canonical manifests and content-addressed files uploaded
to immutable release assets in a dedicated private GitHub evidence repository.
The control plane retrieves and verifies the archive independently, then writes
an immutable `EvidenceReceipt`. A GitHub issue, PR comment or release metadata
never changes resource state without a valid API command and policy decision.

## Consequences

- Controllers and projections tolerate duplicate delivery and restart.
- GitHub may be unavailable without blocking database recovery or corrupting
  lease ownership; finalisation waits for independently verifiable evidence.
- Actions artifacts are transient transport only. Release asset identity is
  repository, release ID/tag, asset name, byte digest and signed manifest
  digest.

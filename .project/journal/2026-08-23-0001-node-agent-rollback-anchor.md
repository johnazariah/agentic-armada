# 2026-08-23: Node-agent rollback-anchor boundary

**Status:** accepted implementation boundary
**Related:** ADR 0002, ADR 0003, ADR 0005; spec/004-node-agent-protocol.md

## Decision

The encrypted local journal's colocated chain marker detects corruption and
ordinary loss, but cannot establish rollback resistance when the journal and
marker are restored together. Production journal construction therefore uses
only the fail-closed platform rollback-anchor path. It does not accept an
arbitrary local anchor implementation.

The hardware/device-secure-store or controller-signed checkpoint adapter is
explicitly deferred. Until a TPM, secure device store, or controller-signed
checkpoint implementation can provide a monotonic external anchor, the
production journal rejects restore and append operations. In-memory anchors
remain internal deterministic test infrastructure only.

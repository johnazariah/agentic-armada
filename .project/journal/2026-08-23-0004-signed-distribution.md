# 2026-08-23: Signed distribution and upgrade boundary

**Status:** implementation evidence only; not production-ready  
**Related:** plan 002; ADR 0002, ADR 0003, ADR 0005; specs 003, 004, 007;
threat model 001 and security-review package 002.

## Work recorded

- Added immutable `armada.release/v1` manifest contracts for control-plane,
  node-agent, and signed platform installer artifacts. The manifest canonically
  records exact payload digests, schema/protocol compatibility, signer identity,
  channel, creation time, revocation, and rollback metadata.
- Added deterministic canonical digest/signature ports and a deterministic
  test-only signer. Production signer/verifier construction fails closed when
  no trusted-key provider is configured.
- Added pure node upgrade selection for channel pinning, protocol compatibility,
  platform selection, explicit revocation, replay/downgrade refusal, and
  rollback-anchor presence. Exact artifact bytes are verified before planning.
- Added a narrow staging/health/atomic-activation/rollback port. Upgrade
  phase evidence is appended to the node journal, and activation follows a
  durable health confirmation only.
- Added compatibility, release-process, and security-review gate records under
  `.project/releases/`.

## Acceptance evidence

Focused contracts and node-agent tests cover canonical ordering, manifest
tampering, signature verification failure, exact-byte mismatch, compatibility,
channel pinning, revocation, replay/downgrade/anchor refusal, health-gated
activation, failed activation rollback, and journal replay.

## Remaining blockers

No production trusted-key source, production rollback-anchor adapter, supported
live Copilot integration, independent security-review approval, live deployment
review, backup/restore drill, release publication, package upload, installer
execution, control-plane deployment, or node enrolment exists. These blockers
continue to prohibit real distribution or activation.

# PR 7: Signed distribution, upgrade and compatibility channel

**Status:** implementation in progress  
**Related:** roadmap item 7; ADR 0002, ADR 0003, ADR 0005; specs 003, 004, 007;
threat model 001 and assurance package 002.

## Acceptance criteria

- Immutable `armada.release/v1` manifests name content-addressed control-plane,
  node-agent, and platform installer artifacts, compatible protocol ranges,
  signer identity, channel, creation time, revocation, and rollback metadata.
- Canonical bytes/digest and signer/verifier ports reject altered manifests,
  mismatched key identities, malformed metadata, and changed artifact bytes.
  The production boundary fails closed without an injected trusted-key source.
- Pure upgrade planning refuses unsupported platforms, incompatible protocols,
  unpinned channels, revocation, manifest replay, downgrade, and absent rollback
  anchors. It selects only the exact node-agent and platform installer artifacts.
- The node reconciliation boundary records stage, health, activation, and
  rollback events in the existing journal. It never activates before verified
  health; failed health or activation triggers rollback through a narrow staging
  port.
- Templates remain platform abstractions only. No package, installer, release,
  download, shell, package manager, deployment, or node-enrolment effect exists.
- Deterministic tests cover canonical digest/signature tampering, compatibility,
  revocation, replay/downgrade/channel/anchor refusal, failed staging/health/
  activation, rollback, health-first activation, and journal replay.
- The tracked `dotnet msbuild eng/Verify.proj /t:Verify` gate passes with no
  broad coverage exclusions and the PostgreSQL CI service required by the
  repository workflow.

## Deployment blockers

The production rollback-anchor adapter, production trusted-key source/key
custody decision, supported live Copilot integration, independent security
review, live deployment review, and backup/restore ceremony remain absent.
Those gaps block real release activation and are not resolved by this PR.


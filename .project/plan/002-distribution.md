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
- The node reconciliation boundary atomically claims journal ordinals and every
  stage, health, activation, and rollback transition in the existing journal.
  Claims precede effects and expire for explicit restart recovery; recovery
  queries the narrow staging-status port rather than blindly repeating an
  effect. Every effect receives a renewable monotonic journal fencing token;
  a superseded operation cannot stage or complete a transition. It never
  activates before verified health; failed health or activation triggers
  rollback through a narrow staging port. Any failed or uncertain stage is
  rollback-required, and a durable rollback claim blocks all forward
  reconciliation until rollback completes. The journal enforces that
  precedence atomically: outstanding rollback rejects every forward claim,
  renewal, and completion.
- Templates remain platform abstractions only. No package, installer, release,
  download, shell, package manager, deployment, or node-enrolment effect exists.
- Deterministic tests cover canonical digest/signature tampering, semantic
  `alpha10`/`alpha2` protocol comparison, compatibility, revocation,
  replay/downgrade/channel/anchor refusal, atomic journal claims, restart after
  stage/health/activation boundaries, expired in-flight fencing, hostile
  null-shaped release records, failed staging/health/activation, rollback,
  health-first activation, failed-rollback restart recovery, forward-worker
  suppression under rollback, unavailable rollback-status recovery, and
  journal replay.
- The tracked `dotnet msbuild eng/Verify.proj /t:Verify` gate passes with no
  broad coverage exclusions and the PostgreSQL CI service required by the
  repository workflow.

## Deployment blockers

The production rollback-anchor adapter, production trusted-key source/key
custody decision, supported live Copilot integration, independent security
review, live deployment review, and backup/restore ceremony remain absent.
Those gaps block real release activation and are not resolved by this PR.

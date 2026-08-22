# 2026-08-23: GitHub projection, evidence archive and PFQE observer tooling

**Status:** complete  
**Related:** ADR 0003, ADR 0004, ADR 0005; specs 001, 003, 007; threat model 001; migration 001; plan 001

## Work recorded

- Added an asynchronous worker over immutable committed outbox snapshots. It maps
  authoritative event metadata to human-readable GitHub projections, persists
  idempotent projection receipts, and acknowledges only successful projections
  or deliberately unmapped events. GitHub output remains an observation and
  cannot update Armada resources, leases, readiness, ownership or policy.
- Added the typed GitHub Release evidence archive adapter. It independently
  retrieves and hashes the expected evidence, manifest and provenance assets,
  validates exact provider/repository/release/asset identities, and delegates
  trusted-signer verification to a narrow provenance port before reporting a
  verified result.
- Added immutable PFQE reference inventory and observer-only candidate tooling.
  Every candidate remains without workload authority or imported readiness; each
  sequential migration stage requires immutable evidence, and canaries are
  explicitly non-scientific.
- Added deterministic adversarial, replay, missing/tampered-asset,
  provenance-verifier and observer-promotion tests. Focused application and
  GitHub infrastructure coverage is respectively 87.39% and 93.82% line
  coverage with the configured 85% threshold.

## Verification boundary

`dotnet msbuild eng/Verify.proj /t:Verify` was invoked locally. The environment
has no Docker daemon or `ARMADA_POSTGRES_CONNECTION`, so PostgreSQL integration
coverage failed explicitly as required rather than being skipped. GitHub Actions
run 32583199545 then supplied PostgreSQL 16 and passed the tracked `Verify`
target, including its PostgreSQL integration coverage.

## Deferred boundaries

No GitHub credential acquisition, live GitHub SDK/session implementation, node
process execution, installer, deployment, PFQE mutation, PFQE identity/poller
replacement, or scientific workload authority was introduced.

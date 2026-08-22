# 2026-08-22: Authoritative control-plane foundation

**Status:** complete  
**Related:** ADR 0001, ADR 0002, ADR 0003, ADR 0004, ADR 0005; plan 001

## Work recorded

- Added immutable resource command values and narrow persistence/policy ports in
  `Armada.Application`.
- Resource creation and CAS spec updates generate an immutable ledger event and
  idempotent transactional-outbox message. Admission decisions are persisted
  only when an admission-policy port returns an unexpired decision bound to the
  exact workload generation, project scope, bundle/policy, source repository,
  source revision, configuration digest, session authority, isolation profile,
  resource limits and permitted actions.
- Added PostgreSQL migration and repository boundary for authoritative current
  resources, append-only ledger and outbox. GitHub is not read as state and no
  node, session, process, GitHub or HTTP adapter was added.
- Added deterministic in-memory CAS/replay/atomicity tests, an FsCheck
  version-law property, and PostgreSQL migration contract tests.

## Quality evidence

PostgreSQL integration coverage now exercises migration idempotence, concurrent
CAS, ledger/outbox atomicity and immutable idempotency snapshots. CI provides a
PostgreSQL 16 service through `ARMADA_POSTGRES_CONNECTION`; local `Verify`
reports the same required connection variable and Docker bootstrap command when
the prerequisite is absent. No executable persistence code is excluded from
coverage.

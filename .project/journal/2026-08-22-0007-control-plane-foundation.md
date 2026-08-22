# 2026-08-22: Authoritative control-plane foundation

**Status:** complete  
**Related:** ADR 0001, ADR 0002, ADR 0003, ADR 0004, ADR 0005; plan 001

## Work recorded

- Added immutable resource command values and narrow persistence/policy ports in
  `Armada.Application`.
- Resource creation and CAS spec updates generate an immutable ledger event and
  idempotent transactional-outbox message. Admission decisions are persisted
  only when an admission-policy port returns an unexpired decision bound to the
  exact workload generation and project scope.
- Added PostgreSQL migration and repository boundary for authoritative current
  resources, append-only ledger and outbox. GitHub is not read as state and no
  node, session, process, GitHub or HTTP adapter was added.
- Added deterministic in-memory CAS/replay/atomicity tests, an FsCheck
  version-law property, and PostgreSQL migration contract tests.

## Quality evidence

The local host has the Docker client but no reachable Docker daemon/socket and
no local PostgreSQL instance. Direct Npgsql execution methods are therefore
narrowly excluded with their reason recorded in code and plan 001. The
control-plane maintainer owns replacement with supported real PostgreSQL
integration coverage by 2026-09-30; SQL schema and repository semantics remain
tested deterministically in the interim.

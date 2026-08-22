# Reviewable PR roadmap

Every layer uses one session, branch and PR. No layer is implemented against an
unmerged private contract.

1. **Contracts and lifecycle:** add `.project` records, schemas/protobuf,
   immutable domain types and state-machine tests for valid/invalid/replayed
   transitions.
2. **Control plane:** PostgreSQL migrations, CAS repository, ledger/outbox,
   API and deterministic admission/scheduler/lease/evidence controllers.
3. **Node agent:** signed .NET agent, enrolment/mTLS, local journal,
   inventory/health, process supervision and offline/reboot reconciliation.
4. **Session adapter:** Major Domo, supported capability-scoped Copilot
   adapter, Issue Master contract and duplicate/disappearance recovery.
5. **GitHub/migration:** asynchronous GitHub projection, immutable release
   evidence archive adapter and PFQE observer/migration tooling.
6. **Assurance:** simulator, chaos/replay/concurrency/offline/security tests
   and security-review material.
7. **Distribution:** signed installers/releases, upgrade/rollback/revocation,
   compatibility records and install/upgrade verification.

Each PR must include its acceptance criteria in its linked `.project/plan/`
record, focused tests, protocol compatibility statement and any ADR it relies
on or supersedes.

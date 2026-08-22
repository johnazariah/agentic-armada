# Reviewable PR roadmap

Every layer uses one session, branch and PR. No layer is implemented against an
unmerged private contract.

1. **Contracts and lifecycle:** add `.project` records, schemas/protobuf,
   immutable domain types and state-machine tests for valid/invalid/replayed
   transitions. Establish the property-testing and 85% coverage gate from
   `.project/spec/007-testing-and-quality.md`.
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

## PR 1: Contracts and lifecycle

**Scope:** introduce the .NET 10 `Armada.Contracts` and `Armada.Domain`
libraries, their xUnit test projects, and the `armada.io/v1alpha1` resource
contracts required for the first pure workload-lifecycle implementation.

**Acceptance criteria:**

- Immutable typed contracts model `Project`, `Node`, `NodeIdentity`,
  `Capability`, `Workload`, `AdmissionDecision`, `Attempt`, `Lease`,
  `AgentSession`, `EvidenceReceipt`, `Condition` and `Event`.
- Version-1 integration profiles remain explicit and limited to GitHub source,
  GitHub Copilot sessions and GitHub Release evidence archives.
- A pure state machine permits only `desired -> admitted -> assigned -> claimed
  -> start-approved -> running -> terminal-pending -> completed|failed|
  cancelled|expired`; it validates generation, resource-version, admission,
  assignment, attempt, lease, session and evidence bindings.
- Terminalisation accepts only a verified `EvidenceReceipt` for the claimed
  attempt. Replays with the same transition identity are idempotent; conflicting
  replays and stale resource versions fail with typed domain errors.
- `Blocked=True` conditions require structured escalation data naming the exact
  blocker, actor, required action, location, successor and deadline.
- Strict v1alpha1 JSON mapping round-trips every core resource kind and rejects
  missing required or unknown root/nested fields with typed validation errors.
- The versioned protobuf contract covers all core envelopes, common metadata,
  status, conditions and escalations, and compiles with the contracts project.
- The solution build and contracts/lifecycle tests pass without adding
  persistence, API, node-agent, session-adapter, GitHub-adapter or process
  execution code.

**Compatibility:** this PR implements the existing
`armada.io/v1alpha1` concepts only. It introduces no provider beyond the
accepted v1 GitHub/GitHubCopilot/GitHubRelease profiles and no consumer
`.armada/` configuration.

**Relies on:** ADR 0002, ADR 0003, ADR 0004 and ADR 0005. It supersedes none.

**Quality gate:** local and CI validation run:

```text
dotnet msbuild eng/Verify.proj /t:Verify
```

The tracked `Verify` target collects deterministic Coverlet/MSBuild line
coverage for the affected production projects and fails below the 85% floor.
The repository CI workflow invokes this exact command. Each test project
includes only its directly tested production assembly. `SkipAutoProps=true`
omits only compiler-generated record/DTO auto-property accessors; all
hand-written contract, mapper and lifecycle source remains measured. The
Contracts test project also excludes only
`src/Armada.Contracts/obj/**/Resources.cs`, the protobuf compiler output; the
versioned source `.proto` remains build-validated and the generated file
contains no hand-written production logic.

## PR 2: Authoritative control plane foundation

**Scope:** add `Armada.Application` resource/admission command ports and the
`Armada.Infrastructure.Postgres` authoritative current-state, append-only-ledger
and transactional-outbox schema/repository boundary. HTTP, node, session and
GitHub adapters remain deferred.

**Acceptance evidence:**

- Resource creation and spec updates validate the typed v1 envelope, use
  resource-version CAS and write the current resource, ledger event and outbox
  message as one repository commit.
- Admission policy remains a port. Only an unexpired typed decision bound to the
  exact workload generation may be persisted.
- PostgreSQL schema records current JSON state separately from an append-only
  ledger and idempotent outbox; the ledger rejects updates and deletes.
- PostgreSQL migration and repository integration tests cover CAS contention,
  ledger/outbox atomicity, immutable replay snapshots and duplicate concurrent
  delivery. CI starts PostgreSQL 16 and passes
  `ARMADA_POSTGRES_CONNECTION` to the tracked `Verify` target.
- Local `Verify` requires the same connection variable. For example:
  `docker run --rm --name armada-postgres -e POSTGRES_DB=armada -e
  POSTGRES_USER=armada -e POSTGRES_PASSWORD=armada -p 5432:5432 postgres:16`,
  then set `ARMADA_POSTGRES_CONNECTION='Host=localhost;Port=5432;Database=armada;Username=armada;Password=armada'`.
  The integration tests fail with this exact prerequisite rather than skipping
  persistence coverage.

**Compatibility:** consumes existing `armada.io/v1alpha1` contracts without
introducing a provider or consumer `.armada/` configuration.

## PR 5: GitHub projection, evidence archive and PFQE observer migration

**Scope:** add asynchronous projection from immutable committed outbox events,
typed GitHub Release evidence verification, and observation-first PFQE migration
tooling. GitHub remains a non-authoritative human view and archive boundary.

**Acceptance evidence:**

- Projection maps only committed ledger/outbox snapshots through typed targets,
  persists idempotent external receipts, retries unacknowledged failures and
  cannot use GitHub content to change Armada authority.
- Evidence verification independently retrieves the exact GitHub release
  evidence, manifest and provenance assets; validates provider, repository,
  release, names and byte digests; and requires a configured trusted-signer
  verifier before reporting success.
- PFQE inventory preserves immutable evidence, identity and host-boundary
  references. Candidates are observer-only, cannot import readiness or workload
  authority, and require immutable evidence for every stage, including an
  explicitly non-scientific canary.
- Focused adversarial/replay tests pass with 87.39% application and 93.82%
  GitHub adapter line coverage. The repository's tracked PostgreSQL
  verification passed in GitHub Actions run 32583199545; the local host
  explicitly rejects missing PostgreSQL coverage rather than skipping it.

**Compatibility:** consumes only the accepted v1 GitHub/GitHubRelease typed
profiles. It creates no product-root `.armada/` configuration and introduces no
scientific, live-deployment or provider authority path.

## PR 4: Major Domo and capability-scoped session orchestration

**Scope:** add a pure Major Domo reconciliation core, a capability-scoped
session-adapter port with deterministic in-memory interpreter, and the typed
`GitHubCopilot` supported-local-integration boundary.

**Acceptance evidence:**

- Reconciliation derives one stable Issue Master idempotency key from node UID,
  workload UID and workload generation; duplicate active sessions produce a
  structured `Blocked` condition instead of another create effect.
- Idle sessions are woken, disappeared owners are handed to their durable
  successor before replacement, and invalid ownership/deadline/heartbeat
  bindings fail closed.
- Child creation requires `IssueMasterWithChildren` in the capability envelope;
  observation and plan-decision bindings require exact AgentSession, Attempt,
  correlation ID and envelope digest, and proposed actions remain within both
  the envelope and admission decision.
- Terminal sessions are archived only after an independently verified
  `EvidenceReceipt` for the current attempt.
- `GitHubCopilot` construction accepts only a matching supported local
  integration/capability contract. No runtime automation, browser scraping,
  broad GitHub token or raw credential path is introduced.

**Compatibility:** consumes existing `armada.io/v1alpha1` resources and does
not add GitHub projections, live Copilot orchestration, node process logic or
consumer `.armada/` configuration.

## PR 6: Simulator, chaos and security assurance

**Scope:** add deterministic assurance scenarios over the existing pure,
application, node/session, and GitHub boundaries. No live deployment or new
runtime authority is introduced.

**Acceptance evidence:**

- Concurrent CAS/idempotency tests retain one durable commit and distinguish an
  exact replay from a changed command.
- Node restart/reconnect snapshots, replay windows, duplicate delivery,
  cancellation, process-start expiry, local journal alteration/rollback, and
  malformed command inputs are deterministic and return exact typed failures.
- Major Domo/session tests retain one active Issue Master, require durable
  disappearance handoff, preserve parent/child bindings, and reject
  cross-project or cross-organisation operations.
- Evidence and GitHub tests reject missing, substituted, tampered, malformed,
  or untrusted release content; GitHub projections remain non-authoritative.
- PFQE observation candidates preserve immutable evidence and cannot import
  readiness or workload authority.
- `.project/threat-model/002-assurance-security-review.md` maps tested threats
  to evidence, records remaining blockers, and defines independent
  pre-deployment review criteria. It does not approve deployment.

**Compatibility:** exercises the accepted v1 GitHub/GitHubCopilot/GitHubRelease
contracts only. Desired node operations remain typed contracts; no cordon,
drain, revoke, or upgrade controller is added.

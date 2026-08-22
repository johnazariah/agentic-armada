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

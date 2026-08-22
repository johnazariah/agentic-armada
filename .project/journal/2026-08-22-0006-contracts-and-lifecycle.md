# 2026-08-22: Contracts and pure workload lifecycle

**Status:** complete
**Related:** ADR 0002, ADR 0003, ADR 0004, ADR 0005; plan 001

## Work recorded

- Created the .NET 10 `Armada.Contracts` and `Armada.Domain` libraries with
  corresponding xUnit test projects.
- Added immutable typed v1alpha1 resource envelopes, metadata/version values,
  explicit GitHub/GitHubCopilot/GitHubRelease provider profiles, and complete
  `Blocked` escalation validation.
- Added a pure workload lifecycle that validates predecessor state, generation,
  resource-version, admitted node, attempt, lease, Issue Master session and
  independently verified evidence receipt.
- Added focused coverage for valid lifecycle progression, invalid predecessors
  and assignments, stale CAS tokens, idempotent/conflicting replays, terminal
  evidence gating and fail-closed contract values.
- Completed strict v1alpha1 JSON wire DTO/mapping support for every core
  resource kind, including nested unknown-field rejection, project-scoped
  resource validation and schema-shaped provider/budget/status values.
- Added the versioned protobuf resource baseline and compile validation, plus
  tracked Coverlet verification and CI invocation for the affected production
  assemblies.
- Coverage excludes only the protobuf compiler's generated
  `obj/**/Resources.cs`; all hand-written resource contracts, wire mappers and
  lifecycle code remain subject to the 85% floor.

## Boundary maintained

This implementation deliberately excludes persistence, controllers, APIs,
node-agent code, session/GitHub adapters and process execution. Product records
remain under `.project/`; no consumer `.armada/` configuration was introduced.

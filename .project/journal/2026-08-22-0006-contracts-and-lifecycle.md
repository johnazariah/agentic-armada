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

## Boundary maintained

This implementation deliberately excludes persistence, controllers, APIs,
node-agent code, session/GitHub adapters and process execution. Product records
remain under `.project/`; no consumer `.armada/` configuration was introduced.

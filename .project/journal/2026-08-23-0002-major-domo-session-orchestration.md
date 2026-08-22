# 2026-08-23: Major Domo session-orchestration boundary

**Status:** complete
**Related:** ADR 0002, ADR 0003, ADR 0004, ADR 0005; specs 003, 004, 005 and
007; plan 001 PR 4

## Work recorded

- Added a deterministic Major Domo reconciliation core keyed by node UID,
  workload UID and workload generation. It derives idempotent Issue Master
  intent, wakes idle sessions, prevents duplicate active owners, requires a
  durable handoff receipt before replacing a disappeared owner, and reports
  checkable blocked conditions.
- Added capability-scoped parent/child session operations and durable
  lifecycle, progress, plan-decision and terminal observations. Every
  observation binds an AgentSession, Attempt, correlation ID and capability
  envelope digest.
- Added the deterministic in-memory adapter for tests and a `GitHubCopilot`
  supported-local-integration boundary that accepts only a durable adapter
  contract with matching provider, version and capability digest. The
  in-memory adapter cannot be selected for production.
- Kept terminal archival behind independent evidence verification. No adapter
  operation can issue leases, mutate admission, alter readiness, enlarge
  capabilities, finalise evidence or acquire credentials.

## Quality evidence

- Domain reconciliation tests include duplicate/replay, wake, disappearance
  recovery, ownership protocol, child authority, plan/action and evidence
  gates, plus an FsCheck idempotency-key law.
- Node adapter tests cover durable typed observations, parent/child lifecycle,
  capability refusal and fail-closed GitHubCopilot construction.

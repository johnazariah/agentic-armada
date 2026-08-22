# Testing and quality policy

## Required quality gates

Every pull request must build, run the relevant unit/integration tests and
enforce at least **85% line coverage** across production source projects
affected by that PR. The main branch must retain or improve that floor.

Generated code, migration snapshots and deliberately untestable host/bootstrap
entry points may be excluded only through a narrow documented exclusion with a
reason in the pull request. Broad directory, assembly or namespace exclusions
are prohibited.

## Property-based testing

Use property-based tests when the behaviour has a compact invariant and a broad
input space. Do not add ceremonial generators for behaviour better expressed by
one or two readable examples.

Mandatory candidates include:

- resource-version/CAS laws and stale-write rejection;
- lifecycle transition closure, replay/idempotency and terminal-state laws;
- lease/admission expiry and authority-binding invariants;
- schema/wire parse-serialize round trips and malformed-input non-throwing
  behaviour;
- scheduler feasibility, taint/toleration and resource-accounting invariants;
- controller replay/reconciliation determinism and outbox idempotency.

Example tests remain required for named regressions, security boundaries and
human-readable behavioural intent. Property tests complement them; they do not
replace them.

## .NET implementation

Use `FsCheck.Xunit` for property tests unless a narrowly scoped alternative is
better justified. Use Coverlet/MSBuild integration for deterministic
cross-platform coverage collection and threshold enforcement. CI and local
developer commands must invoke the same coverage threshold; a green local test
run that omits the threshold is not sufficient for a merge.

## Escalation

If a change cannot meet the floor without misleading exclusions or costly test
scaffolding, record the exact uncovered code, reason, owner and remediation
deadline as a structured quality exception. It requires explicit review and
expires; it is not a permanent waiver.

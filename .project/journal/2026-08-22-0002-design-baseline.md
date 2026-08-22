# 2026-08-22: Design baseline recorded

**Status:** complete  
**Related:** 0001 inception; ADR 0001–0003

## Work recorded

- Created the permanent `.armada/` record structure.
- Captured product requirements/non-goals, three accepted architecture
  decisions, API/resource, reconciliation, node-agent and session contracts,
  threat model, PFQE migration plan and reviewable PR roadmap.
- Added the machine-checkable `armada.io/v1alpha1` resource schema covering
  `Node`, `NodeIdentity`, `Capability`, `Workload`, `Attempt`, `Lease`,
  `AgentSession`, `EvidenceReceipt`, `Condition` and `Event`.
- Validated that the JSON schema parses successfully.

## Boundary maintained

No production implementation, deployment configuration, enrolment material or
live workload authority was created. The next implementation layer begins only
with the contracts/lifecycle PR and retains the documented security-review
gate before any live deployment.

# Controller and reconciliation design

## Rules

Controllers reconcile persisted desired and observed state. A controller:

1. reads a consistent resource snapshot;
2. derives the next desired state and idempotent effects in pure code;
3. commits status/event/outbox entries with CAS;
4. dispatches effects through the outbox;
5. re-reads state after any external effect.

No controller relies on a delivery occurring once or in order. Every effect has
a stable idempotency key and correlation/causation identifiers.

## Controllers

| Controller | Responsibility |
| --- | --- |
| Admission | validates schema, project/provider profile, signature, source/config identity, policy bundle and capability request; persists a typed `AdmissionDecision` and creates an admitted or exact-blocked condition |
| Scheduler | evaluates selectors, resources, taints/tolerations, assurance, affinity, budget and concurrency; assigns a node without issuing execution authority |
| Attempt/lease | creates immutable attempt and lease, renews validated heartbeats, revokes expired/mismatched leases and triggers successor handoff |
| Node health | records observations, derives readiness, cordon/drain/revoke/upgrade state and prevents self-promotion |
| Session | reconciles Major Domo and Issue Master observations, prevents duplicates, wakes eligible idle sessions and replaces disappeared owners |
| Evidence | validates manifest/archive bytes independently and moves a workload out of `terminal-pending` only on a passing receipt |
| GitHub projection | mirrors controller events and summaries asynchronously; failure retries from outbox and never alters fleet authority |

## Ownership and failure

For every non-terminal workload, status contains a durable attempt reference,
current owner, successor, expected event, progress deadline, heartbeat policy
and watchdog identity. Terminal statuses preserve the independently verified
evidence receipt reference without requiring an active owner binding. A missed
deadline creates a structured escalation event. If a session disappears, the
session controller revokes its authority, selects/reconciles a successor, and
retains the same workload/attempt history; a new attempt is created only when
the policy says retry is safe.

Nodes may only run multiple project workloads concurrently when every admitted
workload has a compatible, enforceable isolation profile. `DedicatedNode`,
`IsolatedContainer` and `EphemeralVm` are valid v1 profiles. Process-only
cross-project co-scheduling is invalid admission.

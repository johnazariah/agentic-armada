# Resource API and schemas

## Common envelope

All resources are versioned JSON representations and protobuf messages:

```json
{
  "apiVersion": "armada.io/v1alpha1",
  "kind": "Workload",
  "metadata": {
    "uid": "uuid",
    "organisationId": "uuid",
    "projectId": "uuid for project-owned resources",
    "name": "lowercase-name",
    "resourceVersion": "opaque-cas-token",
    "generation": 4,
    "labels": {},
    "ownerReferences": [],
    "finalizers": []
  },
  "spec": {},
  "status": {
    "observedGeneration": 4,
    "conditions": []
  }
}
```

Only the API accepts `spec` updates. Controllers own `status`. All mutations
need `If-Match: <resourceVersion>` or the corresponding gRPC field.

## Kinds and key invariants

| Kind | Selected `spec` | Selected `status` | Invariants |
| --- | --- | --- | --- |
| `Node` | labels, taints, desired operation, scheduling ceiling | observed inventory, readiness conditions, drain/upgrade progress | organisation-scoped; readiness is controller-derived |
| `NodeIdentity` | public key, requested assurance, rotation intent | approved certificate epoch, attestation verdict, revocation | organisation-scoped identity epochs are immutable |
| `Capability` | requested capability scope | controller-verified inventory and scope verdict | organisation-scoped; a node cannot grant itself capabilities |
| `Project` | GitHub repository allowlist, GitHub release evidence archive, Copilot profile and policy bundle | project conditions and quota observations | first-class workload isolation boundary |
| `Workload` | project-owned GitHub bundle, resources, policy, isolation/evidence/session requirements | lifecycle, assignment, owner, deadlines, conditions | source/config/action identities are exact |
| `AdmissionDecision` | immutable typed policy verdict: node, actions, resources, network/credential grants, session authority, isolation/evidence and expiry | decision and digest | binds the workload generation to executable authority |
| `Attempt` | immutable workload/node/policy/bundle/admission binding | execution and terminal observation | IDs never repeat; retry means new attempt |
| `Lease` | immutable attempt/holder/epoch/expiry binding | heartbeat and revocation observations | only valid lease authorises running work |
| `AgentSession` | adapter/session role and capability envelope | liveness, ownership, successor, archive progress | one active Issue Master per workload generation |
| `EvidenceReceipt` | immutable manifest/archive references | verification verdict | completion requires a passing receipt |
| `Event` | event payload and causation identity | n/a | append-only |

## Conditions

Each condition has `type`, `status`, `reason`, `message`,
`observedGeneration`, `lastTransitionTime` and optional `escalation`.
`Blocked=True` requires:

```json
{
  "exactBlocker": "certificate epoch 7 expired at 2026-08-22T00:00:00Z",
  "actor": "node-identity-controller",
  "requiredAction": "approve or reject rotation request <uid>",
  "location": "NodeIdentity/<uid>",
  "successor": "control-plane-operator",
  "deadline": "2026-08-22T00:15:00Z"
}
```

## Lifecycle

```text
desired -> admitted -> assigned -> claimed -> start-approved -> running
        -> terminal-pending -> completed | failed | cancelled | expired
```

Every transition validates predecessor, workload generation, policy decision,
CAS token, ownership and any required lease/evidence binding. `terminal-pending`
is the only route to a terminal result and waits for independent evidence
verification.

## Version-1 provider profiles and evolution

The `armada.io/v1alpha1` schema supports one typed provider path:
`GitHub` source, `GitHubCopilot` session runtime and `GitHubRelease` evidence
archive. This is a deliberate v1 product constraint.

Providers are explicit fields and project profiles, never inferred from a
repository-shaped string. A future provider requires a new versioned schema or
reviewed typed profile, including its source identity, adapter contract,
evidence semantics and policy input. Labels, annotations and unvalidated JSON
cannot extend authority.

V1 `Workload` specifications bind a GitHub Issue identity and expose the
resulting PR identity only as observed status. Scheduling requirements are
typed: host labels, taints/tolerations, affinity/anti-affinity, CPU/GPU/RAM/
storage, budget ceiling and checkpoint preference. This makes the scheduler's
contract implementable without treating arbitrary labels as authority.

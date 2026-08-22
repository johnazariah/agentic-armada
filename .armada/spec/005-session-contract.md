# Major Domo and Issue Master contract

## Major Domo

There is one node-managed scheduled Major Domo per enrolled node. It reconciles
assigned workloads using the durable key:

```text
(node UID, workload UID, workload generation)
```

It creates at most one active Issue Master for that key, records the returned
`AgentSession` identity before reporting success, and repeats safely after a
crash. It wakes a non-terminal idle session, validates/rejects a child plan
against the workload grant, and requests archival only after the control plane
has independently finalised evidence.

## Issue Master

The default project policy selects the model, reasoning level, execution mode,
context tier, worktree policy and approval gates. The initial project policy
uses `gpt-5.6-sol`, high reasoning, autopilot, `long_context`, a fresh worktree
and one workload/branch/PR. An Issue Master may create, wake, direct and archive
child sessions as part of the workload, with no per-step approval when that
project policy permits it.

It must report exact progress, terminal observations and blocker escalations
through the node agent. Its instructions, repository contents and GitHub text
are untrusted until validated against the signed bundle/capability envelope.
It cannot change policy, readiness, node identity, grants, final evidence
verdicts or control-plane ownership.

## Adapter rule

The session adapter is capability-scoped and records all state-changing
operations durably. The production adapter must use a supported local Copilot integration with an
explicit capability contract. Unsupported integrations may be simulated in test;
they cannot admit production workloads.

## Session adapter contract

Every session adapter declares a provider name/version and implements these
typed operations: create session with an idempotency key; observe a session;
wake/cancel/archive a session; create/observe/archive a child session; and
emit durable lifecycle, progress, plan-decision and terminal observations.
Every observation binds an Armada `AgentSession`, `Attempt`, correlation ID and
capability envelope digest. An adapter cannot issue a lease, change admission,
finalise evidence or enlarge an envelope.

The v1 provider profile is `GitHubCopilot`. A future provider is introduced by
a reviewed profile/schema version and the same contract, not a new controller
authority model.

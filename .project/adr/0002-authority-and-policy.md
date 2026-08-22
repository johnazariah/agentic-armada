# ADR 0002: Signed policy and bounded autonomous agents

**Status:** accepted

## Decision

Workload admission evaluates signed, versioned OPA/Rego policy bundles against
typed resource inputs. The decision binds the workload generation, source and
configuration identities, selected node/capabilities, action set, network
scope, resource budget, credential grants, evidence requirements and session
authority.

Major Domo and Issue Masters need no per-step human approval and may create,
wake, approve/reject plans for, and archive child sessions. They may only act
within the signed capability envelope. The node enforcement kernel independently
checks bundle/policy signatures, expiry, exact bindings and hard local ceilings
before executing an effect.

## Consequences

- A text instruction, GitHub issue, repository file, session prompt or agent
  recommendation cannot enlarge a grant.
- Explicit privileged maintenance is a separately signed capability with a
  named scope, duration, evidence requirement and reviewed policy; it is not
  inherited by ordinary workloads.
- A vendor session integration is an adapter, not an authority source. It must
  report durable action observations to the node agent.

# ADR 0004: GitHub-centred v1 with project-scoped extensibility

**Status:** accepted

## Context

Version 1 needs a narrow, testable delivery path. GitHub Issues, worktrees,
branches and pull requests are the existing human workflow and provide a
useful reviewed surface for autonomous coding agents. That does not make PFQE,
Julia, a single repository, or a particular model the product's domain.

Armada must coordinate independent projects such as PFQE, Pelican and Hermes
on the same just-a-bunch-of-machines (JBOM) cluster without leaking policy,
credentials, evidence or quota between them.

## Decision

Version 1 supports **GitHub engineering workloads** only:

```text
GitHub Issue -> admitted workload -> isolated worktree/branch -> GitHub PR
```

GitHub Release assets in a project-specific private evidence repository retain
evidence. A Copilot session adapter is the sole production session adapter in
v1.

`Project` is a first-class resource below the single private organisation.
Workload, admission decision, attempt, lease, agent session and evidence
receipt resources are project-scoped. Nodes, node identities and observed
hardware capabilities are organisation-scoped reusable cluster resources.

GitHub and Copilot are explicit version-1 integration providers, not implicit
schema assumptions. Provider-specific fields are contained in typed integration
profiles. Future GitLab, local-git, non-code workload or alternate-agent
support requires a new API version or a reviewed typed profile; it must not be
smuggled through labels, annotations or arbitrary JSON.

## Consequences

- Pelican and Hermes can have their own projects, policy bundles, GitHub
  repository allowlists, evidence repositories, RBAC, budgets and quotas while
  sharing enrolled JBOM nodes.
- A Julia, Python, .NET or other runtime is declared by the signed workload
  bundle and capability grant. No language runtime is privileged by Armada's
  resource model.
- The v1 schema deliberately cannot express GitLab, arbitrary shell or
  non-repository work. That limitation is explicit, reviewable and versioned.
- Defaults such as model, reasoning level, worktree policy and human approval
  gates are project policy inputs, not durable global constants.

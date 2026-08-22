# Product requirements and non-goals

## Requirements

1. The control plane is authoritative for resource state, admission,
   assignment, leases, deadlines, ownership and completion.
2. Nodes initiate authenticated outbound connections; inbound SSH and open
   workstation firewall ports are not required.
3. Resources are declarative, versioned and reconciled continuously. Delivery
   is at-least-once; effects are idempotent. Exactly-once claims are forbidden.
4. Every non-terminal workload has a durable owner and successor, expected next
   event, deadline, heartbeat policy, watchdog and explicit escalation.
5. A `Blocked` condition requires an exact checkable failure, named actor,
   concrete action, location/reference and deadline. Bare “blocked” is invalid.
6. Nodes cannot self-authorise production readiness, capabilities or broader
   grants. Policy admission and controller verification are required.
7. Every workload produces independently verified, content-addressed evidence:
   source/config identities, environment, commands, logs, terminal/cancellation
   state, outputs, resource usage and archive receipt.
8. GitHub issues and PRs are human views and audit mirrors. They are not locks,
   leases or authoritative state.
9. PFQE migration preserves existing evidence and uses observation-first,
   non-scientific canaries.
10. The API is first. CLI and local UI consume the same API later.
11. Version 1 admits only typed GitHub engineering workloads: a validated
    GitHub Issue, fresh isolated worktree/branch and one resulting GitHub PR.
    GitHub evidence is retained as release assets in a project-specific private
    evidence repository.
12. A `Project` is the isolation boundary for workload policy, RBAC, repository
    allowlists, evidence archive, budgets and audit. Nodes are reusable
    organisation-scoped JBOM cluster resources.
13. Runtime language, framework and model selection are signed workload/project
    policy inputs. Neither Julia nor PFQE has a privileged schema path.

## Non-goals

- Scientific workloads in this repository.
- Shared long-lived GitHub credentials, arbitrary remote shells, or default
  unrestricted action authority.
- Multi-tenant hosting, HA, automatic trust promotion or a GitHub-only
  dispatcher in version 1.
- GitLab, arbitrary local-git, arbitrary shell and non-code workload adapters
  in version 1. They require future reviewed, typed API/provider profiles.
- Deployment before independent security review.

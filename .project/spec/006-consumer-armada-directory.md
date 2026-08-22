# Consumer `.armada` directory contract

## Purpose

`.armada/` belongs to a repository that **uses** Agentic Armada to orchestrate
its work on a JBOM cluster. It is not the Agentic Armada product's own
architecture/specification directory; that directory is `.project/`.

The consumer directory contains declarative desired state and immutable
references that are reviewed with the consumer project's code. Authoritative
runtime state, leases, secrets, raw node journals and evidence bytes remain
outside the repository.

## Version-1 layout

```text
.armada/
  project.yaml                 Project identity and typed GitHub integration profile
  policies/                    Reviewed, signed-policy source and bundle references
  workloads/                   Declarative GitHub engineering workload manifests
  overlays/                    Environment-specific non-secret configuration overlays
  evidence/                    Immutable EvidenceReceipt references, never evidence bytes
  README.md                    Project-local operational instructions
```

`project.yaml` names the Armada `Project` identity, GitHub repository
allowlist, GitHub Release evidence archive, session profile and policy bundle
identity. Workload manifests refer to exact GitHub Issues, source revisions,
bundle/config digests, scheduling/isolation requirements and allowed actions.

## Rules

- Only schemas/versioned fields recognised by the control plane may influence
  admission. Free-form text, labels and annotations cannot expand authority.
- No long-lived credentials, private keys, raw secrets, database snapshots,
  leases or mutable controller state belong in `.armada/`.
- Evidence entries contain receipt/manifests/archive byte digests and immutable
  locations, never copied logs or output archives.
- A consumer's `.armada/` changes are ordinary GitHub PR changes and become
  effective only after policy review and control-plane admission.
- The product repository may add its own `.armada/` directory only when it is
  deliberately onboarded as a consumer project; it remains separate from
  `.project/`.

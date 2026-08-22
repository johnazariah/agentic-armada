# Control-plane threat model

## Assets

- Authoritative resource state, lease ownership and policy decisions.
- Device private keys, control-plane CA/signing keys and short-lived grants.
- Private repository/secret scopes and enrolled workstation integrity.
- Evidence bytes, manifests, receipt verdicts and audit ledger.

## Trust boundaries

The API/PostgreSQL, key custody, node enforcement kernel, autonomous session
adapter, GitHub integration and GitHub evidence archive are separate trust
zones. GitHub text and repository content are untrusted input. Node inventory
is an observation, not authority.

## Principal threats and controls

| Threat | Control |
| --- | --- |
| Forged/replayed node command | mTLS identity epoch, signatures, expiry, stream sequence, idempotency and encrypted local journal |
| Compromised node self-promotes or expands work | controller-derived readiness, signed grants, policy admission and immutable local hard ceiling |
| Prompt/repository/issue injection | treat as data; validate exact signed bundle identities before action; capability boundary remains authoritative |
| Lease split brain/replay | PostgreSQL CAS, unique attempt/lease epochs, controller watchdog and idempotent reconciliation |
| Session loss leaves work orphaned | durable owner/successor/deadline fields, session reconciliation and automatic replacement/reassignment |
| Evidence fabrication or substitution | content-addressed manifest, signed provenance, independent archive retrieval and verification before final state |
| GitHub compromise/mirror drift | GitHub is projection/archive only; API state and ledger remain authoritative; evidence identity includes byte digest |
| Malicious release/agent update | signed content-addressed releases, trusted-key rotation/revocation and staged non-scientific canary |
| Credential exfiltration | short-lived workload-scoped grants, no shared token, explicit secret capability and evidence redaction |
| Cross-project leakage on a shared node | schedule only to an enforceable workload isolation profile: dedicated node, isolated container or ephemeral VM; no concurrent cross-project process-only execution |
| Operator error/recovery event | least-privileged RBAC, append-only audit, tested backup/restore and named recovery ceremony |

## Security gates

No live deployment, privileged capability, production workload or installer
channel is enabled until security review verifies this model, the open key
custody ADR, adversarial tests and backup/restore procedure.

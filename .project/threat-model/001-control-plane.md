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

## Lab baseline topology

The lab control plane and PostgreSQL run on the Mac. The first future node is
the disposable Ubuntu WSL instance `johnaz-phd-wsl`. The baseline host binds
only to an explicitly configured IP-loopback Kestrel listener and has no node
transport, so WSL cannot reach it and no node may infer enrolment or authority
from a liveness response. `Kestrel:Endpoints`, `urls`, generic HTTP/HTTPS port
inputs, and enabled hosting-URL preference configuration are rejected before
startup so they cannot add a public listener. Readiness requires explicit lab
mode, local PostgreSQL configuration and reachability, operator-applied schema
management, and a locally verified content-addressed restore-drill artifact.
JSON configuration reload is disabled: the control plane uses code-only Kestrel
endpoints. Restore artifacts are opened on macOS with no-follow semantics,
validated from the opened descriptor as regular, and hashed from that same
descriptor; unsupported platforms fail closed.

This is a configuration and dependency gate, not evidence that a backup can be
restored or that a lab deployment is safe. Operators must keep the restore drill
and schema procedure outside the host. mTLS/node enrolment, GitHub credentials,
Copilot adapters, signing/key custody, installers, package downloads, workload
execution, and production/scientific authority remain unavailable.

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
| Accidental exposure of the lab baseline | explicit lab opt-in, validated IP-loopback Kestrel binding, rejection of configured endpoint/URL/port/hosting-preference overrides, liveness/readiness separation, no authority endpoint, and a secret-free checked-in template |
| Kestrel configuration reload adds a listener | code-only Kestrel configuration and non-reloadable JSON sources; listener changes require a reviewed process restart |
| Empty-builder host cannot serve liveness | explicit Kestrel server registration before the validated code-only listener is configured; a loopback process-level test starts, queries, and stops that exact bootstrap path |
| Forged or changed restore evidence | exact SHA-256 verification of a regular local artifact; missing, directory, symlink, unreadable, and tampered artifacts fail readiness |
| Evidence path replacement between inspection and read | macOS `O_NOFOLLOW`, `fstat` validation of the opened descriptor, and hashing from that descriptor; unsupported platforms fail closed |
| Readiness mistaken for deployment approval | readiness checks configuration, the byte identity of a local restore artifact, and PostgreSQL reachability; the runbook prohibits node attachment or workload operation |

## Security gates

No live deployment, privileged capability, production workload or installer
channel is enabled until security review verifies this model, the open key
custody ADR, adversarial tests and backup/restore procedure.

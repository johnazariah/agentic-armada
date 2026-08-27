# ADR 0007: Standalone signed node-agent bootstrap distribution

**Status:** accepted

## Context

The node agent needs a repeatable Linux/WSL installation path before it can
later serve a Major Domo host. Existing release planning models signed
artifacts, while lab mTLS material is deliberately temporary and must not
become the installed node's distribution identity.

## Decision

Use a local directory package with a canonical, content-addressed manifest and
RSA SHA-256 detached signature. Installation trusts an operator-provided public
key configuration containing an exact issuer and key ID. It verifies the
signature and complete payload before touching the active release. Filesystem
work is isolated behind a narrow port; package validation and install planning
remain immutable and pure where possible.

The first implementation supports only local Linux/WSL filesystem
reconciliation. It has no listener, GitHub authentication, C2 enrolment,
remote command path, workload execution, secret grant, or self-readiness
promotion.

## Consequences

- A release signer is distinct from both the lab C2 CA and permanent node
  identity; key custody remains an operator decision.
- The package's deterministic directory layout is directly inspectable and
  testable without a package-manager or remote service dependency.
- The bootstrap executable is an operator tool, not a resident daemon.

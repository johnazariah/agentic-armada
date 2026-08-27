# Node-agent bootstrap vertical slice

**Status:** implementation in progress  
**Related:** ADR 0005, ADR 0007; specs 004, 007, 009.

## Scope

Deliver a standalone Linux/WSL bootstrap CLI and reusable node-agent boundary
that creates a deterministic signed directory package, verifies an explicit
issuer/key trust file, and reconciles secure local install and state roots.

## Acceptance criteria

- `package` emits only `manifest.json`, `manifest.sig`, and sorted
  `payload/` artifacts, with a SHA-256 entry for every payload byte.
- `install` verifies the exact trusted issuer/key detached signature and every
  payload entry before changing install state; it rejects tampering, missing or
  extra files, links, and credential markers.
- Roots are non-symlinked and owner-only; repeated install is a no-op and a
  new signed digest upgrades the active release.
- `status` reports only local installation state and does not assert agent
  health, capability, enrolment, or readiness.
- Focused tests cover tampering, missing/extra/link files, untrusted signing
  keys, repeat install/upgrade, and the absence of GitHub credentials from
  package artifacts.

## Compatibility

This adds `armada.node-bootstrap/v1` and
`armada.node-bootstrap.trust/v1`. It neither changes `armada.io/v1alpha1` nor
the lab transport family, and it creates no permanent C2 identity dependency.

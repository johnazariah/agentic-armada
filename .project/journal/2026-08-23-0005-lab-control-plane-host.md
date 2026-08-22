# 2026-08-23: Lab control-plane host baseline

**Status:** implementation evidence only; not deployment approval
**Related:** plan 003; ADR 0001 and ADR 0005; spec 007; threat model 001.

## Work recorded

- Added the runnable `Armada.ControlPlane.Host` ASP.NET Core host and its
  deterministic tests.
- Added explicit lab-only configuration validation, loopback HTTP binding,
  liveness, and readiness. Readiness requires a local PostgreSQL probe and
  operator-supplied schema/restore prerequisites, and it exposes no secret
  values.
- Added a secret-free configuration example and ignored the copied local
  `appsettings.Lab.json`.
- Recorded the Mac control-plane and disposable `johnaz-phd-wsl` topology in a
  durable plan and lab runbook.

## Authority boundary

The new host does not add resource, admission, execution, node, signing,
installer, GitHub, Copilot, or scientific authority. The existing application
services and PostgreSQL repository remain the authority implementation. This
host neither applies migrations nor exposes an authority endpoint.

## Remaining blockers

Node enrolment and mTLS, outbound transport, an actual WSL node connection,
GitHub App/OAuth and Copilot adapters, production signing and key custody,
installers/downloads, backup/restore execution, workload control, and
production deployment all remain deferred and prohibited.

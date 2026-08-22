# 2026-08-23: Lab host environment-binding correction

**Status:** implementation evidence only; not deployment approval

## Correction recorded

- The published
  `ARMADA_ControlPlane__Postgres__ConnectionString` contract previously reached
  the unprefixed environment provider as
  `ARMADA_ControlPlane:Postgres:ConnectionString`, rather than binding the
  `ControlPlane` options section.
- The host now layers the `ARMADA_` environment provider over the raw provider.
  The published variable therefore binds
  `ControlPlane:Postgres:ConnectionString`; raw environment configuration remains
  visible so validation still rejects Kestrel endpoints, URLs, generic ports,
  hosting preference, and `ASPNETCORE_`/`DOTNET_` aliases.
- Deterministic regressions prove the documented variable binds, raw unsafe
  aliases fail before startup, and an otherwise valid host returns readiness
  with injected evidence and PostgreSQL dependencies. No database is required.
- Validation reads an independent raw environment snapshot. A later empty
  `ARMADA_` value therefore cannot mask a dangerous raw hosting alias.

## Boundary retained

The correction changes only configuration-provider precedence and test seams for
the existing health host. It adds no node, transport, workload, GitHub, Copilot,
signing, installation, migration, backup, or production authority.

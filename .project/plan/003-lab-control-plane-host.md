# Lab control-plane host baseline

**Scope:** issue 15 provides a runnable, loopback-only ASP.NET Core host for
the first disposable lab. It composes the existing PostgreSQL authority
boundary for a connectivity probe but adds no resource, admission, execution,
node, transport, signing, installation, GitHub, or Copilot authority.

## Acceptance criteria

- The host is explicitly lab-only and defaults to not-ready.
- `/health/live` remains available for process liveness; `/health/ready` is
  `503` until lab mode, identity, loopback binding, PostgreSQL configuration,
  operator-owned schema management, verified content-addressed restore evidence,
  and PostgreSQL reachability pass.
- The host rejects `Kestrel:Endpoints`, `urls`, generic HTTP/HTTPS port inputs,
  and enabled hosting-URL preference inputs, then configures only the validated
  IP-loopback Kestrel listener. The empty-builder bootstrap explicitly registers
  Kestrel before configuring that listener; conflicting configuration stops
  startup before a server can bind. Its JSON sources do not reload, so Kestrel
  cannot dynamically add endpoints later.
- Restore evidence is an absolute-path regular local artifact plus its exact
  SHA-256 digest. On macOS the final path is opened with no-follow semantics,
  the opened descriptor is validated as regular, and those bytes are hashed.
  Missing, directory, symlink, and tampered files fail. Unsupported platforms,
  including Windows, fail closed. This is a bounded lab verifier, not a
  production evidence archive or signer.
- Configuration is immutable at the boundary and fails closed without logging
  the PostgreSQL connection string or its credentials.
- Published `ARMADA_` variables map to root application configuration sections:
  `ARMADA_ControlPlane__Postgres__ConnectionString` binds
  `ControlPlane:Postgres:ConnectionString`. An independent raw environment
  snapshot remains visible to startup validation so `Kestrel`, `urls`, generic port, and
  `ASPNETCORE_`/`DOTNET_` hosting aliases cannot evade the listener guard.
- PostgreSQL is probed with `SELECT 1`; this PR neither applies migrations nor
  creates another resource/ledger/admission authority.
- A checked-in example is secret-free. The copied local lab configuration is
  ignored by Git.
- Deterministic unit and process-level loopback Kestrel tests cover configuration,
  startup, clean shutdown, and health semantics at the repository coverage floor.

## Lab topology and prerequisites

The control-plane process and PostgreSQL run on the Mac. The first node is the
disposable `johnaz-phd-wsl` Ubuntu WSL instance. This baseline does not connect
the two: its listener is loopback-only until reviewed node enrolment and mTLS
exist.

Before a readiness claim, an operator must supply a local PostgreSQL connection
string, a stable lab identity, a local restore-drill artifact and exact digest,
and confirmation that schema changes are operator-applied. A passed readiness
check proves configuration, byte identity, and database reachability only; it
is not a deployment, restore, security, or workload-execution approval.

## Deferred work

This PR deliberately defers mTLS and node enrolment, outbound node transport,
GitHub App/OAuth and Copilot adapters, signer/key custody, installers and
package downloads, live session control, migrations, backup execution, workload
admission/execution, and every production or scientific authority.

## Compatibility

The host introduces no API or transport protocol. Existing application resource
and admission services and the PostgreSQL ledger/outbox repository remain the
only authority implementations.

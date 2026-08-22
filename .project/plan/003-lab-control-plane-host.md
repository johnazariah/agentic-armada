# Lab control-plane host baseline

**Scope:** issue 15 provides a runnable, loopback-only ASP.NET Core host for
the first disposable lab. It composes the existing PostgreSQL authority
boundary for a connectivity probe but adds no resource, admission, execution,
node, transport, signing, installation, GitHub, or Copilot authority.

## Acceptance criteria

- The host is explicitly lab-only and defaults to not-ready.
- `/health/live` remains available for process liveness; `/health/ready` is
  `503` until lab mode, identity, loopback binding, PostgreSQL configuration,
  operator-owned schema management, current restore evidence, and PostgreSQL
  reachability pass.
- Configuration is immutable at the boundary and fails closed without logging
  the PostgreSQL connection string or its credentials.
- PostgreSQL is probed with `SELECT 1`; this PR neither applies migrations nor
  creates another resource/ledger/admission authority.
- A checked-in example is secret-free. The copied local lab configuration is
  ignored by Git.
- Deterministic unit and in-process host tests cover configuration and health
  semantics at the repository coverage floor.

## Lab topology and prerequisites

The control-plane process and PostgreSQL run on the Mac. The first node is the
disposable `johnaz-phd-wsl` Ubuntu WSL instance. This baseline does not connect
the two: its listener is loopback-only until reviewed node enrolment and mTLS
exist.

Before a readiness claim, an operator must supply a local PostgreSQL connection
string, a stable lab identity, a current durable restore-drill reference and
timestamp, and confirmation that schema changes are operator-applied. A passed
readiness check proves configuration plus database reachability only; it is not
a deployment, restore, security, or workload-execution approval.

## Deferred work

This PR deliberately defers mTLS and node enrolment, outbound node transport,
GitHub App/OAuth and Copilot adapters, signer/key custody, installers and
package downloads, live session control, migrations, backup execution, workload
admission/execution, and every production or scientific authority.

## Compatibility

The host introduces no API or transport protocol. Existing application resource
and admission services and the PostgreSQL ledger/outbox repository remain the
only authority implementations.

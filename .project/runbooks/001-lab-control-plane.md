# Lab control-plane baseline runbook

**Status:** lab-only baseline; not a deployment runbook

## Topology

Run the control-plane host and PostgreSQL on the Mac. The first future node is
the disposable Ubuntu WSL instance named `johnaz-phd-wsl`. There is no node
connection in this baseline. The host accepts only a loopback HTTP listener and
public base URL, so it is not reachable from WSL or any network peer.

## Preparation

1. Copy `src/Armada.ControlPlane.Host/appsettings.Lab.example.json` to
   `appsettings.Lab.json`; it is intentionally Git-ignored.
2. Replace the identity and restore-evidence placeholders. Set the PostgreSQL
   connection string through
   `ARMADA_ControlPlane__Postgres__ConnectionString`, not a committed file.
3. Confirm PostgreSQL is local, the schema was applied by an operator, and the
   restore evidence names a drill performed within the configured age limit.
4. Start the host with `ASPNETCORE_ENVIRONMENT=Lab dotnet run --project
   src/Armada.ControlPlane.Host`.
5. Query `/health/live` and `/health/ready` over loopback. A `503` readiness
   response is the safe state; do not bypass it by relaxing configuration.

## Safety boundaries

Do not expose the listener beyond loopback, point it at shared or production
PostgreSQL, treat liveness as readiness, run migrations from this host, or
attach the WSL node by ad hoc networking. No mTLS/node enrolment, GitHub App or
OAuth credential, Copilot adapter, signer/key custody, installer, package
download, live session control, workload execution, or scientific authority is
approved by this baseline.

Stopping the process changes no workload state because this host has no
workload endpoint. PostgreSQL backup and restore remain an operator-owned
prerequisite; a readiness check records neither a backup nor a restore result.

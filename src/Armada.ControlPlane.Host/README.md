# Lab control-plane host

This is a lab-only ASP.NET Core host. It serves liveness at `/health/live` and
readiness at `/health/ready`; it deliberately exposes no resource, admission,
node, execution, signing, installer, GitHub, or Copilot endpoint.

To prepare a disposable local run, copy `appsettings.Lab.example.json` to
`appsettings.Lab.json`, replace every `replace-with-*` value, and provide the
PostgreSQL connection string through
`ARMADA_ControlPlane__Postgres__ConnectionString`. The connection must point to
a loopback PostgreSQL instance. `LastRestoreVerifiedAtUtc` and
`RestoreEvidenceReference` must name a current, durable restore drill.

Run with:

```text
ASPNETCORE_ENVIRONMENT=Lab dotnet run --project src/Armada.ControlPlane.Host
```

The host remains not-ready until explicit lab mode, loopback identity/binding,
operator-applied schema management, current restore evidence, and PostgreSQL
reachability all pass. It never runs migrations automatically.

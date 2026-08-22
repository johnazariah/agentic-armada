# Lab control-plane host

This is a lab-only ASP.NET Core host. It serves liveness at `/health/live` and
readiness at `/health/ready`; it deliberately exposes no resource, admission,
node, execution, signing, installer, GitHub, or Copilot endpoint.

To prepare a disposable local run, copy `appsettings.Lab.example.json` to
`appsettings.Lab.json`, replace every `replace-with-*` value, and provide the
PostgreSQL connection string through
`ARMADA_ControlPlane__Postgres__ConnectionString`. The connection must point to
a loopback PostgreSQL instance. Configure an absolute path to a local,
regular-file restore-drill artifact and its exact `sha256:` digest. The host
reads the file and rejects missing, directory, symlink, or changed content; it
does not trust a timestamp or free-text configuration claim as evidence.

Run with:

```text
ASPNETCORE_ENVIRONMENT=Lab dotnet run --project src/Armada.ControlPlane.Host
```

The host remains not-ready until explicit lab mode, loopback identity/binding,
operator-applied schema management, verified local restore evidence, and
PostgreSQL reachability all pass. It rejects `Kestrel:Endpoints` and `urls`
configuration and configures only its validated loopback listener. It never
runs migrations automatically. Its JSON configuration sources do not reload, so
endpoint changes cannot add listeners after startup.

The local artifact verifier is intentionally macOS-only: it opens the final
path with `O_NOFOLLOW`, validates the opened descriptor is a regular file, and
hashes that same descriptor. Unsupported platforms, including Windows, fail
closed; cross-platform evidence opening is deferred.

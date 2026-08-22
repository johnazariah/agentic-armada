# 2026-08-23: Lab host server-bootstrap correction

**Status:** implementation evidence only; not deployment approval

## Correction recorded

- A Mac lab smoke start exposed that `WebApplication.CreateEmptyBuilder` does
  not register an HTTP server merely because `ConfigureKestrel` is called.
  `Build()` therefore failed with no `IServer` registration.
- The lab bootstrap now explicitly registers Kestrel before applying its one
  validated code-only IP-loopback listener. It does not restore ASP.NET Core
  hosting defaults, configuration-based Kestrel endpoints, URL/port overrides,
  or hosting-URL preference.
- A process-level regression builds the same bootstrap from a valid
  configuration, starts Kestrel on an ephemeral loopback port, reads
  `/health/live`, and stops it. A companion regression proves prohibited URL
  configuration still fails while bootstrapping, before a server can start.

## Boundary retained

The correction provides only the previously missing lab HTTP-server
infrastructure. It adds no node, transport, workload, GitHub, Copilot, signing,
installation, migration, backup, or production authority.

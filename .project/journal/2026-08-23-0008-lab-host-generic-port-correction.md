# 2026-08-23: Lab host generic-port correction

**Status:** implementation evidence only; not deployment approval
**Supersedes in part:** journal entry 2026-08-23-0007's incomplete generic
hosting-address boundary.

## Correction recorded

- Added startup rejection for `http_ports`, `https_ports`, and enabled
  `preferHostingUrls`, including `ASPNETCORE_` and `DOTNET_` aliases.
- A deterministic pre-bootstrap regression injects generic port and
  hosting-preference inputs and proves that listener configuration fails before
  Kestrel can bind.

## Boundary retained

The host continues to use only the validated IP-loopback `Listen` endpoint and
adds no authority beyond the existing lab health/readiness boundary.

# ADR 0001: Single active control plane with PostgreSQL

**Status:** accepted

## Context

The first product must be operationally credible without building high
availability before its resource, security and recovery semantics exist.
Workstation agents must survive control-plane and network interruption without
inventing authority locally.

## Decision

Run one active ASP.NET Core control-plane instance on the Mac host, backed by
PostgreSQL. PostgreSQL is the authoritative resource store, audit ledger and
outbox store. The service is recoverable on a cold standby only through a
documented, tested promotion procedure.

The control plane exposes REST/JSON resource APIs and an outbound-only
bidirectional gRPC node stream. Aspire composes local development dependencies;
it is not required in production.

## Consequences

- HA, distributed leader election and multi-site failover are deferred.
- Controller jobs must use database-backed single-active ownership so process
  restart does not duplicate effects.
- Backup, encryption, restore verification and a recovery-time objective are
  release gates, not operational garnish.
- A node may continue only under an unexpired lease and local capability
  ceiling when the control plane is unavailable. It may not self-assign or
  self-promote readiness.

# ADR 0005: Functional-first C# on .NET

**Status:** accepted

## Context

Agentic Armada needs a cross-platform control plane and node agent with strong
testability, modern immutable domain modelling, reliable process/networking
support and a practical local development composition. F# was considered as a
functional alternative, but the Aspire development experience remains awkward
enough to make it an unnecessary delivery risk for this product.

## Decision

Implement Agentic Armada in modern, idiomatic C# on .NET 10. Use ASP.NET Core
for the API, gRPC/protobuf for node transport, PostgreSQL for authoritative
state, and .NET Aspire for local development composition only.

The codebase is functional-first:

- immutable records and algebraic-result/discriminated-union-style domain
  values;
- pure domain transition, scheduling and policy-evaluation functions;
- narrow tagless-final-style ports for persistence, time, cryptography,
  transport, process/session control, GitHub and evidence effects;
- deterministic in-memory interpreters for most controller tests;
- imperative SDK/EF/HTTP/process code confined to infrastructure adapters.

This does not prohibit carefully bounded object-oriented adapters. It prohibits
domain state hidden in mutable service objects, effectful constructors and
unmockable controller dependencies.

## Consequences

- Functional design is a product quality requirement, not an aspiration added
  after controller code exists.
- F# is not a supported implementation language for the initial product. It
  may be reconsidered only if Aspire and the development workflow cease to be
  a practical constraint.
- The node agent and control plane share .NET contracts and testing tools while
  retaining separate deployment boundaries.

# 2026-08-22: Functional-first C# implementation choice

**Status:** accepted  
**Related:** ADR 0005

## Decision

Use modern idiomatic C#/.NET 10 for Agentic Armada, with an immutable
functional core and tagless-final-style effect ports. Aspire is retained for
local development composition. F# was considered but is not selected because
the Aspire experience would add avoidable friction.

# 2026-08-22: Property testing and coverage gate

**Status:** accepted
**Related:** spec/007-testing-and-quality.md

## Decision

Agentic Armada requires property-based testing where a compact invariant has a
meaningful input space, without turning ordinary example tests into ceremony.
The product starts with and retains an 85% line-coverage threshold for affected
production source. Exceptions are narrow, reviewed and time-bound.

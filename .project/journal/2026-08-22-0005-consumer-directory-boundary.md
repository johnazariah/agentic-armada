# 2026-08-22: Correcting product and consumer record boundaries

**Status:** accepted  
**Supersedes:** the `.armada/` product-record assertions in journal entries
2026-08-22-0001 and 2026-08-22-0002

## Correction

The initial design record incorrectly used `.armada/` for Agentic Armada's own
SDD artefacts. That was not an approved product decision.

Agentic Armada stores its product requirements, ADRs, specifications, threat
model, migration record, plans and journal under `.project/`. A consumer
repository such as PFQE, Pelican or Hermes uses `.armada/` for its declarative
Armada/JBOM configuration, policy and evidence references. The consumer
directory never becomes the authoritative state store.

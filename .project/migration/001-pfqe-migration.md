# PFQE migration plan

## Principles

Migration is additive and evidence-preserving. Armada never rewrites a PFQE
identity, poller, issue, PR, registry record or evidence tree in place. Existing
evidence is referenced by immutable digest and source location.

## Stages

1. Inventory PFQE nodes, exact host selectors, identity/assurance, process
   supervisors, readiness limits, issue/PR links and evidence digests.
2. Create observation-only Armada `Node`, `NodeIdentity` and historical
   `EvidenceReceipt` candidates. No production readiness is imported.
3. Install the signed Armada agent in observer mode. It receives no workload
   authority and cannot replace the existing PFQE process.
4. Review policy, identity and evidence mapping. Enrol a distinct Armada
   identity epoch only through reviewed approval.
5. Run a bounded public, non-scientific canary. Verify evidence independently.
6. Drain/retire the old observer only through its own uninstall procedure after
   reviewed handoff. Keep both evidence sources immutable.

## Current node treatment

| Node | Migration boundary |
| --- | --- |
| Mac Studio | Version-1 control-plane host and optional local worker; validate host/agent separation before workload authority |
| ThinkStation | Preserve only conditional public-CPU scope; do not generalise to secrets, GPU, private data or new host identity |
| LabVM | Preserve issue #133/history; install new Major Domo only after new identity and observer review |
| Ryzen | Preserve accepted TPM identity/evidence and current AMD work; onboard from scratch after that work is complete |
| GCP | Keep immutable runner/canary tooling; N=14 remains held by budget and is not migrated as a worker |

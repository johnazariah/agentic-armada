# Assurance security-review package

**Status:** pre-deployment evidence only  
**Scope:** deterministic v1 assurance tests; no deployment approval

## Tested threat evidence

| Threat | Deterministic evidence | Expected fail-closed outcome |
| --- | --- | --- |
| CAS contention, duplicate delivery and conflicting replay | `ResourceApplicationTests` exercises concurrent compare-and-swap, exact replay, and reuse of a transition identity with a different command. `AssuranceScenarioTests` delivers one node command concurrently sixteen times. | One durable mutation; exact replays return the original result; conflicting replays return `idempotency-key-reused`, `idempotency-conflict`, or a CAS failure. |
| Forged, replayed, expired, malformed, or over-scoped node commands | `NodeAgentBoundaryTests` and `AssuranceScenarioTests` exercise identity epochs, stream sequence, verifier refusal, complete authority bindings, expiry after reboot, cross-project isolation, malformed envelopes, and cancellation reason validation. | Typed acknowledgements such as `node-identity-mismatch`, `stale-or-replayed-sequence`, `authority-*`, `expired-authority`, `invalid-envelope-identity`, or `invalid-command-binding`; no process start or recovery poisoning. |
| Local journal alteration, truncation, rollback, corrupt ciphertext, and unavailable rollback anchor | `JournalAndProcessTests` exercises encryption/authentication failure, chain alteration, tail truncation, restoring journal plus local marker, malformed records, concurrent append ordering, and platform-anchor refusal. | Typed journal failure; production journal construction refuses to read or append when a rollback-resistant platform adapter is unavailable. |
| Lost session, duplicate Issue Masters, duplicate children, and cross-scope session authority | `SessionReconciliationTests` and `SessionAdapterTests` exercise duplicate owner blocking, durable handoff before replacement, parent/child idempotency, cross-attempt/node/project/organisation refusal, evidence-gated archival, and replacement provenance. | Typed reconciliation or adapter failure, or a `Blocked` condition with complete escalation. No silent replacement or scope expansion. |
| Evidence substitution, missing assets, malformed release content, and signer mismatch | `GitHubReleaseEvidenceArchiveAdapterTests` exercises byte-digest verification, missing assets, provider/repository substitution, provenance binding/signature refusal, and malformed manifest content. | `release-asset-*`, `evidence-provenance-*`, or `invalid-evidence-expectation`; only independently verified evidence can finalise/archive. |
| GitHub prompt, issue, comment, and release-content injection | `GitHubProjectionAndMigrationTests` verifies that projection output is built from committed typed ledger data and external GitHub references do not alter resource authority. Release evidence tests treat archive content as untrusted bytes. | GitHub remains a projection/archive boundary; no GitHub text can issue a lease, alter admission, readiness, ownership, or policy. |
| PFQE evidence loss or observer self-promotion | `GitHubProjectionAndMigrationTests` verifies immutable reference inventory, ordered evidence at every stage, observer-only candidates, no readiness/workload authority import, and explicit non-scientific canaries. | Typed migration failure including `observer-authority-violation` or `migration-evidence-chain-invalid`. |

## Coverage and execution

The tracked gate is:

```text
dotnet msbuild eng/Verify.proj /t:Verify
```

It runs deterministic tests with Coverlet/MSBuild and fails below 85% line
coverage for each covered production project. CI supplies PostgreSQL 16 through
`ARMADA_POSTGRES_CONNECTION`; PostgreSQL tests fail explicitly when it is absent
rather than being skipped.

## Remaining blocking limitations

1. The production rollback-resistant journal anchor has no TPM, device secure
   store, or controller-signed checkpoint adapter yet. Its unavailable adapter
   correctly fails closed; deterministic in-memory anchors are test-only.
   An interrupted external-anchor advance likewise leaves the local journal
   ahead of its anchor and fails closed as rollback until an approved recovery
   ceremony exists; it must not be mistaken for availability support.
2. No supported live Copilot integration has been implemented. The in-memory
   session adapter is deterministic test infrastructure and cannot admit
   production workloads.
3. No live GitHub token/SDK, deployment, installer, release-signing channel,
   backup/restore drill, or browser automation has been introduced.
4. Cordon, drain, revoke, and upgrade are typed desired node operations, but
   their controller/reconciliation implementation is not present in v1 code.
   This package therefore makes no claim that those operations are deployable.

## Pre-deployment security-review criteria

An independent review must verify the threat model and this evidence against the
implemented adapters, close or explicitly accept the open key-custody and
rollback-anchor decisions, validate a backup/restore ceremony, review the
supported Copilot capability contract and GitHub credential model, repeat
adversarial and PostgreSQL CI gates from clean infrastructure, and approve the
result in a dated review record. Passing these tests is necessary evidence, not
deployment approval.

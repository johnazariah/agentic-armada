# 2026-08-23: Assurance simulator and security-review evidence

**Status:** pre-deployment evidence only  
**Related:** specs 003, 004, 005 and 007; threat model 001; ADRs 0002, 0003,
0004 and 0005

## Work recorded

- Added deterministic chaos/replay coverage for concurrent node delivery, reboot
  reconciliation, malformed command envelopes, and cancellation binding.
- Hardened the node protocol boundary so malformed untrusted envelope identity,
  payload, or cancellation reason returns an exact typed refusal rather than
  throwing before validation.
- Added malformed GitHub release manifest coverage and retained deterministic
  archive verification.
- Recorded a pre-deployment assurance package mapping tested threats to evidence,
  limitations, and independent security-review criteria.

## Boundary maintained

No deployment approval, rollback-anchor platform implementation, live Copilot
integration, live GitHub credential path, installer, release signing, browser
automation, or scientific workload authority was introduced.

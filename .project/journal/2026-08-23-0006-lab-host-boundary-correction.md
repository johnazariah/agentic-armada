# 2026-08-23: Lab host binding and evidence correction

**Status:** implementation evidence only; not deployment approval
**Supersedes in part:** journal entry 2026-08-23-0005's configuration-only
restore evidence claim.

## Correction recorded

- Replaced `UseUrls` with explicit Kestrel configuration from the validated
  IP-loopback endpoint. Startup rejects `Kestrel:Endpoints` and `urls` inputs
  before a listener can be built, preventing configuration precedence from
  widening the lab listener.
- Replaced the free-text restore reference and timestamp readiness claim with a
  structured local artifact path and exact `sha256:` digest. The bounded lab
  verifier accepts only a regular, non-symlink local file and independently
  hashes its opened bytes. Missing, directory, unreadable, mismatch, and
  tampered artifacts remain not-ready.
- Added deterministic configuration, bootstrap, and hostile evidence
  regressions. The verifier is not a production archive, trusted signer, or
  substitute for independent backup/restore review.

## Boundary retained

No node, transport, workload, GitHub, Copilot, signer, installer, deployment,
or production/scientific authority was added.

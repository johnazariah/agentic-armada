# Distribution security-review gate

**Status:** blocked pending pre-deployment review.

| Required evidence | Current state | Release-channel consequence |
| --- | --- | --- |
| Independent review of signed-manifest canonicalisation, exact-byte verification, channel pinning, revocation, downgrade/replay refusal, and health-gated rollback | Deterministic unit evidence exists in this PR; independent review has not occurred. | No live channel activation. |
| Production trusted-key source and key-custody decision | Not implemented. `ProductionReleaseSigner` and `ProductionReleaseVerifier` refuse without an injected trusted-key provider. | No production signing or verification. |
| Rollback-resistant node journal anchor | Not implemented. The production journal refuses when its platform anchor is unavailable. | No live upgrade activation. |
| Supported live Copilot integration | Not implemented; only deterministic test infrastructure exists. | No production workload admission or operational rollout. |
| Live deployment, backup/restore, and installer review | Not performed. | No deployment, package publication, installer execution, or node enrolment. |

The blockers are intentional fail-closed boundaries, not waiver language. A
dated independent review record must name the reviewer, evidence revision,
accepted risks, and any expiry before this gate can change status.


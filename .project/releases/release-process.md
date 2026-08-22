# Signed release process

**Status:** procedure design only. This record does not authorise publication,
deployment, enrolment, or installation.

1. Build release candidates in isolated CI and calculate the SHA-256 digest of
   each exact control-plane, node-agent, and platform installer payload.
2. Construct an `armada.release/v1` manifest with the payload digests,
   protocol compatibility ranges, signer key identity, channel, creation time,
   revocation status, and durable rollback reference.
3. Canonicalise and digest the manifest. A production signing provider may sign
   only through a configured trusted-key source; an unavailable source fails
   closed. Test signing is deterministic and cannot activate a production
   release.
4. Independently retrieve the manifest, signature, and exact payload bytes.
   Verify canonical digest, trusted signer identity/signature, and every
   payload digest before proposing an upgrade.
5. Reconcile one node against its pinned channel and compatibility range.
   Stage only through a platform-specific `IUpgradeStaging` adapter, record the
   stage in the node journal, require health confirmation, then atomically
   activate. A failed stage, health check, or activation must roll back to the
   previously recorded anchor.
6. Record independent security-review approval, supported integration review,
   rollback-anchor availability, and deployment review before enabling any live
   release channel. Passing unit tests is evidence, not approval.

This implementation deliberately has no downloader, shell invocation,
package-manager mutation, package upload, GitHub release publishing,
installation, control-plane deployment, or node enrolment operation.


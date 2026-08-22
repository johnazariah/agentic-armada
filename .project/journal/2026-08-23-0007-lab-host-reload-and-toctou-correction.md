# 2026-08-23: Lab host reload and evidence TOCTOU correction

**Status:** implementation evidence only; not deployment approval
**Supersedes in part:** journal entry 2026-08-23-0006's startup-only listener
and pre-open evidence safety claims.

## Correction recorded

- Rebuilt host configuration from explicit, non-reloadable JSON sources and
  code-only Kestrel binding. A post-start JSON change cannot be observed by
  Kestrel to add an endpoint; conflicting startup endpoint/URL inputs still
  fail before binding.
- Replaced path metadata inspection with a macOS no-follow opener. It opens the
  final artifact path with `O_NOFOLLOW`, validates the opened descriptor with
  `fstat` as a regular file, and hashes that same handle. This removes the
  symlink replacement window between inspection and content hashing.
- Unsupported operating systems, including Windows, return no evidence handle
  and leave readiness false. Cross-platform secure opener support remains
  deferred.

## Boundary retained

This remains a lab-only host boundary. It adds no node, transport, workload,
GitHub, Copilot, signer, installer, deployment, or production/scientific
authority.

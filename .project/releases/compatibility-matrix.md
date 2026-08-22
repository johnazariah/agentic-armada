# Distribution compatibility matrix

**Status:** implementation contract only; not a live release matrix.

| Component | Release schema | Required protocol | Supported package targets | Upgrade rule |
| --- | --- | --- | --- | --- |
| Control plane | `armada.release/v1` | `armada.control/v1alpha1` | content-addressed control-plane artifact | Manifest must declare a compatible control-plane protocol. This PR does not deploy it. |
| Node agent | `armada.release/v1` | `armada.node/v1alpha1` | content-addressed node-agent artifact | Node accepts only a newer, signed, non-revoked manifest on its pinned channel. |
| macOS installer template | `armada.artifact/v1` | `armada.node/v1alpha1` | `MacOsArm64` | A test-only staging port selects the exact signed installer payload. No `.pkg` is generated or invoked. |
| Linux installer template | `armada.artifact/v1` | `armada.node/v1alpha1` | `LinuxX64` | A test-only staging port may select a signed payload. No package manager or shell command is permitted. |
| Windows installer template | `armada.artifact/v1` | `armada.node/v1alpha1` | `WindowsX64` | A test-only staging port selects the payload. No MSI is generated or invoked. |

The manifest contains exact SHA-256 digests for every payload, a signer key
identity, creation timestamp, protocol ranges, release channel, and explicit
revocation and rollback metadata. Canonical manifest bytes are deterministically
ordered before digesting or signing.

Unsupported platforms, mismatched protocol versions, channel drift, stale or
replayed manifest digests, downgrade versions, absent rollback anchors,
revoked manifests, bad signatures, or byte-digest mismatches are refused.


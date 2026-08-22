# Platform installer packaging templates

**Status:** non-executable design templates. They do not create packages or
authorise installation.

| Platform | Manifest target | Intended package boundary | Required verification before a future adapter can stage it |
| --- | --- | --- | --- |
| macOS arm64 | `MacOsArm64` | signed `.pkg` payload selected by exact manifest digest | Canonical manifest, trusted signer, payload digest, pinned channel, compatible protocol, rollback anchor, staged health |
| Linux x64 | `LinuxX64` | signed distribution payload selected by exact manifest digest | Canonical manifest, trusted signer, payload digest, pinned channel, compatible protocol, rollback anchor, staged health |
| Windows x64 | `WindowsX64` | signed `.msi` payload selected by exact manifest digest | Canonical manifest, trusted signer, payload digest, pinned channel, compatible protocol, rollback anchor, staged health |

The current `IUpgradeStaging` interface intentionally contains only
`StageAsync`, `ConfirmHealthAsync`, `ActivateAsync`, and `RollbackAsync`.
It has no URL, command, shell, installer, package-manager, browser, or remote
execution parameter. A future platform adapter must be reviewed independently
and preserve this exact verification order.

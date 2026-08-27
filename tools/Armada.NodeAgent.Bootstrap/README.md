# Armada node-agent bootstrap

This Linux/WSL operator CLI creates and installs a signed, local directory
package. It does not contact GitHub, expose a listener, enrol a node, or run a
workload.

```text
dotnet run --project tools/Armada.NodeAgent.Bootstrap -- package \
  --source ./publish --output ./node-agent-1.0.0 --package-id node-agent \
  --version 1.0.0 --issuer armada-release --key-id release-2026 \
  --private-key ./release-private.pem

dotnet run --project tools/Armada.NodeAgent.Bootstrap -- install \
  --package ./node-agent-1.0.0 --trust ./node-agent-trust.json \
  --install-root ~/.local/lib/armada-node-agent --state-root ~/.local/state/armada-node-agent

dotnet run --project tools/Armada.NodeAgent.Bootstrap -- status \
  --install-root ~/.local/lib/armada-node-agent --state-root ~/.local/state/armada-node-agent
```

`node-agent-trust.json` is held separately from the package:

```json
{
  "schemaVersion": "armada.node-bootstrap.trust/v1",
  "issuer": "armada-release",
  "keyId": "release-2026",
  "publicKeyPem": "-----BEGIN RSA PUBLIC KEY-----\n...\n-----END RSA PUBLIC KEY-----"
}
```

# Node enrolment and transport threat model

**Status:** PR A pure-decision evidence only

| Threat | PR A control | Expected outcome |
| --- | --- | --- |
| Wrong version, malformed wire data, unsupported future payload | Strict family/schema and enabled-oneof validation | Typed rejection; no network or state effect |
| Weak/substituted device key or CSR | P-256 DER SPKI parse, SHA-256 and PKCS#10 signature/public-key binding | `invalid-device-public-key`, digest or CSR mismatch |
| Claim/node/epoch substitution | Canonical UUIDs, positive epoch and transient 256-bit secret shape | Typed rejection; no secret retained |
| SAN, EKU, serial, thumbprint or validity substitution | Exact SPIFFE SAN, client-auth EKU, DER and UTC certificate binding checks | Typed certificate rejection |
| Replay collision or changed replay | Complete replay identity and canonical payload digest | Exact identity is deterministic; durable conflict handling is PR B |
| Resource/readiness scope expansion | No NodeIdentity mutation; observation payloads only | No readiness, admission, command or workload authority |

PR A cannot defend against database disclosure, duplicate consumption races,
revocation persistence, CA compromise or network MITM because it intentionally
contains no storage, issuer or listener. Those controls are prerequisites for
PR B and PR C, not claims made by this record.

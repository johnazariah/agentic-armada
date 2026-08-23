# Node enrolment and transport threat model

**Status:** PR B durable controller-state evidence

| Threat | PR A control | Expected outcome |
| --- | --- | --- |
| Wrong version, malformed wire data, unsupported future payload | Strict family/schema and enabled-oneof validation | Typed rejection; no network or state effect |
| Weak/substituted device key or CSR | P-256 DER SPKI parse, SHA-256 and PKCS#10 signature/public-key binding | `invalid-device-public-key`, digest or CSR mismatch |
| Claim/node/epoch substitution | Canonical UUIDs, positive epoch and transient 256-bit secret shape; PostgreSQL SHA-256 verifier and intended identity | Typed rejection; no raw secret retained |
| SAN, EKU, serial, thumbprint or validity substitution | Exact SPIFFE SAN, client-auth EKU, DER and UTC certificate binding checks | Typed certificate rejection |
| Claim reuse, concurrent binding or response loss | Claim row lock, one atomic identity/claim/audit/outbox transaction and persisted response | At most one binding; authenticated retries return the original response |
| Certificate self-promotion or self-revocation | Direct registration/consumption disabled; immutable identity trigger permits only controller revocation | Node calls cannot create, mutate or revoke an identity |
| Replay collision or changed replay | Complete replay identity, payload digest and sequence/message/idempotency uniqueness | Exact receipt is returned; changed identity fails closed as `replay-conflict` |
| Audit rewrite or lost notification | Append-only transport audit trigger and same-transaction outbox | Correlated durable evidence is immutable and dispatchable |
| Resource/readiness scope expansion | No NodeIdentity mutation; observation payloads only | No readiness, admission, command or workload authority |

PR B does not defend against PostgreSQL disclosure, CA compromise or network MITM:
verifiers still require database confidentiality, and concrete CA/listener/mTLS
controls remain PR C. It intentionally has no claim creation mechanism, signer,
network endpoint or node key store.

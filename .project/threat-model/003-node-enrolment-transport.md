# Node enrolment and transport threat model

**Status:** PR C1 raw-wire adapter foundation

| Threat | PR A control | Expected outcome |
| --- | --- | --- |
| Wrong version, malformed wire data, unsupported future payload | Strict family/schema and enabled-oneof validation | Typed rejection; no network or state effect |
| Weak/substituted device key or CSR | P-256 DER SPKI parse, SHA-256 and PKCS#10 signature/public-key binding | `invalid-device-public-key`, digest or CSR mismatch |
| Claim/node/epoch substitution | Canonical UUIDs, positive epoch and transient 256-bit secret shape; PostgreSQL SHA-256 verifier and intended identity | Typed rejection; no raw secret retained |
| SAN, EKU, serial, thumbprint or validity substitution | Exact SPIFFE SAN, client-auth EKU, DER and UTC certificate binding checks | Typed certificate rejection |
| Claim reuse, concurrent binding, expired reservation or response loss | Single-assignment claim reservation, claim row lock, one atomic identity/claim/audit/outbox transaction and persisted response | At most one issuer authorisation/binding; timed-out work fails closed and authenticated retries return the original response |
| Certificate self-promotion or self-revocation | Direct registration/consumption disabled; immutable identity trigger permits only controller revocation | Node calls cannot create, mutate or revoke an identity |
| Replay collision or changed replay | Complete replay identity, payload digest and sequence/message/idempotency uniqueness | Exact receipt is returned; changed identity fails closed as `replay-conflict` |
| Audit rewrite or lost notification | Append-only transport audit trigger and same-transaction outbox | Correlated durable evidence is immutable and dispatchable |
| Resource/readiness scope expansion | No NodeIdentity mutation; observation payloads only | No readiness, admission, command or workload authority |
| gRPC parser normalises hostile wire data before validation | Public `ServerServiceDefinition` mappings use a raw request wrapper for the exact unary and duplex methods; strict validation occurs before any protobuf object, claim, issuer, identity or replay operation | Unknown, duplicate and malformed outer protobuf fields are rejected before state effect |
| Claim is seeded for a substituted device key | WSL phase one returns a length-prefixed SHA-256-bound public SPKI/digest/CSR frame; controller validates P-256, CSR signature and node/epoch binding before seeding | The one verifier claim binds only to the WSL-generated key |
| SSH command, helper or secret substitution | Fixed stdin-only `ssh -T johnaz-phd-wsl` bootstrap, fixed dotnet path, helper SHA-256 verification, `0700` root and `0600` secret file checks | No remote command injection, source checkout, credential copying or secret retention |
| Incomplete teardown masks a hazardous live run | Every resource has an independently checked cleanup action and errors aggregate into failure | A successful proof cannot conceal a remaining listener, database or temporary root |

PR C1 does not expose a listener or create CA, claim or device-key material.
It does not defend against PostgreSQL disclosure, CA compromise or network MITM:
verifiers still require database confidentiality, and concrete CA/listener/mTLS
controls remain the later C2 harness. It intentionally has no claim creation
mechanism, signer, network endpoint or node key store.

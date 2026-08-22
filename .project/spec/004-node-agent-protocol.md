# Node agent protocol

## Enrolment

1. An operator creates a reviewed, one-use, short-lived enrolment request.
2. The agent creates a device key, gathers bounded inventory and optional
   attestation, and submits its public identity proof.
3. The identity controller approves/rejects it. Approval issues a short-lived
   mTLS certificate bound to a `NodeIdentity` epoch.
4. The agent rotates before expiry and reports revocation immediately. Failure
   to rotate fails closed at lease expiry.

## Stream

The agent opens a mutual-TLS, bidirectional gRPC stream. Every message carries:

```text
protocol version, node UID, identity epoch, stream epoch, sequence,
message ID, correlation ID, idempotency key, sent-at, typed payload
```

Payloads include inventory, health, reconcile snapshots, acknowledged commands,
lease heartbeat, session observations, process/evidence observations and
node-operation results. Commands include exact workload/attempt/lease,
bundle/policy/release digests and expiry.

## Local durability and enforcement

Before action, the agent persists a local encrypted journal entry. It rejects
unknown schema versions, replay outside the documented sequence window,
signature/binding failures, expired grants and effects beyond its hard
capability ceiling. On reboot or reconnect it sends a full durable snapshot;
the control plane reconciles it rather than trusting an old heartbeat.

The agent supervises detached process trees, cancellation, output capture,
resource observation and evidence packaging. It exposes no inbound control
port.

## Workload isolation

The node enforces the isolation profile named by the immutable
`AdmissionDecision`. Version 1 allows `DedicatedNode`, `IsolatedContainer` or
`EphemeralVm`; it rejects a command if the local node cannot enforce that
profile. A node without container/VM support may still run a workload using
`DedicatedNode`, but it may not co-schedule workloads from different projects.
Every workspace, process tree, credential mount, temporary directory and
evidence staging location is attempt-scoped.

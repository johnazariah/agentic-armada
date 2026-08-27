# C2 live mTLS harness

**Status:** implementation review only. No live run is approved by this runbook.

The harness accepts `--preflight` and explicit `--postgres-admin-connection`,
`--listen-ip`, `--enrollment-port`, `--stream-port`, `--database`, and
`--evidence-directory` values. It accepts only a generated
`armada_c2_<32 lowercase hex>` database name, one exact non-loopback IP, and
two distinct ports. Preflight deliberately creates no CA, listener, database,
claim, certificate, or SSH/WSL state.

Live execution additionally requires the `--execute` argument and exact
`ARMADA_C2_LIVE_APPROVAL=approved`; neither a command argument nor environment
value alone can cross that gate. The current checkpoint still stops after this
gate, until the final lifecycle implementation and separate live approval.

After a separate execution approval, the required ordering is: publish and
hash the helper; use stdin-only `ssh -T johnaz-phd-wsl` to create the verified
WSL `0700` root and return the public device frame; validate its P-256 SPKI,
digest and CSR; create the disposable database and single verifier claim;
create the ephemeral CA/listeners; send the secret over stdin or a verified
`0600` transient file; run the proof; then remove remote state, stop listeners,
drop only the exact generated database and remove only the verified local root.
Any cleanup failure fails the run. Retain only redacted evidence digests and
public certificate fingerprints.

The remote root name is a generated `armada-c2-<32 lowercase hex>` token, and
the bootstrap validates its owner/mode and those of `helper` and `device`
children before use. Helper digests are exactly 64 lower-case hexadecimal
characters before interpolation into the fixed-token shell script.

## Gated external effects

Only after both execution factors are supplied may the implementation instantiate
its external resources. In order, it will: create an owner-only local temporary
root; obtain and cryptographically validate the phase-one public device frame;
create a P-256 ephemeral CA and IP-SAN server certificate; create, migrate and
seed the exact generated database; bind the two configured HTTP/2 TLS
listeners; invoke phase two; write owner-only redacted evidence; dispose the
listeners; drop the exact database with forced disconnection; and remove the
temporary root. It has no access to the loopback control-plane health host.

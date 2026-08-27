# Node-agent bootstrap package

## Scope

This specification defines the first installable Linux/WSL node-agent bootstrap
increment. It distributes an agent payload only; it does not enrol a node,
start a listener, grant authority, execute a workload, or report readiness.

## Package format

A package is a directory with exactly these top-level entries:

```text
manifest.json
manifest.sig
payload/<relative artifact path>
```

`manifest.json` has schema `armada.node-bootstrap/v1`, a package ID, semantic
version, issuer, signing key ID, creation time, and a lexically sorted list of
payload artifacts. Each artifact has a relative `payload/` path, byte length,
and lower-case SHA-256 digest. There are no unlisted files, directories, or
symbolic links. The manifest is content addressed by its canonical bytes and
the detached `manifest.sig` is a deterministic RSA PKCS#1 v1.5 SHA-256
signature over those bytes.

Package creation rejects a source tree containing symbolic links or known
GitHub credential markers. Publishing is deterministic for identical payload,
metadata, clock input, and signing key.

## Trust and installation

The operator supplies a separate `armada.node-bootstrap.trust/v1` JSON file
containing one issuer, key ID, and RSA public key PEM. The trust file is not
part of the package and is never sourced from lab C2, node enrolment, or a
remote endpoint.

Before copying a byte, installation must:

1. reject a missing, malformed, substituted, untrusted, or invalid detached
   signature;
2. reject missing, extra, changed, or symbolic-link payload entries;
3. reject install and state roots that are symbolic links or have group/other
   permissions; and
4. reject payload containing GitHub credential markers.

The installer creates owner-only roots, copies a verified release beneath the
install root, and atomically records the active manifest digest and version in
the state root. Reinstalling the same verified digest is a no-op; a different
verified digest replaces the active release. It accepts no GitHub credential,
network endpoint, listener, privilege escalation, or workload argument.

The installer reads at most 64 KiB of manifest JSON and 16 KiB of detached
signature text. It permits each artifact to be at most 512 MiB and total
payload at most 1 GiB, at most 512 payload entries, and at most 16 payload path
segments. It validates the three top-level package entries before it enumerates
the bounded payload tree. Payload artifacts must be POSIX regular files:
symbolic links, FIFOs, devices, and sockets are rejected using no-follow
metadata checks before length inspection or opening. Payloads are incrementally
hashed and credential-scanned while streaming into an owner-only staging root;
no package payload is retained in memory.

## Local status

`status` is a local, read-only operation. It reports whether secure roots and
an active state record exist, plus the recorded package ID, version and digest.
It does not infer node health, capability, enrolment, or readiness.

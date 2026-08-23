# Armada Lab mTLS adapter

This is a disabled-by-default, code-composed lab adapter. It has no executable,
configuration binding, CA, claim creation, key persistence, REST routes, or
reflection routes.

The unary enrolment service and byte-oriented stream core are present, but
`LabMtlsAdapter.Compose` intentionally blocks endpoint exposure. ASP.NET Core's
generated gRPC stream binder exposes deserialised messages, not the original
protobuf bytes required by `NodeEnrollmentDecisions.ValidateTransportEnvelope`.
Re-serialising would alter the replay-security boundary. A byte-preserving gRPC
binding is required before this adapter can listen.

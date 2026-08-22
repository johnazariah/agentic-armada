# Agentic Armada record

This directory is the project's durable specification and decision record.
Normative product requirements, architecture decisions, protocols, migration
records and delivery plans live here before corresponding implementation code.

## Integrity rules

- Journal entries are append-only. Corrections are new entries that name the
  entry they supersede.
- A released specification is identified by its repository commit and file
  digest. Release manifests record both.
- Architecture decisions are never edited to reverse history; a later ADR
  supersedes an earlier ADR.
- Evidence references contain immutable content digests and archive locations.
  A URL alone is not evidence identity.
- `.project/` contains this product's records only. Runtime state belongs in the
  control-plane database; node journals belong on the enrolled node.
- `.armada/` is reserved for a consumer repository's declarative Armada/JBOM
  configuration and retained operational references. Its contract is specified
  in `spec/006-consumer-armada-directory.md`.

## Index

| Path | Purpose |
| --- | --- |
| `journal/` | Append-only product and design activity record |
| `adr/` | Architecture decision records |
| `spec/` | Normative requirements and protocol specifications |
| `threat-model/` | Assets, trust boundaries, threats and controls |
| `migration/` | PFQE migration and evidence preservation records |
| `plan/` | Reviewable PR decomposition and acceptance criteria |
| `releases/` | Signed release manifests and compatibility records |

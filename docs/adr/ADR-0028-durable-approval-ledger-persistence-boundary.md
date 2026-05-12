# ADR-0028: Approval Ledger Persistence Boundary (Non-Authoritative)

**Persistence boundary semantics are proven in this repository; production durability is not proven.**

The reference persistence adapter is in-memory only. No database, network, filesystem, or wall-clock
I/O participates in the contract proofs in this slice.

## Status

Accepted.

## Context

ADR-0027 sealed in-memory repository authority with deterministic compare-and-swap semantics,
detached reads, and fail-closed commit proofs. That slice intentionally avoided durable storage.

The next boundary is persistence semantics: canonical serialization, adapter write/load contracts,
corruption detection, and deterministic recovery validation. This ADR must not weaken repository
authority, CAS integrity, checksum binding, or monotonic ledger progression.

This ADR also must not overclaim production durability. Database/network/filesystem durability,
cryptographic non-repudiation, PKI signatures, authentication, or external storage security are
explicitly out of scope.

## Decision

Aegis defines a deterministic persistence boundary contract for approval-ledger repository state:

- `ApprovalLedgerPersistenceRecord`
- `ApprovalLedgerPersistenceReceipt`
- `ApprovalLedgerPersistenceLoadResult`
- `ApprovalLedgerPersistenceValidationResult`
- `ApprovalLedgerRecoveryResult`
- `ApprovalLedgerPersistenceAdapterDescriptor`
- `ApprovalLedgerPersistenceAdapter` protocol

Reference adapter contract:

- `load_current() -> ApprovalLedgerPersistenceLoadResult`
- `persist_transition(persistence_record=...) -> ApprovalLedgerPersistenceReceipt`

Reference implementation:

- `InMemoryApprovalLedgerPersistenceAdapter`

Canonical serialization is mandatory and checksum-bound:

- `json.dumps(..., sort_keys=True, separators=(",", ":"), allow_nan=False)`
- `sha256(canonical_json)`

Recovery is fail-closed:

- Corrupt JSON, malformed payloads, unknown contract versions, checksum drift, partial writes,
  cross-repository replay, cross-epoch replay, rollback, and forked head/state evidence are blocked.
- Persisted payloads are never trusted as authority by existence alone.
- Recovery reconstructs detached contracts through builders and validation, not unsafe constructors.

## Consequences

- Aegis can prove deterministic persistence-boundary semantics for approval-ledger state
  (**persistence boundary semantics proven; production durability not proven**).
- Read-after-write consistency is testable via load + recover over canonical persisted payloads.
- Failed persistence writes do not mutate repository authority.
- Adapter unavailability and malformed payloads fail closed with deterministic reason codes.
- The persistence layer preserves authority evidence; it does not create approval authority.

## Non-Claims

ADR-0028 does **not** prove:

- production durability guarantees (**persistence boundary semantics proven; production durability not proven**),
- database availability or replication guarantees,
- cryptographic non-repudiation or PKI signatures,
- authenticated storage or external storage security.

## Alternatives Considered

- Direct durable backend integration in this slice (SQLite/Postgres/filesystem).
  Rejected: would couple semantic contract hardening to backend behaviour too early.
- Trusting persisted payload bytes as authority.
  Rejected: violates repository-authority-first model and fail-closed design.

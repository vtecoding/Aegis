# ADR-0027: Approval Ledger Repository Contract and Persistence Adapter Boundary

## Status

Accepted.

## Context

ADR-0024 introduced entry-chain integrity, ADR-0025 introduced head/epoch/context authority and
enforced release behavior, and ADR-0026 introduced canonical state snapshot and transition
authority for supplied evidence.

Those slices prove deterministic integrity of supplied evidence but do not prove global "latest"
state ownership. The missing boundary is repository authority: who owns canonical current state for
one epoch/source domain and how stale, forked, rollback, and cross-epoch commits are rejected.

This ADR must not introduce durable persistence backends. No filesystem, network, database, async,
ROS, runtime execution, or side effects are allowed in deterministic core contracts.

## Decision

Aegis defines an approval-ledger repository contract boundary with deterministic proof obligations
and an in-memory reference adapter only.

Repository interface contract:

- `read_current_state(epoch_manifest) -> ApprovalLedgerStateSnapshot` (detached copy)
- `propose_append(previous_snapshot, release_decision, authority_evidence) -> ApprovalLedgerStateTransition`
- `commit_transition(transition, expected_previous_snapshot_checksum) -> RepositoryCommitResult`

`RepositoryCommitResult` is checksum-bound and proves:

- expected previous snapshot matched current state (CAS precondition)
- transition was valid and proposal-bound
- new snapshot became current on successful commit
- stale writes are rejected
- fork attempts are rejected
- rollback attempts are rejected
- cross-epoch commits are rejected

`ApprovalLedgerRepositoryAuthorityEvidence` binds proposal authority inputs:

- prior entry prefix
- ledger head checksum
- epoch manifest checksum
- state source id

The in-memory adapter (`InMemoryApprovalLedgerRepository`) is the only implementation in ADR-0027.
It stores canonical state in memory, enforces CAS commit semantics, blocks unavailable mode, and
returns detached read objects so external mutation of returned contracts cannot mutate repository-owned
canonical state.

## Consequences

- Aegis can now prove deterministic repository commit semantics for one supplied epoch/source domain.
- Repository read APIs no longer expose live canonical references; read isolation is enforced by detached
  snapshot/head copies.
- Deterministic state evidence remains pure, in-memory, and replayable without durability claims.
- The contract is prepared for later durable adapters (SQLite/Postgres/filesystem) without
  changing core deterministic semantics.
- ADR-0027 still does not claim globally latest external state truth beyond supplied domain evidence.
- ADR-0027 does not claim user authentication, PKI signatures, legal non-repudiation, or durable storage.

## Alternatives Considered

- Implementing SQLite/Postgres in ADR-0027. Rejected: persistence is deferred until after contract
  hardening.
- Reusing ADR-0026 transition validation without repository CAS boundary. Rejected: does not close
  stale-read/lost-update/fork commit classes.
- Global mutable singleton state without commit proof result. Rejected: hidden state mutation
  undermines deterministic evidence and replay guarantees.

# Approval Ledger Repository v1

## Scope

Approval Ledger Repository v1 defines deterministic repository authority for canonical
approval-ledger state in one epoch/source domain.

It does not provide durable persistence, storage engines, network replication, databases,
filesystem I/O, signatures, PKI, ROS integration, async operations, or runtime execution.

## Contracts

- `ApprovalLedgerRepositoryAuthorityEvidence` binds proposal authority:
  - prior entries
  - ledger head
  - ledger epoch manifest
  - state source id
  - authority evidence checksum
- `RepositoryCommitResult` binds commit proof obligations:
  - status and reason
  - expected previous snapshot checksum
  - observed previous/current snapshot checksum
  - committed snapshot checksum
  - committed transition checksum
  - repository epoch manifest checksum
  - stale/fork/rollback/cross-epoch rejection flags
  - commit result checksum

## Repository Interface

- `read_current_state(epoch_manifest) -> ApprovalLedgerStateSnapshot` (detached read object)
- `propose_append(previous_snapshot, release_decision, authority_evidence) -> ApprovalLedgerStateTransition`
- `commit_transition(transition, expected_previous_snapshot_checksum) -> RepositoryCommitResult`

## Required Semantics

- `read_current_state` rejects wrong-epoch manifests and returns a detached snapshot copy.
- `current_snapshot` and `current_head` return detached copies; they must never leak live
  repository-owned canonical objects.
- `propose_append` requires valid state snapshot authority evidence; proposal generation is
  deterministic and append-derived.
- `commit_transition` enforces compare-and-swap:
  - expected previous checksum must match current snapshot checksum
  - transition must match proposal-bound evidence
  - successful commit must advance snapshot/head exactly one append step
- blocked commit must never mutate current state.

## Failure Modes (Must Fail Closed)

- stale read accepted as current
- lost update between read and commit
- two writers commit from same previous snapshot
- commit without CAS proof
- wrong-epoch snapshot returned or committed
- snapshot mutated after validation
- transition generated from forged append result
- commit success reported without new head/snapshot transition match
- repository unavailable while canonical commit is attempted
- external mutation of returned read objects mutates repository canonical state

## Reference Adapter

`InMemoryApprovalLedgerRepository` is the ADR-0027 reference adapter.

It is deterministic and in-memory only. Real durable adapters are out of scope for v1 and must be
implemented behind this boundary in later ADRs.

This boundary provides structural deterministic authority only. It does not provide user
authentication, PKI signatures, cryptographic non-repudiation, or durable persistence guarantees.

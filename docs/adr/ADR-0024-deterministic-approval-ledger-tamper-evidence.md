# ADR-0024: Deterministic Approval Ledger & Tamper Evidence

## Status

Accepted.

## Context

ADR-0022 and ADR-0023 bind one quarantine release to authority, identity, nonce, lease, and
replay validation, but they do not prove an ordered history of releases across multiple
quarantine decisions. Structural approvals alone cannot answer whether a claimed sequence of
releases is internally consistent without mutable hidden state.

The deterministic core must still not add filesystem persistence, network transport, async
scheduling, authentication providers, digital signatures, PKI, ROS, runtime execution, queues,
or physical safety claims.

## Decision

Aegis adds ADR-0024 deterministic tamper-evident approval ledger contracts:

- `approval_ledger_genesis_head_checksum()` defines the canonical prior head for an empty
  ledger prefix using the approval ledger contract version and a fixed anchor string.
- `ApprovalLedgerEntry` binds `sequence_index`, `prior_entry_checksum`, `release_decision_checksum`,
  and `entry_checksum`. Each entry checksum is a SHA-256 over canonical JSON of the contract
  version, sequence index, prior head, and the `QuarantineReleaseDecision.decision_checksum`
  being recorded.
- `append_approval_ledger_entry()` validates the prior prefix, requires `release_status ==
  RELEASED_DRY_RUN`, normalizes the supplied release decision checksum, and emits the next
  entry using the construction gate used elsewhere in execution contracts.
- `approval_ledger_prior_chain_block_reason()` validates a prefix for monotonic sequence indices,
  exact hash linkage from genesis through each prior entry checksum, and per-entry checksum drift.
- `validate_approval_ledger_chain()` returns a checksum-bound `ApprovalLedgerChainValidationResult`
  with `VALID` or `BLOCKED` status.
- `approval_ledger_prior_chain_quarantine_block_reason()` maps ledger failures to
  `CommandQuarantineReason` values consumed by `quarantine_release_block_reason()` when callers
  supply `approval_ledger_prior_entries`.

`evaluate_quarantine_release(..., approval_ledger_prior_entries=None)` optionally enforces that
the supplied prior ledger prefix is intact before emitting `RELEASED_DRY_RUN`. When the
parameter is omitted, behaviour matches the pre-ADR-0024 release gate.

## Consequences

- Reordering, omitting, duplicating, forging, or mutating ledger entries fails closed when the
  prior prefix is enforced.
- Positive dry-run releases can be extended with an append-only evidence chain carried by the
  caller as immutable tuples; persistence remains outside the deterministic core.
- Direct construction of valid `ApprovalLedgerEntry` or `VALID` chain validation results without
  the internal construction tokens remains blocked.
- The ledger does not authenticate human operators, sign decisions, or prove runtime robot
  safety; it only binds ordered release decision checksums under explicit checksum rules.

## Alternatives Considered

- Mutable in-memory nonce tables for ordering. Rejected because hidden mutable state breaks
  replayable evidence and contradicts ADR-0023’s explicit binding discipline.
- Filesystem or networked append logs. Rejected because core I/O remains forbidden without a
  dedicated ADR.
- PKI-backed signed journals. Rejected because signatures and PKI are explicitly out of scope
  for this structural slice.

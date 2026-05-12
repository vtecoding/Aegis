# ADR-0026: Canonical Approval Ledger State Boundary

## Status

Accepted.

## Context

ADR-0024 introduced hash-linked approval ledger entries and ADR-0025 introduced epoch/context-
bound ledger heads. Those slices prove integrity and authority binding, but they do not yet prove
that a supplied head represents the expected canonical current state for a release domain.

A caller can still replay an old valid snapshot, present a forked head with a valid internal
shape, or drift state-source authority without an explicit state-boundary contract.

The deterministic core must remain pure, synchronous, in-memory, and non-persistent. This ADR
must not add filesystem or database persistence, network calls, async behavior, signatures, PKI,
authentication, ROS integration, runtime execution, or durable audit claims.

## Decision

Aegis now defines a deterministic canonical approval-ledger state boundary. ADR-0026 proves that
a supplied ledger head can be validated against a checksum-bound state snapshot and deterministic
transition evidence.

New contracts:

- `ApprovalLedgerStateSnapshot` binds one canonical current state using:
  `ledger_epoch_manifest_checksum`, `ledger_head_checksum`, tip sequence/checksum, genesis,
  context authority, backend admission, `state_source_id`, and `state_snapshot_checksum`.
- `ApprovalLedgerStateTransition` binds one append transition from snapshot N to N+1 with strict
  monotonic sequence progression and append-result/head/snapshot consistency.
- `LedgerStateValidationResult` provides checksum-bound `VALID` or `BLOCKED` evidence. `VALID`
  construction is token-gated and cannot be forged directly.

New deterministic functions:

- `build_approval_ledger_state_snapshot()`
- `validate_approval_ledger_state_snapshot()`
- `build_approval_ledger_state_transition()`
- `validate_approval_ledger_state_transition()`
- `approval_ledger_state_block_reason()`
- `approval_ledger_state_quarantine_block_reason()`
- `append_to_approval_ledger_state()` helper for end-to-end append evidence (optional API)

Release wiring in `evaluate_quarantine_release()` and `quarantine_release_block_reason()` adds:

- `approval_ledger_state_snapshot`
- `approval_ledger_state_source_id`
- `approval_ledger_state_enforced`

Behavior:

- If `approval_ledger_head` is `None`, ADR-0026 state validation does not activate.
- If head is supplied and snapshot is omitted, ADR-0025 behavior remains unless
  `approval_ledger_state_enforced=True`, which returns
  `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_REQUIRED`.
- If snapshot is supplied, the release path requires valid prior entries, a valid head, a valid
  snapshot, and exact epoch/context/backend/tip/source consistency; otherwise it returns
  `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID`.

New quarantine reason codes:

- `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_REQUIRED`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_TRANSITION_INVALID` (reserved for transition-gated use)

Governance additions:

- New field sentinels for snapshot/transition/validation contracts
- New strict property profiles for ADR-0026
- New scenario categories for valid state, stale/forked heads, rollback/skip, cross-epoch graft,
  and source drift
- Adapter authority manifest registrations for all ADR-0026 contracts

## Consequences

- Release logic can now distinguish chain validity, head validity, epoch validity, and canonical
  current-state validity as separate boundaries.
- Stale, forked, rollback, skip, cross-epoch, source-drift, and malformed state evidence blocks
  before release.
- ADR-0026 defines a pure state authority contract that future persistence adapters must satisfy.
- This ADR does not introduce persistence, durable audit logging, non-repudiation, or operator
  identity guarantees beyond already-established deterministic evidence boundaries.

## Alternatives Considered

- Reusing only `ApprovalLedgerHead` as canonical state. Rejected because head validity alone does
  not prove a caller-supplied state authority source or transition continuity proof.
- Mutable in-memory global "current state". Rejected because hidden mutable state breaks explicit
  replay evidence and deterministic call-bound proofs.
- Introducing persistence in ADR-0026. Rejected by architecture sequence; persistence belongs to
  ADR-0027+.

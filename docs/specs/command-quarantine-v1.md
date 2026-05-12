# Runtime Command Quarantine & Operator Approval Receipt v1

## Scope

Command Quarantine v1 adds a deterministic quarantine layer between valid runtime capability
leases and any future executable boundary. It does not execute commands, publish messages,
enqueue work, call ROS, contact a runtime backend, read files, read environment variables,
call hardware, use async scheduling, read clocks, generate random IDs, authenticate operators,
sign receipts, or make physical safety claims.

## Contracts

- `CommandQuarantineEnvelope` records `QUARANTINED` dispatch intent and binds dispatch plan,
  backend admission, capability lease, backend descriptor, authority manifest, registry,
  certification, backend replay proof, context authority, every quarantined item, epoch, and
  quarantine checksum.
- `OperatorApprovalReceipt` records `APPROVED` or `REJECTED`, operator id, quarantine checksum,
  explicit approved item-checksum scope, epoch, reason, and approval checksum. ADR-0023
  supersedes this as release authority; it remains structural evidence only.
- `AuthorityBoundApprovalReceipt` and `ApprovalReplayValidationResult` record the ADR-0023
  authority-bound approval and replay validation proof required for release.
- `QuarantineReleaseDecision` records `RELEASED_DRY_RUN` or `BLOCKED`, reason code, quarantine
  checksum, approval checksum, lease checksum, dispatch plan checksum, released item count,
  and decision checksum.
- `ApprovalLedgerEntry` and `ApprovalLedgerChainValidationResult` (ADR-0024) record an optional
  hash-linked history of release decision checksums for tamper-evident ordering evidence carried
  by the caller as immutable tuples.
- `ApprovalLedgerHead` and `LedgerEpochManifest` (ADR-0025) bind epoch and context authority for
  deterministic head validation.
- `ApprovalLedgerStateSnapshot`, `ApprovalLedgerStateTransition`, and
  `LedgerStateValidationResult` (ADR-0026) define the canonical current state boundary and
  deterministic append transition evidence for one epoch/state-source authority domain.

## Release Requirements

`QuarantineReleaseDecision.status == RELEASED_DRY_RUN` requires all of the following:

- quarantine is an exact `CommandQuarantineEnvelope` with status `QUARANTINED`
- quarantine checksum recomputes
- every dispatch item is present in quarantine with no partial omission
- lease is an exact active `RuntimeCapabilityLease` and validates against current evidence
- backend admission decision status is exactly `ADMITTED`
- dispatch plan, backend admission, descriptor, manifest, registry, certification, replay proof,
  lease, and context authority checksums match exactly
- approval is an exact ADR-0023 `AuthorityBoundApprovalReceipt`
- approval replay validation is an exact ADR-0023 `ApprovalReplayValidationResult` with status
  `VALID`
- approval status is `APPROVED`
- approval checksum recomputes
- approval quarantine checksum matches the quarantine envelope
- approval epoch equals the quarantine epoch
- operator id is structurally well formed
- approval scope is explicit, non-empty, non-wildcard, subset-bounded, and matches every
  quarantined item checksum
- when `approval_ledger_prior_entries` is supplied to `evaluate_quarantine_release()`, the tuple
  contains only `ApprovalLedgerEntry` values, monotonic `sequence_index` values starting at zero,
  each `prior_entry_checksum` equals the genesis head or the previous entry checksum, and every
  `entry_checksum` recomputes from its authoritative fields
- when `approval_ledger_head` is supplied, the head must validate against the same prior chain,
  epoch, and context authority
- when `approval_ledger_state_snapshot` is supplied, snapshot validation requires exact binding to
  the supplied head, derived epoch manifest, context authority, backend admission checksum, and
  optional `approval_ledger_state_source_id`
- when `approval_ledger_state_enforced` is true and a head is supplied, missing
  `approval_ledger_state_snapshot` blocks with
  `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_REQUIRED`

## Failure Reasons

- `COMMAND_QUARANTINE_MISSING_APPROVAL`
- `COMMAND_QUARANTINE_APPROVAL_REJECTED`
- `COMMAND_QUARANTINE_APPROVAL_STATUS_INVALID`
- `COMMAND_QUARANTINE_APPROVAL_CHECKSUM_DRIFT`
- `COMMAND_QUARANTINE_APPROVAL_QUARANTINE_MISMATCH`
- `COMMAND_QUARANTINE_CHECKSUM_DRIFT`
- `COMMAND_QUARANTINE_STATUS_INVALID`
- `COMMAND_QUARANTINE_LEASE_CHECKSUM_DRIFT`
- `COMMAND_QUARANTINE_LEASE_REVOKED`
- `COMMAND_QUARANTINE_LEASE_INVALID`
- `COMMAND_QUARANTINE_DISPATCH_PLAN_DRIFT`
- `COMMAND_QUARANTINE_BACKEND_ADMISSION_DRIFT`
- `COMMAND_QUARANTINE_BACKEND_DESCRIPTOR_DRIFT`
- `COMMAND_QUARANTINE_REGISTRY_DRIFT`
- `COMMAND_QUARANTINE_MANIFEST_DRIFT`
- `COMMAND_QUARANTINE_CERTIFICATION_DRIFT`
- `COMMAND_QUARANTINE_REPLAY_PROOF_DRIFT`
- `COMMAND_QUARANTINE_CONTEXT_AUTHORITY_DRIFT`
- `COMMAND_QUARANTINE_WILDCARD_APPROVAL_SCOPE`
- `COMMAND_QUARANTINE_OVERBROAD_APPROVAL_SCOPE`
- `COMMAND_QUARANTINE_APPROVAL_SCOPE_EMPTY`
- `COMMAND_QUARANTINE_MISSING_APPROVAL_REPLAY_VALIDATION`
- `COMMAND_QUARANTINE_APPROVAL_REPLAY_BLOCKED`
- `COMMAND_QUARANTINE_APPROVAL_REPLAY_CHECKSUM_DRIFT`
- `COMMAND_QUARANTINE_APPROVAL_REPLAY_BINDING_MISMATCH`
- `COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION`
- `COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH`
- `COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED`
- `COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_CHAIN_INVALID`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_HEAD_INVALID`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_ENFORCED_MODE_BYPASS`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_INVALID`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_REQUIRED`
- `COMMAND_QUARANTINE_APPROVAL_LEDGER_STATE_TRANSITION_INVALID`
- `DIRECT_QUARANTINE_RELEASE_CONSTRUCTION`

## Scenario Categories

- `COMMAND_QUARANTINE_POSITIVE`
- `COMMAND_QUARANTINE_REQUIRES_VALID_LEASE`
- `COMMAND_QUARANTINE_MISSING_APPROVAL`
- `COMMAND_QUARANTINE_REJECTED_APPROVAL`
- `COMMAND_QUARANTINE_SCOPE_OVERCLAIM`
- `COMMAND_QUARANTINE_EVIDENCE_DRIFT`
- `COMMAND_QUARANTINE_STALE_APPROVAL`
- `COMMAND_QUARANTINE_PARTIAL_OMISSION`
- `COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION`
- `COMMAND_QUARANTINE_RELEASE_DRY_RUN_ONLY`

## Invariants

- Repeated quarantine over identical evidence produces the same quarantine checksum.
- Repeated release over identical quarantine, approval, lease, and evidence produces the same
  release checksum.
- No release is possible without explicit approval evidence.
- No release is possible without replay-valid ADR-0023 operator authority evidence.
- Rejected approval never releases quarantine.
- Any bound field change changes a checksum or blocks release.
- Approval scope cannot be wildcard, empty, overbroad, or partial for release.
- Quarantine creation and release do not mutate source evidence.
- Release decisions expose no execution, publish, queue, ROS, or backend operation.
- Canonical state validation remains in-memory and deterministic only; it does not provide
  persistence, durability, signatures, PKI, or non-repudiation.

## Release Gate

Command Quarantine v1 is complete only when lease-valid dispatch intent is quarantined by
default, no quarantine releases without explicit replay-valid ADR-0023 operator authority,
approval/release is bound to the dispatch, backend, lease, registry, manifest, replay, and
context chain, rejected, missing, stale, overbroad, drifted, or injected paths fail closed,
scenario/governance sentinels cover ADR-0022 and ADR-0023, forbidden runtime imports remain
absent, and `python scripts\verify.py verify` passes.
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
  explicit approved item-checksum scope, epoch, reason, and approval checksum.
- `QuarantineReleaseDecision` records `RELEASED_DRY_RUN` or `BLOCKED`, reason code, quarantine
  checksum, approval checksum, lease checksum, dispatch plan checksum, released item count,
  and decision checksum.

## Release Requirements

`QuarantineReleaseDecision.status == RELEASED_DRY_RUN` requires all of the following:

- quarantine is an exact `CommandQuarantineEnvelope` with status `QUARANTINED`
- quarantine checksum recomputes
- every dispatch item is present in quarantine with no partial omission
- lease is an exact active `RuntimeCapabilityLease` and validates against current evidence
- backend admission decision status is exactly `ADMITTED`
- dispatch plan, backend admission, descriptor, manifest, registry, certification, replay proof,
  lease, and context authority checksums match exactly
- approval is an exact `OperatorApprovalReceipt`
- approval status is `APPROVED`
- approval checksum recomputes
- approval quarantine checksum matches the quarantine envelope
- approval epoch equals the quarantine epoch
- operator id is structurally well formed
- approval scope is explicit, non-empty, non-wildcard, subset-bounded, and matches every
  quarantined item checksum

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
- `COMMAND_QUARANTINE_PARTIAL_ITEM_OMISSION`
- `COMMAND_QUARANTINE_STALE_APPROVAL_EPOCH`
- `COMMAND_QUARANTINE_OPERATOR_ID_MALFORMED`
- `COMMAND_QUARANTINE_RUNTIME_OBJECT_INJECTION`
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
- Rejected approval never releases quarantine.
- Any bound field change changes a checksum or blocks release.
- Approval scope cannot be wildcard, empty, overbroad, or partial for release.
- Quarantine creation and release do not mutate source evidence.
- Release decisions expose no execution, publish, queue, ROS, or backend operation.

## Release Gate

Command Quarantine v1 is complete only when lease-valid dispatch intent is quarantined by
default, no quarantine releases without explicit operator approval, approval/release is bound to
the dispatch, backend, lease, registry, manifest, replay, and context chain, rejected, missing,
stale, overbroad, drifted, or injected paths fail closed, scenario/governance sentinels cover
ADR-0022, forbidden runtime imports remain absent, and `python scripts\verify.py verify` passes.
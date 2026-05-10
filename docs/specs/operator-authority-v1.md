# Operator Authority, Approval Identity & Anti-Replay Boundary v1

## Scope

Operator Authority v1 makes quarantine approval authority-bound and replay-resistant through
deterministic structural evidence. It does not authenticate operators, create sessions, use
OAuth/JWT, sign receipts, add PKI, call ROS, execute commands, publish messages, enqueue work,
read files, read environment variables, call hardware, use async scheduling, read clocks,
generate random IDs, or make physical safety claims.

## Contracts

- `OperatorAuthorityManifest` records authority id/version, allowed operator roles, allowed
  approval scopes, required context authority checksum, approval epoch,
  `ACTIVE_STRUCTURAL_ONLY`, and manifest checksum.
- `OperatorIdentityClaim` records operator id, operator role, authority manifest checksum,
  context authority checksum, identity epoch, and identity checksum.
- `OperatorApprovalNonce` records deterministic nonce id, quarantine checksum, operator identity
  checksum, approval epoch, and nonce checksum.
- `AuthorityBoundApprovalReceipt` records approval id, `APPROVED` or `REJECTED`, quarantine
  checksum, identity checksum, authority manifest checksum, nonce checksum, explicit approval
  scope, approval epoch, and authority-bound checksum.
- `ApprovalReplayValidationResult` records `VALID` or `BLOCKED`, reason code, approval checksum,
  quarantine checksum, identity checksum, authority manifest checksum, nonce checksum, context
  authority checksum, and replay-validation checksum.

## Valid Replay Requirements

`ApprovalReplayValidationResult.status == VALID` requires all of the following:

- authority manifest is present, active structural-only, and its checksum recomputes
- operator role exists in the manifest and is not wildcarded
- operator id is non-empty, canonical, and structurally well formed
- identity checksum recomputes and binds the manifest, context authority, role, and epoch
- nonce checksum recomputes and binds exactly one quarantine checksum, one identity checksum,
  and one approval epoch
- quarantine checksum recomputes and status is `QUARANTINED`
- dispatch plan, capability lease, backend admission, backend descriptor, backend manifest,
  registry, certification, backend replay proof, and context authority match the quarantine and
  current evidence chain exactly
- approval checksum recomputes and binds the exact quarantine, identity, authority manifest,
  nonce, explicit scope, and epoch
- approval status is `APPROVED`
- approval scope is non-empty, non-wildcard, subset-bounded by the manifest and quarantine, and
  matches the quarantined item scope for release
- all approval, identity, nonce, manifest, quarantine, and lease epochs match

## Failure Reasons

- `OPERATOR_AUTHORITY_UNKNOWN_OPERATOR_ROLE`
- `OPERATOR_AUTHORITY_WILDCARD_OPERATOR_ROLE`
- `OPERATOR_AUTHORITY_WILDCARD_APPROVAL_SCOPE`
- `OPERATOR_AUTHORITY_APPROVAL_SCOPE_EMPTY`
- `OPERATOR_AUTHORITY_OPERATOR_ID_MALFORMED`
- `OPERATOR_AUTHORITY_MANIFEST_DRIFT`
- `OPERATOR_AUTHORITY_CONTEXT_AUTHORITY_DRIFT`
- `OPERATOR_AUTHORITY_IDENTITY_CHECKSUM_DRIFT`
- `OPERATOR_AUTHORITY_NONCE_CHECKSUM_DRIFT`
- `OPERATOR_AUTHORITY_APPROVAL_CHECKSUM_DRIFT`
- `OPERATOR_AUTHORITY_NONCE_QUARANTINE_REPLAY`
- `OPERATOR_AUTHORITY_NONCE_IDENTITY_REPLAY`
- `OPERATOR_AUTHORITY_QUARANTINE_REPLAY`
- `OPERATOR_AUTHORITY_DISPATCH_PLAN_REPLAY`
- `OPERATOR_AUTHORITY_LEASE_REPLAY`
- `OPERATOR_AUTHORITY_BACKEND_ADMISSION_REPLAY`
- `OPERATOR_AUTHORITY_BACKEND_DESCRIPTOR_REPLAY`
- `OPERATOR_AUTHORITY_REGISTRY_REPLAY`
- `OPERATOR_AUTHORITY_CERTIFICATION_REPLAY`
- `OPERATOR_AUTHORITY_BACKEND_REPLAY_PROOF_REPLAY`
- `OPERATOR_AUTHORITY_OPERATOR_IDENTITY_REPLAY`
- `OPERATOR_AUTHORITY_ROLE_REPLAY`
- `OPERATOR_AUTHORITY_EPOCH_REPLAY`
- `OPERATOR_AUTHORITY_OVERBROAD_APPROVAL_SCOPE`
- `OPERATOR_AUTHORITY_PARTIAL_APPROVAL_SCOPE`
- `OPERATOR_AUTHORITY_REJECTED_APPROVAL`
- `OPERATOR_AUTHORITY_APPROVAL_STATUS_INVALID`
- `OPERATOR_AUTHORITY_MISSING_AUTHORITY_MANIFEST`
- `OPERATOR_AUTHORITY_RUNTIME_OBJECT_INJECTION`
- `DIRECT_AUTHORITY_BOUND_APPROVAL_CONSTRUCTION`
- `DIRECT_APPROVAL_REPLAY_VALIDATION_CONSTRUCTION`

## Scenario Categories

- `OPERATOR_AUTHORITY_POSITIVE`
- `OPERATOR_AUTHORITY_UNKNOWN_ROLE`
- `OPERATOR_AUTHORITY_SCOPE_OVERCLAIM`
- `OPERATOR_AUTHORITY_MANIFEST_DRIFT`
- `OPERATOR_AUTHORITY_CONTEXT_DRIFT`
- `OPERATOR_AUTHORITY_NONCE_REPLAY`
- `OPERATOR_AUTHORITY_CROSS_QUARANTINE_REPLAY`
- `OPERATOR_AUTHORITY_CROSS_OPERATOR_REPLAY`
- `OPERATOR_AUTHORITY_EPOCH_REPLAY`
- `OPERATOR_AUTHORITY_OBJECT_INJECTION`

## Invariants

- Repeated authority-bound approval validation over identical evidence produces the same result.
- `VALID` is impossible without an authority manifest, identity claim, nonce, and exact evidence
  chain match.
- Any approval-bound field change changes the approval checksum or blocks replay validation.
- Nonce evidence cannot be reused across quarantine envelopes or operator identities.
- Structural `OperatorApprovalReceipt` alone cannot release quarantine.
- Approval validation does not mutate source evidence.

## Release Gate

Operator Authority v1 is complete only when release requires replay-valid authority-bound
approval, structural-only approval cannot release quarantine, replay across quarantine,
dispatch, lease, backend admission, operator, role, epoch, scope, and context fails closed,
scenario/governance sentinels cover ADR-0023, forbidden runtime imports remain absent, and
`python scripts\verify.py verify` passes.
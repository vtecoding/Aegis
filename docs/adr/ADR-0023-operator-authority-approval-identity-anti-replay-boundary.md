# ADR-0023: Operator Authority, Approval Identity & Anti-Replay Boundary

## Status

Accepted.

## Context

ADR-0022 proves that a structural operator approval receipt exists before quarantine release,
but it does not prove the approval came from an authorized operator role, under a current
authority manifest, for the exact quarantine and runtime evidence chain. Lease validity and a
structural approval receipt must not imply runtime eligibility.

The deterministic core still must not add an auth provider, login/session system, signatures,
PKI, OAuth/JWT, ROS, runtime execution, queues, DDS, publishing, simulator, hardware,
filesystem reads, network calls, environment reads, async scheduling, or physical safety claims.

## Decision

Aegis adds ADR-0023 structural operator authority and anti-replay contracts:

- `OperatorAuthorityManifest` binds allowed operator roles, allowed approval scopes, required
  context authority, approval epoch, `ACTIVE_STRUCTURAL_ONLY` status, and manifest checksum.
- `OperatorIdentityClaim` binds a canonical operator id and role to one authority manifest,
  context authority, identity epoch, and identity checksum.
- `OperatorApprovalNonce` is deterministic evidence, not randomness. It binds one identity to
  one quarantine checksum and approval epoch.
- `AuthorityBoundApprovalReceipt` binds approval status, quarantine checksum, identity checksum,
  authority manifest checksum, nonce checksum, explicit scope, epoch, and checksum.
- `ApprovalReplayValidationResult` returns `VALID` only when the approval, identity, manifest,
  nonce, quarantine, lease, dispatch plan, backend admission, registry, certification, backend
  replay proof, epoch, scope, and context authority all match exactly.

`QuarantineReleaseDecision.status == RELEASED_DRY_RUN` now requires a replay-valid
`ApprovalReplayValidationResult`. A structural `OperatorApprovalReceipt` alone is insufficient
for release.

## Consequences

- Unknown roles, wildcard roles, wildcard scopes, malformed operator ids, manifest drift,
  context drift, identity drift, nonce drift, rejected approvals, overbroad scope, epoch drift,
  cross-quarantine replay, cross-operator replay, and evidence-chain replay fail closed.
- Positive release decisions bind the authority-bound approval checksum and replay-validation
  checksum.
- Direct public construction of a valid authority-bound approval or valid replay result is
  blocked.
- This remains structural-only identity. It does not authenticate real operators, sign receipts,
  provide PKI, or make runtime/robot/collision/middleware/certification safety claims.

## Alternatives Considered

- Treat ADR-0022 structural receipts as sufficient. Rejected because structure is not authority.
- Add real authentication, signatures, or PKI in this slice. Rejected because ADR-0023 is a
  deterministic structural boundary; external authentication belongs to a later phase.
- Store nonce state in mutable memory. Rejected because replay resistance must be proven by
  explicit evidence binding, not hidden mutable state.
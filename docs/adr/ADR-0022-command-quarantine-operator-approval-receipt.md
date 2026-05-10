# ADR-0022: Runtime Command Quarantine & Operator Approval Receipt

## Status

Accepted.

## Context

ADR-0021 proves that an admitted null backend can receive a deterministic capability lease,
but a valid lease is not approval to make runtime intent eligible for any future executable
boundary. Runtime dispatch intent must stop in quarantine by default and remain inert until
an explicit operator approval or rejection receipt is supplied.

The deterministic core still must not import ROS packages, execute commands, publish
messages, enqueue work, call a backend, open sockets, read files, read environment variables,
use async scheduling, read clocks, generate random IDs, or make physical safety claims.

## Decision

Aegis adds ADR-0022 command quarantine contracts and evaluators:

- `CommandQuarantineEnvelope` binds a valid dispatch plan, backend admission decision,
  capability lease, backend descriptor, authority manifest, registry, certification,
  backend replay proof, context authority, every quarantined dispatch item, explicit epoch,
  `QUARANTINED` status, and quarantine checksum.
- `OperatorApprovalReceipt` binds an explicit operator id, `APPROVED` or `REJECTED` status,
  quarantine checksum, explicit item-checksum scope, approval epoch, reason, and checksum.
- `QuarantineReleaseDecision` emits `RELEASED_DRY_RUN` only through the release evaluator and
  otherwise returns `BLOCKED` with a deterministic reason code.

Release requires a valid quarantine, valid active lease, approved operator receipt, exact
evidence-chain match across dispatch, admission, lease, descriptor, manifest, registry,
certification, replay proof, and context authority, plus approval scope matching every
quarantined item. Direct public construction of a released decision is blocked.

## Consequences

- Lease-valid dispatch intent enters quarantine by default.
- Missing, rejected, stale, overbroad, wildcard, drifted, malformed, or injected approvals
  fail closed.
- Registry, manifest, descriptor, backend admission, certification, replay proof, dispatch,
  lease, quarantine, approval, context authority, and item-scope drift fail closed.
- Scenario and governance sentinels now include ADR-0022 quarantine categories and
  checksum-field coverage.
- This does not add ROS, simulator, hardware, filesystem, network, async, queueing,
  execution, actuation, operator authentication, signatures, PKI, or physical safety claims.

## Alternatives Considered

- Treat a valid lease as sufficient release authority. Rejected because leases do not prove
  explicit human/operator approval.
- Allow partial approval scope to release a subset of quarantined items. Rejected for this
  slice because ADR-0022 requires explicit scope match and no silent item omission.
- Add operator identity authority, anti-replay, signatures, or PKI now. Rejected because that
  is the next boundary, ADR-0023.
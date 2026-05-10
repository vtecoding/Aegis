# Runtime Backend Replay & No-Execution Proof Harness v1

## Scope

Backend Replay v1 replays ADR-0018 null backend certification and dry-run receipt evidence
from immutable dispatch, firewall, descriptor, certification, and receipt contracts. It
does not execute commands, publish messages, start nodes, open sockets, read files, read
environment variables, call hardware, use async scheduling, read clocks, generate random
IDs, or import ROS/runtime SDKs.

## Contracts

- `BackendReplayRequest` binds a `RuntimeDispatchPlan`, `DispatchFirewallDecision`,
  `RuntimeBackendDescriptor`, expected `BackendCertificationResult`, expected
  `BackendDryRunReceipt`, `STRICT_BACKEND_REPLAY_V1`, and a closed mutation profile.
- `BackendReplayProofResult` returns `PASSED`, `FAILED`, or `BLOCKED` with checksums for
  dispatch, firewall, descriptor, expected/replayed certification, expected/replayed
  receipt, zero-execution verification, scope verification, match booleans, mutation
  detection, failure stage, and proof checksum.

## Passed Requirements

`BackendReplayProofResult.status == PASSED` requires all of the following:

- dispatch plan checksum recomputes
- firewall decision status is exactly `ALLOWED_DRY_RUN`
- firewall decision checksum recomputes
- firewall decision plan checksum matches the dispatch plan
- backend descriptor checksum recomputes
- backend descriptor is exactly the canonical `NullRuntimeBackend` descriptor for the plan
- backend kind is exactly `NULL_BACKEND_V1`
- backend mode is exactly `DRY_RUN_CERTIFICATION_ONLY`
- execution, I/O, and async flags are false
- capability scope exactly matches the dispatch plan
- runtime-kind scope exactly matches the dispatch plan
- expected certification is `CERTIFIED_NULL`
- replayed certification exactly matches expected certification
- replayed receipt exactly matches expected receipt
- expected and replayed receipts both have `executed_count == 0`

## Failure Reasons

- `BACKEND_REPLAY_FIREWALL_DECISION_NOT_ALLOWED`
- `BACKEND_REPLAY_DISPATCH_PLAN_CHECKSUM_DRIFT`
- `BACKEND_REPLAY_FIREWALL_DECISION_CHECKSUM_DRIFT`
- `BACKEND_REPLAY_FIREWALL_PLAN_MISMATCH`
- `BACKEND_REPLAY_DESCRIPTOR_CHECKSUM_DRIFT`
- `BACKEND_REPLAY_DESCRIPTOR_SHAPE_MISMATCH`
- `BACKEND_REPLAY_BACKEND_KIND_NOT_NULL`
- `BACKEND_REPLAY_BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY`
- `BACKEND_REPLAY_EXECUTION_CAPABILITY_CLAIMED`
- `BACKEND_REPLAY_IO_CAPABILITY_CLAIMED`
- `BACKEND_REPLAY_ASYNC_CAPABILITY_CLAIMED`
- `BACKEND_REPLAY_CAPABILITY_SCOPE_DRIFT`
- `BACKEND_REPLAY_RUNTIME_KIND_SCOPE_DRIFT`
- `BACKEND_REPLAY_EXPECTED_CERTIFICATION_NOT_CERTIFIED_NULL`
- `BACKEND_REPLAY_CERTIFICATION_CHECKSUM_DRIFT`
- `BACKEND_REPLAY_CERTIFICATION_DISPATCH_PLAN_MISMATCH`
- `BACKEND_REPLAY_CERTIFICATION_FIREWALL_DECISION_MISMATCH`
- `BACKEND_REPLAY_CERTIFICATION_DESCRIPTOR_MISMATCH`
- `BACKEND_REPLAY_RECEIPT_EXECUTED_COUNT_NONZERO`
- `BACKEND_REPLAY_RECEIPT_CHECKSUM_DRIFT`
- `BACKEND_REPLAY_RECEIPT_ITEM_COUNT_DRIFT`
- `BACKEND_REPLAY_RECEIPT_PLAN_MISMATCH`
- `BACKEND_REPLAY_RECEIPT_FIREWALL_DECISION_MISMATCH`
- `BACKEND_REPLAY_RECEIPT_CERTIFICATION_MISMATCH`
- `BACKEND_REPLAY_RECEIPT_BACKEND_DESCRIPTOR_MISMATCH`
- `BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION`

## Scenario Categories

- `BACKEND_REPLAY_POSITIVE`
- `BACKEND_REPLAY_REQUIRES_CERTIFIED_NULL`
- `BACKEND_REPLAY_DISPATCH_DRIFT`
- `BACKEND_REPLAY_FIREWALL_DRIFT`
- `BACKEND_REPLAY_DESCRIPTOR_DRIFT`
- `BACKEND_REPLAY_SCOPE_DRIFT`
- `BACKEND_REPLAY_RECEIPT_EXECUTION_DRIFT`
- `BACKEND_REPLAY_CROSS_PLAN_SWAP`
- `BACKEND_REPLAY_RUNTIME_OBJECT_INJECTION`
- `BACKEND_REPLAY_CHECKSUM_DRIFT`

## Invariants

- Repeated backend replay over identical evidence produces the same proof checksum.
- `PASSED` is impossible when either expected or replayed receipt has non-zero execution.
- Any proof-bound field change changes the proof checksum or blocks replay.
- Runtime object, callable, client, and mutable descriptor injection cannot produce
  `PASSED`.
- Backend replay does not mutate dispatch, firewall, descriptor, certification, or receipt
  evidence.

## Release Gate

Backend Replay v1 is complete only when certification and receipt generation are
independently replay-verifiable, every listed mutation fails closed, scenario/governance
sentinels cover ADR-0019, forbidden runtime imports remain absent, and
`python scripts\verify.py verify` passes.
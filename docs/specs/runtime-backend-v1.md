# Runtime Backend Interface Contract & Null Backend Certification v1

## Scope

Runtime Backend v1 certifies the only implemented backend, `NullRuntimeBackend`, against a
firewall-allowed `DRY_RUN_ONLY` `RuntimeDispatchPlan`. It does not execute commands,
publish messages, start nodes, open sockets, read files, read environment variables, call
hardware, use async scheduling, read clocks, generate random IDs, or import ROS/runtime
SDKs.

## Contracts

- `RuntimeBackendDescriptor` declares backend identity, backend kind, backend mode,
  supported runtime kinds, supported capabilities, execution/I/O/async flags, and a
  descriptor checksum.
- `RuntimeBackendContract` exposes descriptor evidence only.
- `NullRuntimeBackend` is the only concrete backend implementation.
- `BackendCertificationResult` returns `CERTIFIED_NULL` or `BLOCKED` with plan, firewall,
  descriptor, guarantee, scope, and certification checksum bindings.
- `BackendDryRunReceipt` binds the dispatch plan, firewall decision, backend certification,
  backend descriptor, observed inert dispatch item IDs, zero execution count, blocked
  execution count, and receipt checksum.

## Certification Requirements

`BackendCertificationResult.status == CERTIFIED_NULL` requires all of the following:

- dispatch plan mode is exactly `DRY_RUN_ONLY`
- dispatch firewall decision status is exactly `ALLOWED_DRY_RUN`
- dispatch plan checksum recomputes
- firewall decision checksum recomputes
- firewall decision plan checksum matches the dispatch plan
- backend descriptor checksum recomputes
- backend kind is exactly `NULL_BACKEND_V1`
- backend mode is exactly `DRY_RUN_CERTIFICATION_ONLY`
- backend declares no execution capability
- backend declares no I/O capability
- backend declares no async capability
- backend exposes no callable, client, runtime, mutable, ROS, network, filesystem, async, or
  environment-backed object
- backend implementation is exactly `NullRuntimeBackend`
- backend capability scope exactly matches the dispatch plan capability scope
- backend runtime-kind scope exactly matches the dispatch plan runtime-kind scope

## Failure Reasons

- `BACKEND_FIREWALL_DECISION_NOT_ALLOWED`
- `BACKEND_DISPATCH_MODE_NOT_DRY_RUN_ONLY`
- `BACKEND_DISPATCH_PLAN_CHECKSUM_MISMATCH`
- `BACKEND_FIREWALL_DECISION_CHECKSUM_MISMATCH`
- `BACKEND_FIREWALL_PLAN_MISMATCH`
- `BACKEND_UNSUPPORTED_IMPLEMENTATION`
- `BACKEND_DESCRIPTOR_CHECKSUM_MISMATCH`
- `BACKEND_KIND_NOT_NULL`
- `BACKEND_MODE_NOT_DRY_RUN_CERTIFICATION_ONLY`
- `BACKEND_EXECUTION_CAPABILITY_CLAIMED`
- `BACKEND_IO_CAPABILITY_CLAIMED`
- `BACKEND_ASYNC_CAPABILITY_CLAIMED`
- `BACKEND_RUNTIME_OBJECT_INJECTION`
- `BACKEND_CAPABILITY_SCOPE_DRIFT`
- `BACKEND_RUNTIME_KIND_SCOPE_DRIFT`
- `BACKEND_CERTIFICATION_CHECKSUM_DRIFT`
- `BACKEND_RECEIPT_EXECUTED_COUNT_NONZERO`
- `BACKEND_RECEIPT_CHECKSUM_MISMATCH`

## Scenario Categories

- `BACKEND_NULL_POSITIVE`
- `BACKEND_REQUIRES_FIREWALL_ALLOWED_PLAN`
- `BACKEND_REJECTS_NON_NULL_KIND`
- `BACKEND_REJECTS_EXECUTION_CAPABILITY`
- `BACKEND_REJECTS_IO_CAPABILITY`
- `BACKEND_REJECTS_ASYNC_CAPABILITY`
- `BACKEND_REJECTS_RUNTIME_OBJECT_INJECTION`
- `BACKEND_REJECTS_SCOPE_DRIFT`
- `BACKEND_RECEIPT_ZERO_EXECUTION`
- `BACKEND_CERTIFICATION_CHECKSUM_DRIFT`

## Invariants

- Same dispatch plan, firewall decision, and backend descriptor produce the same
  certification checksum.
- Repeated null-backend receipt construction for the same evidence produces the same
  receipt checksum.
- `CERTIFIED_NULL` is impossible without an `ALLOWED_DRY_RUN` firewall decision.
- Any bound field change changes a checksum or blocks certification/receipt construction.
- Null backend certification and receipt construction do not mutate the dispatch plan.
- Backend dry-run receipts always report `executed_count == 0`.

## Release Gate

Runtime Backend v1 is complete only when a firewall-allowed dry-run dispatch plan can
produce a certified null-backend receipt, the only implemented backend is non-executing,
backend certification is deterministic and checksum-bound, runtime object/callable/client
injection is rejected, execution/I/O/async/backend-kind/scope/receipt drift fails closed,
scenario and governance sentinels cover ADR-0018, forbidden runtime imports remain absent,
and `python scripts\verify.py verify` passes.

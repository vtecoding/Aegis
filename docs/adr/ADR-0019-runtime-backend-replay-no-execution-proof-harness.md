# ADR-0019: Runtime Backend Replay & No-Execution Proof Harness

## Status

Accepted for Phase 3 Part 5.

## Context

ADR-0018 certifies `NullRuntimeBackend` as a descriptor-only, dry-run certification
backend and emits `BackendDryRunReceipt` evidence with `executed_count == 0`. That proves
the construction path, but Aegis also needs a deterministic replay harness that can
independently reconstruct backend certification and receipt evidence and fail closed when
backend boundary evidence drifts.

This ADR remains pre-runtime. It does not add ROS, runtime execution, simulator
integration, hardware, network, filesystem, async, queues, clocks, randomness, or
actuation.

## Decision

Aegis adds an ADR-0019 backend replay proof harness:

```text
RuntimeDispatchPlan
  -> DispatchFirewallDecision(ALLOWED_DRY_RUN)
  -> RuntimeBackendDescriptor(NULL_BACKEND_V1)
  -> BackendCertificationResult(CERTIFIED_NULL)
  -> BackendDryRunReceipt(executed_count=0)
  -> BackendReplayProofResult(PASSED)
```

`BackendReplayRequest` carries the dispatch plan, firewall decision, backend descriptor,
expected certification, expected receipt, replay profile, and mutation profile. It does
not accept backend objects, raw dictionaries, callable handles, clients, runtime objects,
or optional bypass fields.

`prove_backend_replay()` validates that the dispatch plan, firewall decision, and backend
descriptor remain admissible, reconstructs a descriptor-only `NullRuntimeBackend` from the
request descriptor, then reuses `certify_runtime_backend()` and
`build_backend_dry_run_receipt()` to replay ADR-0018 evidence. `PASSED` requires exact
certification match, exact receipt match, canonical descriptor match, valid
`ALLOWED_DRY_RUN` firewall decision, exact capability and runtime-kind scope, and
`zero_execution_verified == True`.

Invalid authority or input returns `BLOCKED`. Replay-comparable evidence drift returns
`FAILED`. Every proof result is checksum-bound.

## Consequences

- Backend certification and dry-run receipt generation are independently replay-verifiable.
- `PASSED` is impossible unless both expected and replayed receipts report
  `executed_count == 0`.
- Dispatch plan drift, firewall drift, descriptor drift, scope drift, certification drift,
  receipt drift, checksum drift, cross-plan swaps, cross-backend receipt swaps, and runtime
  object injection fail closed.
- The claim remains narrow: Aegis proves deterministic replay integrity for the null
  backend boundary only. It does not prove robot, collision, middleware, runtime, hardware,
  simulator, or external certification safety.

## Non-Goals

- No ROS node, publisher, subscriber, service/action client, DDS, simulator bridge,
  hardware, filesystem, network, environment, wall-clock, randomness, async runtime,
  queue, command execution, or actuation.
- No real backend admission registry. ADR-0020 is expected to introduce a closed runtime
  backend authority registry and adapter admission gate before any real backend exists.

## Verification

```bash
python scripts\verify.py verify
```
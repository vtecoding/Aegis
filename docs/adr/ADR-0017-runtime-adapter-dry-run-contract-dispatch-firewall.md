# ADR-0017: Runtime Adapter Dry-Run Contract & Dispatch Firewall

## Status

Accepted for Phase 3 Part 3.

## Context

ADR-0015 proved construction of non-executing adapter envelopes from allowed,
receipt-valid pipeline results. ADR-0016 proved deterministic replay of that adapter
evidence and rejection of evil-twin mutations. That establishes adapter evidence
integrity, not runtime safety.

Before any ROS node, publisher, service, action, DDS integration, simulator bridge,
network boundary, filesystem boundary, hardware boundary, async runtime, or backend
client exists, Aegis needs a dry-run dispatch boundary that can derive runtime dispatch
intent as inert data and prove that intent is bounded and firewalled.

## Decision

Aegis adds a pure runtime dispatch dry-run layer after a PASSED adapter replay proof:

```text
PipelineResult
  -> ExecutionAdapterEnvelope
  -> AdapterReplayProofResult(PASSED)
  -> RuntimeDispatchPlan
  -> DispatchFirewallDecision
  -> RuntimeDispatchReceipt
```

`build_runtime_dispatch_plan()` consumes a READY `ExecutionAdapterEnvelope` and an
`AdapterReplayProofResult(status="PASSED")` for the exact same envelope. It emits a
`RuntimeDispatchPlan` with `dispatch_mode == "DRY_RUN_ONLY"`, checksum-bound source
envelope/proof evidence, explicit runtime target and mapping checksums, explicit inert
dispatch items, explicit resource bounds, and a plan checksum. Direct public construction
of an allowed dispatch plan is rejected.

`evaluate_dispatch_firewall()` rechecks the plan against the current envelope and replay
proof. `ALLOWED_DRY_RUN` is possible only when the proof is PASSED, proof checksum and
envelope checksum recompute, the proof binds the exact envelope, dispatch mode is
`DRY_RUN_ONLY`, runtime target and mapping checksums match, sequence values are strict and
gapless, payload bounds pass, QoS/namespace/message type/field map evidence matches, and
dispatch items contain only inert contract values. Anything unknown blocks.

## Consequences

- Runtime dispatch intent can be derived deterministically without a runtime backend.
- The dispatch firewall rejects unverified, swapped, mutated, stale, forged, malformed,
  oversized, unauthorised, or non-dry-run plans.
- Runtime dispatch items are descriptions only: no callable handles, ROS objects, backend
  clients, publishers, subscribers, services, actions, DDS entities, sockets, files, or
  hardware objects can enter the contract graph.
- Scenario coverage gains runtime dispatch categories and governance field sentinels.
- The claim remains narrow: adapter evidence integrity and inert dry-run dispatch intent.
  No runtime, middleware, collision, robot, hardware, or certification safety is claimed.

## Non-Goals

- No ROS node.
- No publisher, subscriber, service client, action client, DDS, simulator bridge, network,
  filesystem, environment, wall-clock, async, randomness, hardware, or actuation.
- No runtime backend.
- No robot safety, collision safety, middleware safety, execution safety, or certification
  claim.

## Verification

```bash
python scripts\verify.py verify
```

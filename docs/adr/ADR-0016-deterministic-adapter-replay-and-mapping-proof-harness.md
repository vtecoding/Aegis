# ADR-0016: Deterministic Adapter Replay & Mapping Proof Harness

## Status

Accepted for Phase 3 Part 2.

## Context

ADR-0015 proved that an allowed, receipt-valid `PipelineResult` can construct a non-executing
`ExecutionAdapterEnvelope` and `AdapterReceipt` with explicit ROS 2 mapping evidence. That is
construction evidence, not replay evidence. Before any runtime adapter, ROS node, publisher,
service, action, simulator bridge, DDS layer, network boundary, filesystem boundary, or hardware
boundary exists, Aegis needs to prove that the adapter evidence can be independently rebuilt from
the same source pipeline evidence and mapping authority.

## Decision

Aegis adds a deterministic adapter replay proof harness after the ADR-0015 builder:

```text
Allowed PipelineResult
  -> ADR-0015 adapter builder
  -> ExecutionAdapterEnvelope + AdapterReceipt
  -> ADR-0016 replay proof
  -> AdapterReplayProofResult
```

`AdapterReplayRequest` binds a source `PipelineResult`, the expected READY envelope, the expected
adapter receipt, a strict replay profile, and an explicit mutation profile. `AdapterReplayProofResult`
reports `PASSED`, `FAILED`, or `BLOCKED` with checksum-bound sub-checks for the source pipeline,
expected and replayed envelope checksums, expected and replayed receipt checksums, mapping, runtime
target, QoS, namespace, receipt chain, mutation detection, and failure stage.

`PASSED` is possible only when the replayed envelope and receipt are byte/canonical checksum-equivalent
to the expected evidence and every replay-critical binding matches. `FAILED` means replay ran and found
an evidence mismatch. `BLOCKED` means replay authority was missing or invalid before comparison.

ADR-0015 envelopes now carry the immutable mapping and runtime target evidence objects needed for
independent replay. Their envelope checksum continues to bind those objects through the existing mapping,
runtime target, ROS mapping, and QoS checksums; ADR-0016 recomputes those checksums during proof.

## Consequences

- Adapter receipts are not trusted because they exist; they are trusted only when replay proves the full
  evidence chain.
- Mutations to pipeline receipt evidence, policy result evidence, SafetyCase evidence, context authority,
  policy identity, world snapshot bindings, command plan checksums, capability, mapping, QoS, namespace,
  runtime target, envelope checksum, or adapter receipt checksum fail closed.
- Scenario coverage gains adapter replay categories while remaining a proof harness, not a runtime execution
  harness.
- No `run_pipeline()` semantics change.

## Non-Goals

- No ROS runtime adapter.
- No `rclpy`, `rclcpp`, ROS node, publisher, subscriber, service, action, DDS, MoveIt, Gazebo, Isaac, Viam,
  simulator, hardware, actuator, network, filesystem, environment, async, or wall-clock integration.
- No claim of robot safety, collision safety, middleware safety, physical-world truth, certification readiness,
  execution safety, or runtime command dispatch.

## Verification

```bash
python scripts\verify.py verify
```

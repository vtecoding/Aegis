# ADR-0015: Execution Adapter Boundary & ROS 2 Message Mapping Contract

## Status

Accepted for Phase 3 Part 1.

## Context

Phase 2 sealed the deterministic policy-admission kernel. An allowed `PipelineResult`
already proves validation, planning, audit, world-snapshot admissibility, freshness,
verifier certification, trust-policy configuration, trust evaluation, policy evaluation,
SafetyCase construction, policy admission, gate approval, decision trace integrity, and
approval receipt integrity.

Phase 3 begins the bridge toward runtime systems, but it must not execute anything. ROS 2,
MoveIt, Isaac, Viam, DDS, launch files, nodes, sockets, hardware calls, filesystem reads,
environment reads, async jobs, and runtime message publication remain out of scope for the
deterministic core.

## Decision

Aegis adds a pure, non-executing adapter boundary after the allowed pipeline result:

```text
PipelineResult(ALLOWED, receipt VALID)
  -> ExecutionAdapterMapping validation
  -> Ros2MessageMapping validation
  -> ExecutionAdapterEnvelope
  -> AdapterReceipt
```

The public API is separate from `run_pipeline()`:

```python
build_execution_adapter_envelope(
    pipeline_result: PipelineResult,
    adapter_mapping: ExecutionAdapterMapping,
    target_runtime: RuntimeTarget,
) -> ExecutionAdapterEnvelope
```

`READY` envelopes require an allowed, receipt-valid `PipelineResult`; policy checksum,
context authority checksum, SafetyCase ID, audited plan ID, plan checksum, adapter mapping
checksum, runtime target checksum, ROS 2 mapping checksum, QoS checksum, and adapter
authority are bound into the envelope checksum.

ROS 2 is modelled only as immutable data: runtime target identity, communication primitive,
package, message type, namespace-scoped topic/service/action name, explicit QoS profile,
field map, required fields, forbidden fields, and mapping authority. No ROS package is
imported.

## Consequences

- Future runtime adapters receive a deterministic evidence packet rather than raw intent.
- Policy `ALLOW` and gate approval cannot skip adapter mapping validation.
- Adapter mapping cannot skip policy admission because the only READY source is a fully
  allowed `PipelineResult` with valid approval receipt integrity.
- Blocked, invalid, or errored envelopes carry reasons and no command payload.
- No physical safety, ROS integration, collision safety, actuator safety, simulation safety,
  or certification readiness is claimed.

## Alternatives Considered

- Add `rclpy` publishing now. Rejected because it would cross the deterministic boundary and
  introduce middleware side effects.
- Integrate MoveIt, Isaac, or Viam first. Rejected because Phase 3 Part 1 must define the
  authority and mapping contract before any runtime SDK.
- Build a simulator first. Rejected because simulation without adapter authority would not
  prove receipt-bound runtime intent.
- Use a generic execution adapter only. Rejected because ROS 2 QoS, namespace, primitive, and
  message-type realities must be modelled explicitly as data.

## Verification

```bash
python scripts\verify.py verify
```

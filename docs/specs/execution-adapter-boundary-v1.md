# Execution Adapter Boundary v1

## Scope

Execution Adapter Boundary v1 creates deterministic, immutable adapter evidence after the
sealed Phase 2 pipeline. It does not execute commands, publish messages, open sockets, read
files, read environment variables, call hardware, start nodes, run launch files, use async, or
import ROS/MoveIt/Isaac/Viam/DDS packages.

## Contracts

- `RuntimeTarget` identifies the future runtime as explicit evidence.
- `ExecutionAdapterMapping` binds a runtime target, ROS 2 mapping, accepted pipeline version,
  accepted gate version, accepted policy schema version, adapter authority, effective time,
  superseded checksum, and mapping checksum.
- `ExecutionAdapterEnvelope` is the non-executing packet produced from one allowed pipeline
  result and one valid adapter mapping.
- `AdapterReceipt` binds the envelope checksum to adapter and pipeline evidence for later
  observability export.

## READY Requirements

`ExecutionAdapterEnvelope.status == READY` requires all of the following:

- `PipelineResult.outcome == ALLOWED`
- `ApprovalReceipt.status == VALID`
- `ApprovalReceiptValidationResult.status == VALID`
- decision trace checksum recomputes
- approval receipt checksum recomputes
- approval receipt fields match concrete pipeline artifacts
- policy-backed admission integrity passed
- audited plan ID and plan checksum match the pipeline result
- policy checksum and context authority checksum are present
- SafetyCase ID is present
- adapter mapping checksum recomputes
- runtime target checksum recomputes
- ROS 2 mapping checksum recomputes
- QoS checksum recomputes and uses bounded `KEEP_LAST`
- source command matches the audited command step
- source capability matches the policy-admitted capability
- ROS 2 namespace matches the runtime target namespace
- every required source field is present
- every mapped source path exists
- the command payload contains only explicitly mapped fields
- forbidden runtime override fields are absent
- command payload resource bounds pass

## Non-Ready Requirements

`BLOCKED`, `INVALID`, and `ERROR` envelopes must not carry a command payload. They must carry
deterministic reason codes in `blocked_reasons` and a terminal adapter stage.

## Failure Reasons

- `PIPELINE_RESULT_NOT_ALLOWED`
- `PIPELINE_RECEIPT_INVALID`
- `ADAPTER_CAPABILITY_MISMATCH`
- `ROS2_MAPPING_COMMAND_MISMATCH`
- `ROS2_NAMESPACE_MISMATCH`
- `ROS2_QOS_INVALID`
- `FORBIDDEN_RUNTIME_FIELD`
- `ADAPTER_REQUIRED_FIELD_MISSING`
- `ADAPTER_FIELD_MAP_INVALID`
- `ADAPTER_MAPPING_CHECKSUM_MISMATCH`
- `RUNTIME_TARGET_CHECKSUM_MISMATCH`
- `ROS2_MAPPING_CHECKSUM_MISMATCH`
- `DIRECT_ADAPTER_BYPASS`
- `CONFUSABLE_RUNTIME_STRING`
- `ADAPTER_PAYLOAD_RESOURCE_EXCEEDED`

## Invariants

- Same allowed pipeline result and same adapter mapping produce the same envelope checksum.
- Field-map key order does not change mapping or envelope checksums.
- Non-allowed pipeline outcomes never produce `READY`.
- Checksum mutation prevents `READY`.
- Adapter envelope construction does not mutate the source `PipelineResult`.

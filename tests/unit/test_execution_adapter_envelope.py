"""Unit tests for the ADR-0015 execution adapter envelope builder."""

from __future__ import annotations

from tests.execution_adapter_fixtures import (
    adapter_mapping,
    allowed_pipeline_result,
    blocked_pipeline_result,
    ros2_move_mapping,
    runtime_target,
)

from aegis.contracts.approval_receipt import (
    ApprovalReceiptReason,
    ApprovalReceiptStatus,
    ApprovalReceiptValidationResult,
)
from aegis.contracts.execution_adapter import (
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterReason,
)
from aegis.contracts.ros2_mapping import Ros2History
from aegis.execution import build_execution_adapter_envelope


def test_allowed_pipeline_result_builds_ready_envelope() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result()

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)
    replay = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.READY
    assert envelope.blocked_reasons == ()
    assert envelope.command_payload == {"target.x": 1, "target.y": 2}
    assert envelope.payload_field_count == 2
    assert envelope.envelope_checksum == replay.envelope_checksum


def test_blocked_pipeline_result_cannot_build_ready_envelope() -> None:
    mapping = adapter_mapping()
    result = blocked_pipeline_result()

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.command_payload == {}
    assert envelope.blocked_reasons == (ExecutionAdapterReason.PIPELINE_RESULT_NOT_ALLOWED.value,)


def test_invalid_receipt_blocks_allowed_looking_result() -> None:
    mapping = adapter_mapping()
    result = allowed_pipeline_result(request_id="adapter-invalid-receipt")
    assert result.approval_receipt is not None
    assert result.decision_trace is not None
    object.__setattr__(
        result,
        "receipt_validation",
        ApprovalReceiptValidationResult(
            status=ApprovalReceiptStatus.INVALID,
            reason=ApprovalReceiptReason.APPROVAL_RECEIPT_CHECKSUM_MISMATCH,
            approval_receipt_checksum=result.approval_receipt.approval_receipt_checksum,
            decision_trace_checksum=result.decision_trace.trace_checksum,
            failed_fields=("approval_receipt_checksum",),
        ),
    )

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.blocked_reasons == (ExecutionAdapterReason.PIPELINE_RECEIPT_INVALID.value,)
    assert envelope.command_payload == {}


def test_wrong_capability_blocks_envelope() -> None:
    mapping = adapter_mapping(ros2_mapping=ros2_move_mapping(source_capability="manipulation.grip"))
    result = allowed_pipeline_result(request_id="adapter-wrong-capability")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert ExecutionAdapterReason.ADAPTER_CAPABILITY_MISMATCH.value in envelope.blocked_reasons


def test_wrong_command_blocks_envelope() -> None:
    mapping = adapter_mapping(ros2_mapping=ros2_move_mapping(source_command="inspect"))
    result = allowed_pipeline_result(request_id="adapter-wrong-command")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert ExecutionAdapterReason.ROS2_MAPPING_COMMAND_MISMATCH.value in envelope.blocked_reasons


def test_wrong_namespace_blocks_envelope() -> None:
    target = runtime_target(namespace="robot_arm")
    mapping = adapter_mapping(target=target, ros2_mapping=ros2_move_mapping(namespace="other_arm"))
    result = allowed_pipeline_result(request_id="adapter-wrong-namespace")

    envelope = build_execution_adapter_envelope(result, mapping, target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert ExecutionAdapterReason.ROS2_NAMESPACE_MISMATCH.value in envelope.blocked_reasons


def test_required_field_missing_blocks_envelope() -> None:
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(required_fields=("parameters.target.z",))
    )
    result = allowed_pipeline_result(request_id="adapter-required-missing")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert ExecutionAdapterReason.ADAPTER_REQUIRED_FIELD_MISSING.value in envelope.blocked_reasons


def test_unknown_field_map_source_invalidates_envelope() -> None:
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(field_map={"parameters.target.z": "target.z"})
    )
    result = allowed_pipeline_result(request_id="adapter-field-map-invalid")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.INVALID
    assert ExecutionAdapterReason.ADAPTER_FIELD_MAP_INVALID.value in envelope.blocked_reasons


def test_forbidden_runtime_field_blocks_envelope() -> None:
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(field_map={"parameters.target.x": "force_execute"})
    )
    result = allowed_pipeline_result(request_id="adapter-forbidden-field")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.forbidden_field_detected is True
    assert ExecutionAdapterReason.FORBIDDEN_RUNTIME_FIELD.value in envelope.blocked_reasons


def test_mutated_qos_invalidates_envelope() -> None:
    mapping = adapter_mapping()
    object.__setattr__(mapping.ros2_mapping.qos, "history", Ros2History.KEEP_ALL)
    result = allowed_pipeline_result(request_id="adapter-qos-invalid")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.INVALID
    assert ExecutionAdapterReason.ROS2_QOS_INVALID.value in envelope.blocked_reasons


def test_mapping_not_effective_blocks_envelope() -> None:
    mapping = adapter_mapping(effective_from_ms=9_999_999)
    result = allowed_pipeline_result(request_id="adapter-stale-mapping")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert ExecutionAdapterReason.ADAPTER_MAPPING_NOT_EFFECTIVE.value in envelope.blocked_reasons


def test_pipeline_and_gate_version_mismatch_blocks_envelope() -> None:
    baseline = adapter_mapping()
    mapping = type(baseline)(
        adapter_mapping_id=baseline.adapter_mapping_id,
        adapter_mapping_version=baseline.adapter_mapping_version,
        runtime_target=baseline.runtime_target,
        ros2_mapping=baseline.ros2_mapping,
        accepted_pipeline_version="pipeline-v2",
        accepted_gate_version="gate-v2",
        accepted_policy_schema_version=baseline.accepted_policy_schema_version,
        adapter_authority=baseline.adapter_authority,
        effective_from_ms=baseline.effective_from_ms,
    )
    result = allowed_pipeline_result(request_id="adapter-version-mismatch")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)
    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert (
        ExecutionAdapterReason.ADAPTER_PIPELINE_VERSION_MISMATCH.value in envelope.blocked_reasons
    )
    assert ExecutionAdapterReason.ADAPTER_GATE_VERSION_MISMATCH.value in envelope.blocked_reasons


def test_policy_schema_mismatch_blocks_envelope() -> None:
    mapping = adapter_mapping(accepted_policy_schema_version="policy-v2")
    result = allowed_pipeline_result(request_id="adapter-policy-schema-mismatch")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)
    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert ExecutionAdapterReason.ADAPTER_POLICY_SCHEMA_MISMATCH.value in envelope.blocked_reasons

"""Adversarial tests for ADR-0015 ROS 2 mapping abuse."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import (
    ADAPTER_FORBIDDEN_FIELDS,
    adapter_mapping,
    allowed_pipeline_result,
    ros2_move_mapping,
    runtime_target,
)

from aegis.aegis_constants import MAX_ADAPTER_FIELD_COUNT
from aegis.contracts.aegis_execution_adapter import (
    ExecutionAdapterEnvelopeStatus,
    ExecutionAdapterReason,
)
from aegis.contracts.aegis_ros2_mapping import Ros2MessageMapping, RuntimeKind, RuntimeTarget
from aegis.execution import build_execution_adapter_envelope


def test_confusable_runtime_namespace_rejected_at_contract_boundary() -> None:
    with pytest.raises(ValueError):
        RuntimeTarget(
            runtime_kind=RuntimeKind.ROS2,
            runtime_id="ros2-runtime",
            runtime_version="kilted",
            deployment_domain="SIMULATION",
            target_namespace="robot\u200farm",
            target_robot_id="robot-arm-1",
            runtime_authority="runtime.registry.local",
        )


def test_force_execute_target_field_blocks_ready_envelope() -> None:
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(field_map={"parameters.target.x": "force_execute"})
    )
    result = allowed_pipeline_result(request_id="adapter-force-execute")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.forbidden_field_detected is True
    assert ExecutionAdapterReason.FORBIDDEN_RUNTIME_FIELD.value in envelope.blocked_reasons


def test_disable_safety_target_field_blocks_ready_envelope() -> None:
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(field_map={"parameters.target.x": "disable_safety"})
    )
    result = allowed_pipeline_result(request_id="adapter-disable-safety")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.BLOCKED
    assert envelope.forbidden_field_detected is True


def test_field_map_path_injection_invalidates_envelope() -> None:
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(field_map={"parameters.target.__class__": "target.type"})
    )
    result = allowed_pipeline_result(request_id="adapter-path-injection")

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.INVALID
    assert ExecutionAdapterReason.ADAPTER_FIELD_MAP_INVALID.value in envelope.blocked_reasons


def test_oversized_mapping_rejected_at_contract_boundary() -> None:
    field_map = {
        f"parameters.target.x{i}": f"target.x{i}" for i in range(MAX_ADAPTER_FIELD_COUNT + 1)
    }

    with pytest.raises(ValueError, match="field_map"):
        ros2_move_mapping(field_map=field_map)


def test_runtime_target_checksum_mismatch_prevents_ready_envelope() -> None:
    target = runtime_target()
    mapping = adapter_mapping(target=target)
    object.__setattr__(target, "runtime_target_checksum", "0" * 64)
    result = allowed_pipeline_result(request_id="adapter-runtime-checksum")

    envelope = build_execution_adapter_envelope(result, mapping, target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.INVALID
    assert ExecutionAdapterReason.RUNTIME_TARGET_CHECKSUM_MISMATCH.value in envelope.blocked_reasons


def test_mapping_checksum_mismatch_rejected_at_contract_boundary() -> None:
    with pytest.raises(ValueError, match="checksum"):
        Ros2MessageMapping(
            mapping_id="ros2-move-mapping",
            mapping_version="v1",
            source_command="move",
            source_capability="locomotion.translation",
            primitive="topic",
            package_name="aegis_msgs",
            message_type="msg/MoveCommand",
            topic_or_service_name="command/move",
            namespace="robot_arm",
            frame_id="map",
            qos=adapter_mapping().ros2_mapping.qos,
            field_map={"parameters.target.x": "target.x"},
            required_fields=("parameters.target.x",),
            forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
            mapping_authority="aegis.adapter.registry",
            mapping_checksum="0" * 64,
        )

"""Unit tests for ADR-0015 pure ROS 2 mapping validation."""

from __future__ import annotations

from tests.execution_adapter_fixtures import adapter_mapping, runtime_target

from aegis.contracts.execution_adapter import ExecutionAdapterReason
from aegis.contracts.ros2_mapping import Ros2History
from aegis.execution import validate_ros2_message_mapping


def test_ros2_mapping_validator_accepts_matching_runtime_mapping() -> None:
    mapping = adapter_mapping()

    assert validate_ros2_message_mapping(mapping.ros2_mapping, mapping.runtime_target) == ()


def test_ros2_mapping_validator_detects_runtime_checksum_mutation() -> None:
    target = runtime_target()
    object.__setattr__(target, "runtime_target_checksum", "0" * 64)
    mapping = adapter_mapping(target=runtime_target())

    reasons = validate_ros2_message_mapping(mapping.ros2_mapping, target)

    assert ExecutionAdapterReason.RUNTIME_TARGET_CHECKSUM_MISMATCH in reasons


def test_ros2_mapping_validator_detects_mapping_checksum_mutation() -> None:
    mapping = adapter_mapping()
    object.__setattr__(mapping.ros2_mapping, "mapping_checksum", "0" * 64)

    reasons = validate_ros2_message_mapping(mapping.ros2_mapping, mapping.runtime_target)

    assert ExecutionAdapterReason.ROS2_MAPPING_CHECKSUM_MISMATCH in reasons


def test_ros2_mapping_validator_detects_qos_mutation() -> None:
    mapping = adapter_mapping()
    object.__setattr__(mapping.ros2_mapping.qos, "history", Ros2History.KEEP_ALL)

    reasons = validate_ros2_message_mapping(mapping.ros2_mapping, mapping.runtime_target)

    assert ExecutionAdapterReason.ROS2_QOS_INVALID in reasons


def test_ros2_mapping_validator_detects_namespace_mismatch() -> None:
    mapping = adapter_mapping()
    target = runtime_target(namespace="other_arm")

    reasons = validate_ros2_message_mapping(mapping.ros2_mapping, target)

    assert ExecutionAdapterReason.ROS2_NAMESPACE_MISMATCH in reasons


def test_ros2_mapping_validator_detects_non_positive_mutated_qos_depth() -> None:
    mapping = adapter_mapping()
    object.__setattr__(mapping.ros2_mapping.qos, "depth", 0)

    reasons = validate_ros2_message_mapping(mapping.ros2_mapping, mapping.runtime_target)

    assert ExecutionAdapterReason.ROS2_QOS_INVALID in reasons

"""Pure ROS 2 mapping validation with no ROS imports."""

from __future__ import annotations

from aegis.contracts.aegis_execution_adapter import ExecutionAdapterReason
from aegis.contracts.aegis_ros2_mapping import (
    Ros2History,
    Ros2MessageMapping,
    RuntimeKind,
    RuntimeTarget,
    recompute_ros2_message_mapping_checksum,
    recompute_ros2_qos_profile_checksum,
    recompute_runtime_target_checksum,
)


def validate_ros2_message_mapping(
    mapping: Ros2MessageMapping,
    target_runtime: RuntimeTarget,
) -> tuple[ExecutionAdapterReason, ...]:
    """Return deterministic ROS 2 mapping validation failures.

    Args:
        mapping: Explicit ROS 2 message mapping contract.
        target_runtime: Runtime target supplied by the adapter caller.

    Returns:
        A deterministic tuple of adapter reason codes. An empty tuple means
        the ROS 2 mapping is structurally valid for the target runtime.
    """
    reasons: list[ExecutionAdapterReason] = []
    if target_runtime.runtime_kind is not RuntimeKind.ROS2:
        reasons.append(ExecutionAdapterReason.ADAPTER_RUNTIME_TARGET_MISMATCH)
    if target_runtime.runtime_target_checksum != recompute_runtime_target_checksum(target_runtime):
        reasons.append(ExecutionAdapterReason.RUNTIME_TARGET_CHECKSUM_MISMATCH)
    if mapping.mapping_checksum != recompute_ros2_message_mapping_checksum(mapping):
        reasons.append(ExecutionAdapterReason.ROS2_MAPPING_CHECKSUM_MISMATCH)
    if mapping.qos.qos_checksum != recompute_ros2_qos_profile_checksum(mapping.qos):
        reasons.append(ExecutionAdapterReason.ROS2_QOS_INVALID)
    if mapping.qos.history is Ros2History.KEEP_ALL:
        reasons.append(ExecutionAdapterReason.ROS2_QOS_INVALID)
    if mapping.qos.history is Ros2History.KEEP_LAST and mapping.qos.depth is None:
        reasons.append(ExecutionAdapterReason.ROS2_QOS_INVALID)
    if mapping.qos.depth is not None and mapping.qos.depth <= 0:
        reasons.append(ExecutionAdapterReason.ROS2_QOS_INVALID)
    if mapping.namespace != target_runtime.target_namespace:
        reasons.append(ExecutionAdapterReason.ROS2_NAMESPACE_MISMATCH)
    return tuple(dict.fromkeys(reasons))


__all__ = ["validate_ros2_message_mapping"]

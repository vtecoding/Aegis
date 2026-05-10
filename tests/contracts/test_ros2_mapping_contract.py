"""Contract tests for ADR-0015 ROS 2 mapping contracts."""

from __future__ import annotations

import pytest
from tests.execution_adapter_fixtures import (
    ADAPTER_FORBIDDEN_FIELDS,
    qos_profile,
    ros2_move_mapping,
    runtime_target,
)

from aegis.contracts.aegis_ros2_mapping import (
    DANGEROUS_RUNTIME_OVERRIDE_FIELDS,
    Ros2Durability,
    Ros2History,
    Ros2Liveliness,
    Ros2MessageMapping,
    Ros2QoSProfileSpec,
    Ros2Reliability,
    RuntimeKind,
    RuntimeTarget,
    recompute_ros2_message_mapping_checksum,
    recompute_ros2_qos_profile_checksum,
    recompute_runtime_target_checksum,
)


def test_runtime_target_binds_identity_checksum() -> None:
    target = runtime_target()

    assert target.runtime_kind is RuntimeKind.ROS2
    assert target.runtime_target_checksum == recompute_runtime_target_checksum(target)


@pytest.mark.parametrize("namespace", ("", " robot_arm", "/robot_arm", "robot_arm/../cmd"))
def test_runtime_target_rejects_invalid_namespace(namespace: str) -> None:
    with pytest.raises(ValueError):
        runtime_target(namespace=namespace)


def test_runtime_target_rejects_confusable_unicode() -> None:
    with pytest.raises(ValueError, match="ASCII"):
        RuntimeTarget(
            runtime_kind=RuntimeKind.ROS2,
            runtime_id="ros2-runtime",
            runtime_version="kilted",
            deployment_domain="SIMULATION",
            target_namespace="rёbot_arm",
            target_robot_id="robot-arm-1",
            runtime_authority="runtime.registry.local",
        )


def test_runtime_target_rejects_forged_checksum() -> None:
    with pytest.raises(ValueError, match="checksum"):
        RuntimeTarget(
            runtime_kind=RuntimeKind.ROS2,
            runtime_id="ros2-runtime",
            runtime_version="kilted",
            deployment_domain="SIMULATION",
            target_namespace="robot_arm",
            target_robot_id="robot-arm-1",
            runtime_authority="runtime.registry.local",
            runtime_target_checksum="0" * 64,
        )


def test_qos_profile_binds_checksum_without_defaults() -> None:
    qos = qos_profile()

    assert qos.depth == 10
    assert qos.qos_checksum == recompute_ros2_qos_profile_checksum(qos)


@pytest.mark.parametrize("depth", (None, 0, -1, True))
def test_qos_profile_rejects_invalid_keep_last_depth(depth: object) -> None:
    with pytest.raises(ValueError):
        qos_profile(depth=depth)


def test_qos_profile_rejects_keep_all_for_phase_3_part_1() -> None:
    with pytest.raises(ValueError, match="KEEP_ALL"):
        Ros2QoSProfileSpec(
            reliability=Ros2Reliability.RELIABLE,
            durability=Ros2Durability.VOLATILE,
            history=Ros2History.KEEP_ALL,
            depth=None,
            deadline_ms=100,
            lifespan_ms=1_000,
            liveliness=Ros2Liveliness.AUTOMATIC,
            lease_duration_ms=1_000,
        )


def test_qos_profile_rejects_negative_duration() -> None:
    with pytest.raises(ValueError, match="deadline"):
        Ros2QoSProfileSpec(
            reliability=Ros2Reliability.RELIABLE,
            durability=Ros2Durability.VOLATILE,
            history=Ros2History.KEEP_LAST,
            depth=10,
            deadline_ms=-1,
            lifespan_ms=1_000,
            liveliness=Ros2Liveliness.AUTOMATIC,
            lease_duration_ms=1_000,
        )


def test_ros2_message_mapping_binds_checksum_and_dangerous_fields() -> None:
    mapping = ros2_move_mapping()

    assert DANGEROUS_RUNTIME_OVERRIDE_FIELDS.issubset(mapping.forbidden_fields)
    assert mapping.mapping_checksum == recompute_ros2_message_mapping_checksum(mapping)


def test_ros2_message_mapping_rejects_empty_field_map() -> None:
    with pytest.raises(ValueError, match="field_map"):
        ros2_move_mapping(field_map={})


def test_ros2_message_mapping_rejects_invalid_field_map_shapes() -> None:
    with pytest.raises(ValueError, match="field_map"):
        ros2_move_mapping(field_map="parameters.target.x")
    with pytest.raises(ValueError, match="duplicate target"):
        ros2_move_mapping(
            field_map={"parameters.target.x": "target.x", "parameters.target.y": "target.x"}
        )


def test_ros2_message_mapping_rejects_duplicate_required_fields() -> None:
    with pytest.raises(ValueError, match="required_fields"):
        ros2_move_mapping(required_fields=("parameters.target.x", "parameters.target.x"))


def test_ros2_message_mapping_rejects_bad_enum_and_message_type() -> None:
    with pytest.raises(ValueError, match="primitive"):
        Ros2MessageMapping(
            mapping_id="ros2-move-mapping",
            mapping_version="v1",
            source_command="move",
            source_capability="locomotion.translation",
            primitive="publisher",
            package_name="aegis_msgs",
            message_type="msg/MoveCommand",
            topic_or_service_name="command/move",
            namespace="robot_arm",
            frame_id="map",
            qos=qos_profile(),
            field_map={"parameters.target.x": "target.x"},
            required_fields=("parameters.target.x",),
            forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
            mapping_authority="aegis.adapter.registry",
        )
    with pytest.raises(ValueError, match="message_type"):
        Ros2MessageMapping(
            mapping_id="ros2-move-mapping",
            mapping_version="v1",
            source_command="move",
            source_capability="locomotion.translation",
            primitive="topic",
            package_name="aegis_msgs",
            message_type="MoveCommand",
            topic_or_service_name="command/move",
            namespace="robot_arm",
            frame_id="map",
            qos=qos_profile(),
            field_map={"parameters.target.x": "target.x"},
            required_fields=("parameters.target.x",),
            forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
            mapping_authority="aegis.adapter.registry",
        )


def test_ros2_message_mapping_rejects_missing_dangerous_forbidden_fields() -> None:
    with pytest.raises(ValueError, match="forbidden_fields"):
        ros2_move_mapping(forbidden_fields=("force_execute",))


def test_ros2_message_mapping_rejects_forged_checksum() -> None:
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
            qos=qos_profile(),
            field_map={"parameters.target.x": "target.x"},
            required_fields=("parameters.target.x",),
            forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
            mapping_authority="aegis.adapter.registry",
            mapping_checksum="0" * 64,
        )


def test_ros2_message_mapping_rejects_absolute_topic_name() -> None:
    with pytest.raises(ValueError, match="topic_or_service_name"):
        Ros2MessageMapping(
            mapping_id="ros2-move-mapping",
            mapping_version="v1",
            source_command="move",
            source_capability="locomotion.translation",
            primitive="topic",
            package_name="aegis_msgs",
            message_type="msg/MoveCommand",
            topic_or_service_name="/command/move",
            namespace="robot_arm",
            frame_id="map",
            qos=qos_profile(),
            field_map={"parameters.target.x": "target.x"},
            required_fields=("parameters.target.x",),
            forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
            mapping_authority="aegis.adapter.registry",
        )

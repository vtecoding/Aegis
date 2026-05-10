"""Invariant tests for ADR-0015 ROS 2 message mapping contracts."""

from __future__ import annotations

from tests.execution_adapter_fixtures import (
    ADAPTER_FORBIDDEN_FIELDS,
    qos_profile,
    ros2_move_mapping,
)

from aegis.contracts.aegis_ros2_mapping import DANGEROUS_RUNTIME_OVERRIDE_FIELDS


def test_invariant_mapping_key_order_does_not_change_mapping_checksum() -> None:
    first = ros2_move_mapping(
        field_map={"parameters.target.x": "target.x", "parameters.target.y": "target.y"}
    )
    second = ros2_move_mapping(
        field_map={"parameters.target.y": "target.y", "parameters.target.x": "target.x"}
    )

    assert first.field_map == second.field_map
    assert first.mapping_checksum == second.mapping_checksum


def test_invariant_required_and_forbidden_field_order_is_canonical() -> None:
    first = ros2_move_mapping(
        required_fields=("parameters.target.x", "parameters.target.y"),
        forbidden_fields=ADAPTER_FORBIDDEN_FIELDS,
    )
    second = ros2_move_mapping(
        required_fields=("parameters.target.y", "parameters.target.x"),
        forbidden_fields=tuple(reversed(ADAPTER_FORBIDDEN_FIELDS)),
    )

    assert first.required_fields == second.required_fields
    assert first.forbidden_fields == second.forbidden_fields
    assert first.mapping_checksum == second.mapping_checksum


def test_invariant_dangerous_runtime_fields_are_always_forbidden() -> None:
    mapping = ros2_move_mapping()

    assert DANGEROUS_RUNTIME_OVERRIDE_FIELDS.issubset(mapping.forbidden_fields)


def test_invariant_qos_checksum_is_stable() -> None:
    first = qos_profile()
    second = qos_profile()

    assert first == second
    assert first.qos_checksum == second.qos_checksum

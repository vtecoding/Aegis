"""Invariant tests for ADR-0015 execution adapter envelopes."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.execution_adapter_fixtures import (
    adapter_mapping,
    allowed_pipeline_result,
    blocked_pipeline_result,
    ros2_move_mapping,
)

from aegis.contracts.execution_adapter import ExecutionAdapterEnvelopeStatus, ExecutionAdapterReason
from aegis.execution import build_execution_adapter_envelope


@given(st.integers(min_value=1, max_value=20))
@settings(max_examples=8)
def test_invariant_same_allowed_result_and_mapping_same_envelope_checksum(
    request_number: int,
) -> None:
    result = allowed_pipeline_result(request_id=f"adapter-determinism-{request_number}")
    mapping = adapter_mapping()

    first = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)
    second = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert first == second
    assert first.envelope_checksum == second.envelope_checksum


def test_invariant_field_map_order_does_not_change_envelope_checksum() -> None:
    result = allowed_pipeline_result(request_id="adapter-field-order")
    first_ros2 = ros2_move_mapping(
        field_map={"parameters.target.x": "target.x", "parameters.target.y": "target.y"}
    )
    second_ros2 = ros2_move_mapping(
        field_map={"parameters.target.y": "target.y", "parameters.target.x": "target.x"}
    )
    first_mapping = adapter_mapping(ros2_mapping=first_ros2)
    second_mapping = adapter_mapping(ros2_mapping=second_ros2)

    first = build_execution_adapter_envelope(result, first_mapping, first_mapping.runtime_target)
    second = build_execution_adapter_envelope(result, second_mapping, second_mapping.runtime_target)

    assert (
        first_mapping.ros2_mapping.mapping_checksum == second_mapping.ros2_mapping.mapping_checksum
    )
    assert first.envelope_checksum == second.envelope_checksum


def test_invariant_forbidden_fields_always_prevent_ready() -> None:
    result = allowed_pipeline_result(request_id="adapter-forbidden-invariant")
    mapping = adapter_mapping(
        ros2_mapping=ros2_move_mapping(field_map={"parameters.target.x": "raw_command"})
    )

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is not ExecutionAdapterEnvelopeStatus.READY
    assert ExecutionAdapterReason.FORBIDDEN_RUNTIME_FIELD.value in envelope.blocked_reasons


def test_invariant_non_allowed_pipeline_outcomes_never_produce_ready() -> None:
    result = blocked_pipeline_result()
    mapping = adapter_mapping()

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is not ExecutionAdapterEnvelopeStatus.READY
    assert envelope.command_payload == {}


def test_invariant_checksum_mutation_prevents_ready() -> None:
    result = allowed_pipeline_result(request_id="adapter-checksum-mutation")
    mapping = adapter_mapping()
    object.__setattr__(mapping, "adapter_mapping_checksum", "0" * 64)

    envelope = build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert envelope.status is ExecutionAdapterEnvelopeStatus.INVALID
    assert (
        ExecutionAdapterReason.ADAPTER_MAPPING_CHECKSUM_MISMATCH.value in envelope.blocked_reasons
    )


def test_invariant_adapter_envelope_does_not_mutate_pipeline_result() -> None:
    result = allowed_pipeline_result(request_id="adapter-non-mutation")
    mapping = adapter_mapping()
    assert result.approval_receipt is not None
    receipt_checksum = result.approval_receipt.approval_receipt_checksum
    policy_checksum = result.policy_admission.policy_checksum

    build_execution_adapter_envelope(result, mapping, mapping.runtime_target)

    assert result.approval_receipt.approval_receipt_checksum == receipt_checksum
    assert result.policy_admission.policy_checksum == policy_checksum
